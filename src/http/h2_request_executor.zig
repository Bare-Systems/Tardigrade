//! Process-wide bounded worker pool that executes finite HTTP/2 request jobs
//! handed off through a connection-owned `h2_request_handoff.Handoff` (#866).
//!
//! This module is deliberately ignorant of HTTP/2, routing, or job payload
//! shape: a submitter enqueues a *signal* that one specific handoff has a job
//! ready, and a worker thread picks up that signal and calls the caller's
//! `execute_fn`, which is responsible for calling `Handoff.takeJob` and
//! `Handoff.finish` itself. Keeping this pool generic lets the connection
//! runtime own every HTTP/2-specific detail (request snapshot, response
//! construction) while still sharing one bounded, fixed-size thread pool
//! across every connection on the process.
const std = @import("std");
const compat = @import("zig_compat");
const builtin = @import("builtin");
const h2_request_handoff = @import("h2_request_handoff.zig");

pub const Error = error{QueueFull};

/// Invoked on a worker thread with exactly one handoff known to have at least
/// one job ready. Must call `handoff.takeJob()` and eventually
/// `handoff.finish()` for whatever it takes; a null `takeJob()` result (the
/// job was already drained by a prior signal) is a normal no-op.
pub const ExecuteFn = *const fn (ctx: *anyopaque, handoff: *h2_request_handoff.Handoff) void;

pub const Executor = struct {
    allocator: std.mem.Allocator,
    threads: if (builtin.single_threaded) [0]std.Thread else []std.Thread,
    mutex: compat.Mutex = .{},
    cond: compat.Condition = .{},
    queue: std.ArrayList(*h2_request_handoff.Handoff) = .empty,
    max_queue_len: usize,
    shutting_down: bool = false,
    execute_fn: ExecuteFn,
    execute_ctx: *anyopaque,

    pub fn init(
        self: *Executor,
        allocator: std.mem.Allocator,
        worker_count: usize,
        max_queue_len: usize,
        execute_fn: ExecuteFn,
        execute_ctx: *anyopaque,
    ) !void {
        self.* = .{
            .allocator = allocator,
            .threads = if (builtin.single_threaded) .{} else &.{},
            .max_queue_len = max_queue_len,
            .execute_fn = execute_fn,
            .execute_ctx = execute_ctx,
        };
        try self.queue.ensureTotalCapacity(allocator, max_queue_len);
        if (builtin.single_threaded) return;

        const thread_count = @max(worker_count, 1);
        self.threads = try allocator.alloc(std.Thread, thread_count);
        errdefer allocator.free(self.threads);

        var spawned: usize = 0;
        errdefer {
            self.mutex.lock();
            self.shutting_down = true;
            self.mutex.unlock();
            self.cond.broadcast();
            for (self.threads[0..spawned]) |t| t.join();
        }
        for (self.threads) |*thread| {
            thread.* = try std.Thread.spawn(.{}, workerLoop, .{self});
            spawned += 1;
        }
    }

    /// Enqueue one wakeup for `handoff`. Bounded by `max_queue_len`: the
    /// caller must undo its matching `Handoff.submit` (typically via
    /// `cancelStream`) on `error.QueueFull` so a signal is never lost without
    /// also releasing the job it would have woken a worker for.
    pub fn submitSignal(self: *Executor, handoff: *h2_request_handoff.Handoff) Error!void {
        if (builtin.single_threaded) {
            self.execute_fn(self.execute_ctx, handoff);
            return;
        }
        self.mutex.lock();
        if (self.shutting_down or self.queue.items.len >= self.max_queue_len) {
            self.mutex.unlock();
            return error.QueueFull;
        }
        self.queue.appendAssumeCapacity(handoff);
        self.mutex.unlock();
        self.cond.signal();
    }

    fn workerLoop(self: *Executor) void {
        while (true) {
            self.mutex.lock();
            while (self.queue.items.len == 0 and !self.shutting_down) self.cond.wait(&self.mutex);
            if (self.queue.items.len == 0 and self.shutting_down) {
                self.mutex.unlock();
                return;
            }
            const handoff = self.queue.orderedRemove(0);
            self.mutex.unlock();
            self.execute_fn(self.execute_ctx, handoff);
        }
    }

    /// Stop accepting signals and join every worker thread. Does not touch
    /// any `Handoff`: callers drain/shutdown each connection's handoff
    /// independently and must do so before (or without caring about) this
    /// call, since a worker mid-`execute_fn` keeps running until it returns.
    pub fn shutdownAndJoin(self: *Executor) void {
        if (builtin.single_threaded) return;
        self.mutex.lock();
        self.shutting_down = true;
        self.mutex.unlock();
        self.cond.broadcast();
        for (self.threads) |t| t.join();
        self.allocator.free(self.threads);
        self.queue.deinit(self.allocator);
        self.* = undefined;
    }
};

test "H2 request executor runs the execute callback for a submitted signal" {
    const Counter = struct {
        mutex: compat.Mutex = .{},
        cond: compat.Condition = .{},
        calls: usize = 0,

        fn run(ctx: *anyopaque, handoff: *h2_request_handoff.Handoff) void {
            _ = handoff;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.mutex.lock();
            self.calls += 1;
            self.cond.broadcast();
            self.mutex.unlock();
        }

        fn waitForCalls(self: *@This(), expected: usize) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            while (self.calls < expected) self.cond.wait(&self.mutex);
        }
    };
    var counter = Counter{};
    var executor: Executor = undefined;
    try executor.init(std.testing.allocator, 2, 4, Counter.run, &counter);
    defer executor.shutdownAndJoin();

    var handoff = try h2_request_handoff.Handoff.init(std.testing.allocator, 1);
    defer handoff.deinit();
    try executor.submitSignal(&handoff);
    try executor.submitSignal(&handoff);
    counter.waitForCalls(2);
}

test "H2 request executor bounds its queue" {
    const Blocker = struct {
        mutex: compat.Mutex = .{},
        cond: compat.Condition = .{},
        release: bool = false,
        started: bool = false,

        fn run(ctx: *anyopaque, handoff: *h2_request_handoff.Handoff) void {
            _ = handoff;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.mutex.lock();
            self.started = true;
            self.cond.broadcast();
            while (!self.release) self.cond.wait(&self.mutex);
            self.mutex.unlock();
        }

        fn waitStarted(self: *@This()) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            while (!self.started) self.cond.wait(&self.mutex);
        }

        fn releaseAll(self: *@This()) void {
            self.mutex.lock();
            self.release = true;
            self.cond.broadcast();
            self.mutex.unlock();
        }
    };
    var blocker = Blocker{};
    var executor: Executor = undefined;
    try executor.init(std.testing.allocator, 1, 1, Blocker.run, &blocker);
    defer {
        blocker.releaseAll();
        executor.shutdownAndJoin();
    }

    var handoff_a = try h2_request_handoff.Handoff.init(std.testing.allocator, 1);
    defer handoff_a.deinit();
    var handoff_b = try h2_request_handoff.Handoff.init(std.testing.allocator, 1);
    defer handoff_b.deinit();

    // The one worker picks this up and blocks inside `run`, so the queue
    // itself is empty again once `waitStarted` returns.
    try executor.submitSignal(&handoff_a);
    blocker.waitStarted();
    try executor.submitSignal(&handoff_b);
    try std.testing.expectError(error.QueueFull, executor.submitSignal(&handoff_a));
}
