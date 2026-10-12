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

pub const Error = error{ QueueFull, Detached };

/// Invoked on a worker thread with exactly one handoff known to have at least
/// one job ready. Must call `handoff.takeJob()` and eventually
/// `handoff.finish()` for whatever it takes; a null `takeJob()` result (the
/// job was already drained by a prior signal) is a normal no-op.
pub const ExecuteFn = *const fn (ctx: *anyopaque, handoff: *h2_request_handoff.Handoff) void;

pub const Executor = struct {
    const Signal = struct {
        handoff: *h2_request_handoff.Handoff,
        stream_id: u31,
    };

    allocator: std.mem.Allocator,
    threads: if (builtin.single_threaded) [0]std.Thread else []std.Thread,
    mutex: compat.Mutex = .{},
    cond: compat.Condition = .{},
    callback_cond: compat.Condition = .{},
    queue: std.ArrayList(Signal) = .empty,
    /// A callback is recorded here while it can dereference its handoff,
    /// including the small interval after queue removal and before execute_fn.
    /// `detachAndDrain` waits for this list to lose the target handoff.
    active_callbacks: std.ArrayList(*h2_request_handoff.Handoff) = .empty,
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
        try self.active_callbacks.ensureTotalCapacity(allocator, thread_count);
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
    pub fn submitSignal(self: *Executor, handoff: *h2_request_handoff.Handoff, stream_id: u31) Error!void {
        if (builtin.single_threaded) {
            if (handoff.executor_detached) return error.Detached;
            self.execute_fn(self.execute_ctx, handoff);
            return;
        }
        self.mutex.lock();
        if (handoff.executor_detached) {
            self.mutex.unlock();
            return error.Detached;
        }
        if (self.shutting_down or self.queue.items.len >= self.max_queue_len) {
            self.mutex.unlock();
            return error.QueueFull;
        }
        self.queue.appendAssumeCapacity(.{ .handoff = handoff, .stream_id = stream_id });
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
            const signal = self.queue.orderedRemove(0);
            self.active_callbacks.appendAssumeCapacity(signal.handoff);
            self.mutex.unlock();
            self.execute_fn(self.execute_ctx, signal.handoff);
            self.mutex.lock();
            for (self.active_callbacks.items, 0..) |handoff, index| {
                if (handoff == signal.handoff) {
                    _ = self.active_callbacks.orderedRemove(index);
                    break;
                }
            }
            self.callback_cond.broadcast();
            self.mutex.unlock();
        }
    }

    /// Prevent new callbacks for `handoff`, discard signals that have not
    /// started, and wait for callbacks that have already popped a signal.
    /// The caller may safely deinitialize the handoff only after this returns.
    pub fn detachAndDrain(self: *Executor, handoff: *h2_request_handoff.Handoff) void {
        if (builtin.single_threaded) {
            handoff.executor_detached = true;
            return;
        }
        self.mutex.lock();
        handoff.executor_detached = true;
        var index: usize = 0;
        while (index < self.queue.items.len) {
            if (self.queue.items[index].handoff == handoff) {
                _ = self.queue.orderedRemove(index);
                continue;
            }
            index += 1;
        }
        while (self.hasActiveCallbackLocked(handoff)) self.callback_cond.wait(&self.mutex);
        self.mutex.unlock();
    }

    /// Reclaim a cancelled stream's queued process-wide capacity immediately.
    /// A callback that already popped the signal remains safe: Handoff
    /// cancellation makes `takeJob` a no-op (or marks its active lease).
    pub fn cancelStreamSignals(self: *Executor, handoff: *h2_request_handoff.Handoff, stream_id: u31) void {
        if (builtin.single_threaded) return;
        self.mutex.lock();
        var index: usize = 0;
        while (index < self.queue.items.len) {
            const signal = self.queue.items[index];
            if (signal.handoff == handoff and signal.stream_id == stream_id) {
                _ = self.queue.orderedRemove(index);
                continue;
            }
            index += 1;
        }
        self.mutex.unlock();
    }

    fn hasActiveCallbackLocked(self: *const Executor, handoff: *h2_request_handoff.Handoff) bool {
        for (self.active_callbacks.items) |active| if (active == handoff) return true;
        return false;
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
        self.active_callbacks.deinit(self.allocator);
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
    try executor.submitSignal(&handoff, 1);
    try executor.submitSignal(&handoff, 1);
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
    try executor.submitSignal(&handoff_a, 1);
    blocker.waitStarted();
    try executor.submitSignal(&handoff_b, 3);
    try std.testing.expectError(error.QueueFull, executor.submitSignal(&handoff_a, 1));

    // Resetting B reclaims its queued process-wide slot immediately instead
    // of making a later sibling wait for a worker to discard a stale signal.
    executor.cancelStreamSignals(&handoff_b, 3);
    try executor.submitSignal(&handoff_a, 5);
}

test "H2 request executor detaches queued handoffs before teardown" {
    const Blocker = struct {
        mutex: compat.Mutex = .{},
        cond: compat.Condition = .{},
        release: bool = false,
        started_a: bool = false,
        calls_b: usize = 0,
        handoff_a: *h2_request_handoff.Handoff,
        handoff_b: *h2_request_handoff.Handoff,

        fn run(ctx: *anyopaque, handoff: *h2_request_handoff.Handoff) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.mutex.lock();
            if (handoff == self.handoff_a) {
                self.started_a = true;
                self.cond.broadcast();
                while (!self.release) self.cond.wait(&self.mutex);
            } else if (handoff == self.handoff_b) {
                self.calls_b += 1;
            }
            self.mutex.unlock();
        }
        fn waitStartedA(self: *@This()) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            while (!self.started_a) self.cond.wait(&self.mutex);
        }

        fn releaseA(self: *@This()) void {
            self.mutex.lock();
            self.release = true;
            self.cond.broadcast();
            self.mutex.unlock();
        }
    };

    var handoff_a = try h2_request_handoff.Handoff.init(std.testing.allocator, 1);
    defer handoff_a.deinit();
    var handoff_b = try h2_request_handoff.Handoff.init(std.testing.allocator, 1);
    var blocker = Blocker{ .handoff_a = &handoff_a, .handoff_b = &handoff_b };
    var executor: Executor = undefined;
    try executor.init(std.testing.allocator, 1, 2, Blocker.run, &blocker);
    defer executor.shutdownAndJoin();

    try executor.submitSignal(&handoff_a, 1);
    blocker.waitStartedA();
    try executor.submitSignal(&handoff_b, 3);

    // This is the teardown sequence used by the connection owner. The B
    // signal is removed while A keeps the sole worker blocked; releasing A
    // must not invoke B after B's connection-owned handoff is gone.
    handoff_b.shutdown();
    executor.detachAndDrain(&handoff_b);
    handoff_b.waitForActiveDrain();
    handoff_b.deinit();
    blocker.releaseA();
    while (true) {
        blocker.mutex.lock();
        const released = blocker.release;
        const calls_b = blocker.calls_b;
        blocker.mutex.unlock();
        if (released) {
            try std.testing.expectEqual(@as(usize, 0), calls_b);
            break;
        }
    }
}
