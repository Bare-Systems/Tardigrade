//! Bounded ownership handoff for finite downstream HTTP/2 requests (#866).
//!
//! The HTTP/2 connection runtime remains the owner of protocol state.  A
//! future request executor takes a `Job` from this queue, performs application
//! work without the connection socket, and returns a `Completion` for the
//! runtime to serialize.  This module deliberately does not execute jobs:
//! keeping execution separate makes cancellation and the connection-owned
//! completion drain explicit at the call site.
const std = @import("std");
const compat = @import("zig_compat");

pub const Error = error{ QueueFull, Closed, WakeFailed } || std.mem.Allocator.Error;

/// Opaque, owned request state. `deinit` is called exactly once, either when
/// the job is cancelled before it starts or when its worker finishes.
pub const Job = struct {
    stream_id: u31,
    payload: *anyopaque,
    deinit_fn: *const fn (payload: *anyopaque) void,

    fn deinit(self: Job) void {
        self.deinit_fn(self.payload);
    }
};

/// Opaque, owned response intent. The connection runtime takes this value and
/// is responsible for serializing it through its outbound scheduler.
pub const Completion = struct {
    payload: *anyopaque,
    deinit_fn: *const fn (payload: *anyopaque) void,

    pub fn deinit(self: Completion) void {
        self.deinit_fn(self.payload);
    }
};

/// A completion whose stream routing identity was derived from its source
/// lease. Workers cannot choose this value.
pub const DeliveredCompletion = struct {
    stream_id: u31,
    completion: Completion,

    pub fn deinit(self: DeliveredCompletion) void {
        self.completion.deinit();
    }
};

const Entry = struct {
    job: Job,
    cancelled: bool = false,
};

const QueuedCompletion = struct {
    stream_id: u31,
    completion: Completion,
};

/// An in-flight job, owned by exactly one application worker.  The worker
/// must call `finish` once. `isCancelled` is safe to poll while the job runs;
/// cancellation never frees an active job's payload behind the worker.
pub const Lease = struct {
    handoff: *Handoff,
    entry: ?*Entry,

    pub fn streamId(self: *const Lease) u31 {
        return self.entry.?.job.stream_id;
    }

    /// The worker-owned request data. Cancellation only marks the lease, so
    /// this payload remains valid until the worker calls `finish`.
    pub fn jobPayload(self: *const Lease) *anyopaque {
        return self.entry.?.job.payload;
    }

    pub fn isCancelled(self: *const Lease) bool {
        const entry = self.entry orelse return true;
        self.handoff.mutex.lock();
        defer self.handoff.mutex.unlock();
        return self.handoff.closed or entry.cancelled;
    }
};

pub const FinishResult = enum {
    delivered,
    cancelled,
    already_finished,
};

pub const CancelResult = struct {
    pending_jobs: usize = 0,
    running_jobs: usize = 0,
    completions: usize = 0,
};

/// A connection-scoped, bounded transfer point between protocol ownership and
/// application execution. `capacity` bounds every request that is pending,
/// active, or awaiting connection-side completion; a worker completion simply
/// replaces its active job, so a completed response can never overflow a
/// separate unbounded queue.
pub const Handoff = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    mutex: compat.Mutex = .{},
    pending: std.ArrayList(*Entry) = .empty,
    active: std.ArrayList(*Entry) = .empty,
    completions: std.ArrayList(QueuedCompletion) = .empty,
    outstanding: usize = 0,
    closed: bool = false,
    wake_read: std.posix.fd_t = -1,
    wake_write: std.posix.fd_t = -1,
    wake_pending: bool = false,

    /// Pre-reserve each bounded state queue. Every ownership transition after
    /// this succeeds without allocation, so allocator pressure can reject a
    /// new job but cannot lose a job already accepted by the handoff.
    pub fn init(allocator: std.mem.Allocator, capacity: usize) Error!Handoff {
        var handoff = Handoff{ .allocator = allocator, .capacity = capacity };
        errdefer handoff.pending.deinit(allocator);
        try handoff.pending.ensureTotalCapacity(allocator, capacity);
        errdefer handoff.active.deinit(allocator);
        try handoff.active.ensureTotalCapacity(allocator, capacity);
        errdefer handoff.completions.deinit(allocator);
        try handoff.completions.ensureTotalCapacity(allocator, capacity);

        var fds: [2]std.posix.fd_t = undefined;
        if (std.c.pipe(&fds) != 0) return error.WakeFailed;
        errdefer {
            _ = std.c.close(fds[0]);
            _ = std.c.close(fds[1]);
        }
        try setNonBlocking(fds[0]);
        try setNonBlocking(fds[1]);
        handoff.wake_read = fds[0];
        handoff.wake_write = fds[1];
        return handoff;
    }

    /// Stop accepting work, cancel queued work and response intents, and mark
    /// active workers cancelled. The owner must join/finish active workers
    /// before calling `deinit`.
    pub fn shutdown(self: *Handoff) void {
        self.mutex.lock();
        self.closed = true;
        var pending = self.pending;
        self.pending = .empty;
        var completions = self.completions;
        self.completions = .empty;
        self.outstanding -= pending.items.len + completions.items.len;
        for (self.active.items) |entry| entry.cancelled = true;
        self.clearWakeLocked();
        self.mutex.unlock();

        for (pending.items) |entry| {
            entry.job.deinit();
            self.allocator.destroy(entry);
        }
        pending.deinit(self.allocator);
        for (completions.items) |completion| completion.completion.deinit();
        completions.deinit(self.allocator);
    }

    pub fn deinit(self: *Handoff) void {
        self.shutdown();
        self.mutex.lock();
        std.debug.assert(self.active.items.len == 0);
        self.pending.deinit(self.allocator);
        self.active.deinit(self.allocator);
        self.completions.deinit(self.allocator);
        if (self.wake_read >= 0) _ = std.c.close(self.wake_read);
        if (self.wake_write >= 0) _ = std.c.close(self.wake_write);
        self.mutex.unlock();
        self.* = undefined;
    }

    /// Transfer request ownership to the handoff. A full handoff leaves the
    /// caller responsible for `job` so it can produce a stream-local refusal.
    pub fn submit(self: *Handoff, job: Job) Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.closed) return error.Closed;
        if (self.outstanding >= self.capacity) return error.QueueFull;
        const entry = try self.allocator.create(Entry);
        errdefer self.allocator.destroy(entry);
        entry.* = .{ .job = job };
        self.pending.appendAssumeCapacity(entry);
        self.outstanding += 1;
    }

    /// Hand one queued request to an application worker. A null result means
    /// no worker-safe job is available; it never means a cancellation was
    /// silently converted into a response.
    pub fn takeJob(self: *Handoff) ?Lease {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.closed or self.pending.items.len == 0) return null;
        const entry = self.pending.orderedRemove(0);
        self.active.appendAssumeCapacity(entry);
        return .{ .handoff = self, .entry = entry };
    }

    /// Finish an active request. A cancellation racing completion wins: the
    /// completion is released and cannot reach the downstream H2 writer.
    pub fn finish(self: *Handoff, lease: *Lease, completion: ?Completion) Error!FinishResult {
        const entry = lease.entry orelse {
            if (completion) |value| value.deinit();
            return .already_finished;
        };
        std.debug.assert(lease.handoff == self);

        self.mutex.lock();
        const active_index = self.activeIndexLocked(entry) orelse {
            self.mutex.unlock();
            if (completion) |value| value.deinit();
            lease.entry = null;
            return .already_finished;
        };
        _ = self.active.orderedRemove(active_index);
        const cancelled = self.closed or entry.cancelled;
        if (!cancelled and completion != null) {
            self.signalWakeLocked() catch |err| {
                self.outstanding -= 1;
                self.mutex.unlock();
                entry.job.deinit();
                self.allocator.destroy(entry);
                lease.entry = null;
                completion.?.deinit();
                return err;
            };
            self.completions.appendAssumeCapacity(.{
                .stream_id = entry.job.stream_id,
                .completion = completion.?,
            });
        } else {
            self.outstanding -= 1;
        }
        self.mutex.unlock();

        entry.job.deinit();
        self.allocator.destroy(entry);
        lease.entry = null;
        if (cancelled) {
            if (completion) |value| value.deinit();
            return .cancelled;
        }
        return .delivered;
    }

    /// Cancel one stream on RST_STREAM, GOAWAY selection, or connection-side
    /// shutdown. Queued jobs and response intents are released immediately;
    /// active jobs are only marked so their worker keeps ownership until it
    /// reaches `finish`.
    pub fn cancelStream(self: *Handoff, stream_id: u31) Error!CancelResult {
        // Reserve before mutating live ownership. A cancellation that cannot
        // acquire bounded cleanup storage reports OOM without dropping a job.
        var removed_jobs = try std.ArrayList(*Entry).initCapacity(self.allocator, self.capacity);
        defer removed_jobs.deinit(self.allocator);
        var removed_completions = try std.ArrayList(QueuedCompletion).initCapacity(self.allocator, self.capacity);
        defer removed_completions.deinit(self.allocator);
        var result = CancelResult{};

        self.mutex.lock();
        var index: usize = 0;
        while (index < self.pending.items.len) {
            const entry = self.pending.items[index];
            if (entry.job.stream_id == stream_id) {
                removed_jobs.appendAssumeCapacity(self.pending.orderedRemove(index));
                self.outstanding -= 1;
                result.pending_jobs += 1;
                continue;
            }
            index += 1;
        }
        for (self.active.items) |entry| {
            if (entry.job.stream_id == stream_id) {
                entry.cancelled = true;
                result.running_jobs += 1;
            }
        }
        index = 0;
        while (index < self.completions.items.len) {
            if (self.completions.items[index].stream_id == stream_id) {
                removed_completions.appendAssumeCapacity(self.completions.orderedRemove(index));
                self.outstanding -= 1;
                result.completions += 1;
                continue;
            }
            index += 1;
        }
        if (self.completions.items.len == 0) self.clearWakeLocked();
        self.mutex.unlock();

        for (removed_jobs.items) |entry| {
            entry.job.deinit();
            self.allocator.destroy(entry);
        }
        for (removed_completions.items) |completion| completion.completion.deinit();
        return result;
    }

    /// Transfer one response intent to the connection runtime. The caller now
    /// owns it and must call `Completion.deinit` after serialization or drop.
    pub fn takeCompletion(self: *Handoff) ?DeliveredCompletion {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.completions.items.len == 0) return null;
        self.outstanding -= 1;
        const queued = self.completions.orderedRemove(0);
        if (self.completions.items.len == 0) self.clearWakeLocked();
        return .{ .stream_id = queued.stream_id, .completion = queued.completion };
    }

    /// Pollable completion readiness. A worker only writes this notification;
    /// the connection owner still drains and serializes every response intent.
    pub fn wakeFd(self: *const Handoff) std.posix.fd_t {
        return self.wake_read;
    }

    pub fn outstandingCount(self: *Handoff) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.outstanding;
    }

    fn activeIndexLocked(self: *Handoff, needle: *Entry) ?usize {
        for (self.active.items, 0..) |entry, index| {
            if (entry == needle) return index;
        }
        return null;
    }

    fn signalWakeLocked(self: *Handoff) Error!void {
        if (self.wake_pending) return;
        const byte = [_]u8{1};
        while (true) {
            const n = std.c.write(self.wake_write, &byte, 1);
            if (n == 1) {
                self.wake_pending = true;
                return;
            }
            if (n < 0 and std.posix.errno(n) == .INTR) continue;
            // A full non-blocking pipe already has a readable notification;
            // treat it as a coalesced wake rather than failing the response.
            if (n < 0 and std.posix.errno(n) == .AGAIN) {
                self.wake_pending = true;
                return;
            }
            return error.WakeFailed;
        }
    }

    fn clearWakeLocked(self: *Handoff) void {
        if (drainWake(.{ .ctx = self, .read_fn = readWakeC }, self.wake_read)) {
            self.wake_pending = false;
        }
    }
};

const WakeReadResult = union(enum) {
    bytes: usize,
    eof,
    interrupted,
    would_block,
    failed,
};

const WakeReader = struct {
    ctx: *anyopaque,
    read_fn: *const fn (ctx: *anyopaque, fd: std.posix.fd_t, bytes: []u8) WakeReadResult,

    fn read(self: WakeReader, fd: std.posix.fd_t, bytes: []u8) WakeReadResult {
        return self.read_fn(self.ctx, fd, bytes);
    }
};

/// Drain a coalesced wake notification. An interrupted read did not consume a
/// byte, so only EOF or a non-blocking empty read proves the wake fd is clear.
fn drainWake(reader: WakeReader, fd: std.posix.fd_t) bool {
    var bytes: [64]u8 = undefined;
    while (true) {
        switch (reader.read(fd, &bytes)) {
            .bytes => continue,
            .interrupted => continue,
            .eof, .would_block => return true,
            .failed => return false,
        }
    }
}

fn readWakeC(_: *anyopaque, fd: std.posix.fd_t, bytes: []u8) WakeReadResult {
    const n = std.c.read(fd, bytes.ptr, bytes.len);
    if (n > 0) return .{ .bytes = @intCast(n) };
    if (n == 0) return .eof;
    return switch (std.posix.errno(n)) {
        .INTR => .interrupted,
        .AGAIN => .would_block,
        else => .failed,
    };
}

fn setNonBlocking(fd: std.posix.fd_t) Error!void {
    const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (flags < 0 or std.c.fcntl(fd, std.c.F.SETFL, flags | @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }))) < 0)
        return error.WakeFailed;
}

test "H2 request handoff bounds jobs and preserves FIFO completion ownership" {
    const Counter = struct {
        jobs: usize = 0,
        completions: usize = 0,

        fn dropJob(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.jobs += 1;
        }
        fn dropCompletion(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.completions += 1;
        }
    };
    var counter = Counter{};
    var handoff = try Handoff.init(std.testing.allocator, 2);
    defer handoff.deinit();

    try handoff.submit(.{ .stream_id = 1, .payload = &counter, .deinit_fn = Counter.dropJob });
    try handoff.submit(.{ .stream_id = 3, .payload = &counter, .deinit_fn = Counter.dropJob });
    try std.testing.expectError(error.QueueFull, handoff.submit(.{ .stream_id = 5, .payload = &counter, .deinit_fn = Counter.dropJob }));

    var first = handoff.takeJob().?;
    var second = handoff.takeJob().?;
    try std.testing.expectEqual(@as(u31, 1), first.streamId());
    try std.testing.expectEqual(@as(u31, 3), second.streamId());
    try std.testing.expect(first.jobPayload() == @as(*anyopaque, @ptrCast(&counter)));
    try std.testing.expectEqual(FinishResult.delivered, try handoff.finish(&first, .{ .payload = &counter, .deinit_fn = Counter.dropCompletion }));
    try std.testing.expectEqual(FinishResult.delivered, try handoff.finish(&second, .{ .payload = &counter, .deinit_fn = Counter.dropCompletion }));
    try std.testing.expectEqual(@as(usize, 2), counter.jobs);

    const first_completion = handoff.takeCompletion().?;
    const second_completion = handoff.takeCompletion().?;
    try std.testing.expectEqual(@as(u31, 1), first_completion.stream_id);
    try std.testing.expectEqual(@as(u31, 3), second_completion.stream_id);
    first_completion.deinit();
    second_completion.deinit();
    try std.testing.expectEqual(@as(usize, 2), counter.completions);
    try std.testing.expectEqual(@as(usize, 0), handoff.outstandingCount());
}

test "H2 request handoff releases cancellation before and during execution exactly once" {
    const Counter = struct {
        jobs: usize = 0,
        completions: usize = 0,

        fn dropJob(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.jobs += 1;
        }
        fn dropCompletion(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.completions += 1;
        }
    };
    var counter = Counter{};
    var handoff = try Handoff.init(std.testing.allocator, 2);
    defer handoff.deinit();

    try handoff.submit(.{ .stream_id = 1, .payload = &counter, .deinit_fn = Counter.dropJob });
    const queued_cancel = try handoff.cancelStream(1);
    try std.testing.expectEqual(@as(usize, 1), queued_cancel.pending_jobs);
    try std.testing.expect(handoff.takeJob() == null);

    try handoff.submit(.{ .stream_id = 3, .payload = &counter, .deinit_fn = Counter.dropJob });
    var running = handoff.takeJob().?;
    const running_cancel = try handoff.cancelStream(3);
    try std.testing.expectEqual(@as(usize, 1), running_cancel.running_jobs);
    try std.testing.expect(running.isCancelled());
    try std.testing.expectEqual(FinishResult.cancelled, try handoff.finish(&running, .{ .payload = &counter, .deinit_fn = Counter.dropCompletion }));
    try std.testing.expect(handoff.takeCompletion() == null);
    try std.testing.expectEqual(@as(usize, 2), counter.jobs);
    try std.testing.expectEqual(@as(usize, 1), counter.completions);
    try std.testing.expectEqual(@as(usize, 0), handoff.outstandingCount());
}

test "H2 request handoff drops queued completion on reset and marks active work on shutdown" {
    const Counter = struct {
        jobs: usize = 0,
        completions: usize = 0,

        fn dropJob(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.jobs += 1;
        }
        fn dropCompletion(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.completions += 1;
        }
    };
    var counter = Counter{};
    var handoff = try Handoff.init(std.testing.allocator, 2);
    defer handoff.deinit();

    try handoff.submit(.{ .stream_id = 1, .payload = &counter, .deinit_fn = Counter.dropJob });
    var complete = handoff.takeJob().?;
    _ = try handoff.finish(&complete, .{ .payload = &counter, .deinit_fn = Counter.dropCompletion });
    const completion_cancel = try handoff.cancelStream(1);
    try std.testing.expectEqual(@as(usize, 1), completion_cancel.completions);

    try handoff.submit(.{ .stream_id = 3, .payload = &counter, .deinit_fn = Counter.dropJob });
    var running = handoff.takeJob().?;
    handoff.shutdown();
    try std.testing.expect(running.isCancelled());
    try std.testing.expectEqual(FinishResult.cancelled, try handoff.finish(&running, .{ .payload = &counter, .deinit_fn = Counter.dropCompletion }));
    try std.testing.expectError(error.Closed, handoff.submit(.{ .stream_id = 5, .payload = &counter, .deinit_fn = Counter.dropJob }));
    try std.testing.expectEqual(@as(usize, 2), counter.jobs);
    try std.testing.expectEqual(@as(usize, 2), counter.completions);
}

test "H2 request handoff moves accepted work without allocator activity" {
    const Counter = struct {
        jobs: usize = 0,
        fn dropJob(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.jobs += 1;
        }
    };
    var counter = Counter{};
    // Handoff initialization reserves three arrays; submitting one job owns
    // the fourth allocation. The fifth allocation is deliberately withheld,
    // so `takeJob` would panic under the old post-transfer append shape.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 4 });
    var handoff = try Handoff.init(failing.allocator(), 1);
    defer handoff.deinit();
    try handoff.submit(.{ .stream_id = 1, .payload = &counter, .deinit_fn = Counter.dropJob });
    var lease = handoff.takeJob().?;
    try std.testing.expectError(error.OutOfMemory, handoff.cancelStream(9));
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(FinishResult.delivered, try handoff.finish(&lease, null));
    try std.testing.expectEqual(@as(usize, 1), counter.jobs);
}

test "H2 request handoff wake drain retries interrupted reads" {
    const Script = struct {
        step: usize = 0,

        fn read(raw: *anyopaque, _: std.posix.fd_t, _: []u8) WakeReadResult {
            const self: *@This() = @ptrCast(@alignCast(raw));
            defer self.step += 1;
            return switch (self.step) {
                0 => .interrupted,
                1 => .{ .bytes = 1 },
                else => .would_block,
            };
        }
    };
    var script = Script{};
    try std.testing.expect(drainWake(.{ .ctx = &script, .read_fn = Script.read }, -1));
    try std.testing.expectEqual(@as(usize, 3), script.step);
}

test "H2 request handoff wakes blocked connection owner and rearms" {
    const Counter = struct {
        jobs: usize = 0,
        completions: usize = 0,

        fn dropJob(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.jobs += 1;
        }
        fn dropCompletion(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.completions += 1;
        }
    };
    const Worker = struct {
        handoff: *Handoff,
        lease: *Lease,
        counter: *Counter,

        fn run(self: *@This()) void {
            _ = self.handoff.finish(self.lease, .{
                .payload = self.counter,
                .deinit_fn = Counter.dropCompletion,
            }) catch @panic("completion handoff failed");
        }
    };
    const Waiter = struct {
        handoff: *Handoff,
        mutex: compat.Mutex = .{},
        cond: compat.Condition = .{},
        entered_poll: bool = false,
        woke: bool = false,

        fn run(self: *@This()) void {
            self.mutex.lock();
            // This is deliberately the instruction immediately before the
            // blocking poll, so the test releases a worker only after the
            // connection owner is poised to block.
            self.entered_poll = true;
            self.cond.broadcast();
            self.mutex.unlock();

            var fds = [_]std.posix.pollfd{.{ .fd = self.handoff.wakeFd(), .events = std.posix.POLL.IN, .revents = 0 }};
            const ready = std.posix.poll(&fds, 1_000) catch @panic("wake poll failed");
            self.mutex.lock();
            self.woke = ready == 1 and (fds[0].revents & std.posix.POLL.IN) != 0;
            self.cond.broadcast();
            self.mutex.unlock();
        }

        fn waitUntilEntered(self: *@This()) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            while (!self.entered_poll) self.cond.wait(&self.mutex);
        }
    };

    var counter = Counter{};
    var handoff = try Handoff.init(std.testing.allocator, 1);
    defer handoff.deinit();
    try handoff.submit(.{ .stream_id = 7, .payload = &counter, .deinit_fn = Counter.dropJob });
    var first_lease = handoff.takeJob().?;
    var first_waiter = Waiter{ .handoff = &handoff };
    const first_wait_thread = try std.Thread.spawn(.{}, Waiter.run, .{&first_waiter});
    first_waiter.waitUntilEntered();
    var first_worker = Worker{ .handoff = &handoff, .lease = &first_lease, .counter = &counter };
    const first_worker_thread = try std.Thread.spawn(.{}, Worker.run, .{&first_worker});
    first_worker_thread.join();
    first_wait_thread.join();
    try std.testing.expect(first_waiter.woke);
    const first = handoff.takeCompletion().?;
    try std.testing.expectEqual(@as(u31, 7), first.stream_id);
    first.deinit();

    // Draining clears `wake_pending`. A second completion must write a fresh
    // wake byte and unblock another connection-owner poll.
    try handoff.submit(.{ .stream_id = 9, .payload = &counter, .deinit_fn = Counter.dropJob });
    var second_lease = handoff.takeJob().?;
    var second_waiter = Waiter{ .handoff = &handoff };
    const second_wait_thread = try std.Thread.spawn(.{}, Waiter.run, .{&second_waiter});
    second_waiter.waitUntilEntered();
    var second_worker = Worker{ .handoff = &handoff, .lease = &second_lease, .counter = &counter };
    const second_worker_thread = try std.Thread.spawn(.{}, Worker.run, .{&second_worker});
    second_worker_thread.join();
    second_wait_thread.join();
    try std.testing.expect(second_waiter.woke);
    const second = handoff.takeCompletion().?;
    try std.testing.expectEqual(@as(u31, 9), second.stream_id);
    second.deinit();
    try std.testing.expectEqual(@as(usize, 2), counter.jobs);
    try std.testing.expectEqual(@as(usize, 2), counter.completions);
}
