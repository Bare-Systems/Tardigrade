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

pub const Error = error{ QueueFull, Closed } || std.mem.Allocator.Error;

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
    stream_id: u31,
    payload: *anyopaque,
    deinit_fn: *const fn (payload: *anyopaque) void,

    pub fn deinit(self: Completion) void {
        self.deinit_fn(self.payload);
    }
};

const Entry = struct {
    job: Job,
    cancelled: bool = false,
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
    completions: std.ArrayList(Completion) = .empty,
    outstanding: usize = 0,
    closed: bool = false,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) Handoff {
        return .{ .allocator = allocator, .capacity = capacity };
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
        self.mutex.unlock();

        for (pending.items) |entry| {
            entry.job.deinit();
            self.allocator.destroy(entry);
        }
        pending.deinit(self.allocator);
        for (completions.items) |completion| completion.deinit();
        completions.deinit(self.allocator);
    }

    pub fn deinit(self: *Handoff) void {
        self.shutdown();
        self.mutex.lock();
        std.debug.assert(self.active.items.len == 0);
        self.pending.deinit(self.allocator);
        self.active.deinit(self.allocator);
        self.completions.deinit(self.allocator);
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
        try self.pending.append(self.allocator, entry);
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
        self.active.append(self.allocator, entry) catch unreachable;
        return .{ .handoff = self, .entry = entry };
    }

    /// Finish an active request. A cancellation racing completion wins: the
    /// completion is released and cannot reach the downstream H2 writer.
    pub fn finish(self: *Handoff, lease: *Lease, completion: ?Completion) FinishResult {
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
            self.completions.append(self.allocator, completion.?) catch unreachable;
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
    pub fn cancelStream(self: *Handoff, stream_id: u31) CancelResult {
        var removed_jobs = std.ArrayList(*Entry).empty;
        var removed_completions = std.ArrayList(Completion).empty;
        var result = CancelResult{};

        self.mutex.lock();
        var index: usize = 0;
        while (index < self.pending.items.len) {
            const entry = self.pending.items[index];
            if (entry.job.stream_id == stream_id) {
                removed_jobs.append(self.allocator, self.pending.orderedRemove(index)) catch unreachable;
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
                removed_completions.append(self.allocator, self.completions.orderedRemove(index)) catch unreachable;
                self.outstanding -= 1;
                result.completions += 1;
                continue;
            }
            index += 1;
        }
        self.mutex.unlock();

        for (removed_jobs.items) |entry| {
            entry.job.deinit();
            self.allocator.destroy(entry);
        }
        removed_jobs.deinit(self.allocator);
        for (removed_completions.items) |completion| completion.deinit();
        removed_completions.deinit(self.allocator);
        return result;
    }

    /// Transfer one response intent to the connection runtime. The caller now
    /// owns it and must call `Completion.deinit` after serialization or drop.
    pub fn takeCompletion(self: *Handoff) ?Completion {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.completions.items.len == 0) return null;
        self.outstanding -= 1;
        return self.completions.orderedRemove(0);
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
};

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
    var handoff = Handoff.init(std.testing.allocator, 2);
    defer handoff.deinit();

    try handoff.submit(.{ .stream_id = 1, .payload = &counter, .deinit_fn = Counter.dropJob });
    try handoff.submit(.{ .stream_id = 3, .payload = &counter, .deinit_fn = Counter.dropJob });
    try std.testing.expectError(error.QueueFull, handoff.submit(.{ .stream_id = 5, .payload = &counter, .deinit_fn = Counter.dropJob }));

    var first = handoff.takeJob().?;
    var second = handoff.takeJob().?;
    try std.testing.expectEqual(@as(u31, 1), first.streamId());
    try std.testing.expectEqual(@as(u31, 3), second.streamId());
    try std.testing.expectEqual(FinishResult.delivered, handoff.finish(&first, .{ .stream_id = 1, .payload = &counter, .deinit_fn = Counter.dropCompletion }));
    try std.testing.expectEqual(FinishResult.delivered, handoff.finish(&second, .{ .stream_id = 3, .payload = &counter, .deinit_fn = Counter.dropCompletion }));
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
    var handoff = Handoff.init(std.testing.allocator, 2);
    defer handoff.deinit();

    try handoff.submit(.{ .stream_id = 1, .payload = &counter, .deinit_fn = Counter.dropJob });
    const queued_cancel = handoff.cancelStream(1);
    try std.testing.expectEqual(@as(usize, 1), queued_cancel.pending_jobs);
    try std.testing.expect(handoff.takeJob() == null);

    try handoff.submit(.{ .stream_id = 3, .payload = &counter, .deinit_fn = Counter.dropJob });
    var running = handoff.takeJob().?;
    const running_cancel = handoff.cancelStream(3);
    try std.testing.expectEqual(@as(usize, 1), running_cancel.running_jobs);
    try std.testing.expect(running.isCancelled());
    try std.testing.expectEqual(FinishResult.cancelled, handoff.finish(&running, .{ .stream_id = 3, .payload = &counter, .deinit_fn = Counter.dropCompletion }));
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
    var handoff = Handoff.init(std.testing.allocator, 2);
    defer handoff.deinit();

    try handoff.submit(.{ .stream_id = 1, .payload = &counter, .deinit_fn = Counter.dropJob });
    var complete = handoff.takeJob().?;
    _ = handoff.finish(&complete, .{ .stream_id = 1, .payload = &counter, .deinit_fn = Counter.dropCompletion });
    const completion_cancel = handoff.cancelStream(1);
    try std.testing.expectEqual(@as(usize, 1), completion_cancel.completions);

    try handoff.submit(.{ .stream_id = 3, .payload = &counter, .deinit_fn = Counter.dropJob });
    var running = handoff.takeJob().?;
    handoff.shutdown();
    try std.testing.expect(running.isCancelled());
    try std.testing.expectEqual(FinishResult.cancelled, handoff.finish(&running, .{ .stream_id = 3, .payload = &counter, .deinit_fn = Counter.dropCompletion }));
    try std.testing.expectError(error.Closed, handoff.submit(.{ .stream_id = 5, .payload = &counter, .deinit_fn = Counter.dropJob }));
    try std.testing.expectEqual(@as(usize, 2), counter.jobs);
    try std.testing.expectEqual(@as(usize, 2), counter.completions);
}
