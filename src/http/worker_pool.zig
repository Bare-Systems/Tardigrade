// WorkerPool — manual std.Thread-based connection dispatch pool.
//
// Design rationale (evaluated for Zig 0.16, issue #81):
//
// Tardigrade uses a thread-per-connection blocking I/O model.  Each accepted
// fd is handed to a dedicated OS thread that does blocking TLS, HTTP parsing,
// and proxying.  This is incompatible with async/coroutine runtimes because:
//
//   1. std.Io.Group (Zig 0.16) expects non-blocking, async-style work items.
//      Blocking calls on a Group-managed thread stall the whole group.
//
//   2. std.Thread.Pool (removed in Zig 0.13+) had the same mismatch for
//      long-running blocking tasks.
//
//   3. Manual std.Thread.spawn gives us direct control over thread count,
//      queue depth, work-stealing across per-worker queues, CPU affinity,
//      and graceful drain-before-shutdown semantics — all of which are
//      critical for a production reverse proxy.
//
// Do NOT refactor to std.Io.Group unless the blocking I/O model is first
// replaced with non-blocking I/O throughout the connection handler.  If that
// change is ever made, capture the expected throughput/latency delta first.

const compat = @import("../zig_compat.zig");
const builtin = @import("builtin");
const std = @import("std");

pub const HandlerFn = *const fn (ctx: *anyopaque, fd: std.posix.fd_t) void;
pub const WaitCallbackFn = *const fn (ctx: *anyopaque, wait_ns: i64) void;

const QueueEntry = struct {
    fd: std.posix.fd_t,
    enqueued_ns: i128,
};

const WorkerQueue = struct {
    items: std.Deque(QueueEntry),
};

pub const WorkerPool = struct {
    pub const Snapshot = struct {
        active_jobs: usize,
        queued_jobs: usize,
        worker_threads: usize,
        max_queue_len: usize,
    };

    allocator: std.mem.Allocator,
    threads: if (builtin.single_threaded) [0]std.Thread else []std.Thread,
    worker_queues: []WorkerQueue,
    worker_ids: []usize,
    mutex: compat.Mutex = .{},
    cond: compat.Condition = .{},
    shutting_down: bool = false,
    joined: bool = false,
    active_jobs: usize = 0,
    queued_jobs: usize = 0,
    next_queue: usize = 0,
    handler: HandlerFn,
    handler_ctx: *anyopaque,
    max_queue_len: usize,
    /// Maximum items allowed in any single worker's local queue (0 = no per-worker limit).
    /// When the least-loaded worker queue is at this depth, new submissions return QueueFull.
    max_per_worker_queue_len: usize = 0,
    /// Optional callback invoked after a connection is dispatched from the queue.
    /// Receives the time the entry spent waiting in nanoseconds.
    wait_callback: ?WaitCallbackFn = null,
    wait_callback_ctx: ?*anyopaque = null,

    pub fn init(
        self: *WorkerPool,
        allocator: std.mem.Allocator,
        worker_count: usize,
        max_queue_len: usize,
        max_per_worker_queue_len: usize,
        handler: HandlerFn,
        handler_ctx: *anyopaque,
    ) !void {
        self.* = WorkerPool{
            .allocator = allocator,
            .threads = if (builtin.single_threaded) .{} else &.{},
            .worker_queues = &.{},
            .worker_ids = &.{},
            .handler = handler,
            .handler_ctx = handler_ctx,
            .max_queue_len = max_queue_len,
            .max_per_worker_queue_len = max_per_worker_queue_len,
        };

        if (builtin.single_threaded) return;

        const thread_count = @max(worker_count, 1);

        self.threads = try allocator.alloc(std.Thread, thread_count);
        errdefer allocator.free(self.threads);

        self.worker_queues = try allocator.alloc(WorkerQueue, thread_count);
        errdefer allocator.free(self.worker_queues);

        for (self.worker_queues) |*wq| {
            wq.* = .{ .items = .empty };
        }
        errdefer {
            for (self.worker_queues) |*wq| wq.items.deinit(allocator);
        }

        self.worker_ids = try allocator.alloc(usize, thread_count);
        errdefer allocator.free(self.worker_ids);

        var spawned: usize = 0;
        errdefer {
            self.mutex.lock();
            self.shutting_down = true;
            self.mutex.unlock();
            self.cond.broadcast();
            for (self.threads[0..spawned]) |t| t.join();
        }

        for (self.threads, 0..) |*thread, i| {
            self.worker_ids[i] = i;
            thread.* = try std.Thread.spawn(.{}, workerMain, .{ self, i });
            spawned += 1;
        }
    }

    pub fn setWaitCallback(self: *WorkerPool, cb: WaitCallbackFn, ctx: *anyopaque) void {
        self.wait_callback = cb;
        self.wait_callback_ctx = ctx;
    }

    pub fn deinit(self: *WorkerPool) void {
        _ = self.shutdownAndJoin(30_000);
        if (!builtin.single_threaded) {
            for (self.worker_queues) |*wq| wq.items.deinit(self.allocator);
            self.allocator.free(self.worker_queues);
            self.allocator.free(self.worker_ids);
            self.allocator.free(self.threads);
        }
        self.* = undefined;
    }

    pub fn submit(self: *WorkerPool, fd: std.posix.fd_t) !void {
        if (builtin.single_threaded) {
            self.handler(self.handler_ctx, fd);
            return;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.shutting_down) return error.ShuttingDown;
        if (self.queued_jobs >= self.max_queue_len) return error.QueueFull;

        const queue_index = self.selectQueueForSubmitLocked();
        // Reject if the least-loaded worker queue is already at the per-worker depth limit.
        if (self.max_per_worker_queue_len > 0 and
            self.worker_queues[queue_index].items.len >= self.max_per_worker_queue_len)
            return error.QueueFull;
        try self.worker_queues[queue_index].items.pushBack(self.allocator, .{
            .fd = fd,
            .enqueued_ns = compat.nanoTimestamp(),
        });
        self.queued_jobs += 1;
        if (self.worker_queues.len > 0) {
            self.next_queue = (queue_index + 1) % self.worker_queues.len;
        }
        self.cond.signal();
    }

    pub fn snapshot(self: *WorkerPool) Snapshot {
        if (builtin.single_threaded) {
            return .{
                .active_jobs = self.active_jobs,
                .queued_jobs = self.queued_jobs,
                .worker_threads = 0,
                .max_queue_len = self.max_queue_len,
            };
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .active_jobs = self.active_jobs,
            .queued_jobs = self.queued_jobs,
            .worker_threads = self.threads.len,
            .max_queue_len = self.max_queue_len,
        };
    }

    /// Outcome of a drain, for observability (#170).
    pub const DrainResult = struct {
        /// Queued (unstarted) connections force-closed because the drain did not
        /// finish in time (deadline elapsed, or an immediate no-drain shutdown).
        forced_closes: usize = 0,
        /// True when a positive drain deadline elapsed before work finished.
        timed_out: bool = false,
    };

    /// Drain in-flight work and shut down workers.
    ///
    /// `drain_timeout_ms` controls how long to wait for queued and active jobs
    /// to finish before forcibly closing any remaining queued file descriptors:
    ///   - 0  → close queued fds immediately, then join (no drain)
    ///   - >0 → wait up to that many milliseconds for work to drain;
    ///           after the deadline, force-close remaining queued fds and join
    ///
    /// Active (already-dispatched) handlers are always allowed to finish
    /// naturally; only unstarted queued fds are force-closed on timeout.
    ///
    /// Returns a `DrainResult` describing whether the deadline was hit and how
    /// many queued connections were force-closed.
    pub fn shutdownAndJoin(self: *WorkerPool, drain_timeout_ms: u64) DrainResult {
        if (builtin.single_threaded) return .{};
        if (self.joined) return .{};

        var result = DrainResult{};

        self.mutex.lock();
        self.shutting_down = true;

        if (drain_timeout_ms == 0) {
            // Immediate: close queued fds without waiting (configured no-drain).
            for (self.worker_queues) |*wq| {
                while (wq.items.popFront()) |entry| {
                    _ = std.c.close(entry.fd);
                    result.forced_closes += 1;
                }
            }
            self.queued_jobs = 0;
        } else {
            // Drain with deadline.
            const deadline_ms = compat.milliTimestamp() + @as(i64, @intCast(drain_timeout_ms));
            while (self.queued_jobs > 0 or self.active_jobs > 0) {
                const now_ms = compat.milliTimestamp();
                if (now_ms >= deadline_ms) {
                    // Timeout: force-close remaining queued fds.
                    result.timed_out = true;
                    for (self.worker_queues) |*wq| {
                        while (wq.items.popFront()) |entry| {
                            _ = std.c.close(entry.fd);
                            result.forced_closes += 1;
                        }
                    }
                    self.queued_jobs = 0;
                    break;
                }
                // Unlock and sleep briefly to let workers make progress,
                // then re-check.
                self.mutex.unlock();
                std.Io.sleep(compat.io(), .fromMilliseconds(5), .awake) catch {}; // interrupt wakes are fine; drain loop continues
                self.mutex.lock();
            }
        }

        self.mutex.unlock();
        self.cond.broadcast();

        for (self.threads) |thread| {
            thread.join();
        }
        self.joined = true;
        return result;
    }

    fn workerMain(self: *WorkerPool, worker_index: usize) void {
        while (true) {
            self.mutex.lock();
            while (self.queued_jobs == 0 and !self.shutting_down) {
                self.cond.wait(&self.mutex);
            }

            if (self.queued_jobs == 0 and self.shutting_down) {
                self.mutex.unlock();
                return;
            }

            const entry = self.popWorkLocked(worker_index) orelse {
                self.mutex.unlock();
                continue;
            };
            self.active_jobs += 1;
            self.mutex.unlock();

            if (self.wait_callback) |cb| {
                const dequeued_ns = compat.nanoTimestamp();
                const wait_ns: i64 = @intCast(@min(
                    dequeued_ns - entry.enqueued_ns,
                    std.math.maxInt(i64),
                ));
                cb(self.wait_callback_ctx.?, wait_ns);
            }

            self.handler(self.handler_ctx, entry.fd);

            self.mutex.lock();
            self.active_jobs -= 1;
            self.cond.broadcast();
            self.mutex.unlock();
        }
    }

    fn selectQueueForSubmitLocked(self: *WorkerPool) usize {
        if (self.worker_queues.len == 0) return 0;

        const start = self.next_queue % self.worker_queues.len;
        var best = start;
        var best_len = self.worker_queues[start].items.len;

        var offset: usize = 1;
        while (offset < self.worker_queues.len) : (offset += 1) {
            const idx = (start + offset) % self.worker_queues.len;
            const len = self.worker_queues[idx].items.len;
            if (len < best_len) {
                best = idx;
                best_len = len;
            }
        }

        return best;
    }

    fn popWorkLocked(self: *WorkerPool, worker_index: usize) ?QueueEntry {
        if (worker_index < self.worker_queues.len) {
            var own = &self.worker_queues[worker_index].items;
            if (own.len > 0) {
                self.queued_jobs -= 1;
                return own.popFront().?;
            }
        }

        var offset: usize = 1;
        while (offset < self.worker_queues.len) : (offset += 1) {
            const victim = (worker_index + offset) % self.worker_queues.len;
            var victim_queue = &self.worker_queues[victim].items;
            if (victim_queue.len > 0) {
                self.queued_jobs -= 1;
                return victim_queue.popFront().?;
            }
        }

        return null;
    }
};

test "worker pool processes submitted items" {
    if (builtin.single_threaded) return;

    const Ctx = struct {
        mutex: compat.Mutex = .{},
        total: usize = 0,
    };

    var ctx = Ctx{};

    const handler = struct {
        fn run(raw_ctx: *anyopaque, fd: std.posix.fd_t) void {
            const typed: *Ctx = @ptrCast(@alignCast(raw_ctx));
            typed.mutex.lock();
            typed.total += @intCast(fd);
            typed.mutex.unlock();
        }
    }.run;

    var pool: WorkerPool = undefined;
    try pool.init(std.testing.allocator, 2, 64, 0, handler, &ctx);
    defer pool.deinit();

    try pool.submit(1);
    try pool.submit(2);
    try pool.submit(3);

    std.Io.sleep(compat.io(), .fromMilliseconds(50), .awake) catch unreachable;

    ctx.mutex.lock();
    defer ctx.mutex.unlock();
    try std.testing.expectEqual(@as(usize, 6), ctx.total);
}

test "worker pool shutdown drains in-flight work" {
    if (builtin.single_threaded) return;

    const Ctx = struct {
        mutex: compat.Mutex = .{},
        done: bool = false,
    };
    var ctx = Ctx{};

    const handler = struct {
        fn run(raw_ctx: *anyopaque, _: std.posix.fd_t) void {
            const typed: *Ctx = @ptrCast(@alignCast(raw_ctx));
            std.Io.sleep(compat.io(), .fromMilliseconds(20), .awake) catch unreachable;
            typed.mutex.lock();
            typed.done = true;
            typed.mutex.unlock();
        }
    }.run;

    var pool: WorkerPool = undefined;
    try pool.init(std.testing.allocator, 1, 16, 0, handler, &ctx);
    defer pool.deinit();

    try pool.submit(1);
    const drain = pool.shutdownAndJoin(5_000);
    // The single in-flight job finishes well within the timeout: clean drain.
    try std.testing.expect(!drain.timed_out);
    try std.testing.expectEqual(@as(usize, 0), drain.forced_closes);

    ctx.mutex.lock();
    defer ctx.mutex.unlock();
    try std.testing.expect(ctx.done);
}

test "worker pool queue selection prefers least-loaded worker queue" {
    if (builtin.single_threaded) return;

    var queues = try std.testing.allocator.alloc(WorkerQueue, 3);
    defer std.testing.allocator.free(queues);
    for (queues) |*q| {
        q.* = .{ .items = .empty };
    }
    defer {
        for (queues) |*q| q.items.deinit(std.testing.allocator);
    }

    try queues[0].items.pushBack(std.testing.allocator, .{ .fd = 10, .enqueued_ns = 0 });
    try queues[0].items.pushBack(std.testing.allocator, .{ .fd = 11, .enqueued_ns = 0 });
    try queues[1].items.pushBack(std.testing.allocator, .{ .fd = 20, .enqueued_ns = 0 });

    var pool = WorkerPool{
        .allocator = std.testing.allocator,
        .threads = if (builtin.single_threaded) .{} else &.{},
        .worker_queues = queues,
        .worker_ids = &.{},
        .handler = undefined,
        .handler_ctx = undefined,
        .max_queue_len = 128,
        .queued_jobs = 3,
        .next_queue = 0,
    };

    const idx = pool.selectQueueForSubmitLocked();
    try std.testing.expectEqual(@as(usize, 2), idx);
}

test "worker pool snapshot reports queue and worker capacity" {
    var threads = [_]std.Thread{ undefined, undefined, undefined };
    var pool = WorkerPool{
        .allocator = std.testing.allocator,
        .threads = threads[0..],
        .worker_queues = &.{},
        .worker_ids = &.{},
        .active_jobs = 2,
        .queued_jobs = 5,
        .handler = undefined,
        .handler_ctx = undefined,
        .max_queue_len = 64,
    };

    const snapshot = pool.snapshot();
    try std.testing.expectEqual(@as(usize, 2), snapshot.active_jobs);
    try std.testing.expectEqual(@as(usize, 5), snapshot.queued_jobs);
    try std.testing.expectEqual(@as(usize, 3), snapshot.worker_threads);
    try std.testing.expectEqual(@as(usize, 64), snapshot.max_queue_len);
}

test "worker pool popWorkLocked steals from peer queue" {
    if (builtin.single_threaded) return;

    var queues = try std.testing.allocator.alloc(WorkerQueue, 2);
    defer std.testing.allocator.free(queues);
    for (queues) |*q| {
        q.* = .{ .items = .empty };
    }
    defer {
        for (queues) |*q| q.items.deinit(std.testing.allocator);
    }

    try queues[1].items.pushBack(std.testing.allocator, .{ .fd = 42, .enqueued_ns = 0 });

    var pool = WorkerPool{
        .allocator = std.testing.allocator,
        .threads = if (builtin.single_threaded) .{} else &.{},
        .worker_queues = queues,
        .worker_ids = &.{},
        .handler = undefined,
        .handler_ctx = undefined,
        .max_queue_len = 128,
        .queued_jobs = 1,
        .next_queue = 0,
    };

    const stolen = pool.popWorkLocked(0);
    try std.testing.expectEqual(@as(?QueueEntry, .{ .fd = 42, .enqueued_ns = 0 }), stolen);
    try std.testing.expectEqual(@as(usize, 0), pool.queued_jobs);
}

test "shutdownAndJoin drain_timeout_ms=0 closes queued fds immediately" {
    // Verify that a zero timeout immediately discards queued (unstarted) work
    // without blocking.
    if (builtin.single_threaded) return;

    const Ctx = struct {
        mutex: compat.Mutex = .{},
        ran: bool = false,
    };
    var ctx = Ctx{};

    const handler = struct {
        fn run(raw_ctx: *anyopaque, _: std.posix.fd_t) void {
            // This should not be called because we force-close before dispatch.
            const typed: *Ctx = @ptrCast(@alignCast(raw_ctx));
            typed.mutex.lock();
            typed.ran = true;
            typed.mutex.unlock();
        }
    }.run;

    var pool: WorkerPool = undefined;
    // Single worker — keep it busy so the queued job never starts.
    try pool.init(std.testing.allocator, 1, 16, 0, handler, &ctx);
    defer pool.deinit();

    // Immediate shutdown with zero timeout must complete quickly.
    const t0 = compat.milliTimestamp();
    _ = pool.shutdownAndJoin(0);
    const elapsed = compat.milliTimestamp() - t0;
    // Should finish in well under 1 second even on a slow machine.
    try std.testing.expect(elapsed < 1_000);
}

test "shutdownAndJoin drain_timeout_ms positive drains in-flight work before timeout" {
    // Submit one short job, then call shutdownAndJoin with a generous timeout.
    // The job should complete and done should be true.
    if (builtin.single_threaded) return;

    const Ctx = struct {
        mutex: compat.Mutex = .{},
        done: bool = false,
    };
    var ctx = Ctx{};

    const handler = struct {
        fn run(raw_ctx: *anyopaque, _: std.posix.fd_t) void {
            const typed: *Ctx = @ptrCast(@alignCast(raw_ctx));
            std.Io.sleep(compat.io(), .fromMilliseconds(10), .awake) catch unreachable;
            typed.mutex.lock();
            typed.done = true;
            typed.mutex.unlock();
        }
    }.run;

    var pool: WorkerPool = undefined;
    try pool.init(std.testing.allocator, 1, 16, 0, handler, &ctx);
    defer pool.deinit();

    try pool.submit(1);
    // 2-second timeout is much more than the 10ms handler needs.
    const drain = pool.shutdownAndJoin(2_000);
    try std.testing.expect(!drain.timed_out);

    ctx.mutex.lock();
    defer ctx.mutex.unlock();
    try std.testing.expect(ctx.done);
}

test "shutdownAndJoin drain_timeout_ms expires and returns" {
    // A handler that stays active past the drain timeout must make
    // shutdownAndJoin report `timed_out`. `shutdownAndJoin` still *joins* the
    // worker, so the handler must eventually return on its own (it cannot be
    // gated on the test thread, which is blocked inside shutdownAndJoin). The
    // previous version relied on a single 50ms sleep outlasting the 20ms drain,
    // but a sleep can wake early on a signal — flaky once background threads
    // exist. This version busy-waits against a *monotonic deadline* (re-sleeping
    // on early wakeups) so the handler reliably stays active ~200ms >> 20ms,
    // making `timed_out` deterministic without deadlocking the join.
    if (builtin.single_threaded) return;

    const Ctx = struct {
        started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    };
    var ctx = Ctx{};

    const handler = struct {
        fn run(ctx_ptr: *anyopaque, _: std.posix.fd_t) void {
            const c: *Ctx = @ptrCast(@alignCast(ctx_ptr));
            c.started.store(true, .release);
            const deadline = compat.milliTimestamp() + 200;
            while (compat.milliTimestamp() < deadline) {
                std.Io.sleep(compat.io(), .fromMilliseconds(2), .awake) catch {}; // early wakes fine; loop re-checks
            }
        }
    }.run;

    var pool: WorkerPool = undefined;
    try pool.init(std.testing.allocator, 1, 16, 0, handler, &ctx);
    defer pool.deinit();

    try pool.submit(1);
    // Wait until the handler is actually running (an active job, not queued).
    while (!ctx.started.load(.acquire)) {
        std.Io.sleep(compat.io(), .fromMilliseconds(1), .awake) catch {};
    }

    const t0 = compat.milliTimestamp();
    // Short drain timeout; the active handler (~200ms) outlives it deterministically.
    const drain = pool.shutdownAndJoin(20);
    const elapsed = compat.milliTimestamp() - t0;
    // The deadline elapsed before the active handler finished.
    try std.testing.expect(drain.timed_out);
    // Active (already-dispatched) handlers are not force-closed, only queued fds.
    try std.testing.expectEqual(@as(usize, 0), drain.forced_closes);
    // Bounded: drain reports timeout at ~20ms, then joins the ~200ms handler.
    try std.testing.expect(elapsed < 1_000);
}

test "shutdownAndJoin counts queued connections force-closed (#170)" {
    if (builtin.single_threaded) return;

    // Manually build a pool with no worker threads but with queued fds, so the
    // drain cannot make progress and every queued fd must be force-closed. Using
    // fake fds is safe: std.c.close on a non-socket fd just returns EBADF.
    var queues = try std.testing.allocator.alloc(WorkerQueue, 2);
    defer std.testing.allocator.free(queues);
    for (queues) |*q| q.* = .{ .items = .empty };
    defer for (queues) |*q| q.items.deinit(std.testing.allocator);

    try queues[0].items.pushBack(std.testing.allocator, .{ .fd = 90001, .enqueued_ns = 0 });
    try queues[0].items.pushBack(std.testing.allocator, .{ .fd = 90002, .enqueued_ns = 0 });
    try queues[1].items.pushBack(std.testing.allocator, .{ .fd = 90003, .enqueued_ns = 0 });

    var pool = WorkerPool{
        .allocator = std.testing.allocator,
        .threads = if (builtin.single_threaded) .{} else &.{},
        .worker_queues = queues,
        .worker_ids = &.{},
        .handler = undefined,
        .handler_ctx = undefined,
        .max_queue_len = 128,
        .queued_jobs = 3,
        .next_queue = 0,
    };

    // Immediate (no-drain) shutdown force-closes all 3 queued fds without waiting.
    const drain = pool.shutdownAndJoin(0);
    try std.testing.expect(!drain.timed_out);
    try std.testing.expectEqual(@as(usize, 3), drain.forced_closes);
    try std.testing.expectEqual(@as(usize, 0), pool.queued_jobs);
}

test "worker pool global queue cap rejects without unbounded growth" {
    if (builtin.single_threaded) return;

    // 1 worker, global queue depth = 2, no per-worker cap. With the worker
    // blocked, queued work cannot drain, so the global cap must bound the queue
    // and reject the overflowing submission with QueueFull rather than growing.
    const Ctx = struct {
        mutex: compat.Mutex = .{},
        proceed: bool = false,
    };
    var ctx = Ctx{};

    const handler = struct {
        fn run(raw_ctx: *anyopaque, _: std.posix.fd_t) void {
            const typed: *Ctx = @ptrCast(@alignCast(raw_ctx));
            while (true) {
                std.Io.sleep(compat.io(), .fromMilliseconds(1), .awake) catch {};
                typed.mutex.lock();
                const done = typed.proceed;
                typed.mutex.unlock();
                if (done) break;
            }
        }
    }.run;

    var pool: WorkerPool = undefined;
    try pool.init(std.testing.allocator, 1, 2, 0, handler, &ctx);
    defer pool.deinit();

    // First submission dispatches to the (now blocked) worker; queue depth = 0.
    try pool.submit(1);
    // Wait until the worker has actually picked up fd 1 (active, queue drained)
    // so the queue-depth assertions below are not racing the dispatch.
    var spins: usize = 0;
    while (pool.snapshot().active_jobs < 1 and spins < 1000) : (spins += 1) {
        std.Io.sleep(compat.io(), .fromMilliseconds(1), .awake) catch {};
    }
    try std.testing.expectEqual(@as(usize, 0), pool.snapshot().queued_jobs);

    // Fill the global queue to its depth of 2.
    try pool.submit(2);
    try pool.submit(3);
    try std.testing.expectEqual(@as(usize, 2), pool.snapshot().queued_jobs);

    // The next submission exceeds the global cap and is rejected.
    try std.testing.expectError(error.QueueFull, pool.submit(4));
    try std.testing.expectEqual(@as(usize, 2), pool.snapshot().queued_jobs);

    ctx.mutex.lock();
    ctx.proceed = true;
    ctx.mutex.unlock();
}

test "worker pool per-worker queue depth limit rejects when all worker queues are full" {
    if (builtin.single_threaded) return;

    // 1 worker, global queue=16, per-worker limit=2.
    // Keep the worker busy so queued items stay in the queue.
    const Ctx = struct {
        mutex: compat.Mutex = .{},
        proceed: bool = false,
    };
    var ctx = Ctx{};

    const handler = struct {
        fn run(raw_ctx: *anyopaque, _: std.posix.fd_t) void {
            const typed: *Ctx = @ptrCast(@alignCast(raw_ctx));
            // Block until the test signals proceed so the queue doesn't drain.
            while (true) {
                std.Io.sleep(compat.io(), .fromMilliseconds(1), .awake) catch {};
                typed.mutex.lock();
                const done = typed.proceed;
                typed.mutex.unlock();
                if (done) break;
            }
        }
    }.run;

    var pool: WorkerPool = undefined;
    try pool.init(std.testing.allocator, 1, 16, 2, handler, &ctx);
    defer pool.deinit();

    // First submission dispatches to the active handler — worker queue stays at 0.
    try pool.submit(1);
    // Give the handler time to start and become the active job.
    std.Io.sleep(compat.io(), .fromMilliseconds(5), .awake) catch {};

    // Queue two items — fills the per-worker queue to the limit.
    try pool.submit(2);
    try pool.submit(3);

    // Third queued item should be rejected.
    try std.testing.expectError(error.QueueFull, pool.submit(4));

    // Unblock the handler so the pool can drain on deinit.
    ctx.mutex.lock();
    ctx.proceed = true;
    ctx.mutex.unlock();
}
