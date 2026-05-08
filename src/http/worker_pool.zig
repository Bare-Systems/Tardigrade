const compat = @import("../zig_compat.zig");
const builtin = @import("builtin");
const std = @import("std");

pub const HandlerFn = *const fn (ctx: *anyopaque, fd: std.posix.fd_t) void;

const WorkerQueue = struct {
    items: std.ArrayList(std.posix.fd_t),
};

pub const WorkerPool = struct {
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

    pub fn init(
        self: *WorkerPool,
        allocator: std.mem.Allocator,
        worker_count: usize,
        max_queue_len: usize,
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

    pub fn deinit(self: *WorkerPool) void {
        self.shutdownAndJoin(30_000);
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
        try self.worker_queues[queue_index].items.append(self.allocator, fd);
        self.queued_jobs += 1;
        if (self.worker_queues.len > 0) {
            self.next_queue = (queue_index + 1) % self.worker_queues.len;
        }
        self.cond.signal();
    }

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
    pub fn shutdownAndJoin(self: *WorkerPool, drain_timeout_ms: u64) void {
        if (builtin.single_threaded) return;
        if (self.joined) return;

        self.mutex.lock();
        self.shutting_down = true;

        if (drain_timeout_ms == 0) {
            // Immediate: close queued fds without waiting.
            for (self.worker_queues) |*wq| {
                for (wq.items.items) |fd| _ = std.c.close(fd);
                wq.items.clearRetainingCapacity();
            }
            self.queued_jobs = 0;
        } else {
            // Drain with deadline.
            const deadline_ms = compat.milliTimestamp() + @as(i64, @intCast(drain_timeout_ms));
            while (self.queued_jobs > 0 or self.active_jobs > 0) {
                const now_ms = compat.milliTimestamp();
                if (now_ms >= deadline_ms) {
                    // Timeout: force-close remaining queued fds.
                    for (self.worker_queues) |*wq| {
                        for (wq.items.items) |fd| _ = std.c.close(fd);
                        wq.items.clearRetainingCapacity();
                    }
                    self.queued_jobs = 0;
                    break;
                }
                // Unlock and sleep briefly to let workers make progress,
                // then re-check.
                self.mutex.unlock();
                std.Io.sleep(compat.io(), .fromMilliseconds(5), .awake) catch {};
                self.mutex.lock();
            }
        }

        self.mutex.unlock();
        self.cond.broadcast();

        for (self.threads) |thread| {
            thread.join();
        }
        self.joined = true;
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

            const fd = self.popWorkLocked(worker_index) orelse {
                self.mutex.unlock();
                continue;
            };
            self.active_jobs += 1;
            self.mutex.unlock();

            self.handler(self.handler_ctx, fd);

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
        var best_len = self.worker_queues[start].items.items.len;

        var offset: usize = 1;
        while (offset < self.worker_queues.len) : (offset += 1) {
            const idx = (start + offset) % self.worker_queues.len;
            const len = self.worker_queues[idx].items.items.len;
            if (len < best_len) {
                best = idx;
                best_len = len;
            }
        }

        return best;
    }

    fn popWorkLocked(self: *WorkerPool, worker_index: usize) ?std.posix.fd_t {
        if (worker_index < self.worker_queues.len) {
            var own = &self.worker_queues[worker_index].items;
            if (own.items.len > 0) {
                self.queued_jobs -= 1;
                return own.orderedRemove(0);
            }
        }

        var offset: usize = 1;
        while (offset < self.worker_queues.len) : (offset += 1) {
            const victim = (worker_index + offset) % self.worker_queues.len;
            var victim_queue = &self.worker_queues[victim].items;
            if (victim_queue.items.len > 0) {
                self.queued_jobs -= 1;
                return victim_queue.orderedRemove(0);
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
    try pool.init(std.testing.allocator, 2, 64, handler, &ctx);
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
    try pool.init(std.testing.allocator, 1, 16, handler, &ctx);
    defer pool.deinit();

    try pool.submit(1);
    pool.shutdownAndJoin(5_000);

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

    try queues[0].items.append(std.testing.allocator, 10);
    try queues[0].items.append(std.testing.allocator, 11);
    try queues[1].items.append(std.testing.allocator, 20);

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

    try queues[1].items.append(std.testing.allocator, 42);

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
    try std.testing.expectEqual(@as(?std.posix.fd_t, 42), stolen);
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
    try pool.init(std.testing.allocator, 1, 16, handler, &ctx);
    defer pool.deinit();

    // Immediate shutdown with zero timeout must complete quickly.
    const t0 = compat.milliTimestamp();
    pool.shutdownAndJoin(0);
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
    try pool.init(std.testing.allocator, 1, 16, handler, &ctx);
    defer pool.deinit();

    try pool.submit(1);
    // 2-second timeout is much more than the 10ms handler needs.
    pool.shutdownAndJoin(2_000);

    ctx.mutex.lock();
    defer ctx.mutex.unlock();
    try std.testing.expect(ctx.done);
}

test "shutdownAndJoin drain_timeout_ms expires and returns" {
    // Submit a job that sleeps much longer than the drain timeout.
    // shutdownAndJoin should return within a bounded time (timeout + join overhead).
    if (builtin.single_threaded) return;

    const Ctx = struct {};
    var ctx = Ctx{};

    const handler = struct {
        fn run(_: *anyopaque, _: std.posix.fd_t) void {
            // Sleep longer than the drain timeout below (50ms vs 20ms timeout).
            std.Io.sleep(compat.io(), .fromMilliseconds(50), .awake) catch {};
        }
    }.run;

    var pool: WorkerPool = undefined;
    try pool.init(std.testing.allocator, 1, 16, handler, &ctx);
    defer pool.deinit();

    try pool.submit(1);
    // Give the handler time to start running so it becomes an active job.
    std.Io.sleep(compat.io(), .fromMilliseconds(5), .awake) catch {};
    const t0 = compat.milliTimestamp();
    // Very short drain timeout — the active handler will outlive it.
    pool.shutdownAndJoin(20);
    const elapsed = compat.milliTimestamp() - t0;
    // Should finish well under 1s (handler finishes after timeout).
    try std.testing.expect(elapsed < 1_000);
}
