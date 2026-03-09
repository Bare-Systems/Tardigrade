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
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
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
            wq.* = .{ .items = std.ArrayList(std.posix.fd_t).init(allocator) };
        }
        errdefer {
            for (self.worker_queues) |*wq| wq.items.deinit();
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
        self.shutdownAndJoin(true);
        if (!builtin.single_threaded) {
            for (self.worker_queues) |*wq| wq.items.deinit();
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
        try self.worker_queues[queue_index].items.append(fd);
        self.queued_jobs += 1;
        if (self.worker_queues.len > 0) {
            self.next_queue = (queue_index + 1) % self.worker_queues.len;
        }
        self.cond.signal();
    }

    pub fn shutdownAndJoin(self: *WorkerPool, drain_pending: bool) void {
        if (builtin.single_threaded) return;
        if (self.joined) return;

        self.mutex.lock();
        self.shutting_down = true;

        if (!drain_pending) {
            for (self.worker_queues) |*wq| {
                for (wq.items.items) |fd| std.posix.close(fd);
                wq.items.clearRetainingCapacity();
            }
            self.queued_jobs = 0;
        } else {
            while (self.queued_jobs > 0 or self.active_jobs > 0) {
                self.cond.wait(&self.mutex);
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
        mutex: std.Thread.Mutex = .{},
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

    std.time.sleep(50 * std.time.ns_per_ms);

    ctx.mutex.lock();
    defer ctx.mutex.unlock();
    try std.testing.expectEqual(@as(usize, 6), ctx.total);
}

test "worker pool shutdown drains in-flight work" {
    if (builtin.single_threaded) return;

    const Ctx = struct {
        mutex: std.Thread.Mutex = .{},
        done: bool = false,
    };
    var ctx = Ctx{};

    const handler = struct {
        fn run(raw_ctx: *anyopaque, _: std.posix.fd_t) void {
            const typed: *Ctx = @ptrCast(@alignCast(raw_ctx));
            std.time.sleep(20 * std.time.ns_per_ms);
            typed.mutex.lock();
            typed.done = true;
            typed.mutex.unlock();
        }
    }.run;

    var pool: WorkerPool = undefined;
    try pool.init(std.testing.allocator, 1, 16, handler, &ctx);
    defer pool.deinit();

    try pool.submit(1);
    pool.shutdownAndJoin(true);

    ctx.mutex.lock();
    defer ctx.mutex.unlock();
    try std.testing.expect(ctx.done);
}

test "worker pool queue selection prefers least-loaded worker queue" {
    if (builtin.single_threaded) return;

    var queues = try std.testing.allocator.alloc(WorkerQueue, 3);
    defer std.testing.allocator.free(queues);
    for (queues) |*q| {
        q.* = .{ .items = std.ArrayList(std.posix.fd_t).init(std.testing.allocator) };
    }
    defer {
        for (queues) |*q| q.items.deinit();
    }

    try queues[0].items.append(10);
    try queues[0].items.append(11);
    try queues[1].items.append(20);

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
        q.* = .{ .items = std.ArrayList(std.posix.fd_t).init(std.testing.allocator) };
    }
    defer {
        for (queues) |*q| q.items.deinit();
    }

    try queues[1].items.append(42);

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
