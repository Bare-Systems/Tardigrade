const builtin = @import("builtin");
const std = @import("std");

pub const HandlerFn = *const fn (ctx: *anyopaque, fd: std.posix.fd_t) void;

pub const WorkerPool = struct {
    allocator: std.mem.Allocator,
    threads: if (builtin.single_threaded) [0]std.Thread else []std.Thread,
    queue: std.ArrayList(std.posix.fd_t),
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    shutting_down: bool = false,
    joined: bool = false,
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
            .queue = std.ArrayList(std.posix.fd_t).init(allocator),
            .handler = handler,
            .handler_ctx = handler_ctx,
            .max_queue_len = max_queue_len,
        };

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
            thread.* = try std.Thread.spawn(.{}, workerMain, .{self});
            spawned += 1;
        }
    }

    pub fn deinit(self: *WorkerPool) void {
        self.shutdownAndJoin(true);
        self.queue.deinit();
        if (!builtin.single_threaded) {
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
        if (self.queue.items.len >= self.max_queue_len) return error.QueueFull;

        try self.queue.append(fd);
        self.cond.signal();
    }

    pub fn shutdownAndJoin(self: *WorkerPool, drain_pending: bool) void {
        if (builtin.single_threaded) return;
        if (self.joined) return;

        self.mutex.lock();
        self.shutting_down = true;

        if (!drain_pending) {
            for (self.queue.items) |fd| std.posix.close(fd);
            self.queue.clearRetainingCapacity();
        }

        self.mutex.unlock();
        self.cond.broadcast();

        for (self.threads) |thread| {
            thread.join();
        }
        self.joined = true;
    }

    fn workerMain(self: *WorkerPool) void {
        while (true) {
            self.mutex.lock();
            while (self.queue.items.len == 0 and !self.shutting_down) {
                self.cond.wait(&self.mutex);
            }

            if (self.queue.items.len == 0 and self.shutting_down) {
                self.mutex.unlock();
                return;
            }

            const fd = self.queue.pop().?;
            self.mutex.unlock();

            self.handler(self.handler_ctx, fd);
        }
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
