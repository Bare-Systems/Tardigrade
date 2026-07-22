const compat = @import("zig_compat");
const std = @import("std");

/// Thread-safe fixed-size byte buffer pool.
pub const BufferPool = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    free_list: std.ArrayList([]u8),
    buffer_size: usize,
    max_cached: usize,

    pub fn init(allocator: std.mem.Allocator, buffer_size: usize, max_cached: usize) BufferPool {
        return .{
            .allocator = allocator,
            .free_list = .empty,
            .buffer_size = buffer_size,
            .max_cached = max_cached,
        };
    }

    pub fn deinit(self: *BufferPool) void {
        for (self.free_list.items) |buf| self.allocator.free(buf);
        self.free_list.deinit(self.allocator);
    }

    pub fn acquire(self: *BufferPool) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.free_list.items.len > 0) {
            return self.free_list.pop().?;
        }
        return try self.allocator.alloc(u8, self.buffer_size);
    }

    pub fn release(self: *BufferPool, buf: []u8) void {
        if (buf.len != self.buffer_size) {
            self.allocator.free(buf);
            return;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.free_list.items.len >= self.max_cached) {
            self.allocator.free(buf);
            return;
        }

        self.free_list.append(self.allocator, buf) catch {
            self.allocator.free(buf);
        };
    }
};

test "buffer pool reuses buffers" {
    var pool = BufferPool.init(std.testing.allocator, 1024, 2);
    defer pool.deinit();

    const first = try pool.acquire();
    pool.release(first);
    const second = try pool.acquire();
    defer pool.release(second);

    try std.testing.expect(first.ptr == second.ptr);
    try std.testing.expectEqual(@as(usize, 1024), second.len);
}

test "buffer pool caches at most max_cached and never blocks under pressure (#172)" {
    // The pool is a bounded cache, not a hard cap: acquire always succeeds (no
    // exhaustion/blocking), and release never grows the cache beyond max_cached,
    // so a burst of releases cannot cause unbounded retained allocation.
    var pool = BufferPool.init(std.testing.allocator, 64, 2);
    defer pool.deinit();

    // Acquire well past the cache size; every buffer is valid and distinct.
    var bufs: [5][]u8 = undefined;
    for (&bufs) |*b| {
        b.* = try pool.acquire();
        try std.testing.expectEqual(@as(usize, 64), b.len);
    }
    try std.testing.expectEqual(@as(usize, 0), pool.free_list.items.len);

    // Release all 5; only max_cached (2) are retained, the rest are freed back
    // to the allocator (testing.allocator would flag a leak otherwise).
    for (bufs) |b| pool.release(b);
    try std.testing.expectEqual(@as(usize, 2), pool.free_list.items.len);

    // A wrong-sized buffer is freed immediately, never cached.
    const odd = try std.testing.allocator.alloc(u8, 65);
    pool.release(odd);
    try std.testing.expectEqual(@as(usize, 2), pool.free_list.items.len);
}
