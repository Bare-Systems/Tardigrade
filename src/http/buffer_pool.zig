const compat = @import("../zig_compat.zig");
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
