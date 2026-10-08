//! Connection-owned, wakeable HTTP/2 outbound frame queue.
//!
//! Producers enqueue complete wire frames; exactly one connection runtime
//! drains them into the downstream writer.  This keeps a future asynchronous
//! stream handler from ever acquiring the TCP/TLS writer directly.
const std = @import("std");
const compat = @import("zig_compat");

pub const default_max_queued_bytes: usize = 256 * 1024;

const Entry = struct { bytes: []u8 };

pub const Scheduler = struct {
    allocator: std.mem.Allocator,
    max_queued_bytes: usize,
    mutex: compat.Mutex = .{},
    entries: std.ArrayList(Entry) = .empty,
    /// The connection runtime's frame serializer feeds this a frame header
    /// followed by its payload. No producer uses this writer directly.
    partial_frame: std.ArrayList(u8) = .empty,
    queued_bytes: usize = 0,
    wake_read: std.posix.fd_t = -1,
    wake_write: std.posix.fd_t = -1,
    wake_pending: std.atomic.Value(bool) = .init(false),

    pub const Error = error{ QueueFull, WakeFailed, InvalidFrame } || std.mem.Allocator.Error;

    pub fn init(allocator: std.mem.Allocator, max_queued_bytes: usize) !Scheduler {
        var fds: [2]std.posix.fd_t = undefined;
        if (std.c.pipe(&fds) != 0) return error.WakeFailed;
        return .{ .allocator = allocator, .max_queued_bytes = max_queued_bytes, .wake_read = fds[0], .wake_write = fds[1] };
    }

    pub fn deinit(self: *Scheduler) void {
        self.mutex.lock();
        for (self.entries.items) |entry| self.allocator.free(entry.bytes);
        self.entries.deinit(self.allocator);
        self.partial_frame.deinit(self.allocator);
        self.mutex.unlock();
        if (self.wake_read >= 0) _ = std.c.close(self.wake_read);
        if (self.wake_write >= 0) _ = std.c.close(self.wake_write);
        self.* = undefined;
    }

    pub fn wakeFd(self: *const Scheduler) std.posix.fd_t {
        return self.wake_read;
    }

    pub fn writer(self: *Scheduler) Writer {
        return .{ .scheduler = self };
    }

    pub const Writer = struct {
        scheduler: *Scheduler,

        pub fn write(self: Writer, bytes: []const u8) !usize {
            try self.writeAll(bytes);
            return bytes.len;
        }

        pub fn writeAll(self: Writer, bytes: []const u8) !void {
            try self.scheduler.acceptSerializedBytes(bytes);
        }

        pub fn writeByte(self: Writer, byte: u8) !void {
            try self.writeAll(&.{byte});
        }
    };

    /// Queue one already-encoded, complete frame.  The queue owns a copy so
    /// the producer may release its request/response data immediately.
    pub fn enqueue(self: *Scheduler, frame: []const u8) Error!void {
        if (frame.len < 9) return error.InvalidFrame;
        const declared = (@as(usize, frame[0]) << 16) | (@as(usize, frame[1]) << 8) | @as(usize, frame[2]);
        if (declared + 9 != frame.len) return error.InvalidFrame;

        self.mutex.lock();
        defer self.mutex.unlock();
        if (frame.len > self.max_queued_bytes -| self.queued_bytes) return error.QueueFull;
        const owned = try self.allocator.dupe(u8, frame);
        errdefer self.allocator.free(owned);
        try self.entries.append(self.allocator, .{ .bytes = owned });
        self.queued_bytes += owned.len;
        if (!self.wake_pending.swap(true, .acq_rel)) try self.signalLocked();
    }

    fn acceptSerializedBytes(self: *Scheduler, bytes: []const u8) Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.partial_frame.appendSlice(self.allocator, bytes);
        while (self.partial_frame.items.len >= 9) {
            const declared = (@as(usize, self.partial_frame.items[0]) << 16) |
                (@as(usize, self.partial_frame.items[1]) << 8) |
                @as(usize, self.partial_frame.items[2]);
            const frame_len = declared + 9;
            if (self.partial_frame.items.len < frame_len) return;
            if (frame_len > self.max_queued_bytes -| self.queued_bytes) return error.QueueFull;
            const owned = try self.allocator.dupe(u8, self.partial_frame.items[0..frame_len]);
            errdefer self.allocator.free(owned);
            try self.entries.append(self.allocator, .{ .bytes = owned });
            self.queued_bytes += owned.len;
            const rest = self.partial_frame.items[frame_len..];
            std.mem.copyForwards(u8, self.partial_frame.items[0..rest.len], rest);
            self.partial_frame.items.len = rest.len;
            if (!self.wake_pending.swap(true, .acq_rel)) try self.signalLocked();
        }
    }

    /// The sole connection runtime calls this.  It transfers queued ownership
    /// to a local list before writing, so producers never hold the queue lock
    /// while the transport is blocked.
    pub fn flush(self: *Scheduler, output: anytype) !void {
        while (true) {
            if (self.wake_pending.load(.acquire)) self.drainWake();
            self.mutex.lock();
            if (self.entries.items.len == 0) {
                self.wake_pending.store(false, .release);
                self.mutex.unlock();
                return;
            }
            var pending = self.entries;
            self.entries = .empty;
            self.queued_bytes = 0;
            self.wake_pending.store(false, .release);
            self.mutex.unlock();

            defer pending.deinit(self.allocator);
            for (pending.items) |entry| {
                defer self.allocator.free(entry.bytes);
                try output.writeAll(entry.bytes);
            }
        }
    }

    fn signalLocked(self: *Scheduler) Error!void {
        const byte = [_]u8{1};
        while (true) {
            const n = std.c.write(self.wake_write, &byte, 1);
            if (n == 1) return;
            if (n < 0 and std.posix.errno(n) == .INTR) continue;
            return error.WakeFailed;
        }
    }

    fn drainWake(self: *Scheduler) void {
        // `wake_pending` coalesces notifications to one byte.  Read exactly
        // once: these descriptors intentionally remain blocking so a failed
        // wake cannot turn into a spin loop.
        var byte: [1]u8 = undefined;
        _ = std.c.read(self.wake_read, &byte, 1);
    }
};

test "scheduler preserves producer FIFO and releases queued ownership" {
    const allocator = std.testing.allocator;
    var scheduler = try Scheduler.init(allocator, 128);
    defer scheduler.deinit();
    const a = [_]u8{ 0, 0, 0, 4, 0, 0, 0, 0, 0 };
    const b = [_]u8{ 0, 0, 1, 6, 0, 0, 0, 0, 0, 9 };
    try scheduler.enqueue(&a);
    try scheduler.enqueue(&b);
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try scheduler.flush(&out.writer);
    try std.testing.expectEqualSlices(u8, &a, out.written()[0..a.len]);
    try std.testing.expectEqualSlices(u8, &b, out.written()[a.len..]);
}

test "scheduler bounds queued bytes" {
    var scheduler = try Scheduler.init(std.testing.allocator, 9);
    defer scheduler.deinit();
    const frame = [_]u8{ 0, 0, 0, 4, 0, 0, 0, 0, 0 };
    try scheduler.enqueue(&frame);
    try std.testing.expectError(error.QueueFull, scheduler.enqueue(&frame));
}
