//! Connection-owned, wakeable HTTP/2 outbound frame queue.
//!
//! Producers enqueue complete wire frames; exactly one connection runtime
//! drains them into the downstream writer.  This keeps a future asynchronous
//! stream handler from ever acquiring the TCP/TLS writer directly.
const std = @import("std");
const compat = @import("zig_compat");

pub const default_max_queued_bytes: usize = 256 * 1024;

const Entry = struct { bytes: []u8 };
const Active = struct { entry: Entry, offset: usize = 0 };

pub const Scheduler = struct {
    allocator: std.mem.Allocator,
    max_queued_bytes: usize,
    mutex: compat.Mutex = .{},
    entries: std.ArrayList(Entry) = .empty,
    active: ?Active = null,
    /// The connection runtime's frame serializer feeds this a frame header
    /// followed by its payload. No producer uses this writer directly.
    partial_frame: std.ArrayList(u8) = .empty,
    partial_reserved_bytes: usize = 0,
    queued_bytes: usize = 0,
    wake_read: std.posix.fd_t = -1,
    wake_write: std.posix.fd_t = -1,
    wake_pending: std.atomic.Value(bool) = .init(false),

    pub const Error = error{ QueueFull, WakeFailed, InvalidFrame } || std.mem.Allocator.Error;

    pub fn init(allocator: std.mem.Allocator, max_queued_bytes: usize) !Scheduler {
        var fds: [2]std.posix.fd_t = undefined;
        if (std.c.pipe(&fds) != 0) return error.WakeFailed;
        const flags = std.c.fcntl(fds[0], std.c.F.GETFL, @as(c_int, 0));
        if (flags < 0 or std.c.fcntl(fds[0], std.c.F.SETFL, flags | @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }))) < 0) {
            _ = std.c.close(fds[0]);
            _ = std.c.close(fds[1]);
            return error.WakeFailed;
        }
        return .{ .allocator = allocator, .max_queued_bytes = max_queued_bytes, .wake_read = fds[0], .wake_write = fds[1] };
    }

    pub fn deinit(self: *Scheduler) void {
        self.mutex.lock();
        for (self.entries.items) |entry| self.allocator.free(entry.bytes);
        if (self.active) |active| self.allocator.free(active.entry.bytes);
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

    pub fn hasPendingOutput(self: *Scheduler) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.active != null or self.entries.items.len > 0;
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
        self.entries.append(self.allocator, .{ .bytes = owned }) catch |err| {
            self.allocator.free(owned);
            return err;
        };
        self.queued_bytes += owned.len;
        if (!self.wake_pending.load(.acquire)) {
            self.signalLocked() catch |err| {
                const removed = self.entries.pop().?;
                self.queued_bytes -= removed.bytes.len;
                self.allocator.free(removed.bytes);
                return err;
            };
            self.wake_pending.store(true, .release);
        }
    }

    fn acceptSerializedBytes(self: *Scheduler, bytes: []const u8) Error!void {
        self.mutex.lock();
        defer self.mutex.unlock();
        // The H2 serializers call writeAll for the 9-byte header and then
        // for its payload. Once the header arrives reserve the *whole* frame
        // before accepting any payload, making capacity refusal transactional.
        if (self.partial_frame.items.len == 0 and bytes.len >= 9) {
            const declared = (@as(usize, bytes[0]) << 16) |
                (@as(usize, bytes[1]) << 8) |
                @as(usize, bytes[2]);
            const frame_len = declared + 9;
            if (frame_len > self.max_queued_bytes -| self.queued_bytes) return error.QueueFull;
            self.partial_reserved_bytes = frame_len;
            self.queued_bytes += frame_len;
        } else if (self.partial_frame.items.len == 0 and bytes.len > self.max_queued_bytes -| self.queued_bytes) {
            return error.QueueFull;
        }
        try self.partial_frame.appendSlice(self.allocator, bytes);
        while (self.partial_frame.items.len >= 9) {
            const declared = (@as(usize, self.partial_frame.items[0]) << 16) |
                (@as(usize, self.partial_frame.items[1]) << 8) |
                @as(usize, self.partial_frame.items[2]);
            const frame_len = declared + 9;
            if (self.partial_frame.items.len < frame_len) return;
            if (self.partial_reserved_bytes == 0) {
                if (frame_len > self.max_queued_bytes -| self.queued_bytes) {
                    self.partial_frame.clearRetainingCapacity();
                    return error.QueueFull;
                }
                self.queued_bytes += frame_len;
            }
            if (frame_len != self.partial_reserved_bytes and self.partial_reserved_bytes != 0) {
                self.queued_bytes -= self.partial_reserved_bytes;
                self.partial_reserved_bytes = 0;
                self.partial_frame.clearRetainingCapacity();
                return error.InvalidFrame;
            }
            const owned = try self.allocator.dupe(u8, self.partial_frame.items[0..frame_len]);
            self.entries.append(self.allocator, .{ .bytes = owned }) catch |err| {
                self.allocator.free(owned);
                self.queued_bytes -= frame_len;
                self.partial_reserved_bytes = 0;
                self.partial_frame.clearRetainingCapacity();
                return err;
            };
            const rest = self.partial_frame.items[frame_len..];
            std.mem.copyForwards(u8, self.partial_frame.items[0..rest.len], rest);
            self.partial_frame.items.len = rest.len;
            self.partial_reserved_bytes = 0;
            if (!self.wake_pending.load(.acquire)) {
                self.signalLocked() catch |err| {
                    const removed = self.entries.pop().?;
                    self.queued_bytes -= removed.bytes.len;
                    self.allocator.free(removed.bytes);
                    return err;
                };
                self.wake_pending.store(true, .release);
            }
        }
    }

    /// The sole connection runtime calls this. A temporary `WouldBlock` keeps
    /// the active frame and its cursor owned by the scheduler for a later
    /// writable wake; only a complete frame is ever released.
    pub fn flush(self: *Scheduler, output: anytype) !void {
        while (true) {
            self.mutex.lock();
            self.drainWakeLocked();
            if (self.active == null and self.entries.items.len == 0) {
                self.wake_pending.store(false, .release);
                self.mutex.unlock();
                return;
            }
            if (self.active == null) self.active = .{ .entry = self.entries.orderedRemove(0) };
            const active = &self.active.?;
            const bytes = active.entry.bytes[active.offset..];
            self.mutex.unlock();
            const n = output.write(bytes) catch |err| switch (err) {
                error.WouldBlock => return,
                else => return err,
            };
            if (n == 0) return;
            self.mutex.lock();
            self.active.?.offset += n;
            if (self.active.?.offset == self.active.?.entry.bytes.len) {
                const done = self.active.?.entry;
                self.active = null;
                self.queued_bytes -= done.bytes.len;
                self.allocator.free(done.bytes);
            }
            self.mutex.unlock();
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

    fn drainWakeLocked(self: *Scheduler) void {
        var bytes: [64]u8 = undefined;
        while (true) {
            const n = std.c.read(self.wake_read, &bytes, bytes.len);
            if (n <= 0) break;
        }
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

test "serializer capacity refusal leaves no partial frame state" {
    var scheduler = try Scheduler.init(std.testing.allocator, 9);
    defer scheduler.deinit();
    const header = [_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectError(error.QueueFull, scheduler.writer().writeAll(&header));
    try std.testing.expectEqual(@as(usize, 0), scheduler.partial_frame.items.len);
    try std.testing.expectEqual(@as(usize, 0), scheduler.queued_bytes);
}

test "scheduler retains and resumes a frame after temporary backpressure" {
    const TestWriter = struct {
        blocked: bool = true,
        out: std.Io.Writer.Allocating,

        fn write(self: *@This(), bytes: []const u8) error{WouldBlock}!usize {
            if (self.blocked) return error.WouldBlock;
            try self.out.writer.writeAll(bytes);
            return bytes.len;
        }
    };
    var scheduler = try Scheduler.init(std.testing.allocator, 64);
    defer scheduler.deinit();
    const frame = [_]u8{ 0, 0, 1, 6, 0, 0, 0, 0, 1, 9 };
    try scheduler.enqueue(&frame);
    var writer = TestWriter{ .out = .init(std.testing.allocator) };
    defer writer.out.deinit();
    try scheduler.flush(&writer);
    try std.testing.expect(scheduler.hasPendingOutput());
    writer.blocked = false;
    try scheduler.flush(&writer);
    try std.testing.expectEqualSlices(u8, &frame, writer.out.written());
    try std.testing.expect(!scheduler.hasPendingOutput());
}
