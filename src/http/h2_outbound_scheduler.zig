//! Connection-owned, wakeable HTTP/2 outbound frame queue.
//!
//! Producers enqueue complete wire frames; exactly one connection runtime
//! drains them into the downstream writer.  This keeps a future asynchronous
//! stream handler from ever acquiring the TCP/TLS writer directly.
const std = @import("std");
const compat = @import("zig_compat");
const http2_frame = @import("http2_frame.zig");

pub const default_max_queued_bytes: usize = 256 * 1024;

const Entry = struct { bytes: []u8 };
const Active = struct { entry: Entry, offset: usize = 0 };

pub const Scheduler = struct {
    allocator: std.mem.Allocator,
    max_queued_bytes: usize,
    mutex: compat.Mutex = .{},
    entries: std.ArrayList(Entry) = .empty,
    active: ?Active = null,
    queued_bytes: usize = 0,
    wake_read: std.posix.fd_t = -1,
    wake_write: std.posix.fd_t = -1,
    wake_pending: std.atomic.Value(bool) = .init(false),
    draining: std.atomic.Value(bool) = .init(false),

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
            _ = self;
            _ = bytes;
            return error.InvalidFrame;
        }

        pub fn writeByte(self: Writer, byte: u8) !void {
            try self.writeAll(&.{byte});
        }

        /// `http2_frame.writeFrame` detects this method and hands an entire
        /// frame to the scheduler in one operation.  A frame can therefore
        /// never be interleaved with another producer's header or payload.
        pub fn enqueueFrame(self: Writer, typ: http2_frame.Type, flags: u8, stream_id: u31, payload: []const u8) Error!void {
            return self.scheduler.enqueueFrame(typ, flags, stream_id, payload);
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
        const owned = try self.allocator.dupe(u8, frame);
        errdefer self.allocator.free(owned);
        try self.enqueueOwnedLocked(owned);
    }

    /// Atomically copies a complete frame while holding the queue mutex. This
    /// is intentionally the only scheduled HTTP/2 serialization path.
    pub fn enqueueFrame(self: *Scheduler, typ: http2_frame.Type, flags: u8, stream_id: u31, payload: []const u8) Error!void {
        if (payload.len > 0xFF_FF_FF) return error.InvalidFrame;
        const len = payload.len + 9;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (len > self.max_queued_bytes -| self.queued_bytes) return error.QueueFull;
        const owned = try self.allocator.alloc(u8, len);
        errdefer self.allocator.free(owned);
        owned[0] = @intCast((payload.len >> 16) & 0xff);
        owned[1] = @intCast((payload.len >> 8) & 0xff);
        owned[2] = @intCast(payload.len & 0xff);
        owned[3] = @intFromEnum(typ);
        owned[4] = flags;
        std.mem.writeInt(u32, owned[5..9], @as(u32, stream_id) & 0x7fff_ffff, .big);
        @memcpy(owned[9..], payload);
        try self.enqueueOwnedLocked(owned);
    }

    fn enqueueOwnedLocked(self: *Scheduler, owned: []u8) Error!void {
        if (owned.len > self.max_queued_bytes -| self.queued_bytes) return error.QueueFull;
        self.entries.append(self.allocator, .{ .bytes = owned }) catch |err| return err;
        self.queued_bytes += owned.len;
        if (!self.wake_pending.load(.acquire)) self.signalLocked() catch |err| {
            const removed = self.entries.pop().?;
            self.queued_bytes -= removed.bytes.len;
            return err;
        };
        self.wake_pending.store(true, .release);
    }

    /// The sole connection runtime calls this. A temporary `WouldBlock` keeps
    /// the active frame and its cursor owned by the scheduler for a later
    /// writable wake; only a complete frame is ever released.
    pub fn flush(self: *Scheduler, output: anytype) !void {
        if (self.draining.swap(true, .acq_rel)) return;
        defer self.draining.store(false, .release);
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
            const n = output.write(bytes) catch |err| {
                const any_err: anyerror = err;
                if (any_err == error.WouldBlock) return;
                return err;
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

test "atomic frame enqueue refuses capacity without queue mutation" {
    var scheduler = try Scheduler.init(std.testing.allocator, 9);
    defer scheduler.deinit();
    try std.testing.expectError(error.QueueFull, scheduler.writer().enqueueFrame(.data, 0, 1, &.{1}));
    try std.testing.expectEqual(@as(usize, 0), scheduler.queued_bytes);
    try std.testing.expect(!scheduler.hasPendingOutput());
}

test "atomic frame enqueue rolls back on allocation failure" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var scheduler = try Scheduler.init(failing.allocator(), 64);
    defer scheduler.deinit();
    try std.testing.expectError(error.OutOfMemory, scheduler.enqueueFrame(.data, 0, 1, &.{ 1, 2 }));
    try std.testing.expectEqual(@as(usize, 0), scheduler.queued_bytes);
    try std.testing.expect(!scheduler.hasPendingOutput());
}

test "scheduler retains and resumes a frame after temporary backpressure" {
    const TestWriter = struct {
        blocked: bool = true,
        out: std.Io.Writer.Allocating,

        fn write(self: *@This(), bytes: []const u8) anyerror!usize {
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
