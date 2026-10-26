//! Connection-owned, wakeable HTTP/2 outbound frame queue.
//!
//! Producers enqueue complete wire frames; exactly one connection runtime
//! drains them into the downstream writer.  This keeps a future asynchronous
//! stream handler from ever acquiring the TCP/TLS writer directly.
const std = @import("std");
const compat = @import("zig_compat");
const http2_frame = @import("http2_frame.zig");
const h2_transport_metrics = @import("h2_transport_metrics.zig");

pub const default_max_queued_bytes: usize = 256 * 1024;

const Entry = struct {
    bytes: []u8,
    stream_id: u31,
};
const Active = struct { entry: Entry, offset: usize = 0 };

/// Payload length of an already-framed entry if it is a DATA frame, else 0.
/// Only DATA frame payloads consume HTTP/2 send-window credit; every other
/// frame type (HEADERS, RST_STREAM, WINDOW_UPDATE, ...) does not.
fn dataFramePayloadLen(frame_bytes: []const u8) usize {
    if (frame_bytes.len < 9) return 0;
    if (frame_bytes[3] != @intFromEnum(http2_frame.Type.data)) return 0;
    return (@as(usize, frame_bytes[0]) << 16) | (@as(usize, frame_bytes[1]) << 8) | @as(usize, frame_bytes[2]);
}

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
    /// #951 second review: this connection's own writer-queue slot, so its
    /// high-water mark can be bounded against *its own* `max_queued_bytes`
    /// -- the process-wide aggregate high water (every live connection's
    /// queued bytes summed) is not comparable to any single connection's
    /// cap once more than one connection is live.
    metrics_slot: ?h2_transport_metrics.SlotHandle = null,

    pub const Error = error{ QueueFull, WakeFailed, InvalidFrame } || std.mem.Allocator.Error;

    pub fn init(allocator: std.mem.Allocator, connection_id: u64, max_queued_bytes: usize) !Scheduler {
        var fds: [2]std.posix.fd_t = undefined;
        if (std.c.pipe(&fds) != 0) return error.WakeFailed;
        const flags = std.c.fcntl(fds[0], std.c.F.GETFL, @as(c_int, 0));
        if (flags < 0 or std.c.fcntl(fds[0], std.c.F.SETFL, flags | @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }))) < 0) {
            _ = std.c.close(fds[0]);
            _ = std.c.close(fds[1]);
            return error.WakeFailed;
        }
        // #951 review: publish the configured cap so evidence/tests can
        // assert the writer-queue high-water mark never exceeds it without
        // hardcoding `default_max_queued_bytes` on the reading side.
        h2_transport_metrics.setWriterQueueCapBytes(max_queued_bytes);
        const metrics_slot = h2_transport_metrics.writerQueueSlotRegister(connection_id, max_queued_bytes);
        return .{ .allocator = allocator, .max_queued_bytes = max_queued_bytes, .wake_read = fds[0], .wake_write = fds[1], .metrics_slot = metrics_slot };
    }

    pub fn deinit(self: *Scheduler) void {
        self.mutex.lock();
        // #951 third review: the depth count (entries plus the in-flight
        // `active` one, if any) needs the same teardown refund as the byte
        // count below, computed before either list is actually freed.
        const remaining_depth: i64 = @as(i64, @intCast(self.entries.items.len)) + @as(i64, @intFromBool(self.active != null));
        for (self.entries.items) |entry| self.allocator.free(entry.bytes);
        if (self.active) |active| self.allocator.free(active.entry.bytes);
        self.entries.deinit(self.allocator);
        // #951 review: a connection torn down with unflushed frames still
        // owed the global aggregate a matching decrement, or it would
        // retain this scheduler's last published contribution forever.
        if (self.queued_bytes > 0) {
            h2_transport_metrics.writerQueueBytesChanged(-@as(i64, @intCast(self.queued_bytes)));
            h2_transport_metrics.writerQueueSlotChanged(self.metrics_slot, -@as(i64, @intCast(self.queued_bytes)));
        }
        if (remaining_depth > 0) {
            h2_transport_metrics.writerQueueSlotDepthChanged(self.metrics_slot, -remaining_depth);
        }
        h2_transport_metrics.writerQueueSlotUnregister(self.metrics_slot);
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

    /// Current total queued bytes (including the in-progress `active`
    /// frame, if any). #951 review: `enqueueOwnedLocked`/`cancelStream`/
    /// `flush` now publish their own deltas directly as they mutate
    /// `queued_bytes`, so this remains a plain read-only snapshot for
    /// callers/tests that want this one connection's own current value.
    pub fn queuedBytes(self: *Scheduler) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.queued_bytes;
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
        const stream_id: u31 = @intCast(std.mem.readInt(u32, frame[5..9], .big) & 0x7fff_ffff);

        self.mutex.lock();
        defer self.mutex.unlock();
        const owned = try self.allocator.dupe(u8, frame);
        errdefer self.allocator.free(owned);
        try self.enqueueOwnedLocked(.{ .bytes = owned, .stream_id = stream_id });
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
        try self.enqueueOwnedLocked(.{ .bytes = owned, .stream_id = stream_id });
    }

    fn enqueueOwnedLocked(self: *Scheduler, owned: Entry) Error!void {
        if (owned.bytes.len > self.max_queued_bytes -| self.queued_bytes) return error.QueueFull;
        self.entries.append(self.allocator, owned) catch |err| return err;
        self.queued_bytes += owned.bytes.len;
        h2_transport_metrics.writerQueueBytesChanged(@intCast(owned.bytes.len));
        h2_transport_metrics.writerQueueSlotChanged(self.metrics_slot, @intCast(owned.bytes.len));
        h2_transport_metrics.writerQueueSlotDepthChanged(self.metrics_slot, 1);
        if (!self.wake_pending.load(.acquire)) self.signalLocked() catch |err| {
            const removed = self.entries.pop().?;
            self.queued_bytes -= removed.bytes.len;
            h2_transport_metrics.writerQueueBytesChanged(-@as(i64, @intCast(removed.bytes.len)));
            h2_transport_metrics.writerQueueSlotChanged(self.metrics_slot, -@as(i64, @intCast(removed.bytes.len)));
            h2_transport_metrics.writerQueueSlotDepthChanged(self.metrics_slot, -1);
            return err;
        };
        self.wake_pending.store(true, .release);
    }

    /// Remove unsent frames for a stream after an inbound RST_STREAM.  A frame
    /// already partially written must finish so its wire framing remains valid.
    ///
    /// Returns the sum of DATA frame payload bytes among the frames actually
    /// removed (never counting a frame that is mid-transmission, since it is
    /// deliberately left to finish). A removed DATA frame's payload already
    /// debited the connection (and, until the stream is torn down, per-stream)
    /// HTTP/2 send-window credit when it was queued; that debit must be
    /// refunded here or it is permanently lost, starving unrelated streams
    /// even though those bytes were never actually sent to the peer.
    pub fn cancelStream(self: *Scheduler, stream_id: u31) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        var refunded_payload_bytes: usize = 0;
        var i: usize = 0;
        while (i < self.entries.items.len) {
            if (self.entries.items[i].stream_id == stream_id) {
                const removed = self.entries.orderedRemove(i);
                refunded_payload_bytes += dataFramePayloadLen(removed.bytes);
                self.queued_bytes -= removed.bytes.len;
                h2_transport_metrics.writerQueueBytesChanged(-@as(i64, @intCast(removed.bytes.len)));
                h2_transport_metrics.writerQueueSlotChanged(self.metrics_slot, -@as(i64, @intCast(removed.bytes.len)));
                h2_transport_metrics.writerQueueSlotDepthChanged(self.metrics_slot, -1);
                self.allocator.free(removed.bytes);
                continue;
            }
            i += 1;
        }
        if (self.active) |active| {
            if (active.entry.stream_id == stream_id and active.offset == 0) {
                refunded_payload_bytes += dataFramePayloadLen(active.entry.bytes);
                self.active = null;
                self.queued_bytes -= active.entry.bytes.len;
                h2_transport_metrics.writerQueueBytesChanged(-@as(i64, @intCast(active.entry.bytes.len)));
                h2_transport_metrics.writerQueueSlotChanged(self.metrics_slot, -@as(i64, @intCast(active.entry.bytes.len)));
                h2_transport_metrics.writerQueueSlotDepthChanged(self.metrics_slot, -1);
                self.allocator.free(active.entry.bytes);
            }
        }
        if (self.active == null and self.entries.items.len == 0) {
            self.drainWakeLocked();
            self.wake_pending.store(false, .release);
        }
        return refunded_payload_bytes;
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
                h2_transport_metrics.writerQueueBytesChanged(-@as(i64, @intCast(done.bytes.len)));
                h2_transport_metrics.writerQueueSlotChanged(self.metrics_slot, -@as(i64, @intCast(done.bytes.len)));
                h2_transport_metrics.writerQueueSlotDepthChanged(self.metrics_slot, -1);
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
    var scheduler = try Scheduler.init(allocator, 1, 128);
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
    var scheduler = try Scheduler.init(std.testing.allocator, 1, 9);
    defer scheduler.deinit();
    const frame = [_]u8{ 0, 0, 0, 4, 0, 0, 0, 0, 0 };
    try scheduler.enqueue(&frame);
    try std.testing.expectError(error.QueueFull, scheduler.enqueue(&frame));
}

test "atomic frame enqueue refuses capacity without queue mutation" {
    var scheduler = try Scheduler.init(std.testing.allocator, 1, 9);
    defer scheduler.deinit();
    try std.testing.expectError(error.QueueFull, scheduler.writer().enqueueFrame(.data, 0, 1, &.{1}));
    try std.testing.expectEqual(@as(usize, 0), scheduler.queued_bytes);
    try std.testing.expect(!scheduler.hasPendingOutput());
}

test "atomic frame enqueue rolls back on allocation failure" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var scheduler = try Scheduler.init(failing.allocator(), 1, 64);
    defer scheduler.deinit();
    try std.testing.expectError(error.OutOfMemory, scheduler.enqueueFrame(.data, 0, 1, &.{ 1, 2 }));
    try std.testing.expectEqual(@as(usize, 0), scheduler.queued_bytes);
    try std.testing.expect(!scheduler.hasPendingOutput());
}

test "concurrent producers retain whole cross-stream frames" {
    const Producer = struct {
        scheduler: *Scheduler,
        stream_id: u31,
        payload: []const u8,

        fn run(self: *@This()) void {
            self.scheduler.enqueueFrame(.data, 0, self.stream_id, self.payload) catch @panic("enqueue failed");
        }
    };
    var scheduler = try Scheduler.init(std.testing.allocator, 1, 128);
    defer scheduler.deinit();
    var first = Producer{ .scheduler = &scheduler, .stream_id = 1, .payload = "first" };
    var second = Producer{ .scheduler = &scheduler, .stream_id = 3, .payload = "second" };
    const first_thread = try std.Thread.spawn(.{}, Producer.run, .{&first});
    const second_thread = try std.Thread.spawn(.{}, Producer.run, .{&second});
    first_thread.join();
    second_thread.join();

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try scheduler.flush(&out.writer);
    var offset: usize = 0;
    var seen_first = false;
    var seen_second = false;
    while (offset < out.written().len) {
        const bytes = out.written()[offset..];
        const payload_len = (@as(usize, bytes[0]) << 16) | (@as(usize, bytes[1]) << 8) | bytes[2];
        const stream_id = std.mem.readInt(u32, bytes[5..9], .big) & 0x7fff_ffff;
        if (stream_id == 1) {
            try std.testing.expectEqualSlices(u8, "first", bytes[9 .. 9 + payload_len]);
            seen_first = true;
        } else if (stream_id == 3) {
            try std.testing.expectEqualSlices(u8, "second", bytes[9 .. 9 + payload_len]);
            seen_second = true;
        } else return error.TestUnexpectedResult;
        offset += 9 + payload_len;
    }
    try std.testing.expect(seen_first and seen_second);
}

test "wake notification coalesces, drains, and republishes" {
    var scheduler = try Scheduler.init(std.testing.allocator, 1, 128);
    defer scheduler.deinit();
    try scheduler.enqueueFrame(.data, 0, 1, "a");
    try scheduler.enqueueFrame(.data, 0, 3, "b");
    var poll_fds = [_]std.posix.pollfd{.{
        .fd = scheduler.wakeFd(),
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&poll_fds, 0));
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(isize, 1), std.c.read(scheduler.wake_read, &byte, 1));
    try std.testing.expect(std.c.read(scheduler.wake_read, &byte, 1) < 0);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try scheduler.flush(&out.writer);
    try std.testing.expect(!scheduler.hasPendingOutput());
    try scheduler.enqueueFrame(.data, 0, 5, "c");
    try std.testing.expectEqual(@as(isize, 1), std.c.read(scheduler.wake_read, &byte, 1));
}

test "producer wakes a waiter already blocked on the scheduler fd" {
    const Waiter = struct {
        scheduler: *Scheduler,
        entered: *std.atomic.Value(bool),
        woke: *std.atomic.Value(bool),

        fn run(self: *@This()) void {
            var fds = [_]std.posix.pollfd{.{
                .fd = self.scheduler.wakeFd(),
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            self.entered.store(true, .release);
            const ready = std.posix.poll(&fds, 1_000) catch @panic("poll failed");
            self.woke.store(ready == 1 and (fds[0].revents & std.posix.POLL.IN) != 0, .release);
        }
    };
    var scheduler = try Scheduler.init(std.testing.allocator, 1, 64);
    defer scheduler.deinit();
    var entered = std.atomic.Value(bool).init(false);
    var woke = std.atomic.Value(bool).init(false);
    var waiter = Waiter{ .scheduler = &scheduler, .entered = &entered, .woke = &woke };
    const thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});
    while (!entered.load(.acquire)) std.Thread.yield() catch {};
    try scheduler.enqueueFrame(.data, 0, 1, "wake");
    thread.join();
    try std.testing.expect(woke.load(.acquire));

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try scheduler.flush(&out.writer);
    try std.testing.expect(!scheduler.hasPendingOutput());
}

test "wake publication failure rolls back producer ownership" {
    var scheduler = try Scheduler.init(std.testing.allocator, 1, 64);
    defer scheduler.deinit();
    _ = std.c.close(scheduler.wake_write);
    scheduler.wake_write = -1;
    try std.testing.expectError(error.WakeFailed, scheduler.enqueueFrame(.data, 0, 1, "x"));
    try std.testing.expectEqual(@as(usize, 0), scheduler.queued_bytes);
    try std.testing.expectEqual(@as(usize, 0), scheduler.entries.items.len);
    try std.testing.expect(!scheduler.hasPendingOutput());
}

test "deinit releases active and queued frames after blocked output" {
    const BlockingWriter = struct {
        fn write(_: *@This(), _: []const u8) error{WouldBlock}!usize {
            return error.WouldBlock;
        }
    };
    var scheduler = try Scheduler.init(std.testing.allocator, 1, 64);
    try scheduler.enqueueFrame(.data, 0, 1, "first");
    try scheduler.enqueueFrame(.data, 0, 3, "second");
    var writer = BlockingWriter{};
    try scheduler.flush(&writer);
    try std.testing.expect(scheduler.active != null);
    try std.testing.expectEqual(@as(usize, 1), scheduler.entries.items.len);
    scheduler.deinit();
}

test "cancel stream drops unsent active and queued frames but keeps siblings" {
    const BlockingWriter = struct {
        out: std.Io.Writer.Allocating,
        blocked: bool = true,

        fn write(self: *@This(), bytes: []const u8) anyerror!usize {
            if (self.blocked) return error.WouldBlock;
            try self.out.writer.writeAll(bytes);
            return bytes.len;
        }
    };
    const first = [_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 1, 'a' };
    const follower = [_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 1, 'b' };
    const sibling = [_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 3, 'c' };
    var scheduler = try Scheduler.init(std.testing.allocator, 1, 64);
    defer scheduler.deinit();
    try scheduler.enqueue(&first);
    try scheduler.enqueue(&follower);
    try scheduler.enqueue(&sibling);
    var writer = BlockingWriter{ .out = .init(std.testing.allocator) };
    defer writer.out.deinit();
    try scheduler.flush(&writer);
    // Neither the still-unsent active frame (offset 0) nor the queued
    // follower frame was ever written to the peer, so their 1-byte DATA
    // payloads must both come back as send-window refund.
    try std.testing.expectEqual(@as(usize, 2), scheduler.cancelStream(1));
    writer.blocked = false;
    try scheduler.flush(&writer);
    try std.testing.expectEqualSlices(u8, &sibling, writer.out.written());
}

test "cancel stream finishes a partial frame but drops later frames" {
    const PartialWriter = struct {
        out: std.Io.Writer.Allocating,
        phase: u2 = 0,

        fn write(self: *@This(), bytes: []const u8) anyerror!usize {
            if (self.phase == 0) {
                self.phase = 1;
                try self.out.writer.writeAll(bytes[0..4]);
                return 4;
            }
            if (self.phase == 1) {
                self.phase = 2;
                return error.WouldBlock;
            }
            try self.out.writer.writeAll(bytes);
            return bytes.len;
        }
    };
    const first = [_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 1, 'a' };
    const follower = [_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 1, 'b' };
    const sibling = [_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 3, 'c' };
    var scheduler = try Scheduler.init(std.testing.allocator, 1, 64);
    defer scheduler.deinit();
    try scheduler.enqueue(&first);
    try scheduler.enqueue(&follower);
    try scheduler.enqueue(&sibling);
    var writer = PartialWriter{ .out = .init(std.testing.allocator) };
    defer writer.out.deinit();
    try scheduler.flush(&writer);
    // The active frame is already mid-transmission (offset 4 of 10), so it
    // must finish rather than be refunded; only the still-queued follower's
    // 1-byte DATA payload counts as send-window refund.
    try std.testing.expectEqual(@as(usize, 1), scheduler.cancelStream(1));
    try scheduler.flush(&writer);
    try std.testing.expectEqualSlices(u8, &first, writer.out.written()[0..first.len]);
    try std.testing.expectEqualSlices(u8, &sibling, writer.out.written()[first.len..]);
}

test "reentrant drain attempt preserves the active frame exactly once" {
    const ReentrantWriter = struct {
        scheduler: *Scheduler,
        recurse: bool = true,
        out: std.Io.Writer.Allocating,

        fn write(self: *@This(), bytes: []const u8) anyerror!usize {
            if (self.recurse) {
                self.recurse = false;
                // This models the native-TLS wait callback attempting to
                // service the same scheduler while its outer drain owns it.
                try self.scheduler.flush(self);
                return error.WouldBlock;
            }
            try self.out.writer.writeAll(bytes);
            return bytes.len;
        }
    };
    const frame = [_]u8{ 0, 0, 1, 6, 0, 0, 0, 0, 1, 9 };
    var scheduler = try Scheduler.init(std.testing.allocator, 1, 64);
    defer scheduler.deinit();
    try scheduler.enqueue(&frame);
    var writer = ReentrantWriter{ .scheduler = &scheduler, .out = .init(std.testing.allocator) };
    defer writer.out.deinit();
    try scheduler.flush(&writer);
    try std.testing.expect(scheduler.hasPendingOutput());
    try scheduler.flush(&writer);
    try std.testing.expectEqualSlices(u8, &frame, writer.out.written());
    try std.testing.expect(!scheduler.hasPendingOutput());
}

test "scheduler retains and resumes a frame after temporary backpressure" {
    const TestWriter = struct {
        blocked: bool = true,
        return_partial: bool = true,
        out: std.Io.Writer.Allocating,

        fn write(self: *@This(), bytes: []const u8) anyerror!usize {
            if (self.blocked and self.return_partial) {
                self.return_partial = false;
                const n = @min(@as(usize, 4), bytes.len);
                try self.out.writer.writeAll(bytes[0..n]);
                return n;
            }
            if (self.blocked) return error.WouldBlock;
            try self.out.writer.writeAll(bytes);
            return bytes.len;
        }
    };
    var scheduler = try Scheduler.init(std.testing.allocator, 1, 64);
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

test "two connections each stay within their own writer-queue cap even though their aggregate exceeds a single cap (#951 second review)" {
    const BlockingWriter = struct {
        fn write(_: *@This(), _: []const u8) error{WouldBlock}!usize {
            return error.WouldBlock;
        }
    };
    h2_transport_metrics.resetForTesting();
    var scheduler_a = try Scheduler.init(std.testing.allocator, 10, 256 * 1024);
    defer scheduler_a.deinit();
    var scheduler_b = try Scheduler.init(std.testing.allocator, 20, 256 * 1024);
    defer scheduler_b.deinit();
    var writer_a = BlockingWriter{};
    var writer_b = BlockingWriter{};

    const payload_a = [_]u8{0} ** (200 * 1024);
    const payload_b = [_]u8{0} ** (200 * 1024);
    try scheduler_a.enqueueFrame(.data, 0, 1, &payload_a);
    try scheduler_b.enqueueFrame(.data, 0, 1, &payload_b);
    try scheduler_a.flush(&writer_a);
    try scheduler_b.flush(&writer_b);

    // Each connection independently stays under its own 256KiB cap...
    var buf: [8]h2_transport_metrics.WriterQueueSlotSnapshot = undefined;
    const slots = h2_transport_metrics.snapshotWriterQueueSlots(&buf);
    try std.testing.expectEqual(@as(usize, 2), slots.len);
    for (slots) |slot| try std.testing.expect(slot.queued_bytes_high_water <= slot.cap_bytes);
    // ...while the process-wide aggregate genuinely exceeds a single
    // connection's cap without that being a failure -- the defect the old
    // aggregate-vs-single-cap comparison had.
    try std.testing.expect(h2_transport_metrics.snapshot().writer_queue_bytes_high_water > 256 * 1024);
}

test "writer queue depth high water is tracked independently of byte occupancy (#951 third review)" {
    const BlockingWriter = struct {
        fn write(_: *@This(), _: []const u8) error{WouldBlock}!usize {
            return error.WouldBlock;
        }
    };
    h2_transport_metrics.resetForTesting();
    var scheduler_a = try Scheduler.init(std.testing.allocator, 30, 256 * 1024);
    defer scheduler_a.deinit();
    var scheduler_b = try Scheduler.init(std.testing.allocator, 40, 256 * 1024);
    defer scheduler_b.deinit();
    var writer_a = BlockingWriter{};
    var writer_b = BlockingWriter{};

    // Many tiny frames: byte occupancy stays trivially small (well under
    // the cap) while the frame-intent depth is what actually grows large
    // -- a scheduler holding thousands of tiny frames is deep and unfair
    // even though it looks small by byte capacity alone.
    const frame_count: u31 = 500;
    var i: u31 = 0;
    while (i < frame_count) : (i += 1) {
        try scheduler_a.enqueueFrame(.data, 0, 1, &.{1});
        try scheduler_b.enqueueFrame(.data, 0, 1, &.{1});
    }
    try scheduler_a.flush(&writer_a);
    try scheduler_b.flush(&writer_b);

    var buf: [8]h2_transport_metrics.WriterQueueSlotSnapshot = undefined;
    const slots = h2_transport_metrics.snapshotWriterQueueSlots(&buf);
    try std.testing.expectEqual(@as(usize, 2), slots.len);
    for (slots) |slot| {
        // Byte occupancy peak is tiny (one byte payload + a nine-byte
        // header per frame, all still queued behind the blocked writer).
        try std.testing.expect(slot.queued_bytes_high_water <= 10 * frame_count);
        try std.testing.expect(slot.queued_bytes_high_water <= slot.cap_bytes);
        // Depth peak reflects the real frame-intent count, a genuinely
        // distinct dimension the byte-cap check above cannot see.
        try std.testing.expectEqual(@as(u64, frame_count), slot.depth_high_water);
        try std.testing.expectEqual(@as(u64, frame_count), slot.depth);
    }
}
