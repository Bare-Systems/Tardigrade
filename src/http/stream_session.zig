//! Bounded, connection-owned byte session for long-lived downstream streams.
//!
//! A protocol reactor owns `deliver*`, `peekOutbound`, and terminal delivery;
//! a worker owns `read`, `write`, and `consumerDetach`.  The worker never sees
//! the underlying connection.  This is deliberately protocol-neutral so H3
//! can use the same tunnel ownership contract as H2 without sharing a socket
//! or QUIC connection with a relay.
const std = @import("std");
const compat = @import("zig_compat");

pub const Error = error{ QueueFull, Closed, InvalidCapacity, WakeFailed, WriteFailed } || std.mem.Allocator.Error;

pub const TerminalReason = enum { reset, connection_closed, shutdown };

pub const Terminal = struct {
    reason: TerminalReason,
    error_code: u64 = 0,
};

pub const ReadResult = union(enum) {
    data: usize,
    end_stream,
    reset: u64,
    closed: TerminalReason,
};

pub const WriteResult = union(enum) {
    ok,
    reset: u64,
    closed: TerminalReason,
    finished,
};

/// The reactor supplies a coalescing wake implementation when it needs prompt
/// notification of consumer writes/cancellation.  It must not call back into
/// the session: notification occurs while its mutex is held.
pub const Wake = struct {
    ctx: *anyopaque,
    notify_fn: *const fn (*anyopaque) anyerror!void,

    fn notify(self: Wake) anyerror!void {
        try self.notify_fn(self.ctx);
    }
};

const Chunk = struct {
    bytes: []u8,
    offset: usize = 0,

    fn remaining(self: *const Chunk) []const u8 {
        return self.bytes[self.offset..];
    }
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    stream_id: u64,
    max_inbound_bytes: usize,
    max_outbound_bytes: usize,
    wake: ?Wake,

    mutex: compat.Mutex = .{},
    cond: compat.Condition = .{},
    inbound: std.ArrayList(Chunk) = .empty,
    outbound: std.ArrayList(Chunk) = .empty,
    inbound_bytes: usize = 0,
    outbound_bytes: usize = 0,
    /// Credit is deliberately earned on `read`, never on arrival.  A QUIC
    /// integration maps this to its receive-window/accounting mechanism.
    inbound_credit_to_return: usize = 0,
    remote_end_stream: bool = false,
    local_end_requested: bool = false,
    local_end_sent: bool = false,
    cancel_requested: bool = false,
    terminal: ?Terminal = null,
    wake_failed: bool = false,
    /// A producer write has failed after it may have queued a prefix, or a
    /// wake notification has been lost.  In either case a retry could
    /// duplicate bytes or block forever, so the runtime must reset/detach
    /// this session instead of draining it as a healthy stream.
    write_failed: bool = false,
    runtime_attached: bool = true,
    consumer_attached: bool = true,

    pub fn init(allocator: std.mem.Allocator, stream_id: u64, max_inbound_bytes: usize, max_outbound_bytes: usize, wake: ?Wake) Error!Session {
        if (max_inbound_bytes == 0 or max_outbound_bytes == 0) return error.InvalidCapacity;
        return .{
            .allocator = allocator,
            .stream_id = stream_id,
            .max_inbound_bytes = max_inbound_bytes,
            .max_outbound_bytes = max_outbound_bytes,
            .wake = wake,
        };
    }

    pub fn deinit(self: *Session) void {
        self.freeChunks(&self.inbound);
        self.freeChunks(&self.outbound);
        self.* = undefined;
    }

    fn freeChunks(self: *Session, chunks: *std.ArrayList(Chunk)) void {
        for (chunks.items) |chunk| self.allocator.free(chunk.bytes);
        chunks.deinit(self.allocator);
    }

    /// Reactor-facing incremental inbound delivery.  A full queue means the
    /// reactor must apply its protocol's backpressure/error policy.
    pub fn deliverInbound(self: *Session, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.terminal != null or self.remote_end_stream) return error.Closed;
        if (bytes.len > self.max_inbound_bytes -| self.inbound_bytes) return error.QueueFull;
        const owned = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(owned);
        try self.inbound.append(self.allocator, .{ .bytes = owned });
        self.inbound_bytes += owned.len;
        self.cond.signal();
    }

    /// Reactor-facing incremental inbound delivery that accepts as many
    /// leading bytes of `bytes` as currently fit (possibly zero), rather
    /// than requiring the whole slice to fit at once. The caller is
    /// responsible for retrying the unaccepted suffix later; this is not an
    /// error condition, just backpressure.
    pub fn deliverInboundPartial(self: *Session, bytes: []const u8) Error!usize {
        if (bytes.len == 0) return 0;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.terminal != null or self.remote_end_stream) return error.Closed;
        const available = self.max_inbound_bytes -| self.inbound_bytes;
        const n = @min(bytes.len, available);
        if (n == 0) return 0;
        const owned = try self.allocator.dupe(u8, bytes[0..n]);
        errdefer self.allocator.free(owned);
        try self.inbound.append(self.allocator, .{ .bytes = owned });
        self.inbound_bytes += n;
        self.cond.signal();
        return n;
    }

    pub fn deliverRemoteEndStream(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.terminal != null) return;
        self.remote_end_stream = true;
        self.cond.broadcast();
    }

    pub fn deliverReset(self: *Session, error_code: u64) void {
        self.settle(.{ .reason = .reset, .error_code = error_code });
    }

    pub fn deliverConnectionClosed(self: *Session) void {
        self.settle(.{ .reason = .connection_closed });
    }

    pub fn deliverShutdown(self: *Session) void {
        self.settle(.{ .reason = .shutdown });
    }

    fn settle(self: *Session, terminal: Terminal) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.terminal != null) return;
        self.terminal = terminal;
        self.inbound_credit_to_return += self.inbound_bytes;
        self.freeChunks(&self.inbound);
        self.freeChunks(&self.outbound);
        self.inbound = .empty;
        self.outbound = .empty;
        self.inbound_bytes = 0;
        self.outbound_bytes = 0;
        self.cond.broadcast();
        self.signalWakeLocked() catch {};
    }

    /// Reactor borrows outbound bytes and must commit exactly the bytes it
    /// placed into its protocol frames before asking again.
    pub fn peekOutbound(self: *Session, max_len: usize) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.outbound.items.len == 0) return null;
        const bytes = self.outbound.items[0].remaining();
        return bytes[0..@min(bytes.len, max_len)];
    }

    pub fn commitOutboundSent(self: *Session, n: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var remaining = n;
        while (remaining > 0 and self.outbound.items.len > 0) {
            const chunk = &self.outbound.items[0];
            const consumed = @min(remaining, chunk.bytes.len - chunk.offset);
            chunk.offset += consumed;
            remaining -= consumed;
            self.outbound_bytes -= consumed;
            if (chunk.offset == chunk.bytes.len) {
                self.allocator.free(chunk.bytes);
                _ = self.outbound.orderedRemove(0);
            }
        }
        self.cond.broadcast();
    }

    pub fn outboundLocalEndPending(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.local_end_requested and !self.local_end_sent and self.outbound_bytes == 0;
    }

    pub fn markLocalEndStreamSent(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.local_end_sent = true;
    }

    pub fn takeReceiveCreditToReturn(self: *Session) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const credit = self.inbound_credit_to_return;
        self.inbound_credit_to_return = 0;
        return credit;
    }

    pub fn takeCancelRequest(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const requested = self.cancel_requested;
        self.cancel_requested = false;
        return requested;
    }

    pub fn hasWakeFailure(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.wake_failed;
    }

    /// True once either side has settled this session for good (reset,
    /// connection close, or shutdown). A reactor uses this to decide when it
    /// can stop pumping a stream and reap the session, without needing to
    /// race a consumer `read`/`write` to discover the same terminal state.
    pub fn isSettled(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.terminal != null;
    }

    /// True once both directions of this session have ended cleanly: the
    /// peer's half-close was delivered and this side's own final frame has
    /// already been sent. Unlike `isSettled`, this is not a terminal/reset
    /// condition -- the consumer may still be draining already-queued
    /// inbound bytes via `read()` -- but once `local_end_sent` is true the
    /// consumer itself already called `finishLocal()` and can never write
    /// again, so a reactor may safely detach and reap a session in this
    /// state without manufacturing a reset.
    pub fn gracefulComplete(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.remote_end_stream and self.local_end_sent;
    }

    /// True once a producer write cannot be retried safely.  The reactor
    /// must treat this as fatal and reset/detach the stream.
    pub fn hasWriteFailure(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.write_failed;
    }

    pub fn runtimeDetach(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.runtime_attached);
        self.runtime_attached = false;
        return !self.consumer_attached;
    }

    // Consumer-facing methods ------------------------------------------------

    pub fn read(self: *Session, buf: []u8) ReadResult {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (true) {
            if (self.inbound.items.len > 0) {
                const chunk = &self.inbound.items[0];
                const src = chunk.remaining();
                const n = @min(src.len, buf.len);
                @memcpy(buf[0..n], src[0..n]);
                chunk.offset += n;
                self.inbound_bytes -= n;
                self.inbound_credit_to_return += n;
                if (chunk.offset == chunk.bytes.len) {
                    self.allocator.free(chunk.bytes);
                    _ = self.inbound.orderedRemove(0);
                }
                self.signalWakeLocked() catch {};
                return .{ .data = n };
            }
            if (self.terminal) |terminal| return readTerminal(terminal);
            if (self.remote_end_stream) return .end_stream;
            self.cond.wait(&self.mutex);
        }
    }

    pub fn write(self: *Session, bytes: []const u8) Error!WriteResult {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.write_failed) return error.WriteFailed;
        var remaining = bytes;
        while (remaining.len > 0) {
            if (self.write_failed) return error.WriteFailed;
            if (self.terminal) |terminal| return writeTerminal(terminal);
            if (self.local_end_requested) return .finished;
            const capacity = self.max_outbound_bytes -| self.outbound_bytes;
            if (capacity == 0) {
                self.cond.wait(&self.mutex);
                continue;
            }
            const n = @min(capacity, remaining.len);
            const owned = self.allocator.dupe(u8, remaining[0..n]) catch |err| {
                self.failWriteLocked();
                return err;
            };
            self.outbound.append(self.allocator, .{ .bytes = owned }) catch |err| {
                self.allocator.free(owned);
                self.failWriteLocked();
                return err;
            };
            self.outbound_bytes += n;
            remaining = remaining[n..];
            try self.signalWakeLocked();
        }
        return .ok;
    }

    pub fn finishLocal(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.local_end_requested = true;
        self.signalWakeLocked() catch {};
    }

    pub fn requestCancel(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.terminal != null) return;
        self.cancel_requested = true;
        self.signalWakeLocked() catch {};
    }

    pub fn consumerDetach(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.consumer_attached);
        self.consumer_attached = false;
        return !self.runtime_attached;
    }

    fn failWriteLocked(self: *Session) void {
        self.write_failed = true;
        self.cond.broadcast();
        self.signalWakeLocked() catch {};
    }

    /// Notify the reactor while holding `mutex`.  A failed notification is
    /// fail-closed: no producer may enter a capacity wait that only the
    /// sleeping reactor could release, and the runtime can discover both
    /// sticky failure flags on its next bounded servicing pass.
    fn signalWakeLocked(self: *Session) Error!void {
        const wake = self.wake orelse return;
        wake.notify() catch {
            self.wake_failed = true;
            self.write_failed = true;
            self.cond.broadcast();
            return error.WakeFailed;
        };
    }
};

fn readTerminal(terminal: Terminal) ReadResult {
    return switch (terminal.reason) {
        .reset => .{ .reset = terminal.error_code },
        .connection_closed, .shutdown => .{ .closed = terminal.reason },
    };
}

fn writeTerminal(terminal: Terminal) WriteResult {
    return switch (terminal.reason) {
        .reset => .{ .reset = terminal.error_code },
        .connection_closed, .shutdown => .{ .closed = terminal.reason },
    };
}

test "bounded inbound delivery returns credit only after consumer reads" {
    var session = try Session.init(std.testing.allocator, 4, 4, 4, null);
    defer session.deinit();
    try session.deliverInbound("four");
    try std.testing.expectError(error.QueueFull, session.deliverInbound("x"));
    try std.testing.expectEqual(@as(usize, 0), session.takeReceiveCreditToReturn());
    var buf: [4]u8 = undefined;
    try std.testing.expectEqual(ReadResult{ .data = 4 }, session.read(&buf));
    try std.testing.expectEqualStrings("four", &buf);
    try std.testing.expectEqual(@as(usize, 4), session.takeReceiveCreditToReturn());
}

test "outbound is bounded then finishes only after reactor drains it" {
    var session = try Session.init(std.testing.allocator, 4, 4, 4, null);
    defer session.deinit();
    try std.testing.expectEqual(WriteResult.ok, try session.write("four"));
    try std.testing.expectEqualStrings("fo", session.peekOutbound(2).?);
    session.commitOutboundSent(2);
    try std.testing.expectEqualStrings("ur", session.peekOutbound(8).?);
    session.finishLocal();
    try std.testing.expect(!session.outboundLocalEndPending());
    session.commitOutboundSent(2);
    try std.testing.expect(session.outboundLocalEndPending());
}

test "FIN drains queued bytes before end stream and reset settles both directions" {
    var session = try Session.init(std.testing.allocator, 4, 16, 16, null);
    defer session.deinit();
    try session.deliverInbound("tail");
    session.deliverRemoteEndStream();
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(ReadResult{ .data = 4 }, session.read(&buf));
    try std.testing.expectEqual(ReadResult.end_stream, session.read(&buf));
    session.deliverReset(0x10c);
    try std.testing.expectEqual(ReadResult{ .reset = 0x10c }, session.read(&buf));
    try std.testing.expectEqual(WriteResult{ .reset = 0x10c }, try session.write("x"));
}

test "consumer cancellation and two party detach are explicit" {
    var session = try Session.init(std.testing.allocator, 4, 16, 16, null);
    defer session.deinit();
    session.requestCancel();
    try std.testing.expect(session.takeCancelRequest());
    try std.testing.expect(!session.takeCancelRequest());
    try std.testing.expect(!session.consumerDetach());
    try std.testing.expect(session.runtimeDetach());
}

test "partial write allocation failure is sticky and cannot duplicate a retry" {
    // The first chunk needs a duplicate and the outbound list's initial
    // allocation.  Let those succeed, then fail the duplicate attempted
    // after the reactor releases capacity for the second chunk.
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 2 });
    var session = try Session.init(failing.allocator(), 4, 4, 4, null);
    defer session.deinit();

    const Ctx = struct {
        session: *Session,
        result: Error!WriteResult = undefined,

        fn run(ctx: *@This()) void {
            ctx.result = ctx.session.write("eightbyt");
        }
    };
    var ctx = Ctx{ .session = &session };
    const writer = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});

    // The writer first queues exactly one bounded chunk, then waits for the
    // reactor to commit it before attempting the allocation that fails.
    while (session.peekOutbound(4) == null) {}
    try std.testing.expectEqualStrings("eigh", session.peekOutbound(4).?);
    session.commitOutboundSent(4);
    writer.join();

    try std.testing.expectError(error.OutOfMemory, ctx.result);
    try std.testing.expect(session.hasWriteFailure());
    try std.testing.expectEqual(@as(?[]const u8, null), session.peekOutbound(4));
    try std.testing.expectError(error.WriteFailed, session.write("eightbyt"));
}

test "failed wake fails closed before an oversized write can block" {
    const FailingWake = struct {
        fn fail(_: *anyopaque) anyerror!void {
            return error.BrokenWake;
        }
    };
    var wake_ctx: u8 = 0;
    var session = try Session.init(std.testing.allocator, 4, 4, 4, .{
        .ctx = &wake_ctx,
        .notify_fn = FailingWake.fail,
    });
    defer session.deinit();

    // A 4-byte queue would otherwise make this call wait after its first
    // chunk.  The failed wake must return immediately instead.
    try std.testing.expectError(error.WakeFailed, session.write("eightbyt"));
    try std.testing.expect(session.hasWakeFailure());
    try std.testing.expect(session.hasWriteFailure());
    try std.testing.expectError(error.WriteFailed, session.write("retry"));
}

test "failed consumer control wakes remain observable for runtime cleanup" {
    const FailingWake = struct {
        fn fail(_: *anyopaque) anyerror!void {
            return error.BrokenWake;
        }
    };
    var wake_ctx: u8 = 0;

    var cancelled = try Session.init(std.testing.allocator, 4, 4, 4, .{
        .ctx = &wake_ctx,
        .notify_fn = FailingWake.fail,
    });
    defer cancelled.deinit();
    cancelled.requestCancel();
    try std.testing.expect(cancelled.takeCancelRequest());
    try std.testing.expect(cancelled.hasWakeFailure());
    try std.testing.expect(cancelled.hasWriteFailure());

    var finished = try Session.init(std.testing.allocator, 4, 4, 4, .{
        .ctx = &wake_ctx,
        .notify_fn = FailingWake.fail,
    });
    defer finished.deinit();
    finished.finishLocal();
    try std.testing.expect(finished.hasWakeFailure());
    try std.testing.expect(finished.hasWriteFailure());
}
