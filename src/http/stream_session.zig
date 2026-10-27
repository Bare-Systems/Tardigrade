//! Bounded, connection-owned byte session for long-lived downstream streams.
//!
//! A protocol reactor owns `deliver*`, `peekOutbound`, and terminal delivery;
//! a worker owns `read`, `write`, and `consumerDetach`.  The worker never sees
//! the underlying connection.  This is deliberately protocol-neutral so H3
//! can use the same tunnel ownership contract as H2 without sharing a socket
//! or QUIC connection with a relay.
const std = @import("std");
const compat = @import("zig_compat");

pub const Error = error{ QueueFull, Closed, InvalidCapacity, WakeFailed } || std.mem.Allocator.Error;

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
        self.signalWakeLocked();
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
                self.signalWakeLocked();
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
        var remaining = bytes;
        while (remaining.len > 0) {
            if (self.terminal) |terminal| return writeTerminal(terminal);
            if (self.local_end_requested) return .finished;
            const capacity = self.max_outbound_bytes -| self.outbound_bytes;
            if (capacity == 0) {
                self.cond.wait(&self.mutex);
                continue;
            }
            const n = @min(capacity, remaining.len);
            const owned = try self.allocator.dupe(u8, remaining[0..n]);
            errdefer self.allocator.free(owned);
            try self.outbound.append(self.allocator, .{ .bytes = owned });
            self.outbound_bytes += n;
            remaining = remaining[n..];
            self.signalWakeLocked();
        }
        return .ok;
    }

    pub fn finishLocal(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.local_end_requested = true;
        self.signalWakeLocked();
    }

    pub fn requestCancel(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.terminal != null) return;
        self.cancel_requested = true;
        self.signalWakeLocked();
    }

    pub fn consumerDetach(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.consumer_attached);
        self.consumer_attached = false;
        return !self.runtime_attached;
    }

    fn signalWakeLocked(self: *Session) void {
        const wake = self.wake orelse return;
        wake.notify() catch {
            self.wake_failed = true;
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
