//! Connection-owned, bounded, bidirectional HTTP/2 stream session (#867).
//!
//! The connection runtime remains the sole owner of the TCP/TLS socket and
//! all HTTP/2 framing. A `Session` is the generic transport primitive a
//! long-lived stream consumer (a future RFC 8441 WebSocket, today only a
//! test/integration consumer) uses instead of the connection socket:
//!
//!   - the runtime delivers inbound DATA incrementally via `deliverInbound`
//!     and drains outbound bytes via `peekOutbound`/`commitOutboundSent`,
//!     applying its own HTTP/2 flow-control and max-frame-size accounting
//!     exactly as it already does for finite #866 responses;
//!   - the consumer calls the blocking `read`/`write` pair from its own
//!     worker (thread-per-connection model, see `worker_pool.zig`), never
//!     touching the connection's socket or TLS object.
//!
//! Receive-window credit is only earned when the consumer actually drains
//! queued bytes (`takeReceiveCreditToReturn`), not when bytes are merely
//! queued. A stalled consumer therefore caps retained memory at
//! `max_inbound_bytes` by starving the runtime's WINDOW_UPDATE emission,
//! rather than by growing an unbounded buffer. Outbound memory is bounded
//! the same way: `write` blocks once `max_outbound_bytes` are queued until
//! the runtime drains them.
//!
//! Both directions settle at most once. `deliverReset`, `deliverGoaway`,
//! `deliverConnectionClosed`, and `deliverShutdown` all route through
//! `settleLocked`, which frees every queued byte immediately so a terminal
//! stream never retains memory waiting for a consumer that already stopped
//! reading.
const std = @import("std");
const compat = @import("zig_compat");
const http2_stream = @import("http2_stream.zig");
const h2_transport_metrics = @import("h2_transport_metrics.zig");

pub const Error = error{ QueueFull, Closed, WakeFailed, InvalidCapacity } || std.mem.Allocator.Error;

pub const TerminalReason = enum {
    reset,
    goaway,
    connection_closed,
    shutdown,
};

pub const Terminal = struct {
    reason: TerminalReason,
    error_code: http2_stream.ErrorCode = .no_error,
};

pub const ReadResult = union(enum) {
    /// `buf[0..n]` was filled from the inbound queue.
    data: usize,
    /// The inbound queue is empty and the remote sent END_STREAM.
    end_stream,
    reset: http2_stream.ErrorCode,
    closed: TerminalReason,
};

pub const WriteResult = union(enum) {
    ok,
    reset: http2_stream.ErrorCode,
    closed: TerminalReason,
    /// `write` was called after `finishLocal`. Local production is already
    /// over; this is a caller bug, not a protocol-level terminal event.
    finished,
};

const Chunk = struct {
    bytes: []u8,
    offset: usize = 0,

    fn remaining(self: *const Chunk) []const u8 {
        return self.bytes[self.offset..];
    }
};

/// A connection-owned, bidirectional HTTP/2 stream transport.
///
/// Exactly two parties hold a reference: the connection runtime and the
/// stream consumer. Each must call its `*Detach` exactly once; the session
/// frees itself when the second detach observes the other already gone.
/// The consumer's reference *is* its stream handle — it carries no socket
/// or TLS access.
pub const Session = struct {
    allocator: std.mem.Allocator,
    stream_id: u31,
    max_inbound_bytes: usize,
    max_outbound_bytes: usize,

    mutex: compat.Mutex = .{},
    cond: compat.Condition = .{},

    inbound: std.ArrayList(Chunk) = .empty,
    inbound_bytes: usize = 0,
    inbound_credit_to_return: usize = 0,
    remote_end_stream: bool = false,

    outbound: std.ArrayList(Chunk) = .empty,
    outbound_bytes: usize = 0,
    local_end_requested: bool = false,
    local_end_sent: bool = false,

    cancel_requested: bool = false,
    terminal: ?Terminal = null,

    wake_read: std.posix.fd_t = -1,
    wake_write: std.posix.fd_t = -1,
    wake_pending: bool = false,
    /// A wake notification was lost (the pipe write failed with something
    /// other than a coalesced EAGAIN). The runtime must treat this as fatal
    /// for the stream -- it can no longer learn about inbound credit or
    /// outbound bytes becoming available -- rather than silently stalling.
    wake_failed: bool = false,
    /// A producer `write` failed (allocator error), possibly after already
    /// queuing part of its input. A caller that retried the same bytes
    /// would duplicate whatever prefix already reached the queue, so
    /// further writes are rejected immediately and the runtime must treat
    /// this as fatal for the stream (RST_STREAM and detach), exactly like
    /// `wake_failed`.
    write_failed: bool = false,

    runtime_attached: bool = true,
    consumer_attached: bool = true,
    /// #951 second review: a handle to this session's own slot, claimed
    /// once at `init` and used directly for every later update/unregister
    /// instead of a `stream_id`-only lookup -- two simultaneous connections
    /// commonly both use stream id 1, and a lookup keyed on stream id alone
    /// would route both sessions' updates to whichever slot matched first.
    metrics_slot: ?h2_transport_metrics.SlotHandle = null,

    pub fn init(allocator: std.mem.Allocator, connection_id: u64, stream_id: u31, max_inbound_bytes: usize, max_outbound_bytes: usize) Error!Session {
        if (max_inbound_bytes == 0 or max_outbound_bytes == 0) return error.InvalidCapacity;
        var fds: [2]std.posix.fd_t = undefined;
        if (std.c.pipe(&fds) != 0) return error.WakeFailed;
        errdefer {
            _ = std.c.close(fds[0]);
            _ = std.c.close(fds[1]);
        }
        try setNonBlocking(fds[0]);
        try setNonBlocking(fds[1]);
        // #951 review: register this stream's own slot in the process-wide
        // per-stream table (`h2_transport_metrics.sessionSlotRegister`)
        // *before* this session is reachable by any producer/consumer, so
        // the slot always exists once bytes can actually be queued against
        // it -- `sessionSlotUpdate`'s no-op-on-miss behavior would otherwise
        // silently drop every update for this stream.
        const metrics_slot = h2_transport_metrics.sessionSlotRegister(connection_id, stream_id);
        return .{
            .allocator = allocator,
            .stream_id = stream_id,
            .max_inbound_bytes = max_inbound_bytes,
            .max_outbound_bytes = max_outbound_bytes,
            .wake_read = fds[0],
            .wake_write = fds[1],
            .metrics_slot = metrics_slot,
        };
    }

    /// Publish this stream's current queue occupancy into its own
    /// per-stream slot (#951 review), called under `self.mutex` right after
    /// every site that already updates the process-wide aggregate via
    /// `h2_transport_metrics.sessionQueuedBytesChanged`.
    fn publishQueueSlot(self: *const Session) void {
        h2_transport_metrics.sessionSlotUpdate(self.metrics_slot, self.inbound_bytes, self.outbound_bytes);
    }

    /// Only valid once both the runtime and the consumer have detached.
    ///
    /// #951 review: `settleLocked` already refunds the global queued-bytes
    /// gauge and zeroes `inbound_bytes`/`outbound_bytes` on every terminal
    /// path, but a session destroyed without ever settling (e.g. the
    /// runtime and consumer both detach normally while bytes are still
    /// queued) would otherwise free those chunks here without refunding
    /// the gauge, permanently overstating it. Refund whatever is still
    /// outstanding exactly once before freeing; this is a no-op after
    /// `settleLocked` already zeroed both counters.
    pub fn deinit(self: *Session) void {
        const outstanding: i64 = @intCast(self.inbound_bytes + self.outbound_bytes);
        if (outstanding > 0) h2_transport_metrics.sessionQueuedBytesChanged(-outstanding);
        h2_transport_metrics.sessionSlotUnregister(self.metrics_slot);
        for (self.inbound.items) |chunk| self.allocator.free(chunk.bytes);
        self.inbound.deinit(self.allocator);
        for (self.outbound.items) |chunk| self.allocator.free(chunk.bytes);
        self.outbound.deinit(self.allocator);
        if (self.wake_read >= 0) _ = std.c.close(self.wake_read);
        if (self.wake_write >= 0) _ = std.c.close(self.wake_write);
        self.* = undefined;
    }

    pub fn wakeFd(self: *const Session) std.posix.fd_t {
        return self.wake_read;
    }

    // -- Runtime-facing: producer of inbound, consumer of outbound --------

    /// Deliver one incremental inbound DATA payload. The runtime must size
    /// deliveries within the receive window it already advertised; a
    /// `QueueFull` here signals a peer that exceeded that window.
    pub fn deliverInbound(self: *Session, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.terminal != null) return error.Closed;
        if (self.remote_end_stream) return error.Closed;
        if (bytes.len > self.max_inbound_bytes -| self.inbound_bytes) return error.QueueFull;
        const owned = try self.allocator.dupe(u8, bytes);
        errdefer self.allocator.free(owned);
        try self.inbound.append(self.allocator, .{ .bytes = owned });
        self.inbound_bytes += owned.len;
        h2_transport_metrics.sessionQueuedBytesChanged(@intCast(owned.len));
        self.publishQueueSlot();
        self.cond.signal();
    }

    pub fn deliverRemoteEndStream(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.terminal != null) return;
        self.remote_end_stream = true;
        self.cond.broadcast();
    }

    pub fn deliverReset(self: *Session, code: http2_stream.ErrorCode) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.settleLocked(.{ .reason = .reset, .error_code = code });
    }

    pub fn deliverGoaway(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.settleLocked(.{ .reason = .goaway });
    }

    pub fn deliverConnectionClosed(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.settleLocked(.{ .reason = .connection_closed });
    }

    pub fn deliverShutdown(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.settleLocked(.{ .reason = .shutdown });
    }

    /// Settle exactly once: first terminal event wins, queued bytes are
    /// released immediately, and both a blocked consumer (`cond`) and a
    /// blocked runtime poll (`wake`) are notified.
    ///
    /// Unread inbound bytes already charged the peer's connection-level
    /// receive window (the runtime only credits application bytes once a
    /// consumer actually drains them). Discarding them here without folding
    /// them into `inbound_credit_to_return` would leak that connection
    /// credit forever once the stream is gone; the caller is expected to
    /// `takeReceiveCreditToReturn` after settling and return it with a
    /// stream-0-only WINDOW_UPDATE, since the stream itself is closing.
    fn settleLocked(self: *Session, terminal: Terminal) void {
        if (self.terminal != null) return;
        self.terminal = terminal;
        self.inbound_credit_to_return += self.inbound_bytes;
        const released: i64 = @intCast(self.inbound_bytes + self.outbound_bytes);
        for (self.inbound.items) |chunk| self.allocator.free(chunk.bytes);
        self.inbound.clearAndFree(self.allocator);
        self.inbound_bytes = 0;
        for (self.outbound.items) |chunk| self.allocator.free(chunk.bytes);
        self.outbound.clearAndFree(self.allocator);
        self.outbound_bytes = 0;
        if (released > 0) h2_transport_metrics.sessionQueuedBytesChanged(-released);
        self.publishQueueSlot();
        self.cond.broadcast();
        self.signalWakeLocked() catch {
            self.wake_failed = true;
        };
    }

    /// Borrow up to `max_len` contiguous outbound bytes from the front of
    /// the queue. The caller must `commitOutboundSent` before the next call;
    /// the borrow is invalidated by any other session method in between.
    pub fn peekOutbound(self: *Session, max_len: usize) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.outbound.items.len == 0) return null;
        const front = self.outbound.items[0].remaining();
        return front[0..@min(front.len, max_len)];
    }

    /// Release `n` bytes already written to the wire from the front of the
    /// outbound queue, freeing fully-consumed chunks and waking a producer
    /// blocked on queue capacity.
    pub fn commitOutboundSent(self: *Session, n: usize) void {
        if (n == 0) return;
        self.mutex.lock();
        defer self.mutex.unlock();
        var remaining = n;
        while (remaining > 0 and self.outbound.items.len > 0) {
            const chunk = &self.outbound.items[0];
            const avail = chunk.bytes.len - chunk.offset;
            const take = @min(avail, remaining);
            chunk.offset += take;
            remaining -= take;
            self.outbound_bytes -= take;
            if (chunk.offset == chunk.bytes.len) {
                self.allocator.free(chunk.bytes);
                _ = self.outbound.orderedRemove(0);
            }
        }
        const committed = n - remaining;
        if (committed > 0) h2_transport_metrics.sessionQueuedBytesChanged(-@as(i64, @intCast(committed)));
        self.publishQueueSlot();
        self.cond.broadcast();
    }

    pub fn hasPendingOutbound(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.outbound.items.len > 0;
    }

    /// True once the consumer finished producing and every outbound byte has
    /// drained: the runtime should send END_STREAM on its next DATA frame
    /// (or an empty one) and call `markLocalEndStreamSent`.
    pub fn outboundLocalEndPending(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.local_end_requested and !self.local_end_sent and self.outbound.items.len == 0;
    }

    pub fn markLocalEndStreamSent(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.local_end_sent = true;
    }

    /// True once the runtime has actually emitted the final END_STREAM.
    /// A relay that observed a clean upstream EOF uses this to release its
    /// upstream resources without turning a completed graceful close into a
    /// late RST_STREAM.
    pub fn localEndStreamSent(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.local_end_sent;
    }

    /// True once the downstream peer has ended its half of the stream. A
    /// relay may finish a clean upstream EOF without a RST only after both
    /// halves have completed; otherwise its blocked `read` consumer still
    /// needs cancellation to wake.
    pub fn remoteEndStreamReceived(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.remote_end_stream;
    }

    /// Drain and reset the receive-window credit earned by consumer reads
    /// since the last call. The runtime uses this to size WINDOW_UPDATE.
    pub fn takeReceiveCreditToReturn(self: *Session) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const credit = self.inbound_credit_to_return;
        self.inbound_credit_to_return = 0;
        return credit;
    }

    /// Read the receive-window credit earned so far, without clearing it.
    /// Pairs with `consumeReceiveCredit` so a runtime that must emit two
    /// WINDOW_UPDATE frames (stream + connection) for the same credit can
    /// retry on partial failure instead of losing it, by only clearing the
    /// amount it actually finished emitting.
    pub fn peekReceiveCreditToReturn(self: *Session) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.inbound_credit_to_return;
    }

    /// Clear `amount` of previously peeked credit that the runtime confirmed
    /// it emitted. Any credit that accrued after the matching `peek` (a
    /// consumer read racing the runtime's drain) remains pending.
    pub fn consumeReceiveCredit(self: *Session, amount: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.inbound_credit_to_return -= @min(amount, self.inbound_credit_to_return);
    }

    /// True if the consumer requested cancellation (`requestCancel`). The
    /// runtime should answer with RST_STREAM and call `deliverReset`.
    pub fn takeCancelRequest(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const requested = self.cancel_requested;
        self.cancel_requested = false;
        return requested;
    }

    /// The runtime calls this exactly once when it stops servicing the
    /// stream (stream fully closed, GOAWAY/connection teardown already
    /// settled). Returns true when the caller must now `deinit` the session.
    pub fn runtimeDetach(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.runtime_attached);
        self.runtime_attached = false;
        return !self.consumer_attached;
    }

    // -- Consumer-facing: blocking read/write from the worker thread ------

    /// Block until inbound bytes, remote END_STREAM, or a terminal event is
    /// observed. Never spins: waits on `cond`, which the runtime signals.
    pub fn read(self: *Session, buf: []u8) ReadResult {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (true) {
            if (self.inbound.items.len > 0) {
                const chunk = &self.inbound.items[0];
                const avail = chunk.remaining();
                const n = @min(avail.len, buf.len);
                @memcpy(buf[0..n], avail[0..n]);
                chunk.offset += n;
                self.inbound_bytes -= n;
                h2_transport_metrics.sessionQueuedBytesChanged(-@as(i64, @intCast(n)));
                self.publishQueueSlot();
                self.inbound_credit_to_return += n;
                if (chunk.offset == chunk.bytes.len) {
                    self.allocator.free(chunk.bytes);
                    _ = self.inbound.orderedRemove(0);
                }
                self.signalWakeLocked() catch {
                    self.wake_failed = true;
                };
                return .{ .data = n };
            }
            if (self.terminal) |terminal| return terminalReadResult(terminal);
            if (self.remote_end_stream) return .end_stream;
            self.cond.wait(&self.mutex);
        }
    }

    /// Block until `bytes` is fully queued, local production is already
    /// finished, or a terminal event is observed. Queue capacity bounds
    /// outbound memory even if the runtime is slow to drain (e.g. the client
    /// is a slow reader). Allocator failures propagate to the caller instead
    /// of blocking forever: there is no guarantee free capacity will ever
    /// appear to unblock a retry, and nothing else would signal this waiter.
    ///
    /// An allocator failure here can happen after one or more earlier
    /// chunks of this same `bytes` were already queued successfully, so the
    /// caller cannot tell from the error alone how much was accepted.
    /// Rather than leave that ambiguous, a failure sets `write_failed`
    /// sticky: this and every later `write` fail fast with `.reset` instead
    /// of risking a retry that duplicates an already-queued prefix on the
    /// wire, and the runtime detects the flag and tears the stream down.
    pub fn write(self: *Session, bytes: []const u8) Error!WriteResult {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.write_failed) return .{ .reset = .internal_error };
        var remaining = bytes;
        while (remaining.len > 0) {
            if (self.terminal) |terminal| return terminalWriteResult(terminal);
            if (self.local_end_requested) return .finished;
            const capacity = self.max_outbound_bytes -| self.outbound_bytes;
            if (capacity == 0) {
                self.cond.wait(&self.mutex);
                continue;
            }
            const n = @min(capacity, remaining.len);
            const owned = self.allocator.dupe(u8, remaining[0..n]) catch |err| {
                self.write_failed = true;
                self.signalWakeLocked() catch {
                    self.wake_failed = true;
                };
                return err;
            };
            self.outbound.append(self.allocator, .{ .bytes = owned }) catch |err| {
                self.allocator.free(owned);
                self.write_failed = true;
                self.signalWakeLocked() catch {
                    self.wake_failed = true;
                };
                return err;
            };
            self.outbound_bytes += n;
            h2_transport_metrics.sessionQueuedBytesChanged(@intCast(n));
            self.publishQueueSlot();
            remaining = remaining[n..];
            self.signalWakeLocked() catch {
                self.wake_failed = true;
            };
        }
        return .ok;
    }

    /// Mark local production finished. Idempotent.
    pub fn finishLocal(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.local_end_requested) return;
        self.local_end_requested = true;
        self.signalWakeLocked() catch {
            self.wake_failed = true;
        };
    }

    /// Ask the runtime to RST_STREAM this session (consumer-originated
    /// cancellation). The runtime observes this via `takeCancelRequest`.
    pub fn requestCancel(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.terminal != null) return;
        self.cancel_requested = true;
        self.signalWakeLocked() catch {
            self.wake_failed = true;
        };
    }

    /// True once a wake notification was lost. The runtime must treat this
    /// as connection-fatal for the stream (RST_STREAM and detach) rather
    /// than risk a consumer or producer stalling forever on a signal that
    /// will never arrive.
    pub fn hasWakeFailure(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.wake_failed;
    }

    /// True once a producer `write` failed irrecoverably (see `write`'s
    /// doc comment). The runtime must treat this as connection-fatal for
    /// the stream exactly like `hasWakeFailure`.
    pub fn hasWriteFailure(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.write_failed;
    }

    /// The consumer calls this exactly once when it stops using the handle.
    /// Returns true when the caller must now `deinit` the session.
    pub fn consumerDetach(self: *Session) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(self.consumer_attached);
        self.consumer_attached = false;
        return !self.runtime_attached;
    }

    fn signalWakeLocked(self: *Session) Error!void {
        if (self.wake_pending) return;
        const byte = [_]u8{1};
        while (true) {
            const n = std.c.write(self.wake_write, &byte, 1);
            if (n == 1) {
                self.wake_pending = true;
                return;
            }
            if (n < 0 and std.posix.errno(n) == .INTR) continue;
            if (n < 0 and std.posix.errno(n) == .AGAIN) {
                self.wake_pending = true;
                return;
            }
            return error.WakeFailed;
        }
    }

    /// Drain the coalesced wake notification. The runtime calls this after
    /// servicing the session so a later producer can signal again.
    pub fn clearWake(self: *Session) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var bytes: [64]u8 = undefined;
        while (true) {
            const n = std.c.read(self.wake_read, &bytes, bytes.len);
            if (n <= 0) break;
        }
        self.wake_pending = false;
    }
};

fn terminalReadResult(terminal: Terminal) ReadResult {
    return switch (terminal.reason) {
        .reset => .{ .reset = terminal.error_code },
        .goaway, .connection_closed, .shutdown => .{ .closed = terminal.reason },
    };
}

fn terminalWriteResult(terminal: Terminal) WriteResult {
    return switch (terminal.reason) {
        .reset => .{ .reset = terminal.error_code },
        .goaway, .connection_closed, .shutdown => .{ .closed = terminal.reason },
    };
}

fn setNonBlocking(fd: std.posix.fd_t) Error!void {
    const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (flags < 0 or std.c.fcntl(fd, std.c.F.SETFL, flags | @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }))) < 0)
        return error.WakeFailed;
}

fn destroyDetached(allocator: std.mem.Allocator, session: *Session) void {
    session.deinit();
    allocator.destroy(session);
}

test "inbound DATA is delivered incrementally without buffering the full request" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 1024, 1024);
    defer session.deinit();

    try session.deliverInbound("first");
    var buf: [16]u8 = undefined;
    const r1 = session.read(&buf);
    try std.testing.expectEqual(ReadResult{ .data = 5 }, r1);
    try std.testing.expectEqualSlices(u8, "first", buf[0..5]);

    try session.deliverInbound("second");
    const r2 = session.read(&buf);
    try std.testing.expectEqual(ReadResult{ .data = 6 }, r2);
    try std.testing.expectEqualSlices(u8, "second", buf[0..6]);
}

test "inbound queue is bounded and rejects a delivery exceeding capacity" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 8, 1024);
    defer session.deinit();

    try session.deliverInbound("12345678");
    try std.testing.expectError(error.QueueFull, session.deliverInbound("x"));

    var buf: [8]u8 = undefined;
    _ = session.read(&buf);
    try session.deliverInbound("y");
}

test "receive credit accrues only on consumption, not on queuing" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 1024, 1024);
    defer session.deinit();

    try session.deliverInbound("abcd");
    try std.testing.expectEqual(@as(usize, 0), session.takeReceiveCreditToReturn());

    var buf: [4]u8 = undefined;
    _ = session.read(&buf);
    try std.testing.expectEqual(@as(usize, 4), session.takeReceiveCreditToReturn());
    try std.testing.expectEqual(@as(usize, 0), session.takeReceiveCreditToReturn());
}

test "remote END_STREAM only settles read after the queue drains" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 1024, 1024);
    defer session.deinit();

    try session.deliverInbound("tail");
    session.deliverRemoteEndStream();

    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(ReadResult{ .data = 4 }, session.read(&buf));
    try std.testing.expectEqual(ReadResult.end_stream, session.read(&buf));
}

test "outbound production is segmented by caller-provided max length" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 1024, 1024);
    defer session.deinit();

    try std.testing.expectEqual(WriteResult.ok, try session.write("0123456789"));
    const first = session.peekOutbound(4).?;
    try std.testing.expectEqualSlices(u8, "0123", first);
    session.commitOutboundSent(4);

    const second = session.peekOutbound(100).?;
    try std.testing.expectEqualSlices(u8, "456789", second);
    session.commitOutboundSent(6);

    try std.testing.expectEqual(@as(?[]const u8, null), session.peekOutbound(4));
}

test "local END_STREAM is pending only after producer finishes and queue drains" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 1024, 1024);
    defer session.deinit();

    try std.testing.expectEqual(WriteResult.ok, try session.write("bytes"));
    session.finishLocal();
    try std.testing.expect(!session.outboundLocalEndPending());

    session.commitOutboundSent(5);
    try std.testing.expect(session.outboundLocalEndPending());
    session.markLocalEndStreamSent();
    try std.testing.expect(!session.outboundLocalEndPending());
    try std.testing.expect(session.localEndStreamSent());
}

test "write after finishLocal is rejected before and after markLocalEndStreamSent" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 1024, 1024);
    defer session.deinit();

    session.finishLocal();
    try std.testing.expectEqual(WriteResult.finished, try session.write("too-late"));

    session.markLocalEndStreamSent();
    try std.testing.expectEqual(WriteResult.finished, try session.write("still-too-late"));
}

test "zero-capacity session configuration is rejected" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidCapacity, Session.init(allocator, 1, 1, 0, 64));
    try std.testing.expectError(error.InvalidCapacity, Session.init(allocator, 1, 1, 64, 0));
}

test "an allocator failure during write propagates instead of blocking forever" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var session = try Session.init(failing.allocator(), 1, 1, 1024, 1024);
    defer session.deinit();

    try std.testing.expectError(error.OutOfMemory, session.write("bytes"));
}

test "RST_STREAM settles exactly once, releases queued bytes, and wakes both sides" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 1024, 1024);
    defer session.deinit();

    try session.deliverInbound("queued");
    try std.testing.expectEqual(WriteResult.ok, try session.write("queued-out"));

    session.deliverReset(.cancel);
    session.deliverReset(.flow_control_error); // second settle is a no-op

    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(ReadResult{ .reset = .cancel }, session.read(&buf));
    try std.testing.expectEqual(WriteResult{ .reset = .cancel }, try session.write("more"));
    try std.testing.expectError(error.Closed, session.deliverInbound("late"));
}

test "GOAWAY, connection close, and shutdown settle as closed with their own reason" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { reason: TerminalReason, trigger: *const fn (*Session) void }{
        .{ .reason = .goaway, .trigger = Session.deliverGoaway },
        .{ .reason = .connection_closed, .trigger = Session.deliverConnectionClosed },
        .{ .reason = .shutdown, .trigger = Session.deliverShutdown },
    };
    for (cases) |case| {
        var session = try Session.init(allocator, 1, 1, 1024, 1024);
        defer session.deinit();
        case.trigger(&session);
        var buf: [4]u8 = undefined;
        try std.testing.expectEqual(ReadResult{ .closed = case.reason }, session.read(&buf));
        try std.testing.expectEqual(WriteResult{ .closed = case.reason }, try session.write("x"));
    }
}

test "deinit refunds the global queued-bytes gauge exactly once, with or without a prior settle" {
    const allocator = std.testing.allocator;

    // No settle before deinit: `settleLocked` never zeroed the counters, so
    // `deinit` itself must refund whatever is still queued.
    h2_transport_metrics.resetForTesting();
    {
        var session = try Session.init(allocator, 1, 1, 1024, 1024);
        try session.deliverInbound("queued-in");
        try std.testing.expectEqual(WriteResult.ok, try session.write("queued-out"));
        try std.testing.expectEqual(@as(u64, "queued-in".len + "queued-out".len), h2_transport_metrics.snapshot().session_queued_bytes);
        session.deinit();
    }
    try std.testing.expectEqual(@as(u64, 0), h2_transport_metrics.snapshot().session_queued_bytes);

    // Settle before deinit: `settleLocked` already refunded and zeroed both
    // counters, so `deinit`'s own refund must be a no-op, not a double
    // refund driving the gauge negative (clamped to 0 by `snapshot`).
    h2_transport_metrics.resetForTesting();
    {
        var session = try Session.init(allocator, 1, 1, 1024, 1024);
        try session.deliverInbound("queued-in");
        try std.testing.expectEqual(WriteResult.ok, try session.write("queued-out"));
        session.deliverReset(.cancel);
        try std.testing.expectEqual(@as(u64, 0), h2_transport_metrics.snapshot().session_queued_bytes);
        session.deinit();
    }
    try std.testing.expectEqual(@as(u64, 0), h2_transport_metrics.snapshot().session_queued_bytes);
}

test "consumer-requested cancellation is observed exactly once by the runtime" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 1024, 1024);
    defer session.deinit();

    try std.testing.expect(!session.takeCancelRequest());
    session.requestCancel();
    try std.testing.expect(session.takeCancelRequest());
    try std.testing.expect(!session.takeCancelRequest());
}

test "a lost wake notification is surfaced as a sticky failure instead of dropped" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 1024, 1024);
    defer session.deinit();

    // Closing only the write end is a deterministic fault injection,
    // mirroring how `h2_request_handoff` tests the same failure mode.
    _ = std.c.close(session.wake_write);
    session.wake_write = -1;

    try std.testing.expect(!session.hasWakeFailure());
    session.requestCancel();
    try std.testing.expect(session.hasWakeFailure());
}

test "wake notification coalesces across multiple producer signals" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 1024, 1024);
    defer session.deinit();

    try std.testing.expectEqual(WriteResult.ok, try session.write("a"));
    try std.testing.expectEqual(WriteResult.ok, try session.write("b"));
    session.finishLocal();

    var pfd = [_]std.posix.pollfd{.{ .fd = session.wakeFd(), .events = std.posix.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&pfd, 0));
    session.clearWake();

    pfd[0].revents = 0;
    try std.testing.expectEqual(@as(usize, 0), try std.posix.poll(&pfd, 0));
}

test "a stalled consumer stops earning receive credit, bounding retained memory" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 16, 1024);
    defer session.deinit();

    try session.deliverInbound("0123456789012345");
    try std.testing.expectError(error.QueueFull, session.deliverInbound("x"));
    try std.testing.expectEqual(@as(usize, 0), session.takeReceiveCreditToReturn());
}

test "two-party detach frees the session only after both sides release" {
    const allocator = std.testing.allocator;
    const session = try allocator.create(Session);
    session.* = try Session.init(allocator, 1, 1, 64, 64);

    try std.testing.expect(!session.runtimeDetach());
    try std.testing.expect(session.consumerDetach());
    destroyDetached(allocator, session);
}

test "repeated attach/close churn settles resources with no leak" {
    const allocator = std.testing.allocator;
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        const session = try allocator.create(Session);
        session.* = try Session.init(allocator, 1, @intCast(i + 1), 64, 64);
        try session.deliverInbound("x");
        try session.deliverInbound("y");
        session.deliverReset(.cancel);
        const runtime_last = session.runtimeDetach();
        const consumer_last = session.consumerDetach();
        try std.testing.expect(runtime_last or consumer_last);
        destroyDetached(allocator, session);
    }
}

test "blocked read wakes deterministically when inbound is delivered from another thread" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 64, 64);
    defer session.deinit();

    const Ctx = struct {
        session: *Session,
        result: ReadResult = undefined,
        fn run(ctx: *@This()) void {
            var buf: [16]u8 = undefined;
            ctx.result = ctx.session.read(&buf);
        }
    };
    var ctx = Ctx{ .session = &session };
    const reader = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});

    // `deliverInbound` and `read` both serialize through `session.mutex`, so
    // whichever side runs first observes a consistent queue: there is no
    // lost-wakeup window to race here regardless of thread scheduling.
    try session.deliverInbound("woke");
    reader.join();
    try std.testing.expectEqual(ReadResult{ .data = 4 }, ctx.result);
}

test "blocked write wakes deterministically when the runtime commits queued bytes" {
    const allocator = std.testing.allocator;
    var session = try Session.init(allocator, 1, 1, 64, 4);
    defer session.deinit();

    const Ctx = struct {
        session: *Session,
        result: Error!WriteResult = undefined,
        fn run(ctx: *@This()) void {
            ctx.result = ctx.session.write("abcdefgh");
        }
    };
    var ctx = Ctx{ .session = &session };
    const writer_thread = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});

    // The writer can only fill its 4-byte bound and then must block; spin
    // until that first chunk lands rather than sleeping an arbitrary delay.
    while (!session.hasPendingOutbound()) {}
    session.commitOutboundSent(4);
    writer_thread.join();
    try std.testing.expectEqual(WriteResult.ok, try ctx.result);
    try std.testing.expectEqual(@as(usize, 4), session.outbound_bytes);
    session.commitOutboundSent(4);
}

test "two sessions on different connections sharing a stream id do not corrupt each other's metrics (#951 second review)" {
    const allocator = std.testing.allocator;
    h2_transport_metrics.resetForTesting();
    // Two simultaneous H2 connections commonly both use stream id 1; each
    // `Session.init` call below claims its own metrics slot scoped by a
    // distinct `connection_id`, not by `stream_id` alone.
    var session_a = try Session.init(allocator, 100, 1, 1024, 1024);
    defer session_a.deinit();
    var session_b = try Session.init(allocator, 200, 1, 1024, 1024);
    defer session_b.deinit();

    try session_a.deliverInbound("from-a");
    try session_b.deliverInbound("from-b-longer");

    var buf: [8]h2_transport_metrics.SessionSlotSnapshot = undefined;
    const slots = h2_transport_metrics.snapshotSessionSlots(&buf);
    try std.testing.expectEqual(@as(usize, 2), slots.len);
    for (slots) |slot| {
        try std.testing.expectEqual(@as(u31, 1), slot.stream_id);
        if (slot.connection_id == 100) {
            try std.testing.expectEqual(@as(u64, "from-a".len), slot.queued_bytes);
        } else if (slot.connection_id == 200) {
            try std.testing.expectEqual(@as(u64, "from-b-longer".len), slot.queued_bytes);
        } else {
            return error.TestUnexpectedResult;
        }
    }

    // Draining session_a must not disturb session_b's independently-tracked
    // slot, and unregistering session_a (via deinit, below) must only ever
    // release its own slot.
    var drain_buf: [16]u8 = undefined;
    _ = session_a.read(&drain_buf);
    const after_drain = h2_transport_metrics.snapshotSessionSlots(&buf);
    try std.testing.expectEqual(@as(usize, 2), after_drain.len);
    for (after_drain) |slot| {
        if (slot.connection_id == 200) try std.testing.expectEqual(@as(u64, "from-b-longer".len), slot.queued_bytes);
    }
}
