//! QUIC streams (#245, RFC 9000 §2-§4, §19.8-§19.13): per-stream send/receive
//! state, stream- and connection-level flow control, RESET_STREAM /
//! STOP_SENDING, and the backpressure integration that HTTP/3 relies on.
//!
//! The packet layer owns wire encoding. This module accepts decoded STREAM-like
//! inputs, returns explicit read/write grants and flow-credit updates, and keeps
//! all stream buffers bounded by the transport parameters in `config.zig`.

const std = @import("std");

const config = @import("config.zig");

pub const StreamId = u64;

pub const EndpointRole = enum {
    client,
    server,

    fn initiator(self: EndpointRole) Initiator {
        return switch (self) {
            .client => .client,
            .server => .server,
        };
    }
};

pub const Initiator = enum {
    client,
    server,
};

pub const StreamType = enum {
    bidi,
    uni,
};

pub const StreamState = enum {
    open,
    half_closed_local,
    half_closed_remote,
    closed,
    reset_received,
    reset_sent,
};

pub const StreamFrame = struct {
    id: StreamId,
    offset: u64,
    data: []const u8,
    fin: bool = false,
};

pub const ResetStreamFrame = struct {
    id: StreamId,
    app_error_code: u64,
    final_size: u64,
};

pub const StopSendingFrame = struct {
    id: StreamId,
    app_error_code: u64,
};

pub const SendGrant = struct {
    id: StreamId,
    offset: u64,
    len: usize,
    fin: bool,
};

pub const ReadResult = struct {
    len: usize,
    fin: bool,
    credit: FlowCredit = .{},
};

pub const FlowCredit = struct {
    max_data: ?u64 = null,
    max_stream_data: ?u64 = null,
};

pub const Metrics = struct {
    active_streams: u64 = 0,
    opened_streams: u64 = 0,
    closed_streams: u64 = 0,
    reset_streams: u64 = 0,
    stop_sending_events: u64 = 0,
    data_blocked_events: u64 = 0,
    stream_data_blocked_events: u64 = 0,
    streams_blocked_events: u64 = 0,
    max_data_credit_events: u64 = 0,
    max_stream_data_credit_events: u64 = 0,
};

pub fn makeStreamId(init: Initiator, typ: StreamType, ordinal_value: u64) !StreamId {
    if (ordinal_value > (std.math.maxInt(StreamId) >> 2)) return error.InvalidStreamId;
    return (ordinal_value << 2) |
        (switch (typ) {
            .bidi => @as(StreamId, 0),
            .uni => @as(StreamId, 0x2),
        }) |
        (switch (init) {
            .client => @as(StreamId, 0),
            .server => @as(StreamId, 0x1),
        });
}

pub fn streamInitiator(id: StreamId) Initiator {
    return if ((id & 0x1) == 0) .client else .server;
}

pub fn streamType(id: StreamId) StreamType {
    return if ((id & 0x2) == 0) .bidi else .uni;
}

pub fn streamOrdinal(id: StreamId) u64 {
    return id >> 2;
}

const Segment = struct {
    offset: u64,
    data: []u8,
    read_start: usize = 0,

    fn end(self: Segment) u64 {
        return self.offset + @as(u64, @intCast(self.remaining().len));
    }

    fn remaining(self: Segment) []u8 {
        return self.data[self.read_start..];
    }

    fn deinit(self: Segment, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }
};

const ReceiveBuffer = struct {
    segments: std.ArrayList(Segment) = .empty,

    fn deinit(self: *ReceiveBuffer, allocator: std.mem.Allocator) void {
        for (self.segments.items) |segment| {
            segment.deinit(allocator);
        }
        self.segments.deinit(allocator);
    }

    fn insert(self: *ReceiveBuffer, allocator: std.mem.Allocator, offset: u64, data: []const u8, final_size: ?u64) !u64 {
        if (data.len == 0) return 0;
        const newly_buffered = try self.countNew(offset, data, final_size);
        const end = offset + @as(u64, @intCast(data.len));
        var pending: std.ArrayList(Segment) = .empty;
        defer pending.deinit(allocator);
        errdefer {
            for (pending.items) |segment| {
                segment.deinit(allocator);
            }
        }

        var cursor = offset;
        for (self.segments.items) |segment| {
            if (segment.end() <= cursor) continue;
            if (segment.offset >= end) break;
            if (segment.offset > cursor) {
                const piece_end = @min(segment.offset, end);
                try pending.append(allocator, try makeSegment(allocator, cursor, data[@intCast(cursor - offset)..@intCast(piece_end - offset)]));
            }
            cursor = @max(cursor, segment.end());
            if (cursor >= end) break;
        }
        if (cursor < end) {
            try pending.append(allocator, try makeSegment(allocator, cursor, data[@intCast(cursor - offset)..]));
        }

        try self.segments.ensureUnusedCapacity(allocator, pending.items.len);
        for (pending.items) |segment| {
            self.addSegmentAssumeCapacity(segment);
        }
        return newly_buffered;
    }

    fn countNew(self: ReceiveBuffer, offset: u64, data: []const u8, final_size: ?u64) !u64 {
        if (data.len == 0) return 0;
        const end = std.math.add(u64, offset, @as(u64, @intCast(data.len))) catch return error.FinalSizeError;
        if (final_size) |size| {
            if (end > size) return error.FinalSizeError;
        }

        for (self.segments.items) |segment| {
            const overlap_start = @max(offset, segment.offset);
            const overlap_end = @min(end, segment.end());
            if (overlap_start >= overlap_end) continue;

            const incoming_start: usize = @intCast(overlap_start - offset);
            const incoming_end: usize = @intCast(overlap_end - offset);
            const existing_start: usize = @intCast(overlap_start - segment.offset);
            const existing_end: usize = @intCast(overlap_end - segment.offset);
            if (!std.mem.eql(u8, data[incoming_start..incoming_end], segment.remaining()[existing_start..existing_end])) {
                return error.OverlappingStreamDataMismatch;
            }
        }

        var newly_buffered: u64 = 0;
        var cursor = offset;
        for (self.segments.items) |segment| {
            if (segment.end() <= cursor) continue;
            if (segment.offset >= end) break;
            if (segment.offset > cursor) {
                const piece_end = @min(segment.offset, end);
                newly_buffered += piece_end - cursor;
            }
            cursor = @max(cursor, segment.end());
            if (cursor >= end) break;
        }
        if (cursor < end) newly_buffered += end - cursor;
        return newly_buffered;
    }

    fn makeSegment(allocator: std.mem.Allocator, offset: u64, data: []const u8) !Segment {
        const owned = try allocator.dupe(u8, data);
        return .{ .offset = offset, .data = owned };
    }

    fn addSegmentAssumeCapacity(self: *ReceiveBuffer, segment: Segment) void {
        var insert_at: usize = 0;
        while (insert_at < self.segments.items.len and self.segments.items[insert_at].offset < segment.offset) : (insert_at += 1) {}
        self.segments.insertAssumeCapacity(insert_at, segment);
    }

    fn read(self: *ReceiveBuffer, allocator: std.mem.Allocator, offset: u64, out: []u8) usize {
        if (out.len == 0) return 0;
        var current_offset = offset;
        var written: usize = 0;

        while (written < out.len) {
            var index: usize = 0;
            while (index < self.segments.items.len and self.segments.items[index].offset != current_offset) : (index += 1) {}
            if (index == self.segments.items.len) break;

            const segment = &self.segments.items[index];
            const n = @min(out.len - written, segment.remaining().len);
            @memcpy(out[written..][0..n], segment.remaining()[0..n]);
            segment.offset += @intCast(n);
            segment.read_start += n;
            current_offset += @intCast(n);
            written += n;
            if (segment.read_start == segment.data.len) {
                const removed = self.segments.orderedRemove(index);
                removed.deinit(allocator);
            }
        }
        return written;
    }
};

pub const Stream = struct {
    id: StreamId,
    role: EndpointRole,
    typ: StreamType,
    init: Initiator,
    initial_recv_window: u64,
    max_recv_data: u64,
    max_send_data: u64,
    send_offset: u64 = 0,
    recv_offset: u64 = 0,
    recv_consumed: u64 = 0,
    recv_final_size: ?u64 = null,
    send_final_size: ?u64 = null,
    recv_closed: bool = false,
    send_closed: bool = false,
    reset_received: bool = false,
    reset_sent: bool = false,
    stop_sending_received: bool = false,
    stop_sending_sent: bool = false,
    close_counted: bool = false,
    app_error_code: ?u64 = null,
    recv: ReceiveBuffer = .{},

    fn initStream(role: EndpointRole, id: StreamId, recv_window: u64, send_window: u64) Stream {
        return .{
            .id = id,
            .role = role,
            .typ = streamType(id),
            .init = streamInitiator(id),
            .initial_recv_window = recv_window,
            .max_recv_data = recv_window,
            .max_send_data = send_window,
        };
    }

    fn deinit(self: *Stream, allocator: std.mem.Allocator) void {
        self.recv.deinit(allocator);
    }

    pub fn canSend(self: Stream) bool {
        if (self.typ == .bidi) return true;
        return self.init == self.role.initiator();
    }

    pub fn canReceive(self: Stream) bool {
        if (self.typ == .bidi) return true;
        return self.init != self.role.initiator();
    }

    pub fn state(self: Stream) StreamState {
        // Terminal precedence (#247 soak finding): a stream whose send and
        // receive sides are *both* closed is `.closed` even when one or
        // both sides closed via reset -- e.g. a fully cancelled bidi
        // request (client RESET_STREAM closes recv here, then the server's
        // own RFC 9000 SS3.5 auto-RESET_STREAM in response to STOP_SENDING
        // closes send here). Checking `reset_received`/`reset_sent` first
        // left such a stream permanently reporting a reset state instead of
        // `.closed`, so `StreamManager.maybeClose` never saw `.closed` and
        // never decremented `active_streams`/incremented `closed_streams`
        // for it -- an accounting leak for any stream closed via reset in
        // both directions while the connection stays alive.
        //
        // A unidirectional stream has only one real direction --
        // `canSend()`/`canReceive()` is false for the nonexistent one, and
        // `send_closed`/`recv_closed` for that side never becomes true
        // (nothing ever closes a direction that was never open). Treating a
        // nonexistent direction as still-open left every uni stream
        // permanently short of `.closed` (stuck at `.half_closed_*` or a
        // reset state), so `maybeClose` never counted it and MAX_STREAMS_UNI
        // credit could never replenish (#247 soak finding).
        const send_done = !self.canSend() or self.send_closed;
        const recv_done = !self.canReceive() or self.recv_closed;
        if (send_done and recv_done) return .closed;
        if (self.reset_received) return .reset_received;
        if (self.reset_sent) return .reset_sent;
        if (send_done) return .half_closed_local;
        if (recv_done) return .half_closed_remote;
        return .open;
    }

    fn receive(self: *Stream, allocator: std.mem.Allocator, frame: StreamFrame) !u64 {
        const normalized = (try self.normalizeReceiveFrame(frame)) orelse {
            if (frame.fin) {
                const end = frame.offset + @as(u64, @intCast(frame.data.len));
                // RFC 9000 SS4.5: a FIN must not claim a final size smaller
                // than data this stream has already buffered, even data
                // that arrived out of order past `recv_offset` and hasn't
                // been read yet. `end <= recv_offset` (why we're in this
                // early-return branch at all) does not imply
                // `end <= highestReceivedEnd()` -- unread buffered segments
                // past `recv_offset` are exactly what `highestReceivedEnd`
                // adds on top.
                if (end < self.highestReceivedEnd()) return error.FinalSizeError;
                self.recv_final_size = end;
                self.recv_closed = self.recv_final_size == self.recv_offset;
            }
            return 0;
        };
        _ = try self.previewReceive(normalized);
        const end = normalized.offset + @as(u64, @intCast(normalized.data.len));
        const final_size = if (normalized.fin) end else self.recv_final_size;
        const newly_buffered = try self.recv.insert(allocator, normalized.offset, normalized.data, final_size);
        if (normalized.fin) self.recv_final_size = end;
        if (self.recv_final_size == self.recv_offset and newly_buffered == 0) {
            self.recv_closed = true;
        }
        return newly_buffered;
    }

    fn previewReceive(self: Stream, frame: StreamFrame) !u64 {
        const normalized = (try self.normalizeReceiveFrame(frame)) orelse return 0;
        const end = normalized.offset + @as(u64, @intCast(normalized.data.len));
        if (end > self.max_recv_data) return error.StreamDataBlocked;

        if (normalized.fin) {
            if (self.recv_final_size) |known| {
                if (known != end) return error.FinalSizeError;
            }
            // RFC 9000 SS4.5: reject a final size smaller than data already
            // buffered for this stream -- symmetric with the identical
            // check `StreamManager.receiveResetStream` already applies for
            // RESET_STREAM's `final_size`. Without this, a short STREAM
            // frame carrying FIN could shrink `recv_final_size` below
            // `highestReceivedEnd()`; later draining that already-buffered
            // out-of-order data through `Stream.read` would then push
            // `recv_offset` past `recv_final_size`.
            if (end < self.highestReceivedEnd()) return error.FinalSizeError;
        }
        if (self.recv_final_size) |known| {
            if (end > known) return error.FinalSizeError;
        }

        return self.recv.countNew(normalized.offset, normalized.data, if (normalized.fin) end else self.recv_final_size);
    }

    fn normalizeReceiveFrame(self: Stream, frame: StreamFrame) !?StreamFrame {
        if (!self.canReceive()) return error.SendOnlyStream;
        if (self.reset_received) return error.StreamReset;

        const end = std.math.add(u64, frame.offset, @as(u64, @intCast(frame.data.len))) catch return error.FinalSizeError;
        if (frame.fin) {
            if (self.recv_final_size) |known| {
                if (known != end) return error.FinalSizeError;
            }
            if (end < self.recv_offset) return error.FinalSizeError;
        }
        if (end <= self.recv_offset) return null;
        if (frame.offset >= self.recv_offset) return frame;

        const skip: usize = @intCast(self.recv_offset - frame.offset);
        return .{
            .id = frame.id,
            .offset = self.recv_offset,
            .data = frame.data[skip..],
            .fin = frame.fin,
        };
    }

    fn read(self: *Stream, allocator: std.mem.Allocator, out: []u8) !ReadResult {
        if (!self.canReceive()) return error.SendOnlyStream;
        if (self.reset_received) return error.StreamReset;

        const n = self.recv.read(allocator, self.recv_offset, out);
        self.recv_offset += @intCast(n);
        self.recv_consumed += @intCast(n);
        const fin = if (self.recv_final_size) |size| self.recv_offset == size else false;
        if (fin) self.recv_closed = true;
        return .{ .len = n, .fin = fin };
    }

    fn receivedUnique(self: Stream) u64 {
        var total = self.recv_offset;
        for (self.recv.segments.items) |segment| {
            total += @intCast(segment.remaining().len);
        }
        return total;
    }

    fn highestReceivedEnd(self: Stream) u64 {
        var highest = self.recv_offset;
        for (self.recv.segments.items) |segment| {
            highest = @max(highest, segment.end());
        }
        return highest;
    }

    fn reserveSend(self: *Stream, len: usize, fin: bool) !SendGrant {
        if (!self.canSend()) return error.RecvOnlyStream;
        if (self.stop_sending_received) return error.StopSending;
        if (self.reset_sent) return error.StreamReset;
        if (self.send_closed) return error.StreamClosed;

        const requested_end = std.math.add(u64, self.send_offset, @as(u64, @intCast(len))) catch return error.StreamDataBlocked;
        if (requested_end > self.max_send_data) return error.StreamDataBlocked;

        const grant: SendGrant = .{
            .id = self.id,
            .offset = self.send_offset,
            .len = len,
            .fin = fin,
        };
        self.send_offset = requested_end;
        if (fin) {
            self.send_final_size = requested_end;
            self.send_closed = true;
        }
        return grant;
    }
};

pub const StreamManager = struct {
    allocator: std.mem.Allocator,
    role: EndpointRole,
    local: config.TransportParameters,
    peer: config.TransportParameters,
    streams: std.AutoHashMap(StreamId, *Stream),
    next_local_bidi: u64 = 0,
    next_local_uni: u64 = 0,
    opened_peer_bidi: u64 = 0,
    opened_peer_uni: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    bytes_consumed: u64 = 0,
    max_data_send: u64,
    max_data_recv: u64,
    metrics: Metrics = .{},
    // RFC 9000 §4.6 MAX_STREAMS replenishment (#247 soak finding): without
    // this, a long-lived connection whose peer opens and fully closes many
    // streams (e.g. a persistent HTTP/3 connection serving many requests)
    // would permanently exhaust `local.initial_max_streams_{bidi,uni}` and
    // could never accept stream N+1 even though every earlier stream is
    // long closed. `closed_peer_{bidi,uni}` counts peer-initiated streams
    // that have reached `.closed` (both directions terminal); `maybeClose`
    // grants one more unit of credit per closed stream by raising
    // `local.initial_max_streams_{bidi,uni}` in place to
    // `closed_peer_X + initial_max_streams_X_floor` -- the *floor* fields
    // below hold the original, pre-mutation initial value so growth is
    // additive (total lifetime allowance = original + closed), not
    // compounding. This exactly mirrors `applyMaxStreams`'s identical
    // in-place mutation of `peer.initial_max_streams_{bidi,uni}` for the
    // opposite (outbound) direction -- see that function's own comment.
    //
    // Deliberate scope boundary: `streams` entries are never removed once
    // `close_counted`, so replenishment is capped at
    // `config.max_retained_closed_streams_per_direction` per direction (see
    // that constant's doc comment for the full reasoning) rather than
    // granted without bound -- once `closed_peer_X` reaches the cap,
    // further peer-initiated closes still increment `metrics.closed_streams`
    // but stop raising `local.initial_max_streams_X`, so `streams` for that
    // direction cannot grow past a small, fixed, provable ceiling regardless
    // of connection lifetime.
    closed_peer_bidi: u64 = 0,
    closed_peer_uni: u64 = 0,
    initial_max_streams_bidi_floor: u64 = 0,
    initial_max_streams_uni_floor: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        role: EndpointRole,
        local: config.TransportParameters,
        peer: config.TransportParameters,
    ) StreamManager {
        return .{
            .allocator = allocator,
            .role = role,
            .local = local,
            .peer = peer,
            .streams = std.AutoHashMap(StreamId, *Stream).init(allocator),
            .max_data_send = peer.initial_max_data,
            .max_data_recv = local.initial_max_data,
            .initial_max_streams_bidi_floor = local.initial_max_streams_bidi,
            .initial_max_streams_uni_floor = local.initial_max_streams_uni,
        };
    }

    pub fn deinit(self: *StreamManager) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.streams.deinit();
    }

    pub fn openLocal(self: *StreamManager, typ: StreamType) !StreamId {
        const id = switch (typ) {
            .bidi => blk: {
                if (self.next_local_bidi >= self.peer.initial_max_streams_bidi) {
                    self.metrics.streams_blocked_events += 1;
                    return error.StreamLimitExceeded;
                }
                const id = try makeStreamId(self.role.initiator(), .bidi, self.next_local_bidi);
                self.next_local_bidi += 1;
                break :blk id;
            },
            .uni => blk: {
                if (self.next_local_uni >= self.peer.initial_max_streams_uni) {
                    self.metrics.streams_blocked_events += 1;
                    return error.StreamLimitExceeded;
                }
                const id = try makeStreamId(self.role.initiator(), .uni, self.next_local_uni);
                self.next_local_uni += 1;
                break :blk id;
            },
        };
        _ = try self.createStream(id);
        return id;
    }

    pub fn receiveStreamFrame(self: *StreamManager, frame: StreamFrame) !u64 {
        var stream = try self.getOrCreatePeerStream(frame.id);
        const expected_new = stream.previewReceive(frame) catch |err| {
            if (err == error.StreamDataBlocked) self.metrics.stream_data_blocked_events += 1;
            return err;
        };
        if (self.bytes_received + expected_new > self.max_data_recv) {
            self.metrics.data_blocked_events += 1;
            return error.FlowControlBlocked;
        }
        const newly_buffered = try stream.receive(self.allocator, frame);
        self.bytes_received += newly_buffered;
        return newly_buffered;
    }

    pub fn read(self: *StreamManager, id: StreamId, out: []u8) !ReadResult {
        const stream = self.streams.get(id) orelse return error.UnknownStream;
        var result = try stream.read(self.allocator, out);
        if (result.len == 0 and !result.fin) return result;

        self.bytes_consumed += @intCast(result.len);

        const new_connection_limit = self.bytes_consumed + self.local.initial_max_data;
        if (new_connection_limit > self.max_data_recv) {
            self.max_data_recv = new_connection_limit;
            result.credit.max_data = new_connection_limit;
            self.metrics.max_data_credit_events += 1;
        }

        const new_stream_limit = stream.recv_consumed + stream.initial_recv_window;
        if (new_stream_limit > stream.max_recv_data) {
            stream.max_recv_data = new_stream_limit;
            result.credit.max_stream_data = new_stream_limit;
            self.metrics.max_stream_data_credit_events += 1;
        }

        self.maybeClose(stream);
        return result;
    }

    pub fn reserveSend(self: *StreamManager, id: StreamId, len: usize, fin: bool) !SendGrant {
        const stream = self.streams.get(id) orelse return error.UnknownStream;
        const requested_end = std.math.add(u64, self.bytes_sent, @as(u64, @intCast(len))) catch return error.FlowControlBlocked;
        if (requested_end > self.max_data_send) {
            self.metrics.data_blocked_events += 1;
            return error.FlowControlBlocked;
        }

        const grant = stream.reserveSend(len, fin) catch |err| {
            if (err == error.StreamDataBlocked) self.metrics.stream_data_blocked_events += 1;
            return err;
        };
        self.bytes_sent = requested_end;
        self.maybeClose(stream);
        return grant;
    }

    pub fn applyMaxData(self: *StreamManager, limit: u64) void {
        if (limit > self.max_data_send) self.max_data_send = limit;
    }

    pub fn applyMaxStreamData(self: *StreamManager, id: StreamId, limit: u64) !void {
        const stream = self.streams.get(id) orelse return error.UnknownStream;
        if (limit > stream.max_send_data) stream.max_send_data = limit;
    }

    /// Swap in the peer's authenticated transport parameters once the
    /// handshake completes, for a manager that was brought up early (before
    /// authentication) to admit 0-RTT stream data. Only ever raises existing
    /// send-side limits, mirroring `applyMaxData`/`applyMaxStreamData` — the
    /// placeholder parameters used during 0-RTT are never more permissive
    /// than what the real peer eventually grants, since nothing may be sent
    /// through this manager until this call has already happened.
    pub fn refreshPeerParams(self: *StreamManager, peer_params: config.TransportParameters) void {
        // MAX_STREAMS received during 0-RTT (`applyMaxStreams`, monotonic)
        // already raised `self.peer.initial_max_streams_{bidi,uni}` above
        // whatever the placeholder started at — preserve that credit rather
        // than overwriting it with the peer's un-raised initial value below.
        const max_bidi = @max(self.peer.initial_max_streams_bidi, peer_params.initial_max_streams_bidi);
        const max_uni = @max(self.peer.initial_max_streams_uni, peer_params.initial_max_streams_uni);

        self.peer = peer_params;
        self.peer.initial_max_streams_bidi = max_bidi;
        self.peer.initial_max_streams_uni = max_uni;

        self.applyMaxData(peer_params.initial_max_data);
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const id = entry.key_ptr.*;
            const stream = entry.value_ptr.*;
            const limit = streamDataLimit(peer_params, peerRole(self.role), id);
            if (limit > stream.max_send_data) stream.max_send_data = limit;
        }
    }

    pub fn applyMaxStreams(self: *StreamManager, typ: StreamType, limit: u64) void {
        switch (typ) {
            .bidi => self.peer.initial_max_streams_bidi = @max(self.peer.initial_max_streams_bidi, limit),
            .uni => self.peer.initial_max_streams_uni = @max(self.peer.initial_max_streams_uni, limit),
        }
    }

    pub fn receiveResetStream(self: *StreamManager, frame: ResetStreamFrame) !void {
        const stream = try self.getOrCreatePeerStream(frame.id);
        if (!stream.canReceive()) return error.SendOnlyStream;
        if (stream.reset_received) {
            if (stream.recv_final_size != frame.final_size) return error.FinalSizeError;
            return;
        }
        if (stream.recv_final_size) |known| {
            if (known != frame.final_size) return error.FinalSizeError;
        }
        if (frame.final_size < stream.highestReceivedEnd()) return error.FinalSizeError;

        const already_received = stream.receivedUnique();
        const missing = frame.final_size - already_received;
        if (self.bytes_received + missing > self.max_data_recv) {
            self.metrics.data_blocked_events += 1;
            return error.FlowControlBlocked;
        }
        self.bytes_received += missing;

        stream.recv_final_size = frame.final_size;
        stream.recv_closed = true;
        stream.reset_received = true;
        stream.app_error_code = frame.app_error_code;
        self.metrics.reset_streams += 1;
        self.maybeClose(stream);
    }

    /// `null` means "already in Reset Sent, nothing new to do" -- both
    /// explicit local resets (`Connection.resetStream`) and the RFC 9000
    /// §3.5 automatic reset a received STOP_SENDING triggers share this one
    /// idempotent transition. QUIC retransmits a STOP_SENDING whose ACK was
    /// lost in a new packet, so a caller seeing the same logical reset
    /// request twice is not hypothetical; §3.5 only requires the automatic
    /// RESET_STREAM while the stream is Ready/Send, not a second one once
    /// it is already Reset Sent. Callers must treat `null` as success/no-op
    /// -- never queue another frame, re-emit a local reset transition, or
    /// re-increment `reset_streams` for it.
    pub fn sendResetStream(self: *StreamManager, id: StreamId, app_error_code: u64) !?ResetStreamFrame {
        const stream = self.streams.get(id) orelse return error.UnknownStream;
        if (!stream.canSend()) return error.RecvOnlyStream;
        if (stream.reset_sent) return null;
        stream.reset_sent = true;
        stream.send_closed = true;
        stream.app_error_code = app_error_code;
        self.metrics.reset_streams += 1;
        // Captured before `maybeClose`: `stream` is never freed by anything
        // in this file today, but reading it only via values captured
        // beforehand costs nothing and stays correct if that ever changes.
        const final_size = stream.send_offset;
        self.maybeClose(stream);
        return .{ .id = id, .app_error_code = app_error_code, .final_size = final_size };
    }

    pub fn receiveStopSending(self: *StreamManager, frame: StopSendingFrame) !void {
        const stream = self.streams.get(frame.id) orelse return error.UnknownStream;
        if (!stream.canSend()) return error.RecvOnlyStream;
        stream.stop_sending_received = true;
        stream.app_error_code = frame.app_error_code;
        self.metrics.stop_sending_events += 1;
    }

    pub fn sendStopSending(self: *StreamManager, id: StreamId, app_error_code: u64) !StopSendingFrame {
        const stream = self.streams.get(id) orelse return error.UnknownStream;
        if (!stream.canReceive()) return error.SendOnlyStream;
        stream.stop_sending_sent = true;
        stream.app_error_code = app_error_code;
        self.metrics.stop_sending_events += 1;
        return .{ .id = id, .app_error_code = app_error_code };
    }

    pub fn get(self: *StreamManager, id: StreamId) ?*Stream {
        return self.streams.get(id);
    }

    fn getOrCreatePeerStream(self: *StreamManager, id: StreamId) !*Stream {
        if (self.streams.get(id)) |stream| return stream;
        if (streamInitiator(id) == self.role.initiator()) return error.UnknownStream;
        try self.ensurePeerStreamAllowed(id);
        return self.createStream(id);
    }

    fn ensurePeerStreamAllowed(self: *StreamManager, id: StreamId) !void {
        const ordinal_value = streamOrdinal(id);
        switch (streamType(id)) {
            .bidi => {
                if (ordinal_value >= self.local.initial_max_streams_bidi) {
                    self.metrics.streams_blocked_events += 1;
                    return error.StreamLimitExceeded;
                }
                self.opened_peer_bidi = @max(self.opened_peer_bidi, ordinal_value + 1);
            },
            .uni => {
                if (ordinal_value >= self.local.initial_max_streams_uni) {
                    self.metrics.streams_blocked_events += 1;
                    return error.StreamLimitExceeded;
                }
                self.opened_peer_uni = @max(self.opened_peer_uni, ordinal_value + 1);
            },
        }
    }

    fn createStream(self: *StreamManager, id: StreamId) !*Stream {
        if (self.streams.get(id)) |stream| return stream;
        const stream = try self.allocator.create(Stream);
        errdefer self.allocator.destroy(stream);
        stream.* = Stream.initStream(self.role, id, self.initialRecvWindow(id), self.initialSendWindow(id));
        try self.streams.put(id, stream);
        self.metrics.opened_streams += 1;
        self.metrics.active_streams += 1;
        return stream;
    }

    fn maybeClose(self: *StreamManager, stream: *Stream) void {
        if (stream.state() == .closed and !stream.close_counted) {
            stream.close_counted = true;
            if (self.metrics.active_streams > 0) self.metrics.active_streams -= 1;
            self.metrics.closed_streams += 1;
            // RFC 9000 §4.6 MAX_STREAMS replenishment (#247 soak finding):
            // grant one more unit of credit per closed peer-initiated
            // stream by raising `local.initial_max_streams_{bidi,uni}` in
            // place -- mirroring `applyMaxStreams`'s identical mutation of
            // `peer.initial_max_streams_{bidi,uni}` for the opposite
            // (outbound) direction, see that function's comment. The
            // `_floor` fields hold the original, pre-mutation initial
            // value so growth is additive (total lifetime allowance =
            // original + closed), not compounding. `Stream` entries
            // themselves are never removed from `streams`, so growth stops
            // once `closed_peer_{bidi,uni}` reaches
            // `config.max_retained_closed_streams_per_direction` -- see that
            // constant's doc comment and the note on the closed-stream-
            // retention tradeoff at the top of this struct's `_floor`
            // fields' declaration.
            if (streamInitiator(stream.id) != self.role.initiator()) {
                switch (streamType(stream.id)) {
                    .bidi => {
                        if (self.closed_peer_bidi < config.max_retained_closed_streams_per_direction) {
                            self.closed_peer_bidi +|= 1;
                            self.local.initial_max_streams_bidi = @min(
                                config.max_initial_streams_transport_parameter,
                                self.closed_peer_bidi +| self.initial_max_streams_bidi_floor,
                            );
                        }
                    },
                    .uni => {
                        if (self.closed_peer_uni < config.max_retained_closed_streams_per_direction) {
                            self.closed_peer_uni +|= 1;
                            self.local.initial_max_streams_uni = @min(
                                config.max_initial_streams_transport_parameter,
                                self.closed_peer_uni +| self.initial_max_streams_uni_floor,
                            );
                        }
                    },
                }
            }
        }
    }

    fn initialRecvWindow(self: StreamManager, id: StreamId) u64 {
        return streamDataLimit(self.local, self.role, id);
    }

    fn initialSendWindow(self: StreamManager, id: StreamId) u64 {
        return streamDataLimit(self.peer, peerRole(self.role), id);
    }
};

fn peerRole(role: EndpointRole) EndpointRole {
    return switch (role) {
        .client => .server,
        .server => .client,
    };
}

fn streamDataLimit(params: config.TransportParameters, owner_role: EndpointRole, id: StreamId) u64 {
    return switch (streamType(id)) {
        .uni => params.initial_max_stream_data_uni,
        .bidi => if (streamInitiator(id) == owner_role.initiator())
            params.initial_max_stream_data_bidi_local
        else
            params.initial_max_stream_data_bidi_remote,
    };
}

fn testParams() config.TransportParameters {
    return .{
        .max_idle_timeout_ms = 30_000,
        .active_connection_id_limit = 4,
        .max_udp_payload_size = 1200,
        .initial_max_data = 32,
        .initial_max_stream_data_bidi_local = 16,
        .initial_max_stream_data_bidi_remote = 16,
        .initial_max_stream_data_uni = 12,
        .initial_max_streams_bidi = 2,
        .initial_max_streams_uni = 1,
        .disable_active_migration = true,
    };
}

test "stream id bits encode initiator type and ordinal" {
    const client_bidi = try makeStreamId(.client, .bidi, 7);
    try std.testing.expectEqual(@as(StreamId, 28), client_bidi);
    try std.testing.expectEqual(Initiator.client, streamInitiator(client_bidi));
    try std.testing.expectEqual(StreamType.bidi, streamType(client_bidi));
    try std.testing.expectEqual(@as(u64, 7), streamOrdinal(client_bidi));

    const server_uni = try makeStreamId(.server, .uni, 3);
    try std.testing.expectEqual(@as(StreamId, 15), server_uni);
    try std.testing.expectEqual(Initiator.server, streamInitiator(server_uni));
    try std.testing.expectEqual(StreamType.uni, streamType(server_uni));
    try std.testing.expectEqual(@as(u64, 3), streamOrdinal(server_uni));
}

test "local stream limits produce blocked accounting" {
    var params = testParams();
    params.initial_max_streams_bidi = 1;
    var manager = StreamManager.init(std.testing.allocator, .client, testParams(), params);
    defer manager.deinit();

    try std.testing.expectEqual(@as(StreamId, 0), try manager.openLocal(.bidi));
    try std.testing.expectError(error.StreamLimitExceeded, manager.openLocal(.bidi));
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.streams_blocked_events);
}

test "refreshPeerParams (#523) preserves MAX_STREAMS credit granted during 0-RTT instead of rolling it back" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    // Simulate an accepted 0-RTT MAX_STREAMS frame raising bidi credit well
    // above `testParams()`'s initial value (2).
    manager.applyMaxStreams(.bidi, 500);
    try std.testing.expectEqual(@as(u64, 500), manager.peer.initial_max_streams_bidi);

    // The handshake completes; the authenticated peer parameters only ever
    // granted `testParams()`'s smaller initial value. Refreshing must not
    // roll the already-raised credit back down to it.
    manager.refreshPeerParams(testParams());
    try std.testing.expectEqual(@as(u64, 500), manager.peer.initial_max_streams_bidi);

    // And that credit is genuinely usable: opening more local bidi streams
    // than `testParams()`'s own limit (2) would ever allow succeeds.
    var opened: usize = 0;
    while (opened < 5) : (opened += 1) {
        _ = try manager.openLocal(.bidi);
    }
}

test "send path enforces stream and connection flow control" {
    var local = testParams();
    var peer = testParams();
    local.initial_max_data = 128;
    peer.initial_max_data = 20;
    peer.initial_max_stream_data_bidi_remote = 8;

    var manager = StreamManager.init(std.testing.allocator, .client, local, peer);
    defer manager.deinit();

    const id = try manager.openLocal(.bidi);
    const first = try manager.reserveSend(id, 8, false);
    try std.testing.expectEqual(@as(u64, 0), first.offset);
    try std.testing.expectEqual(@as(usize, 8), first.len);
    try std.testing.expectError(error.StreamDataBlocked, manager.reserveSend(id, 1, false));
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.stream_data_blocked_events);

    try manager.applyMaxStreamData(id, 32);
    _ = try manager.reserveSend(id, 12, false);
    try std.testing.expectError(error.FlowControlBlocked, manager.reserveSend(id, 1, false));
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.data_blocked_events);

    manager.applyMaxData(64);
    const final = try manager.reserveSend(id, 1, true);
    try std.testing.expect(final.fin);
}

test "receive path reassembles out of order stream data" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    try std.testing.expectEqual(@as(u64, 5), try manager.receiveStreamFrame(.{ .id = id, .offset = 5, .data = "world", .fin = true }));
    try std.testing.expectEqual(@as(u64, 5), try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "hello" }));

    var out: [16]u8 = undefined;
    const read = try manager.read(id, &out);
    try std.testing.expectEqual(@as(usize, 10), read.len);
    try std.testing.expect(read.fin);
    try std.testing.expectEqualStrings("helloworld", out[0..read.len]);
}

test "overlapping duplicate data must match" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "abcdef" });
    try std.testing.expectEqual(@as(u64, 0), try manager.receiveStreamFrame(.{ .id = id, .offset = 2, .data = "cde" }));
    try std.testing.expectError(error.OverlappingStreamDataMismatch, manager.receiveStreamFrame(.{ .id = id, .offset = 2, .data = "cXe" }));
}

test "retransmitted bytes below consumed offset are ignored" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "hello" });

    var out: [8]u8 = undefined;
    const read = try manager.read(id, out[0..5]);
    try std.testing.expectEqual(@as(usize, 5), read.len);
    try std.testing.expectEqual(@as(u64, 5), manager.bytes_received);

    try std.testing.expectEqual(@as(u64, 0), try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "hello" }));
    try std.testing.expectEqual(@as(u64, 5), manager.bytes_received);
    try std.testing.expectEqual(@as(usize, 0), manager.get(id).?.recv.segments.items.len);
}

test "partially consumed retransmits are trimmed before accounting" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "hello" });

    var out: [8]u8 = undefined;
    _ = try manager.read(id, out[0..3]);
    try std.testing.expectEqual(@as(u64, 5), manager.bytes_received);

    try std.testing.expectEqual(@as(u64, 2), try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "hello!!" }));
    try std.testing.expectEqual(@as(u64, 7), manager.bytes_received);

    const read_rest = try manager.read(id, &out);
    try std.testing.expectEqualStrings("lo!!", out[0..read_rest.len]);
}

test "final size is enforced" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "abc", .fin = true });
    try std.testing.expectError(error.FinalSizeError, manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "abcd", .fin = true }));
    try std.testing.expectError(error.FinalSizeError, manager.receiveStreamFrame(.{ .id = id, .offset = 3, .data = "d" }));
}

test "known final size allows later data up to the boundary" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 5, .data = "", .fin = true });
    try std.testing.expectEqual(@as(u64, 5), try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "hello" }));
    try std.testing.expectError(error.FinalSizeError, manager.receiveStreamFrame(.{ .id = id, .offset = 5, .data = "!" }));

    var out: [8]u8 = undefined;
    const read = try manager.read(id, &out);
    try std.testing.expectEqualStrings("hello", out[0..read.len]);
    try std.testing.expect(read.fin);
}

test "duplicate data after FIN close is a no-op" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "abc", .fin = true });

    var out: [8]u8 = undefined;
    const read = try manager.read(id, &out);
    try std.testing.expectEqualStrings("abc", out[0..read.len]);
    try std.testing.expect(read.fin);
    try std.testing.expectEqual(@as(u64, 3), manager.bytes_received);

    try std.testing.expectEqual(@as(u64, 0), try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "abc" }));
    try std.testing.expectEqual(@as(u64, 3), manager.bytes_received);
}

test "application reads return connection and stream flow credit" {
    var local = testParams();
    local.initial_max_data = 10;
    local.initial_max_stream_data_bidi_remote = 10;

    var manager = StreamManager.init(std.testing.allocator, .server, local, testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "12345" });

    var out: [8]u8 = undefined;
    const read = try manager.read(id, &out);
    try std.testing.expectEqual(@as(usize, 5), read.len);
    try std.testing.expectEqual(@as(?u64, 15), read.credit.max_data);
    try std.testing.expectEqual(@as(?u64, 15), read.credit.max_stream_data);
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.max_data_credit_events);
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.max_stream_data_credit_events);
}

test "slow stream buffering does not stall unrelated streams" {
    var local = testParams();
    local.initial_max_data = 24;
    local.initial_max_streams_bidi = 2;
    var manager = StreamManager.init(std.testing.allocator, .server, local, testParams());
    defer manager.deinit();

    const slow = try makeStreamId(.client, .bidi, 0);
    const fast = try makeStreamId(.client, .bidi, 1);
    _ = try manager.receiveStreamFrame(.{ .id = slow, .offset = 0, .data = "blocked-slow" });
    _ = try manager.receiveStreamFrame(.{ .id = fast, .offset = 0, .data = "ok", .fin = true });

    var out: [8]u8 = undefined;
    const read = try manager.read(fast, &out);
    try std.testing.expectEqualStrings("ok", out[0..read.len]);
    try std.testing.expect(read.fin);
}

test "reset stream and stop sending update state and propagation" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "abc" });
    try manager.receiveResetStream(.{ .id = id, .app_error_code = 42, .final_size = 3 });
    try std.testing.expectEqual(StreamState.reset_received, manager.get(id).?.state());

    var out: [8]u8 = undefined;
    try std.testing.expectError(error.StreamReset, manager.read(id, &out));

    const stop = try manager.sendStopSending(id, 99);
    try std.testing.expectEqual(@as(u64, 99), stop.app_error_code);
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.stop_sending_events);
}

test "stream reset in both directions while connection stays alive counts closed exactly once" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "abc" });
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.active_streams);
    try std.testing.expectEqual(@as(u64, 0), manager.metrics.closed_streams);

    // Client abandons its request (recv-side close here): still only
    // half-duplex closed, so this must not count as terminally closed yet.
    try manager.receiveResetStream(.{ .id = id, .app_error_code = 42, .final_size = 3 });
    try std.testing.expectEqual(StreamState.reset_received, manager.get(id).?.state());
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.active_streams);
    try std.testing.expectEqual(@as(u64, 0), manager.metrics.closed_streams);

    // Server's own RFC 9000 SS3.5 auto-RESET_STREAM in response to a
    // STOP_SENDING it received (mirrors `Connection`'s `.stop_sending`
    // handler, which calls this same `sendResetStream` after
    // `receiveStopSending`) closes the send side too -- both directions
    // are now closed, so this must count as terminally closed exactly once
    // even though closure happened entirely via reset, not FIN.
    _ = try manager.sendResetStream(id, 42);
    try std.testing.expectEqual(StreamState.closed, manager.get(id).?.state());
    try std.testing.expectEqual(@as(u64, 0), manager.metrics.active_streams);
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.closed_streams);

    // Idempotent: a duplicate/late-retransmitted RESET_STREAM for the same
    // final size must not double-count the close.
    try manager.receiveResetStream(.{ .id = id, .app_error_code = 42, .final_size = 3 });
    try std.testing.expectEqual(@as(u64, 0), manager.metrics.active_streams);
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.closed_streams);
}

test "sendResetStream is idempotent once already Reset Sent" {
    // QUIC retransmits a STOP_SENDING whose ACK was lost in a new packet,
    // so `Connection`'s RFC 9000 SS3.5 automatic-reset handler can call
    // `sendResetStream` for the same stream more than once. The first call
    // must behave exactly as before; every call after that must be a
    // pure no-op (`null`, no new frame, no metric/state mutation) rather
    // than re-queuing another RESET_STREAM for a stream already in Reset
    // Sent.
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "abc" });

    const first = try manager.sendResetStream(id, 7);
    try std.testing.expect(first != null);
    try std.testing.expectEqual(@as(u64, 7), first.?.app_error_code);
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.reset_streams);
    try std.testing.expectEqual(StreamState.reset_sent, manager.get(id).?.state());

    // A retransmitted STOP_SENDING driving the same automatic reset again:
    // no second frame, no second metric increment.
    const second = try manager.sendResetStream(id, 7);
    try std.testing.expect(second == null);
    try std.testing.expectEqual(@as(u64, 1), manager.metrics.reset_streams);
    try std.testing.expectEqual(StreamState.reset_sent, manager.get(id).?.state());
}

test "MAX_STREAMS replenishment credit stops growing once the retained-stream cap is reached" {
    // #247 soak finding (review round 7): closed `Stream` objects are never
    // removed from `streams`, so replenishing credit without any bound
    // would turn the old functional lifetime cap into unbounded
    // per-connection memory growth. `closed_peer_bidi` -- and therefore
    // `local.initial_max_streams_bidi` -- stops advancing once it reaches
    // `config.max_retained_closed_streams_per_direction`, even though
    // `metrics.closed_streams` keeps counting every close. Seeded one below
    // the cap directly (the cap is large by design) rather than driving
    // real cycles up to it -- this only needs to prove the boundary.
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();
    manager.closed_peer_bidi = config.max_retained_closed_streams_per_direction - 1;
    const floor = manager.initial_max_streams_bidi_floor;

    const at_cap_id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = at_cap_id, .offset = 0, .data = "x" });
    try manager.receiveResetStream(.{ .id = at_cap_id, .app_error_code = 1, .final_size = 1 });
    _ = try manager.sendResetStream(at_cap_id, 1);
    try std.testing.expectEqual(StreamState.closed, manager.get(at_cap_id).?.state());
    try std.testing.expectEqual(config.max_retained_closed_streams_per_direction, manager.closed_peer_bidi);
    try std.testing.expectEqual(
        config.max_retained_closed_streams_per_direction + floor,
        manager.local.initial_max_streams_bidi,
    );

    const over_cap_id = try makeStreamId(.client, .bidi, 1);
    _ = try manager.receiveStreamFrame(.{ .id = over_cap_id, .offset = 0, .data = "x" });
    try manager.receiveResetStream(.{ .id = over_cap_id, .app_error_code = 1, .final_size = 1 });
    _ = try manager.sendResetStream(over_cap_id, 1);
    try std.testing.expectEqual(StreamState.closed, manager.get(over_cap_id).?.state());

    // Capped: this second close still counted in metrics, but did not push
    // `closed_peer_bidi` (or the resulting credit) past the cap.
    try std.testing.expectEqual(config.max_retained_closed_streams_per_direction, manager.closed_peer_bidi);
    try std.testing.expectEqual(
        config.max_retained_closed_streams_per_direction + floor,
        manager.local.initial_max_streams_bidi,
    );
    try std.testing.expectEqual(@as(u64, 2), manager.metrics.closed_streams);
}

test "reset final size consumes remaining connection credit" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "abc" });
    try std.testing.expectEqual(@as(u64, 3), manager.bytes_received);

    try manager.receiveResetStream(.{ .id = id, .app_error_code = 1, .final_size = 20 });
    try std.testing.expectEqual(@as(u64, 20), manager.bytes_received);
    try std.testing.expectEqual(StreamState.reset_received, manager.get(id).?.state());
}

test "reset final size beyond connection window is blocked" {
    var local = testParams();
    local.initial_max_data = 8;
    var manager = StreamManager.init(std.testing.allocator, .server, local, testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "abc" });
    try std.testing.expectError(error.FlowControlBlocked, manager.receiveResetStream(.{ .id = id, .app_error_code = 1, .final_size = 9 }));
    try std.testing.expectEqual(@as(u64, 3), manager.bytes_received);
}

test "reset final size below buffered out of order data is rejected" {
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 10, .data = "abc" });
    try std.testing.expectError(error.FinalSizeError, manager.receiveResetStream(.{ .id = id, .app_error_code = 1, .final_size = 12 }));
    try std.testing.expectEqual(@as(u64, 3), manager.bytes_received);
}

test "FIN final size below buffered out of order data is rejected (#675 campaign finding)" {
    // Sibling of "reset final size below buffered out of order data is
    // rejected" above, but for a FIN carried on a STREAM frame instead of
    // RESET_STREAM: `previewReceive` checked a new final size against an
    // existing `recv_final_size` and against `recv_offset`, but never
    // against data already buffered out of order past `recv_offset` --
    // exactly what `highestReceivedEnd()` (already used by
    // `receiveResetStream`) tracks. A short FIN could shrink
    // `recv_final_size` below data the stream had already buffered;
    // draining that data through `Stream.read` would then push
    // `recv_offset` past `recv_final_size`, which the fuzz model's
    // `expectStreamManagerInvariants` (recv_offset <= recv_final_size)
    // caught (#675 campaign finding, quic__family, `.zig-cache/f/crash`
    // sha256 a0c1636b...).
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 10, .data = "abc" });
    try std.testing.expectError(error.FinalSizeError, manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "hello", .fin = true }));
    try std.testing.expectEqual(@as(u64, 3), manager.bytes_received);
}

test "FIN at recv_offset below buffered out of order data is rejected" {
    // Same defect, the OTHER vulnerable path: `Stream.receive`'s early
    // return (a FIN whose claimed end lands at-or-before `recv_offset`,
    // e.g. a stale/duplicate FIN for already-consumed data) set
    // `recv_final_size` without checking `highestReceivedEnd()` either.
    var manager = StreamManager.init(std.testing.allocator, .server, testParams(), testParams());
    defer manager.deinit();

    const id = try makeStreamId(.client, .bidi, 0);
    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = "ab" });
    var out: [8]u8 = undefined;
    _ = try manager.read(id, &out); // recv_offset now 2

    _ = try manager.receiveStreamFrame(.{ .id = id, .offset = 10, .data = "xyz" }); // highestReceivedEnd = 13

    // end == recv_offset (2) so this hits Stream.receive's early-return
    // branch rather than previewReceive, but 2 < highestReceivedEnd (13).
    try std.testing.expectError(error.FinalSizeError, manager.receiveStreamFrame(.{ .id = id, .offset = 2, .data = "", .fin = true }));
    try std.testing.expectEqual(@as(u64, 5), manager.bytes_received);
}

test "STOP_SENDING received blocks future sends" {
    var manager = StreamManager.init(std.testing.allocator, .client, testParams(), testParams());
    defer manager.deinit();

    const id = try manager.openLocal(.bidi);
    try manager.receiveStopSending(.{ .id = id, .app_error_code = 7 });
    try std.testing.expectError(error.StopSending, manager.reserveSend(id, 1, false));
}

test "fuzz: stream manager command sequences preserve flow-control invariants" {
    try std.testing.fuzz({}, fuzzStreamManagerCommands, .{ .corpus = &.{
        "",
        "\x00\x00\x01\x02\x03\x00\x00\x03abc\x07\x00\x08",
        "\x04\x00\x08abcdefgh\x04\x00\x09abcdefghi\x08\x00\x08",
        "\x03\x00\x00\x03abc\x03\x02\x03cde\x03\x02\x03cXe",
        "\x09\x00\x03abc\x0a\x00\x03\x0a\x00\x04\x0b\x00\x0c",
        "\x0c\x00\x01\x0d\x00\x20\x0e\x00\x02\x0f\x00\x02",
    } });
}

fn fuzzStreamManagerCommands(_: void, smith: *std.testing.Smith) !void {
    var input: [256]u8 = undefined;
    const len = smith.slice(&input);
    try runStreamManagerCommands(input[0..len], .client);
    try runStreamManagerCommands(input[0..len], .server);
}

const StreamManagerSnapshot = struct {
    bytes_sent: u64,
    bytes_received: u64,
    bytes_consumed: u64,
    max_data_send: u64,
    max_data_recv: u64,
    local_bidi_limit: u64,
    local_uni_limit: u64,
    peer_bidi_limit: u64,
    peer_uni_limit: u64,
    active_streams: u64,
    opened_streams: u64,
    closed_streams: u64,
};

fn snapshotStreamManager(manager: StreamManager) StreamManagerSnapshot {
    return .{
        .bytes_sent = manager.bytes_sent,
        .bytes_received = manager.bytes_received,
        .bytes_consumed = manager.bytes_consumed,
        .max_data_send = manager.max_data_send,
        .max_data_recv = manager.max_data_recv,
        .local_bidi_limit = manager.local.initial_max_streams_bidi,
        .local_uni_limit = manager.local.initial_max_streams_uni,
        .peer_bidi_limit = manager.peer.initial_max_streams_bidi,
        .peer_uni_limit = manager.peer.initial_max_streams_uni,
        .active_streams = manager.metrics.active_streams,
        .opened_streams = manager.metrics.opened_streams,
        .closed_streams = manager.metrics.closed_streams,
    };
}

fn runStreamManagerCommands(input: []const u8, role: EndpointRole) !void {
    var local = testParams();
    var peer = testParams();
    local.initial_max_data = 24;
    local.initial_max_stream_data_bidi_remote = 8;
    local.initial_max_stream_data_uni = 8;
    local.initial_max_streams_bidi = 2;
    local.initial_max_streams_uni = 1;
    peer.initial_max_data = 24;
    peer.initial_max_stream_data_bidi_remote = 8;
    peer.initial_max_stream_data_bidi_local = 8;
    peer.initial_max_stream_data_uni = 8;
    peer.initial_max_streams_bidi = 2;
    peer.initial_max_streams_uni = 1;

    var manager = StreamManager.init(std.testing.allocator, role, local, peer);
    defer manager.deinit();

    var remembered_local_bidi: ?StreamId = null;
    var remembered_peer_bidi: ?StreamId = null;
    var pos: usize = 0;
    while (pos < input.len) {
        const op = input[pos];
        pos += 1;
        const before = snapshotStreamManager(manager);
        const ordinal = if (pos < input.len) @as(u64, input[pos] & 0x03) else 0;
        pos +|= @as(usize, @intFromBool(pos < input.len));
        const peer_init = peerRole(role).initiator();
        const local_init = role.initiator();
        const peer_bidi = makeStreamId(peer_init, .bidi, ordinal) catch 0;
        const peer_uni = makeStreamId(peer_init, .uni, ordinal) catch 0;
        const local_bidi = remembered_local_bidi orelse makeStreamId(local_init, .bidi, 0) catch 0;

        switch (op % 16) {
            0 => if (manager.openLocal(.bidi)) |id| {
                remembered_local_bidi = id;
            } else |_| {},
            1 => if (manager.openLocal(.uni)) |_| {} else |_| {},
            2 => {
                const id = if ((op & 0x80) != 0) peer_uni else peer_bidi;
                const len = boundedPayloadLen(input, pos);
                const data = input[pos..][0..len];
                pos += len;
                _ = manager.receiveStreamFrame(.{ .id = id, .offset = 0, .data = data, .fin = (op & 0x20) != 0 }) catch {};
                if (manager.get(peer_bidi) != null) remembered_peer_bidi = peer_bidi;
            },
            3 => {
                const id = remembered_peer_bidi orelse peer_bidi;
                const offset = if (pos < input.len) @as(u64, input[pos] & 0x0f) else 0;
                pos +|= @as(usize, @intFromBool(pos < input.len));
                const len = boundedPayloadLen(input, pos);
                const data = input[pos..][0..len];
                pos += len;
                _ = manager.receiveStreamFrame(.{ .id = id, .offset = offset, .data = data, .fin = (op & 0x40) != 0 }) catch {};
                if (manager.get(id) != null) remembered_peer_bidi = id;
            },
            4 => {
                const id = remembered_local_bidi orelse manager.openLocal(.bidi) catch local_bidi;
                remembered_local_bidi = id;
                const len = if (pos < input.len) @as(usize, input[pos] & 0x0f) else 0;
                pos +|= @as(usize, @intFromBool(pos < input.len));
                _ = manager.reserveSend(id, len, (op & 0x20) != 0) catch {};
            },
            5 => {
                const id = remembered_peer_bidi orelse peer_bidi;
                var out: [16]u8 = undefined;
                _ = manager.read(id, &out) catch {};
            },
            6 => manager.applyMaxData(before.max_data_send),
            7 => manager.applyMaxData(before.max_data_send +| 8),
            8 => if (remembered_local_bidi) |id| manager.applyMaxStreamData(id, before.max_data_send) catch {} else {},
            9 => if (remembered_local_bidi) |id| manager.applyMaxStreamData(id, before.max_data_send +| 8) catch {} else {},
            10 => {
                const id = remembered_peer_bidi orelse peer_bidi;
                const final_size = if (pos < input.len) @as(u64, input[pos] & 0x1f) else 0;
                pos +|= @as(usize, @intFromBool(pos < input.len));
                _ = manager.receiveResetStream(.{ .id = id, .app_error_code = op, .final_size = final_size }) catch {};
                if (manager.get(id) != null) remembered_peer_bidi = id;
            },
            11 => {
                if (remembered_local_bidi) |id| _ = manager.sendResetStream(id, op) catch {};
            },
            12 => {
                if (remembered_local_bidi) |id| manager.receiveStopSending(.{ .id = id, .app_error_code = op }) catch {};
            },
            13 => {
                if (remembered_peer_bidi) |id| _ = manager.sendStopSending(id, op) catch {};
            },
            14 => manager.applyMaxStreams(.bidi, before.peer_bidi_limit +| 1),
            else => manager.applyMaxStreams(.uni, before.peer_uni_limit +| 1),
        }

        try expectStreamManagerInvariants(&manager, before);
    }
}

fn boundedPayloadLen(input: []const u8, pos: usize) usize {
    if (pos >= input.len) return 0;
    return @min(@as(usize, input[pos] & 0x07), input.len - pos);
}

fn expectStreamManagerInvariants(manager: *StreamManager, before: StreamManagerSnapshot) !void {
    try std.testing.expect(manager.bytes_sent >= before.bytes_sent);
    try std.testing.expect(manager.bytes_received >= before.bytes_received);
    try std.testing.expect(manager.bytes_consumed >= before.bytes_consumed);
    try std.testing.expect(manager.bytes_consumed <= manager.bytes_received);
    try std.testing.expect(manager.bytes_received <= manager.max_data_recv);
    try std.testing.expect(manager.max_data_send >= before.max_data_send);
    try std.testing.expect(manager.peer.initial_max_streams_bidi >= before.peer_bidi_limit);
    try std.testing.expect(manager.peer.initial_max_streams_uni >= before.peer_uni_limit);
    try std.testing.expect(manager.metrics.opened_streams >= manager.metrics.closed_streams);
    try std.testing.expect(manager.metrics.active_streams <= manager.metrics.opened_streams);

    var per_stream_unique: u64 = 0;
    var it = manager.streams.iterator();
    while (it.next()) |entry| {
        const s = entry.value_ptr.*;
        try std.testing.expect(s.recv_offset <= s.receivedUnique());
        try std.testing.expect(s.receivedUnique() <= s.max_recv_data);
        try std.testing.expect(s.send_offset <= s.max_send_data);
        if (s.recv_final_size) |final_size| {
            try std.testing.expect(s.recv_offset <= final_size);
        }
        per_stream_unique += s.receivedUnique();
    }
    try std.testing.expect(per_stream_unique >= manager.bytes_consumed);
    try std.testing.expect(per_stream_unique <= manager.bytes_received);
}

test {
    std.testing.refAllDecls(@This());
}
