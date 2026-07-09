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
        if (self.reset_received) return .reset_received;
        if (self.reset_sent) return .reset_sent;
        if (self.send_closed and self.recv_closed) return .closed;
        if (self.send_closed) return .half_closed_local;
        if (self.recv_closed) return .half_closed_remote;
        return .open;
    }

    fn receive(self: *Stream, allocator: std.mem.Allocator, frame: StreamFrame) !u64 {
        const normalized = (try self.normalizeReceiveFrame(frame)) orelse {
            if (frame.fin) {
                self.recv_final_size = frame.offset + @as(u64, @intCast(frame.data.len));
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

    pub fn sendResetStream(self: *StreamManager, id: StreamId, app_error_code: u64) !ResetStreamFrame {
        const stream = self.streams.get(id) orelse return error.UnknownStream;
        if (!stream.canSend()) return error.RecvOnlyStream;
        stream.reset_sent = true;
        stream.send_closed = true;
        stream.app_error_code = app_error_code;
        self.metrics.reset_streams += 1;
        self.maybeClose(stream);
        return .{ .id = id, .app_error_code = app_error_code, .final_size = stream.send_offset };
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

test "STOP_SENDING received blocks future sends" {
    var manager = StreamManager.init(std.testing.allocator, .client, testParams(), testParams());
    defer manager.deinit();

    const id = try manager.openLocal(.bidi);
    try manager.receiveStopSending(.{ .id = id, .app_error_code = 7 });
    try std.testing.expectError(error.StopSending, manager.reserveSend(id, 1, false));
}

test {
    std.testing.refAllDecls(@This());
}
