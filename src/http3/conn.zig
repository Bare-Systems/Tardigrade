//! HTTP/3 connection glue (#247): maps QUIC streams onto the HTTP/3 wire
//! model — unidirectional control/QPACK streams, SETTINGS exchange, request
//! streams — using the frame/QPACK/session codecs in this package.
//!
//! Generic over the QUIC transport type so `src/http3/` depends only on the
//! stream-shaped API a transport exposes (open/write/read/accept), never on
//! packet internals. The native driver in `src/quic/connection.zig`, the
//! deterministic harness, and the interop tool all instantiate it with their
//! transport.
//!
//! Scope: request/response HEADERS + DATA with static-table QPACK (the
//! interoperable baseline this stack advertises in SETTINGS). Server push is
//! rejected per RFC 9114 §7.2.3 (we never send MAX_PUSH_ID).

const std = @import("std");
const early_data = @import("early_data.zig");
const frame = @import("frame.zig");
const qpack = @import("qpack.zig");
const session = @import("session.zig");
const stream_transport = @import("stream_transport");

pub const Role = enum { client, server };

pub const H3Error = error{
    OutOfMemory,
    ProtocolError,
    ResponseTooLarge,
    UnknownStream,
};

/// HTTP/3 wire error codes (RFC 9114 §8.1). Zig errors carry no payload, so
/// when a method returns `error.ProtocolError` the connection-close code
/// travels via `Conn.closeCode()`.
pub const ErrorCode = enum(u64) {
    no_error = 0x0100,
    general_protocol_error = 0x0101,
    internal_error = 0x0102,
    stream_creation_error = 0x0103,
    closed_critical_stream = 0x0104,
    frame_unexpected = 0x0105,
    frame_error = 0x0106,
    id_error = 0x0108,
    settings_error = 0x0109,
    missing_settings = 0x010a,
    message_error = 0x010e,

    pub fn wire(self: ErrorCode) u64 {
        return @intFromEnum(self);
    }
};

/// Hard bound for one accumulated response (headers + body) on the client
/// side; mirrors `session.RequestStream.max_frame_payload_len`.
pub const max_response_len: usize = 1024 * 1024;

pub const Response = struct {
    status: u16,
    /// Decoded header fields, backed by `Client.Pending.buffer`.
    headers: []const qpack.HeaderField,
    body: []const u8,
};

/// The transport contract `Conn` expects. Kept as a comptime duck type so the
/// QUIC driver, mocks, and future transports need no shared vtable:
///   openStream(.uni/.bidi) !u64
///   writeStream(id, bytes, fin) !usize
///   readStream(id, buf) !{ len: usize, fin: bool, ... }
///   acceptStream() ?u64
pub fn Conn(comptime Transport: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        role: Role,
        /// Our outbound control stream id, once opened.
        control_out: ?u64 = null,
        /// Peer streams by uni stream type.
        peer_control: ?u64 = null,
        peer_qpack_encoder: ?u64 = null,
        peer_qpack_decoder: ?u64 = null,
        peer_control_view: frame.ControlStream = .{},
        local_settings: frame.Settings = .{},
        /// Peer uni streams whose type varint has not fully arrived yet, and
        /// unknown-type streams we drain and ignore.
        pending_uni: std.AutoHashMap(u64, PendingUni),
        /// Server: in-flight request decoding sessions by stream id.
        requests: std.AutoHashMap(u64, *ServerRequest),
        /// Client: in-flight response accumulation by stream id.
        responses: std.AutoHashMap(u64, *ClientResponse),
        /// Bidirectional streams the peer opened that we haven't classified.
        metrics: Metrics = .{},
        /// The RFC 9114 code to close the QUIC connection with after a
        /// method returned `error.ProtocolError`; see `closeCode`.
        close_code: ?ErrorCode = null,

        pub const Metrics = struct {
            requests_decoded: u64 = 0,
            responses_decoded: u64 = 0,
            settings_received: bool = false,
            unknown_uni_streams: u64 = 0,
        };

        const PendingUni = struct {
            classified: bool = false,
            typ: frame.StreamType = .unknown,
        };

        const ServerRequest = struct {
            stream: session.RequestStream,
            finished: bool = false,
        };

        const ClientResponse = struct {
            buffer: std.ArrayList(u8) = .empty,
            fin: bool = false,
            fields: [64]qpack.HeaderField = undefined,
            scratch: [4096]u8 = undefined,
        };

        pub fn init(allocator: std.mem.Allocator, role: Role) Self {
            return initWithSettings(allocator, role, .{});
        }

        pub fn initWithSettings(allocator: std.mem.Allocator, role: Role, settings: frame.Settings) Self {
            return .{
                .allocator = allocator,
                .role = role,
                .local_settings = settings,
                .pending_uni = std.AutoHashMap(u64, PendingUni).init(allocator),
                .requests = std.AutoHashMap(u64, *ServerRequest).init(allocator),
                .responses = std.AutoHashMap(u64, *ClientResponse).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.peer_control_view.deinit(self.allocator);
            self.pending_uni.deinit();
            var request_it = self.requests.valueIterator();
            while (request_it.next()) |request| {
                request.*.stream.deinit();
                self.allocator.destroy(request.*);
            }
            self.requests.deinit();
            var response_it = self.responses.valueIterator();
            while (response_it.next()) |response| {
                response.*.buffer.deinit(self.allocator);
                self.allocator.destroy(response.*);
            }
            self.responses.deinit();
        }

        /// The RFC 9114 §8.1 code to close the QUIC connection with after a
        /// method returned `error.ProtocolError`.
        pub fn closeCode(self: *const Self) u64 {
            const code = self.close_code orelse ErrorCode.general_protocol_error;
            return code.wire();
        }

        pub fn peerSettings(self: *const Self) ?frame.Settings {
            if (!self.peer_control_view.saw_settings) return null;
            return self.peer_control_view.settings;
        }

        /// Client-side #367 handoff: before SETTINGS arrives, H3 0-RTT uses
        /// RFC defaults; after the peer control stream is decoded,
        /// subsequently received tickets inherit the remembered server
        /// SETTINGS snapshot.
        pub fn encodePeerSettingsForEarlyDataTicket(self: *const Self, out: []u8) early_data.SnapshotError![]const u8 {
            return early_data.encodeSettingsSnapshot(self.peerSettings() orelse .{}, out);
        }

        /// Record the wire close code (first failure wins) and produce the
        /// generic protocol error the H3Error set carries.
        fn fail(self: *Self, code: ErrorCode) H3Error {
            if (self.close_code == null) self.close_code = code;
            return error.ProtocolError;
        }

        fn failControl(self: *Self, err: frame.DecodeError) H3Error {
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.MissingSettings => self.fail(.missing_settings),
                error.DuplicateSettings => self.fail(.frame_unexpected),
                error.InvalidControlFrame => self.fail(.frame_unexpected),
                error.ReservedSetting,
                error.DuplicateSetting,
                error.InvalidSettingValue,
                error.MalformedSettings,
                => self.fail(.settings_error),
                error.BufferTooShort,
                error.FrameLengthOverflow,
                error.FrameTooLarge,
                => self.fail(.frame_error),
                error.ControlStreamClosed => self.fail(.closed_critical_stream),
                error.InvalidUnidirectionalStreamType,
                error.DuplicateControlStream,
                => self.fail(.stream_creation_error),
            };
        }

        fn isCriticalUniType(typ: frame.StreamType) bool {
            return typ == .control or typ == .qpack_encoder or typ == .qpack_decoder;
        }

        /// Open the control stream and send SETTINGS. Call once the QUIC
        /// connection is established.
        pub fn start(self: *Self, transport: *Transport) !void {
            if (self.control_out != null) return;
            const control = try transport.openStream(.uni);
            var bytes: [64]u8 = undefined;
            var len: usize = 0;
            len += (try frame.encodeStreamType(.control, bytes[len..])).len;
            var settings_payload: [64]u8 = undefined;
            var settings_entries: [5]frame.Setting = undefined;
            const settings = try encodeLocalSettings(self.local_settings, &settings_entries, &settings_payload);
            len += (try frame.encodeKnownFrame(.settings, settings, bytes[len..])).len;
            _ = try transport.writeStream(control, bytes[0..len], false);
            self.control_out = control;
        }

        fn encodeLocalSettings(settings: frame.Settings, entries: *[5]frame.Setting, out: []u8) ![]u8 {
            var count: usize = 0;
            if (settings.qpack_max_table_capacity != 0) {
                entries[count] = .{ .id = .qpack_max_table_capacity, .id_value = 0x01, .value = settings.qpack_max_table_capacity };
                count += 1;
            }
            if (settings.max_field_section_size) |max| {
                entries[count] = .{ .id = .max_field_section_size, .id_value = 0x06, .value = max };
                count += 1;
            }
            if (settings.qpack_blocked_streams != 0) {
                entries[count] = .{ .id = .qpack_blocked_streams, .id_value = 0x07, .value = settings.qpack_blocked_streams };
                count += 1;
            }
            if (settings.enable_connect_protocol) {
                entries[count] = .{ .id = .enable_connect_protocol, .id_value = 0x08, .value = 1 };
                count += 1;
            }
            if (settings.h3_datagram) {
                entries[count] = .{ .id = .h3_datagram, .id_value = 0x33, .value = 1 };
                count += 1;
            }
            return frame.encodeSettings(entries[0..count], out);
        }

        /// Drain newly accepted and readable peer streams. Call after every
        /// network progress step.
        pub fn pump(self: *Self, transport: *Transport) H3Error!void {
            while (transport.acceptStream()) |id| {
                if (id % 4 == 2 or id % 4 == 3) {
                    // Peer unidirectional stream: classify by type varint.
                    self.pending_uni.put(id, .{}) catch return error.OutOfMemory;
                } else if (self.role == .server) {
                    const request = self.allocator.create(ServerRequest) catch return error.OutOfMemory;
                    request.* = .{ .stream = session.RequestStream.init(self.allocator, id) };
                    self.requests.put(id, request) catch {
                        request.stream.deinit();
                        self.allocator.destroy(request);
                        return error.OutOfMemory;
                    };
                } else {
                    // A server must not open bidirectional streams: without a
                    // negotiated extension this is a connection error of type
                    // H3_STREAM_CREATION_ERROR (RFC 9114 §6.1).
                    return self.fail(.stream_creation_error);
                }
            }
            try self.pumpUniStreams(transport);
            if (self.role == .server) try self.pumpRequests(transport);
            if (self.role == .client) try self.pumpResponses(transport);
        }

        fn pumpUniStreams(self: *Self, transport: *Transport) H3Error!void {
            var it = self.pending_uni.iterator();
            while (it.next()) |entry| {
                const id = entry.key_ptr.*;
                const state = entry.value_ptr;
                var buf: [2048]u8 = undefined;
                while (true) {
                    const result = transport.readStream(id, &buf) catch |err| {
                        // A reset of a critical stream closes it just as a FIN
                        // does (RFC 9114 §6.2.1, RFC 9204 §4.2).
                        if (err == error.StreamReset and isCriticalUniType(state.typ)) {
                            return self.fail(.closed_critical_stream);
                        }
                        break;
                    };
                    if (result.len == 0 and !result.fin) break;
                    var bytes: []const u8 = buf[0..result.len];
                    if (!state.classified and bytes.len > 0) {
                        const decoded = frame.decodeStreamType(bytes) catch break;
                        state.classified = true;
                        state.typ = decoded.typ;
                        // The control-stream view consumes its own stream-type
                        // varint; strip it only for the other types.
                        if (decoded.typ != .control) bytes = bytes[decoded.len..];
                        // Only one peer control stream and one of each QPACK
                        // stream is allowed; a duplicate is a connection error
                        // of type H3_STREAM_CREATION_ERROR (RFC 9114 §6.2.1,
                        // RFC 9204 §4.2).
                        switch (decoded.typ) {
                            .control => {
                                if (self.peer_control != null) return self.fail(.stream_creation_error);
                                self.peer_control = id;
                            },
                            .qpack_encoder => {
                                if (self.peer_qpack_encoder != null) return self.fail(.stream_creation_error);
                                self.peer_qpack_encoder = id;
                            },
                            .qpack_decoder => {
                                if (self.peer_qpack_decoder != null) return self.fail(.stream_creation_error);
                                self.peer_qpack_decoder = id;
                            },
                            .push => {
                                // Only servers push, and we never send
                                // MAX_PUSH_ID, so a push stream at the client
                                // exceeds the push ID space (H3_ID_ERROR, RFC
                                // 9114 §7.2.3) and one at the server is a
                                // stream the peer may not create (§6.2.2).
                                if (self.role == .client) return self.fail(.id_error);
                                return self.fail(.stream_creation_error);
                            },
                            .unknown => self.metrics.unknown_uni_streams += 1,
                        }
                    }
                    if (bytes.len > 0 and state.typ == .control) {
                        _ = self.peer_control_view.ingest(self.allocator, bytes) catch |err| {
                            return self.failControl(err);
                        };
                        if (self.peer_control_view.saw_settings) self.metrics.settings_received = true;
                    }
                    // QPACK encoder/decoder instructions: with a zero-capacity
                    // dynamic table the peer sends none that affect state;
                    // unknown streams are drained and dropped.
                    if (result.fin) {
                        // Closing the control or either QPACK stream is a
                        // connection error of type H3_CLOSED_CRITICAL_STREAM
                        // (RFC 9114 §6.2.1, RFC 9204 §4.2).
                        if (isCriticalUniType(state.typ)) return self.fail(.closed_critical_stream);
                        break;
                    }
                }
            }
        }

        fn pumpRequests(self: *Self, transport: *Transport) H3Error!void {
            var it = self.requests.iterator();
            while (it.next()) |entry| {
                const id = entry.key_ptr.*;
                const request = entry.value_ptr.*;
                if (request.finished) continue;
                var buf: [2048]u8 = undefined;
                var qpack_scratch: [4096]u8 = undefined;
                while (true) {
                    const result = transport.readStream(id, &buf) catch break;
                    if (result.len > 0) {
                        _ = request.stream.ingestBytes(buf[0..result.len], &qpack_scratch) catch {
                            return self.fail(.message_error);
                        };
                    }
                    if (result.fin) {
                        request.finished = true;
                        break;
                    }
                    if (result.len == 0) break;
                }
            }
        }

        fn pumpResponses(self: *Self, transport: *Transport) H3Error!void {
            var it = self.responses.iterator();
            while (it.next()) |entry| {
                const id = entry.key_ptr.*;
                const response = entry.value_ptr.*;
                if (response.fin) continue;
                var buf: [2048]u8 = undefined;
                while (true) {
                    const result = transport.readStream(id, &buf) catch break;
                    if (result.len > 0) {
                        if (response.buffer.items.len + result.len > max_response_len) return error.ResponseTooLarge;
                        response.buffer.appendSlice(self.allocator, buf[0..result.len]) catch return error.OutOfMemory;
                    }
                    if (result.fin) {
                        response.fin = true;
                        break;
                    }
                    if (result.len == 0) break;
                }
            }
        }

        // -- client -------------------------------------------------------

        pub const Request = struct {
            method: []const u8 = "GET",
            scheme: []const u8 = "https",
            authority: []const u8,
            path: []const u8,
            headers: []const qpack.HeaderField = &.{},
            body: []const u8 = "",
        };

        /// Encode and send one request; returns the request stream id.
        pub fn sendRequest(self: *Self, transport: *Transport, request: Request) !u64 {
            std.debug.assert(self.role == .client);
            const id = try transport.openStream(.bidi);

            var fields_buf: [68]qpack.HeaderField = undefined;
            fields_buf[0] = .{ .name = ":method", .value = request.method };
            fields_buf[1] = .{ .name = ":scheme", .value = request.scheme };
            fields_buf[2] = .{ .name = ":authority", .value = request.authority };
            fields_buf[3] = .{ .name = ":path", .value = request.path };
            if (request.headers.len > fields_buf.len - 4) return error.TooManyHeaders;
            for (request.headers, 0..) |header, i| fields_buf[4 + i] = header;

            var block: [4096]u8 = undefined;
            const header_block = try qpack.encode(fields_buf[0 .. 4 + request.headers.len], &block);
            var wire: [8192]u8 = undefined;
            var len: usize = 0;
            len += (try frame.encodeKnownFrame(.headers, header_block, wire[len..])).len;
            if (request.body.len > 0) {
                len += (try frame.encodeKnownFrame(.data, request.body, wire[len..])).len;
            }
            var written: usize = 0;
            while (written < len) {
                written += try transport.writeStream(id, wire[written..len], true);
            }

            const response = self.allocator.create(ClientResponse) catch return error.OutOfMemory;
            response.* = .{};
            self.responses.put(id, response) catch {
                self.allocator.destroy(response);
                return error.OutOfMemory;
            };
            return id;
        }

        /// Decode the response once the peer has finished the stream.
        /// Returns null while the response is still in flight. The returned
        /// slices borrow the connection's accumulation buffer and stay valid
        /// until the stream is released with `releaseResponse`.
        pub fn pollResponse(self: *Self, id: u64) H3Error!?Response {
            const response = self.responses.get(id) orelse return error.UnknownStream;
            if (!response.fin) return null;

            var offset: usize = 0;
            var status: ?u16 = null;
            var field_count: usize = 0;
            var body_start: usize = 0;
            var body_len: usize = 0;
            while (offset < response.buffer.items.len) {
                const raw = frame.decodeFrameWithLimit(response.buffer.items[offset..], max_response_len) catch return error.ProtocolError;
                switch (raw.typ) {
                    .headers => {
                        if (status != null) return error.ProtocolError;
                        var scratch: []u8 = &response.scratch;
                        field_count = qpack.decode(raw.payload, &response.fields, scratch[0..]) catch return error.ProtocolError;
                        if (field_count == 0) return error.ProtocolError;
                        if (!std.mem.eql(u8, response.fields[0].name, ":status")) return error.ProtocolError;
                        status = std.fmt.parseInt(u16, response.fields[0].value, 10) catch return error.ProtocolError;
                    },
                    .data => {
                        if (status == null) return error.ProtocolError;
                        if (body_len == 0) {
                            body_start = offset + (raw.len - raw.payload.len);
                        }
                        // Contiguity: DATA payloads are adjacent in wire order;
                        // multiple DATA frames are concatenated by copy-down.
                        if (body_len > 0) {
                            std.mem.copyForwards(
                                u8,
                                response.buffer.items[body_start + body_len ..][0..raw.payload.len],
                                raw.payload,
                            );
                        }
                        body_len += raw.payload.len;
                    },
                    else => {}, // unknown frames on request streams are ignored (RFC 9114 §9)
                }
                offset += raw.len;
            }
            const final_status = status orelse return error.ProtocolError;
            self.metrics.responses_decoded += 1;
            return .{
                .status = final_status,
                .headers = response.fields[1..field_count],
                .body = response.buffer.items[body_start..][0..body_len],
            };
        }

        pub fn releaseResponse(self: *Self, id: u64) void {
            if (self.responses.fetchRemove(id)) |entry| {
                entry.value.buffer.deinit(self.allocator);
                self.allocator.destroy(entry.value);
            }
        }

        // -- server -------------------------------------------------------

        pub const IncomingRequest = struct {
            stream_id: u64,
            exchange: stream_transport.Exchange,
        };

        /// Pop the next fully received request. The exchange borrows the
        /// request session's memory; call `finishRequest` after responding.
        pub fn pollRequest(self: *Self) H3Error!?IncomingRequest {
            var it = self.requests.iterator();
            while (it.next()) |entry| {
                const request = entry.value_ptr.*;
                if (!request.finished or request.stream.finished) continue;
                const exchange = request.stream.finish() catch return self.fail(.message_error);
                self.metrics.requests_decoded += 1;
                return .{ .stream_id = entry.key_ptr.*, .exchange = exchange };
            }
            return null;
        }

        /// Encode and send a response with optional body, closing the stream.
        /// The body is framed in bounded DATA chunks; if the transport's send
        /// buffer fills before everything is queued, `error.StreamBackpressure`
        /// is returned (streamed responses over H3 arrive with #257).
        pub fn sendResponse(
            self: *Self,
            transport: *Transport,
            stream_id: u64,
            status: u16,
            headers: []const stream_transport.Header,
            body: []const u8,
        ) !void {
            var wire: [8192]u8 = undefined;
            const header_frame = try session.ResponseEncoder.encodeHeaders(status, headers, &wire);
            try self.writeAll(transport, stream_id, header_frame, body.len == 0);

            var offset: usize = 0;
            while (offset < body.len) {
                const chunk_len = @min(body.len - offset, 4096);
                const chunk = try session.ResponseEncoder.encodeData(body[offset..][0..chunk_len], &wire);
                offset += chunk_len;
                try self.writeAll(transport, stream_id, chunk, offset == body.len);
            }
            self.finishRequest(stream_id);
        }

        fn writeAll(self: *Self, transport: *Transport, stream_id: u64, bytes: []const u8, fin: bool) !void {
            _ = self;
            // The transport records FIN only when it accepts the whole slice
            // of a fin-marked write, so passing `fin` per attempt is exact.
            if (bytes.len == 0) {
                if (fin) _ = try transport.writeStream(stream_id, "", true);
                return;
            }
            var written: usize = 0;
            while (written < bytes.len) {
                const n = try transport.writeStream(stream_id, bytes[written..], fin);
                if (n == 0) return error.StreamBackpressure;
                written += n;
            }
        }

        pub fn finishRequest(self: *Self, stream_id: u64) void {
            if (self.requests.fetchRemove(stream_id)) |entry| {
                entry.value.stream.deinit();
                self.allocator.destroy(entry.value);
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Tests with an in-memory mock transport (the full QUIC-backed end-to-end
// path is exercised in tests/quic_h3_e2e.zig).
// ---------------------------------------------------------------------------

const testing = std.testing;

const MockStream = struct {
    data: std.ArrayList(u8) = .empty,
    read_pos: usize = 0,
    fin: bool = false,
};

/// Two mock transports joined back-to-back: writes on one side become reads
/// on the other. Stream ids follow RFC 9000 §2.1 numbering.
const MockTransport = struct {
    allocator: std.mem.Allocator,
    is_client: bool,
    streams: std.AutoHashMap(u64, *MockStream),
    peer: ?*MockTransport = null,
    next_bidi: u64 = 0,
    next_uni: u64 = 0,
    accepted: std.ArrayList(u64) = .empty,

    fn init(allocator: std.mem.Allocator, is_client: bool) MockTransport {
        return .{
            .allocator = allocator,
            .is_client = is_client,
            .streams = std.AutoHashMap(u64, *MockStream).init(allocator),
        };
    }

    fn deinit(self: *MockTransport) void {
        var it = self.streams.valueIterator();
        while (it.next()) |s| {
            s.*.data.deinit(self.allocator);
            self.allocator.destroy(s.*);
        }
        self.streams.deinit();
        self.accepted.deinit(self.allocator);
    }

    fn stream(self: *MockTransport, id: u64) !*MockStream {
        if (self.streams.get(id)) |s| return s;
        const s = try self.allocator.create(MockStream);
        s.* = .{};
        try self.streams.put(id, s);
        return s;
    }

    pub fn openStream(self: *MockTransport, typ: enum { bidi, uni }) !u64 {
        const base: u64 = if (self.is_client) 0 else 1;
        const id = switch (typ) {
            .bidi => blk: {
                defer self.next_bidi += 1;
                break :blk base + self.next_bidi * 4;
            },
            .uni => blk: {
                defer self.next_uni += 1;
                break :blk base + 2 + self.next_uni * 4;
            },
        };
        _ = try self.stream(id);
        if (self.peer) |peer| try peer.accepted.append(peer.allocator, id);
        return id;
    }

    pub fn writeStream(self: *MockTransport, id: u64, bytes: []const u8, fin: bool) !usize {
        const target = self.peer orelse return error.UnknownStream;
        const s = try target.stream(id);
        try s.data.appendSlice(target.allocator, bytes);
        if (fin) s.fin = true;
        return bytes.len;
    }

    pub fn readStream(self: *MockTransport, id: u64, out: []u8) !struct { len: usize, fin: bool } {
        const s = self.streams.get(id) orelse return error.UnknownStream;
        const available = s.data.items.len - s.read_pos;
        const n = @min(available, out.len);
        @memcpy(out[0..n], s.data.items[s.read_pos..][0..n]);
        s.read_pos += n;
        return .{ .len = n, .fin = s.fin and s.read_pos == s.data.items.len };
    }

    pub fn acceptStream(self: *MockTransport) ?u64 {
        if (self.accepted.items.len == 0) return null;
        return self.accepted.orderedRemove(0);
    }
};

test "H3 conn: SETTINGS exchange and request/response over a mock transport" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var client = H3.init(allocator, .client);
    defer client.deinit();
    var server = H3.init(allocator, .server);
    defer server.deinit();

    try client.start(&client_transport);
    try server.start(&server_transport);
    try server.pump(&server_transport);
    try client.pump(&client_transport);
    try testing.expect(server.metrics.settings_received);
    try testing.expect(client.metrics.settings_received);

    const id = try client.sendRequest(&client_transport, .{
        .authority = "tardigrade.test",
        .path = "/hello",
        .body = "ping",
    });
    try server.pump(&server_transport);
    const incoming = (try server.pollRequest()).?;
    try testing.expectEqualStrings("GET", incoming.exchange.request.method);
    try testing.expectEqualStrings("/hello", incoming.exchange.request.path);
    try testing.expectEqualStrings("ping", incoming.exchange.body.buffered);

    try server.sendResponse(&server_transport, incoming.stream_id, 200, &.{
        .{ .name = "server", .value = "tardigrade" },
    }, "pong");
    try client.pump(&client_transport);
    const response = (try client.pollResponse(id)).?;
    try testing.expectEqual(@as(u16, 200), response.status);
    try testing.expectEqualStrings("pong", response.body);
    try testing.expectEqualStrings("server", response.headers[0].name);
    client.releaseResponse(id);
}

test "H3 conn: start emits configured non-default SETTINGS" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var server = H3.initWithSettings(allocator, .server, .{
        .qpack_max_table_capacity = 1024,
        .qpack_blocked_streams = 2,
        .max_field_section_size = 4096,
        .enable_connect_protocol = true,
    });
    defer server.deinit();

    try server.start(&server_transport);
    try testing.expectEqual(@as(?u64, 3), server.control_out);
    const stream = client_transport.streams.get(3) orelse return error.TestExpectedEqual;
    var control = frame.ControlStream{};
    defer control.deinit(allocator);
    try testing.expectEqual(stream.data.items.len, try control.ingest(allocator, stream.data.items));
    try testing.expect(control.saw_settings);
    try testing.expectEqual(@as(u64, 1024), control.settings.qpack_max_table_capacity);
    try testing.expectEqual(@as(u64, 2), control.settings.qpack_blocked_streams);
    try testing.expectEqual(@as(?u64, 4096), control.settings.max_field_section_size);
    try testing.expect(control.settings.enable_connect_protocol);
}

test "H3 conn: early ticket snapshot uses defaults until peer SETTINGS arrive" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var client = H3.init(allocator, .client);
    defer client.deinit();
    var snapshot: [early_data.encoded_snapshot_len]u8 = undefined;
    const defaults = try client.encodePeerSettingsForEarlyDataTicket(&snapshot);
    try testing.expectEqual(frame.Settings{}, try early_data.decodeSettingsSnapshot(defaults));

    var server = H3.initWithSettings(allocator, .server, .{
        .qpack_blocked_streams = 3,
        .max_field_section_size = 8192,
        .enable_connect_protocol = true,
    });
    defer server.deinit();
    try server.start(&server_transport);
    try client.pump(&client_transport);
    const remembered = try client.encodePeerSettingsForEarlyDataTicket(&snapshot);
    try testing.expectEqual(frame.Settings{
        .qpack_blocked_streams = 3,
        .max_field_section_size = 8192,
        .enable_connect_protocol = true,
    }, try early_data.decodeSettingsSnapshot(remembered));
}

test "H3 conn: duplicate QPACK encoder stream is a stream creation error" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var client = H3.init(allocator, .client);
    defer client.deinit();

    // The "server" opens two uni streams that both declare the QPACK encoder
    // stream type (0x02).
    const first = try server_transport.openStream(.uni);
    _ = try server_transport.writeStream(first, "\x02", false);
    const second = try server_transport.openStream(.uni);
    _ = try server_transport.writeStream(second, "\x02", false);

    try testing.expectError(error.ProtocolError, client.pump(&client_transport));
    try testing.expectEqual(ErrorCode.stream_creation_error.wire(), client.closeCode());
}

test "H3 conn: server-initiated bidirectional stream is a connection error at the client" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var client = H3.init(allocator, .client);
    defer client.deinit();

    _ = try server_transport.openStream(.bidi);
    try testing.expectError(error.ProtocolError, client.pump(&client_transport));
    try testing.expectEqual(ErrorCode.stream_creation_error.wire(), client.closeCode());
}

test "H3 conn: FIN on the peer control stream closes the connection" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var client = H3.init(allocator, .client);
    defer client.deinit();
    var server = H3.init(allocator, .server);
    defer server.deinit();

    // A well-formed control stream (type + SETTINGS) that then ends.
    try server.start(&server_transport);
    const control = server.control_out.?;
    _ = try server_transport.writeStream(control, "", true);

    try testing.expectError(error.ProtocolError, client.pump(&client_transport));
    try testing.expectEqual(ErrorCode.closed_critical_stream.wire(), client.closeCode());
    // SETTINGS were still processed before the close.
    try testing.expect(client.metrics.settings_received);
}

test {
    std.testing.refAllDecls(@This());
}
