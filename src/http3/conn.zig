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
const priority = @import("priority.zig");
const qpack = @import("qpack.zig");
const session = @import("session.zig");
const stream_transport = @import("stream_transport");
const varint = @import("quic_varint");

pub const Role = enum { client, server };

pub const EventStreamType = enum {
    request,
    control,
    push,
    qpack_encoder,
    qpack_decoder,
    unknown,
};

pub const EventInitiator = enum { local, remote };

pub const EventSetting = struct {
    id_value: u64,
    value: u64,
};

pub const EventFrame = union(enum) {
    data: struct {
        raw_length: usize,
    },
    headers: struct {
        fields: []const qpack.HeaderField = &.{},
        raw_length: usize,
    },
    settings: struct {
        entries: []const EventSetting,
        raw_length: usize,
    },
    goaway: struct {
        id: u64,
        raw_length: usize,
    },
    priority_update: union(enum) {
        request: struct {
            stream_id: u64,
            field_value: []const u8,
            raw_length: usize,
        },
        push: struct {
            push_id: u64,
            field_value: []const u8,
            raw_length: usize,
        },
    },
    push_promise: struct {
        push_id: u64,
        fields: []const qpack.HeaderField = &.{},
        raw_length: usize,
    },
    cancel_push: struct {
        push_id: u64,
        raw_length: usize,
    },
    max_push_id: struct {
        push_id: u64,
        raw_length: usize,
    },
    unknown: struct {
        frame_type_value: u64,
        raw_length: usize,
    },
    malformed: struct {
        frame_type: frame.FrameType,
        frame_type_value: u64,
        raw_length: usize,
    },
};

pub const Event = union(enum) {
    parameters_set: struct {
        initiator: EventInitiator,
        settings: frame.Settings,
    },
    stream_type_set: struct {
        stream_id: u64,
        stream_type: EventStreamType,
    },
    frame_created: struct {
        stream_id: u64,
        frame: EventFrame,
    },
    frame_parsed: struct {
        stream_id: u64,
        frame: EventFrame,
    },
    priority_updated: struct {
        stream_id: u64,
        urgency: u3,
        incremental: bool,
    },
};

/// Diagnostics hook for H3/qlog. Must not block or feed errors back into
/// protocol state; sinks retain failures out-of-band.
///
/// All slices inside `event` are borrowed and valid only for the synchronous
/// callback. Implementations must serialize or deep-copy before returning and
/// must not retain/enqueue `event` itself.
pub const EventSink = struct {
    context: ?*anyopaque = null,
    emitFn: ?*const fn (?*anyopaque, Event) void = null,

    pub fn emit(self: EventSink, event: Event) void {
        if (self.emitFn) |emit_fn| emit_fn(self.context, event);
    }
};

pub const H3Error = error{
    OutOfMemory,
    ProtocolError,
    GoawayReceived,
    ResponseTooLarge,
    UnknownStream,
    UnsupportedH3Setting,
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
    excessive_load = 0x0107,
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
        /// PRIORITY_UPDATE frames may overtake their request streams; retain
        /// the newest bounded update until the stream appears.
        pending_priority_updates: std.AutoHashMap(u64, priority.Priority),
        /// Client: in-flight response accumulation by stream id.
        responses: std.AutoHashMap(u64, *ClientResponse),
        peer_goaway_id: ?u64 = null,
        local_goaway_id: ?u64 = null,
        /// Bidirectional streams the peer opened that we haven't classified.
        metrics: Metrics = .{},
        events: EventSink = .{},
        /// The RFC 9114 code to close the QUIC connection with after a
        /// method returned `error.ProtocolError`; see `closeCode`.
        close_code: ?ErrorCode = null,

        pub const Metrics = struct {
            requests_decoded: u64 = 0,
            responses_decoded: u64 = 0,
            settings_received: bool = false,
            unknown_uni_streams: u64 = 0,
            priority_updates_received: u64 = 0,
            priority_updates_ignored_push: u64 = 0,
            priority_parse_errors: u64 = 0,
            priority_invalid_parameters: u64 = 0,
            priority_duplicate_parameters: u64 = 0,
            priority_updates_buffered: u64 = 0,
            goaway_received: u64 = 0,
            /// Peer request streams rejected directly by `pump()` because
            /// they arrived at or above `local_goaway_id` — never surfaced
            /// as an `IncomingRequest`, so `Runtime` cannot observe them via
            /// `pollRequest()`. See `Metrics.goaway_request_rejections` at
            /// the call site in `pump()`.
            goaway_request_rejections: u64 = 0,
        };

        const max_pending_priority_updates: usize = 64;

        const PendingUni = struct {
            classified: bool = false,
            typ: frame.StreamType = .unknown,
        };

        const ServerRequest = struct {
            stream: session.RequestStream,
            finished: bool = false,
            transport_early: bool = false,
            priority_metrics_recorded: bool = false,
            pending_priority_update: ?priority.Priority = null,
        };

        fn transportStreamTransportEarly(transport: *Transport, stream_id: u64) bool {
            if (comptime @hasDecl(Transport, "streamTransportEarly")) {
                return transport.streamTransportEarly(stream_id);
            }
            return false;
        }

        fn rejectRequestStream(transport: *Transport, stream_id: u64) void {
            if (comptime @hasDecl(Transport, "resetStream")) {
                transport.resetStream(stream_id, 0x010b) catch {};
            } else if (comptime @hasDecl(Transport, "resetStreamForTest")) {
                transport.resetStreamForTest(stream_id) catch {};
            }
        }

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
                .pending_priority_updates = std.AutoHashMap(u64, priority.Priority).init(allocator),
                .responses = std.AutoHashMap(u64, *ClientResponse).init(allocator),
            };
        }

        pub fn setEventSink(self: *Self, sink: EventSink) void {
            self.events = sink;
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
            self.pending_priority_updates.deinit();
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
            frame.validateLocallySupportedSettings(self.local_settings) catch return error.UnsupportedH3Setting;
            const control = try transport.openStream(.uni);
            var bytes: [64]u8 = undefined;
            var len: usize = 0;
            len += (try frame.encodeStreamType(.control, bytes[len..])).len;
            var settings_payload: [64]u8 = undefined;
            var settings_entries: [5]frame.Setting = undefined;
            var event_settings: [5]EventSetting = undefined;
            const settings = try encodeLocalSettings(self.local_settings, &settings_entries, &event_settings, &settings_payload);
            const settings_frame = try frame.encodeKnownFrame(.settings, settings.payload, bytes[len..]);
            len += settings_frame.len;
            self.events.emit(.{ .stream_type_set = .{ .stream_id = control, .stream_type = .control } });
            self.events.emit(.{ .frame_created = .{ .stream_id = control, .frame = .{ .settings = .{ .entries = settings.entries, .raw_length = settings_frame.len } } } });
            _ = try transport.writeStream(control, bytes[0..len], false);
            self.control_out = control;
            self.events.emit(.{ .parameters_set = .{ .initiator = .local, .settings = self.local_settings } });
            if (self.role == .client) try self.publishEarlyTicketSnapshot(transport);
        }

        fn publishEarlyTicketSnapshot(self: *const Self, transport: *Transport) H3Error!void {
            if (!@hasDecl(Transport, "setEarlyDataApplicationCompat")) return;
            var snapshot: [early_data.encoded_snapshot_len]u8 = undefined;
            const encoded = self.encodePeerSettingsForEarlyDataTicket(&snapshot) catch return error.ProtocolError;
            transport.setEarlyDataApplicationCompat(.{
                .format_id = early_data.format_id,
                .format_version = early_data.format_version,
                .bytes = encoded,
            }) catch return error.ProtocolError;
        }

        fn encodeLocalSettings(settings: frame.Settings, entries: *[5]frame.Setting, event_entries: *[5]EventSetting, out: []u8) !struct { payload: []u8, entries: []const EventSetting } {
            var count: usize = 0;
            if (settings.qpack_max_table_capacity != 0) {
                entries[count] = .{ .id = .qpack_max_table_capacity, .id_value = 0x01, .value = settings.qpack_max_table_capacity };
                event_entries[count] = .{ .id_value = entries[count].id_value, .value = entries[count].value };
                count += 1;
            }
            if (settings.max_field_section_size) |max| {
                entries[count] = .{ .id = .max_field_section_size, .id_value = 0x06, .value = max };
                event_entries[count] = .{ .id_value = entries[count].id_value, .value = entries[count].value };
                count += 1;
            }
            if (settings.qpack_blocked_streams != 0) {
                entries[count] = .{ .id = .qpack_blocked_streams, .id_value = 0x07, .value = settings.qpack_blocked_streams };
                event_entries[count] = .{ .id_value = entries[count].id_value, .value = entries[count].value };
                count += 1;
            }
            if (settings.enable_connect_protocol) {
                entries[count] = .{ .id = .enable_connect_protocol, .id_value = 0x08, .value = 1 };
                event_entries[count] = .{ .id_value = entries[count].id_value, .value = entries[count].value };
                count += 1;
            }
            if (settings.h3_datagram) {
                entries[count] = .{ .id = .h3_datagram, .id_value = 0x33, .value = 1 };
                event_entries[count] = .{ .id_value = entries[count].id_value, .value = entries[count].value };
                count += 1;
            }
            const payload = try frame.encodeSettings(entries[0..count], out);
            return .{ .payload = payload, .entries = event_entries[0..count] };
        }

        /// Drain newly accepted and readable peer streams. Call after every
        /// network progress step.
        pub fn pump(self: *Self, transport: *Transport) H3Error!void {
            // Once the connection has already failed, it must not keep
            // accepting or tracking new peer-initiated state (streams,
            // requests, pending uni entries): every field below this guard
            // is inert until deinit. In production this stays unreachable
            // in practice, since a QUIC-level close stops stream delivery
            // to this layer first, but the H3 connection object itself
            // must not depend on that upstream guarantee to stay bounded.
            if (self.close_code != null) return;
            while (transport.acceptStream()) |id| {
                if (id % 4 == 2 or id % 4 == 3) {
                    // Peer unidirectional stream: classify by type varint.
                    self.pending_uni.put(id, .{}) catch return error.OutOfMemory;
                } else if (self.role == .server) {
                    if (!isClientRequestStream(id)) return self.fail(.stream_creation_error);
                    if (self.local_goaway_id) |limit| {
                        if (id >= limit) {
                            rejectRequestStream(transport, id);
                            self.metrics.goaway_request_rejections += 1;
                            continue;
                        }
                    }
                    const request = self.allocator.create(ServerRequest) catch return error.OutOfMemory;
                    request.* = .{
                        .stream = session.RequestStream.init(self.allocator, id),
                        .transport_early = transportStreamTransportEarly(transport, id),
                    };
                    self.events.emit(.{ .stream_type_set = .{ .stream_id = id, .stream_type = .request } });
                    if (self.pending_priority_updates.fetchRemove(id)) |pending| {
                        request.pending_priority_update = pending.value;
                    }
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
                        self.events.emit(.{ .stream_type_set = .{ .stream_id = id, .stream_type = eventStreamTypeFromWire(decoded.typ) } });
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
                        const had_settings = self.peer_control_view.saw_settings;
                        // ingestControlBytes can observe a valid SETTINGS
                        // frame (setting saw_settings) and then fail on a
                        // later frame in the same buffer (e.g. a duplicate
                        // SETTINGS, RFC 9114 §7.2.4) within the same call.
                        // The metrics sync below must run against that
                        // outcome unconditionally — deferred past the
                        // `try` — or an error path leaves saw_settings and
                        // settings_received permanently out of sync.
                        const ingest_result = self.ingestControlBytes(transport, bytes);
                        if (self.peer_control_view.saw_settings) self.metrics.settings_received = true;
                        _ = try ingest_result;
                        if (self.role == .client and !had_settings and self.peer_control_view.saw_settings) {
                            try self.publishEarlyTicketSnapshot(transport);
                        }
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

        fn ingestControlBytes(self: *Self, transport: *Transport, bytes: []const u8) H3Error!usize {
            if (self.peer_control_view.closed) return self.fail(.closed_critical_stream);
            self.peer_control_view.pending.appendSlice(self.allocator, bytes) catch return error.OutOfMemory;

            while (true) {
                if (!self.peer_control_view.saw_type) {
                    const stream_type = frame.decodeStreamType(self.peer_control_view.pending.items) catch |err| switch (err) {
                        error.BufferTooShort => return bytes.len,
                        else => return self.failControl(err),
                    };
                    if (self.peer_control_view.pending.items.len == stream_type.len) return bytes.len;
                    const frame_preview = frame.decodeFrameWithLimit(self.peer_control_view.pending.items[stream_type.len..], frame.ControlStream.max_frame_payload_len) catch |err| switch (err) {
                        error.BufferTooShort => return bytes.len,
                        else => return self.failControl(err),
                    };
                    if (frame_preview.typ != .settings) return self.fail(.missing_settings);
                    if (stream_type.typ != .control) return self.fail(.stream_creation_error);
                    self.peer_control_view.saw_type = true;
                    discardPrefix(&self.peer_control_view.pending, stream_type.len);
                }

                const raw = frame.decodeFrameWithLimit(self.peer_control_view.pending.items, frame.ControlStream.max_frame_payload_len) catch |err| switch (err) {
                    error.BufferTooShort => return bytes.len,
                    else => return self.failControl(err),
                };
                try self.ingestControlFrame(transport, raw);
                discardPrefix(&self.peer_control_view.pending, raw.len);
            }
        }

        fn ingestControlFrame(self: *Self, transport: *Transport, raw: frame.RawFrame) H3Error!void {
            const had_settings = self.peer_control_view.saw_settings;
            if (self.peer_control) |control| {
                var event_scratch = EventDecodeScratch{};
                self.events.emit(.{ .frame_parsed = .{ .stream_id = control, .frame = eventFrameFromRaw(raw, &event_scratch) } });
            }
            switch (raw.typ) {
                .priority_update_request, .priority_update_push => {
                    if (!self.peer_control_view.saw_settings) return self.fail(.missing_settings);
                    try self.applyPriorityUpdate(transport, raw);
                },
                .goaway => {
                    if (!self.peer_control_view.saw_settings) return self.fail(.missing_settings);
                    try self.applyGoaway(raw);
                },
                else => self.peer_control_view.ingestFrame(raw) catch |err| return self.failControl(err),
            }
            if (!had_settings and self.peer_control_view.saw_settings) {
                self.events.emit(.{ .parameters_set = .{ .initiator = .remote, .settings = self.peer_control_view.settings } });
            }
        }

        fn applyGoaway(self: *Self, raw: frame.RawFrame) H3Error!void {
            const decoded = varint.decode(raw.payload) catch return self.fail(.frame_error);
            if (decoded.len != raw.payload.len) return self.fail(.frame_error);
            const id = decoded.value;
            if (self.role == .client and !isClientRequestStream(id)) return self.fail(.id_error);
            if (self.peer_goaway_id) |previous| {
                if (id > previous) return self.fail(.id_error);
            }
            self.peer_goaway_id = id;
            self.metrics.goaway_received += 1;
        }

        fn applyPriorityUpdate(self: *Self, transport: *Transport, raw: frame.RawFrame) H3Error!void {
            if (self.role == .client) return self.fail(.frame_unexpected);
            const kind = priority.kindFromFrameType(raw.typ) orelse return;
            const update = priority.decodePayload(raw.payload) catch return self.fail(.frame_error);
            switch (kind) {
                .push => return self.fail(.id_error),
                .request => if (!isClientRequestStream(update.element_id)) return self.fail(.id_error),
            }

            self.metrics.priority_updates_received += 1;
            const parsed = priority.parse(update.field_value) catch {
                self.metrics.priority_parse_errors += 1;
                return;
            };
            if (parsed.invalid_parameter) self.metrics.priority_invalid_parameters += 1;
            if (parsed.duplicate_parameter) self.metrics.priority_duplicate_parameters += 1;
            if (self.requests.get(update.element_id)) |request| {
                request.pending_priority_update = parsed.effective();
                if (request.stream.saw_headers) self.applyPendingPriorityUpdate(update.element_id, request);
                _ = applyTransportPriority(transport, update.element_id, parsed.effective());
            } else {
                if (applyTransportPriority(transport, update.element_id, parsed.effective())) return;
                if (!self.pending_priority_updates.contains(update.element_id) and
                    self.pending_priority_updates.count() >= max_pending_priority_updates)
                {
                    return self.fail(.excessive_load);
                }
                self.pending_priority_updates.put(update.element_id, parsed.effective()) catch return error.OutOfMemory;
                self.metrics.priority_updates_buffered += 1;
            }
        }

        const RequestFrameObserver = struct {
            conn: *Self,
            stream_id: u64,

            fn observer(self: *RequestFrameObserver) session.RequestStream.FrameObserver {
                return .{ .context = self, .parsedFn = parsed };
            }

            fn parsed(ctx: ?*anyopaque, raw: frame.RawFrame) void {
                const self: *RequestFrameObserver = @ptrCast(@alignCast(ctx.?));
                if (raw.typ == .headers) {
                    var fields: [128]qpack.HeaderField = undefined;
                    var scratch: [4096]u8 = undefined;
                    const count = qpack.decode(raw.payload, &fields, &scratch) catch {
                        self.conn.events.emit(.{ .frame_parsed = .{ .stream_id = self.stream_id, .frame = .{ .malformed = .{ .frame_type = raw.typ, .frame_type_value = raw.type_value, .raw_length = raw.len } } } });
                        return;
                    };
                    self.conn.events.emit(.{ .frame_parsed = .{ .stream_id = self.stream_id, .frame = .{ .headers = .{
                        .fields = fields[0..count],
                        .raw_length = raw.len,
                    } } } });
                    return;
                }
                var event_scratch = EventDecodeScratch{};
                self.conn.events.emit(.{ .frame_parsed = .{ .stream_id = self.stream_id, .frame = eventFrameFromRaw(raw, &event_scratch) } });
            }
        };

        fn pumpRequests(self: *Self, transport: *Transport) H3Error!void {
            var reset_requests: std.ArrayList(u64) = .empty;
            defer reset_requests.deinit(self.allocator);
            var it = self.requests.iterator();
            while (it.next()) |entry| {
                const id = entry.key_ptr.*;
                const request = entry.value_ptr.*;
                if (request.finished) {
                    // The peer must not send more stream data once we have
                    // already observed its FIN (RFC 9114 §4.1: e.g. a
                    // second HEADERS frame on a request stream is
                    // malformed). A real QUIC transport is expected to
                    // reject bytes received past the stream's final size
                    // before they ever reach this layer, but this layer
                    // must not silently trust and drop unexpected
                    // post-finish bytes instead of treating them as the
                    // message error they are.
                    var post_finish_buf: [1]u8 = undefined;
                    const result = transport.readStream(id, &post_finish_buf) catch |err| {
                        if (err == error.StreamReset) reset_requests.append(self.allocator, id) catch return error.OutOfMemory;
                        continue;
                    };
                    if (result.len > 0) return self.fail(.message_error);
                    continue;
                }
                var buf: [2048]u8 = undefined;
                var qpack_scratch: [4096]u8 = undefined;
                while (true) {
                    const result = transport.readStream(id, &buf) catch |err| {
                        if (err == error.StreamReset) {
                            reset_requests.append(self.allocator, id) catch return error.OutOfMemory;
                        }
                        break;
                    };
                    request.transport_early = request.transport_early or transportStreamTransportEarly(transport, id);
                    if (result.len > 0) {
                        var observer = RequestFrameObserver{ .conn = self, .stream_id = id };
                        const frame_observer = if (self.events.emitFn != null) observer.observer() else null;
                        _ = request.stream.ingestBytesWithObserver(buf[0..result.len], &qpack_scratch, frame_observer) catch |err| {
                            if (err == error.UnexpectedFrame) return self.fail(.frame_unexpected);
                            return self.fail(.message_error);
                        };
                        self.recordPriorityHeaderMetrics(request);
                        self.applyPendingPriorityUpdate(id, request);
                    }
                    if (result.fin) {
                        request.finished = true;
                        break;
                    }
                    if (result.len == 0) break;
                }
            }
            for (reset_requests.items) |id| self.finishRequest(id);
        }

        fn applyPendingPriorityUpdate(self: *Self, stream_id: u64, request: *ServerRequest) void {
            if (!request.stream.saw_headers) return;
            if (request.pending_priority_update) |update| {
                request.stream.priority = update;
                request.pending_priority_update = null;
                self.events.emit(.{ .priority_updated = .{
                    .stream_id = stream_id,
                    .urgency = update.urgency,
                    .incremental = update.incremental,
                } });
            }
        }

        fn applyTransportPriority(transport: *Transport, id: u64, p: priority.Priority) bool {
            if (comptime @hasDecl(Transport, "setStreamSchedulingHint")) {
                transport.setStreamSchedulingHint(id, .{
                    .urgency = p.urgency,
                    .incremental = p.incremental,
                }) catch return false;
                return true;
            }
            return false;
        }

        fn recordPriorityHeaderMetrics(self: *Self, request: *ServerRequest) void {
            if (request.priority_metrics_recorded) return;
            if (request.stream.priority_parse_error) {
                self.metrics.priority_parse_errors += 1;
                request.priority_metrics_recorded = true;
                return;
            }
            if (request.stream.priority_invalid_parameter) {
                self.metrics.priority_invalid_parameters += 1;
                request.priority_metrics_recorded = true;
            }
            if (request.stream.priority_duplicate_parameter) {
                self.metrics.priority_duplicate_parameters += 1;
                request.priority_metrics_recorded = true;
            }
        }

        fn priorityBefore(lhs_priority: priority.Priority, lhs_stream_id: u64, rhs_priority: priority.Priority, rhs_stream_id: u64) bool {
            if (lhs_priority.urgency != rhs_priority.urgency) return lhs_priority.urgency < rhs_priority.urgency;
            if (lhs_priority.incremental != rhs_priority.incremental) return lhs_priority.incremental and !rhs_priority.incremental;
            return lhs_stream_id < rhs_stream_id;
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
                        if (containsPriorityUpdateFrame(response.buffer.items)) return self.fail(.frame_unexpected);
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
            if (self.peer_goaway_id != null) return error.GoawayReceived;
            const id = try transport.openStream(.bidi);
            self.events.emit(.{ .stream_type_set = .{ .stream_id = id, .stream_type = .request } });

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
            const headers_frame = try frame.encodeKnownFrame(.headers, header_block, wire[len..]);
            len += headers_frame.len;
            self.events.emit(.{ .frame_created = .{ .stream_id = id, .frame = .{ .headers = .{ .fields = fields_buf[0 .. 4 + request.headers.len], .raw_length = headers_frame.len } } } });
            var data_frame_len: usize = 0;
            if (request.body.len > 0) {
                const data_frame = try frame.encodeKnownFrame(.data, request.body, wire[len..]);
                data_frame_len = data_frame.len;
                len += data_frame.len;
                self.events.emit(.{ .frame_created = .{ .stream_id = id, .frame = .{ .data = .{ .raw_length = data_frame_len } } } });
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
                        var scratch: []u8 = &response.scratch;
                        field_count = qpack.decode(raw.payload, &response.fields, scratch[0..]) catch {
                            self.events.emit(.{ .frame_parsed = .{ .stream_id = id, .frame = .{ .malformed = .{ .frame_type = raw.typ, .frame_type_value = raw.type_value, .raw_length = raw.len } } } });
                            return error.ProtocolError;
                        };
                        self.events.emit(.{ .frame_parsed = .{ .stream_id = id, .frame = .{ .headers = .{ .fields = response.fields[0..field_count], .raw_length = raw.len } } } });
                        if (status != null) return error.ProtocolError;
                        if (field_count == 0) return error.ProtocolError;
                        if (!std.mem.eql(u8, response.fields[0].name, ":status")) return error.ProtocolError;
                        status = std.fmt.parseInt(u16, response.fields[0].value, 10) catch return error.ProtocolError;
                    },
                    .data => {
                        self.events.emit(.{ .frame_parsed = .{ .stream_id = id, .frame = .{ .data = .{ .raw_length = raw.len } } } });
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
                    .priority_update_request, .priority_update_push => {
                        var event_scratch = EventDecodeScratch{};
                        self.events.emit(.{ .frame_parsed = .{ .stream_id = id, .frame = eventFrameFromRaw(raw, &event_scratch) } });
                        return self.fail(.frame_unexpected);
                    },
                    else => {
                        var event_scratch = EventDecodeScratch{};
                        self.events.emit(.{ .frame_parsed = .{ .stream_id = id, .frame = eventFrameFromRaw(raw, &event_scratch) } });
                    },
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
            transport_early: bool,
            priority: priority.Priority,
        };

        pub const ResponseSendState = struct {
            status: u16,
            headers: []const stream_transport.Header,
            body: []const u8,
            phase: Phase = .headers,
            body_offset: usize = 0,
            frame_buf: [8192]u8 = undefined,
            frame_len: usize = 0,
            frame_written: usize = 0,
            frame_fin: bool = false,

            const Phase = enum {
                headers,
                body,
                done,
            };

            pub fn init(status: u16, headers: []const stream_transport.Header, body: []const u8) ResponseSendState {
                return .{
                    .status = status,
                    .headers = headers,
                    .body = body,
                };
            }

            fn hasPendingFrame(self: *const ResponseSendState) bool {
                return self.frame_written < self.frame_len;
            }

            fn clearPendingFrame(self: *ResponseSendState) void {
                self.frame_len = 0;
                self.frame_written = 0;
                self.frame_fin = false;
            }
        };

        /// Pop the next fully received request. The exchange borrows the
        /// request session's memory; call `finishRequest` after responding.
        pub fn pollRequest(self: *Self) H3Error!?IncomingRequest {
            var selected_id: ?u64 = null;
            var selected_request: ?*ServerRequest = null;
            var it = self.requests.iterator();
            while (it.next()) |entry| {
                const stream_id = entry.key_ptr.*;
                const request = entry.value_ptr.*;
                if (!request.finished or request.stream.finished) continue;
                if (selected_request) |current| {
                    if (!priorityBefore(request.stream.priority, stream_id, current.stream.priority, selected_id.?)) continue;
                }
                selected_id = stream_id;
                selected_request = request;
            }
            if (selected_request) |request| {
                const stream_id = selected_id.?;
                const request_priority = request.stream.priority;
                const exchange = request.stream.finish() catch return self.fail(.message_error);
                self.metrics.requests_decoded += 1;
                return .{
                    .stream_id = stream_id,
                    .exchange = exchange,
                    .transport_early = request.transport_early,
                    .priority = request_priority,
                };
            }
            return null;
        }

        /// Encode and send a response with optional body, closing the stream.
        /// The body is framed in bounded DATA chunks; if the transport's send
        /// buffer fills before everything is queued, `error.StreamBackpressure`
        /// is returned. Runtime callers that can yield to the QUIC event loop
        /// should use `sendResponseProgress` and retry the same state later.
        pub fn sendResponse(
            self: *Self,
            transport: *Transport,
            stream_id: u64,
            status: u16,
            headers: []const stream_transport.Header,
            body: []const u8,
        ) !void {
            var state = ResponseSendState.init(status, headers, body);
            while (true) {
                if (try self.sendResponseProgress(transport, stream_id, &state)) return;
                return error.StreamBackpressure;
            }
        }

        /// Continue encoding and queueing one response. Returns `false` when
        /// the QUIC stream send buffer is currently full; callers must yield
        /// to the transport driver and retry the same state later.
        pub fn sendResponseProgress(
            self: *Self,
            transport: *Transport,
            stream_id: u64,
            state: *ResponseSendState,
        ) !bool {
            while (state.phase != .done or state.hasPendingFrame()) {
                if (!state.hasPendingFrame()) {
                    try self.prepareResponseFrame(state, stream_id);
                }
                while (state.frame_written < state.frame_len) {
                    const n = try transport.writeStream(
                        stream_id,
                        state.frame_buf[state.frame_written..state.frame_len],
                        state.frame_fin,
                    );
                    if (n == 0) return false;
                    state.frame_written += n;
                }
                state.clearPendingFrame();
                if (state.phase == .done) {
                    self.finishRequest(stream_id);
                    return true;
                }
            }
            return true;
        }

        fn prepareResponseFrame(self: *Self, state: *ResponseSendState, stream_id: u64) !void {
            switch (state.phase) {
                .headers => {
                    const header_frame = try session.ResponseEncoder.encodeHeaders(state.status, state.headers, &state.frame_buf);
                    state.frame_len = header_frame.len;
                    state.frame_written = 0;
                    state.frame_fin = state.body.len == 0;
                    state.phase = if (state.body.len == 0) .done else .body;

                    var event_fields: [129]qpack.HeaderField = undefined;
                    var status_buf: [3]u8 = undefined;
                    const status_text = std.fmt.bufPrint(&status_buf, "{d}", .{state.status}) catch "500";
                    event_fields[0] = .{ .name = ":status", .value = status_text };
                    if (state.headers.len > event_fields.len - 1) return error.TooManyHeaders;
                    for (state.headers, 0..) |header, i| event_fields[i + 1] = .{ .name = header.name, .value = header.value };
                    self.events.emit(.{ .frame_created = .{ .stream_id = stream_id, .frame = .{ .headers = .{ .fields = event_fields[0 .. state.headers.len + 1], .raw_length = state.frame_len } } } });
                },
                .body => {
                    const chunk_len = @min(state.body.len - state.body_offset, 4096);
                    const chunk = try session.ResponseEncoder.encodeData(state.body[state.body_offset..][0..chunk_len], &state.frame_buf);
                    state.body_offset += chunk_len;
                    state.frame_len = chunk.len;
                    state.frame_written = 0;
                    state.frame_fin = state.body_offset == state.body.len;
                    if (state.frame_fin) state.phase = .done;
                    self.events.emit(.{ .frame_created = .{ .stream_id = stream_id, .frame = .{ .data = .{ .raw_length = state.frame_len } } } });
                },
                .done => {},
            }
        }

        pub fn sendGoaway(self: *Self, transport: *Transport, stream_id: u64) !void {
            const control = self.control_out orelse return error.MissingControlStream;
            if (self.local_goaway_id) |previous| {
                if (stream_id > previous) return self.fail(.id_error);
            }
            var wire: [32]u8 = undefined;
            const goaway = try session.ResponseEncoder.encodeGoaway(stream_id, &wire);
            self.events.emit(.{ .frame_created = .{ .stream_id = control, .frame = .{ .goaway = .{ .id = stream_id, .raw_length = goaway.len } } } });
            try self.writeAll(transport, control, goaway, false);
            self.local_goaway_id = stream_id;
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

fn discardPrefix(list: *std.ArrayList(u8), len: usize) void {
    if (len == 0) return;
    if (len >= list.items.len) {
        list.clearRetainingCapacity();
        return;
    }
    std.mem.copyForwards(u8, list.items[0 .. list.items.len - len], list.items[len..]);
    list.shrinkRetainingCapacity(list.items.len - len);
}

fn isClientRequestStream(stream_id: u64) bool {
    return (stream_id & 0x3) == 0;
}

fn containsPriorityUpdateFrame(bytes: []const u8) bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const raw = frame.decodeFrameWithLimit(bytes[offset..], std.math.maxInt(usize)) catch return false;
        if (raw.typ == .priority_update_request or raw.typ == .priority_update_push) return true;
        offset += raw.len;
    }
    return false;
}

fn decodeEventSettings(payload: []const u8, scratch: []EventSetting) ?[]const EventSetting {
    var count: usize = 0;
    var pos: usize = 0;
    while (pos < payload.len) {
        if (count >= scratch.len) return null;
        const id = varint.decode(payload[pos..]) catch return null;
        pos += id.len;
        const value = varint.decode(payload[pos..]) catch return null;
        pos += value.len;
        scratch[count] = .{ .id_value = id.value, .value = value.value };
        count += 1;
    }
    return scratch[0..count];
}

const EventDecodeScratch = struct {
    settings: [32]EventSetting = undefined,
    fields: [128]qpack.HeaderField = undefined,
    qpack: [4096]u8 = undefined,
};

fn eventFrameFromRaw(raw: frame.RawFrame, scratch: *EventDecodeScratch) EventFrame {
    const malformed = EventFrame{ .malformed = .{ .frame_type = raw.typ, .frame_type_value = raw.type_value, .raw_length = raw.len } };
    return switch (raw.typ) {
        .data => .{ .data = .{ .raw_length = raw.len } },
        .headers => .{ .headers = .{ .raw_length = raw.len } },
        .settings => blk: {
            const entries = decodeEventSettings(raw.payload, &scratch.settings) orelse return malformed;
            break :blk .{ .settings = .{ .entries = entries, .raw_length = raw.len } };
        },
        .goaway => blk: {
            const decoded = varint.decode(raw.payload) catch return malformed;
            if (decoded.len != raw.payload.len) return malformed;
            break :blk .{ .goaway = .{ .id = decoded.value, .raw_length = raw.len } };
        },
        .priority_update_request, .priority_update_push => blk: {
            const decoded = priority.decodePayload(raw.payload) catch return malformed;
            const kind = priority.kindFromFrameType(raw.typ) orelse return malformed;
            break :blk switch (kind) {
                .request => .{ .priority_update = .{ .request = .{
                    .stream_id = decoded.element_id,
                    .field_value = decoded.field_value,
                    .raw_length = raw.len,
                } } },
                .push => .{ .priority_update = .{ .push = .{
                    .push_id = decoded.element_id,
                    .field_value = decoded.field_value,
                    .raw_length = raw.len,
                } } },
            };
        },
        .push_promise => blk: {
            const decoded = varint.decode(raw.payload) catch return malformed;
            const count = qpack.decode(raw.payload[decoded.len..], &scratch.fields, &scratch.qpack) catch return .{ .malformed = .{
                .frame_type = raw.typ,
                .frame_type_value = raw.type_value,
                .raw_length = raw.len,
            } };
            break :blk .{ .push_promise = .{ .push_id = decoded.value, .fields = scratch.fields[0..count], .raw_length = raw.len } };
        },
        .cancel_push => blk: {
            const decoded = varint.decode(raw.payload) catch return malformed;
            if (decoded.len != raw.payload.len) return malformed;
            break :blk .{ .cancel_push = .{ .push_id = decoded.value, .raw_length = raw.len } };
        },
        .max_push_id => blk: {
            const decoded = varint.decode(raw.payload) catch return malformed;
            if (decoded.len != raw.payload.len) return malformed;
            break :blk .{ .max_push_id = .{ .push_id = decoded.value, .raw_length = raw.len } };
        },
        .unknown => .{ .unknown = .{ .frame_type_value = raw.type_value, .raw_length = raw.len } },
    };
}

fn eventStreamTypeFromWire(typ: frame.StreamType) EventStreamType {
    return switch (typ) {
        .control => .control,
        .push => .push,
        .qpack_encoder => .qpack_encoder,
        .qpack_decoder => .qpack_decoder,
        .unknown => .unknown,
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
    reset: bool = false,
};

/// Two mock transports joined back-to-back: writes on one side become reads
/// on the other. Stream ids follow RFC 9000 §2.1 numbering.
const MockTransport = struct {
    allocator: std.mem.Allocator,
    is_client: bool,
    streams: std.AutoHashMap(u64, *MockStream),
    scheduling_hints: std.AutoHashMap(u64, priority.Priority),
    peer: ?*MockTransport = null,
    next_bidi: u64 = 0,
    next_uni: u64 = 0,
    accepted: std.ArrayList(u64) = .empty,
    write_calls: usize = 0,
    fail_writes_after: ?usize = null,

    fn init(allocator: std.mem.Allocator, is_client: bool) MockTransport {
        return .{
            .allocator = allocator,
            .is_client = is_client,
            .streams = std.AutoHashMap(u64, *MockStream).init(allocator),
            .scheduling_hints = std.AutoHashMap(u64, priority.Priority).init(allocator),
        };
    }

    fn deinit(self: *MockTransport) void {
        var it = self.streams.valueIterator();
        while (it.next()) |s| {
            s.*.data.deinit(self.allocator);
            self.allocator.destroy(s.*);
        }
        self.streams.deinit();
        self.scheduling_hints.deinit();
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
        if (self.fail_writes_after) |limit| {
            if (self.write_calls >= limit) return error.StreamBackpressure;
        }
        self.write_calls += 1;
        const target = self.peer orelse return error.UnknownStream;
        const s = try target.stream(id);
        try s.data.appendSlice(target.allocator, bytes);
        if (fin) s.fin = true;
        return bytes.len;
    }

    pub fn readStream(self: *MockTransport, id: u64, out: []u8) !struct { len: usize, fin: bool } {
        const s = self.streams.get(id) orelse return error.UnknownStream;
        if (s.reset) return error.StreamReset;
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

    pub fn setStreamSchedulingHint(self: *MockTransport, id: u64, hint: anytype) !void {
        if (!self.streams.contains(id)) return error.UnknownStream;
        try self.scheduling_hints.put(id, .{
            .urgency = hint.urgency,
            .incremental = hint.incremental,
        });
    }

    fn resetStreamForTest(self: *MockTransport, id: u64) !void {
        const s = try self.stream(id);
        s.reset = true;
    }
};

const EventRecorder = struct {
    events: std.ArrayList(Event) = .empty,

    fn deinit(self: *EventRecorder, allocator: std.mem.Allocator) void {
        for (self.events.items) |*event| freeEvent(allocator, event.*);
        self.events.deinit(allocator);
    }

    fn sink(self: *EventRecorder) EventSink {
        return .{ .context = self, .emitFn = emit };
    }

    fn emit(ctx: ?*anyopaque, event: Event) void {
        const self: *EventRecorder = @ptrCast(@alignCast(ctx.?));
        self.events.append(testing.allocator, cloneEvent(testing.allocator, event) catch unreachable) catch unreachable;
    }

    fn cloneFields(allocator: std.mem.Allocator, fields: []const qpack.HeaderField) ![]const qpack.HeaderField {
        const copy = try allocator.alloc(qpack.HeaderField, fields.len);
        errdefer allocator.free(copy);
        for (fields, 0..) |field, i| {
            const name = try allocator.dupe(u8, field.name);
            errdefer allocator.free(name);
            const value = try allocator.dupe(u8, field.value);
            errdefer allocator.free(value);
            copy[i] = .{ .name = name, .value = value };
        }
        return copy;
    }

    fn freeFields(allocator: std.mem.Allocator, fields: []const qpack.HeaderField) void {
        for (fields) |field| {
            allocator.free(field.name);
            allocator.free(field.value);
        }
        allocator.free(fields);
    }

    fn cloneFrame(allocator: std.mem.Allocator, event_frame: EventFrame) !EventFrame {
        return switch (event_frame) {
            .headers => |h| .{ .headers = .{ .fields = try cloneFields(allocator, h.fields), .raw_length = h.raw_length } },
            .settings => |s| blk: {
                const entries = try allocator.dupe(EventSetting, s.entries);
                break :blk .{ .settings = .{ .entries = entries, .raw_length = s.raw_length } };
            },
            .priority_update => |update| .{ .priority_update = switch (update) {
                .request => |r| .{ .request = .{
                    .stream_id = r.stream_id,
                    .field_value = try allocator.dupe(u8, r.field_value),
                    .raw_length = r.raw_length,
                } },
                .push => |p| .{ .push = .{
                    .push_id = p.push_id,
                    .field_value = try allocator.dupe(u8, p.field_value),
                    .raw_length = p.raw_length,
                } },
            } },
            .push_promise => |p| .{ .push_promise = .{
                .push_id = p.push_id,
                .fields = try cloneFields(allocator, p.fields),
                .raw_length = p.raw_length,
            } },
            else => event_frame,
        };
    }

    fn freeFrame(allocator: std.mem.Allocator, event_frame: EventFrame) void {
        switch (event_frame) {
            .headers => |h| freeFields(allocator, h.fields),
            .settings => |s| allocator.free(s.entries),
            .priority_update => |update| switch (update) {
                .request => |r| allocator.free(r.field_value),
                .push => |p| allocator.free(p.field_value),
            },
            .push_promise => |p| freeFields(allocator, p.fields),
            else => {},
        }
    }

    fn cloneEvent(allocator: std.mem.Allocator, event: Event) !Event {
        return switch (event) {
            .frame_created => |f| .{ .frame_created = .{ .stream_id = f.stream_id, .frame = try cloneFrame(allocator, f.frame) } },
            .frame_parsed => |f| .{ .frame_parsed = .{ .stream_id = f.stream_id, .frame = try cloneFrame(allocator, f.frame) } },
            else => event,
        };
    }

    fn freeEvent(allocator: std.mem.Allocator, event: Event) void {
        switch (event) {
            .frame_created => |f| freeFrame(allocator, f.frame),
            .frame_parsed => |f| freeFrame(allocator, f.frame),
            else => {},
        }
    }

    fn eventFrameType(event_frame: EventFrame) frame.FrameType {
        return switch (event_frame) {
            .data => .data,
            .headers => .headers,
            .settings => .settings,
            .goaway => .goaway,
            .priority_update => |update| switch (update) {
                .request => .priority_update_request,
                .push => .priority_update_push,
            },
            .push_promise => .push_promise,
            .cancel_push => .cancel_push,
            .max_push_id => .max_push_id,
            .unknown => .unknown,
            .malformed => |f| f.frame_type,
        };
    }

    fn eventFrameRawLength(event_frame: EventFrame) usize {
        return switch (event_frame) {
            .data => |f| f.raw_length,
            .headers => |f| f.raw_length,
            .settings => |f| f.raw_length,
            .goaway => |f| f.raw_length,
            .priority_update => |update| switch (update) {
                .request => |f| f.raw_length,
                .push => |f| f.raw_length,
            },
            .push_promise => |f| f.raw_length,
            .cancel_push => |f| f.raw_length,
            .max_push_id => |f| f.raw_length,
            .unknown => |f| f.raw_length,
            .malformed => |f| f.raw_length,
        };
    }

    fn sawFrame(self: *const EventRecorder, direction: enum { created, parsed }, typ: frame.FrameType) bool {
        for (self.events.items) |event| switch (event) {
            .frame_created => |f| if (direction == .created and eventFrameType(f.frame) == typ) return true,
            .frame_parsed => |f| if (direction == .parsed and eventFrameType(f.frame) == typ) return true,
            else => {},
        };
        return false;
    }

    fn sawStreamType(self: *const EventRecorder, typ: EventStreamType) bool {
        for (self.events.items) |event| switch (event) {
            .stream_type_set => |s| if (s.stream_type == typ) return true,
            else => {},
        };
        return false;
    }

    fn sawFrameWithLength(self: *const EventRecorder, direction: enum { created, parsed }, typ: frame.FrameType, length: usize) bool {
        for (self.events.items) |event| switch (event) {
            .frame_created => |f| if (direction == .created and eventFrameType(f.frame) == typ and eventFrameRawLength(f.frame) == length) return true,
            .frame_parsed => |f| if (direction == .parsed and eventFrameType(f.frame) == typ and eventFrameRawLength(f.frame) == length) return true,
            else => {},
        };
        return false;
    }

    fn sawParametersSet(self: *const EventRecorder) bool {
        for (self.events.items) |event| switch (event) {
            .parameters_set => return true,
            else => {},
        };
        return false;
    }

    fn sawGoawayParsed(self: *const EventRecorder, id: u64) bool {
        for (self.events.items) |event| switch (event) {
            .frame_parsed => |parsed| switch (parsed.frame) {
                .goaway => |g| if (g.id == id) return true,
                else => {},
            },
            else => {},
        };
        return false;
    }

    fn sawSettingsEntry(self: *const EventRecorder, id_value: u64, value: u64) bool {
        for (self.events.items) |event| switch (event) {
            .frame_created => |parsed| switch (parsed.frame) {
                .settings => |settings| for (settings.entries) |entry| {
                    if (entry.id_value == id_value and entry.value == value) return true;
                },
                else => {},
            },
            .frame_parsed => |parsed| switch (parsed.frame) {
                .settings => |settings| for (settings.entries) |entry| {
                    if (entry.id_value == id_value and entry.value == value) return true;
                },
                else => {},
            },
            else => {},
        };
        return false;
    }

    fn sawSettingsEntryCountAtLeast(self: *const EventRecorder, min_count: usize) bool {
        for (self.events.items) |event| switch (event) {
            .frame_created => |parsed| switch (parsed.frame) {
                .settings => |settings| if (settings.entries.len >= min_count) return true,
                else => {},
            },
            .frame_parsed => |parsed| switch (parsed.frame) {
                .settings => |settings| if (settings.entries.len >= min_count) return true,
                else => {},
            },
            else => {},
        };
        return false;
    }

    fn sawUnknownFrame(self: *const EventRecorder, frame_type_value: u64) bool {
        for (self.events.items) |event| switch (event) {
            .frame_created => |parsed| switch (parsed.frame) {
                .unknown => |unknown| if (unknown.frame_type_value == frame_type_value) return true,
                else => {},
            },
            .frame_parsed => |parsed| switch (parsed.frame) {
                .unknown => |unknown| if (unknown.frame_type_value == frame_type_value) return true,
                else => {},
            },
            else => {},
        };
        return false;
    }

    fn sawMalformedFrame(self: *const EventRecorder, typ: frame.FrameType) bool {
        for (self.events.items) |event| switch (event) {
            .frame_created => |parsed| switch (parsed.frame) {
                .malformed => |malformed| if (malformed.frame_type == typ) return true,
                else => {},
            },
            .frame_parsed => |parsed| switch (parsed.frame) {
                .malformed => |malformed| if (malformed.frame_type == typ) return true,
                else => {},
            },
            else => {},
        };
        return false;
    }

    fn sawPriorityUpdated(self: *const EventRecorder, stream_id: u64, urgency: u3, incremental: bool) bool {
        for (self.events.items) |event| switch (event) {
            .priority_updated => |p| if (p.stream_id == stream_id and p.urgency == urgency and p.incremental == incremental) return true,
            else => {},
        };
        return false;
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

test "H3 conn: client observes response HEADERS before QPACK failure" {
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
    var client_events = EventRecorder{};
    defer client_events.deinit(allocator);
    client.setEventSink(client_events.sink());

    const id = try client.sendRequest(&client_transport, .{ .authority = "tardigrade.test", .path = "/bad-qpack" });
    var wire: [64]u8 = undefined;
    const headers = try frame.encodeKnownFrame(.headers, &.{ 0x00, 0x00, 0x80 }, &wire);
    _ = try server_transport.writeStream(id, headers, true);
    try client.pump(&client_transport);

    try testing.expectError(error.ProtocolError, client.pollResponse(id));
    try testing.expect(client_events.sawMalformedFrame(.headers));
}

test "H3 conn: client observes duplicate response HEADERS before rejection" {
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
    var client_events = EventRecorder{};
    defer client_events.deinit(allocator);
    client.setEventSink(client_events.sink());

    const id = try client.sendRequest(&client_transport, .{ .authority = "tardigrade.test", .path = "/duplicate-headers" });
    var wire: [512]u8 = undefined;
    var len: usize = 0;
    const first = try session.ResponseEncoder.encodeHeaders(200, &.{}, wire[len..]);
    len += first.len;
    const second = try session.ResponseEncoder.encodeHeaders(200, &.{}, wire[len..]);
    len += second.len;
    _ = try server_transport.writeStream(id, wire[0..len], true);
    try client.pump(&client_transport);

    try testing.expectError(error.ProtocolError, client.pollResponse(id));
    try testing.expect(client_events.sawFrame(.parsed, .headers));
}

test "H3 conn: client observes response DATA before missing-headers rejection" {
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
    var client_events = EventRecorder{};
    defer client_events.deinit(allocator);
    client.setEventSink(client_events.sink());

    const id = try client.sendRequest(&client_transport, .{ .authority = "tardigrade.test", .path = "/data-first" });
    var wire: [64]u8 = undefined;
    const data = try frame.encodeKnownFrame(.data, "body", &wire);
    _ = try server_transport.writeStream(id, data, true);
    try client.pump(&client_transport);

    try testing.expectError(error.ProtocolError, client.pollResponse(id));
    try testing.expect(client_events.sawFrame(.parsed, .data));
}

test "H3 conn: event sink observes settings stream frames and priority updates" {
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

    var client_events = EventRecorder{};
    defer client_events.deinit(allocator);
    var server_events = EventRecorder{};
    defer server_events.deinit(allocator);
    client.setEventSink(client_events.sink());
    server.setEventSink(server_events.sink());

    try client.start(&client_transport);
    try server.start(&server_transport);
    try server.pump(&server_transport);
    try client.pump(&client_transport);

    try testing.expect(client_events.sawFrame(.created, .settings));
    try testing.expect(client_events.sawParametersSet());
    try testing.expect(server_events.sawFrame(.parsed, .settings));
    try testing.expect(server_events.sawStreamType(.control));
    try testing.expect(server_events.sawParametersSet());

    var expected_body_frame: [64]u8 = undefined;
    const expected_data_len = (try frame.encodeKnownFrame(.data, "body", &expected_body_frame)).len;
    const request_id = try client.sendRequest(&client_transport, .{
        .authority = "tardigrade.test",
        .path = "/priority",
        .headers = &.{.{ .name = "priority", .value = "u=1, i" }},
        .body = "body",
    });
    try testing.expect(client_events.sawStreamType(.request));
    try testing.expect(client_events.sawFrame(.created, .headers));
    try testing.expect(client_events.sawFrameWithLength(.created, .data, expected_data_len));
    try server.pump(&server_transport);
    try testing.expect(server_events.sawStreamType(.request));
    try testing.expect(server_events.sawFrame(.parsed, .headers));
    try testing.expect(server_events.sawFrameWithLength(.parsed, .data, expected_data_len));

    var payload: [32]u8 = undefined;
    const priority_payload = try priority.encodePayload(.{ .element_id = request_id, .field_value = "u=2" }, &payload);
    var wire: [64]u8 = undefined;
    const priority_frame = try frame.encodeKnownFrame(.priority_update_request, priority_payload, &wire);
    _ = try client_transport.writeStream(client.control_out.?, priority_frame, false);
    try server.pump(&server_transport);
    try testing.expect(server_events.sawFrame(.parsed, .priority_update_request));
    try testing.expect(server_events.sawPriorityUpdated(request_id, 2, false));
}

test "H3 conn: control frame observer reports GOAWAY before semantic rejection" {
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

    var client_events = EventRecorder{};
    defer client_events.deinit(allocator);
    client.setEventSink(client_events.sink());

    try client.start(&client_transport);
    try server.start(&server_transport);
    try client.pump(&client_transport);
    try testing.expect(client.metrics.settings_received);

    var payload: [8]u8 = undefined;
    const payload_len = try varint.encode(1, &payload);
    var wire: [16]u8 = undefined;
    const goaway = try frame.encodeKnownFrame(.goaway, payload[0..payload_len], &wire);
    _ = try server_transport.writeStream(server.control_out.?, goaway, false);

    try testing.expectError(error.ProtocolError, client.pump(&client_transport));
    try testing.expect(client_events.sawGoawayParsed(1));
}

test "H3 conn: SETTINGS frame events preserve wire entries before semantic policy" {
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
    var client_events = EventRecorder{};
    defer client_events.deinit(allocator);
    client.setEventSink(client_events.sink());

    const control = try server_transport.openStream(.uni);
    var settings_entries: [10]frame.Setting = undefined;
    settings_entries[0] = .{ .id = .qpack_blocked_streams, .id_value = 0x07, .value = 0 };
    settings_entries[1] = .{ .id = .enable_connect_protocol, .id_value = 0x08, .value = 0 };
    inline for (0..8) |i| {
        settings_entries[i + 2] = .{ .id = .unknown, .id_value = 0x21 + i, .value = i };
    }
    var payload: [128]u8 = undefined;
    const settings_payload = try frame.encodeSettings(&settings_entries, &payload);
    var wire: [160]u8 = undefined;
    var len: usize = 0;
    len += (try frame.encodeStreamType(.control, wire[len..])).len;
    len += (try frame.encodeKnownFrame(.settings, settings_payload, wire[len..])).len;
    _ = try server_transport.writeStream(control, wire[0..len], false);

    try client.pump(&client_transport);
    try testing.expect(client_events.sawSettingsEntry(0x07, 0));
    try testing.expect(client_events.sawSettingsEntry(0x08, 0));
    try testing.expect(client_events.sawSettingsEntry(0x21, 0));
    try testing.expect(client_events.sawSettingsEntryCountAtLeast(10));
}

test "H3 conn: rejected SETTINGS frame remains observable" {
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
    var client_events = EventRecorder{};
    defer client_events.deinit(allocator);
    client.setEventSink(client_events.sink());

    const control = try server_transport.openStream(.uni);
    var payload: [32]u8 = undefined;
    const settings_payload = try frame.encodeSettings(&.{
        .{ .id = .unknown, .id_value = 0x02, .value = 1 },
        .{ .id = .qpack_blocked_streams, .id_value = 0x07, .value = 0 },
    }, &payload);
    var wire: [64]u8 = undefined;
    var len: usize = 0;
    len += (try frame.encodeStreamType(.control, wire[len..])).len;
    len += (try frame.encodeKnownFrame(.settings, settings_payload, wire[len..])).len;
    _ = try server_transport.writeStream(control, wire[0..len], false);

    try testing.expectError(error.ProtocolError, client.pump(&client_transport));
    try testing.expect(client_events.sawSettingsEntry(0x02, 1));
    try testing.expect(client_events.sawSettingsEntry(0x07, 0));
}

test "H3 conn: unknown request frame is observed as unknown" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var server = H3.init(allocator, .server);
    defer server.deinit();
    var server_events = EventRecorder{};
    defer server_events.deinit(allocator);
    server.setEventSink(server_events.sink());

    const id = try client_transport.openStream(.bidi);
    var wire: [32]u8 = undefined;
    const unknown = try frame.encodeFrame(0x21, "", &wire);
    _ = try client_transport.writeStream(id, unknown, false);

    try server.pump(&server_transport);
    try testing.expect(server_events.sawUnknownFrame(0x21));
    try testing.expect(!server_events.sawFrame(.parsed, .data));
}

test "H3 conn: malformed known frames are not observed as unknown" {
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
    var client_events = EventRecorder{};
    defer client_events.deinit(allocator);
    client.setEventSink(client_events.sink());

    try client.start(&client_transport);
    try server.start(&server_transport);
    try client.pump(&client_transport);

    var wire: [32]u8 = undefined;
    const malformed_goaway = try frame.encodeKnownFrame(.goaway, &.{}, &wire);
    _ = try server_transport.writeStream(server.control_out.?, malformed_goaway, false);

    try testing.expectError(error.ProtocolError, client.pump(&client_transport));
    try testing.expect(client_events.sawMalformedFrame(.goaway));
    try testing.expect(!client_events.sawUnknownFrame(@intFromEnum(frame.FrameType.goaway)));
}

test "H3 conn: incomplete PUSH_PROMISE is preserved as malformed known frame" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var server = H3.init(allocator, .server);
    defer server.deinit();
    var server_events = EventRecorder{};
    defer server_events.deinit(allocator);
    server.setEventSink(server_events.sink());

    const id = try client_transport.openStream(.bidi);
    var payload: [8]u8 = undefined;
    const payload_len = try varint.encode(1, &payload);
    var wire: [32]u8 = undefined;
    const push_promise = try frame.encodeKnownFrame(.push_promise, payload[0..payload_len], &wire);
    _ = try client_transport.writeStream(id, push_promise, false);

    try testing.expectError(error.ProtocolError, server.pump(&server_transport));
    try testing.expect(server_events.sawMalformedFrame(.push_promise));
    try testing.expect(!server_events.sawUnknownFrame(@intFromEnum(frame.FrameType.push_promise)));
}

test "H3 conn: valid PUSH_PROMISE is observed as known decoded frame" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var server = H3.init(allocator, .server);
    defer server.deinit();
    var server_events = EventRecorder{};
    defer server_events.deinit(allocator);
    server.setEventSink(server_events.sink());

    const id = try client_transport.openStream(.bidi);
    var payload: [128]u8 = undefined;
    var payload_len = try varint.encode(1, &payload);
    const fields = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
    };
    const encoded_fields = try qpack.encode(&fields, payload[payload_len..]);
    payload_len += encoded_fields.len;
    var wire: [160]u8 = undefined;
    const push_promise = try frame.encodeKnownFrame(.push_promise, payload[0..payload_len], &wire);
    _ = try client_transport.writeStream(id, push_promise, false);

    try testing.expectError(error.ProtocolError, server.pump(&server_transport));
    try testing.expect(server_events.sawFrame(.parsed, .push_promise));
    try testing.expect(!server_events.sawMalformedFrame(.push_promise));
    try testing.expect(!server_events.sawUnknownFrame(@intFromEnum(frame.FrameType.push_promise)));
}

test "H3 conn: frame_created is emitted when encoded request write fails" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;
    client_transport.fail_writes_after = 0;

    const H3 = Conn(MockTransport);
    var client = H3.init(allocator, .client);
    defer client.deinit();
    var client_events = EventRecorder{};
    defer client_events.deinit(allocator);
    client.setEventSink(client_events.sink());

    try testing.expectError(error.StreamBackpressure, client.sendRequest(&client_transport, .{
        .authority = "tardigrade.test",
        .path = "/blocked",
        .body = "body",
    }));
    try testing.expect(client_events.sawStreamType(.request));
    try testing.expect(client_events.sawFrame(.created, .headers));
    try testing.expect(client_events.sawFrame(.created, .data));
}

test "H3 conn: sendGoaway writes the selected request boundary on the control stream" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var server = H3.init(allocator, .server);
    defer server.deinit();

    try server.start(&server_transport);
    try server.sendGoaway(&server_transport, 4);

    const control_id = server.control_out.?;
    const stream = client_transport.streams.get(control_id).?;
    const bytes = stream.data.items;
    const stream_type = try frame.decodeStreamType(bytes);
    try testing.expectEqual(frame.StreamType.control, stream_type.typ);

    const settings = try frame.decodeFrame(bytes[stream_type.len..]);
    try testing.expectEqual(frame.FrameType.settings, settings.typ);

    const goaway = try frame.decodeFrame(bytes[stream_type.len + settings.len ..]);
    try testing.expectEqual(frame.FrameType.goaway, goaway.typ);
    const boundary = try varint.decode(goaway.payload);
    try testing.expectEqual(@as(u64, 4), boundary.value);
}

test "H3 conn: inbound GOAWAY is monotonic and stops new local requests" {
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
    try client.pump(&client_transport);

    var goaway_buf: [16]u8 = undefined;
    const goaway_4 = try encodeGoawayFrameForTest(4, &goaway_buf);
    _ = try server_transport.writeStream(server.control_out.?, goaway_4, false);
    try client.pump(&client_transport);
    try testing.expectEqual(@as(?u64, 4), client.peer_goaway_id);
    try testing.expectEqual(@as(u64, 1), client.metrics.goaway_received);

    try testing.expectError(error.GoawayReceived, client.sendRequest(&client_transport, .{ .authority = "tardigrade.test", .path = "/rejected" }));
    try testing.expectEqual(@as(?ErrorCode, null), client.close_code);
    try testing.expectEqual(@as(u64, 0), client_transport.next_bidi);
}

test "H3 conn: inbound GOAWAY cannot increase the advertised boundary" {
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
    try client.pump(&client_transport);

    var goaway_buf: [16]u8 = undefined;
    const goaway_4 = try encodeGoawayFrameForTest(4, &goaway_buf);
    _ = try server_transport.writeStream(server.control_out.?, goaway_4, false);
    try client.pump(&client_transport);

    const goaway_8 = try encodeGoawayFrameForTest(8, &goaway_buf);
    _ = try server_transport.writeStream(server.control_out.?, goaway_8, false);
    try testing.expectError(error.ProtocolError, client.pump(&client_transport));
    try testing.expectEqual(ErrorCode.id_error.wire(), client.closeCode());
}

test "H3 conn: sent GOAWAY rejects boundary and later peer requests without closing" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var server = H3.init(allocator, .server);
    defer server.deinit();

    server.local_goaway_id = 0;
    const first_rejected = try client_transport.openStream(.bidi);
    try testing.expectEqual(@as(u64, 0), first_rejected);
    _ = try client_transport.writeStream(first_rejected, requestHeadersBytes()[0..], true);
    const second_rejected = try client_transport.openStream(.bidi);
    try testing.expectEqual(@as(u64, 4), second_rejected);
    _ = try client_transport.writeStream(second_rejected, requestHeadersBytes()[0..], true);

    try server.pump(&server_transport);
    try testing.expectEqual(@as(u32, 0), server.requests.count());
    try testing.expectEqual(@as(?ErrorCode, null), server.close_code);
    try testing.expect((try server_transport.stream(first_rejected)).reset);
    try testing.expect((try server_transport.stream(second_rejected)).reset);
    // #546: both peer request streams landed at/above `local_goaway_id`
    // directly during `pump()`'s admission check, never becoming an
    // `IncomingRequest` — this is the only place that observes them, so the
    // runtime-level `h3_drain_request_rejections` fold depends on this count.
    try testing.expectEqual(@as(u64, 2), server.metrics.goaway_request_rejections);
}

test "H3 conn: polls completed requests by urgency and reports priority" {
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

    _ = try client.sendRequest(&client_transport, .{
        .authority = "tardigrade.test",
        .path = "/slow",
        .headers = &.{.{ .name = "priority", .value = "u=6" }},
    });
    _ = try client.sendRequest(&client_transport, .{
        .authority = "tardigrade.test",
        .path = "/urgent",
        .headers = &.{.{ .name = "priority", .value = "u=1, i" }},
    });

    try server.pump(&server_transport);
    const first = (try server.pollRequest()).?;
    try testing.expectEqualStrings("/urgent", first.exchange.request.path);
    try testing.expectEqual(priority.Priority{ .urgency = 1, .incremental = true }, first.priority);
    server.finishRequest(first.stream_id);

    const second = (try server.pollRequest()).?;
    try testing.expectEqualStrings("/slow", second.exchange.request.path);
    try testing.expectEqual(priority.Priority{ .urgency = 6, .incremental = false }, second.priority);
    server.finishRequest(second.stream_id);
}

test "H3 conn: PRIORITY_UPDATE on control stream updates request priority" {
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

    const request_id = try client.sendRequest(&client_transport, .{
        .authority = "tardigrade.test",
        .path = "/reprioritized",
        .headers = &.{.{ .name = "priority", .value = "u=7" }},
    });
    try server.pump(&server_transport);

    var update_buf: [64]u8 = undefined;
    const update = try priority.encodeFrame(.request, .{ .element_id = request_id, .field_value = "u=0, i" }, &update_buf);
    _ = try client_transport.writeStream(client.control_out.?, update, false);

    try server.pump(&server_transport);
    const incoming = (try server.pollRequest()).?;
    try testing.expectEqualStrings("/reprioritized", incoming.exchange.request.path);
    try testing.expectEqual(priority.Priority{ .urgency = 0, .incremental = true }, incoming.priority);
    try testing.expectEqual(@as(u64, 1), server.metrics.priority_updates_received);
    server.finishRequest(incoming.stream_id);
}

test "H3 conn: client rejects server-sent PRIORITY_UPDATE" {
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

    var update_buf: [64]u8 = undefined;
    const update = try priority.encodeFrame(.request, .{ .element_id = 0, .field_value = "u=0" }, &update_buf);
    _ = try server_transport.writeStream(server.control_out.?, update, false);

    try testing.expectError(error.ProtocolError, client.pump(&client_transport));
    try testing.expectEqual(ErrorCode.frame_unexpected.wire(), client.closeCode());
}

test "H3 conn: invalid PRIORITY_UPDATE targets close with H3_ID_ERROR" {
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

    var update_buf: [64]u8 = undefined;
    const bad_request = try priority.encodeFrame(.request, .{ .element_id = 1, .field_value = "u=0" }, &update_buf);
    _ = try client_transport.writeStream(client.control_out.?, bad_request, false);
    try testing.expectError(error.ProtocolError, server.pump(&server_transport));
    try testing.expectEqual(ErrorCode.id_error.wire(), server.closeCode());

    var client_transport2 = MockTransport.init(allocator, true);
    defer client_transport2.deinit();
    var server_transport2 = MockTransport.init(allocator, false);
    defer server_transport2.deinit();
    client_transport2.peer = &server_transport2;
    server_transport2.peer = &client_transport2;
    var client2 = H3.init(allocator, .client);
    defer client2.deinit();
    var server2 = H3.init(allocator, .server);
    defer server2.deinit();

    try client2.start(&client_transport2);
    try server2.start(&server_transport2);
    try server2.pump(&server_transport2);
    try client2.pump(&client_transport2);

    const push_update = try priority.encodeFrame(.push, .{ .element_id = 0, .field_value = "u=0" }, &update_buf);
    _ = try client_transport2.writeStream(client2.control_out.?, push_update, false);
    try testing.expectError(error.ProtocolError, server2.pump(&server_transport2));
    try testing.expectEqual(ErrorCode.id_error.wire(), server2.closeCode());
}

test "H3 conn: PRIORITY_UPDATE before request stream is retained" {
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

    var update_buf: [64]u8 = undefined;
    const update1 = try priority.encodeFrame(.request, .{ .element_id = 0, .field_value = "u=6" }, &update_buf);
    _ = try client_transport.writeStream(client.control_out.?, update1, false);
    const update2 = try priority.encodeFrame(.request, .{ .element_id = 0, .field_value = "u=0, i" }, &update_buf);
    _ = try client_transport.writeStream(client.control_out.?, update2, false);
    try server.pump(&server_transport);
    try testing.expectEqual(@as(u64, 2), server.metrics.priority_updates_buffered);

    _ = try client.sendRequest(&client_transport, .{
        .authority = "tardigrade.test",
        .path = "/raced",
        .headers = &.{.{ .name = "priority", .value = "u=7" }},
    });
    try server.pump(&server_transport);

    const incoming = (try server.pollRequest()).?;
    try testing.expectEqualStrings("/raced", incoming.exchange.request.path);
    try testing.expectEqual(priority.Priority{ .urgency = 0, .incremental = true }, incoming.priority);
    server.finishRequest(incoming.stream_id);
}

test "H3 conn: PRIORITY_UPDATE overrides later decoded request priority header" {
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

    const request_id = try client_transport.openStream(.bidi);
    var qpack_buf: [512]u8 = undefined;
    const block = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
        .{ .name = ":path", .value = "/fragmented" },
        .{ .name = "priority", .value = "u=7" },
    }, &qpack_buf);
    var request_buf: [1024]u8 = undefined;
    const request = try frame.encodeKnownFrame(.headers, block, &request_buf);
    _ = try client_transport.writeStream(request_id, request[0..1], false);
    try server.pump(&server_transport);

    var update_buf: [64]u8 = undefined;
    const update = try priority.encodeFrame(.request, .{ .element_id = request_id, .field_value = "u=0, i" }, &update_buf);
    _ = try client_transport.writeStream(client.control_out.?, update, false);
    try server.pump(&server_transport);

    _ = try client_transport.writeStream(request_id, request[1..2], false);
    try server.pump(&server_transport);

    _ = try client_transport.writeStream(request_id, request[2..], true);
    try server.pump(&server_transport);

    const incoming = (try server.pollRequest()).?;
    try testing.expectEqualStrings("/fragmented", incoming.exchange.request.path);
    try testing.expectEqual(priority.Priority{ .urgency = 0, .incremental = true }, incoming.priority);
    server.finishRequest(incoming.stream_id);
}

test "H3 conn: late PRIORITY_UPDATE updates active response transport hint" {
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

    const request_id = try client.sendRequest(&client_transport, .{
        .authority = "tardigrade.test",
        .path = "/active",
        .headers = &.{.{ .name = "priority", .value = "u=7" }},
    });
    try server.pump(&server_transport);
    const incoming = (try server.pollRequest()).?;
    try server.sendResponse(&server_transport, incoming.stream_id, 200, &.{}, "large-ish response body");
    try testing.expectEqual(@as(?priority.Priority, null), server_transport.scheduling_hints.get(request_id));

    var update_buf: [64]u8 = undefined;
    const update = try priority.encodeFrame(.request, .{ .element_id = request_id, .field_value = "u=0" }, &update_buf);
    _ = try client_transport.writeStream(client.control_out.?, update, false);
    try server.pump(&server_transport);

    try testing.expectEqual(priority.Priority{ .urgency = 0, .incremental = false }, server_transport.scheduling_hints.get(request_id).?);
    try testing.expectEqual(@as(usize, 0), server.pending_priority_updates.count());
}

test "H3 conn: request stream reset releases request state" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var server = H3.init(allocator, .server);
    defer server.deinit();

    const request_id = try client_transport.openStream(.bidi);
    _ = try client_transport.writeStream(request_id, requestHeadersBytes()[0..1], false);
    try server.pump(&server_transport);
    try testing.expectEqual(@as(u32, 1), server.requests.count());

    try server_transport.resetStreamForTest(request_id);
    try server.pump(&server_transport);
    try testing.expectEqual(@as(u32, 0), server.requests.count());
}

test "H3 conn: request stream reset cleanup handles default concurrency" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var server = H3.init(allocator, .server);
    defer server.deinit();

    var ids: [100]u64 = undefined;
    for (&ids) |*id| {
        id.* = try client_transport.openStream(.bidi);
        _ = try client_transport.writeStream(id.*, requestHeadersBytes()[0..1], false);
    }
    try server.pump(&server_transport);
    try testing.expectEqual(@as(u32, ids.len), server.requests.count());

    for (ids) |id| try server_transport.resetStreamForTest(id);
    try server.pump(&server_transport);
    try testing.expectEqual(@as(u32, 0), server.requests.count());
    try testing.expectEqual(@as(?ErrorCode, null), server.close_code);
}

test "fuzz: H3 connection state command sequences preserve critical stream and request invariants" {
    try testing.fuzz({}, fuzzH3ConnStateCommands, .{ .corpus = &.{
        "",
        "\x00\x07",
        "\x00\x01\x02\x03",
        "\x04\x00\x05\x00",
        "\x06\x07\x08\x09",
        "\x0a\x0b\x0c\x0d",
        "\x0e\x0f\x10\x11",
    } });
}

fn fuzzH3ConnStateCommands(_: void, smith: *testing.Smith) !void {
    var input: [192]u8 = undefined;
    const len = smith.slice(&input);
    try runH3ConnStateCommands(input[0..len], .server);
    try runH3ConnStateCommands(input[0..len], .client);
}

fn runH3ConnStateCommands(input: []const u8, role: Role) !void {
    const allocator = testing.allocator;
    var peer_transport = MockTransport.init(allocator, role == .server);
    defer peer_transport.deinit();
    var local_transport = MockTransport.init(allocator, role == .client);
    defer local_transport.deinit();
    peer_transport.peer = &local_transport;
    local_transport.peer = &peer_transport;

    const H3 = Conn(MockTransport);
    var conn = H3.init(allocator, role);
    defer conn.deinit();

    var peer_control: ?u64 = null;
    var peer_qpack_encoder: ?u64 = null;
    var peer_qpack_decoder: ?u64 = null;
    var peer_request: ?u64 = null;
    var pos: usize = 0;
    while (pos < input.len) {
        const op = input[pos];
        pos += 1;
        const before_close = conn.close_code;
        const before_settings = conn.peer_control_view.saw_settings;
        const before_requests = conn.requests.count();
        var expected_close: ?ErrorCode = null;

        const result = switch (op % 25) {
            0 => blk: {
                try writePeerUni(&peer_transport, .control, validSettingsBytes()[0..], false, &peer_control);
                break :blk conn.pump(&local_transport);
            },
            1 => blk: {
                try writePeerUni(&peer_transport, .qpack_encoder, "", false, &peer_qpack_encoder);
                break :blk conn.pump(&local_transport);
            },
            2 => blk: {
                try writePeerUni(&peer_transport, .qpack_decoder, "", false, &peer_qpack_decoder);
                break :blk conn.pump(&local_transport);
            },
            3 => blk: {
                const id = try peer_transport.openStream(.uni);
                var bytes: [16]u8 = undefined;
                const typ_len = try varint.encode(0x21, &bytes);
                _ = try peer_transport.writeStream(id, bytes[0..typ_len], false);
                break :blk conn.pump(&local_transport);
            },
            4 => blk: {
                if (peer_control == null and before_close == null) {
                    try writePeerUni(&peer_transport, .control, validSettingsBytes()[0..], false, &peer_control);
                    try conn.pump(&local_transport);
                }
                expected_close = .stream_creation_error;
                var duplicate: ?u64 = null;
                try writePeerUni(&peer_transport, .control, validSettingsBytes()[0..], false, &duplicate);
                break :blk conn.pump(&local_transport);
            },
            5 => blk: {
                expected_close = if (before_settings) .frame_unexpected else .missing_settings;
                try writePeerUni(&peer_transport, .control, forbiddenControlDataBytes()[0..], false, &peer_control);
                break :blk conn.pump(&local_transport);
            },
            6 => blk: {
                expected_close = .frame_unexpected;
                try writePeerUni(&peer_transport, .control, duplicateSettingsBytes()[0..], false, &peer_control);
                break :blk conn.pump(&local_transport);
            },
            7 => blk: {
                if (peer_control == null and before_close == null) {
                    try writePeerUni(&peer_transport, .control, validSettingsBytes()[0..], false, &peer_control);
                    try conn.pump(&local_transport);
                }
                expected_close = .closed_critical_stream;
                if (peer_control) |id| _ = try peer_transport.writeStream(id, "", true);
                break :blk conn.pump(&local_transport);
            },
            8 => blk: {
                expected_close = .closed_critical_stream;
                try writePeerUni(&peer_transport, .qpack_encoder, "", true, &peer_qpack_encoder);
                break :blk conn.pump(&local_transport);
            },
            9 => blk: {
                if (peer_control == null and before_close == null) {
                    try writePeerUni(&peer_transport, .control, validSettingsBytes()[0..], false, &peer_control);
                    try conn.pump(&local_transport);
                }
                expected_close = .closed_critical_stream;
                if (peer_control) |id| try local_transport.resetStreamForTest(id);
                break :blk conn.pump(&local_transport);
            },
            10 => blk: {
                expected_close = if (role == .client) .stream_creation_error else .message_error;
                if (role == .server) {
                    const id = try peer_transport.openStream(.bidi);
                    peer_request = id;
                    _ = try peer_transport.writeStream(id, dataFrameBytes()[0..], false);
                } else {
                    _ = try peer_transport.openStream(.bidi);
                }
                break :blk conn.pump(&local_transport);
            },
            11 => blk: {
                if (role == .server) {
                    const id = peer_request orelse try peer_transport.openStream(.bidi);
                    peer_request = id;
                    _ = try peer_transport.writeStream(id, requestHeadersBytes()[0..], false);
                }
                break :blk conn.pump(&local_transport);
            },
            12 => blk: {
                if (role == .server) {
                    const id = peer_request orelse try peer_transport.openStream(.bidi);
                    peer_request = id;
                    _ = try peer_transport.writeStream(id, requestHeadersBytes()[0..], false);
                    _ = try peer_transport.writeStream(id, dataFrameBytes()[0..], true);
                }
                break :blk conn.pump(&local_transport);
            },
            13 => blk: {
                expected_close = if (role == .server) .message_error else null;
                if (role == .server) {
                    const id = peer_request orelse try peer_transport.openStream(.bidi);
                    peer_request = id;
                    _ = try peer_transport.writeStream(id, duplicateRequestHeadersBytes()[0..], false);
                }
                break :blk conn.pump(&local_transport);
            },
            14 => blk: {
                expected_close = if (role == .server) .message_error else null;
                if (role == .server) {
                    const id = peer_request orelse try peer_transport.openStream(.bidi);
                    peer_request = id;
                    _ = try peer_transport.writeStream(id, requestWithTrailersThenDataBytes()[0..], false);
                }
                break :blk conn.pump(&local_transport);
            },
            15 => blk: {
                if (role == .server) {
                    const id = peer_request orelse try peer_transport.openStream(.bidi);
                    peer_request = id;
                    const s = try local_transport.stream(id);
                    s.fin = true;
                }
                break :blk conn.pump(&local_transport);
            },
            16 => blk: {
                expected_close = if (before_settings) null else .missing_settings;
                try writePeerUni(&peer_transport, .control, goawayBytes()[0..], false, &peer_control);
                break :blk conn.pump(&local_transport);
            },
            17 => blk: {
                expected_close = .stream_creation_error;
                var duplicate: ?u64 = null;
                try writePeerUni(&peer_transport, .qpack_encoder, "", false, &peer_qpack_encoder);
                try writePeerUni(&peer_transport, .qpack_encoder, "", false, &duplicate);
                break :blk conn.pump(&local_transport);
            },
            18 => blk: {
                expected_close = .stream_creation_error;
                var duplicate: ?u64 = null;
                try writePeerUni(&peer_transport, .qpack_decoder, "", false, &peer_qpack_decoder);
                try writePeerUni(&peer_transport, .qpack_decoder, "", false, &duplicate);
                break :blk conn.pump(&local_transport);
            },
            19 => blk: {
                expected_close = .closed_critical_stream;
                try writePeerUni(&peer_transport, .qpack_decoder, "", true, &peer_qpack_decoder);
                break :blk conn.pump(&local_transport);
            },
            20 => blk: {
                if (peer_qpack_encoder == null and before_close == null) {
                    try writePeerUni(&peer_transport, .qpack_encoder, "", false, &peer_qpack_encoder);
                    try conn.pump(&local_transport);
                }
                expected_close = .closed_critical_stream;
                if (peer_qpack_encoder) |id| try local_transport.resetStreamForTest(id);
                break :blk conn.pump(&local_transport);
            },
            21 => blk: {
                if (role == .server) {
                    const id = peer_request orelse try peer_transport.openStream(.bidi);
                    peer_request = id;
                    try local_transport.resetStreamForTest(id);
                }
                break :blk conn.pump(&local_transport);
            },
            22 => blk: {
                expected_close = if (before_settings) .id_error else .missing_settings;
                try writePeerUni(&peer_transport, .control, goawayBytes()[0..], false, &peer_control);
                try writePeerUni(&peer_transport, .control, largerGoawayBytes()[0..], false, &peer_control);
                break :blk conn.pump(&local_transport);
            },
            23 => blk: {
                expected_close = if (!before_settings) .missing_settings else if (role == .client) .id_error else null;
                try writePeerUni(&peer_transport, .control, invalidClientGoawayBytes()[0..], false, &peer_control);
                break :blk conn.pump(&local_transport);
            },
            else => blk: {
                if (peer_qpack_decoder == null and before_close == null) {
                    try writePeerUni(&peer_transport, .qpack_decoder, "", false, &peer_qpack_decoder);
                    try conn.pump(&local_transport);
                }
                expected_close = .closed_critical_stream;
                if (peer_qpack_decoder) |id| try local_transport.resetStreamForTest(id);
                break :blk conn.pump(&local_transport);
            },
        };

        if (result) |_| {
            if (expected_close) |code| if (before_close == null) {
                try testing.expect(conn.close_code != null);
                try testing.expectEqual(code.wire(), conn.closeCode());
            };
            try expectH3ConnInvariants(&conn, role, before_settings, before_requests);
        } else |err| {
            try testing.expect(err == error.ProtocolError or err == error.OutOfMemory);
            try testing.expect(conn.close_code != null);
            if (before_close) |code| try testing.expectEqual(code, conn.close_code.?);
            if (expected_close) |code| if (before_close == null) try testing.expectEqual(code.wire(), conn.closeCode());
        }
    }
}

fn writePeerUni(peer_transport: *MockTransport, typ: frame.StreamType, payload_after_type: []const u8, fin: bool, slot: *?u64) !void {
    const id = slot.* orelse try peer_transport.openStream(.uni);
    slot.* = id;
    var prefix: [8]u8 = undefined;
    const stream_type = try frame.encodeStreamType(typ, &prefix);
    if (payload_after_type.len == 0 and typ != .control) {
        _ = try peer_transport.writeStream(id, stream_type, fin);
        return;
    }
    if (peer_transport.peer) |target| {
        const s = try target.stream(id);
        if (s.data.items.len == 0) try s.data.appendSlice(target.allocator, stream_type);
    }
    _ = try peer_transport.writeStream(id, payload_after_type, fin);
}

fn validSettingsBytes() [2]u8 {
    return .{ 0x04, 0x00 };
}

fn forbiddenControlDataBytes() [2]u8 {
    return .{ 0x00, 0x00 };
}

fn duplicateSettingsBytes() [4]u8 {
    return .{ 0x04, 0x00, 0x04, 0x00 };
}

fn goawayBytes() [3]u8 {
    return .{ 0x07, 0x01, 0x04 };
}

fn encodeGoawayFrameForTest(id: u64, out: []u8) ![]u8 {
    var payload: [8]u8 = undefined;
    const payload_len = try varint.encode(id, &payload);
    return frame.encodeKnownFrame(.goaway, payload[0..payload_len], out);
}

fn largerGoawayBytes() [3]u8 {
    return .{ 0x07, 0x01, 0x08 };
}

fn invalidClientGoawayBytes() [3]u8 {
    return .{ 0x07, 0x01, 0x01 };
}

fn dataFrameBytes() [5]u8 {
    return .{ 0x00, 0x03, 'b', 'o', 'd' };
}

fn requestHeadersBytes() [9]u8 {
    return .{ 0x01, 0x07, 0x00, 0x00, 0xd1, 0xd7, 0x50, 0x00, 0xc1 };
}

fn duplicateRequestHeadersBytes() [18]u8 {
    const h = requestHeadersBytes();
    return h ++ h;
}

fn requestWithTrailersThenDataBytes() [23]u8 {
    const h = requestHeadersBytes();
    const d = dataFrameBytes();
    return h ++ h ++ d;
}

test "H3 conn: pump stops accepting and tracking streams once already closed" {
    // Found 2026-09-02 by the #675 campaign (test-quic --fuzz, "H3
    // connection state command sequences" target): pump() had no guard
    // against self.close_code already being set, so a peer stream opened
    // after the connection failed was still accepted and tracked into
    // conn.requests. Pins that a request opened strictly after close is
    // never tracked and the sticky close_code is not disturbed.
    const allocator = testing.allocator;
    var peer_transport = MockTransport.init(allocator, true);
    defer peer_transport.deinit();
    var local_transport = MockTransport.init(allocator, false);
    defer local_transport.deinit();
    peer_transport.peer = &local_transport;
    local_transport.peer = &peer_transport;

    const H3 = Conn(MockTransport);
    var conn = H3.init(allocator, .server);
    defer conn.deinit();

    var peer_control: ?u64 = null;
    try writePeerUni(&peer_transport, .control, duplicateSettingsBytes()[0..], false, &peer_control);
    try testing.expectError(error.ProtocolError, conn.pump(&local_transport));
    try testing.expectEqual(ErrorCode.frame_unexpected, conn.close_code.?);

    const id = try peer_transport.openStream(.bidi);
    _ = try peer_transport.writeStream(id, requestHeadersBytes()[0..], false);
    try conn.pump(&local_transport);

    try testing.expectEqual(ErrorCode.frame_unexpected, conn.close_code.?);
    try testing.expectEqual(@as(u32, 0), conn.requests.count());
}

test "H3 conn: server rejects more data on a request stream after its FIN" {
    // Found 2026-09-02 by the #675 campaign, same target: once a request
    // reached request.finished (FIN observed), pumpRequests() permanently
    // skipped reading its stream, so a second HEADERS frame sent after FIN
    // (RFC 9114 SS4.1) was silently dropped instead of failing the
    // connection with message_error.
    const allocator = testing.allocator;
    var peer_transport = MockTransport.init(allocator, true);
    defer peer_transport.deinit();
    var local_transport = MockTransport.init(allocator, false);
    defer local_transport.deinit();
    peer_transport.peer = &local_transport;
    local_transport.peer = &peer_transport;

    const H3 = Conn(MockTransport);
    var conn = H3.init(allocator, .server);
    defer conn.deinit();

    const id = try peer_transport.openStream(.bidi);
    _ = try peer_transport.writeStream(id, requestHeadersBytes()[0..], false);
    _ = try peer_transport.writeStream(id, dataFrameBytes()[0..], true);
    try conn.pump(&local_transport);
    try testing.expectEqual(@as(?ErrorCode, null), conn.close_code);
    try testing.expectEqual(@as(u32, 1), conn.requests.count());

    _ = try peer_transport.writeStream(id, requestHeadersBytes()[0..], false);
    try testing.expectError(error.ProtocolError, conn.pump(&local_transport));
    try testing.expectEqual(ErrorCode.message_error, conn.close_code.?);
}

fn expectH3ConnInvariants(conn: anytype, role: Role, before_settings: bool, before_requests: u32) !void {
    if (conn.peer_control) |id| {
        try testing.expect((id & 0x2) != 0);
    }
    if (conn.peer_qpack_encoder) |id| {
        try testing.expect((id & 0x2) != 0);
    }
    if (conn.peer_qpack_decoder) |id| {
        try testing.expect((id & 0x2) != 0);
    }
    try testing.expect(conn.pending_uni.count() <= 32);
    _ = before_requests;
    try testing.expect(conn.requests.count() <= 32 or role == .client);
    if (before_settings) try testing.expect(conn.peer_control_view.saw_settings);
    if (conn.peer_control_view.saw_settings) try testing.expect(conn.metrics.settings_received);

    if (role == .server) {
        var it = conn.requests.iterator();
        while (it.next()) |entry| {
            const request = entry.value_ptr.*;
            try testing.expect(isClientRequestStream(entry.key_ptr.*));
            if (request.stream.saw_data) try testing.expect(request.stream.saw_headers);
            try testing.expect(!request.stream.finished or request.finished);
        }
    }
}

test "H3 conn: PRIORITY_UPDATE on request stream closes with frame unexpected" {
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

    const request_id = try client_transport.openStream(.bidi);
    var update_buf: [64]u8 = undefined;
    const update = try priority.encodeFrame(.request, .{ .element_id = request_id, .field_value = "u=0" }, &update_buf);
    _ = try client_transport.writeStream(request_id, update, true);

    try testing.expectError(error.ProtocolError, server.pump(&server_transport));
    try testing.expectEqual(ErrorCode.frame_unexpected.wire(), server.closeCode());
}

test "H3 conn: PRIORITY_UPDATE on response stream closes with frame unexpected" {
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

    const request_id = try client.sendRequest(&client_transport, .{
        .authority = "tardigrade.test",
        .path = "/bad-response-frame",
    });
    try server.pump(&server_transport);
    _ = (try server.pollRequest()).?;

    var update_buf: [64]u8 = undefined;
    const update = try priority.encodeFrame(.request, .{ .element_id = request_id, .field_value = "u=0" }, &update_buf);
    _ = try server_transport.writeStream(request_id, update, true);
    try testing.expectError(error.ProtocolError, client.pump(&client_transport));
    try testing.expectEqual(ErrorCode.frame_unexpected.wire(), client.closeCode());
}

test "H3 conn: priority parse metrics cover headers and updates" {
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

    const request_id = try client.sendRequest(&client_transport, .{
        .authority = "tardigrade.test",
        .path = "/invalid",
        .headers = &.{.{ .name = "priority", .value = "u=8" }},
    });
    var malformed_buf: [64]u8 = undefined;
    const malformed_update = try priority.encodeFrame(.request, .{ .element_id = request_id, .field_value = "=bad" }, &malformed_buf);
    _ = try client_transport.writeStream(client.control_out.?, malformed_update, false);

    try server.pump(&server_transport);
    try testing.expectEqual(@as(u64, 1), server.metrics.priority_updates_received);
    try testing.expectEqual(@as(u64, 1), server.metrics.priority_parse_errors);
    try testing.expectEqual(@as(u64, 1), server.metrics.priority_invalid_parameters);
}

test "H3 conn: start emits default SETTINGS" {
    const allocator = testing.allocator;
    var client_transport = MockTransport.init(allocator, true);
    defer client_transport.deinit();
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();
    client_transport.peer = &server_transport;
    server_transport.peer = &client_transport;

    const H3 = Conn(MockTransport);
    var server = H3.initWithSettings(allocator, .server, .{});
    defer server.deinit();

    try server.start(&server_transport);
    try testing.expectEqual(@as(?u64, 3), server.control_out);
    const stream = client_transport.streams.get(3) orelse return error.TestExpectedEqual;
    var control = frame.ControlStream{};
    defer control.deinit(allocator);
    try testing.expectEqual(stream.data.items.len, try control.ingest(allocator, stream.data.items));
    try testing.expect(control.saw_settings);
    try testing.expectEqual(frame.Settings{}, control.settings);
}

test "H3 conn: start rejects unsupported qpack_max_table_capacity" {
    const allocator = testing.allocator;
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();

    const H3 = Conn(MockTransport);
    var server = H3.initWithSettings(allocator, .server, .{ .qpack_max_table_capacity = 1 });
    defer server.deinit();

    try testing.expectError(error.UnsupportedH3Setting, server.start(&server_transport));
}

test "H3 conn: start rejects unsupported qpack_blocked_streams" {
    const allocator = testing.allocator;
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();

    const H3 = Conn(MockTransport);
    var server = H3.initWithSettings(allocator, .server, .{ .qpack_blocked_streams = 1 });
    defer server.deinit();

    try testing.expectError(error.UnsupportedH3Setting, server.start(&server_transport));
}

test "H3 conn: start rejects unsupported enable_connect_protocol" {
    const allocator = testing.allocator;
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();

    const H3 = Conn(MockTransport);
    var server = H3.initWithSettings(allocator, .server, .{ .enable_connect_protocol = true });
    defer server.deinit();

    try testing.expectError(error.UnsupportedH3Setting, server.start(&server_transport));
}

test "H3 conn: start rejects unsupported h3_datagram" {
    const allocator = testing.allocator;
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();

    const H3 = Conn(MockTransport);
    var server = H3.initWithSettings(allocator, .server, .{ .h3_datagram = true });
    defer server.deinit();

    try testing.expectError(error.UnsupportedH3Setting, server.start(&server_transport));
}

test "H3 conn: start rejects unsupported max_field_section_size" {
    const allocator = testing.allocator;
    var server_transport = MockTransport.init(allocator, false);
    defer server_transport.deinit();

    const H3 = Conn(MockTransport);
    var server = H3.initWithSettings(allocator, .server, .{ .max_field_section_size = 1024 });
    defer server.deinit();

    try testing.expectError(error.UnsupportedH3Setting, server.start(&server_transport));
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

    const control_id = try server_transport.openStream(.uni);
    var settings_payload_buf: [64]u8 = undefined;
    const settings_payload = try frame.encodeSettings(&.{
        .{ .id = .qpack_blocked_streams, .id_value = 0x07, .value = 3 },
        .{ .id = .max_field_section_size, .id_value = 0x06, .value = 8192 },
        .{ .id = .enable_connect_protocol, .id_value = 0x08, .value = 1 },
    }, &settings_payload_buf);
    var control_buf: [128]u8 = undefined;
    var control_len: usize = 0;
    control_len += (try frame.encodeStreamType(.control, control_buf[control_len..])).len;
    control_len += (try frame.encodeKnownFrame(.settings, settings_payload, control_buf[control_len..])).len;
    _ = try server_transport.writeStream(control_id, control_buf[0..control_len], false);

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
