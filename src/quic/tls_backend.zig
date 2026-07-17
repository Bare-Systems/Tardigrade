//! Thin QUIC profile for the TLS-owned TLS 1.3 engine.
//!
//! TLS handshake processing, key schedule, certificate verification, Finished
//! handling, and zeroization live in `tls_core.tls13_backend`. This module owns
//! only RFC 9000 transport-parameter/CID binding, QUIC epoch translation, and
//! construction of the shared engine with the QUIC extension profile.

const std = @import("std");
const config = @import("config.zig");
const varint = @import("quic_varint");
const tls_adapter = @import("tls_adapter.zig");
const tls_handshake = @import("tls_handshake.zig");
const tls_core = @import("tls_core");

const shared = tls_core.tls13_backend;
const RecordSink = tls_core.encrypted_stream.RecordTransport.EventSink;
const HandshakeError = tls_handshake.HandshakeError;
const EventSink = tls_handshake.EventSink;
const EncryptionLevel = tls_adapter.EncryptionLevel;

pub const Identity = shared.Identity;
pub const Trust = shared.Trust;
pub const Entropy = shared.Entropy;
pub const KeySchedule = shared.KeySchedule;
pub const hash_len = shared.hash_len;
pub const max_message_len = shared.max_message_len;
pub const max_certificate_len = shared.max_certificate_len;
pub const testdata = shared.testdata;

const ext_quic_transport_parameters: u16 = 57;
const tp_max_idle_timeout: u64 = 0x01;
const tp_max_udp_payload_size: u64 = 0x03;
const tp_initial_max_data: u64 = 0x04;
const tp_initial_max_stream_data_bidi_local: u64 = 0x05;
const tp_initial_max_stream_data_bidi_remote: u64 = 0x06;
const tp_initial_max_stream_data_uni: u64 = 0x07;
const tp_initial_max_streams_bidi: u64 = 0x08;
const tp_initial_max_streams_uni: u64 = 0x09;
const tp_disable_active_migration: u64 = 0x0c;
const tp_active_connection_id_limit: u64 = 0x0e;
const tp_original_destination_connection_id: u64 = 0x00;
const tp_stateless_reset_token: u64 = 0x02;
const tp_ack_delay_exponent: u64 = 0x0a;
const tp_max_ack_delay: u64 = 0x0b;
const tp_initial_source_connection_id: u64 = 0x0f;
const tp_retry_source_connection_id: u64 = 0x10;

pub const max_transport_parameters_len = 11 * (2 + 1 + 8) + 3 + 3 * (2 + 1 + config.max_cid_len) + (2 + 1 + 16);

pub fn encodeTransportParameters(params: config.TransportParameters, buf: []u8) HandshakeError![]const u8 {
    return encodeTransportParametersBound(params, .{}, buf);
}

pub fn encodeTransportParametersBound(
    params: config.TransportParameters,
    binding: config.CidBinding,
    buf: []u8,
) HandshakeError![]const u8 {
    var len: usize = 0;
    const entries = [_]struct { id: u64, value: u64 }{
        .{ .id = tp_max_idle_timeout, .value = params.max_idle_timeout_ms },
        .{ .id = tp_max_udp_payload_size, .value = params.max_udp_payload_size },
        .{ .id = tp_initial_max_data, .value = params.initial_max_data },
        .{ .id = tp_initial_max_stream_data_bidi_local, .value = params.initial_max_stream_data_bidi_local },
        .{ .id = tp_initial_max_stream_data_bidi_remote, .value = params.initial_max_stream_data_bidi_remote },
        .{ .id = tp_initial_max_stream_data_uni, .value = params.initial_max_stream_data_uni },
        .{ .id = tp_initial_max_streams_bidi, .value = params.initial_max_streams_bidi },
        .{ .id = tp_initial_max_streams_uni, .value = params.initial_max_streams_uni },
        .{ .id = tp_active_connection_id_limit, .value = params.active_connection_id_limit },
        .{ .id = tp_ack_delay_exponent, .value = params.ack_delay_exponent },
        .{ .id = tp_max_ack_delay, .value = params.max_ack_delay_ms },
    };
    for (entries) |entry| {
        len += varint.encode(entry.id, buf[len..]) catch return error.HandshakeBufferOverflow;
        const value_len = varint.encodedLen(entry.value) catch return error.HandshakeBufferOverflow;
        len += varint.encode(value_len, buf[len..]) catch return error.HandshakeBufferOverflow;
        len += varint.encode(entry.value, buf[len..]) catch return error.HandshakeBufferOverflow;
    }
    if (params.disable_active_migration) {
        len += varint.encode(tp_disable_active_migration, buf[len..]) catch return error.HandshakeBufferOverflow;
        len += varint.encode(0, buf[len..]) catch return error.HandshakeBufferOverflow;
    }
    const cid_entries = [_]struct { id: u64, value: ?config.CidValue }{
        .{ .id = tp_initial_source_connection_id, .value = binding.initial_source_connection_id },
        .{ .id = tp_original_destination_connection_id, .value = binding.original_destination_connection_id },
        .{ .id = tp_retry_source_connection_id, .value = binding.retry_source_connection_id },
    };
    for (cid_entries) |entry| {
        const value = entry.value orelse continue;
        len += varint.encode(entry.id, buf[len..]) catch return error.HandshakeBufferOverflow;
        len += varint.encode(value.len, buf[len..]) catch return error.HandshakeBufferOverflow;
        if (value.len > buf.len - len) return error.HandshakeBufferOverflow;
        @memcpy(buf[len..][0..value.len], value.slice());
        len += value.len;
    }
    if (binding.stateless_reset_token) |token| {
        len += varint.encode(tp_stateless_reset_token, buf[len..]) catch return error.HandshakeBufferOverflow;
        len += varint.encode(token.len, buf[len..]) catch return error.HandshakeBufferOverflow;
        if (token.len > buf.len - len) return error.HandshakeBufferOverflow;
        @memcpy(buf[len..][0..token.len], &token);
        len += token.len;
    }
    return buf[0..len];
}

pub const max_distinct_transport_parameters = 64;

pub fn decodeTransportParameters(bytes: []const u8) HandshakeError!config.TransportParameters {
    var binding = config.CidBinding{};
    return decodeTransportParametersBound(bytes, &binding);
}

pub fn decodeTransportParametersBound(
    bytes: []const u8,
    binding: *config.CidBinding,
) HandshakeError!config.TransportParameters {
    var params = config.TransportParameters{
        .max_idle_timeout_ms = 0,
        .active_connection_id_limit = 2,
        .max_udp_payload_size = 65_527,
        .initial_max_data = 0,
        .initial_max_stream_data_bidi_local = 0,
        .initial_max_stream_data_bidi_remote = 0,
        .initial_max_stream_data_uni = 0,
        .initial_max_streams_bidi = 0,
        .initial_max_streams_uni = 0,
        .disable_active_migration = false,
    };
    var seen_ids: [max_distinct_transport_parameters]u64 = undefined;
    var seen_count: usize = 0;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const id = varint.decode(bytes[offset..]) catch return error.InvalidTransportParameters;
        offset += id.len;
        const value_len = varint.decode(bytes[offset..]) catch return error.InvalidTransportParameters;
        offset += value_len.len;
        if (value_len.value > bytes.len - offset) return error.InvalidTransportParameters;
        const value_bytes = bytes[offset..][0..@intCast(value_len.value)];
        offset += value_bytes.len;

        for (seen_ids[0..seen_count]) |seen_id| {
            if (seen_id == id.value) return error.InvalidTransportParameters;
        }
        if (seen_count == seen_ids.len) return error.InvalidTransportParameters;
        seen_ids[seen_count] = id.value;
        seen_count += 1;

        switch (id.value) {
            tp_max_idle_timeout => params.max_idle_timeout_ms = try integerParameter(value_bytes),
            tp_max_udp_payload_size => params.max_udp_payload_size = try integerParameter(value_bytes),
            tp_initial_max_data => params.initial_max_data = try integerParameter(value_bytes),
            tp_initial_max_stream_data_bidi_local => params.initial_max_stream_data_bidi_local = try integerParameter(value_bytes),
            tp_initial_max_stream_data_bidi_remote => params.initial_max_stream_data_bidi_remote = try integerParameter(value_bytes),
            tp_initial_max_stream_data_uni => params.initial_max_stream_data_uni = try integerParameter(value_bytes),
            tp_initial_max_streams_bidi => params.initial_max_streams_bidi = try integerParameter(value_bytes),
            tp_initial_max_streams_uni => params.initial_max_streams_uni = try integerParameter(value_bytes),
            tp_disable_active_migration => {
                if (value_bytes.len != 0) return error.InvalidTransportParameters;
                params.disable_active_migration = true;
            },
            tp_active_connection_id_limit => params.active_connection_id_limit = try integerParameter(value_bytes),
            tp_ack_delay_exponent => {
                const value = try integerParameter(value_bytes);
                if (value > 20) return error.InvalidTransportParameters;
                params.ack_delay_exponent = @intCast(value);
            },
            tp_max_ack_delay => {
                const value = try integerParameter(value_bytes);
                if (value >= 1 << 14) return error.InvalidTransportParameters;
                params.max_ack_delay_ms = value;
            },
            tp_initial_source_connection_id => binding.initial_source_connection_id = config.CidValue.init(value_bytes) catch return error.InvalidTransportParameters,
            tp_original_destination_connection_id => binding.original_destination_connection_id = config.CidValue.init(value_bytes) catch return error.InvalidTransportParameters,
            tp_retry_source_connection_id => binding.retry_source_connection_id = config.CidValue.init(value_bytes) catch return error.InvalidTransportParameters,
            tp_stateless_reset_token => {
                if (value_bytes.len != 16) return error.InvalidTransportParameters;
                binding.stateless_reset_token = value_bytes[0..16].*;
            },
            else => {},
        }
    }
    if (params.max_udp_payload_size < 1200 or params.max_udp_payload_size > 65_527) return error.InvalidTransportParameters;
    if (params.active_connection_id_limit < 2) return error.InvalidTransportParameters;
    return params;
}

fn integerParameter(value_bytes: []const u8) HandshakeError!u64 {
    const decoded = varint.decode(value_bytes) catch return error.InvalidTransportParameters;
    if (decoded.len != value_bytes.len) return error.InvalidTransportParameters;
    return decoded.value;
}

pub const Tls13Backend = struct {
    engine: shared.Tls13Backend,
    alpn: []const u8 = "h3",
    cid_binding: config.CidBinding = .{},
    peer_cid_binding: config.CidBinding = .{},
    local_transport_parameters: [max_transport_parameters_len]u8 = undefined,
    scratch: RecordSink = .{},

    pub fn initClient(entropy: Entropy, trust: Trust) Tls13Backend {
        return .{ .engine = shared.Tls13Backend.initClient(entropy, trust, .{ .extension = .{
            .alpn = "h3",
            .extension_type = ext_quic_transport_parameters,
            .local = "",
        } }) };
    }

    pub fn initServer(entropy: Entropy, identity: Identity) Tls13Backend {
        return .{ .engine = shared.Tls13Backend.initServer(entropy, identity, .{ .extension = .{
            .alpn = "h3",
            .extension_type = ext_quic_transport_parameters,
            .local = "",
        } }) };
    }

    pub fn backend(self: *Tls13Backend) tls_handshake.TlsBackend {
        return .{
            .transport = .{ .ptr = self, .startFn = start, .receiveFn = receive, .deinitFn = deinitImpl },
            .setCidBindingFn = setCidBinding,
            .peerCidBindingFn = peerCidBinding,
        };
    }

    pub fn deinit(self: *Tls13Backend) void {
        self.scratch.deinit();
        self.engine.deinit();
        std.crypto.secureZero(u8, &self.local_transport_parameters);
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    fn setCidBinding(ptr: *anyopaque, binding: config.CidBinding) void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        self.cid_binding = binding;
    }

    fn peerCidBinding(ptr: *anyopaque) config.CidBinding {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return self.peer_cid_binding;
    }

    fn start(ptr: *anyopaque, role: tls_handshake.Role, params: config.TransportParameters, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        const encoded = try encodeTransportParametersBound(params, self.cid_binding, &self.local_transport_parameters);
        self.engine.profile = .{ .extension = .{
            .alpn = self.alpn,
            .extension_type = ext_quic_transport_parameters,
            .local = encoded,
        } };
        self.scratch.reset();
        const result = self.engine.backend().start(role, {}, &self.scratch);
        try self.forwardPeerTransportParameters(sink);
        try translate(&self.scratch, sink);
        result catch |err| return mapError(err);
    }

    fn receive(ptr: *anyopaque, level: EncryptionLevel, bytes: []const u8, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        self.scratch.reset();
        const result = self.engine.backend().receive(toEpoch(level), bytes, &self.scratch);
        try self.forwardPeerTransportParameters(sink);
        try translate(&self.scratch, sink);
        result catch |err| return mapError(err);
    }

    fn forwardPeerTransportParameters(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        const bytes = self.engine.takePeerTransportExtension() orelse return;
        try sink.emitPeerTransportParameters(try decodeTransportParametersBound(bytes, &self.peer_cid_binding));
    }
};

fn translate(source: *const RecordSink, destination: *EventSink) HandshakeError!void {
    for (source.items[0..source.len]) |event| {
        switch (event) {
            .handshake_bytes => |item| try destination.emitHandshakeBytes(toLevel(item.epoch), item.data),
            .traffic_secret => |item| try destination.emitSecret(toLevel(item.epoch), item.direction, item.data),
            .peer_transport_parameters => {},
            .alpn => |protocol| try destination.emitAlpn(protocol),
            .certificate => |state| try destination.emitCertificate(state),
            .discard_epoch => |epoch| try destination.emitDiscardEpoch(toLevel(epoch)),
            .handshake_complete => try destination.emitHandshakeComplete(),
            .fatal_alert => |alert| try destination.emitFatalAlert(alert),
        }
    }
}

fn mapError(err: tls_core.encrypted_stream.RecordHandshakeError) HandshakeError {
    return switch (err) {
        error.UnexpectedTransportEpoch => error.UnexpectedCryptoLevel,
        error.MissingTransportExtension => error.MissingTransportParameters,
        error.TransportBufferOverflow => error.HandshakeBufferOverflow,
        error.AuthenticationFailed,
        error.UnsupportedRecordEpoch,
        error.DuplicateTrafficSecret,
        error.MissingReadKeys,
        error.MissingWriteKeys,
        error.MissingApplicationKeys,
        error.HandshakeNotComplete,
        error.InvalidEpochTransition,
        error.UnexpectedRecordContent,
        error.EpochAlreadyDiscarded,
        error.EpochDiscardTooEarly,
        error.InvalidInput,
        error.InvalidRecordType,
        error.InvalidRecordVersion,
        error.InvalidTrafficSecretLength,
        error.MalformedInnerPlaintext,
        error.RecordBufferOverflow,
        error.RecordSinkOverflow,
        error.RecordTooLarge,
        error.SequenceExhausted,
        error.TruncatedRecord,
        error.UnsupportedCapability,
        => error.SecretExportFailed,
        else => @errorCast(err),
    };
}

fn toEpoch(level: EncryptionLevel) tls_core.events.EncryptionEpoch {
    return switch (level) {
        .initial => .initial,
        .zero_rtt => .zero_rtt,
        .handshake => .handshake,
        .application => .application,
    };
}

fn toLevel(epoch: tls_core.events.EncryptionEpoch) EncryptionLevel {
    return switch (epoch) {
        .initial => .initial,
        .zero_rtt => .zero_rtt,
        .handshake => .handshake,
        .application => .application,
    };
}

test "QUIC transport parameters remain owned by the QUIC adapter" {
    const params = (config.Config{}).transportParameters() catch unreachable;
    var buf: [max_transport_parameters_len]u8 = undefined;
    const encoded = try encodeTransportParameters(params, &buf);
    const decoded = try decodeTransportParameters(encoded);
    try std.testing.expectEqualDeep(params, decoded);
}

test "QUIC transport parameter decoding preserves defaults and unknown values" {
    const bytes = [_]u8{ 0x21, 0x03, 0xaa, 0xbb, 0xcc, 0x03, 0x02, 0x45, 0xac };
    const decoded = try decodeTransportParameters(&bytes);
    try std.testing.expectEqual(@as(u64, 1452), decoded.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 2), decoded.active_connection_id_limit);
    try std.testing.expectEqual(@as(u64, 0), decoded.initial_max_data);
    try std.testing.expect(!decoded.disable_active_migration);
}

test "QUIC transport parameter decoding rejects duplicates and illegal values" {
    const duplicated = [_]u8{ 0x03, 0x02, 0x45, 0xac, 0x03, 0x02, 0x45, 0xac };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&duplicated));
    const duplicated_unknown = [_]u8{ 0x2a, 0x01, 0xaa, 0x2a, 0x01, 0xbb };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&duplicated_unknown));
    const truncated = [_]u8{ 0x04, 0x08, 0x00 };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&truncated));
    const overlong = [_]u8{ 0x04, 0x02, 0x01, 0xff };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&overlong));
    const illegal = [_]u8{ 0x03, 0x02, 0x40, 0x64 };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&illegal));
    const flag_with_value = [_]u8{ 0x0c, 0x01, 0x01 };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&flag_with_value));
}

test "QUIC adapter owns CID binding round trip" {
    const params = (config.Config{}).transportParameters() catch unreachable;
    const scid = try config.CidValue.init(&.{ 0x01, 0x02, 0x03, 0x04 });
    const odcid = try config.CidValue.init(&.{ 0x10, 0x11, 0x12 });
    const local = config.CidBinding{
        .initial_source_connection_id = scid,
        .original_destination_connection_id = odcid,
        .stateless_reset_token = [_]u8{0xa5} ** 16,
    };
    var buf: [max_transport_parameters_len]u8 = undefined;
    const encoded = try encodeTransportParametersBound(params, local, &buf);
    var peer = config.CidBinding{};
    _ = try decodeTransportParametersBound(encoded, &peer);
    try std.testing.expectEqualDeep(local, peer);
}
