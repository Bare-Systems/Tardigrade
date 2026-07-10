//! HTTP/3 framing layer (#246, RFC 9114 §7): frame codec, unidirectional stream
//! types, SETTINGS handling, and control-stream validation.
//!
//! This module is intentionally transport-free. QUIC streams provide ordered
//! bytes; HTTP/3 frame boundaries and control-stream rules live here.

const std = @import("std");

const varint = @import("quic_varint");

pub const alpn = "h3";

pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
    priority_update_request = 0x0f0700,
    priority_update_push = 0x0f0701,
    unknown = std.math.maxInt(u64),

    pub fn fromValue(value: u64) FrameType {
        return switch (value) {
            0x00 => .data,
            0x01 => .headers,
            0x03 => .cancel_push,
            0x04 => .settings,
            0x05 => .push_promise,
            0x07 => .goaway,
            0x0d => .max_push_id,
            0x0f0700 => .priority_update_request,
            0x0f0701 => .priority_update_push,
            else => .unknown,
        };
    }
};

pub const RawFrame = struct {
    typ: FrameType,
    type_value: u64,
    payload: []const u8,
    len: usize,
};

pub const DecodeError = error{
    BufferTooShort,
    FrameLengthOverflow,
    FrameTooLarge,
    ReservedSetting,
    DuplicateSetting,
    InvalidSettingValue,
    MalformedSettings,
    MissingSettings,
    DuplicateSettings,
    InvalidControlFrame,
    ControlStreamClosed,
    InvalidUnidirectionalStreamType,
    DuplicateControlStream,
    OutOfMemory,
};

pub const EncodeError = error{
    ValueTooLarge,
    BufferTooShort,
};

pub fn encodeFrame(type_value: u64, payload: []const u8, out: []u8) EncodeError![]u8 {
    var pos: usize = 0;
    pos += try varint.encode(type_value, out[pos..]);
    pos += try varint.encode(payload.len, out[pos..]);
    if (payload.len > out.len - pos) return error.BufferTooShort;
    @memcpy(out[pos..][0..payload.len], payload);
    pos += payload.len;
    return out[0..pos];
}

pub fn encodeKnownFrame(typ: FrameType, payload: []const u8, out: []u8) EncodeError![]u8 {
    return encodeFrame(@intFromEnum(typ), payload, out);
}

pub fn decodeFrame(bytes: []const u8) DecodeError!RawFrame {
    const typ = varint.decode(bytes) catch return error.BufferTooShort;
    const len = varint.decode(bytes[typ.len..]) catch return error.BufferTooShort;
    if (len.value > std.math.maxInt(usize)) return error.FrameLengthOverflow;
    const payload_len: usize = @intCast(len.value);
    const start = typ.len + len.len;
    if (payload_len > bytes.len - start) return error.BufferTooShort;
    return .{
        .typ = FrameType.fromValue(typ.value),
        .type_value = typ.value,
        .payload = bytes[start..][0..payload_len],
        .len = start + payload_len,
    };
}

pub fn decodeFrameWithLimit(bytes: []const u8, max_payload_len: usize) DecodeError!RawFrame {
    const typ = varint.decode(bytes) catch return error.BufferTooShort;
    const len = varint.decode(bytes[typ.len..]) catch return error.BufferTooShort;
    if (len.value > std.math.maxInt(usize)) return error.FrameLengthOverflow;
    const payload_len: usize = @intCast(len.value);
    if (payload_len > max_payload_len) return error.FrameTooLarge;
    const start = typ.len + len.len;
    if (payload_len > bytes.len - start) return error.BufferTooShort;
    return .{
        .typ = FrameType.fromValue(typ.value),
        .type_value = typ.value,
        .payload = bytes[start..][0..payload_len],
        .len = start + payload_len,
    };
}

pub const StreamType = enum(u64) {
    control = 0x00,
    push = 0x01,
    qpack_encoder = 0x02,
    qpack_decoder = 0x03,
    unknown = std.math.maxInt(u64),

    pub fn fromValue(value: u64) StreamType {
        return switch (value) {
            0x00 => .control,
            0x01 => .push,
            0x02 => .qpack_encoder,
            0x03 => .qpack_decoder,
            else => .unknown,
        };
    }
};

pub const DecodedStreamType = struct {
    typ: StreamType,
    value: u64,
    len: usize,
};

pub fn encodeStreamType(typ: StreamType, out: []u8) EncodeError![]u8 {
    const len = try varint.encode(@intFromEnum(typ), out);
    return out[0..len];
}

pub fn decodeStreamType(bytes: []const u8) DecodeError!DecodedStreamType {
    const decoded = varint.decode(bytes) catch return error.BufferTooShort;
    return .{ .typ = StreamType.fromValue(decoded.value), .value = decoded.value, .len = decoded.len };
}

pub const SettingId = enum(u64) {
    qpack_max_table_capacity = 0x01,
    max_field_section_size = 0x06,
    qpack_blocked_streams = 0x07,
    enable_connect_protocol = 0x08,
    h3_datagram = 0x33,
    unknown = std.math.maxInt(u64),

    pub fn fromValue(value: u64) SettingId {
        return switch (value) {
            0x01 => .qpack_max_table_capacity,
            0x06 => .max_field_section_size,
            0x07 => .qpack_blocked_streams,
            0x08 => .enable_connect_protocol,
            0x33 => .h3_datagram,
            else => .unknown,
        };
    }
};

pub const Setting = struct {
    id: SettingId,
    id_value: u64,
    value: u64,
};

pub const Settings = struct {
    qpack_max_table_capacity: u64 = 0,
    qpack_blocked_streams: u64 = 0,
    max_field_section_size: ?u64 = null,
    enable_connect_protocol: bool = false,
    h3_datagram: bool = false,
};

pub fn encodeSettings(settings: []const Setting, out: []u8) EncodeError![]u8 {
    var pos: usize = 0;
    for (settings) |setting| {
        pos += try varint.encode(setting.id_value, out[pos..]);
        pos += try varint.encode(setting.value, out[pos..]);
    }
    return out[0..pos];
}

pub fn decodeSettings(payload: []const u8, scratch: []Setting) DecodeError!struct { parsed: Settings, count: usize } {
    var parsed = Settings{};
    var count: usize = 0;
    var pos: usize = 0;
    while (pos < payload.len) {
        if (count >= scratch.len) return error.MalformedSettings;
        const id = varint.decode(payload[pos..]) catch return error.MalformedSettings;
        pos += id.len;
        if (isReservedSetting(id.value)) return error.ReservedSetting;
        const value = varint.decode(payload[pos..]) catch return error.MalformedSettings;
        pos += value.len;

        for (scratch[0..count]) |seen| {
            if (seen.id_value == id.value) return error.DuplicateSetting;
        }

        const setting = Setting{ .id = SettingId.fromValue(id.value), .id_value = id.value, .value = value.value };
        scratch[count] = setting;
        count += 1;

        switch (setting.id) {
            .qpack_max_table_capacity => parsed.qpack_max_table_capacity = setting.value,
            .qpack_blocked_streams => parsed.qpack_blocked_streams = setting.value,
            .max_field_section_size => parsed.max_field_section_size = setting.value,
            .enable_connect_protocol => parsed.enable_connect_protocol = try decodeBooleanSetting(setting.value),
            .h3_datagram => parsed.h3_datagram = try decodeBooleanSetting(setting.value),
            .unknown => {},
        }
    }
    return .{ .parsed = parsed, .count = count };
}

fn isReservedSetting(id: u64) bool {
    return id == 0x00 or id == 0x02 or id == 0x03 or id == 0x04 or id == 0x05;
}

fn decodeBooleanSetting(value: u64) DecodeError!bool {
    return switch (value) {
        0 => false,
        1 => true,
        else => error.InvalidSettingValue,
    };
}

pub const ApplicationErrorCode = enum(u64) {
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
    request_rejected = 0x010b,
    request_cancelled = 0x010c,
    request_incomplete = 0x010d,
    message_error = 0x010e,
    connect_error = 0x010f,
    version_fallback = 0x0110,
};

pub const ConnectionError = struct {
    code: ApplicationErrorCode,
    reason: []const u8,
};

pub const ControlStreamRegistry = struct {
    control_stream_id: ?u64 = null,
    last_error: ?ConnectionError = null,

    pub fn openControlStream(self: *ControlStreamRegistry, stream_id: u64) DecodeError!void {
        if (self.control_stream_id) |existing| {
            if (existing != stream_id) {
                self.last_error = .{
                    .code = .stream_creation_error,
                    .reason = "duplicate HTTP/3 control stream",
                };
                return error.DuplicateControlStream;
            }
            return;
        }
        self.control_stream_id = stream_id;
    }
};

pub const ControlStream = struct {
    pub const max_frame_payload_len: usize = 16 * 1024;

    pending: std.ArrayList(u8) = .empty,
    saw_type: bool = false,
    saw_settings: bool = false,
    closed: bool = false,
    settings: Settings = .{},

    pub fn deinit(self: *ControlStream, allocator: std.mem.Allocator) void {
        self.pending.deinit(allocator);
    }

    pub fn ingest(self: *ControlStream, allocator: std.mem.Allocator, bytes: []const u8) DecodeError!usize {
        if (self.closed) return error.ControlStreamClosed;
        self.pending.appendSlice(allocator, bytes) catch return error.OutOfMemory;

        while (true) {
            if (!self.saw_type) {
                const stream_type = decodeStreamType(self.pending.items) catch |err| switch (err) {
                    error.BufferTooShort => return bytes.len,
                    else => return err,
                };
                if (self.pending.items.len == stream_type.len) return bytes.len;
                const frame_preview = decodeFrameWithLimit(self.pending.items[stream_type.len..], max_frame_payload_len) catch |err| switch (err) {
                    error.BufferTooShort => return bytes.len,
                    else => return err,
                };
                if (frame_preview.typ != .settings) return error.MissingSettings;
                if (stream_type.typ != .control) return error.InvalidUnidirectionalStreamType;
                self.saw_type = true;
                discardPrefix(&self.pending, stream_type.len);
            }

            const raw = decodeFrameWithLimit(self.pending.items, max_frame_payload_len) catch |err| switch (err) {
                error.BufferTooShort => return bytes.len,
                else => return err,
            };
            try self.ingestFrame(raw);
            discardPrefix(&self.pending, raw.len);
        }
    }

    pub fn ingestComplete(self: *ControlStream, bytes: []const u8) DecodeError!usize {
        if (self.closed) return error.ControlStreamClosed;
        var pos: usize = 0;
        if (!self.saw_type) {
            const stream_type = try decodeStreamType(bytes);
            if (stream_type.typ != .control) return error.InvalidUnidirectionalStreamType;
            self.saw_type = true;
            pos += stream_type.len;
        }
        while (pos < bytes.len) {
            const frame = try decodeFrameWithLimit(bytes[pos..], max_frame_payload_len);
            try self.ingestFrame(frame);
            pos += frame.len;
        }
        return pos;
    }

    pub fn ingestFrame(self: *ControlStream, raw: RawFrame) DecodeError!void {
        if (self.closed) return error.ControlStreamClosed;
        if (!self.saw_settings) {
            if (raw.typ != .settings) return error.MissingSettings;
            var scratch: [32]Setting = undefined;
            const decoded = try decodeSettings(raw.payload, &scratch);
            self.settings = decoded.parsed;
            self.saw_settings = true;
            return;
        }
        switch (raw.typ) {
            .settings => return error.DuplicateSettings,
            .data, .headers, .push_promise => return error.InvalidControlFrame,
            else => {},
        }
    }

    pub fn finish(self: *ControlStream) DecodeError!void {
        self.closed = true;
        if (self.pending.items.len != 0 or !self.saw_settings) return error.MissingSettings;
    }
};

fn discardPrefix(list: *std.ArrayList(u8), len: usize) void {
    if (len == 0) return;
    if (len >= list.items.len) {
        list.clearRetainingCapacity();
        return;
    }
    std.mem.copyForwards(u8, list.items[0 .. list.items.len - len], list.items[len..]);
    list.shrinkRetainingCapacity(list.items.len - len);
}

const testing = std.testing;

test "ALPN token is h3" {
    try testing.expectEqualStrings("h3", alpn);
}

test "frame codec round-trips known and unknown frame types" {
    var buf: [64]u8 = undefined;
    const encoded = try encodeKnownFrame(.headers, "abc", &buf);
    const decoded = try decodeFrame(encoded);
    try testing.expectEqual(FrameType.headers, decoded.typ);
    try testing.expectEqual(@as(u64, 0x01), decoded.type_value);
    try testing.expectEqualStrings("abc", decoded.payload);
    try testing.expectEqual(encoded.len, decoded.len);

    const unknown = try encodeFrame(0x21, "", &buf);
    const decoded_unknown = try decodeFrame(unknown);
    try testing.expectEqual(FrameType.unknown, decoded_unknown.typ);
    try testing.expectEqual(@as(u64, 0x21), decoded_unknown.type_value);
}

test "frame decoder rejects truncated headers and payloads" {
    try testing.expectError(error.BufferTooShort, decodeFrame(&.{}));
    try testing.expectError(error.BufferTooShort, decodeFrame(&.{0x01}));
    try testing.expectError(error.BufferTooShort, decodeFrame(&.{ 0x01, 0x03, 'a' }));
}

test "SETTINGS codec accepts static QPACK defaults and unknown settings" {
    var payload: [64]u8 = undefined;
    const settings_payload = try encodeSettings(&.{
        .{ .id = .qpack_max_table_capacity, .id_value = 0x01, .value = 0 },
        .{ .id = .qpack_blocked_streams, .id_value = 0x07, .value = 0 },
        .{ .id = .unknown, .id_value = 0x2a, .value = 99 },
    }, &payload);

    var scratch: [8]Setting = undefined;
    const decoded = try decodeSettings(settings_payload, &scratch);
    try testing.expectEqual(@as(usize, 3), decoded.count);
    try testing.expectEqual(@as(u64, 0), decoded.parsed.qpack_max_table_capacity);
    try testing.expectEqual(@as(u64, 0), decoded.parsed.qpack_blocked_streams);
}

test "SETTINGS decoder rejects reserved and duplicate settings" {
    var payload: [64]u8 = undefined;
    const reserved = try encodeSettings(&.{.{ .id = .unknown, .id_value = 0x02, .value = 1 }}, &payload);
    var scratch: [8]Setting = undefined;
    try testing.expectError(error.ReservedSetting, decodeSettings(reserved, &scratch));

    const duplicate = try encodeSettings(&.{
        .{ .id = .qpack_blocked_streams, .id_value = 0x07, .value = 0 },
        .{ .id = .qpack_blocked_streams, .id_value = 0x07, .value = 1 },
    }, &payload);
    try testing.expectError(error.DuplicateSetting, decodeSettings(duplicate, &scratch));

    const invalid_bool = try encodeSettings(&.{.{ .id = .enable_connect_protocol, .id_value = 0x08, .value = 2 }}, &payload);
    try testing.expectError(error.InvalidSettingValue, decodeSettings(invalid_bool, &scratch));
}

test "control stream requires SETTINGS first and rejects illegal control frames" {
    var payload: [64]u8 = undefined;
    const settings_payload = try encodeSettings(&.{.{ .id = .qpack_blocked_streams, .id_value = 0x07, .value = 0 }}, &payload);
    var stream_buf: [128]u8 = undefined;
    var pos: usize = 0;
    pos += (try encodeStreamType(.control, stream_buf[pos..])).len;
    pos += (try encodeKnownFrame(.settings, settings_payload, stream_buf[pos..])).len;
    pos += (try encodeFrame(0x21, "", stream_buf[pos..])).len;

    var control = ControlStream{};
    defer control.deinit(testing.allocator);
    try testing.expectEqual(pos, try control.ingest(testing.allocator, stream_buf[0..pos]));
    try testing.expect(control.saw_settings);

    const data = try encodeKnownFrame(.data, "", &payload);
    try testing.expectError(error.InvalidControlFrame, control.ingestFrame(try decodeFrame(data)));
}

test "control stream rejects missing duplicate and malformed SETTINGS" {
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    pos += (try encodeStreamType(.control, buf[pos..])).len;
    pos += (try encodeKnownFrame(.headers, "", buf[pos..])).len;

    {
        var control = ControlStream{};
        defer control.deinit(testing.allocator);
        try testing.expectError(error.MissingSettings, control.ingest(testing.allocator, buf[0..pos]));
    }

    pos = 0;
    pos += (try encodeStreamType(.control, buf[pos..])).len;
    pos += (try encodeKnownFrame(.settings, "", buf[pos..])).len;
    pos += (try encodeKnownFrame(.settings, "", buf[pos..])).len;
    {
        var control = ControlStream{};
        defer control.deinit(testing.allocator);
        try testing.expectError(error.DuplicateSettings, control.ingest(testing.allocator, buf[0..pos]));
    }

    {
        var control = ControlStream{ .saw_type = true };
        defer control.deinit(testing.allocator);
        try testing.expectError(error.MissingSettings, control.finish());
    }
}

test "control stream ingests split type length and payload without advancing early" {
    var settings_payload: [16]u8 = undefined;
    const settings = try encodeSettings(&.{.{ .id = .qpack_blocked_streams, .id_value = 0x07, .value = 0 }}, &settings_payload);
    var buf: [128]u8 = undefined;
    var pos: usize = 0;
    pos += (try encodeStreamType(.control, buf[pos..])).len;
    pos += (try encodeKnownFrame(.settings, settings, buf[pos..])).len;

    var control = ControlStream{};
    defer control.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), try control.ingest(testing.allocator, buf[0..1]));
    try testing.expect(!control.saw_type);
    try testing.expect(!control.saw_settings);

    try testing.expectEqual(@as(usize, 1), try control.ingest(testing.allocator, buf[1..2]));
    try testing.expect(!control.saw_type);
    try testing.expect(!control.saw_settings);

    _ = try control.ingest(testing.allocator, buf[2 .. pos - 1]);
    try testing.expect(!control.saw_type);
    try testing.expect(!control.saw_settings);

    _ = try control.ingest(testing.allocator, buf[pos - 1 .. pos]);
    try testing.expect(control.saw_type);
    try testing.expect(control.saw_settings);
}

test "frame decoder rejects payload lengths above configured limit before waiting for payload" {
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(@intFromEnum(FrameType.data), buf[pos..]);
    pos += try varint.encode(1024, buf[pos..]);
    try testing.expectError(error.FrameTooLarge, decodeFrameWithLimit(buf[0..pos], 16));
}

test "duplicate control stream maps to connection close error code" {
    var registry = ControlStreamRegistry{};
    try registry.openControlStream(2);
    try testing.expectError(error.DuplicateControlStream, registry.openControlStream(6));
    try testing.expectEqual(ApplicationErrorCode.stream_creation_error, registry.last_error.?.code);
}

test "fuzz: frame decoder never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeFrame, .{ .corpus = &.{
        "",
        "\x01",
        "\x01\x00",
        "\x01\x03abc",
        "\x04\x00",
        "\x40\x21\x00",
        "\x80\x0f\x07\x00\x00",
    } });
}

fn fuzzDecodeFrame(_: void, smith: *testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    const raw = decodeFrame(buf[0..len]) catch return;
    try testing.expect(raw.len <= len);
    try testing.expect(raw.payload.len <= raw.len);
    try testing.expectEqual(FrameType.fromValue(raw.type_value), raw.typ);

    const limited = decodeFrameWithLimit(buf[0..len], raw.payload.len) catch |err| switch (err) {
        error.FrameTooLarge => unreachable,
        else => return,
    };
    try testing.expectEqual(raw.type_value, limited.type_value);
    try testing.expectEqual(raw.len, limited.len);
}

test "fuzz: SETTINGS decoder never panics on arbitrary payloads" {
    try testing.fuzz({}, fuzzDecodeSettings, .{ .corpus = &.{
        "",
        "\x01\x00",
        "\x07\x00",
        "\x08\x01",
        "\x08\x02",
        "\x40\x08\x40\x01",
        "\x02\x01",
        "\x40\x02\x40\x01",
        "\x07\x00\x07\x01",
    } });
}

fn fuzzDecodeSettings(_: void, smith: *testing.Smith) !void {
    var buf: [256]u8 = undefined;
    const len = smith.slice(&buf);
    var scratch: [16]Setting = undefined;
    const decoded = decodeSettings(buf[0..len], &scratch) catch return;
    try testing.expect(decoded.count <= scratch.len);
    try expectUniqueSettings(scratch[0..decoded.count]);
    try expectCanonicalBooleanSettings(scratch[0..decoded.count]);

    var reencoded_buf: [256]u8 = undefined;
    const reencoded = encodeSettings(scratch[0..decoded.count], &reencoded_buf) catch return;
    var roundtrip_scratch: [16]Setting = undefined;
    const roundtrip = try decodeSettings(reencoded, &roundtrip_scratch);
    try testing.expectEqual(decoded.count, roundtrip.count);
    try testing.expectEqual(decoded.parsed.qpack_max_table_capacity, roundtrip.parsed.qpack_max_table_capacity);
    try testing.expectEqual(decoded.parsed.qpack_blocked_streams, roundtrip.parsed.qpack_blocked_streams);
    try testing.expectEqual(decoded.parsed.max_field_section_size, roundtrip.parsed.max_field_section_size);
    try testing.expectEqual(decoded.parsed.enable_connect_protocol, roundtrip.parsed.enable_connect_protocol);
    try testing.expectEqual(decoded.parsed.h3_datagram, roundtrip.parsed.h3_datagram);
}

fn expectUniqueSettings(settings: []const Setting) !void {
    for (settings, 0..) |setting, index| {
        for (settings[0..index]) |prior| {
            try testing.expect(setting.id_value != prior.id_value);
        }
    }
}

fn expectCanonicalBooleanSettings(settings: []const Setting) !void {
    for (settings) |setting| {
        switch (setting.id) {
            .enable_connect_protocol, .h3_datagram => try testing.expect(setting.value == 0 or setting.value == 1),
            else => {},
        }
    }
}

test "fuzz: control stream ingestion never panics or leaks" {
    try testing.fuzz({}, fuzzControlStreamIngest, .{ .corpus = &.{
        "",
        "\x00",
        "\x00\x04\x00",
        "\x00\x04\x02\x01\x00",
        "\x00\x04\x04\x01\x00\x07\x00",
        "\x00\x04\x02\x40\x07",
        "\x00\x40\x04\x40\x00",
        "\x00\x01\x00",
        "\x02\x04\x00",
    } });
}

fn fuzzControlStreamIngest(_: void, smith: *testing.Smith) !void {
    const allocator = testing.allocator;
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);

    var whole = ControlStream{};
    defer whole.deinit(allocator);
    const whole_result = whole.ingest(allocator, buf[0..len]);
    const whole_state = controlStreamState(&whole);

    var fragmented = ControlStream{};
    defer fragmented.deinit(allocator);
    var pos: usize = 0;
    var failed = false;
    while (pos < len) {
        const remaining = len - pos;
        var chunk_len = @as(usize, smith.value(u8)) % remaining + 1;
        if (smith.value(u1) == 1) chunk_len = 1;
        const before = controlStreamState(&fragmented);
        const result = fragmented.ingest(allocator, buf[pos..][0..chunk_len]);
        if (result) |_| {
            const after = controlStreamState(&fragmented);
            try expectControlStateMonotonic(before, after);
            pos += chunk_len;
        } else |_| {
            failed = true;
            break;
        }
    }

    if (whole_result) |_| {
        try testing.expect(!failed);
        try testing.expectEqual(whole_state.saw_type, fragmented.saw_type);
        try testing.expectEqual(whole_state.saw_settings, fragmented.saw_settings);
        try testing.expectEqual(whole_state.pending_len, fragmented.pending.items.len);
        if (whole.saw_settings and whole.pending.items.len == 0) {
            try whole.finish();
            try fragmented.finish();
            try testing.expect(whole.closed);
            try testing.expect(fragmented.closed);
        } else {
            try testing.expectError(error.MissingSettings, whole.finish());
        }
    } else |_| {
        if (!failed) {
            try testing.expect(fragmented.saw_type == whole_state.saw_type or !fragmented.saw_type);
            try testing.expect(fragmented.saw_settings == whole_state.saw_settings or !fragmented.saw_settings);
        }
    }
}

const ControlState = struct {
    saw_type: bool,
    saw_settings: bool,
    pending_len: usize,
};

fn controlStreamState(stream: *const ControlStream) ControlState {
    return .{
        .saw_type = stream.saw_type,
        .saw_settings = stream.saw_settings,
        .pending_len = stream.pending.items.len,
    };
}

fn expectControlStateMonotonic(before: ControlState, after: ControlState) !void {
    if (before.saw_type) try testing.expect(after.saw_type);
    if (before.saw_settings) try testing.expect(after.saw_settings);
}

test {
    std.testing.refAllDecls(@This());
}
