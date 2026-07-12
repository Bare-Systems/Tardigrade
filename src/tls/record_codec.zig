//! Bounded TLS 1.3 record codec.
//!
//! This module owns only TLS record envelopes and `TLSInnerPlaintext` framing.
//! It never performs socket I/O, AEAD sealing/opening, key selection, or
//! handshake progression. Callers feed arbitrary TCP fragments into `Parser`,
//! consume copied `Record` payloads from a bounded sink, and pass decrypted
//! ciphertext payloads to `decodeInnerPlaintext`.

const std = @import("std");

pub const header_len = 5;
pub const legacy_record_version: u16 = 0x0303;
pub const max_plaintext_fragment_len = 16 * 1024;
pub const max_ciphertext_fragment_len = max_plaintext_fragment_len + 256;
pub const max_ciphertext_record_len = header_len + max_ciphertext_fragment_len;

pub const Error = error{
    InvalidRecordType,
    InvalidRecordVersion,
    RecordTooLarge,
    RecordBufferOverflow,
    RecordSinkOverflow,
    TruncatedRecord,
    MalformedInnerPlaintext,
};

pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

pub const RecordMode = enum {
    plaintext,
    ciphertext,
};

pub const Record = struct {
    content_type: ContentType,
    legacy_version: u16,
    payload: []const u8,
};

pub const TLSPlaintext = Record;
pub const TLSCiphertext = Record;

pub const InnerPlaintext = struct {
    content_type: ContentType,
    content: []const u8,
    padding_len: usize,
};

pub const TLSInnerPlaintext = InnerPlaintext;

pub fn RecordSink(comptime max_record_count: usize, comptime max_payload_bytes: usize) type {
    return struct {
        items: [max_record_count]Record = undefined,
        len: usize = 0,
        scratch: [max_payload_bytes]u8 = undefined,
        used: usize = 0,

        const Self = @This();

        pub fn reset(self: *Self) void {
            self.len = 0;
            self.used = 0;
        }

        fn store(self: *Self, payload: []const u8) Error![]const u8 {
            if (payload.len > self.scratch.len - self.used) return error.RecordSinkOverflow;
            const start = self.used;
            @memcpy(self.scratch[start..][0..payload.len], payload);
            self.used += payload.len;
            return self.scratch[start..][0..payload.len];
        }

        pub fn push(self: *Self, record: Record) Error!void {
            if (self.len == self.items.len) return error.RecordSinkOverflow;
            self.items[self.len] = .{
                .content_type = record.content_type,
                .legacy_version = record.legacy_version,
                .payload = try self.store(record.payload),
            };
            self.len += 1;
        }
    };
}

pub const DefaultSink = RecordSink(16, 64 * 1024);

pub const Parser = struct {
    mode: RecordMode,
    pending: [max_ciphertext_record_len]u8 = undefined,
    len: usize = 0,

    pub fn init(mode: RecordMode) Parser {
        return .{ .mode = mode };
    }

    pub fn reset(self: *Parser) void {
        self.len = 0;
    }

    /// Feed arbitrary TCP bytes into the parser. Completed records are copied
    /// into `sink`; incomplete headers/bodies stay buffered for the next feed.
    pub fn feed(self: *Parser, bytes: []const u8, sink: anytype) Error!void {
        for (bytes) |byte| {
            if (self.len == self.pending.len) return error.RecordBufferOverflow;
            self.pending[self.len] = byte;
            self.len += 1;
            try self.drain(sink);
        }
    }

    pub fn finish(self: *const Parser) Error!void {
        if (self.len != 0) return error.TruncatedRecord;
    }

    fn drain(self: *Parser, sink: anytype) Error!void {
        while (self.len >= header_len) {
            const header = try parseHeader(self.pending[0..header_len], self.mode);
            const record_len = header_len + header.payload_len;
            if (self.len < record_len) return;
            try sink.push(.{
                .content_type = header.content_type,
                .legacy_version = header.legacy_version,
                .payload = self.pending[header_len..record_len],
            });
            self.discard(record_len);
        }
    }

    fn discard(self: *Parser, count: usize) void {
        std.debug.assert(count <= self.len);
        std.mem.copyForwards(u8, self.pending[0 .. self.len - count], self.pending[count..self.len]);
        self.len -= count;
    }
};

pub const RecordHeader = struct {
    content_type: ContentType,
    legacy_version: u16,
    payload_len: usize,
};

pub fn parseHeader(bytes: []const u8, mode: RecordMode) Error!RecordHeader {
    if (bytes.len != header_len) return error.TruncatedRecord;
    const content_type = parseContentType(bytes[0]) catch return error.InvalidRecordType;
    const version = std.mem.readInt(u16, bytes[1..3], .big);
    if (version != legacy_record_version) return error.InvalidRecordVersion;
    const payload_len: usize = std.mem.readInt(u16, bytes[3..5], .big);
    const max_len: usize = switch (mode) {
        .plaintext => max_plaintext_fragment_len,
        .ciphertext => max_ciphertext_fragment_len,
    };
    if (payload_len > max_len) return error.RecordTooLarge;
    if (mode == .ciphertext and content_type != .application_data) return error.InvalidRecordType;
    return .{ .content_type = content_type, .legacy_version = version, .payload_len = payload_len };
}

pub fn encodePlaintextRecord(content_type: ContentType, payload: []const u8, out: []u8) Error![]const u8 {
    if (content_type == .application_data) return error.InvalidRecordType;
    if (payload.len > max_plaintext_fragment_len) return error.RecordTooLarge;
    return encodeRecord(content_type, payload, out);
}

pub fn encodeCiphertextRecord(payload: []const u8, out: []u8) Error![]const u8 {
    if (payload.len > max_ciphertext_fragment_len) return error.RecordTooLarge;
    return encodeRecord(.application_data, payload, out);
}

fn encodeRecord(content_type: ContentType, payload: []const u8, out: []u8) Error![]const u8 {
    if (out.len < header_len + payload.len) return error.RecordBufferOverflow;
    out[0] = @intFromEnum(content_type);
    std.mem.writeInt(u16, out[1..3], legacy_record_version, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(payload.len), .big);
    @memcpy(out[header_len..][0..payload.len], payload);
    return out[0 .. header_len + payload.len];
}

pub fn encodeInnerPlaintext(content_type: ContentType, content: []const u8, padding_len: usize, out: []u8) Error![]const u8 {
    if (content_type == .change_cipher_spec) return error.InvalidRecordType;
    if (content.len > max_plaintext_fragment_len) return error.RecordTooLarge;
    const total = content.len + 1 + padding_len;
    if (total > max_ciphertext_fragment_len) return error.RecordTooLarge;
    if (out.len < total) return error.RecordBufferOverflow;
    @memcpy(out[0..content.len], content);
    out[content.len] = @intFromEnum(content_type);
    @memset(out[content.len + 1 ..][0..padding_len], 0);
    return out[0..total];
}

pub fn decodeInnerPlaintext(bytes: []const u8) Error!InnerPlaintext {
    if (bytes.len == 0) return error.MalformedInnerPlaintext;
    if (bytes.len > max_ciphertext_fragment_len) return error.RecordTooLarge;

    var index = bytes.len;
    while (index > 0) {
        index -= 1;
        if (bytes[index] != 0) {
            const content_type = parseContentType(bytes[index]) catch return error.MalformedInnerPlaintext;
            if (content_type == .change_cipher_spec) return error.MalformedInnerPlaintext;
            return .{
                .content_type = content_type,
                .content = bytes[0..index],
                .padding_len = bytes.len - index - 1,
            };
        }
    }
    return error.MalformedInnerPlaintext;
}

fn parseContentType(value: u8) Error!ContentType {
    return std.enums.fromInt(ContentType, value) orelse error.InvalidRecordType;
}

/// Fuzz entrypoint for #327-G. It intentionally swallows parser errors because
/// malformed input is the expected corpus majority; crashes and bounds failures
/// are the signal.
pub fn fuzzRecordInput(bytes: []const u8) void {
    var parser = Parser.init(.ciphertext);
    var sink = DefaultSink{};
    parser.feed(bytes, &sink) catch {};
    parser.finish() catch {};
}

const testing = std.testing;

test "plaintext parser reassembles split header and body" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    var encoded: [32]u8 = undefined;
    const record = try encodePlaintextRecord(.handshake, "hello", &encoded);

    try parser.feed(record[0..2], &sink);
    try testing.expectEqual(@as(usize, 0), sink.len);
    try parser.feed(record[2..4], &sink);
    try testing.expectEqual(@as(usize, 0), sink.len);
    try parser.feed(record[4..], &sink);

    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(ContentType.handshake, sink.items[0].content_type);
    try testing.expectEqual(legacy_record_version, sink.items[0].legacy_version);
    try testing.expectEqualStrings("hello", sink.items[0].payload);
    try parser.finish();
}

test "plaintext parser accepts byte-at-a-time input" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    var encoded: [32]u8 = undefined;
    const record = try encodePlaintextRecord(.alert, &.{ 2, 50 }, &encoded);

    for (record) |byte| try parser.feed(&.{byte}, &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(ContentType.alert, sink.items[0].content_type);
    try testing.expectEqualSlices(u8, &.{ 2, 50 }, sink.items[0].payload);
    try parser.finish();
}

test "plaintext parser emits multiple coalesced records" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    var encoded: [64]u8 = undefined;
    const first = try encodePlaintextRecord(.handshake, "one", encoded[0..]);
    const second = try encodePlaintextRecord(.alert, "two", encoded[first.len..]);

    try parser.feed(encoded[0 .. first.len + second.len], &sink);
    try testing.expectEqual(@as(usize, 2), sink.len);
    try testing.expectEqualStrings("one", sink.items[0].payload);
    try testing.expectEqualStrings("two", sink.items[1].payload);
    try parser.finish();
}

test "record parser rejects oversized and invalid headers deterministically" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 22, 3, 1, 0, 0 }, &sink));

    parser.reset();
    try testing.expectError(error.InvalidRecordType, parser.feed(&.{ 99, 3, 3, 0, 0 }, &sink));

    parser.reset();
    try testing.expectError(error.RecordTooLarge, parser.feed(&.{ 22, 3, 3, 0x40, 0x01 }, &sink));
}

test "ciphertext parser requires application_data envelope and allows TLS 1.3 expansion" {
    var parser = Parser.init(.ciphertext);
    var sink = RecordSink(1, max_ciphertext_fragment_len){};
    var encoded: [max_ciphertext_record_len]u8 = undefined;
    const payload = [_]u8{0xaa} ** max_ciphertext_fragment_len;
    const record = try encodeCiphertextRecord(&payload, &encoded);

    try parser.feed(record, &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(ContentType.application_data, sink.items[0].content_type);
    try testing.expectEqual(@as(usize, max_ciphertext_fragment_len), sink.items[0].payload.len);

    var bad_parser = Parser.init(.ciphertext);
    try testing.expectError(error.InvalidRecordType, bad_parser.feed(&.{ 22, 3, 3, 0, 0 }, &sink));
}

test "finish reports truncated records" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    try parser.feed(&.{ 22, 3, 3, 0, 4, 1 }, &sink);
    try testing.expectError(error.TruncatedRecord, parser.finish());
}

test "record sink bounds copied payload storage" {
    var parser = Parser.init(.plaintext);
    var sink = RecordSink(1, 1){};
    var encoded: [32]u8 = undefined;
    const record = try encodePlaintextRecord(.handshake, "too large", &encoded);
    try testing.expectError(error.RecordSinkOverflow, parser.feed(record, &sink));
}

test "plaintext and ciphertext serializers enforce limits and envelope type" {
    var out: [header_len + 4]u8 = undefined;
    const plain = try encodePlaintextRecord(.handshake, "abcd", &out);
    try testing.expectEqualSlices(u8, &.{ 22, 3, 3, 0, 4, 'a', 'b', 'c', 'd' }, plain);

    try testing.expectError(error.InvalidRecordType, encodePlaintextRecord(.application_data, "", &out));
    try testing.expectError(error.RecordBufferOverflow, encodeCiphertextRecord("abcd", out[0..4]));

    const oversized_plaintext = [_]u8{0} ** (max_plaintext_fragment_len + 1);
    try testing.expectError(error.RecordTooLarge, encodePlaintextRecord(.handshake, &oversized_plaintext, &out));
}

test "inner plaintext encodes content type followed by zero padding" {
    var out: [32]u8 = undefined;
    const inner = try encodeInnerPlaintext(.handshake, "finished", 3, &out);
    try testing.expectEqualSlices(u8, &.{ 'f', 'i', 'n', 'i', 's', 'h', 'e', 'd', 22, 0, 0, 0 }, inner);

    const decoded = try decodeInnerPlaintext(inner);
    try testing.expectEqual(ContentType.handshake, decoded.content_type);
    try testing.expectEqualStrings("finished", decoded.content);
    try testing.expectEqual(@as(usize, 3), decoded.padding_len);
}

test "inner plaintext rejects all-zero, invalid type, and oversized content" {
    try testing.expectError(error.MalformedInnerPlaintext, decodeInnerPlaintext(&.{ 0, 0, 0 }));
    try testing.expectError(error.MalformedInnerPlaintext, decodeInnerPlaintext(&.{ 1, 99, 0 }));
    try testing.expectError(error.MalformedInnerPlaintext, decodeInnerPlaintext(&.{ 20, 0 }));

    var out: [4]u8 = undefined;
    try testing.expectError(error.InvalidRecordType, encodeInnerPlaintext(.change_cipher_spec, "", 0, &out));
}

test "fuzz entrypoint accepts arbitrary bytes without escaping errors" {
    fuzzRecordInput(&.{ 23, 3, 3, 0, 3, 0, 0, 0, 99, 1, 2 });
}
