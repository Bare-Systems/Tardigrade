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

/// Legacy record-version acceptance policy for one header parse.
///
/// RFC 8446 SS5.1: `legacy_record_version` MUST be `0x0303` for every record a
/// TLS 1.3 implementation sends or expects, *except* an initial ClientHello
/// (one not generated after a HelloRetryRequest), which MAY use `0x0301` for
/// middlebox compatibility. `record_codec` never inspects handshake message
/// types, so it cannot itself recognize "this is a ClientHello" — the caller,
/// which knows its own role and which parser instance owns the initial epoch,
/// supplies this policy per parse.
pub const VersionPolicy = enum {
    /// Only `0x0303` is accepted. Used for every record after the first, and
    /// for any parser that never legitimately sees the compatibility version
    /// (a client's view of the server's records, and every ciphertext record).
    strict,
    /// `0x0301` or `0x0303` is accepted. Scoped by the caller to exactly the
    /// first record a server-role initial-epoch parser observes.
    allow_initial_client_hello_compat,
};

const compat_client_hello_version: u16 = 0x0301;

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
    /// Policy applied only to the very first record this parser instance
    /// successfully consumes; every subsequent record is `.strict` regardless
    /// of this setting. See `VersionPolicy`.
    first_record_version_policy: VersionPolicy = .strict,
    parsed_first_record: bool = false,

    pub fn init(mode: RecordMode) Parser {
        return .{ .mode = mode };
    }

    /// Construct a parser whose first successfully-consumed record may use
    /// `policy` instead of the default strict `0x0303`-only acceptance. Only a
    /// server-role parser dedicated to the initial (plaintext) epoch should
    /// pass `.allow_initial_client_hello_compat`.
    pub fn initWithVersionPolicy(mode: RecordMode, policy: VersionPolicy) Parser {
        return .{ .mode = mode, .first_record_version_policy = policy };
    }

    pub fn reset(self: *Parser) void {
        self.len = 0;
        self.parsed_first_record = false;
    }

    /// Feed arbitrary TCP bytes into the parser. Completed records are copied
    /// into `sink`; incomplete headers/bodies stay buffered for the next feed.
    pub fn feed(self: *Parser, bytes: []const u8, sink: anytype) Error!void {
        try self.drain(sink);
        for (bytes) |byte| {
            if (self.len == self.pending.len) return error.RecordBufferOverflow;
            self.pending[self.len] = byte;
            self.len += 1;
            try self.drain(sink);
        }
    }

    pub const FeedOneResult = struct {
        consumed: usize,
        emitted: bool,
    };

    /// Feed bytes until at most one complete record is emitted. The returned
    /// `consumed` count is exact, so callers can retain `bytes[consumed..]`
    /// without replaying or dropping carrier input.
    pub fn feedOne(self: *Parser, bytes: []const u8, sink: anytype) Error!FeedOneResult {
        try self.drainOne(sink);
        if (sink.len > 0) return .{ .consumed = 0, .emitted = true };

        var consumed: usize = 0;
        while (consumed < bytes.len and sink.len == 0) {
            if (self.len == self.pending.len) return error.RecordBufferOverflow;
            self.pending[self.len] = bytes[consumed];
            self.len += 1;
            consumed += 1;
            try self.drainOne(sink);
        }
        return .{ .consumed = consumed, .emitted = sink.len > 0 };
    }

    /// Retry emission of already-buffered complete records after the caller has
    /// made room in `sink`. This supports bounded sink/backpressure loops
    /// without appending unrelated bytes first.
    pub fn drainReady(self: *Parser, sink: anytype) Error!void {
        try self.drain(sink);
    }

    pub fn finish(self: *const Parser) Error!void {
        if (self.len != 0) return error.TruncatedRecord;
    }

    fn drain(self: *Parser, sink: anytype) Error!void {
        while (self.len >= header_len) {
            const header = try parseHeader(self.pending[0..header_len], self.mode, self.currentVersionPolicy());
            const record_len = header_len + header.payload_len;
            if (self.len < record_len) return;
            try sink.push(.{
                .content_type = header.content_type,
                .legacy_version = header.legacy_version,
                .payload = self.pending[header_len..record_len],
            });
            self.discard(record_len);
            self.parsed_first_record = true;
        }
    }

    fn drainOne(self: *Parser, sink: anytype) Error!void {
        if (self.len < header_len) return;
        const header = try parseHeader(self.pending[0..header_len], self.mode, self.currentVersionPolicy());
        const record_len = header_len + header.payload_len;
        if (self.len < record_len) return;
        try sink.push(.{
            .content_type = header.content_type,
            .legacy_version = header.legacy_version,
            .payload = self.pending[header_len..record_len],
        });
        self.discard(record_len);
        self.parsed_first_record = true;
    }

    /// The very first record this parser consumes may use its configured
    /// compatibility policy; every record after that is always `.strict`,
    /// matching the RFC 8446 SS5.1 scoping to an initial (non-post-HRR)
    /// ClientHello.
    fn currentVersionPolicy(self: *const Parser) VersionPolicy {
        return if (self.parsed_first_record) .strict else self.first_record_version_policy;
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

pub fn parseHeader(bytes: []const u8, mode: RecordMode, version_policy: VersionPolicy) Error!RecordHeader {
    if (bytes.len != header_len) return error.TruncatedRecord;
    const content_type = parseContentType(bytes[0]) catch return error.InvalidRecordType;
    const version = std.mem.readInt(u16, bytes[1..3], .big);
    // The compatibility version has no meaning once records are encrypted: a
    // ciphertext-mode parser always requires exactly 0x0303, regardless of
    // the caller-supplied policy, so a misconfigured parser instance still
    // fails closed rather than accepting it on the wrong record stream.
    const version_ok = version == legacy_record_version or
        (mode == .plaintext and version_policy == .allow_initial_client_hello_compat and version == compat_client_hello_version);
    if (!version_ok) return error.InvalidRecordVersion;
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
    const content_and_type = std.math.add(usize, content.len, 1) catch return error.RecordTooLarge;
    const total = std.math.add(usize, content_and_type, padding_len) catch return error.RecordTooLarge;
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

test "parser feedOne reports exact consumption for coalesced records" {
    var parser = Parser.init(.plaintext);
    var first_encoded: [32]u8 = undefined;
    var second_encoded: [32]u8 = undefined;
    const first = try encodePlaintextRecord(.handshake, "one", &first_encoded);
    const second = try encodePlaintextRecord(.handshake, "two", &second_encoded);

    var coalesced: [64]u8 = undefined;
    @memcpy(coalesced[0..first.len], first);
    @memcpy(coalesced[first.len..][0..second.len], second);

    var sink = RecordSink(1, max_plaintext_fragment_len){};
    const first_result = try parser.feedOne(coalesced[0 .. first.len + second.len], &sink);
    try testing.expect(first_result.emitted);
    try testing.expectEqual(first.len, first_result.consumed);
    try testing.expectEqualStrings("one", sink.items[0].payload);

    sink.reset();
    const second_result = try parser.feedOne(coalesced[first_result.consumed .. first.len + second.len], &sink);
    try testing.expect(second_result.emitted);
    try testing.expectEqual(second.len, second_result.consumed);
    try testing.expectEqualStrings("two", sink.items[0].payload);
}

test "parser feedOne against an already-saturated sink consumes nothing" {
    var parser = Parser.init(.plaintext);
    var encoded: [32]u8 = undefined;
    const record = try encodePlaintextRecord(.handshake, "one", &encoded);

    // Simulate a caller that has not yet drained a previous feedOne result:
    // the sink already holds an item before this call.
    var sink = RecordSink(1, max_plaintext_fragment_len){};
    try sink.push(.{ .content_type = .handshake, .legacy_version = legacy_record_version, .payload = "stale" });

    const result = try parser.feedOne(record, &sink);
    try testing.expectEqual(@as(usize, 0), result.consumed);
    try testing.expect(result.emitted);
    // The stale entry is untouched, and none of `record`'s bytes were
    // absorbed into the parser's internal buffer -- the caller can retry
    // the exact same slice once the sink is drained.
    try testing.expectEqualStrings("stale", sink.items[0].payload);
    try testing.expectEqual(@as(usize, 0), parser.len);

    sink.reset();
    const retry = try parser.feedOne(record, &sink);
    try testing.expectEqual(record.len, retry.consumed);
    try testing.expect(retry.emitted);
    try testing.expectEqualStrings("one", sink.items[0].payload);
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

test "strict parser rejects the 0x0301 ClientHello compatibility version by default" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    var encoded: [32]u8 = undefined;
    const record = try encodePlaintextRecord(.handshake, "client hello", &encoded);
    var compat_record: [64]u8 = undefined;
    @memcpy(compat_record[0..record.len], record);
    compat_record[1] = 0x03;
    compat_record[2] = 0x01;

    try testing.expectError(error.InvalidRecordVersion, parser.feed(compat_record[0..record.len], &sink));
}

test "server initial parser accepts 0x0301 only for the first record, then requires 0x0303" {
    var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
    var sink = DefaultSink{};
    var encoded: [64]u8 = undefined;
    const client_hello = try encodePlaintextRecord(.handshake, "client hello", &encoded);
    var compat_client_hello: [64]u8 = undefined;
    @memcpy(compat_client_hello[0..client_hello.len], client_hello);
    compat_client_hello[1] = 0x03;
    compat_client_hello[2] = 0x01;

    try parser.feed(compat_client_hello[0..client_hello.len], &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(@as(u16, 0x0301), sink.items[0].legacy_version);
    try testing.expectEqualStrings("client hello", sink.items[0].payload);

    // A second post-HRR ClientHello (or any later record) MUST be 0x0303;
    // the compatibility window closes after the first consumed record.
    sink.reset();
    var second_encoded: [64]u8 = undefined;
    const second_client_hello = try encodePlaintextRecord(.handshake, "second client hello", &second_encoded);
    var compat_second: [64]u8 = undefined;
    @memcpy(compat_second[0..second_client_hello.len], second_client_hello);
    compat_second[1] = 0x03;
    compat_second[2] = 0x01;
    try testing.expectError(error.InvalidRecordVersion, parser.feed(compat_second[0..second_client_hello.len], &sink));
}

test "compat policy still rejects legacy versions other than 0x0301 and 0x0303" {
    var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
    var sink = DefaultSink{};
    // 0x0300 (SSLv3) and 0x0302 (TLS 1.1) are not in the permitted set even
    // during the first-record compatibility window.
    try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 22, 3, 0, 0, 0 }, &sink));
    parser.reset();
    try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 22, 3, 2, 0, 0 }, &sink));
}

test "compat policy does not apply to the ciphertext parser" {
    var parser = Parser.initWithVersionPolicy(.ciphertext, .allow_initial_client_hello_compat);
    var sink = RecordSink(1, max_ciphertext_fragment_len){};
    // Even with the compat policy set, a ciphertext-mode header must still be
    // application_data at 0x0303; 0x0301 has no meaning post-encryption.
    try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 23, 3, 1, 0, 0 }, &sink));
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

test "parser can retry buffered record after sink backpressure" {
    var parser = Parser.init(.plaintext);
    var sink = RecordSink(1, 32){};
    var encoded: [64]u8 = undefined;
    const first = try encodePlaintextRecord(.handshake, "one", encoded[0..]);
    const second = try encodePlaintextRecord(.alert, "two", encoded[first.len..]);

    try testing.expectError(error.RecordSinkOverflow, parser.feed(encoded[0 .. first.len + second.len], &sink));
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqualStrings("one", sink.items[0].payload);

    sink.reset();
    try parser.drainReady(&sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqualStrings("two", sink.items[0].payload);
    try parser.finish();
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
    try testing.expectError(error.RecordTooLarge, encodeInnerPlaintext(.handshake, "", std.math.maxInt(usize), &out));
}

test "fuzz entrypoint accepts arbitrary bytes without escaping errors" {
    fuzzRecordInput(&.{ 23, 3, 3, 0, 3, 0, 0, 0, 99, 1, 2 });
}
