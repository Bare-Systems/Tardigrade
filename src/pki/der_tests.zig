//! DER decoder regression and adversarial tests (#339).

const std = @import("std");
const der = @import("der.zig");
const oid = @import("oid.zig");
const time = @import("time.zig");

const testing = std.testing;

const Builder = struct {
    buf: std.ArrayList(u8),

    fn init() Builder {
        return .{ .buf = std.ArrayList(u8).empty };
    }

    fn deinit(self: *Builder, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
    }

    fn appendTlv(self: *Builder, allocator: std.mem.Allocator, tag: der.Tag, content: []const u8) !void {
        var tag_buf: [8]u8 = undefined;
        const tag_len = try der.encodeTag(tag, &tag_buf);
        try self.buf.appendSlice(allocator, tag_buf[0..tag_len]);
        var len_buf: [9]u8 = undefined;
        const len_written = try der.encodeLength(content.len, &len_buf);
        try self.buf.appendSlice(allocator, len_buf[0..len_written]);
        try self.buf.appendSlice(allocator, content);
    }

    fn toOwnedSlice(self: *Builder, allocator: std.mem.Allocator) ![]u8 {
        return self.buf.toOwnedSlice(allocator);
    }
};

fn appendIntegerContent(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try out.appendSlice(allocator, value);
}

test "canonical positive fixtures for X.509 building blocks" {
    const allocator = testing.allocator;
    var b = Builder.init();
    defer b.deinit(allocator);

    // AlgorithmIdentifier-like SEQUENCE { OID, NULL }
    var inner = std.ArrayList(u8).empty;
    defer inner.deinit(allocator);
    var oid_buf: [32]u8 = undefined;
    const oid_len = try oid.encodeComponents(&oid.well_known.rsa_encryption, &oid_buf);
    var oid_builder = Builder.init();
    defer oid_builder.deinit(allocator);
    try oid_builder.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.object_identifier), false), oid_buf[0..oid_len]);
    try inner.appendSlice(allocator, oid_builder.buf.items);
    var null_builder = Builder.init();
    defer null_builder.deinit(allocator);
    try null_builder.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.null), false), &.{});
    try inner.appendSlice(allocator, null_builder.buf.items);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), inner.items);

    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);

    var reader = der.Reader.init(encoded, der.default_limits);
    var seq = try reader.readSequence();
    const alg_oid = try seq.readObjectIdentifier();
    try testing.expectEqual(@as(usize, 7), alg_oid.len);
    for (alg_oid.components(), 0..) |component, i| {
        try testing.expectEqual(oid.well_known.rsa_encryption[i], component);
    }
    try seq.readNull();
    try seq.expectEnd();
    try reader.expectEnd();
}

test "INTEGER positive and negative minimal encodings" {
    const allocator = testing.allocator;
    const cases = [_]struct { bytes: []const u8, negative: bool }{
        .{ .bytes = &.{0x00}, .negative = false },
        .{ .bytes = &.{0x01}, .negative = false },
        .{ .bytes = &.{ 0x00, 0x80 }, .negative = false },
        .{ .bytes = &.{0xff}, .negative = true },
        .{ .bytes = &.{ 0xff, 0x7f }, .negative = true },
    };
    for (cases) |c| {
        var b = Builder.init();
        defer b.deinit(allocator);
        var inner = std.ArrayList(u8).empty;
        defer inner.deinit(allocator);
        try appendIntegerContent(&inner, allocator, c.bytes);
        try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.integer), false), inner.items);
        const encoded = try b.toOwnedSlice(allocator);
        defer allocator.free(encoded);
        var reader = der.Reader.init(encoded, der.default_limits);
        const value = try reader.readInteger();
        try testing.expectEqual(c.negative, value.isNegative());
        try reader.expectEnd();
    }
}

test "BOOLEAN, BIT STRING, strings, and times" {
    const allocator = testing.allocator;
    var b = Builder.init();
    defer b.deinit(allocator);

    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.boolean), false), &.{0xff});
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.bit_string), false), &.{ 0x00, 0xA0 });
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.octet_string), false), "deadbeef");
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.utf8_string), false), "café");
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.printable_string), false), "Test CA");
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.ia5_string), false), "example.com");
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.utc_time), false), "240630120000Z");
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.generalized_time), false), "20240630120000Z");

    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);

    var reader = der.Reader.init(encoded, der.default_limits);
    try testing.expect(try reader.readBoolean());
    const bits = try reader.readBitString();
    try testing.expectEqual(@as(u3, 0), bits.unused_bits);
    try testing.expectEqual(@as(u8, 0xA0), bits.data[0]);
    try testing.expectEqualStrings("deadbeef", try reader.readOctetString());
    try testing.expectEqualStrings("café", try reader.readUtf8String());
    try testing.expectEqualStrings("Test CA", try reader.readPrintableString());
    try testing.expectEqualStrings("example.com", try reader.readIa5String());
    const utc = try reader.readUtcTime();
    try testing.expectEqual(@as(u16, 2024), utc.year);
    const gen = try reader.readGeneralizedTime();
    try testing.expectEqual(@as(u16, 2024), gen.year);
    try reader.expectEnd();
}

test "explicit and implicit context-specific tagging" {
    const allocator = testing.allocator;
    var seq_content = std.ArrayList(u8).empty;
    defer seq_content.deinit(allocator);

    var int_tlv = Builder.init();
    defer int_tlv.deinit(allocator);
    try int_tlv.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.integer), false), &.{0x2a});
    var explicit = Builder.init();
    defer explicit.deinit(allocator);
    try explicit.appendTlv(allocator, der.Tag.contextSpecific(0, true), int_tlv.buf.items);
    try seq_content.appendSlice(allocator, explicit.buf.items);

    var implicit = Builder.init();
    defer implicit.deinit(allocator);
    try implicit.appendTlv(allocator, der.Tag.contextSpecific(1, false), "implicit");
    try seq_content.appendSlice(allocator, implicit.buf.items);

    var outer = Builder.init();
    defer outer.deinit(allocator);
    try outer.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), seq_content.items);
    const encoded = try outer.toOwnedSlice(allocator);
    defer allocator.free(encoded);

    var reader = der.Reader.init(encoded, der.default_limits);
    var seq = try reader.readSequence();
    const explicit_elem = try seq.readExplicitContext(0);
    try testing.expect(explicit_elem.tag.number == @intFromEnum(der.UniversalTag.integer));
    try testing.expectEqual(@as(u8, 0x2a), explicit_elem.content[0]);

    const implicit_elem = try seq.readContextSpecific(1, false);
    try testing.expectEqualStrings("implicit", implicit_elem.content);
    try seq.expectEnd();
}

test "truncated tag and length" {
    const allocator = testing.allocator;
    try testing.expectError(error.Truncated, parseOne(allocator, &.{}));
    try testing.expectError(error.Truncated, parseOne(allocator, &.{0x30}));
    try testing.expectError(error.Truncated, parseOne(allocator, &.{ 0x30, 0x82 }));
    try testing.expectError(error.Truncated, parseOne(allocator, &.{ 0x30, 0x82, 0x01 }));
}

fn parseOne(allocator: std.mem.Allocator, input: []const u8) !void {
    return parseOneWithLimits(allocator, input, der.default_limits);
}

fn parseOneWithLimits(allocator: std.mem.Allocator, input: []const u8, limits: der.Limits) !void {
    var reader = der.Reader.init(input, limits);
    _ = try reader.readElement();
    try reader.expectEnd();
    _ = allocator;
}

test "high tag number edge cases" {
    const allocator = testing.allocator;
    // Tag 31 must use extended form; single-byte 0x1f is reserved as lead-in.
    try testing.expectError(error.InvalidTag, parseOne(allocator, &.{ 0x1f, 0x00, 0x00 }));

    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(31, false), &.{0x00});
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    const elem = try reader.readElement();
    try testing.expectEqual(@as(u32, 31), elem.tag.number);
}

test "indefinite length rejected" {
    const allocator = testing.allocator;
    try testing.expectError(error.IndefiniteLength, parseOne(allocator, &.{ 0x30, 0x80, 0x00, 0x00 }));
    try testing.expectError(error.IndefiniteLength, parseOne(allocator, &.{ 0x04, 0x80 }));
}

test "non-minimal long-form lengths rejected" {
    const allocator = testing.allocator;
    // Length 1 encoded as 0x81 0x01
    try testing.expectError(error.NonMinimalLength, parseOne(allocator, &.{ 0x04, 0x81, 0x01, 0x00 }));
    // Length 0x80 encoded with leading zero byte 0x82 0x00 0x80
    var long_len_input: [4 + 0x80]u8 = undefined;
    long_len_input[0] = 0x04;
    long_len_input[1] = 0x82;
    long_len_input[2] = 0x00;
    long_len_input[3] = 0x80;
    @memset(long_len_input[4..], 0);
    try testing.expectError(error.NonMinimalLength, parseOne(allocator, &long_len_input));
}

test "length beyond input and overflow" {
    const allocator = testing.allocator;
    try testing.expectError(error.LengthBeyondInput, parseOne(allocator, &.{ 0x04, 0x05, 0x01, 0x02 }));
    try testing.expectError(error.LengthOverflow, parseOneWithLimits(allocator, &.{ 0x04, 0x84, 0x00, 0x10, 0x00, 0x00 }, .{ .max_element_len = 1024 }));
}

test "excessive nesting and element count" {
    const allocator = testing.allocator;
    // Three nested empty SEQUENCEs: 30 06 30 04 30 02 30 00
    const deep = [_]u8{ 0x30, 0x06, 0x30, 0x04, 0x30, 0x02, 0x30, 0x00 };
    var reader = der.Reader.init(&deep, .{ .max_depth = 2 });
    var level1 = try reader.readSequence();
    var level2 = try level1.readSequence();
    try testing.expectError(error.NestingLimit, level2.readSequence());

    var b = Builder.init();
    defer b.deinit(allocator);
    var payload = std.ArrayList(u8).empty;
    defer payload.deinit(allocator);
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        var item = Builder.init();
        defer item.deinit(allocator);
        try item.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.null), false), &.{});
        try payload.appendSlice(allocator, item.buf.items);
    }
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), payload.items);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var elem_reader = der.Reader.init(encoded, .{ .max_elements = 4 });
    var seq = try elem_reader.readSequence();
    try seq.readNull();
    try seq.readNull();
    try seq.readNull();
    try testing.expectError(error.ElementCountLimit, seq.readNull());
}

test "element count limit is shared across nested sibling containers" {
    const allocator = testing.allocator;

    var first_payload = std.ArrayList(u8).empty;
    defer first_payload.deinit(allocator);
    var second_payload = std.ArrayList(u8).empty;
    defer second_payload.deinit(allocator);
    var i: usize = 0;
    while (i < 2) : (i += 1) {
        var item = Builder.init();
        defer item.deinit(allocator);
        try item.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.null), false), &.{});
        try first_payload.appendSlice(allocator, item.buf.items);
        try second_payload.appendSlice(allocator, item.buf.items);
    }

    var outer_payload = std.ArrayList(u8).empty;
    defer outer_payload.deinit(allocator);
    var first_seq = Builder.init();
    defer first_seq.deinit(allocator);
    try first_seq.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), first_payload.items);
    try outer_payload.appendSlice(allocator, first_seq.buf.items);
    var second_seq = Builder.init();
    defer second_seq.deinit(allocator);
    try second_seq.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), second_payload.items);
    try outer_payload.appendSlice(allocator, second_seq.buf.items);

    var outer = Builder.init();
    defer outer.deinit(allocator);
    try outer.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), outer_payload.items);
    const encoded = try outer.toOwnedSlice(allocator);
    defer allocator.free(encoded);

    var reader = der.Reader.init(encoded, .{ .max_elements = 5 });
    var seq = try reader.readSequence();
    var first = try seq.readSequence();
    try first.readNull();
    try first.readNull();
    try first.expectEnd();
    var second = try seq.readSequence();
    try testing.expectError(error.ElementCountLimit, second.readNull());
}

test "short-form lengths honor max element length" {
    const allocator = testing.allocator;
    try testing.expectError(error.LengthOverflow, parseOneWithLimits(allocator, &.{ 0x04, 0x05, 1, 2, 3, 4, 5 }, .{ .max_element_len = 4 }));
}

test "non-minimal INTEGER encodings rejected" {
    const allocator = testing.allocator;
    try testing.expectError(error.MalformedInteger, parseInteger(allocator, &.{ 0x00, 0x01 }));
    try testing.expectError(error.MalformedInteger, parseInteger(allocator, &.{ 0xff, 0xff }));
    try testing.expectError(error.MalformedInteger, parseInteger(allocator, &.{}));
}

test "constructed encodings for primitive universal types rejected" {
    const allocator = testing.allocator;
    try testing.expectError(error.UnexpectedTag, parseIntegerTlv(allocator, &.{ 0x22, 0x01, 0x01 }));
    try testing.expectError(error.UnexpectedTag, parseBooleanTlv(allocator, &.{ 0x21, 0x01, 0xff }));
    try testing.expectError(error.UnexpectedTag, parseBitStringTlv(allocator, &.{ 0x23, 0x02, 0x00, 0x80 }));
    try testing.expectError(error.UnexpectedTag, parseOidTlv(allocator, &.{ 0x26, 0x03, 0x55, 0x04, 0x03 }));
    try testing.expectError(error.UnexpectedTag, parseUtcTlv(allocator, "\x37\x0d240101000000Z"));
    try testing.expectError(error.UnexpectedTag, parseGenTlv(allocator, "\x38\x0f20240101000000Z"));
    try testing.expectError(error.InvalidTag, parseOne(allocator, &.{ 0x00, 0x00 }));
}

test "invalid BOOLEAN values" {
    const allocator = testing.allocator;
    try testing.expectError(error.MalformedBoolean, parseBoolean(allocator, &.{0x01}));
    try testing.expectError(error.MalformedBoolean, parseBoolean(allocator, &.{ 0x00, 0x00 }));
}

test "invalid BIT STRING unused bits" {
    const allocator = testing.allocator;
    try testing.expectError(error.MalformedBitString, parseBitString(allocator, &.{}));
    try testing.expectError(error.MalformedBitString, parseBitString(allocator, &.{8}));
    try testing.expectError(error.MalformedBitString, parseBitString(allocator, &.{ 0x01, 0x03 }));
}

test "malformed OID and component overflow" {
    const allocator = testing.allocator;
    try testing.expectError(error.MalformedOid, parseOid(allocator, &.{}));
    try testing.expectError(error.MalformedOid, parseOid(allocator, &.{ 0x55, 0x80 }));
    // Non-minimal base128 for zero
    try testing.expectError(error.MalformedOid, parseOid(allocator, &.{ 0x55, 0x80, 0x00 }));
}

test "invalid time syntax" {
    const allocator = testing.allocator;
    try testing.expectError(error.MalformedTime, parseUtc(allocator, "24010100000"));
    try testing.expectError(error.MalformedTime, parseUtc(allocator, "2401010000Z"));
    try testing.expectError(error.MalformedTime, parseUtc(allocator, "240101000000"));
    try testing.expectError(error.MalformedTime, parseGen(allocator, "2024010100000Z"));
    try testing.expectError(error.MalformedTime, parseGen(allocator, "202401010000Z"));
}

test "diagnostic read captures typed error offsets" {
    try expectDiagnostic(&.{ 0x1f, 0x00, 0x00 }, error.InvalidTag, 1);
    try expectDiagnostic(&.{ 0x30, 0x82, 0x01 }, error.Truncated, 2);
    try expectDiagnostic(&.{ 0x04, 0x81, 0x01, 0x00 }, error.NonMinimalLength, 2);

    const child_boundary = [_]u8{ 0x30, 0x03, 0x04, 0x05, 0x00 };
    var reader = der.Reader.init(&child_boundary, der.default_limits);
    var child = try reader.readSequence();
    const diag = child.readElementDiagnostic();
    switch (diag) {
        .element => return error.TestExpectedError,
        .err => |parse_err| {
            try testing.expectEqual(error.LengthBeyondInput, parse_err.err);
            try testing.expectEqual(@as(usize, 4), parse_err.offset);
        },
    }
}

test "trailing bytes and child boundary escape" {
    const allocator = testing.allocator;
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.null), false), &.{});
    try b.buf.append(allocator, 0x00);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    try reader.readNull();
    try testing.expectError(error.TrailingData, reader.expectEnd());

    var seq_b = Builder.init();
    defer seq_b.deinit(allocator);
    try seq_b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), &.{});
    const seq_bytes = try seq_b.toOwnedSlice(allocator);
    defer allocator.free(seq_bytes);
    var seq_reader = der.Reader.init(seq_bytes, der.default_limits);
    var child = try seq_reader.readSequence();
    try child.expectEnd();
    try seq_reader.expectEnd();
}

test "empty and zero-length values" {
    const allocator = testing.allocator;
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true), &.{});
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.octet_string), false), &.{});
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    var seq = try reader.readSequence();
    try seq.expectEnd();
    try testing.expectEqual(@as(usize, 0), (try reader.readOctetString()).len);
    try reader.expectEnd();
}

test "length encode/decode round-trip" {
    const allocator = testing.allocator;
    const lengths = [_]usize{ 0, 1, 127, 128, 255, 256 };
    for (lengths) |len| {
        var content = std.ArrayList(u8).empty;
        defer content.deinit(allocator);
        try content.appendNTimes(allocator, 0, len);
        var b = Builder.init();
        defer b.deinit(allocator);
        try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.octet_string), false), content.items);
        const encoded = try b.toOwnedSlice(allocator);
        defer allocator.free(encoded);
        var reader = der.Reader.init(encoded, der.default_limits);
        const value = try reader.readOctetString();
        try testing.expectEqual(len, value.len);
        try reader.expectEnd();
    }
}

// Seeds promoted from PKI differential mismatch minimization (#348) join the
// hand-written corpus automatically.
const reduced_corpus_seeds = blk: {
    const reduced_corpus = @import("pki_reduced_corpus");
    var seeds: [reduced_corpus.entries.len][]const u8 = undefined;
    for (reduced_corpus.entries, &seeds) |entry, *seed| seed.* = entry.seed;
    break :blk seeds;
};

test "fuzz: DER parser never panics or leaks on arbitrary input" {
    try testing.fuzz({}, fuzzDerParse, .{ .corpus = &([_][]const u8{
        "",
        "\x30\x00",
        "\x02\x01\x01",
        "\x30\x80\x00\x00",
        "\x04\x81\x01\x00",
        "\x06\x03\x55\x04\x03",
        "\x17\x0d\x32\x34\x30\x36\x30\x31\x30\x30\x30\x30\x30\x30\x5a",
        "\x18\x0f\x32\x30\x32\x34\x30\x36\x30\x31\x30\x30\x30\x30\x30\x30\x5a",
        "\xa0\x03\x02\x01\x2a",
        @embedFile("pki_malformed_der"),
    } ++ reduced_corpus_seeds) });
}

fn fuzzDerParse(_: void, smith: *testing.Smith) !void {
    var buf: [8192]u8 = undefined;
    const len = smith.slice(&buf);
    der.fuzzParseInput(buf[0..len]);
}

test "reduced differential DER seeds keep their exact DER parse outcome" {
    const reduced_corpus = @import("pki_reduced_corpus");
    for (reduced_corpus.entries) |entry| {
        switch (entry.expected) {
            .der_parse_error => |expected| {
                var reader = der.Reader.init(entry.seed, der.default_limits);
                const expected_error = if (std.mem.eql(u8, expected, "NonMinimalLength"))
                    error.NonMinimalLength
                else
                    return error.TestUnexpectedResult;
                try testing.expectError(expected_error, reader.readElement());
            },
            else => {},
        }
    }
}

fn parseInteger(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.integer), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readInteger();
}

fn parseIntegerTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readInteger();
}

fn parseBoolean(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.boolean), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readBoolean();
}

fn parseBooleanTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readBoolean();
}

fn parseBitString(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.bit_string), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readBitString();
}

fn parseBitStringTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readBitString();
}

fn parseOid(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.object_identifier), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readObjectIdentifier();
}

fn parseOidTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readObjectIdentifier();
}

fn parseUtc(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.utc_time), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readUtcTime();
}

fn parseUtcTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readUtcTime();
}

fn parseGen(allocator: std.mem.Allocator, content: []const u8) !void {
    var b = Builder.init();
    defer b.deinit(allocator);
    try b.appendTlv(allocator, der.Tag.universal(@intFromEnum(der.UniversalTag.generalized_time), false), content);
    const encoded = try b.toOwnedSlice(allocator);
    defer allocator.free(encoded);
    var reader = der.Reader.init(encoded, der.default_limits);
    _ = try reader.readGeneralizedTime();
}

fn parseGenTlv(_: std.mem.Allocator, input: []const u8) !void {
    var reader = der.Reader.init(input, der.default_limits);
    _ = try reader.readGeneralizedTime();
}

fn expectDiagnostic(input: []const u8, expected_err: der.Error, expected_offset: usize) !void {
    var reader = der.Reader.init(input, der.default_limits);
    const diag = reader.readElementDiagnostic();
    switch (diag) {
        .element => return error.TestExpectedError,
        .err => |parse_err| {
            try testing.expectEqual(expected_err, parse_err.err);
            try testing.expectEqual(expected_offset, parse_err.offset);
        },
    }
}
