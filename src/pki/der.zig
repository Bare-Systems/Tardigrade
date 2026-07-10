//! Bounded ASN.1 DER decoder for X.509 (#339).
//!
//! ## Supported subset
//!
//! Universal types used by X.509: SEQUENCE, SET, INTEGER, BOOLEAN, BIT STRING,
//! OCTET STRING, NULL, OBJECT IDENTIFIER, UTF8String, PrintableString, IA5String,
//! BMPString, UTCTime, GeneralizedTime; plus context-specific explicit and
//! implicit tags.
//!
//! ## DER-only policy
//!
//! Definite lengths only. BER indefinite lengths, non-minimal length encodings,
//! and non-minimal INTEGER encodings are rejected. Malformed input is never
//! silently normalized.
//!
//! ## Default limits
//!
//! See `Limits`: 32 nesting depth, 1 MiB per element, 4096 elements per parse
//! tree, 32 OID components, 4096 integer bytes.
//!
//! ## Ownership and zero-copy
//!
//! `Reader` and `Element` hold borrowed slices into the caller-supplied input.
//! The caller owns the backing buffer for the parser lifetime. Typed decoders
//! return views (`IntegerView`, `BitStringView`, string slices) without copying
//! untrusted content. Never allocate directly from an unchecked attacker length.
//!
//! ## Complete consumption
//!
//! Call `expectEnd` after parsing a bounded region to reject trailing bytes.
//! Child readers from `readSequence` / `readSet` enforce their own boundaries.
//!
//! ## Intentionally unsupported
//!
//! BER indefinite length, SET OF sorting requirements, REAL, EXTERNAL, EMBEDDED
//! PDV, unrestricted ANY, and non-DER string encodings.
//!
//! ## Consumers
//!
//! #340 (PEM/chain loading) should wrap DER blobs in `Reader` and enforce
//! `expectEnd`. #341 (X.509 certificate model) should walk TBSCertificate and
//! extension sequences via child readers and typed decoders defined here.

const std = @import("std");
const oid_mod = @import("oid.zig");
const time_mod = @import("time.zig");

pub const oid = oid_mod;
pub const time = time_mod;

/// Configurable parser resource bounds.
pub const Limits = struct {
    max_depth: usize = 32,
    max_element_len: usize = 1024 * 1024,
    max_elements: usize = 4096,
    max_oid_components: usize = 32,
    max_integer_bytes: usize = 4096,
};

pub const default_limits: Limits = .{};

pub const TagClass = enum(u2) {
    universal = 0,
    application = 1,
    context_specific = 2,
    private = 3,
};

pub const UniversalTag = enum(u32) {
    end_of_content = 0,
    boolean = 1,
    integer = 2,
    bit_string = 3,
    octet_string = 4,
    null = 5,
    object_identifier = 6,
    utf8_string = 12,
    sequence = 16,
    set = 17,
    printable_string = 19,
    ia5_string = 22,
    utc_time = 23,
    generalized_time = 24,
    bmp_string = 30,
};

pub const Tag = struct {
    class: TagClass,
    number: u32,
    constructed: bool,

    pub fn universal(number: u32, constructed: bool) Tag {
        return .{ .class = .universal, .number = number, .constructed = constructed };
    }

    pub fn contextSpecific(number: u32, constructed: bool) Tag {
        return .{ .class = .context_specific, .number = number, .constructed = constructed };
    }

    pub fn eql(self: Tag, other: Tag) bool {
        return self.class == other.class and self.number == other.number and
            self.constructed == other.constructed;
    }
};

pub const Element = struct {
    tag: Tag,
    /// Full TLV bytes (tag + length + content) within the parent input slice.
    encoded: []const u8,
    /// Value bytes only.
    content: []const u8,
    /// Absolute offset of `content` in the root input slice.
    content_offset: usize,
};

pub const IntegerView = struct {
    /// Validated minimal big-endian two's-complement encoding.
    content: []const u8,

    pub fn isNegative(self: IntegerView) bool {
        return self.content.len > 0 and (self.content[0] & 0x80) != 0;
    }

    pub fn isZero(self: IntegerView) bool {
        return self.content.len == 1 and self.content[0] == 0;
    }
};

pub const BitStringView = struct {
    unused_bits: u3,
    /// Payload bits excluding the leading unused-bits octet.
    data: []const u8,
};

pub const Error = error{
    Truncated,
    InvalidTag,
    InvalidLength,
    NonMinimalLength,
    IndefiniteLength,
    LengthOverflow,
    LengthBeyondInput,
    NestingLimit,
    ElementCountLimit,
    UnexpectedTag,
    MalformedInteger,
    MalformedBoolean,
    MalformedBitString,
    MalformedOid,
    MalformedString,
    MalformedTime,
    TrailingData,
} || oid_mod.Error || time_mod.Error;

pub const ParseError = struct {
    err: Error,
    /// Absolute offset of the offending byte when known, otherwise the tag
    /// start for the element whose parse failed.
    offset: usize,
};

pub const DiagnosticElement = union(enum) {
    element: Element,
    err: ParseError,
};

pub const Reader = struct {
    input: []const u8,
    start: usize,
    end: usize,
    offset: usize,
    depth: usize,
    element_count: usize,
    shared_element_count: ?*usize,
    last_error_offset: ?usize,
    limits: Limits,

    pub fn init(input: []const u8, limits: Limits) Reader {
        return .{
            .input = input,
            .start = 0,
            .end = input.len,
            .offset = 0,
            .depth = 0,
            .element_count = 0,
            .shared_element_count = null,
            .last_error_offset = null,
            .limits = limits,
        };
    }

    pub fn initBounded(input: []const u8, start: usize, end: usize, depth: usize, element_count: usize, shared_element_count: ?*usize, limits: Limits) Reader {
        return .{
            .input = input,
            .start = start,
            .end = end,
            .offset = start,
            .depth = depth,
            .element_count = element_count,
            .shared_element_count = shared_element_count,
            .last_error_offset = null,
            .limits = limits,
        };
    }

    pub fn remaining(self: *const Reader) usize {
        return self.end - self.offset;
    }

    pub fn currentOffset(self: *const Reader) usize {
        return self.offset;
    }

    pub fn readElement(self: *Reader) Error!Element {
        if (self.currentElementCount() >= self.limits.max_elements) return self.fail(error.ElementCountLimit, self.offset);
        const elem_start = self.offset;
        const tag = try self.readTag();
        if (tag.class == .universal and tag.number == @intFromEnum(UniversalTag.end_of_content)) {
            return self.fail(error.InvalidTag, elem_start);
        }
        const content_len = try self.readDefiniteLength();
        if (content_len > self.remaining()) return self.fail(error.LengthBeyondInput, self.offset);
        const content_start = self.offset;
        const content_end = content_start + content_len;
        self.offset = content_end;
        self.incrementElementCount();
        return .{
            .tag = tag,
            .encoded = self.input[elem_start..content_end],
            .content = self.input[content_start..content_end],
            .content_offset = content_start,
        };
    }

    /// Parse one element and capture typed error plus offset. The offset is the
    /// offending byte when the low-level decoder can identify it; otherwise it
    /// is the tag start for the element being parsed.
    pub fn readElementDiagnostic(self: *Reader) DiagnosticElement {
        const elem_start = self.offset;
        const elem = self.readElement() catch |err| {
            return .{ .err = .{ .err = err, .offset = self.last_error_offset orelse elem_start } };
        };
        return .{ .element = elem };
    }

    pub fn readSequence(self: *Reader) Error!Reader {
        const elem = try self.readElement();
        try self.expectUniversalTag(elem, .sequence, true);
        return self.childReader(elem.content_offset, elem.content.len);
    }

    pub fn readSet(self: *Reader) Error!Reader {
        const elem = try self.readElement();
        try self.expectUniversalTag(elem, .set, true);
        return self.childReader(elem.content_offset, elem.content.len);
    }

    pub fn childReader(self: *Reader, content_offset: usize, content_len: usize) Error!Reader {
        if (self.depth >= self.limits.max_depth) return self.fail(error.NestingLimit, content_offset);
        const end = content_offset + content_len;
        if (content_offset < self.start or end > self.end) return self.fail(error.LengthBeyondInput, content_offset);
        const shared_count = self.shared_element_count orelse &self.element_count;
        return Reader.initBounded(self.input, content_offset, end, self.depth + 1, self.currentElementCount(), shared_count, self.limits);
    }

    pub fn expectEnd(self: *const Reader) Error!void {
        if (self.offset != self.end) return error.TrailingData;
    }

    pub fn expectTag(self: *Reader, expected: Tag) Error!Element {
        const elem = try self.readElement();
        if (!elem.tag.eql(expected)) return error.UnexpectedTag;
        return elem;
    }

    pub fn readContextSpecific(self: *Reader, number: u32, constructed: bool) Error!Element {
        const elem = try self.readElement();
        if (elem.tag.class != .context_specific or elem.tag.number != number or elem.tag.constructed != constructed) {
            return error.UnexpectedTag;
        }
        return elem;
    }

    /// Explicit context tag: outer constructed wrapper around one inner element.
    pub fn readExplicitContext(self: *Reader, number: u32) Error!Element {
        const wrapper = try self.readContextSpecific(number, true);
        var inner = try self.childReader(wrapper.content_offset, wrapper.content.len);
        const elem = try inner.readElement();
        try inner.expectEnd();
        return elem;
    }

    pub fn readInteger(self: *Reader) Error!IntegerView {
        const elem = try self.readElement();
        try self.expectUniversalTag(elem, .integer, false);
        try validateInteger(elem.content, self.limits.max_integer_bytes);
        return .{ .content = elem.content };
    }

    pub fn readBoolean(self: *Reader) Error!bool {
        const elem = try self.readElement();
        try self.expectUniversalTag(elem, .boolean, false);
        if (elem.content.len != 1) return error.MalformedBoolean;
        return switch (elem.content[0]) {
            0x00 => false,
            0xff => true,
            else => error.MalformedBoolean,
        };
    }

    pub fn readNull(self: *Reader) Error!void {
        const elem = try self.readElement();
        try self.expectUniversalTag(elem, .null, false);
        if (elem.content.len != 0) return error.UnexpectedTag;
    }

    pub fn readOctetString(self: *Reader) Error![]const u8 {
        const elem = try self.readElement();
        try self.expectUniversalTag(elem, .octet_string, false);
        return elem.content;
    }

    pub fn readBitString(self: *Reader) Error!BitStringView {
        const elem = try self.readElement();
        try self.expectUniversalTag(elem, .bit_string, false);
        return decodeBitStringContent(elem.content);
    }

    pub fn readObjectIdentifier(self: *Reader) Error!oid_mod.ObjectIdentifier {
        const elem = try self.readElement();
        try self.expectUniversalTag(elem, .object_identifier, false);
        return oid_mod.decode(elem.content, self.limits.max_oid_components);
    }

    pub fn readUtf8String(self: *Reader) Error![]const u8 {
        const content = try self.readStringElement(.utf8_string);
        try validateUtf8(content);
        return content;
    }

    pub fn readPrintableString(self: *Reader) Error![]const u8 {
        const content = try self.readStringElement(.printable_string);
        try validatePrintableString(content);
        return content;
    }

    pub fn readIa5String(self: *Reader) Error![]const u8 {
        const content = try self.readStringElement(.ia5_string);
        try validateIa5String(content);
        return content;
    }

    pub fn readBmpString(self: *Reader) Error![]const u8 {
        const content = try self.readStringElement(.bmp_string);
        try validateBmpString(content);
        return content;
    }

    pub fn readUtcTime(self: *Reader) Error!time_mod.UtcTime {
        const elem = try self.readElement();
        try self.expectUniversalTag(elem, .utc_time, false);
        return time_mod.parseUtcTime(elem.content);
    }

    pub fn readGeneralizedTime(self: *Reader) Error!time_mod.GeneralizedTime {
        const elem = try self.readElement();
        try self.expectUniversalTag(elem, .generalized_time, false);
        return time_mod.parseGeneralizedTime(elem.content);
    }

    fn readStringElement(self: *Reader, tag_number: UniversalTag) Error![]const u8 {
        const elem = try self.readElement();
        try self.expectUniversalTag(elem, tag_number, false);
        return elem.content;
    }

    fn readTag(self: *Reader) Error!Tag {
        if (self.remaining() == 0) return self.fail(error.Truncated, self.offset);
        const first = self.input[self.offset];
        self.offset += 1;

        const class: TagClass = @enumFromInt(first >> 6);
        const constructed = (first & 0x20) != 0;
        var number: u32 = first & 0x1f;

        if (number == 0x1f) {
            number = 0;
            var continuation_bytes: usize = 0;
            while (true) {
                if (self.remaining() == 0) return self.fail(error.Truncated, self.offset);
                const b = self.input[self.offset];
                self.offset += 1;
                if (continuation_bytes == 0 and b == 0x80) return self.fail(error.InvalidTag, self.offset - 1);
                const chunk: u32 = b & 0x7f;
                if (number > (std.math.maxInt(u32) >> 7)) return self.fail(error.InvalidTag, self.offset - 1);
                number = (number << 7) | chunk;
                if (b & 0x80 == 0) break;
                continuation_bytes += 1;
                if (continuation_bytes > 4) return self.fail(error.InvalidTag, self.offset - 1);
            }
            if (number < 31) return self.fail(error.InvalidTag, self.offset - 1);
        }

        return .{ .class = class, .number = number, .constructed = constructed };
    }

    fn readDefiniteLength(self: *Reader) Error!usize {
        if (self.remaining() == 0) return self.fail(error.Truncated, self.offset);
        const first = self.input[self.offset];
        self.offset += 1;

        if (first & 0x80 == 0) {
            if (first > self.limits.max_element_len) return self.fail(error.LengthOverflow, self.offset - 1);
            return first;
        }

        const num_bytes = first & 0x7f;
        if (num_bytes == 0) return self.fail(error.IndefiniteLength, self.offset - 1);
        if (num_bytes > 8) return self.fail(error.InvalidLength, self.offset - 1);
        if (self.remaining() < num_bytes) return self.fail(error.Truncated, self.offset);

        var length: u64 = 0;
        var i: usize = 0;
        while (i < num_bytes) : (i += 1) {
            length = (length << 8) | self.input[self.offset + i];
        }
        if (length < 128) return self.fail(error.NonMinimalLength, self.offset);
        if (length > self.limits.max_element_len) return self.fail(error.LengthOverflow, self.offset);

        const first_len_byte = self.input[self.offset];
        if (num_bytes > 1 and first_len_byte == 0) return self.fail(error.NonMinimalLength, self.offset);
        const minimal_bytes = minimalLengthBytes(length);
        if (num_bytes != minimal_bytes) return self.fail(error.NonMinimalLength, self.offset);

        self.offset += num_bytes;
        const len: usize = @intCast(length);
        if (len > self.remaining()) return self.fail(error.LengthBeyondInput, self.offset);
        return len;
    }

    fn currentElementCount(self: *const Reader) usize {
        if (self.shared_element_count) |count| return count.*;
        return self.element_count;
    }

    fn incrementElementCount(self: *Reader) void {
        if (self.shared_element_count) |count| {
            count.* += 1;
        } else {
            self.element_count += 1;
        }
    }

    fn expectUniversalTag(self: *Reader, elem: Element, tag_number: UniversalTag, constructed: bool) Error!void {
        if (elem.tag.class != .universal or elem.tag.number != @intFromEnum(tag_number) or elem.tag.constructed != constructed) {
            const header_len = elem.encoded.len - elem.content.len;
            return self.fail(error.UnexpectedTag, elem.content_offset - header_len);
        }
    }

    fn fail(self: *Reader, err: Error, offset: usize) Error {
        self.last_error_offset = offset;
        return err;
    }
};

fn minimalLengthBytes(length: u64) usize {
    if (length < 128) return 0;
    var bytes: usize = 0;
    var value = length;
    while (value > 0) : (bytes += 1) {
        value >>= 8;
    }
    return bytes;
}

pub fn validateInteger(content: []const u8, max_bytes: usize) Error!void {
    if (content.len == 0) return error.MalformedInteger;
    if (content.len > max_bytes) return error.MalformedInteger;
    if (content.len > 1) {
        const first = content[0];
        const second = content[1];
        if ((first == 0x00 and (second & 0x80) == 0) or (first == 0xff and (second & 0x80) != 0)) {
            return error.MalformedInteger;
        }
    }
}

pub fn decodeBitStringContent(content: []const u8) Error!BitStringView {
    if (content.len == 0) return error.MalformedBitString;
    if (content[0] > 7) return error.MalformedBitString;
    const unused_bits: u3 = @intCast(content[0]);
    const data = content[1..];
    if (data.len == 0 and unused_bits != 0) return error.MalformedBitString;
    if (data.len > 0 and unused_bits > 0) {
        const mask: u8 = @truncate((@as(u16, 1) << @intCast(unused_bits)) - 1);
        if (data[data.len - 1] & mask != 0) return error.MalformedBitString;
    }
    return .{ .unused_bits = unused_bits, .data = data };
}

pub fn validateUtf8(content: []const u8) Error!void {
    if (std.unicode.utf8ValidateSlice(content)) return;
    return error.MalformedString;
}

pub fn validatePrintableString(content: []const u8) Error!void {
    for (content) |c| {
        if (!isPrintableChar(c)) return error.MalformedString;
    }
}

fn isPrintableChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or
        (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or
        c == ' ' or c == '\'' or c == '(' or c == ')' or
        c == '+' or c == ',' or c == '-' or c == '.' or
        c == '/' or c == ':' or c == '=' or c == '?';
}

pub fn validateIa5String(content: []const u8) Error!void {
    for (content) |c| {
        if (c > 0x7f) return error.MalformedString;
    }
}

pub fn validateBmpString(content: []const u8) Error!void {
    if (@rem(content.len, 2) != 0) return error.MalformedString;
    var i: usize = 0;
    while (i < content.len) : (i += 2) {
        const unit = std.mem.readInt(u16, content[i..][0..2], .big);
        if (unit >= 0xd800 and unit <= 0xdfff) return error.MalformedString;
        if (unit >= 0xfdd0 and unit <= 0xfdef) return error.MalformedString;
        if (unit == 0xfffe or unit == 0xffff) return error.MalformedString;
    }
}

/// Canonical DER length encoding for round-trip tests.
pub fn encodeLength(length: usize, out: []u8) Error!usize {
    if (length < 128) {
        if (out.len == 0) return error.Truncated;
        out[0] = @intCast(length);
        return 1;
    }
    var tmp: [8]u8 = undefined;
    var value = length;
    var nbytes: usize = 0;
    while (value > 0) {
        tmp[7 - nbytes] = @intCast(value & 0xff);
        value >>= 8;
        nbytes += 1;
    }
    if (out.len < 1 + nbytes) return error.Truncated;
    out[0] = @intCast(0x80 | nbytes);
    @memcpy(out[1 .. 1 + nbytes], tmp[8 - nbytes ..][0..nbytes]);
    return 1 + nbytes;
}

pub fn encodeTag(tag: Tag, out: []u8) Error!usize {
    var first: u8 = @as(u8, @intFromEnum(tag.class)) * 0x40;
    if (tag.constructed) first |= 0x20;
    if (tag.number < 31) {
        if (out.len == 0) return error.Truncated;
        out[0] = first | @as(u8, @intCast(tag.number));
        return 1;
    }
    if (out.len == 0) return error.Truncated;
    out[0] = first | 0x1f;
    var written: usize = 1;
    var stack: [5]u8 = undefined;
    var value = tag.number;
    var count: usize = 0;
    while (value > 0) : (count += 1) {
        stack[count] = @intCast(value & 0x7f);
        value >>= 7;
    }
    var i: usize = 0;
    while (i < count - 1) : (i += 1) {
        if (written >= out.len) return error.Truncated;
        out[written] = stack[count - 1 - i] | 0x80;
        written += 1;
    }
    if (written >= out.len) return error.Truncated;
    out[written] = stack[0];
    written += 1;
    return written;
}

/// Fuzz and regression entrypoint (#376): parse arbitrary bytes under strict
/// limits without I/O, panics, or unbounded allocation.
pub fn fuzzParseInput(input: []const u8) void {
    var reader = Reader.init(input, .{
        .max_depth = 8,
        .max_element_len = 4096,
        .max_elements = 64,
        .max_oid_components = 16,
        .max_integer_bytes = 256,
    });
    fuzzParseReader(&reader) catch {};
}

fn fuzzParseReader(reader: *Reader) Error!void {
    while (reader.remaining() > 0) {
        const elem = reader.readElement() catch return;
        if (elem.tag.constructed and elem.tag.class == .universal and
            (elem.tag.number == @intFromEnum(UniversalTag.sequence) or elem.tag.number == @intFromEnum(UniversalTag.set)))
        {
            var child = try reader.childReader(elem.content_offset, elem.content.len);
            try fuzzParseReader(&child);
            try child.expectEnd();
        } else if (elem.tag.class == .universal) {
            switch (elem.tag.number) {
                @intFromEnum(UniversalTag.integer) => try validateInteger(elem.content, reader.limits.max_integer_bytes),
                @intFromEnum(UniversalTag.boolean) => {
                    if (elem.content.len != 1 or (elem.content[0] != 0 and elem.content[0] != 0xff)) return error.MalformedBoolean;
                },
                @intFromEnum(UniversalTag.bit_string) => _ = try decodeBitStringContent(elem.content),
                @intFromEnum(UniversalTag.object_identifier) => _ = try oid_mod.decode(elem.content, reader.limits.max_oid_components),
                @intFromEnum(UniversalTag.utc_time) => _ = try time_mod.parseUtcTime(elem.content),
                @intFromEnum(UniversalTag.generalized_time) => _ = try time_mod.parseGeneralizedTime(elem.content),
                @intFromEnum(UniversalTag.utf8_string) => try validateUtf8(elem.content),
                @intFromEnum(UniversalTag.printable_string) => try validatePrintableString(elem.content),
                @intFromEnum(UniversalTag.ia5_string) => try validateIa5String(elem.content),
                @intFromEnum(UniversalTag.bmp_string) => try validateBmpString(elem.content),
                else => {},
            }
        }
    }
}

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
