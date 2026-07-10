//! RFC 9218 Extensible Prioritization for HTTP/3 (#254): the `Priority` field
//! value model + parser/serializer, and PRIORITY_UPDATE payload helpers.
//!
//! This module is intentionally transport-free and scheduler-free. It models
//! the *hints* — urgency and the incremental flag — and the wire encodings, and
//! documents the default scheduling policy below. It does **not** implement a
//! scheduler, and deliberately does not recreate HTTP/2's dependency tree
//! (RFC 9218's whole point is to avoid that).
//!
//! ## `Priority` field value (RFC 9218 §4)
//!
//! The `priority` request/response header (and the PRIORITY_UPDATE field value)
//! is an RFC 8941 Structured Fields Dictionary with two defined members:
//!
//!   * `u` — urgency, an Integer in 0..7. Lower is more urgent. Default 3.
//!   * `i` — incremental, a Boolean. Default false. `i` (bare) means `i=?1`.
//!
//! Per RFC 9218 §4.1/§4.2, a known parameter whose value is out of range or the
//! wrong type MUST be ignored and the default used; unknown parameters are also
//! ignored. `parse` follows that leniently but records that it happened
//! (`Parsed.invalid_parameter` / `.duplicate_parameter`) so callers can count a
//! metric. Only genuinely malformed Dictionary *syntax* is a hard error
//! (`error.MalformedPriority`).
//!
//! ## Default scheduling policy (documented, not implemented here)
//!
//! When a scheduler is wired (follow-up, out of scope for #254's model layer),
//! the intended baseline — deliberately simple, per the issue — is:
//!
//!   1. Serve lower urgency values first (u=0 before u=7).
//!   2. Within one urgency band, streams marked incremental (`i`) are served
//!      round-robin so they make forward progress together; non-incremental
//!      streams in the band are served in stream-arrival (FIFO) order so a
//!      complete response is delivered before the next begins.
//!   3. Equal priority (same urgency, same incremental flag) is strictly
//!      FIFO/round-robin and never reorders, which keeps it fair and
//!      starvation-free.
//!
//! No adaptive or dependency-tree scheduling. That is an explicit non-goal.

const std = @import("std");

const varint = @import("quic_varint");
const frame = @import("frame.zig");

// ---------------------------------------------------------------------------
// Priority field value model (RFC 9218 §4)
// ---------------------------------------------------------------------------

pub const urgency_min: u8 = 0;
pub const urgency_max: u8 = 7;
pub const default_urgency: u3 = 3;
pub const default_incremental: bool = false;

/// A parsed, always-valid priority signal. `urgency` is a `u3` so an
/// out-of-range value is unrepresentable — the parser folds invalid input to
/// the default rather than storing it.
pub const Priority = struct {
    urgency: u3 = default_urgency,
    incremental: bool = default_incremental,

    /// The RFC 9218 defaults (u=3, i=false) used when the header is absent or a
    /// parameter is omitted/ignored.
    pub const default: Priority = .{};

    pub fn eql(self: Priority, other: Priority) bool {
        return self.urgency == other.urgency and self.incremental == other.incremental;
    }

    /// Serialize to a canonical RFC 8941 Dictionary value, omitting parameters
    /// that are at their default (so both-default yields ""). Booleans use the
    /// bare `i` form. Round-trips through `parse`. A 16-byte buffer is plenty.
    pub fn serialize(self: Priority, out: []u8) error{BufferTooShort}![]u8 {
        var pos: usize = 0;
        if (self.urgency != default_urgency) {
            pos += try writeStr(out, pos, "u=");
            if (pos >= out.len) return error.BufferTooShort;
            out[pos] = '0' + @as(u8, self.urgency);
            pos += 1;
        }
        if (self.incremental != default_incremental) {
            if (pos != 0) pos += try writeStr(out, pos, ", ");
            pos += try writeStr(out, pos, "i");
        }
        return out[0..pos];
    }
};

fn writeStr(out: []u8, pos: usize, str: []const u8) error{BufferTooShort}!usize {
    if (str.len > out.len - pos) return error.BufferTooShort;
    @memcpy(out[pos..][0..str.len], str);
    return str.len;
}

pub const ParseError = error{MalformedPriority};

/// Result of parsing a `priority` field value. `priority` always holds a valid
/// signal (defaults applied). The flags surface RFC-mandated leniency so a
/// caller can record a parse-quality metric without changing behavior.
pub const Parsed = struct {
    priority: Priority = .{},
    /// A known parameter (`u`/`i`) had an out-of-range or wrong-typed value and
    /// was ignored (RFC 9218 §4.1/§4.2), leaving the default in place.
    invalid_parameter: bool = false,
    /// A known parameter appeared more than once; per RFC 8941 the last
    /// occurrence wins. Reported for visibility.
    duplicate_parameter: bool = false,
};

/// Parse an RFC 9218 `priority` field value (also the PRIORITY_UPDATE field
/// value). Returns `error.MalformedPriority` only for malformed Dictionary
/// syntax; semantically-invalid known parameters are folded to defaults with
/// `Parsed.invalid_parameter` set.
pub fn parse(value: []const u8) ParseError!Parsed {
    var result = Parsed{};
    var seen_u = false;
    var seen_i = false;
    const s = value;
    var i: usize = 0;

    skipOws(s, &i);
    if (i >= s.len) return result; // empty dictionary → defaults

    while (true) {
        if (i >= s.len or !isKeyStart(s[i])) return error.MalformedPriority;
        const key_start = i;
        i += 1;
        while (i < s.len and isKeyChar(s[i])) i += 1;
        const key = s[key_start..i];

        var val: Value = .{ .boolean = true }; // a bare key is Boolean true
        if (i < s.len and s[i] == '=') {
            i += 1;
            val = try parseValue(s, &i);
        }

        if (std.mem.eql(u8, key, "u")) {
            if (seen_u) result.duplicate_parameter = true;
            seen_u = true;
            switch (val) {
                .integer => |n| {
                    if (n < urgency_min or n > urgency_max) {
                        result.invalid_parameter = true;
                    } else {
                        result.priority.urgency = @intCast(n);
                    }
                },
                else => result.invalid_parameter = true,
            }
        } else if (std.mem.eql(u8, key, "i")) {
            if (seen_i) result.duplicate_parameter = true;
            seen_i = true;
            switch (val) {
                .boolean => |b| result.priority.incremental = b,
                else => result.invalid_parameter = true,
            }
        } else {
            // Unknown parameter: parsed for structural correctness, then
            // ignored (RFC 9218 §4). Not a parse error.
        }

        skipOws(s, &i);
        if (i >= s.len) break;
        if (s[i] != ',') return error.MalformedPriority;
        i += 1;
        skipOws(s, &i);
        if (i >= s.len) return error.MalformedPriority; // trailing comma
    }

    return result;
}

// ---------------------------------------------------------------------------
// Minimal RFC 8941 bare-item value parsing (enough for u, i, and to skip
// unknown parameter values). Inner lists and member parameters are not used by
// the priority field and are treated as malformed.
// ---------------------------------------------------------------------------

const Value = union(enum) {
    integer: i64,
    boolean: bool,
    token: []const u8,
    string: []const u8,
};

fn parseValue(s: []const u8, i: *usize) ParseError!Value {
    if (i.* >= s.len) return error.MalformedPriority;
    const c = s[i.*];
    if (c == '?') {
        i.* += 1;
        if (i.* >= s.len) return error.MalformedPriority;
        const b = s[i.*];
        if (b != '0' and b != '1') return error.MalformedPriority;
        i.* += 1;
        return .{ .boolean = b == '1' };
    }
    if (c == '-' or isDigit(c)) return parseInteger(s, i);
    if (c == '"') return parseString(s, i);
    if (isAlpha(c) or c == '*') return parseToken(s, i);
    return error.MalformedPriority;
}

fn parseInteger(s: []const u8, i: *usize) ParseError!Value {
    var negative = false;
    if (s[i.*] == '-') {
        negative = true;
        i.* += 1;
    }
    var digits: usize = 0;
    var magnitude: i64 = 0;
    while (i.* < s.len and isDigit(s[i.*])) : (i.* += 1) {
        digits += 1;
        if (digits > 15) return error.MalformedPriority; // SF Integer: max 15 digits
        magnitude = magnitude * 10 + @as(i64, s[i.*] - '0');
    }
    if (digits == 0) return error.MalformedPriority;
    // A trailing '.' would make this a Decimal, which the priority field never
    // uses; reject rather than silently truncate.
    if (i.* < s.len and s[i.*] == '.') return error.MalformedPriority;
    return .{ .integer = if (negative) -magnitude else magnitude };
}

fn parseToken(s: []const u8, i: *usize) ParseError!Value {
    const start = i.*;
    i.* += 1; // first char already validated (ALPHA / '*')
    while (i.* < s.len and isTokenChar(s[i.*])) i.* += 1;
    return .{ .token = s[start..i.*] };
}

fn parseString(s: []const u8, i: *usize) ParseError!Value {
    const start = i.*;
    i.* += 1; // opening DQUOTE
    while (i.* < s.len) {
        const c = s[i.*];
        if (c == '\\') {
            i.* += 1;
            if (i.* >= s.len) return error.MalformedPriority;
            const escaped = s[i.*];
            if (escaped != '\\' and escaped != '"') return error.MalformedPriority;
            i.* += 1;
            continue;
        }
        if (c == '"') {
            i.* += 1;
            return .{ .string = s[start..i.*] };
        }
        if (c < 0x20 or c > 0x7e) return error.MalformedPriority;
        i.* += 1;
    }
    return error.MalformedPriority; // unterminated string
}

fn skipOws(s: []const u8, i: *usize) void {
    while (i.* < s.len and (s[i.*] == ' ' or s[i.*] == '\t')) i.* += 1;
}

fn isLcAlpha(c: u8) bool {
    return c >= 'a' and c <= 'z';
}
fn isAlpha(c: u8) bool {
    return isLcAlpha(c) or (c >= 'A' and c <= 'Z');
}
fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}
fn isKeyStart(c: u8) bool {
    return isLcAlpha(c) or c == '*';
}
fn isKeyChar(c: u8) bool {
    return isLcAlpha(c) or isDigit(c) or c == '_' or c == '-' or c == '.' or c == '*';
}
fn isTokenChar(c: u8) bool {
    if (isAlpha(c) or isDigit(c)) return true;
    return switch (c) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~', ':', '/' => true,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// PRIORITY_UPDATE payload helpers (RFC 9218 §7)
// ---------------------------------------------------------------------------
//
// PRIORITY_UPDATE Frame {
//   Type (i) = 0x0F0700 (request) or 0x0F0701 (push),
//   Length (i),
//   Prioritized Element ID (i),      // request stream ID or push ID
//   Priority Field Value (..),       // ASCII RFC 9218 field value, may be empty
// }
//
// The two variants differ only in the frame *type* (already defined in
// frame.zig); the payload layout is identical.

pub const Kind = enum { request, push };

pub fn frameType(kind: Kind) frame.FrameType {
    return switch (kind) {
        .request => .priority_update_request,
        .push => .priority_update_push,
    };
}

pub fn kindFromFrameType(typ: frame.FrameType) ?Kind {
    return switch (typ) {
        .priority_update_request => .request,
        .priority_update_push => .push,
        else => null,
    };
}

/// A decoded PRIORITY_UPDATE payload. `field_value` borrows the source bytes.
pub const Update = struct {
    element_id: u64,
    field_value: []const u8 = "",
};

pub const PayloadEncodeError = error{ ValueTooLarge, BufferTooShort };
pub const PayloadDecodeError = error{BufferTooShort};

/// Encode just the frame payload: `Prioritized Element ID` (varint) followed by
/// the `Priority Field Value` bytes. Returns the written slice.
pub fn encodePayload(update: Update, out: []u8) PayloadEncodeError![]u8 {
    var pos: usize = try varint.encode(update.element_id, out);
    if (update.field_value.len > out.len - pos) return error.BufferTooShort;
    @memcpy(out[pos..][0..update.field_value.len], update.field_value);
    pos += update.field_value.len;
    return out[0..pos];
}

/// Decode a PRIORITY_UPDATE frame payload into its element ID and (borrowed)
/// field value bytes. Parse the field value with `parse` if you need the model.
pub fn decodePayload(payload: []const u8) PayloadDecodeError!Update {
    const id = varint.decode(payload) catch return error.BufferTooShort;
    return .{ .element_id = id.value, .field_value = payload[id.len..] };
}

pub const FrameEncodeError = error{ ValueTooLarge, BufferTooShort };

/// Encode a complete PRIORITY_UPDATE frame (type + length + payload) for the
/// given variant, using the frame types already defined in `frame.zig`.
pub fn encodeFrame(kind: Kind, update: Update, out: []u8) FrameEncodeError![]u8 {
    const id_len = try varint.encodedLen(update.element_id);
    const payload_len = id_len + update.field_value.len;
    var pos: usize = try varint.encode(@intFromEnum(frameType(kind)), out);
    pos += try varint.encode(payload_len, out[pos..]);
    if (payload_len > out.len - pos) return error.BufferTooShort;
    pos += try varint.encode(update.element_id, out[pos..]);
    @memcpy(out[pos..][0..update.field_value.len], update.field_value);
    pos += update.field_value.len;
    return out[0..pos];
}

pub const DecodedFrame = struct {
    kind: Kind,
    update: Update,
};

pub const FrameDecodeError = frame.DecodeError || error{NotPriorityUpdate};

/// Decode a complete frame and, if it is a PRIORITY_UPDATE variant, return its
/// kind and payload. A non-PRIORITY_UPDATE frame is `error.NotPriorityUpdate`.
pub fn decodeFrame(bytes: []const u8) FrameDecodeError!DecodedFrame {
    const raw = try frame.decodeFrame(bytes);
    const kind = kindFromFrameType(raw.typ) orelse return error.NotPriorityUpdate;
    const update = try decodePayload(raw.payload);
    return .{ .kind = kind, .update = update };
}

// ---------------------------------------------------------------------------
// Metrics (model-layer counters; scheduler/session wiring is a follow-up)
// ---------------------------------------------------------------------------

/// Counters for priority observability (RFC 9218 §4 parse quality, updates).
/// Kept here at the model layer so the parser/frame helpers can feed them
/// before the scheduler exists; mirrors the per-module `Metrics` structs in
/// `src/quic`.
pub const Metrics = struct {
    priority_updates_encoded: u64 = 0,
    priority_updates_decoded: u64 = 0,
    parse_errors: u64 = 0,
    invalid_parameters: u64 = 0,
    duplicate_parameters: u64 = 0,

    /// Fold a `parse` outcome into the counters: a hard error bumps
    /// `parse_errors`, otherwise the leniency flags bump their counters.
    pub fn recordParse(self: *Metrics, outcome: ParseError!Parsed) void {
        const parsed = outcome catch {
            self.parse_errors += 1;
            return;
        };
        if (parsed.invalid_parameter) self.invalid_parameters += 1;
        if (parsed.duplicate_parameter) self.duplicate_parameters += 1;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parse defaults when header absent or parameters omitted" {
    try testing.expect((try parse("")).priority.eql(Priority.default));
    try testing.expect((try parse("   ")).priority.eql(Priority.default));
    const only_u = try parse("u=5");
    try testing.expectEqual(@as(u3, 5), only_u.priority.urgency);
    try testing.expectEqual(false, only_u.priority.incremental);
    const only_i = try parse("i");
    try testing.expectEqual(default_urgency, only_i.priority.urgency);
    try testing.expectEqual(true, only_i.priority.incremental);
}

test "parse urgency and incremental combinations" {
    const p1 = try parse("u=0, i");
    try testing.expectEqual(@as(u3, 0), p1.priority.urgency);
    try testing.expectEqual(true, p1.priority.incremental);

    const p2 = try parse("u=7,i"); // OWS around comma is optional
    try testing.expectEqual(@as(u3, 7), p2.priority.urgency);
    try testing.expectEqual(true, p2.priority.incremental);

    const p3 = try parse("u=2 ,  i=?0"); // explicit boolean false
    try testing.expectEqual(@as(u3, 2), p3.priority.urgency);
    try testing.expectEqual(false, p3.priority.incremental);

    const p4 = try parse("i=?1");
    try testing.expectEqual(true, p4.priority.incremental);

    const p5 = try parse("u=03"); // leading zero is a valid SF integer
    try testing.expectEqual(@as(u3, 3), p5.priority.urgency);
}

test "parse ignores invalid known parameters and flags them" {
    const over = try parse("u=8");
    try testing.expectEqual(default_urgency, over.priority.urgency);
    try testing.expect(over.invalid_parameter);

    const negative = try parse("u=-1");
    try testing.expectEqual(default_urgency, negative.priority.urgency);
    try testing.expect(negative.invalid_parameter);

    const wrong_u = try parse("u=?1"); // boolean where integer expected
    try testing.expectEqual(default_urgency, wrong_u.priority.urgency);
    try testing.expect(wrong_u.invalid_parameter);

    const wrong_i = try parse("i=5"); // integer where boolean expected
    try testing.expectEqual(default_incremental, wrong_i.priority.incremental);
    try testing.expect(wrong_i.invalid_parameter);
}

test "parse keeps last value for duplicate parameters and flags it" {
    const dup = try parse("u=1, u=6");
    try testing.expectEqual(@as(u3, 6), dup.priority.urgency);
    try testing.expect(dup.duplicate_parameter);
}

test "parse ignores unknown parameters without error" {
    const p = try parse("a=42, u=5, b=?1, c=tok, d=\"x,y\"");
    try testing.expectEqual(@as(u3, 5), p.priority.urgency);
    try testing.expect(!p.invalid_parameter);
}

test "parse rejects malformed dictionary syntax" {
    try testing.expectError(error.MalformedPriority, parse("=5"));
    try testing.expectError(error.MalformedPriority, parse("u="));
    try testing.expectError(error.MalformedPriority, parse("u=5,"));
    try testing.expectError(error.MalformedPriority, parse(",u=5"));
    try testing.expectError(error.MalformedPriority, parse("u=5 x"));
    try testing.expectError(error.MalformedPriority, parse("u=1.5"));
    try testing.expectError(error.MalformedPriority, parse("!bad"));
    try testing.expectError(error.MalformedPriority, parse("u=-"));
    try testing.expectError(error.MalformedPriority, parse("a=\"unterminated"));
}

test "serialize omits defaults and round-trips through parse" {
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("", try Priority.default.serialize(&buf));
    try testing.expectEqualStrings("u=5", try (Priority{ .urgency = 5 }).serialize(&buf));
    try testing.expectEqualStrings("i", try (Priority{ .incremental = true }).serialize(&buf));
    try testing.expectEqualStrings("u=0, i", try (Priority{ .urgency = 0, .incremental = true }).serialize(&buf));

    var u: u3 = 0;
    while (true) : (u += 1) {
        for ([_]bool{ false, true }) |inc| {
            const original = Priority{ .urgency = u, .incremental = inc };
            const text = try original.serialize(&buf);
            const round = try parse(text);
            try testing.expect(round.priority.eql(original));
        }
        if (u == urgency_max) break;
    }
}

test "PRIORITY_UPDATE payload round-trips element id and field value" {
    var buf: [64]u8 = undefined;
    const payload = try encodePayload(.{ .element_id = 0x3fff_ffff, .field_value = "u=2, i" }, &buf);
    const decoded = try decodePayload(payload);
    try testing.expectEqual(@as(u64, 0x3fff_ffff), decoded.element_id);
    try testing.expectEqualStrings("u=2, i", decoded.field_value);

    // Empty field value is valid (peer requests the default priority).
    const empty = try encodePayload(.{ .element_id = 4 }, &buf);
    const decoded_empty = try decodePayload(empty);
    try testing.expectEqual(@as(u64, 4), decoded_empty.element_id);
    try testing.expectEqualStrings("", decoded_empty.field_value);

    try testing.expectError(error.BufferTooShort, decodePayload(""));
}

test "PRIORITY_UPDATE frame round-trips for request and push variants" {
    var buf: [64]u8 = undefined;
    inline for (.{ Kind.request, Kind.push }) |kind| {
        const bytes = try encodeFrame(kind, .{ .element_id = 8, .field_value = "u=1" }, &buf);

        const raw = try frame.decodeFrame(bytes);
        try testing.expectEqual(frameType(kind), raw.typ);

        const decoded = try decodeFrame(bytes);
        try testing.expectEqual(kind, decoded.kind);
        try testing.expectEqual(@as(u64, 8), decoded.update.element_id);
        try testing.expectEqualStrings("u=1", decoded.update.field_value);

        const model = try parse(decoded.update.field_value);
        try testing.expectEqual(@as(u3, 1), model.priority.urgency);
    }
}

test "decodeFrame rejects non-PRIORITY_UPDATE frames" {
    var buf: [32]u8 = undefined;
    const headers = try frame.encodeKnownFrame(.headers, "abc", &buf);
    try testing.expectError(error.NotPriorityUpdate, decodeFrame(headers));
}

test "metrics fold parse outcomes" {
    var metrics = Metrics{};
    metrics.recordParse(parse("u=5"));
    metrics.recordParse(parse("u=8")); // invalid parameter
    metrics.recordParse(parse("u=1, u=2")); // duplicate parameter
    metrics.recordParse(parse("u=5,")); // hard error
    try testing.expectEqual(@as(u64, 1), metrics.invalid_parameters);
    try testing.expectEqual(@as(u64, 1), metrics.duplicate_parameters);
    try testing.expectEqual(@as(u64, 1), metrics.parse_errors);
}

test {
    std.testing.refAllDecls(@This());
}
