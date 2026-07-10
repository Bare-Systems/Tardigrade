//! RFC 9218 Extensible Prioritization for HTTP/3 (#254): the `priority` field
//! value model + parser/serializer, and PRIORITY_UPDATE payload helpers.
//!
//! This module is intentionally transport-free and scheduler-free. It models
//! the *hints* — urgency and the incremental flag — and the wire encodings, and
//! documents the default scheduling policy below. It does **not** implement a
//! scheduler, and deliberately does not recreate HTTP/2's dependency tree
//! (RFC 9218's whole point is to avoid that).
//!
//! ## `priority` field value (RFC 9218 §4)
//!
//! The `priority` request/response header (and the PRIORITY_UPDATE field value)
//! is an RFC 8941 Structured Fields Dictionary with two defined members:
//!
//!   * `u` — urgency, an Integer in 0..7. Lower is more urgent. Default 3.
//!   * `i` — incremental, a Boolean. Default false. `i` (bare) means `i=?1`.
//!
//! Parsing follows RFC 9218 §4 exactly: parse the *whole* Dictionary as RFC
//! 8941 (so unknown members and otherwise-valid Structured Fields syntax —
//! Decimals, Byte Sequences, Inner Lists, Item parameters — are accepted), then
//! keep only the last occurrence of each key (RFC 8941 duplicate handling), then
//! ignore any known member whose final value is out of range or the wrong type,
//! falling back to the default. `parse` records that leniency
//! (`Parsed.invalid_parameter` / `.duplicate_parameter`) for metrics. Only
//! genuinely malformed Structured Fields *syntax* is a hard
//! `error.MalformedPriority` (the caller should then ignore the field and use
//! defaults, per RFC 9218 §4.1).
//!
//! ### Member presence vs. effective value (RFC 9218 §8)
//!
//! Request/PRIORITY_UPDATE and response semantics differ: in a response, an
//! omitted parameter means "keep the client-provided value", not "use the
//! default". So the wire model (`Field`) preserves *presence* — `urgency` and
//! `incremental` are optional, and a value is present only if a valid one was
//! given. `Field.serialize` emits exactly the members that are present, so a
//! response can explicitly send `u=3` to reset urgency to the default. The
//! defaults-applied, always-valid view used by a scheduler is `Priority`, via
//! `Field.effective()`.
//!
//! ## Default scheduling policy (documented, not implemented here)
//!
//! When a scheduler is wired (follow-up, out of scope for #254's model layer),
//! the intended baseline — deliberately simple, per the issue — is:
//!
//!   1. Serve lower urgency values first (u=0 before u=7).
//!   2. Within one urgency band, share the connection across all ready
//!      responses using a **bounded quantum / round-robin**, not run-to-
//!      completion. RFC 9218 §10 warns that serving a non-incremental response
//!      strictly to completion can starve its peers — a large or unbounded body
//!      (e.g. a tunnel) would otherwise block everything else at that urgency.
//!      Incremental (`i`) responses interleave naturally; non-incremental ones
//!      each get a bounded turn so every response makes forward progress.
//!
//! This module makes no starvation-freedom guarantee on its own — fairness is
//! the scheduler's responsibility via that bounded quantum. No adaptive or
//! dependency-tree scheduling; those are explicit non-goals.

const std = @import("std");

const varint = @import("quic_varint");
const frame = @import("frame.zig");

// ---------------------------------------------------------------------------
// Priority field value model (RFC 9218 §4, §8)
// ---------------------------------------------------------------------------

pub const urgency_min: u8 = 0;
pub const urgency_max: u8 = 7;
pub const default_urgency: u3 = 3;
pub const default_incremental: bool = false;

/// The defaults-applied, always-valid priority signal a scheduler consumes.
pub const Priority = struct {
    urgency: u3 = default_urgency,
    incremental: bool = default_incremental,

    /// The RFC 9218 defaults (u=3, i=false).
    pub const default: Priority = .{};

    pub fn eql(self: Priority, other: Priority) bool {
        return self.urgency == other.urgency and self.incremental == other.incremental;
    }
};

/// The wire view of a `priority` field value, preserving member *presence*
/// (RFC 9218 §8): a `null` member was omitted (or was invalid and ignored),
/// which a response reader must treat as "unchanged" rather than "default".
pub const Field = struct {
    urgency: ?u3 = null,
    incremental: ?bool = null,

    /// Collapse to the always-valid scheduler view, applying RFC 9218 defaults
    /// for any omitted member.
    pub fn effective(self: Field) Priority {
        return .{
            .urgency = self.urgency orelse default_urgency,
            .incremental = self.incremental orelse default_incremental,
        };
    }

    pub fn eql(self: Field, other: Field) bool {
        const u_eq = (self.urgency == null and other.urgency == null) or
            (self.urgency != null and other.urgency != null and self.urgency.? == other.urgency.?);
        const i_eq = (self.incremental == null and other.incremental == null) or
            (self.incremental != null and other.incremental != null and self.incremental.? == other.incremental.?);
        return u_eq and i_eq;
    }

    /// Serialize exactly the members that are present, as a canonical RFC 8941
    /// Dictionary value (bare `i` for incremental true, `i=?0` for false). An
    /// all-`null` field serializes to "". Round-trips through `parse`. A 16-byte
    /// buffer is plenty.
    pub fn serialize(self: Field, out: []u8) error{BufferTooShort}![]u8 {
        var pos: usize = 0;
        if (self.urgency) |u| {
            pos += try writeStr(out, pos, "u=");
            if (pos >= out.len) return error.BufferTooShort;
            out[pos] = '0' + @as(u8, u);
            pos += 1;
        }
        if (self.incremental) |inc| {
            if (pos != 0) pos += try writeStr(out, pos, ", ");
            pos += try writeStr(out, pos, if (inc) "i" else "i=?0");
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

/// Result of parsing a `priority` field value. `field` preserves member
/// presence; the flags surface RFC-mandated leniency so a caller can record a
/// parse-quality metric without changing behavior.
pub const Parsed = struct {
    field: Field = .{},
    /// A known parameter (`u`/`i`) had, as its *final* value, an out-of-range or
    /// wrong-typed value and was ignored (RFC 9218 §4.1/§4.2), leaving the
    /// member omitted.
    invalid_parameter: bool = false,
    /// A known parameter appeared more than once; per RFC 8941 only the last
    /// occurrence is kept (and then validated). Reported for visibility.
    duplicate_parameter: bool = false,

    /// Convenience: the defaults-applied scheduler view.
    pub fn effective(self: Parsed) Priority {
        return self.field.effective();
    }
};

/// Parse an RFC 9218 `priority` field value (also the PRIORITY_UPDATE field
/// value). Parses the full RFC 8941 Dictionary, keeps the last occurrence of
/// each key, then validates the known members. Returns `error.MalformedPriority`
/// only for malformed Structured Fields syntax; a well-formed but
/// out-of-range/wrong-typed known member is folded to its default with
/// `Parsed.invalid_parameter` set.
pub fn parse(value: []const u8) ParseError!Parsed {
    var result = Parsed{};
    var u_member: ?MemberValue = null;
    var i_member: ?MemberValue = null;
    const s = value;
    var i: usize = 0;

    skipOws(s, &i);
    if (i >= s.len) return result; // empty dictionary → all members omitted

    while (true) {
        if (i >= s.len or !isKeyStart(s[i])) return error.MalformedPriority;
        const key_start = i;
        i += 1;
        while (i < s.len and isKeyChar(s[i])) i += 1;
        const key = s[key_start..i];

        // RFC 8941 §4.2.2: "=" → parse Item/Inner List (with its parameters);
        // otherwise the value is Boolean true, still followed by parameters.
        var member: MemberValue = undefined;
        if (i < s.len and s[i] == '=') {
            i += 1;
            member = try parseMemberValue(s, &i);
        } else {
            member = .{ .item = .{ .kind = .boolean, .boolean = true } };
            try parseParameters(s, &i);
        }

        if (std.mem.eql(u8, key, "u")) {
            if (u_member != null) result.duplicate_parameter = true;
            u_member = member;
        } else if (std.mem.eql(u8, key, "i")) {
            if (i_member != null) result.duplicate_parameter = true;
            i_member = member;
        } else {
            // Unknown member: parsed for structural correctness, then ignored
            // (RFC 9218 §4). Not an error.
        }

        skipOws(s, &i);
        if (i >= s.len) break;
        if (s[i] != ',') return error.MalformedPriority;
        i += 1;
        skipOws(s, &i);
        if (i >= s.len) return error.MalformedPriority; // trailing comma
    }

    // Validate the surviving (last) known members. RFC 8941 overwrote
    // duplicates already; RFC 9218 §4 now ignores an invalid survivor.
    if (u_member) |mv| switch (mv) {
        .item => |b| {
            if (b.kind == .integer and b.integer >= urgency_min and b.integer <= urgency_max) {
                result.field.urgency = @intCast(b.integer);
            } else {
                result.invalid_parameter = true;
            }
        },
        .inner_list => result.invalid_parameter = true,
    };
    if (i_member) |mv| switch (mv) {
        .item => |b| {
            if (b.kind == .boolean) {
                result.field.incremental = b.boolean;
            } else {
                result.invalid_parameter = true;
            }
        },
        .inner_list => result.invalid_parameter = true,
    };

    return result;
}

// ---------------------------------------------------------------------------
// RFC 8941 value parsing: enough of the grammar to (a) advance correctly past
// any valid Dictionary member value so unknown members are skipped, and (b)
// recover the bare-item type/value of known members for interpretation.
// ---------------------------------------------------------------------------

const BareKind = enum { integer, decimal, string, token, byte_sequence, boolean };

const Bare = struct {
    kind: BareKind,
    integer: i64 = 0,
    boolean: bool = false,
};

const MemberValue = union(enum) {
    item: Bare,
    inner_list,
};

fn parseMemberValue(s: []const u8, i: *usize) ParseError!MemberValue {
    if (i.* >= s.len) return error.MalformedPriority;
    if (s[i.*] == '(') {
        try parseInnerList(s, i);
        try parseParameters(s, i);
        return .inner_list;
    }
    const bare = try parseBareItem(s, i);
    try parseParameters(s, i);
    return .{ .item = bare };
}

fn parseInnerList(s: []const u8, i: *usize) ParseError!void {
    i.* += 1; // opening '('
    while (true) {
        skipSp(s, i);
        if (i.* >= s.len) return error.MalformedPriority; // unterminated
        if (s[i.*] == ')') {
            i.* += 1;
            return;
        }
        _ = try parseBareItem(s, i);
        try parseParameters(s, i);
        if (i.* < s.len and s[i.*] != ' ' and s[i.*] != ')') return error.MalformedPriority;
    }
}

fn parseParameters(s: []const u8, i: *usize) ParseError!void {
    while (i.* < s.len and s[i.*] == ';') {
        i.* += 1;
        skipSp(s, i);
        if (i.* >= s.len or !isKeyStart(s[i.*])) return error.MalformedPriority;
        i.* += 1;
        while (i.* < s.len and isKeyChar(s[i.*])) i.* += 1;
        if (i.* < s.len and s[i.*] == '=') {
            i.* += 1;
            _ = try parseBareItem(s, i);
        }
    }
}

fn parseBareItem(s: []const u8, i: *usize) ParseError!Bare {
    if (i.* >= s.len) return error.MalformedPriority;
    const c = s[i.*];
    if (c == '?') {
        i.* += 1;
        if (i.* >= s.len) return error.MalformedPriority;
        const b = s[i.*];
        if (b != '0' and b != '1') return error.MalformedPriority;
        i.* += 1;
        return .{ .kind = .boolean, .boolean = b == '1' };
    }
    if (c == '-' or isDigit(c)) return parseNumber(s, i);
    if (c == '"') {
        try parseString(s, i);
        return .{ .kind = .string };
    }
    if (c == ':') {
        try parseByteSequence(s, i);
        return .{ .kind = .byte_sequence };
    }
    if (isAlpha(c) or c == '*') {
        parseToken(s, i);
        return .{ .kind = .token };
    }
    return error.MalformedPriority;
}

fn parseNumber(s: []const u8, i: *usize) ParseError!Bare {
    var negative = false;
    if (s[i.*] == '-') {
        negative = true;
        i.* += 1;
    }
    if (i.* >= s.len or !isDigit(s[i.*])) return error.MalformedPriority;
    var int_digits: usize = 0;
    var magnitude: i64 = 0;
    while (i.* < s.len and isDigit(s[i.*])) : (i.* += 1) {
        int_digits += 1;
        if (int_digits > 15) return error.MalformedPriority; // SF Integer: max 15 digits
        magnitude = magnitude * 10 + @as(i64, s[i.*] - '0');
    }
    if (i.* < s.len and s[i.*] == '.') {
        // Decimal (RFC 8941 §3.3.2): ≤12 integer digits, 1..3 fractional digits.
        if (int_digits > 12) return error.MalformedPriority;
        i.* += 1;
        var frac_digits: usize = 0;
        while (i.* < s.len and isDigit(s[i.*])) : (i.* += 1) {
            frac_digits += 1;
            if (frac_digits > 3) return error.MalformedPriority;
        }
        if (frac_digits == 0) return error.MalformedPriority;
        return .{ .kind = .decimal };
    }
    return .{ .kind = .integer, .integer = if (negative) -magnitude else magnitude };
}

fn parseString(s: []const u8, i: *usize) ParseError!void {
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
            return;
        }
        if (c < 0x20 or c > 0x7e) return error.MalformedPriority;
        i.* += 1;
    }
    return error.MalformedPriority; // unterminated string
}

fn parseByteSequence(s: []const u8, i: *usize) ParseError!void {
    i.* += 1; // opening ':'
    while (i.* < s.len and s[i.*] != ':') {
        const c = s[i.*];
        if (!(isAlpha(c) or isDigit(c) or c == '+' or c == '/' or c == '=')) return error.MalformedPriority;
        i.* += 1;
    }
    if (i.* >= s.len) return error.MalformedPriority; // unterminated
    i.* += 1; // closing ':'
}

fn parseToken(s: []const u8, i: *usize) void {
    i.* += 1; // first char already validated (ALPHA / '*')
    while (i.* < s.len and isTokenChar(s[i.*])) i.* += 1;
}

fn skipOws(s: []const u8, i: *usize) void {
    while (i.* < s.len and (s[i.*] == ' ' or s[i.*] == '\t')) i.* += 1;
}

fn skipSp(s: []const u8, i: *usize) void {
    while (i.* < s.len and s[i.*] == ' ') i.* += 1;
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

/// A decoded PRIORITY_UPDATE payload. `field_value` borrows the source bytes;
/// parse it with `parse` to get the model.
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
/// field value bytes.
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
    try testing.expect((try parse("")).effective().eql(Priority.default));
    try testing.expect((try parse("   ")).effective().eql(Priority.default));

    const only_u = try parse("u=5");
    try testing.expectEqual(@as(?u3, 5), only_u.field.urgency);
    try testing.expectEqual(@as(?bool, null), only_u.field.incremental); // presence preserved
    try testing.expectEqual(false, only_u.effective().incremental);

    const only_i = try parse("i");
    try testing.expectEqual(@as(?u3, null), only_i.field.urgency);
    try testing.expectEqual(@as(?bool, true), only_i.field.incremental);
    try testing.expectEqual(default_urgency, only_i.effective().urgency);
}

test "parse urgency and incremental combinations" {
    try testing.expect((try parse("u=0, i")).effective().eql(.{ .urgency = 0, .incremental = true }));
    try testing.expect((try parse("u=7,i")).effective().eql(.{ .urgency = 7, .incremental = true }));
    try testing.expect((try parse("u=2 ,  i=?0")).effective().eql(.{ .urgency = 2, .incremental = false }));
    try testing.expectEqual(true, (try parse("i=?1")).effective().incremental);
    try testing.expectEqual(@as(u3, 3), (try parse("u=03")).effective().urgency); // leading zero valid
}

test "parse ignores invalid known parameters and flags them" {
    const over = try parse("u=8");
    try testing.expectEqual(@as(?u3, null), over.field.urgency);
    try testing.expectEqual(default_urgency, over.effective().urgency);
    try testing.expect(over.invalid_parameter);

    try testing.expect((try parse("u=-1")).invalid_parameter);
    try testing.expect((try parse("u=?1")).invalid_parameter); // boolean where integer expected
    const wrong_i = try parse("i=5"); // integer where boolean expected
    try testing.expectEqual(default_incremental, wrong_i.effective().incremental);
    try testing.expect(wrong_i.invalid_parameter);
}

test "duplicate keys keep the last value, then validate it (RFC 8941 then RFC 9218)" {
    const valid_dup = try parse("u=1, u=6");
    try testing.expectEqual(@as(u3, 6), valid_dup.effective().urgency);
    try testing.expect(valid_dup.duplicate_parameter);
    try testing.expect(!valid_dup.invalid_parameter);

    // Regression (review): last value wins even when it is the invalid one, so
    // urgency must fall back to the default rather than keep the earlier `1`.
    const invalid_dup = try parse("u=1, u=8");
    try testing.expectEqual(default_urgency, invalid_dup.effective().urgency);
    try testing.expect(invalid_dup.duplicate_parameter);
    try testing.expect(invalid_dup.invalid_parameter);

    // Same for incremental: `i, i=5` → last is wrong-typed → default false.
    const invalid_dup_i = try parse("i, i=5");
    try testing.expectEqual(false, invalid_dup_i.effective().incremental);
    try testing.expect(invalid_dup_i.duplicate_parameter);
    try testing.expect(invalid_dup_i.invalid_parameter);
}

test "parse accepts valid Structured Fields syntax for unknown members" {
    // Regression (review): decimals, inner lists, byte sequences, and item
    // parameters are valid SF and must be ignored, not rejected.
    try testing.expectEqual(@as(u3, 5), (try parse("a=42, u=5")).effective().urgency);
    try testing.expectEqual(@as(u3, 5), (try parse("x=(1 2), u=5")).effective().urgency);
    try testing.expectEqual(@as(u3, 2), (try parse("a=1.5, u=2")).effective().urgency);
    try testing.expectEqual(@as(u3, 2), (try parse("a=:aGk=:, u=2")).effective().urgency);
    try testing.expectEqual(@as(u3, 5), (try parse("u=5;foo=bar")).effective().urgency); // item params ignored
    try testing.expectEqual(true, (try parse("i;x=1")).effective().incremental); // bare-key params ignored
    try testing.expect(!(try parse("x=(1 2), u=5")).invalid_parameter);
}

test "well-formed but wrong-typed urgency is ignored, not a hard error" {
    // Regression (review): u=1.5 parses as a Decimal, then urgency falls back to
    // the default with invalid_parameter set — it must NOT be MalformedPriority.
    const decimal_u = try parse("u=1.5");
    try testing.expectEqual(default_urgency, decimal_u.effective().urgency);
    try testing.expect(decimal_u.invalid_parameter);
}

test "parse rejects genuinely malformed dictionary syntax" {
    try testing.expectError(error.MalformedPriority, parse("=5"));
    try testing.expectError(error.MalformedPriority, parse("u="));
    try testing.expectError(error.MalformedPriority, parse("u=5,"));
    try testing.expectError(error.MalformedPriority, parse(",u=5"));
    try testing.expectError(error.MalformedPriority, parse("u=5 x"));
    try testing.expectError(error.MalformedPriority, parse("!bad"));
    try testing.expectError(error.MalformedPriority, parse("u=-"));
    try testing.expectError(error.MalformedPriority, parse("u=1.")); // decimal needs a fraction
    try testing.expectError(error.MalformedPriority, parse("a=\"unterminated"));
    try testing.expectError(error.MalformedPriority, parse("a=:abc")); // unterminated byte sequence
    try testing.expectError(error.MalformedPriority, parse("a=(1 2")); // unterminated inner list
}

test "serialize preserves member presence and round-trips through parse" {
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("", try (Field{}).serialize(&buf));
    try testing.expectEqualStrings("u=5", try (Field{ .urgency = 5 }).serialize(&buf));
    // A response can explicitly reset urgency to the default value.
    try testing.expectEqualStrings("u=3", try (Field{ .urgency = 3 }).serialize(&buf));
    try testing.expectEqualStrings("i", try (Field{ .incremental = true }).serialize(&buf));
    try testing.expectEqualStrings("i=?0", try (Field{ .incremental = false }).serialize(&buf));
    try testing.expectEqualStrings("u=0, i", try (Field{ .urgency = 0, .incremental = true }).serialize(&buf));
    try testing.expectEqualStrings("u=5, i=?0", try (Field{ .urgency = 5, .incremental = false }).serialize(&buf));

    const urgencies = [_]?u3{ null, 0, 3, 7 };
    const incrementals = [_]?bool{ null, false, true };
    for (urgencies) |u| {
        for (incrementals) |inc| {
            const original = Field{ .urgency = u, .incremental = inc };
            const text = try original.serialize(&buf);
            const round = try parse(text);
            try testing.expect(round.field.eql(original));
        }
    }
}

test "PRIORITY_UPDATE payload round-trips element id and field value" {
    var buf: [64]u8 = undefined;
    const payload = try encodePayload(.{ .element_id = 0x3fff_ffff, .field_value = "u=2, i" }, &buf);
    const decoded = try decodePayload(payload);
    try testing.expectEqual(@as(u64, 0x3fff_ffff), decoded.element_id);
    try testing.expectEqualStrings("u=2, i", decoded.field_value);
    try testing.expect((try parse(decoded.field_value)).effective().eql(.{ .urgency = 2, .incremental = true }));

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
        try testing.expectEqual(@as(u3, 1), (try parse(decoded.update.field_value)).effective().urgency);
    }
}

test "decodeFrame rejects non-PRIORITY_UPDATE frames" {
    var buf: [32]u8 = undefined;
    const headers = try frame.encodeKnownFrame(.headers, "abc", &buf);
    try testing.expectError(error.NotPriorityUpdate, decodeFrame(headers));
}

test "metrics fold parse outcomes" {
    var metrics = Metrics{};
    metrics.recordParse(parse("u=5")); // clean
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
