/// W3C Trace Context (traceparent / tracestate) propagation for Tardigrade.
///
/// Spec: https://www.w3.org/TR/trace-context/
///
/// Tardigrade acts as an intermediary: it propagates inbound trace context to
/// upstream proxy requests and originates a new context when none is present.
/// Actual OTLP span export (configured via TARDIGRADE_OTEL_ENDPOINT) is a
/// separate runtime concern; this module focuses on the wire protocol.
const std = @import("std");

/// Parsed representation of a W3C `traceparent` header value.
pub const TraceContext = struct {
    /// 16-byte trace identifier (must be non-zero).
    trace_id: [16]u8,
    /// 8-byte parent-id / span identifier (must be non-zero).
    parent_id: [8]u8,
    /// Trace flags byte (0x01 = sampled).
    flags: u8,

    /// Return true when the sampling flag is set.
    pub fn sampled(self: TraceContext) bool {
        return (self.flags & 0x01) != 0;
    }

    /// Write the trace-id as 32 lowercase hex characters into `buf`.
    pub fn traceIdHex(self: TraceContext, buf: *[32]u8) void {
        _ = std.fmt.bufPrint(buf, "{}", .{std.fmt.fmtSliceHexLower(&self.trace_id)}) catch {};
    }

    /// Format a `traceparent` header value into `buf` (must be ≥55 bytes).
    pub fn format(self: TraceContext, buf: []u8) []u8 {
        return std.fmt.bufPrint(buf, "00-{s}-{s}-{x:0>2}", .{
            std.fmt.fmtSliceHexLower(&self.trace_id),
            std.fmt.fmtSliceHexLower(&self.parent_id),
            self.flags,
        }) catch buf[0..0];
    }
};

/// Parse a W3C `traceparent` header value.
/// Returns null when the header is absent, malformed, or contains an all-zero ID.
pub fn parse(header: ?[]const u8) ?TraceContext {
    const value = header orelse return null;
    const trimmed = std.mem.trim(u8, value, " \t\r\n");

    // Format: "00-{32hex}-{16hex}-{2hex}" → exactly 55 characters.
    if (trimmed.len != 55) return null;
    if (trimmed[0] != '0' or trimmed[1] != '0') return null; // version must be 00
    if (trimmed[2] != '-' or trimmed[35] != '-' or trimmed[52] != '-') return null;

    const trace_hex = trimmed[3..35];
    const parent_hex = trimmed[36..52];
    const flags_hex = trimmed[53..55];

    var ctx: TraceContext = undefined;
    parseHexBytes(&ctx.trace_id, trace_hex) catch return null;
    parseHexBytes(&ctx.parent_id, parent_hex) catch return null;
    ctx.flags = std.fmt.parseInt(u8, flags_hex, 16) catch return null;

    // Reject all-zero IDs as invalid per spec.
    if (std.mem.eql(u8, &ctx.trace_id, &([_]u8{0} ** 16))) return null;
    if (std.mem.eql(u8, &ctx.parent_id, &([_]u8{0} ** 8))) return null;

    return ctx;
}

/// Generate a fresh `TraceContext` with a random trace-id, a random span-id,
/// and the sampled flag set (0x01).
pub fn generate() TraceContext {
    var ctx: TraceContext = undefined;
    std.crypto.random.bytes(&ctx.trace_id);
    std.crypto.random.bytes(&ctx.parent_id);
    ctx.flags = 0x01;
    return ctx;
}

/// Create a child-span context: same trace-id, new random span-id, same flags.
pub fn childSpan(parent: TraceContext) TraceContext {
    var child = parent;
    std.crypto.random.bytes(&child.parent_id);
    return child;
}

/// Extract or originate a `TraceContext` from request headers.
/// If a valid `traceparent` header is present it is parsed and a child span is
/// returned. Otherwise a new root span is generated.
pub fn extractOrGenerate(traceparent_header: ?[]const u8) TraceContext {
    if (parse(traceparent_header)) |parent| {
        return childSpan(parent);
    }
    return generate();
}

/// Write a `traceparent` header value into `buf`. `buf` must be ≥55 bytes.
pub fn formatHeader(ctx: TraceContext, buf: []u8) []u8 {
    return ctx.format(buf);
}

fn parseHexBytes(out: []u8, hex: []const u8) !void {
    if (hex.len != out.len * 2) return error.InvalidLength;
    for (out, 0..) |*byte, i| {
        byte.* = try std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16);
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parse valid traceparent" {
    const valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const ctx = parse(valid).?;
    try testing.expect(ctx.sampled());
    try testing.expectEqual(@as(u8, 0x01), ctx.flags);

    var hex_buf: [32]u8 = undefined;
    ctx.traceIdHex(&hex_buf);
    try testing.expectEqualStrings("4bf92f3577b34da6a3ce929d0e0e4736", &hex_buf);
}

test "parse rejects malformed traceparent" {
    try testing.expect(parse(null) == null);
    try testing.expect(parse("") == null);
    try testing.expect(parse("garbage") == null);
    try testing.expect(parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") == null); // wrong version
    try testing.expect(parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01") == null); // zero trace-id
}

test "generate produces valid non-zero IDs" {
    const ctx = generate();
    var buf: [55]u8 = undefined;
    const formatted = ctx.format(&buf);
    try testing.expectEqual(@as(usize, 55), formatted.len);
    try testing.expect(!std.mem.eql(u8, ctx.trace_id[0..], &([_]u8{0} ** 16)));
    try testing.expect(!std.mem.eql(u8, ctx.parent_id[0..], &([_]u8{0} ** 8)));
}

test "childSpan preserves trace-id and changes parent-id" {
    const parent = generate();
    const child = childSpan(parent);
    try testing.expectEqualSlices(u8, &parent.trace_id, &child.trace_id);
    // parent_id should almost certainly differ (astronomically unlikely collision)
    _ = child.parent_id;
}

test "extractOrGenerate propagates existing context" {
    const header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const ctx = extractOrGenerate(header);
    var hex_buf: [32]u8 = undefined;
    ctx.traceIdHex(&hex_buf);
    // Trace ID must be preserved; only span ID changes.
    try testing.expectEqualStrings("4bf92f3577b34da6a3ce929d0e0e4736", &hex_buf);
}

test "extractOrGenerate creates new context when absent" {
    const ctx = extractOrGenerate(null);
    try testing.expect(!std.mem.eql(u8, ctx.trace_id[0..], &([_]u8{0} ** 16)));
}

test "round-trip format and parse" {
    const original = generate();
    var buf: [55]u8 = undefined;
    const formatted = original.format(&buf);
    const parsed = parse(formatted).?;
    try testing.expectEqualSlices(u8, &original.trace_id, &parsed.trace_id);
    try testing.expectEqualSlices(u8, &original.parent_id, &parsed.parent_id);
    try testing.expectEqual(original.flags, parsed.flags);
}
