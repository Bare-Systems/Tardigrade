//! Header trust-boundary logic for the HTTP reverse proxy.
//!
//! This module owns the decisions about which headers cross the client↔proxy
//! and proxy↔upstream boundaries: hop-by-hop stripping, Connection token
//! handling, X-Forwarded-* chain building, upstream identity trust, and
//! asserted-identity header injection.  All functions are pure logic — no
//! network I/O, no response formatting.

const compat = @import("zig_compat");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");

// ---------------------------------------------------------------------------
// Hop-by-hop header filtering
// ---------------------------------------------------------------------------

/// Returns true when the named request header should be dropped before the
/// request is forwarded to an upstream.
///
/// Strips the RFC 7230 §6.1 hop-by-hop set, headers named by the inbound
/// `Connection` value, Tardigrade-specific identity headers (prevents
/// client-forgery of asserted identity), and forwarded-metadata headers that
/// Tardigrade re-populates with authoritative values.
pub fn shouldSkipUpstreamRequestHeader(name: []const u8, connection_header: ?[]const u8) bool {
    // Strip inbound X-Tardigrade-* headers so clients cannot forge asserted
    // identity. Tardigrade re-adds the real values after auth resolves.
    const tardigrade_prefix = "x-tardigrade-";
    if (name.len >= tardigrade_prefix.len and
        std.ascii.eqlIgnoreCase(name[0..tardigrade_prefix.len], tardigrade_prefix))
        return true;

    if (std.ascii.eqlIgnoreCase(name, http.early_data.HEADER_NAME)) return true;

    if (connectionHeaderReferencesHeader(connection_header, name)) return true;

    return std.ascii.eqlIgnoreCase(name, "accept-encoding") or
        std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-authenticate") or
        std.ascii.eqlIgnoreCase(name, "proxy-authorization") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "te") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade") or
        std.ascii.eqlIgnoreCase(name, "x-forwarded-for") or
        std.ascii.eqlIgnoreCase(name, "x-forwarded-host") or
        std.ascii.eqlIgnoreCase(name, "x-forwarded-proto") or
        std.ascii.eqlIgnoreCase(name, "x-real-ip") or
        std.ascii.eqlIgnoreCase(name, http.correlation.REQUEST_HEADER_NAME) or
        std.ascii.eqlIgnoreCase(name, http.correlation.HEADER_NAME);
}

/// Returns true when the named upstream response header should be dropped
/// before the response is forwarded to the client.
///
/// Strips the RFC 7230 hop-by-hop set and technology-disclosure headers
/// (WSTG-INFO-02, ASVS-14.3.3).  Tardigrade emits its own `Server` header
/// and re-calculates `Content-Length` from the materialized body.
///
/// `connection_header` is the upstream response's own `Connection` value (if
/// any). RFC 7230 §6.1 lets *either* end of a hop nominate extra headers as
/// hop-by-hop via `Connection`; a malicious or misbehaving upstream must not
/// be able to ride a nominated header past this filter to the client the way
/// `shouldSkipUpstreamRequestHeader` already blocks it on the request side.
pub fn shouldSkipUpstreamResponseHeader(name: []const u8, connection_header: ?[]const u8) bool {
    if (connectionHeaderReferencesHeader(connection_header, name)) return true;

    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-encoding") or
        std.ascii.eqlIgnoreCase(name, http.early_data.HEADER_NAME) or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "te") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade") or
        std.ascii.eqlIgnoreCase(name, "alt-svc") or
        // Strip upstream technology-disclosure headers. Tardigrade emits its
        // own Server header; leaking the upstream value exposes backend stack
        // details to external clients (WSTG-INFO-02, ASVS-14.3.3).
        std.ascii.eqlIgnoreCase(name, "server") or
        std.ascii.eqlIgnoreCase(name, "x-powered-by") or
        std.ascii.eqlIgnoreCase(name, http.correlation.REQUEST_HEADER_NAME) or
        std.ascii.eqlIgnoreCase(name, http.correlation.HEADER_NAME);
}

/// Returns true if `name` appears as a token in the `Connection` header
/// value (RFC 7230 §6.1 hop-by-hop extension mechanism).
/// Comparison is case-insensitive; whitespace around tokens is ignored.
pub fn connectionHeaderReferencesHeader(connection_header: ?[]const u8, name: []const u8) bool {
    const raw = connection_header orelse return false;
    var tokens = std.mem.splitScalar(u8, raw, ',');
    while (tokens.next()) |token_raw| {
        const token = std.mem.trim(u8, token_raw, " \t");
        if (token.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(token, name)) return true;
    }
    return false;
}

/// Returns true if `name` is nominated as hop-by-hop by *any* occurrence of
/// a `Connection` header among an already-parsed list of `{name, value}`
/// headers (RFC 7230 §6.1) -- duplicate `Connection` fields must each be
/// evaluated in full, not just the first (`Headers.get()` semantics) and
/// not via a fixed-size join buffer. A prior version of this fix joined
/// every occurrence into a `[4096]u8` buffer and silently truncated on
/// overflow, which is itself bypassable: pad the first Connection field(s)
/// with enough benign tokens to push a real nomination past byte 4096 and
/// it would silently drop out of the joined value (#673 review). Scanning
/// each occurrence's own (unbounded) value directly has no such limit.
pub fn anyConnectionHeaderReferencesHeader(headers: anytype, name: []const u8) bool {
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
        if (connectionHeaderReferencesHeader(header.value, name)) return true;
    }
    return false;
}

/// Same as `anyConnectionHeaderReferencesHeader`, but scans a raw
/// `\r\n`-separated header block (status/request line included -- lines
/// without a colon are skipped) instead of an already-parsed list. Used
/// during a single streaming parse pass, before per-header filtering
/// decisions.
pub fn anyRawConnectionHeaderReferencesHeader(header_block: []const u8, name: []const u8) bool {
    var lines = std.mem.splitSequence(u8, header_block, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const hname = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(hname, "connection")) continue;
        const hval = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (connectionHeaderReferencesHeader(hval, name)) return true;
    }
    return false;
}

/// Copy safe client request headers into `extra_headers`, omitting all
/// hop-by-hop and Tardigrade-reserved headers.
pub fn appendProxyRequestHeaders(
    extra_headers: *std.array_list.Managed(std.http.Header),
    request_headers: *const http.Headers,
) !void {
    // `Headers.get()` returns only the first match, but a client may repeat
    // `Connection` as multiple fields; check every occurrence directly
    // rather than pre-joining into a bounded buffer (#673).
    const headers_list = request_headers.iterator();
    for (headers_list) |header| {
        if (shouldSkipUpstreamRequestHeader(header.name, null)) continue;
        if (anyConnectionHeaderReferencesHeader(headers_list, header.name)) continue;
        try extra_headers.append(.{ .name = header.name, .value = header.value });
    }
}

pub fn appendCanonicalEarlyDataHeader(extra_headers: *std.array_list.Managed(std.http.Header), enabled: bool) !void {
    if (!enabled) return;
    try extra_headers.append(.{ .name = http.early_data.HEADER_NAME, .value = http.early_data.HEADER_VALUE });
}

// ---------------------------------------------------------------------------
// Forwarded-for chain building
// ---------------------------------------------------------------------------

/// An optionally-owned byte slice.  When `owned` is non-null, the caller
/// must free it with `deinit`.
pub const MaybeOwnedBytes = struct {
    value: []const u8,
    owned: ?[]u8 = null,

    pub fn deinit(self: *MaybeOwnedBytes, allocator: std.mem.Allocator) void {
        if (self.owned) |buf| allocator.free(buf);
        self.* = undefined;
    }
};

/// Build the outbound `X-Forwarded-For` value by appending `client_ip` to
/// any existing chain from a trusted upstream tier.  Returns a borrowed slice
/// when no allocation is needed (empty or null `incoming`).
pub fn buildForwardedFor(allocator: std.mem.Allocator, incoming: ?[]const u8, client_ip: []const u8) !MaybeOwnedBytes {
    if (incoming) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) {
            const owned = try std.fmt.allocPrint(allocator, "{s}, {s}", .{ trimmed, client_ip });
            return .{ .value = owned, .owned = owned };
        }
    }
    return .{ .value = client_ip };
}

// ---------------------------------------------------------------------------
// Upstream trust boundary
// ---------------------------------------------------------------------------

/// Strip the port suffix from an authority string.
/// Handles bare hostnames, `host:port`, and IPv6 bracket notation `[::1]:port`.
pub fn stripPort(authority: []const u8) []const u8 {
    if (authority.len == 0) return authority;
    if (authority[0] == '[') {
        const close_idx = std.mem.findScalar(u8, authority, ']') orelse return authority;
        return authority[0 .. close_idx + 1];
    }
    const colon_idx = std.mem.findScalarLast(u8, authority, ':') orelse return authority;
    return authority[0..colon_idx];
}

/// Returns true when the connecting upstream host is in the trusted set, or
/// when trust enforcement is disabled (the default for single-tier deployments).
///
/// Operators running Tardigrade behind a load balancer should set
/// `trusted_upstream_identities` to the load balancer's address and enable
/// `trust_require_upstream_identity` to prevent clients from spoofing
/// `X-Forwarded-For`.
pub fn isTrustedUpstream(cfg: *const edge_config.EdgeConfig, upstream_host: []const u8) bool {
    if (!cfg.trust_require_upstream_identity and cfg.trusted_upstream_identities.len == 0) return true;
    if (upstream_host.len == 0) return false;
    const host = stripPort(upstream_host);

    for (cfg.trusted_upstream_identities) |trusted| {
        const trusted_host = stripPort(trusted);
        if (std.ascii.eqlIgnoreCase(trusted, upstream_host) or std.ascii.eqlIgnoreCase(trusted_host, host)) {
            return true;
        }
    }
    return false;
}

/// Geo policy is meaningful only when the country header arrived from the
/// explicitly trusted proxy/CDN tier. Direct clients must not be able to pick
/// their own country by supplying the configured header name.
pub fn isTrustedGeoSource(cfg: *const edge_config.EdgeConfig, peer_host: []const u8) bool {
    return cfg.geo_blocked_countries.len == 0 or isTrustedUpstream(cfg, peer_host);
}

/// Append HMAC-signed gateway-identity headers so an internal upstream can
/// verify the request originated from a trusted Tardigrade instance.
pub fn appendTrustedUpstreamHeaders(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    extra_headers: *std.array_list.Managed(std.http.Header),
    owned_header_values: *std.array_list.Managed([]u8),
    target_url: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    auth_identity: ?[]const u8,
    api_version: ?u32,
    payload: []const u8,
) !void {
    if (cfg.trust_shared_secret.len == 0) return;

    const ts = compat.unixTimestamp();
    const ts_value = try std.fmt.allocPrint(allocator, "{d}", .{ts});
    try owned_header_values.append(ts_value);
    try extra_headers.append(.{ .name = "X-Tardigrade-Gateway-Id", .value = cfg.trust_gateway_id });
    try extra_headers.append(.{ .name = "X-Tardigrade-Trust-Timestamp", .value = ts_value });

    var payload_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &payload_digest, .{});
    var payload_digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&payload_digest_hex, "{f}", .{compat.fmtSliceHexLower(&payload_digest)}) catch unreachable;

    const identity = auth_identity orelse "-";
    const api_version_value = if (api_version) |ver|
        try std.fmt.allocPrint(allocator, "{d}", .{ver})
    else
        try allocator.dupe(u8, "-");
    defer allocator.free(api_version_value);

    const material = try std.fmt.allocPrint(
        allocator,
        "POST\n{s}\n{s}\n{s}\n{s}\n{s}\n{s}\n{s}\n{s}",
        .{ target_url, correlation_id, client_ip, cfg.trust_gateway_id, ts_value, payload_digest_hex, identity, api_version_value },
    );
    defer allocator.free(material);

    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, material, cfg.trust_shared_secret);
    const signature_hex = try std.fmt.allocPrint(allocator, "{f}", .{compat.fmtSliceHexLower(&mac)});
    try owned_header_values.append(signature_hex);
    try extra_headers.append(.{ .name = "X-Tardigrade-Trust-Signature", .value = signature_hex });
}

// ---------------------------------------------------------------------------
// Asserted identity headers
// ---------------------------------------------------------------------------

/// Append X-Tardigrade-* identity headers derived from a resolved auth
/// context.  Only non-empty values are appended.
pub fn appendAssertedIdentityHeaders(
    headers: *std.array_list.Managed(std.http.Header),
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
) !void {
    if (auth_identity) |identity| {
        if (identity.len > 0) {
            try validateAssertedHeaderValue(identity);
            try headers.append(.{ .name = "X-Tardigrade-Auth-Identity", .value = identity });
        }
    }
    if (auth_user_id) |user_id| {
        if (user_id.len > 0) {
            try validateAssertedHeaderValue(user_id);
            try headers.append(.{ .name = "X-Tardigrade-User-ID", .value = user_id });
        }
    }
    if (auth_device_id) |device_id| {
        if (device_id.len > 0) {
            try validateAssertedHeaderValue(device_id);
            try headers.append(.{ .name = "X-Tardigrade-Device-ID", .value = device_id });
        }
    }
    if (auth_scopes) |scopes| {
        if (scopes.len > 0) {
            try validateAssertedHeaderValue(scopes);
            try headers.append(.{ .name = "X-Tardigrade-Scopes", .value = scopes });
        }
    }
}

/// Write X-Tardigrade-* identity headers directly to a request writer.
pub fn writeAssertedIdentityHeaders(
    writer: anytype,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
) !void {
    if (auth_identity) |identity| {
        if (identity.len > 0) {
            try validateAssertedHeaderValue(identity);
            try writer.print("X-Tardigrade-Auth-Identity: {s}\r\n", .{identity});
        }
    }
    if (auth_user_id) |user_id| {
        if (user_id.len > 0) {
            try validateAssertedHeaderValue(user_id);
            try writer.print("X-Tardigrade-User-ID: {s}\r\n", .{user_id});
        }
    }
    if (auth_device_id) |device_id| {
        if (device_id.len > 0) {
            try validateAssertedHeaderValue(device_id);
            try writer.print("X-Tardigrade-Device-ID: {s}\r\n", .{device_id});
        }
    }
    if (auth_scopes) |scopes| {
        if (scopes.len > 0) {
            try validateAssertedHeaderValue(scopes);
            try writer.print("X-Tardigrade-Scopes: {s}\r\n", .{scopes});
        }
    }
}

fn validateAssertedHeaderValue(value: []const u8) !void {
    if (!http.headers.isValidHeaderValue(value)) return error.InvalidHeaderValue;
}

// ---------------------------------------------------------------------------
// Correlation ID / request-tracing headers
// ---------------------------------------------------------------------------

/// Set both X-Request-ID and X-Correlation-ID on an http.Response.
pub fn setRequestIdHeaders(response: *http.Response, request_id: []const u8) void {
    _ = response.setHeader(http.correlation.REQUEST_HEADER_NAME, request_id);
    _ = response.setHeader(http.correlation.HEADER_NAME, request_id);
}

/// Write both X-Request-ID and X-Correlation-ID lines to a raw writer.
pub fn writeRequestIdHeaders(writer: anytype, request_id: []const u8) !void {
    try writer.print("{s}: {s}\r\n", .{ http.correlation.REQUEST_HEADER_NAME, request_id });
    try writer.print("{s}: {s}\r\n", .{ http.correlation.HEADER_NAME, request_id });
}

/// Append both X-Request-ID and X-Correlation-ID to a header list.
pub fn appendRequestIdHeaders(headers: *std.array_list.Managed(std.http.Header), request_id: []const u8) !void {
    try headers.append(.{ .name = http.correlation.REQUEST_HEADER_NAME, .value = request_id });
    try headers.append(.{ .name = http.correlation.HEADER_NAME, .value = request_id });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "shouldSkipUpstreamRequestHeader strips inbound X-Tardigrade headers" {
    try std.testing.expect(shouldSkipUpstreamRequestHeader("X-Tardigrade-Auth-Identity", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("x-tardigrade-user-id", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("X-TARDIGRADE-DEVICE-ID", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("x-tardigrade-scopes", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("x-tardigrade-anything-custom", null));
    try std.testing.expect(!shouldSkipUpstreamRequestHeader("X-Custom-Header", null));
    try std.testing.expect(!shouldSkipUpstreamRequestHeader("Authorization", null));
    try std.testing.expect(!shouldSkipUpstreamRequestHeader("Content-Type", null));
}

test "asserted identity headers reject CR LF and NUL values" {
    const allocator = std.testing.allocator;
    var headers = std.array_list.Managed(std.http.Header).init(allocator);
    defer headers.deinit();
    try std.testing.expectError(
        error.InvalidHeaderValue,
        appendAssertedIdentityHeaders(&headers, "user\r\nX-Injected: yes", null, null, null),
    );

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.testing.expectError(
        error.InvalidHeaderValue,
        writeAssertedIdentityHeaders(&output.writer, null, "user\x00suffix", null, null),
    );
    try std.testing.expectEqual(@as(usize, 0), output.written().len);
}

test "shouldSkipUpstreamRequestHeader strips standard hop-by-hop headers" {
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Connection", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Keep-Alive", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Proxy-Authenticate", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Proxy-Authorization", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("TE", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Trailer", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Transfer-Encoding", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Upgrade", null));
}

test "shouldSkipUpstreamRequestHeader strips raw Early-Data before canonical append" {
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Early-Data", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("early-data", "Early-Data"));
}

test "shouldSkipUpstreamRequestHeader strips headers named by Connection" {
    const connection_header = "X-Test-Hop, keep-alive, Another-Hop";
    try std.testing.expect(shouldSkipUpstreamRequestHeader("X-Test-Hop", connection_header));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("another-hop", connection_header));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Keep-Alive", connection_header));
    try std.testing.expect(!shouldSkipUpstreamRequestHeader("X-Not-Hop", connection_header));
}

test "shouldSkipUpstreamRequestHeader strips all standard hop-by-hop headers case-insensitively" {
    const cases = [_][]const u8{
        "Accept-Encoding",    "accept-encoding",     "ACCEPT-ENCODING",
        "Connection",         "connection",          "CONNECTION",
        "Content-Length",     "content-length",      "CONTENT-LENGTH",
        "Host",               "host",                "HOST",
        "Keep-Alive",         "keep-alive",          "KEEP-ALIVE",
        "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection",
        "TE",                 "te",                  "Trailer",
        "trailer",            "Transfer-Encoding",   "transfer-encoding",
        "Upgrade",            "upgrade",             "X-Forwarded-For",
        "x-forwarded-for",    "X-Forwarded-Host",    "X-Forwarded-Proto",
        "X-Real-IP",          "x-real-ip",
    };
    for (cases) |name| {
        try std.testing.expect(shouldSkipUpstreamRequestHeader(name, null));
    }
}

test "shouldSkipUpstreamRequestHeader passes safe application headers" {
    const pass_cases = [_][]const u8{
        "Authorization",
        "Accept",
        "Content-Type",
        "X-Custom-Header",
        "traceparent",
        "User-Agent",
    };
    for (pass_cases) |name| {
        try std.testing.expect(!shouldSkipUpstreamRequestHeader(name, null));
    }
}

test "shouldSkipUpstreamRequestHeader drops Connection-listed custom hop-by-hop headers" {
    const conn = "X-Internal-State, X-Debug-Token";
    try std.testing.expect(shouldSkipUpstreamRequestHeader("X-Internal-State", conn));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("x-debug-token", conn));
    try std.testing.expect(!shouldSkipUpstreamRequestHeader("X-Safe-Header", conn));
    try std.testing.expect(!shouldSkipUpstreamRequestHeader("Authorization", conn));
}

test "shouldSkipUpstreamResponseHeader strips stale content-encoding" {
    try std.testing.expect(shouldSkipUpstreamResponseHeader("Content-Encoding", null));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("content-encoding", null));
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("Content-Type", null));
}

test "shouldSkipUpstreamResponseHeader strips Early-Data response headers" {
    try std.testing.expect(shouldSkipUpstreamResponseHeader("Early-Data", null));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("early-data", null));
}

test "appendCanonicalEarlyDataHeader emits exactly one RFC 8470 marker when enabled" {
    var headers = std.array_list.Managed(std.http.Header).init(std.testing.allocator);
    defer headers.deinit();

    try appendCanonicalEarlyDataHeader(&headers, false);
    try std.testing.expectEqual(@as(usize, 0), headers.items.len);

    try appendCanonicalEarlyDataHeader(&headers, true);
    try std.testing.expectEqual(@as(usize, 1), headers.items.len);
    try std.testing.expectEqualStrings("Early-Data", headers.items[0].name);
    try std.testing.expectEqualStrings("1", headers.items[0].value);
}

test "appendProxyRequestHeaders normalizes duplicate inbound Early-Data through canonical helper" {
    var request_headers = http.Headers.init(std.testing.allocator);
    defer request_headers.deinit();
    try request_headers.append("Connection", "Early-Data");
    try request_headers.append("Early-Data", "0");
    try request_headers.append("early-data", "garbage");
    try request_headers.append("X-Application", "kept");

    var extra_headers = std.array_list.Managed(std.http.Header).init(std.testing.allocator);
    defer extra_headers.deinit();

    try appendProxyRequestHeaders(&extra_headers, &request_headers);
    try appendCanonicalEarlyDataHeader(&extra_headers, true);

    try std.testing.expectEqual(@as(usize, 2), extra_headers.items.len);
    try std.testing.expectEqualStrings("x-application", extra_headers.items[0].name);
    try std.testing.expectEqualStrings("kept", extra_headers.items[0].value);
    try std.testing.expectEqualStrings("Early-Data", extra_headers.items[1].name);
    try std.testing.expectEqualStrings("1", extra_headers.items[1].value);
}

test "appendProxyRequestHeaders unions duplicate Connection fields, not just the first (#673)" {
    // `Headers.get()` returns only the first match; a client repeating
    // `Connection` as two separate fields must still have every nominated
    // header stripped, not just whichever field happened to come first.
    var request_headers = http.Headers.init(std.testing.allocator);
    defer request_headers.deinit();
    try request_headers.append("Connection", "X-Ignore");
    try request_headers.append("Connection", "X-Hostile-Secret");
    try request_headers.append("X-Ignore", "client-value");
    try request_headers.append("X-Hostile-Secret", "client-value");
    try request_headers.append("X-Safe", "kept");

    var extra_headers = std.array_list.Managed(std.http.Header).init(std.testing.allocator);
    defer extra_headers.deinit();

    try appendProxyRequestHeaders(&extra_headers, &request_headers);

    try std.testing.expectEqual(@as(usize, 1), extra_headers.items.len);
    try std.testing.expectEqualStrings("x-safe", extra_headers.items[0].name);
}

test "shouldSkipUpstreamResponseHeader strips upstream Server and X-Powered-By" {
    // WSTG-INFO-02 / ASVS-14.3.3: upstream technology headers must not leak
    // to external clients — Tardigrade emits its own Server header instead.
    try std.testing.expect(shouldSkipUpstreamResponseHeader("Server", null));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("server", null));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("SERVER", null));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("X-Powered-By", null));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("x-powered-by", null));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("X-POWERED-BY", null));
    // Must not suppress unrelated headers.
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("Content-Type", null));
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("X-Custom-Header", null));
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("Set-Cookie", null));
}

test "shouldSkipUpstreamResponseHeader strips all hop-by-hop and disclosure headers" {
    const strip_cases = [_][]const u8{
        "Connection",       "connection",        "CONNECTION",
        "Keep-Alive",       "keep-alive",        "Proxy-Connection",
        "TE",               "te",                "Trailer",
        "trailer",          "Transfer-Encoding", "transfer-encoding",
        "Upgrade",          "upgrade",           "Content-Encoding",
        "content-encoding", "Content-Length",    "content-length",
        "Server",           "server",            "SERVER",
        "X-Powered-By",     "x-powered-by",
    };
    for (strip_cases) |name| {
        try std.testing.expect(shouldSkipUpstreamResponseHeader(name, null));
    }
}

test "shouldSkipUpstreamResponseHeader passes safe application response headers" {
    const pass_cases = [_][]const u8{
        "Content-Type",
        "Cache-Control",
        "Set-Cookie",
        "Location",
        "X-Custom-Response",
        "ETag",
        "Last-Modified",
    };
    for (pass_cases) |name| {
        try std.testing.expect(!shouldSkipUpstreamResponseHeader(name, null));
    }
}

test "shouldSkipUpstreamResponseHeader strips headers nominated by the upstream's own Connection value (#673)" {
    // RFC 7230 §6.1 lets either end of a hop nominate extra hop-by-hop
    // headers via `Connection`. A hostile or misbehaving upstream sending
    // `Connection: X-Hostile-Secret` alongside `X-Hostile-Secret: ...` must
    // not be able to ride that header past the proxy to the client -- this
    // mirrors the request-direction protection already covered by
    // `shouldSkipUpstreamRequestHeader drops Connection-listed custom
    // hop-by-hop headers`.
    const conn = "X-Hostile-Secret, X-Also-Hostile";
    try std.testing.expect(shouldSkipUpstreamResponseHeader("X-Hostile-Secret", conn));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("x-also-hostile", conn));
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("X-Safe-Header", conn));
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("Set-Cookie", conn));
}

test "anyConnectionHeaderReferencesHeader and anyRawConnectionHeaderReferencesHeader locate Connection case-insensitively" {
    const Header = struct { name: []const u8, value: []const u8 };
    const headers = [_]Header{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "CONNECTION", .value = "X-Foo" },
    };
    try std.testing.expect(anyConnectionHeaderReferencesHeader(&headers, "X-Foo"));
    try std.testing.expect(!anyConnectionHeaderReferencesHeader(&headers, "X-Missing"));

    const raw = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: X-Foo\r\n";
    try std.testing.expect(anyRawConnectionHeaderReferencesHeader(raw, "X-Foo"));
    try std.testing.expect(!anyRawConnectionHeaderReferencesHeader(raw, "X-Missing"));
}

test "anyConnectionHeaderReferencesHeader and anyRawConnectionHeaderReferencesHeader union duplicate Connection fields regardless of order/casing (#673)" {
    // A response (or request) is allowed to repeat Connection as multiple
    // header fields; RFC 7230 §3.2.2 treats that as equivalent to one
    // comma-joined field. Consulting only the first occurrence would let a
    // nomination hiding in a second/later field bypass filtering.
    const Header = struct { name: []const u8, value: []const u8 };
    const headers = [_]Header{
        .{ .name = "Connection", .value = "X-Ignore" },
        .{ .name = "CONNECTION", .value = "X-Hostile-Secret" },
    };
    try std.testing.expect(anyConnectionHeaderReferencesHeader(&headers, "X-Ignore"));
    try std.testing.expect(anyConnectionHeaderReferencesHeader(&headers, "X-Hostile-Secret"));
    try std.testing.expect(!anyConnectionHeaderReferencesHeader(&headers, "X-Safe"));

    // Reversed order, reversed casing: still evaluated correctly.
    const headers_reversed = [_]Header{
        .{ .name = "connection", .value = "X-Hostile-Secret" },
        .{ .name = "Connection", .value = "X-Ignore" },
    };
    try std.testing.expect(anyConnectionHeaderReferencesHeader(&headers_reversed, "X-Hostile-Secret"));
    try std.testing.expect(anyConnectionHeaderReferencesHeader(&headers_reversed, "X-Ignore"));

    const raw = "HTTP/1.1 200 OK\r\nConnection: X-Ignore\r\nConnection: X-Hostile-Secret\r\n";
    try std.testing.expect(anyRawConnectionHeaderReferencesHeader(raw, "X-Hostile-Secret"));
}

test "anyConnectionHeaderReferencesHeader has no fixed-size limit -- a late nomination beyond 4096 bytes is still honored (#673 review)" {
    // A prior version of this fix pre-joined every Connection occurrence
    // into a fixed [4096]u8 buffer and silently truncated on overflow.
    // That is itself bypassable: pad earlier Connection field(s) with
    // enough benign tokens to push a real nomination past byte 4096, and
    // the truncated joined value would silently drop it. Scanning each
    // occurrence's own unbounded value directly (as these functions do)
    // has no such limit.
    const allocator = std.testing.allocator;

    // A single ~4500-byte token, comfortably past the old 4096-byte
    // buffer, followed by the real nomination in the SAME Connection field.
    const padding = "X-Benign-" ** 500;
    const conn_value = try std.fmt.allocPrint(allocator, "{s}, X-Hostile-Secret", .{padding});
    defer allocator.free(conn_value);
    try std.testing.expect(conn_value.len > 4096);

    const Header = struct { name: []const u8, value: []const u8 };
    const headers = [_]Header{.{ .name = "Connection", .value = conn_value }};
    try std.testing.expect(anyConnectionHeaderReferencesHeader(&headers, "X-Hostile-Secret"));

    const raw = try std.fmt.allocPrint(allocator, "HTTP/1.1 200 OK\r\nConnection: {s}\r\n", .{conn_value});
    defer allocator.free(raw);
    try std.testing.expect(anyRawConnectionHeaderReferencesHeader(raw, "X-Hostile-Secret"));

    // Also cover the nomination being pushed past byte 4096 by *multiple*
    // separate Connection fields rather than one long value.
    const headers_multi = [_]Header{
        .{ .name = "Connection", .value = padding },
        .{ .name = "Connection", .value = padding },
        .{ .name = "Connection", .value = "X-Hostile-Secret" },
    };
    try std.testing.expect(anyConnectionHeaderReferencesHeader(&headers_multi, "X-Hostile-Secret"));

    const raw_multi = try std.fmt.allocPrint(
        allocator,
        "HTTP/1.1 200 OK\r\nConnection: {s}\r\nConnection: {s}\r\nConnection: X-Hostile-Secret\r\n",
        .{ padding, padding },
    );
    defer allocator.free(raw_multi);
    try std.testing.expect(anyRawConnectionHeaderReferencesHeader(raw_multi, "X-Hostile-Secret"));
}

test "connectionHeaderReferencesHeader handles whitespace around tokens" {
    try std.testing.expect(connectionHeaderReferencesHeader("  X-Foo  ,  X-Bar  ", "X-Foo"));
    try std.testing.expect(connectionHeaderReferencesHeader("  X-Foo  ,  X-Bar  ", "X-Bar"));
    try std.testing.expect(connectionHeaderReferencesHeader("\tX-Foo\t,\tX-Bar\t", "x-foo"));
    try std.testing.expect(!connectionHeaderReferencesHeader("X-Foo, X-Bar", "X-Baz"));
}

test "connectionHeaderReferencesHeader is case-insensitive" {
    try std.testing.expect(connectionHeaderReferencesHeader("x-my-hop", "X-MY-HOP"));
    try std.testing.expect(connectionHeaderReferencesHeader("X-MY-HOP", "x-my-hop"));
    try std.testing.expect(connectionHeaderReferencesHeader("KEEP-ALIVE", "keep-alive"));
}

test "connectionHeaderReferencesHeader ignores empty tokens" {
    try std.testing.expect(!connectionHeaderReferencesHeader(",,,", "X-Foo"));
    try std.testing.expect(!connectionHeaderReferencesHeader("", "X-Foo"));
    try std.testing.expect(connectionHeaderReferencesHeader(",X-Foo,", "X-Foo"));
}

test "buildForwardedFor appends client ip" {
    const allocator = std.testing.allocator;
    var value = try buildForwardedFor(allocator, "10.0.0.1, 10.0.0.2", "127.0.0.1");
    defer value.deinit(allocator);
    try std.testing.expectEqualStrings("10.0.0.1, 10.0.0.2, 127.0.0.1", value.value);
}

test "buildForwardedFor borrows client ip when no incoming chain exists" {
    const value = try buildForwardedFor(std.testing.allocator, null, "127.0.0.1");
    try std.testing.expect(value.owned == null);
    try std.testing.expectEqualStrings("127.0.0.1", value.value);
}

test "buildForwardedFor handles empty incoming chain" {
    const result = try buildForwardedFor(std.testing.allocator, "", "10.0.0.1");
    try std.testing.expect(result.owned == null);
    try std.testing.expectEqualStrings("10.0.0.1", result.value);
}

test "buildForwardedFor trims whitespace from existing chain" {
    var result = try buildForwardedFor(std.testing.allocator, "  192.168.1.1  ", "10.0.0.1");
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("192.168.1.1, 10.0.0.1", result.value);
}

test "buildForwardedFor handles multi-hop chain" {
    var result = try buildForwardedFor(std.testing.allocator, "1.2.3.4, 5.6.7.8", "9.10.11.12");
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("1.2.3.4, 5.6.7.8, 9.10.11.12", result.value);
}

test "isTrustedUpstream returns true when trust is not required" {
    const cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .trust_require_upstream_identity = false,
    });
    try std.testing.expect(isTrustedUpstream(&cfg, "any-host.example.com"));
    try std.testing.expect(isTrustedUpstream(&cfg, ""));
}

test "isTrustedUpstream matches host case-insensitively" {
    var identities = [_][]const u8{"trusted.internal"};
    const cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .trust_require_upstream_identity = true,
        .trusted_upstream_identities = identities[0..],
    });
    try std.testing.expect(isTrustedUpstream(&cfg, "trusted.internal"));
    try std.testing.expect(isTrustedUpstream(&cfg, "TRUSTED.INTERNAL"));
    try std.testing.expect(!isTrustedUpstream(&cfg, "untrusted.internal"));
    try std.testing.expect(!isTrustedUpstream(&cfg, ""));
}

test "isTrustedUpstream strips port before matching" {
    var identities = [_][]const u8{"trusted.internal"};
    const cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .trust_require_upstream_identity = true,
        .trusted_upstream_identities = identities[0..],
    });
    try std.testing.expect(isTrustedUpstream(&cfg, "trusted.internal:8080"));
    try std.testing.expect(!isTrustedUpstream(&cfg, "untrusted.internal:8080"));
}

test "geo country identity requires the configured trusted proxy source" {
    var blocked = [_][]const u8{"RU"};
    var identities = [_][]const u8{"192.0.2.10"};
    const cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .geo_blocked_countries = blocked[0..],
        .trust_require_upstream_identity = true,
        .trusted_upstream_identities = identities[0..],
    });
    try std.testing.expect(isTrustedGeoSource(&cfg, "192.0.2.10"));
    try std.testing.expect(!isTrustedGeoSource(&cfg, "198.51.100.20"));
}

test "stripPort handles bare hostname" {
    try std.testing.expectEqualStrings("example.com", stripPort("example.com"));
    try std.testing.expectEqualStrings("example.com", stripPort("example.com:443"));
    try std.testing.expectEqualStrings("127.0.0.1", stripPort("127.0.0.1:8080"));
    try std.testing.expectEqualStrings("", stripPort(""));
}

test "stripPort handles IPv6 addresses" {
    try std.testing.expectEqualStrings("[::1]", stripPort("[::1]"));
    try std.testing.expectEqualStrings("[::1]", stripPort("[::1]:8080"));
    try std.testing.expectEqualStrings("[2001:db8::1]", stripPort("[2001:db8::1]:443"));
}
