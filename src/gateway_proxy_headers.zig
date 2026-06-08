//! Header trust-boundary logic for the HTTP reverse proxy.
//!
//! This module owns the decisions about which headers cross the client↔proxy
//! and proxy↔upstream boundaries: hop-by-hop stripping, Connection token
//! handling, X-Forwarded-* chain building, upstream identity trust, and
//! asserted-identity header injection.  All functions are pure logic — no
//! network I/O, no response formatting.

const compat = @import("zig_compat.zig");
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
pub fn shouldSkipUpstreamResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-encoding") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "te") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade") or
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

/// Copy safe client request headers into `extra_headers`, omitting all
/// hop-by-hop and Tardigrade-reserved headers.
pub fn appendProxyRequestHeaders(
    extra_headers: *std.array_list.Managed(std.http.Header),
    request_headers: *const http.Headers,
) !void {
    const connection_header = request_headers.get("connection");
    for (request_headers.iterator()) |header| {
        if (shouldSkipUpstreamRequestHeader(header.name, connection_header)) continue;
        try extra_headers.append(.{ .name = header.name, .value = header.value });
    }
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
        if (identity.len > 0) try headers.append(.{ .name = "X-Tardigrade-Auth-Identity", .value = identity });
    }
    if (auth_user_id) |user_id| {
        if (user_id.len > 0) try headers.append(.{ .name = "X-Tardigrade-User-ID", .value = user_id });
    }
    if (auth_device_id) |device_id| {
        if (device_id.len > 0) try headers.append(.{ .name = "X-Tardigrade-Device-ID", .value = device_id });
    }
    if (auth_scopes) |scopes| {
        if (scopes.len > 0) try headers.append(.{ .name = "X-Tardigrade-Scopes", .value = scopes });
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
        if (identity.len > 0) try writer.print("X-Tardigrade-Auth-Identity: {s}\r\n", .{identity});
    }
    if (auth_user_id) |user_id| {
        if (user_id.len > 0) try writer.print("X-Tardigrade-User-ID: {s}\r\n", .{user_id});
    }
    if (auth_device_id) |device_id| {
        if (device_id.len > 0) try writer.print("X-Tardigrade-Device-ID: {s}\r\n", .{device_id});
    }
    if (auth_scopes) |scopes| {
        if (scopes.len > 0) try writer.print("X-Tardigrade-Scopes: {s}\r\n", .{scopes});
    }
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
    try std.testing.expect(shouldSkipUpstreamResponseHeader("Content-Encoding"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("content-encoding"));
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("Content-Type"));
}

test "shouldSkipUpstreamResponseHeader strips upstream Server and X-Powered-By" {
    // WSTG-INFO-02 / ASVS-14.3.3: upstream technology headers must not leak
    // to external clients — Tardigrade emits its own Server header instead.
    try std.testing.expect(shouldSkipUpstreamResponseHeader("Server"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("server"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("SERVER"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("X-Powered-By"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("x-powered-by"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("X-POWERED-BY"));
    // Must not suppress unrelated headers.
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("Content-Type"));
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("X-Custom-Header"));
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("Set-Cookie"));
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
        try std.testing.expect(shouldSkipUpstreamResponseHeader(name));
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
        try std.testing.expect(!shouldSkipUpstreamResponseHeader(name));
    }
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
