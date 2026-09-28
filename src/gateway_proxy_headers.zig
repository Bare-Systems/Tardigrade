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

// ---------------------------------------------------------------------------
// proxy_set_header (#809)
// ---------------------------------------------------------------------------

/// Per-request values for the variables a `proxy_set_header` value may use.
pub const ProxySetHeaderVars = struct {
    /// Raw client `Host` (or `:authority`); `$http_host`, and `$host` without
    /// its port and lowercased.
    host: ?[]const u8,
    /// The trusted client IP Tardigrade already resolved (the `X-Real-IP`
    /// value), never a raw client-supplied `X-Forwarded-For` entry.
    remote_addr: []const u8,
    scheme: []const u8,
    /// The `X-Forwarded-For` value Tardigrade would send (`$remote_addr`
    /// appended to the inbound chain).
    proxy_add_x_forwarded_for: []const u8,
    request_id: []const u8,
};

/// Apply `proxy_set_header` rules to a fully built upstream header list.
///
/// Runs after every client-copied and Tardigrade-generated header is in place,
/// so a rule overrides both: every instance of the name, in any case, is
/// removed before the expanded value is appended; a value that expands to the
/// empty string only removes. Expanded values are allocated from `arena` and
/// must outlive the upstream request write.
pub fn applyProxySetHeaders(
    arena: std.mem.Allocator,
    extra_headers: *std.array_list.Managed(std.http.Header),
    rules: []const http.location_router.ProxySetHeader,
    vars: ProxySetHeaderVars,
) !void {
    if (rules.len == 0) return;
    // Remove first, then add, so two rules never interfere with each other.
    var i: usize = 0;
    while (i < extra_headers.items.len) {
        if (proxySetHeaderRuleFor(rules, extra_headers.items[i].name) != null) {
            _ = extra_headers.orderedRemove(i);
        } else {
            i += 1;
        }
    }
    for (rules) |rule| {
        const value = try expandProxySetHeaderValue(arena, rule.value, vars);
        if (value.len == 0) continue;
        try extra_headers.append(.{ .name = rule.name, .value = value });
    }
}

fn proxySetHeaderRuleFor(rules: []const http.location_router.ProxySetHeader, name: []const u8) ?*const http.location_router.ProxySetHeader {
    for (rules) |*rule| {
        if (std.ascii.eqlIgnoreCase(rule.name, name)) return rule;
    }
    return null;
}

fn expandProxySetHeaderValue(arena: std.mem.Allocator, template: []const u8, vars: ProxySetHeaderVars) ![]const u8 {
    if (std.mem.findScalar(u8, template, '$') == null) return template;
    var out = std.ArrayList(u8).empty;
    var i: usize = 0;
    while (i < template.len) {
        if (template[i] != '$') {
            try out.append(arena, template[i]);
            i += 1;
            continue;
        }
        var end = i + 1;
        while (end < template.len and http.location_router.isProxySetHeaderVariableChar(template[end])) end += 1;
        const name = template[i + 1 .. end];
        if (std.mem.eql(u8, name, "host")) {
            if (vars.host) |raw| {
                const host = stripPort(std.mem.trim(u8, raw, " \t"));
                for (host) |c| try out.append(arena, std.ascii.toLower(c));
            }
        } else if (std.mem.eql(u8, name, "http_host")) {
            if (vars.host) |raw| try out.appendSlice(arena, std.mem.trim(u8, raw, " \t"));
        } else if (std.mem.eql(u8, name, "remote_addr")) {
            try out.appendSlice(arena, vars.remote_addr);
        } else if (std.mem.eql(u8, name, "scheme")) {
            try out.appendSlice(arena, vars.scheme);
        } else if (std.mem.eql(u8, name, "proxy_add_x_forwarded_for")) {
            try out.appendSlice(arena, vars.proxy_add_x_forwarded_for);
        } else if (std.mem.eql(u8, name, "request_id")) {
            try out.appendSlice(arena, vars.request_id);
        } else {
            // Config load rejects unknown variables; keep the text literal
            // rather than guess if one ever reaches here.
            try out.appendSlice(arena, template[i..end]);
        }
        i = end;
    }
    return out.items;
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
///
/// A bare (unbracketed) IPv6 literal has no unambiguous `:port` suffix — RFC
/// 3986 §3.2.2 requires brackets whenever a port follows an IPv6 host — so the
/// final group of such a value is address data, not a port. Truncating it would
/// make `2001:db8::1` and `2001:db8::2` normalize to the same string, which is
/// a trust-comparison bypass rather than a formatting nit.
pub fn stripPort(authority: []const u8) []const u8 {
    if (authority.len == 0) return authority;
    if (authority[0] == '[') {
        const close_idx = std.mem.findScalar(u8, authority, ']') orelse return authority;
        return authority[0 .. close_idx + 1];
    }
    if (std.mem.count(u8, authority, ":") > 1) return authority;
    const colon_idx = std.mem.findScalarLast(u8, authority, ':') orelse return authority;
    return authority[0..colon_idx];
}

/// Remove surrounding IPv6 brackets, if present, leaving the address text.
fn unbracketHost(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') return host[1 .. host.len - 1];
    return host;
}

/// Match a `trusted_upstream_identities` entry against a peer host.
///
/// An entry containing `/` is a CIDR block (e.g. `172.16.0.0/12`, for a
/// sidecar such as cloudflared on a Docker bridge whose address is not
/// fixed) and matches any IP literal inside it. Otherwise the entry is
/// compared with `trustHostsEqual`.
fn trustEntryMatches(entry: []const u8, host: []const u8) bool {
    if (std.mem.findScalar(u8, entry, '/') != null) {
        const block = http.access_control.parseCidr(std.mem.trim(u8, entry, " \t")) orelse return false;
        const ip = http.access_control.parseIp(unbracketHost(stripPort(host))) orelse return false;
        return block.contains(ip);
    }
    return trustHostsEqual(entry, host);
}

/// Compare two authority hosts for a trust decision.
///
/// IP literals are compared by their parsed binary address, so every legal
/// spelling of one address matches (`2001:db8::1`, `2001:db8:0:0:0:0:0:1`,
/// `[2001:db8::1]`) while two different addresses can never collide through
/// textual normalization. Hostnames fall back to a case-insensitive compare.
/// An IP literal and a hostname are never considered equal.
fn trustHostsEqual(a: []const u8, b: []const u8) bool {
    const host_a = unbracketHost(stripPort(a));
    const host_b = unbracketHost(stripPort(b));
    if (host_a.len == 0 or host_b.len == 0) return false;

    const ip_a = http.access_control.parseIp(host_a);
    const ip_b = http.access_control.parseIp(host_b);
    if (ip_a != null or ip_b != null) {
        if (ip_a == null or ip_b == null) return false;
        return ip_a.?.eql(ip_b.?);
    }
    return std.ascii.eqlIgnoreCase(host_a, host_b);
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

    for (cfg.trusted_upstream_identities) |trusted| {
        if (trustEntryMatches(trusted, upstream_host)) return true;
    }
    return false;
}

/// Whether an HTTP/2 or HTTP/3 peer may supply the client IP through
/// `TARDIGRADE_REAL_IP_HEADER` / `X-Forwarded-For` / `X-Real-IP`: only a peer
/// matching an explicitly configured `trusted_upstream_identities` entry.
/// Unlike `isTrustedUpstream` there is no open-trust default, because #756
/// made those front ends key ACLs and rate limits on the transport peer so a
/// direct client cannot choose its own address.
pub fn isExplicitlyTrustedUpstream(cfg: *const edge_config.EdgeConfig, upstream_host: []const u8) bool {
    return cfg.trusted_upstream_identities.len > 0 and isTrustedUpstream(cfg, upstream_host);
}

/// The trusted-proxy set `http.request_context.extractClientIp` consults
/// while walking `X-Forwarded-For` right to left: an address is a trusted
/// hop only when it explicitly matches a `trusted_upstream_identities`
/// entry. Unlike `isTrustedUpstream`, there is no open-trust default -- with
/// no identities configured, no hop is skipped and the rightmost entry (the
/// address the connecting peer observed) is the client.
pub const TrustedProxySet = struct {
    cfg: *const edge_config.EdgeConfig,

    pub fn isTrustedProxy(self: TrustedProxySet, ip: []const u8) bool {
        for (self.cfg.trusted_upstream_identities) |trusted| {
            if (trustEntryMatches(trusted, ip)) return true;
        }
        return false;
    }
};

/// True for the inbound forwarded-client headers an untrusted peer must not be
/// able to supply: they would otherwise choose the resolved client IP or reach
/// an origin that trusts them (#791).
pub fn isForwardedClientHeader(cfg: *const edge_config.EdgeConfig, name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "x-forwarded-for") or
        std.ascii.eqlIgnoreCase(name, "x-real-ip") or
        (cfg.real_ip_header.len > 0 and std.ascii.eqlIgnoreCase(name, cfg.real_ip_header));
}

/// Drop an untrusted peer's forwarded-client headers before the client IP is
/// resolved or the request is proxied. Shared by the HTTP/1 and HTTP/2 front
/// ends so `$remote_addr` and rate limiting agree across protocols (#809).
pub fn stripUntrustedForwardingHeaders(headers: *http.Headers, cfg: *const edge_config.EdgeConfig) void {
    headers.remove("x-forwarded-for");
    headers.remove("x-real-ip");
    if (cfg.real_ip_header.len > 0) headers.remove(cfg.real_ip_header);
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

test "stripPort never truncates a bare IPv6 literal" {
    // Unbracketed IPv6 has no port to strip: the final hextet is address data.
    // H3 supplies peers in exactly this expanded, unbracketed form.
    try std.testing.expectEqualStrings("2001:db8:0:0:0:0:0:1", stripPort("2001:db8:0:0:0:0:0:1"));
    try std.testing.expectEqualStrings("2001:db8::1", stripPort("2001:db8::1"));
    try std.testing.expectEqualStrings("::1", stripPort("::1"));
}

test "trusted-peer matching is exact for every authority spelling" {
    var identities = [_][]const u8{"2001:db8:0:0:0:0:0:1"};
    const cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .trust_require_upstream_identity = true,
        .trusted_upstream_identities = identities[0..],
    });

    // The original bypass: two IPv6 addresses differing only in the final
    // hextet both normalized to "2001:db8:0:0:0:0:0" and compared equal.
    try std.testing.expect(!isTrustedUpstream(&cfg, "2001:db8:0:0:0:0:0:2"));
    try std.testing.expect(!isTrustedUpstream(&cfg, "2001:db8::2"));
    // Exact match still trusts, in any legal spelling of the same address.
    try std.testing.expect(isTrustedUpstream(&cfg, "2001:db8:0:0:0:0:0:1"));
    try std.testing.expect(isTrustedUpstream(&cfg, "2001:db8::1"));
    try std.testing.expect(isTrustedUpstream(&cfg, "[2001:db8::1]"));
    try std.testing.expect(isTrustedUpstream(&cfg, "[2001:db8::1]:8443"));
    // A prefix of the trusted address is not the trusted address.
    try std.testing.expect(!isTrustedUpstream(&cfg, "2001:db8:0:0:0:0:0"));

    // Compressed spelling in the *config* matches an expanded H3 peer.
    var compressed = [_][]const u8{"2001:db8::1"};
    const cfg_compressed = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .trust_require_upstream_identity = true,
        .trusted_upstream_identities = compressed[0..],
    });
    try std.testing.expect(isTrustedUpstream(&cfg_compressed, "2001:db8:0:0:0:0:0:1"));
    try std.testing.expect(!isTrustedUpstream(&cfg_compressed, "2001:db8:0:0:0:0:0:2"));

    // IPv4 and hostname:port forms keep working, and an IP literal never
    // equals a hostname.
    var mixed = [_][]const u8{ "192.0.2.10", "lb.internal:8443" };
    const cfg_mixed = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .trust_require_upstream_identity = true,
        .trusted_upstream_identities = mixed[0..],
    });
    try std.testing.expect(isTrustedUpstream(&cfg_mixed, "192.0.2.10"));
    try std.testing.expect(isTrustedUpstream(&cfg_mixed, "192.0.2.10:443"));
    try std.testing.expect(!isTrustedUpstream(&cfg_mixed, "192.0.2.11"));
    try std.testing.expect(isTrustedUpstream(&cfg_mixed, "lb.internal"));
    try std.testing.expect(isTrustedUpstream(&cfg_mixed, "LB.Internal:9000"));
    try std.testing.expect(!isTrustedUpstream(&cfg_mixed, "lb.internal.evil.test"));
}

test "isTrustedUpstream accepts CIDR entries (#791)" {
    // A host-local cloudflared on a Docker bridge has no fixed address, so
    // operators pin the bridge subnet instead of a single IP.
    var identities = [_][]const u8{ "172.16.0.0/12", "2001:db8::/32" };
    const cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .trust_require_upstream_identity = true,
        .trusted_upstream_identities = identities[0..],
    });
    try std.testing.expect(isTrustedUpstream(&cfg, "172.18.0.1"));
    try std.testing.expect(isTrustedUpstream(&cfg, "172.31.255.254:5000"));
    try std.testing.expect(!isTrustedUpstream(&cfg, "172.32.0.1"));
    try std.testing.expect(!isTrustedUpstream(&cfg, "10.0.0.1"));
    try std.testing.expect(isTrustedUpstream(&cfg, "2001:db8:0:0:0:0:0:7"));
    try std.testing.expect(isTrustedUpstream(&cfg, "[2001:db8::7]:443"));
    try std.testing.expect(!isTrustedUpstream(&cfg, "2001:db9::1"));
    // A CIDR entry never matches a hostname.
    try std.testing.expect(!isTrustedUpstream(&cfg, "cloudflared.internal"));
}

test "TrustedProxySet only trusts explicitly listed hops (#791)" {
    var identities = [_][]const u8{ "10.0.0.0/8", "192.0.2.10" };
    const cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .trusted_upstream_identities = identities[0..],
    });
    const set = TrustedProxySet{ .cfg = &cfg };
    try std.testing.expect(set.isTrustedProxy("10.1.2.3"));
    try std.testing.expect(set.isTrustedProxy("192.0.2.10"));
    try std.testing.expect(!set.isTrustedProxy("192.0.2.11"));

    // Open trust (nothing configured) still admits every peer's forwarding
    // headers, but skips no XFF hop.
    const open_cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    try std.testing.expect(isTrustedUpstream(&open_cfg, "198.51.100.1"));
    try std.testing.expect(!(TrustedProxySet{ .cfg = &open_cfg }).isTrustedProxy("198.51.100.1"));
}

test "H3 transport peers feed the trust check without an IPv6 bypass" {
    // Drive the concrete producer: whatever H3 formats for `client_ip` is what
    // the trust boundary must compare, so the two stay honest together.
    const allocator = std.testing.allocator;
    var trusted_bytes: [16]u8 = [_]u8{0} ** 16;
    trusted_bytes[0] = 0x20;
    trusted_bytes[1] = 0x01;
    trusted_bytes[2] = 0x0d;
    trusted_bytes[3] = 0xb8;
    trusted_bytes[15] = 0x01;
    var attacker_bytes = trusted_bytes;
    attacker_bytes[15] = 0x02;

    const trusted_peer = try http.http3_runtime.formatAddressHostAlloc(
        allocator,
        .{ .family = .ip6, .bytes = trusted_bytes, .port = 44300 },
    );
    defer allocator.free(trusted_peer);
    const attacker_peer = try http.http3_runtime.formatAddressHostAlloc(
        allocator,
        .{ .family = .ip6, .bytes = attacker_bytes, .port = 44301 },
    );
    defer allocator.free(attacker_peer);

    // Confirms the producer really emits the unbracketed form this finding is
    // about, so the test cannot silently stop covering it.
    try std.testing.expectEqualStrings("2001:db8:0:0:0:0:0:1", trusted_peer);
    try std.testing.expect(std.mem.count(u8, attacker_peer, ":") > 1);
    try std.testing.expect(attacker_peer[0] != '[');

    var identities = [_][]const u8{trusted_peer};
    const cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .trust_require_upstream_identity = true,
        .trusted_upstream_identities = identities[0..],
    });
    try std.testing.expect(isTrustedUpstream(&cfg, trusted_peer));
    try std.testing.expect(!isTrustedUpstream(&cfg, attacker_peer));
}

test "geo trust source rejects a near-miss IPv6 peer" {
    var blocked = [_][]const u8{"RU"};
    var identities = [_][]const u8{"2001:db8::1"};
    const cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .geo_blocked_countries = blocked[0..],
        .trust_require_upstream_identity = true,
        .trusted_upstream_identities = identities[0..],
    });
    try std.testing.expect(isTrustedGeoSource(&cfg, "2001:db8:0:0:0:0:0:1"));
    try std.testing.expect(!isTrustedGeoSource(&cfg, "2001:db8:0:0:0:0:0:2"));
}

test "stripPort handles IPv6 addresses" {
    try std.testing.expectEqualStrings("[::1]", stripPort("[::1]"));
    try std.testing.expectEqualStrings("[::1]", stripPort("[::1]:8080"));
    try std.testing.expectEqualStrings("[2001:db8::1]", stripPort("[2001:db8::1]:443"));
}

fn countHeaders(headers: []const std.http.Header, name: []const u8) usize {
    var n: usize = 0;
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) n += 1;
    }
    return n;
}

fn findHeader(headers: []const std.http.Header, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

const test_set_header_vars = ProxySetHeaderVars{
    .host = "App.Example.Test:8443",
    .remote_addr = "198.51.100.7",
    .scheme = "https",
    .proxy_add_x_forwarded_for = "203.0.113.9, 198.51.100.7",
    .request_id = "req-809",
};

test "proxy_set_header overwrites every client and generated instance of a header (#809)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var headers = std.array_list.Managed(std.http.Header).init(std.testing.allocator);
    defer headers.deinit();
    // Client duplicates and case variants, plus the value Tardigrade generated.
    try headers.append(.{ .name = "x-forwarded-proto", .value = "http" });
    try headers.append(.{ .name = "Accept", .value = "*/*" });
    try headers.append(.{ .name = "X-FORWARDED-PROTO", .value = "gopher" });
    try headers.append(.{ .name = "X-Forwarded-Proto", .value = "http" });

    const rules = [_]http.location_router.ProxySetHeader{
        .{ .name = "X-Forwarded-Proto", .value = "https" },
    };
    try applyProxySetHeaders(arena.allocator(), &headers, &rules, test_set_header_vars);

    try std.testing.expectEqual(@as(usize, 1), countHeaders(headers.items, "x-forwarded-proto"));
    try std.testing.expectEqualStrings("https", findHeader(headers.items, "x-forwarded-proto").?);
    try std.testing.expectEqualStrings("*/*", findHeader(headers.items, "accept").?);
}

test "proxy_set_header empty value removes the header (#809)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var headers = std.array_list.Managed(std.http.Header).init(std.testing.allocator);
    defer headers.deinit();
    try headers.append(.{ .name = "X-Forwarded-For", .value = "10.9.9.9" });
    try headers.append(.{ .name = "x-forwarded-for", .value = "10.8.8.8, 198.51.100.7" });

    const rules = [_]http.location_router.ProxySetHeader{
        .{ .name = "X-Forwarded-For", .value = "" },
    };
    try applyProxySetHeaders(arena.allocator(), &headers, &rules, test_set_header_vars);
    try std.testing.expectEqual(@as(usize, 0), countHeaders(headers.items, "x-forwarded-for"));
}

test "proxy_set_header Host replaces the upstream Host override (#809)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var headers = std.array_list.Managed(std.http.Header).init(std.testing.allocator);
    defer headers.deinit();
    try headers.append(.{ .name = "Host", .value = "client.example" });

    const rules = [_]http.location_router.ProxySetHeader{
        .{ .name = "Host", .value = "auth.baresystems.com" },
    };
    try applyProxySetHeaders(arena.allocator(), &headers, &rules, test_set_header_vars);
    try std.testing.expectEqual(@as(usize, 1), countHeaders(headers.items, "host"));
    try std.testing.expectEqualStrings("auth.baresystems.com", findHeader(headers.items, "host").?);
}

test "proxy_set_header expands variables from trusted request state (#809)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var headers = std.array_list.Managed(std.http.Header).init(std.testing.allocator);
    defer headers.deinit();
    // A spoofed client X-Forwarded-For must not feed $remote_addr.
    try headers.append(.{ .name = "X-Forwarded-For", .value = "6.6.6.6" });

    const rules = [_]http.location_router.ProxySetHeader{
        .{ .name = "X-Forwarded-For", .value = "$remote_addr" },
        .{ .name = "X-Origin", .value = "$scheme://$host" },
        .{ .name = "X-Raw-Host", .value = "$http_host" },
        .{ .name = "X-Chain", .value = "$proxy_add_x_forwarded_for" },
        .{ .name = "X-Req", .value = "id=$request_id;" },
    };
    try applyProxySetHeaders(arena.allocator(), &headers, &rules, test_set_header_vars);
    try std.testing.expectEqualStrings("198.51.100.7", findHeader(headers.items, "x-forwarded-for").?);
    try std.testing.expectEqual(@as(usize, 1), countHeaders(headers.items, "x-forwarded-for"));
    try std.testing.expectEqualStrings("https://app.example.test", findHeader(headers.items, "x-origin").?);
    try std.testing.expectEqualStrings("App.Example.Test:8443", findHeader(headers.items, "x-raw-host").?);
    try std.testing.expectEqualStrings("203.0.113.9, 198.51.100.7", findHeader(headers.items, "x-chain").?);
    try std.testing.expectEqualStrings("id=req-809;", findHeader(headers.items, "x-req").?);
}

test "proxy_set_header variable expanding to empty removes the header (#809)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var headers = std.array_list.Managed(std.http.Header).init(std.testing.allocator);
    defer headers.deinit();
    try headers.append(.{ .name = "X-Forwarded-Host", .value = "evil.example" });

    var vars = test_set_header_vars;
    vars.host = null;
    const rules = [_]http.location_router.ProxySetHeader{
        .{ .name = "X-Forwarded-Host", .value = "$host" },
    };
    try applyProxySetHeaders(arena.allocator(), &headers, &rules, vars);
    try std.testing.expectEqual(@as(usize, 0), countHeaders(headers.items, "x-forwarded-host"));
}
