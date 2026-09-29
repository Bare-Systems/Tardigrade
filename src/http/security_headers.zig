const std = @import("std");
const Response = @import("response.zig").Response;

/// A response header scoped to the request currently being handled on this
/// thread (#761: `forward_auth_client_headers` on an allowed request).
pub const ScopedHeader = struct {
    name: []const u8,
    value: []const u8,
};

/// Shared-cache policy for a response to a request that passed
/// `forward_auth` (#761). A protected response must never be stored by a
/// shared cache: the next request would be answered without the auth check.
pub const ProtectedCachePolicy = enum {
    /// Not a forward_auth-protected response.
    none,
    /// Protected: keep the origin's directives but make them `private`,
    /// dropping `public`, `s-maxage` and `proxy-revalidate`.
    private,
    /// Protected and carrying auth-issued headers such as a session cookie:
    /// `no-store` outright.
    no_store,
};

/// HTTP/1.1 handles one request at a time per worker thread, and every H1
/// response head passes through `SecurityHeaders.apply` or the raw
/// security-header writer. Scoping extra headers and the cache policy here
/// lets them reach proxied (buffered and streamed), static, local and upgrade
/// responses without threading them through each writer. Callers must pair
/// `set` with `clear`.
threadlocal var request_scoped_headers: []const ScopedHeader = &.{};
threadlocal var request_cache_policy: ProtectedCachePolicy = .none;

pub fn setRequestScope(headers: []const ScopedHeader, cache_policy: ProtectedCachePolicy) void {
    request_scoped_headers = headers;
    request_cache_policy = cache_policy;
}

pub fn clearRequestScope() void {
    request_scoped_headers = &.{};
    request_cache_policy = .none;
}

pub fn requestScopedHeaders() []const ScopedHeader {
    return request_scoped_headers;
}

pub fn requestCachePolicy() ProtectedCachePolicy {
    return request_cache_policy;
}

/// True when a raw writer must not forward the origin's value of `name`
/// because the request scope replaces it.
pub fn requestScopeReplacesHeader(name: []const u8) bool {
    return request_cache_policy != .none and std.ascii.eqlIgnoreCase(name, "cache-control");
}

/// The `Cache-Control` value for a protected response, derived from the
/// origin's value (if any). Written into `buf`; falls back to `no-store` if
/// the rewritten directives would not fit.
pub fn protectedCacheControl(buf: []u8, origin: ?[]const u8, policy: ProtectedCachePolicy) []const u8 {
    std.debug.assert(policy != .none);
    if (policy == .no_store) return "no-store";
    var out: std.ArrayList(u8) = .initBuffer(buf);
    out.appendSliceBounded("private") catch return "no-store";
    var directives = std.mem.splitScalar(u8, origin orelse "", ',');
    while (directives.next()) |raw| {
        const directive = std.mem.trim(u8, raw, " \t");
        if (directive.len == 0) continue;
        const name_end = std.mem.findScalar(u8, directive, '=') orelse directive.len;
        const name = std.mem.trim(u8, directive[0..name_end], " \t");
        if (std.ascii.eqlIgnoreCase(name, "no-store")) return "no-store";
        // Shared-cache permissions and qualified `private="field"` (which
        // still lets a shared cache store the rest) are replaced by the
        // unqualified `private` above.
        if (std.ascii.eqlIgnoreCase(name, "public") or
            std.ascii.eqlIgnoreCase(name, "s-maxage") or
            std.ascii.eqlIgnoreCase(name, "proxy-revalidate") or
            std.ascii.eqlIgnoreCase(name, "private")) continue;
        out.appendSliceBounded(", ") catch return "no-store";
        out.appendSliceBounded(directive) catch return "no-store";
    }
    return out.items;
}

/// Replace every `Cache-Control` on `response` with the protected policy.
pub fn applyProtectedCachePolicy(response: *Response, policy: ProtectedCachePolicy) void {
    if (policy == .none) return;
    // Computed into `buf` (or a literal) before the origin field is freed.
    var buf: [256]u8 = undefined;
    const value = protectedCacheControl(&buf, response.headers.get("cache-control"), policy);
    response.headers.remove("cache-control");
    response.headers.append("Cache-Control", value) catch {};
}

/// Standard security headers applied to all responses.
///
/// - X-Frame-Options
/// - X-Content-Type-Options
/// - Content-Security-Policy
/// - Strict-Transport-Security
/// - Referrer-Policy
/// - Permissions-Policy
/// - Cross-Origin-Opener-Policy
/// - Cross-Origin-Resource-Policy
pub const SecurityHeaders = struct {
    x_frame_options: []const u8 = "DENY",
    x_content_type_options: []const u8 = "nosniff",
    content_security_policy: []const u8 = "default-src 'self'",
    /// HSTS value is intentionally empty by default. The gateway populates this
    /// field only when TLS is active and HSTS is explicitly enabled in config.
    strict_transport_security: []const u8 = "",
    referrer_policy: []const u8 = "strict-origin-when-cross-origin",
    permissions_policy: []const u8 = "camera=(), microphone=(), geolocation=()",
    x_xss_protection: []const u8 = "0", // Disabled per modern best practice (CSP preferred)
    /// Isolates the browsing context from cross-origin documents, preventing
    /// Spectre-style attacks that exploit shared browsing context groups.
    cross_origin_opener_policy: []const u8 = "same-origin",
    /// Controls which origins may embed this resource cross-origin, preventing
    /// cross-origin information leaks via <img>, <video>, fetch, etc.
    cross_origin_resource_policy: []const u8 = "same-origin",

    /// Apply all configured security headers to a response.
    /// Each header is only set if the response does not already carry a header
    /// with that name — this prevents duplicate or conflicting headers when the
    /// upstream (e.g. a Rails app) already supplies its own security policy.
    pub fn apply(self: *const SecurityHeaders, response: *Response) void {
        if (self.x_frame_options.len > 0)
            _ = response.setHeaderIfAbsent("X-Frame-Options", self.x_frame_options);
        if (self.x_content_type_options.len > 0)
            _ = response.setHeaderIfAbsent("X-Content-Type-Options", self.x_content_type_options);
        if (self.content_security_policy.len > 0)
            _ = response.setHeaderIfAbsent("Content-Security-Policy", self.content_security_policy);
        if (self.strict_transport_security.len > 0)
            _ = response.setHeaderIfAbsent("Strict-Transport-Security", self.strict_transport_security);
        if (self.referrer_policy.len > 0)
            _ = response.setHeaderIfAbsent("Referrer-Policy", self.referrer_policy);
        if (self.permissions_policy.len > 0)
            _ = response.setHeaderIfAbsent("Permissions-Policy", self.permissions_policy);
        if (self.x_xss_protection.len > 0)
            _ = response.setHeaderIfAbsent("X-XSS-Protection", self.x_xss_protection);
        if (self.cross_origin_opener_policy.len > 0)
            _ = response.setHeaderIfAbsent("Cross-Origin-Opener-Policy", self.cross_origin_opener_policy);
        if (self.cross_origin_resource_policy.len > 0)
            _ = response.setHeaderIfAbsent("Cross-Origin-Resource-Policy", self.cross_origin_resource_policy);
        appendRequestScopedHeaders(response);
        applyProtectedCachePolicy(response, request_cache_policy);
    }

    /// Default secure configuration.
    pub const default: SecurityHeaders = .{};

    /// API-oriented configuration. Includes the full default security header
    /// set: CSP (`default-src 'self'`), X-Frame-Options (`DENY`), COOP, CORP,
    /// and all other standard headers. Operators can override individual fields
    /// in config if a looser policy is required for their application.
    pub const api: SecurityHeaders = .{};
};

/// Append the request-scoped headers, skipping any exact name/value pair the
/// response already carries so a response decorated twice stays correct.
fn appendRequestScopedHeaders(response: *Response) void {
    outer: for (request_scoped_headers) |scoped| {
        for (response.headers.iterator()) |existing| {
            if (std.ascii.eqlIgnoreCase(existing.name, scoped.name) and std.mem.eql(u8, existing.value, scoped.value)) continue :outer;
        }
        response.headers.append(scoped.name, scoped.value) catch {};
    }
}

// Tests

test "protectedCacheControl never leaves a protected response shared-cacheable" {
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("private, max-age=600", protectedCacheControl(&buf, "public, max-age=600, s-maxage=3600", .private));
    try std.testing.expectEqualStrings("private", protectedCacheControl(&buf, null, .private));
    try std.testing.expectEqualStrings("private, no-cache", protectedCacheControl(&buf, "private=\"Set-Cookie\", no-cache, proxy-revalidate", .private));
    try std.testing.expectEqualStrings("no-store", protectedCacheControl(&buf, "public, NO-STORE", .private));
    try std.testing.expectEqualStrings("no-store", protectedCacheControl(&buf, "public, max-age=600", .no_store));
}

test "apply rewrites Cache-Control under a protected request scope" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();
    _ = response.setHeader("Cache-Control", "public, max-age=600");
    setRequestScope(&.{}, .private);
    defer clearRequestScope();
    const sec = SecurityHeaders{};
    sec.apply(&response);
    try std.testing.expectEqual(@as(usize, 1), response.headers.countByName("cache-control"));
    try std.testing.expectEqualStrings("private, max-age=600", response.headers.get("cache-control").?);
}

test "apply adds request-scoped headers once, keeping repeated names" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();
    const scoped = [_]ScopedHeader{
        .{ .name = "Set-Cookie", .value = "a=1" },
        .{ .name = "Set-Cookie", .value = "b=2" },
    };
    setRequestScope(&scoped, .none);
    defer clearRequestScope();
    const sec = SecurityHeaders{};
    sec.apply(&response);
    sec.apply(&response);
    try std.testing.expectEqual(@as(usize, 2), response.headers.countByName("set-cookie"));
}

test "apply sets all default security headers" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();

    const headers = SecurityHeaders.default;
    headers.apply(&response);

    try std.testing.expectEqualStrings("DENY", response.headers.get("X-Frame-Options").?);
    try std.testing.expectEqualStrings("nosniff", response.headers.get("X-Content-Type-Options").?);
    try std.testing.expectEqualStrings("default-src 'self'", response.headers.get("Content-Security-Policy").?);
    try std.testing.expect(response.headers.get("Strict-Transport-Security") == null);
    try std.testing.expectEqualStrings("strict-origin-when-cross-origin", response.headers.get("Referrer-Policy").?);
    try std.testing.expectEqualStrings("0", response.headers.get("X-XSS-Protection").?);
    try std.testing.expectEqualStrings("same-origin", response.headers.get("Cross-Origin-Opener-Policy").?);
    try std.testing.expectEqualStrings("same-origin", response.headers.get("Cross-Origin-Resource-Policy").?);
}

test "api preset includes csp and x-frame-options alongside coop and corp" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();

    const headers = SecurityHeaders.api;
    headers.apply(&response);

    try std.testing.expectEqualStrings("DENY", response.headers.get("X-Frame-Options").?);
    try std.testing.expectEqualStrings("default-src 'self'", response.headers.get("Content-Security-Policy").?);
    try std.testing.expectEqualStrings("nosniff", response.headers.get("X-Content-Type-Options").?);
    try std.testing.expectEqualStrings("same-origin", response.headers.get("Cross-Origin-Opener-Policy").?);
    try std.testing.expectEqualStrings("same-origin", response.headers.get("Cross-Origin-Resource-Policy").?);
}

test "hsts is emitted when strict_transport_security is set" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();

    var headers = SecurityHeaders.default;
    headers.strict_transport_security = "max-age=31536000; includeSubDomains";
    headers.apply(&response);

    try std.testing.expectEqualStrings(
        "max-age=31536000; includeSubDomains",
        response.headers.get("Strict-Transport-Security").?,
    );
}

test "hsts is absent when strict_transport_security is empty" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();

    const headers = SecurityHeaders.default;
    headers.apply(&response);

    try std.testing.expect(response.headers.get("Strict-Transport-Security") == null);
}
