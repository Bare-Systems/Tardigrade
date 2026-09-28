const std = @import("std");
const Response = @import("response.zig").Response;

/// A response header scoped to the request currently being handled on this
/// thread (#761: `forward_auth_client_headers` on an allowed request).
pub const ScopedHeader = struct {
    name: []const u8,
    value: []const u8,
};

/// HTTP/1.1 handles one request at a time per worker thread, and every H1
/// response head passes through `SecurityHeaders.apply` or the raw
/// security-header writer. Scoping extra headers here lets them reach proxied
/// (buffered and streamed), static, local and upgrade responses without
/// threading them through each writer. Callers must pair `set` with `clear`.
threadlocal var request_scoped_headers: []const ScopedHeader = &.{};

pub fn setRequestScopedHeaders(headers: []const ScopedHeader) void {
    request_scoped_headers = headers;
}

pub fn clearRequestScopedHeaders() void {
    request_scoped_headers = &.{};
}

pub fn requestScopedHeaders() []const ScopedHeader {
    return request_scoped_headers;
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

test "apply adds request-scoped headers once, keeping repeated names" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();
    const scoped = [_]ScopedHeader{
        .{ .name = "Set-Cookie", .value = "a=1" },
        .{ .name = "Set-Cookie", .value = "b=2" },
    };
    setRequestScopedHeaders(&scoped);
    defer clearRequestScopedHeaders();
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
