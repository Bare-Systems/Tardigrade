const std = @import("std");
const Response = @import("response.zig").Response;

/// Standard security headers applied to all responses.
///
/// Maps to PLAN Phase 6.5 (Security Headers):
/// - X-Frame-Options
/// - X-Content-Type-Options
/// - Content-Security-Policy
/// - Strict-Transport-Security
/// - Referrer-Policy
/// - Permissions-Policy
pub const SecurityHeaders = struct {
    x_frame_options: []const u8 = "DENY",
    x_content_type_options: []const u8 = "nosniff",
    content_security_policy: []const u8 = "default-src 'self'",
    strict_transport_security: []const u8 = "max-age=31536000; includeSubDomains",
    referrer_policy: []const u8 = "strict-origin-when-cross-origin",
    permissions_policy: []const u8 = "camera=(), microphone=(), geolocation=()",
    x_xss_protection: []const u8 = "0", // Disabled per modern best practice (CSP preferred)

    /// Apply all configured security headers to a response.
    pub fn apply(self: *const SecurityHeaders, response: *Response) void {
        if (self.x_frame_options.len > 0)
            _ = response.setHeader("X-Frame-Options", self.x_frame_options);
        if (self.x_content_type_options.len > 0)
            _ = response.setHeader("X-Content-Type-Options", self.x_content_type_options);
        if (self.content_security_policy.len > 0)
            _ = response.setHeader("Content-Security-Policy", self.content_security_policy);
        if (self.strict_transport_security.len > 0)
            _ = response.setHeader("Strict-Transport-Security", self.strict_transport_security);
        if (self.referrer_policy.len > 0)
            _ = response.setHeader("Referrer-Policy", self.referrer_policy);
        if (self.permissions_policy.len > 0)
            _ = response.setHeader("Permissions-Policy", self.permissions_policy);
        if (self.x_xss_protection.len > 0)
            _ = response.setHeader("X-XSS-Protection", self.x_xss_protection);
    }

    /// Default secure configuration.
    pub const default: SecurityHeaders = .{};

    /// API-oriented configuration (no CSP frame restrictions).
    pub const api: SecurityHeaders = .{
        .x_frame_options = "",
        .content_security_policy = "",
        .strict_transport_security = "max-age=31536000; includeSubDomains",
    };
};

// Tests

test "apply sets all default security headers" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();

    const headers = SecurityHeaders.default;
    headers.apply(&response);

    try std.testing.expectEqualStrings("DENY", response.headers.get("X-Frame-Options").?);
    try std.testing.expectEqualStrings("nosniff", response.headers.get("X-Content-Type-Options").?);
    try std.testing.expectEqualStrings("default-src 'self'", response.headers.get("Content-Security-Policy").?);
    try std.testing.expectEqualStrings("max-age=31536000; includeSubDomains", response.headers.get("Strict-Transport-Security").?);
    try std.testing.expectEqualStrings("strict-origin-when-cross-origin", response.headers.get("Referrer-Policy").?);
    try std.testing.expectEqualStrings("0", response.headers.get("X-XSS-Protection").?);
}

test "api preset skips frame and csp headers" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();

    const headers = SecurityHeaders.api;
    headers.apply(&response);

    try std.testing.expect(response.headers.get("X-Frame-Options") == null);
    try std.testing.expect(response.headers.get("Content-Security-Policy") == null);
    try std.testing.expectEqualStrings("nosniff", response.headers.get("X-Content-Type-Options").?);
}
