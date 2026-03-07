const std = @import("std");

/// API version routing.
///
/// Extracts the version number from paths like `/v1/chat`, `/v2/users`, etc.
/// and provides the remaining path segment for downstream routing.
pub const VersionedRoute = struct {
    version: u16,
    /// Path after the version prefix (e.g. "/chat" from "/v1/chat").
    path: []const u8,
};

/// Parse a versioned API path.
///
/// Recognises `/v<N>/...` patterns where N is a positive integer.
/// Returns null for paths that don't match the pattern.
pub fn parseVersionedPath(path: []const u8) ?VersionedRoute {
    if (path.len < 3) return null; // need at least "/vN"
    if (path[0] != '/' or path[1] != 'v') return null;

    // Find the end of the version number
    var i: usize = 2;
    while (i < path.len and std.ascii.isDigit(path[i])) : (i += 1) {}

    if (i == 2) return null; // no digits after "v"

    const version = std.fmt.parseInt(u16, path[2..i], 10) catch return null;
    if (version == 0) return null; // v0 is not a valid API version

    // Remaining path (could be "/" or "/resource")
    const remaining = if (i < path.len) path[i..] else "";
    return .{
        .version = version,
        .path = remaining,
    };
}

/// Check whether a given path matches a specific API version and route.
pub fn matchRoute(path: []const u8, version: u16, route: []const u8) bool {
    const parsed = parseVersionedPath(path) orelse return false;
    return parsed.version == version and std.mem.eql(u8, parsed.path, route);
}

/// Supported API versions. New versions can be added here.
pub const SUPPORTED_VERSIONS = [_]u16{ 1, 2 };

pub fn isSupportedVersion(version: u16) bool {
    for (SUPPORTED_VERSIONS) |v| {
        if (v == version) return true;
    }
    return false;
}

// Tests

test "parseVersionedPath extracts version and route" {
    const route = parseVersionedPath("/v1/chat").?;
    try std.testing.expectEqual(@as(u16, 1), route.version);
    try std.testing.expectEqualStrings("/chat", route.path);
}

test "parseVersionedPath handles multi-digit version" {
    const route = parseVersionedPath("/v12/users/list").?;
    try std.testing.expectEqual(@as(u16, 12), route.version);
    try std.testing.expectEqualStrings("/users/list", route.path);
}

test "parseVersionedPath returns null for non-versioned paths" {
    try std.testing.expect(parseVersionedPath("/health") == null);
    try std.testing.expect(parseVersionedPath("/api/chat") == null);
    try std.testing.expect(parseVersionedPath("/v/chat") == null); // no digits
    try std.testing.expect(parseVersionedPath("/v0/chat") == null); // v0 invalid
    try std.testing.expect(parseVersionedPath("") == null);
    try std.testing.expect(parseVersionedPath("/") == null);
}

test "parseVersionedPath handles bare version" {
    const route = parseVersionedPath("/v3").?;
    try std.testing.expectEqual(@as(u16, 3), route.version);
    try std.testing.expectEqualStrings("", route.path);
}

test "matchRoute checks version and path" {
    try std.testing.expect(matchRoute("/v1/chat", 1, "/chat"));
    try std.testing.expect(!matchRoute("/v2/chat", 1, "/chat"));
    try std.testing.expect(!matchRoute("/v1/users", 1, "/chat"));
    try std.testing.expect(!matchRoute("/health", 1, "/health"));
}

test "isSupportedVersion checks allowlist" {
    try std.testing.expect(isSupportedVersion(1));
    try std.testing.expect(isSupportedVersion(2));
    try std.testing.expect(!isSupportedVersion(99));
}
