//! HTTP reverse-proxy target and URL resolution helpers.
//!
//! This module owns all logic for deciding where a proxied request goes:
//! proxy_pass target combination, request-query preservation, redirect target
//! resolution, upstream host extraction, and Unix-socket endpoint detection.
//! It performs no network I/O and no downstream response formatting.

const compat = @import("zig_compat.zig");
const std = @import("std");
const gph = @import("gateway_proxy_headers.zig");
const gs = @import("gateway_state.zig");

const MaybeOwnedBytes = gph.MaybeOwnedBytes;
const isAbsoluteHttpUrl = gs.isAbsoluteHttpUrl;

pub const ResolvedProxyTarget = struct {
    url: []u8,
    upstream_host: []const u8,
    unix_socket_path: ?[]const u8 = null,
};

pub fn isRedirectStatusCode(status_code: u16) bool {
    return switch (status_code) {
        301, 302, 303, 307, 308 => true,
        else => false,
    };
}

pub fn resolveProxyTarget(
    allocator: std.mem.Allocator,
    upstream_base_url: []const u8,
    proxy_pass_target: []const u8,
    suffix_path: ?[]const u8,
) !ResolvedProxyTarget {
    const target_trimmed = std.mem.trim(u8, proxy_pass_target, " \t\r\n");
    const target = if (target_trimmed.len == 0) "/" else target_trimmed;
    const combined_target = try combineProxyTarget(allocator, target, suffix_path);
    errdefer allocator.free(combined_target);

    if (isAbsoluteHttpUrl(target)) {
        return .{
            .url = combined_target,
            .upstream_host = parseUpstreamHost(combined_target) orelse "",
            .unix_socket_path = null,
        };
    }

    if (unixSocketPathFromEndpoint(upstream_base_url)) |socket_path| {
        var normalized: []const u8 = combined_target;
        if (!std.mem.startsWith(u8, normalized, "/")) {
            const with_slash = try std.fmt.allocPrint(allocator, "/{s}", .{normalized});
            allocator.free(combined_target);
            normalized = with_slash;
        }
        const full_url = try std.fmt.allocPrint(allocator, "http://localhost{s}", .{normalized});
        allocator.free(normalized);
        return .{
            .url = full_url,
            .upstream_host = socket_path,
            .unix_socket_path = socket_path,
        };
    }

    var normalized: []const u8 = combined_target;
    if (!std.mem.startsWith(u8, normalized, "/")) {
        const with_slash = try std.fmt.allocPrint(allocator, "/{s}", .{normalized});
        allocator.free(combined_target);
        normalized = with_slash;
    }
    errdefer if (normalized.ptr != combined_target.ptr) allocator.free(normalized);

    const full_url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ upstream_base_url, normalized });
    if (normalized.ptr != combined_target.ptr) allocator.free(normalized);
    allocator.free(combined_target);

    return .{
        .url = full_url,
        .upstream_host = parseUpstreamHost(upstream_base_url) orelse "",
        .unix_socket_path = null,
    };
}

pub fn appendProxyQueryString(
    allocator: std.mem.Allocator,
    url: []const u8,
    query: ?[]const u8,
) !MaybeOwnedBytes {
    const value = query orelse return .{ .value = url };
    if (value.len == 0) return .{ .value = url };
    if (std.mem.findScalar(u8, url, '?') != null) {
        const owned = try std.fmt.allocPrint(allocator, "{s}&{s}", .{ url, value });
        return .{ .value = owned, .owned = owned };
    }
    const owned = try std.fmt.allocPrint(allocator, "{s}?{s}", .{ url, value });
    return .{ .value = owned, .owned = owned };
}

pub fn resolveRedirectTargetUrl(allocator: std.mem.Allocator, current_url: []const u8, location: []const u8) ![]u8 {
    if (isAbsoluteHttpUrl(location)) return allocator.dupe(u8, location);
    if (!std.mem.startsWith(u8, location, "/")) return error.HttpRedirectLocationInvalid;

    const current_uri = try std.Uri.parse(current_url);
    const scheme = current_uri.scheme;
    const host = (current_uri.host orelse return error.HttpRedirectLocationInvalid).raw;
    if (current_uri.port) |port| {
        return std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ scheme, host, port, location });
    }
    return std.fmt.allocPrint(allocator, "{s}://{s}{s}", .{ scheme, host, location });
}

pub fn unixSocketPathFromEndpoint(endpoint: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, endpoint, "unix://")) {
        const path = endpoint["unix://".len..];
        if (path.len == 0) return null;
        return path;
    }
    if (std.mem.startsWith(u8, endpoint, "unix:")) {
        const path = endpoint["unix:".len..];
        if (path.len == 0) return null;
        return path;
    }
    return null;
}

pub fn combineProxyTarget(allocator: std.mem.Allocator, target: []const u8, suffix_path: ?[]const u8) ![]u8 {
    if (suffix_path == null) return allocator.dupe(u8, target);

    const suffix = suffix_path.?;
    const left_trimmed = compat.trimRight(u8, target, "/");
    const right_trimmed = std.mem.trimStart(u8, suffix, "/");

    if (left_trimmed.len == 0) {
        return std.fmt.allocPrint(allocator, "/{s}", .{right_trimmed});
    }

    if (right_trimmed.len == 0) {
        return allocator.dupe(u8, left_trimmed);
    }

    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ left_trimmed, right_trimmed });
}

pub fn parseUpstreamHost(base_url: []const u8) ?[]const u8 {
    const scheme_end = std.mem.find(u8, base_url, "://") orelse return null;
    const authority_start = scheme_end + 3;
    if (authority_start >= base_url.len) return null;

    const path_start = std.mem.findScalarPos(u8, base_url, authority_start, '/') orelse base_url.len;
    if (path_start <= authority_start) return null;
    return base_url[authority_start..path_start];
}

test "parseUpstreamHost extracts authority" {
    try std.testing.expectEqualStrings("127.0.0.1:8080", parseUpstreamHost("http://127.0.0.1:8080") orelse "");
    try std.testing.expectEqualStrings("api.example.com", parseUpstreamHost("https://api.example.com/v1") orelse "");
    try std.testing.expect(parseUpstreamHost("invalid-url") == null);
}

test "combineProxyTarget joins prefix and suffix" {
    const allocator = std.testing.allocator;
    const joined = try combineProxyTarget(allocator, "/api", "/api/messages");
    defer allocator.free(joined);
    try std.testing.expectEqualStrings("/api/api/messages", joined);
}

test "resolveProxyTarget handles absolute and relative proxy_pass" {
    const allocator = std.testing.allocator;

    const abs = try resolveProxyTarget(allocator, "http://127.0.0.1:8080", "https://api.example.com/base", "/api/messages");
    defer allocator.free(abs.url);
    try std.testing.expectEqualStrings("https://api.example.com/base/api/messages", abs.url);
    try std.testing.expectEqualStrings("api.example.com", abs.upstream_host);

    const rel = try resolveProxyTarget(allocator, "http://127.0.0.1:8080", "/gateway", "/v1/tools");
    defer allocator.free(rel.url);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/gateway/v1/tools", rel.url);
    try std.testing.expectEqualStrings("127.0.0.1:8080", rel.upstream_host);
}

test "resolveProxyTarget supports unix socket upstream base" {
    const allocator = std.testing.allocator;
    const resolved = try resolveProxyTarget(allocator, "unix:/tmp/tardigrade.sock", "/gateway", "/api/messages");
    defer allocator.free(resolved.url);
    try std.testing.expectEqualStrings("http://localhost/gateway/api/messages", resolved.url);
    try std.testing.expectEqualStrings("/tmp/tardigrade.sock", resolved.upstream_host);
    try std.testing.expect(resolved.unix_socket_path != null);
    try std.testing.expectEqualStrings("/tmp/tardigrade.sock", resolved.unix_socket_path.?);
}

test "appendProxyQueryString preserves request query" {
    const allocator = std.testing.allocator;

    var appended = try appendProxyQueryString(allocator, "http://127.0.0.1:8080/auth/login", "next=%2F");
    defer appended.deinit(allocator);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/auth/login?next=%2F", appended.value);

    var appended_existing = try appendProxyQueryString(allocator, "http://127.0.0.1:8080/auth/login?foo=bar", "next=%2F");
    defer appended_existing.deinit(allocator);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/auth/login?foo=bar&next=%2F", appended_existing.value);
}

test "appendProxyQueryString borrows base url when request has no query" {
    const base = "http://127.0.0.1:8080/auth/login";
    const appended = try appendProxyQueryString(std.testing.allocator, base, null);
    try std.testing.expect(appended.owned == null);
    try std.testing.expectEqual(@intFromPtr(base.ptr), @intFromPtr(appended.value.ptr));
}
