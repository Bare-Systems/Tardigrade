const std = @import("std");
const ngtcp2_binding = @import("ngtcp2_binding.zig");
const Headers = @import("headers.zig").Headers;
const http3_session = @import("http3_session.zig");
const Response = @import("response.zig").Response;

pub const Http3Error = error{
    Http3Disabled,
    DependencyUnavailable,
    NotYetImplemented,
};

pub const HandlerConfig = struct {
    enable_0rtt: bool = false,
    connection_migration: bool = false,
    max_datagram_size: usize = 1350,
};

pub const Handler = struct {
    allocator: std.mem.Allocator,
    config: HandlerConfig,

    pub fn init(allocator: std.mem.Allocator, config: HandlerConfig) Http3Error!Handler {
        ngtcp2_binding.validateConfig(.{
            .enable_0rtt = config.enable_0rtt,
            .connection_migration = config.connection_migration,
            .max_datagram_size = config.max_datagram_size,
        }) catch |err| switch (err) {
            error.DependencyUnavailable => return error.DependencyUnavailable,
            else => return error.NotYetImplemented,
        };
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn advertisedAltSvc(self: *const Handler, allocator: std.mem.Allocator, https_port: u16) ![]u8 {
        _ = self;
        return formatAltSvc(allocator, https_port);
    }

    pub fn mapPseudoHeadersToRequest(
        allocator: std.mem.Allocator,
        method: []const u8,
        path: []const u8,
        authority: ?[]const u8,
        header_fields: []const http3_session.HeaderField,
        body: []const u8,
    ) !struct { headers: Headers, body_copy: []u8 } {
        var headers = Headers.init(allocator);
        errdefer headers.deinit();
        for (header_fields) |field| {
            if (field.name.len == 0 or field.name[0] == ':') continue;
            try headers.append(field.name, field.value);
        }
        if (authority) |host| {
            if (headers.get("host") == null) try headers.append("Host", host);
        }
        if (headers.get(":method") == null) _ = method;
        if (headers.get(":path") == null) _ = path;
        return .{
            .headers = headers,
            .body_copy = try allocator.dupe(u8, body),
        };
    }

    pub fn encodeResponseHeaders(self: *const Handler, allocator: std.mem.Allocator, response: *const Response) !http3_session.EncodedHeaderBlock {
        _ = self;
        return http3_session.encodeResponseHeaderBlock(allocator, response);
    }
};

pub fn formatAltSvc(allocator: std.mem.Allocator, https_port: u16) ![]u8 {
    return std.fmt.allocPrint(allocator, "h3=\":{d}\"", .{https_port});
}

pub fn configurationStatus(http3_enabled: bool, tls_ready: bool) []const u8 {
    if (!http3_enabled) return "disabled";
    if (!tls_ready) return "config_incomplete";
    return "configured";
}

test "http3 handler alt-svc formatting" {
    const value = try formatAltSvc(std.testing.allocator, 443);
    defer std.testing.allocator.free(value);
    try std.testing.expectEqualStrings("h3=\":443\"", value);
}

test "http3 handler configuration status reports expected states" {
    try std.testing.expectEqualStrings("disabled", configurationStatus(false, false));
    try std.testing.expectEqualStrings("config_incomplete", configurationStatus(true, false));
    try std.testing.expectEqualStrings("configured", configurationStatus(true, true));
}

test "http3 handler header mapping skips pseudo headers" {
    const allocator = std.testing.allocator;
    var mapped = try Handler.mapPseudoHeadersToRequest(allocator, "GET", "/status", "example.com", &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/status" },
        .{ .name = "accept", .value = "application/json" },
    }, "");
    defer mapped.headers.deinit();
    defer allocator.free(mapped.body_copy);
    try std.testing.expectEqualStrings("application/json", mapped.headers.get("accept").?);
    try std.testing.expectEqualStrings("example.com", mapped.headers.get("Host").?);
}
