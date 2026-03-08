const std = @import("std");

pub const Endpoint = struct {
    host: []const u8,
    port: u16,
};

pub fn parseEndpoint(raw: []const u8) !Endpoint {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    const colon = std.mem.lastIndexOfScalar(u8, trimmed, ':') orelse return error.InvalidEndpoint;
    const host = trimmed[0..colon];
    const port_str = trimmed[colon + 1 ..];
    if (host.len == 0 or port_str.len == 0) return error.InvalidEndpoint;
    const port = try std.fmt.parseInt(u16, port_str, 10);
    return .{ .host = host, .port = port };
}

pub fn get(allocator: std.mem.Allocator, endpoint: []const u8, key: []const u8) !?[]u8 {
    const ep = try parseEndpoint(endpoint);
    const stream = try std.net.tcpConnectToHost(allocator, ep.host, ep.port);
    defer stream.close();
    try stream.writer().print("get {s}\r\n", .{key});
    var buf: [64 * 1024]u8 = undefined;
    const n = try stream.read(&buf);
    if (n == 0) return null;
    const resp = buf[0..n];
    if (std.mem.startsWith(u8, resp, "END\r\n")) return null;
    const value_start = std.mem.indexOf(u8, resp, "\r\n") orelse return error.InvalidResponse;
    const value_end = std.mem.indexOfPos(u8, resp, value_start + 2, "\r\nEND\r\n") orelse return error.InvalidResponse;
    return try allocator.dupe(u8, resp[value_start + 2 .. value_end]);
}

pub fn set(allocator: std.mem.Allocator, endpoint: []const u8, key: []const u8, value: []const u8, ttl: u32) !bool {
    const ep = try parseEndpoint(endpoint);
    const stream = try std.net.tcpConnectToHost(allocator, ep.host, ep.port);
    defer stream.close();
    try stream.writer().print("set {s} 0 {d} {d}\r\n", .{ key, ttl, value.len });
    try stream.writer().writeAll(value);
    try stream.writer().writeAll("\r\n");
    var buf: [256]u8 = undefined;
    const n = try stream.read(&buf);
    if (n == 0) return false;
    return std.mem.indexOf(u8, buf[0..n], "STORED") != null;
}

test "parseEndpoint parses host and port" {
    const ep = try parseEndpoint("127.0.0.1:11211");
    try std.testing.expectEqualStrings("127.0.0.1", ep.host);
    try std.testing.expectEqual(@as(u16, 11211), ep.port);
}
