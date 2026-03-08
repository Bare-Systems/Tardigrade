const std = @import("std");

pub fn buildPacket(
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    body: []const u8,
) ![]u8 {
    var vars = std.ArrayList(u8).init(allocator);
    defer vars.deinit();

    try appendKv(&vars, "REQUEST_METHOD", method);
    try appendKv(&vars, "PATH_INFO", path);
    var len_buf: [32]u8 = undefined;
    const len_str = try std.fmt.bufPrint(&len_buf, "{d}", .{body.len});
    try appendKv(&vars, "CONTENT_LENGTH", len_str);

    const size: u16 = @intCast(vars.items.len);
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(0);
    try out.append(@intCast(size & 0xff));
    try out.append(@intCast((size >> 8) & 0xff));
    try out.append(0);
    try out.appendSlice(vars.items);
    try out.appendSlice(body);
    return out.toOwnedSlice();
}

fn appendKv(out: *std.ArrayList(u8), key: []const u8, value: []const u8) !void {
    try out.append(@intCast(key.len & 0xff));
    try out.append(@intCast((key.len >> 8) & 0xff));
    try out.append(@intCast(value.len & 0xff));
    try out.append(@intCast((value.len >> 8) & 0xff));
    try out.appendSlice(key);
    try out.appendSlice(value);
}

test "buildPacket writes uwsgi header" {
    const allocator = std.testing.allocator;
    const pkt = try buildPacket(allocator, "POST", "/rpc", "abc");
    defer allocator.free(pkt);
    try std.testing.expect(pkt.len > 12);
    try std.testing.expectEqual(@as(u8, 0), pkt[0]);
}
