const std = @import("std");

pub fn buildRequest(
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    body: []const u8,
) ![]u8 {
    var headers = std.ArrayList(u8).init(allocator);
    defer headers.deinit();
    var len_buf: [32]u8 = undefined;
    const body_len = try std.fmt.bufPrint(&len_buf, "{d}", .{body.len});
    try appendHeader(&headers, "CONTENT_LENGTH", body_len);
    try appendHeader(&headers, "SCGI", "1");
    try appendHeader(&headers, "REQUEST_METHOD", method);
    try appendHeader(&headers, "REQUEST_URI", path);

    const netstring_len = headers.items.len;
    const prefix = try std.fmt.allocPrint(allocator, "{d}:", .{netstring_len});
    defer allocator.free(prefix);

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.appendSlice(prefix);
    try out.appendSlice(headers.items);
    try out.append(',');
    try out.appendSlice(body);
    return out.toOwnedSlice();
}

fn appendHeader(out: *std.ArrayList(u8), key: []const u8, value: []const u8) !void {
    try out.appendSlice(key);
    try out.append(0);
    try out.appendSlice(value);
    try out.append(0);
}

test "buildRequest writes scgi netstring prefix" {
    const allocator = std.testing.allocator;
    const req = try buildRequest(allocator, "GET", "/x", "");
    defer allocator.free(req);
    try std.testing.expect(std.mem.indexOfScalar(u8, req, ':') != null);
}
