const std = @import("std");

pub const Version1: u8 = 1;
pub const BeginRequest: u8 = 1;
pub const Params: u8 = 4;
pub const Stdin: u8 = 5;

fn writeHeader(out: *std.ArrayList(u8), kind: u8, request_id: u16, content_len: u16, padding_len: u8) !void {
    try out.append(Version1);
    try out.append(kind);
    try out.append(@intCast((request_id >> 8) & 0xff));
    try out.append(@intCast(request_id & 0xff));
    try out.append(@intCast((content_len >> 8) & 0xff));
    try out.append(@intCast(content_len & 0xff));
    try out.append(padding_len);
    try out.append(0);
}

fn appendNameValue(out: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    if (name.len < 128) {
        try out.append(@intCast(name.len));
    } else {
        const n = 0x80000000 | @as(u32, @intCast(name.len));
        try out.appendSlice(&[_]u8{ @intCast((n >> 24) & 0xff), @intCast((n >> 16) & 0xff), @intCast((n >> 8) & 0xff), @intCast(n & 0xff) });
    }

    if (value.len < 128) {
        try out.append(@intCast(value.len));
    } else {
        const v = 0x80000000 | @as(u32, @intCast(value.len));
        try out.appendSlice(&[_]u8{ @intCast((v >> 24) & 0xff), @intCast((v >> 16) & 0xff), @intCast((v >> 8) & 0xff), @intCast(v & 0xff) });
    }
    try out.appendSlice(name);
    try out.appendSlice(value);
}

pub fn buildRequest(
    allocator: std.mem.Allocator,
    method: []const u8,
    script_filename: []const u8,
    request_uri: []const u8,
    body: []const u8,
) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    // BEGIN_REQUEST record
    try writeHeader(&out, BeginRequest, 1, 8, 0);
    try out.appendSlice(&[_]u8{
        0, 1, // role = responder
        0, // flags
        0,
        0,
        0,
        0,
        0,
    });

    var params = std.ArrayList(u8).init(allocator);
    defer params.deinit();
    try appendNameValue(&params, "REQUEST_METHOD", method);
    try appendNameValue(&params, "SCRIPT_FILENAME", script_filename);
    try appendNameValue(&params, "REQUEST_URI", request_uri);
    var len_buf: [32]u8 = undefined;
    const len_str = try std.fmt.bufPrint(&len_buf, "{d}", .{body.len});
    try appendNameValue(&params, "CONTENT_LENGTH", len_str);

    try writeHeader(&out, Params, 1, @intCast(params.items.len), 0);
    try out.appendSlice(params.items);
    try writeHeader(&out, Params, 1, 0, 0); // end params

    if (body.len > 0) {
        try writeHeader(&out, Stdin, 1, @intCast(body.len), 0);
        try out.appendSlice(body);
    }
    try writeHeader(&out, Stdin, 1, 0, 0); // end stdin
    return out.toOwnedSlice();
}

test "buildRequest emits fcgi records" {
    const allocator = std.testing.allocator;
    const req = try buildRequest(allocator, "POST", "/srv/app.php", "/index.php", "hello");
    defer allocator.free(req);
    try std.testing.expect(req.len > 24);
    try std.testing.expectEqual(@as(u8, Version1), req[0]);
    try std.testing.expectEqual(@as(u8, BeginRequest), req[1]);
}
