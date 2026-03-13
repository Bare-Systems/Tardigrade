const std = @import("std");

pub const Entry = struct {
    ts_ms: i64,
    scope: []const u8,
    route: []const u8,
    correlation_id: []const u8,
    identity: []const u8,
    client_ip: []const u8,
    upstream_url: []const u8,
    request_body: []const u8,
    response_status: u16,
    response_content_type: []const u8,
    response_body: []const u8,
};

pub fn append(allocator: std.mem.Allocator, path: []const u8, entry: Entry) !void {
    if (path.len == 0) return;

    if (std.fs.path.dirname(path)) |dir_name| {
        std.fs.makeDirAbsolute(dir_name) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    const file = try std.fs.createFileAbsolute(path, .{ .read = true, .truncate = false });
    defer file.close();
    try file.seekFromEnd(0);

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try std.json.stringify(entry, .{}, buf.writer());
    try file.writeAll(buf.items);
    try file.writeAll("\n");
}

test "transcript store appends ndjson records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/transcripts.ndjson", .{tmp_abs});
    defer allocator.free(path);

    try append(allocator, path, .{
        .ts_ms = 1,
        .scope = "chat",
        .route = "/v1/chat",
        .correlation_id = "corr-1",
        .identity = "user-1",
        .client_ip = "127.0.0.1",
        .upstream_url = "http://127.0.0.1:8080/v1/chat",
        .request_body = "{\"message\":\"hello\"}",
        .response_status = 200,
        .response_content_type = "application/json",
        .response_body = "{\"ok\":true}",
    });

    const contents = try std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
    defer allocator.free(contents);
    try std.testing.expect(std.mem.indexOf(u8, contents, "\"scope\":\"chat\"") != null);
    try std.testing.expect(std.mem.endsWith(u8, contents, "\n"));
}
