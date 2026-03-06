const std = @import("std");
const main = @import("main.zig");
const http = @import("http.zig");

// Test streaming path for large files (>1MB)
test "static file large streaming sends full body" {
    const allocator = std.testing.allocator;
    const file_size: usize = 1_200_000; // 1.2MB

    const raw = "GET /large.bin HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const result = try http.Request.parse(allocator, raw, http.DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file_name = "large.bin";
    var f = try tmp.dir.createFile(file_name, .{});
    // Write a repeating pattern
    var written: usize = 0;
    while (written < file_size) {
        const chunk_size = if (file_size - written < 8192) file_size - written else 8192;
        var chunk = std.mem.alloc(allocator, u8, chunk_size) catch unreachable;
        defer allocator.free(chunk);
        for (chunk_size) |i| chunk[i] = @intCast(u8, (i & 0xFF));
        try f.writeAll(chunk);
        written += chunk_size;
    }
    try f.flush();

    // Prepare output buffer large enough
    var out_buf = try allocator.alloc(u8, file_size + 8192);
    defer allocator.free(out_buf);
    var stream = std.io.fixedBufferStream(out_buf);

    try main.serveFileContent(allocator, &req, file_name, stream.writer(), false, false, true, null);
    const output = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "200 OK") != null);

    const sep = std.mem.indexOf(u8, output, "\r\n\r\n") orelse @panic("no header-body separator");
    const body = output[sep + 4 ..];
    try std.testing.expectEqual(file_size, body.len);
    // spot-check first bytes
    try std.testing.expectEqual(@bitCast(u8, 0), body[0]);
}

// Test If-None-Match returns 304 and no body
test "static file If-None-Match returns 304 Not Modified" {
    const allocator = std.testing.allocator;
    const file_size: usize = 1024;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file_name = "et.bin";
    var f = try tmp.dir.createFile(file_name, .{});
    try f.writeAll("abcd");
    try f.flush();

    const stat = try f.stat();
    const msecs: usize = @intCast(usize, @divTrunc(stat.mtime, std.time.ns_per_s));
    const etag_buf = try http.etag.generateETag(allocator, stat.size, msecs);
    defer allocator.free(etag_buf);

    const raw = try std.fmt.allocPrint(allocator, "GET /{s} HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: {s}\r\n\r\n", .{ file_name, etag_buf });
    defer allocator.free(raw);

    const result = try http.Request.parse(allocator, raw, http.DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();

    var out_buf = try allocator.alloc(u8, 4096);
    defer allocator.free(out_buf);
    var stream = std.io.fixedBufferStream(out_buf);

    try main.serveFileContent(allocator, &req, file_name, stream.writer(), false, false, true, null);
    const output = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "304 Not Modified") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\r\n\r\n") == std.mem.indexOf(u8, output, "\r\n\r\n"));
    // ensure no body content after separator
    const sep = std.mem.indexOf(u8, output, "\r\n\r\n") orelse @panic("no header-body separator");
    const body = output[sep + 4 ..];
    try std.testing.expectEqual(0, body.len);
}
