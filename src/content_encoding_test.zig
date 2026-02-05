const std = @import("std");
const main = @import("main.zig");
const http = @import("http.zig");

// Test Accept-Encoding: identity (should succeed)
test "static file Accept-Encoding identity" {
    const allocator = std.testing.allocator;
    const raw = "GET /test.txt HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: identity\r\n\r\n";
    const result = try http.Request.parse(allocator, raw, http.DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();
    // Simulate file exists: create a temp file
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file_name = "test.txt";
    var file = try tmp.dir.createFile(file_name, .{});
    try file.writeAll("hello world");
    // Call serveFileContent
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try main.serveFileContent(allocator, &req, file_name, stream.writer(), false, false, true);
    const output = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Content-Encoding") == null or std.mem.indexOf(u8, output, "identity") != null);
}

// Test Accept-Encoding: br (should 406)
test "static file Accept-Encoding br returns 406" {
    const allocator = std.testing.allocator;
    const raw = "GET /test.txt HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: br\r\n\r\n";
    const result = try http.Request.parse(allocator, raw, http.DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();
    // Simulate file exists: create a temp file
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file_name = "test.txt";
    var file = try tmp.dir.createFile(file_name, .{});
    try file.writeAll("hello world");
    // Call serveFileContent
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try main.serveFileContent(allocator, &req, file_name, stream.writer(), false, false, true);
    const output = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "406 Not Acceptable") != null);
}

// Test Accept-Encoding: gzip, identity (should succeed as identity)
test "static file Accept-Encoding gzip, identity" {
    const allocator = std.testing.allocator;
    const raw = "GET /test.txt HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip, identity\r\n\r\n";
    const result = try http.Request.parse(allocator, raw, http.DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();
    // Simulate file exists: create a temp file
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file_name = "test.txt";
    var file = try tmp.dir.createFile(file_name, .{});
    try file.writeAll("hello world");
    // Call serveFileContent
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try main.serveFileContent(allocator, &req, file_name, stream.writer(), false, false, true);
    const output = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Content-Encoding") == null or std.mem.indexOf(u8, output, "identity") != null);
}
