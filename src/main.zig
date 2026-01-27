const std = @import("std");
const http = @import("http.zig");

const MAX_REQUEST_SIZE = 64 * 1024; // 64KB max request size
const MAX_BODY_SIZE = 1 * 1024 * 1024; // 1MB max body size

pub fn main() !void {
    const address = try std.net.Address.parseIp("0.0.0.0", 8069);

    var server = try std.net.Address.listen(address, .{
        .reuse_address = true,
    });
    defer server.deinit();

    std.log.info("Listening on 0.0.0.0:8069", .{});

    while (true) {
        const conn = try server.accept();
        defer conn.stream.close();
        handleConnection(&conn.stream) catch |err| {
            std.log.err("Connection error: {}", .{err});
        };
    }
}

fn handleConnection(stream: *const std.net.Stream) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var reader = stream.reader();
    const writer = stream.writer();

    // Read request data
    var buf: [MAX_REQUEST_SIZE]u8 = undefined;
    var total_read: usize = 0;

    // Read until we have the complete headers (ends with \r\n\r\n)
    while (total_read < buf.len) {
        const n = reader.read(buf[total_read..]) catch |err| {
            std.log.err("Read error: {}", .{err});
            return err;
        };
        if (n == 0) break; // Connection closed
        total_read += n;

        // Check if we have complete headers
        if (std.mem.indexOf(u8, buf[0..total_read], "\r\n\r\n")) |_| {
            break;
        }
    }

    if (total_read == 0) {
        return; // Empty request, client disconnected
    }

    const request_data = buf[0..total_read];

    // Parse the request
    const parse_result = http.Request.parse(allocator, request_data, MAX_BODY_SIZE) catch |err| {
        std.log.err("Parse error: {}", .{err});
        try sendError(writer, err);
        return;
    };
    var request = parse_result.request;
    defer request.deinit();

    std.log.info("{s} {s} {s}", .{
        request.method.toString(),
        request.uri.path,
        request.version.toString(),
    });

    // Handle the request based on method
    switch (request.method) {
        .GET, .HEAD => {
            try serveFile(request.uri.path, writer, request.method == .HEAD);
        },
        else => {
            try sendResponse(writer, 405, "Method Not Allowed", "Method Not Allowed");
        },
    }
}

fn sendError(writer: anytype, err: http.ParseError) !void {
    switch (err) {
        error.InvalidMethod => try sendResponse(writer, 501, "Not Implemented", "Unsupported HTTP method"),
        error.InvalidVersion => try sendResponse(writer, 505, "HTTP Version Not Supported", "HTTP Version Not Supported"),
        error.BodyTooLarge => try sendResponse(writer, 413, "Payload Too Large", "Request body too large"),
        error.HeaderTooLarge, error.HeadersTooLarge, error.TooManyHeaders => try sendResponse(writer, 431, "Request Header Fields Too Large", "Headers too large"),
        else => try sendResponse(writer, 400, "Bad Request", "Malformed request"),
    }
}

fn sendResponse(writer: anytype, status: u16, status_text: []const u8, body: []const u8) !void {
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ status, status_text });
    try writer.print("Content-Type: text/plain\r\n", .{});
    try writer.print("Content-Length: {d}\r\n", .{body.len});
    try writer.print("Connection: close\r\n", .{});
    try writer.print("\r\n", .{});
    try writer.writeAll(body);
}

fn serveFile(path: []const u8, writer: anytype, head_only: bool) !void {
    // Prevent path traversal
    if (std.mem.indexOf(u8, path, "..") != null) {
        try sendResponse(writer, 403, "Forbidden", "Access denied");
        return;
    }

    const fs_path = if (std.mem.eql(u8, path, "/"))
        "public/index.html"
    else blk: {
        var buffer: [512]u8 = undefined;
        const result = std.fmt.bufPrint(&buffer, "public{s}", .{path}) catch {
            try sendResponse(writer, 414, "URI Too Long", "URI Too Long");
            return;
        };
        break :blk result;
    };

    var file = std.fs.cwd().openFile(fs_path, .{}) catch {
        try sendResponse(writer, 404, "Not Found", "Not Found");
        return;
    };
    defer file.close();

    // Get file size
    const stat = file.stat() catch {
        try sendResponse(writer, 500, "Internal Server Error", "Internal Server Error");
        return;
    };
    const file_size = stat.size;

    // Determine content type
    const content_type = getContentType(fs_path);

    // Send headers
    try writer.print("HTTP/1.1 200 OK\r\n", .{});
    try writer.print("Content-Type: {s}\r\n", .{content_type});
    try writer.print("Content-Length: {d}\r\n", .{file_size});
    try writer.print("Connection: close\r\n", .{});
    try writer.print("\r\n", .{});

    // Send body (unless HEAD request)
    if (!head_only) {
        var file_reader = file.reader();
        var read_buf: [4096]u8 = undefined;
        while (true) {
            const n = try file_reader.read(&read_buf);
            if (n == 0) break;
            try writer.writeAll(read_buf[0..n]);
        }
    }
}

fn getContentType(path: []const u8) []const u8 {
    const extension = std.fs.path.extension(path);

    const content_types = std.StaticStringMap([]const u8).initComptime(.{
        .{ ".html", "text/html; charset=utf-8" },
        .{ ".htm", "text/html; charset=utf-8" },
        .{ ".css", "text/css; charset=utf-8" },
        .{ ".js", "text/javascript; charset=utf-8" },
        .{ ".json", "application/json" },
        .{ ".xml", "application/xml" },
        .{ ".txt", "text/plain; charset=utf-8" },
        .{ ".md", "text/markdown; charset=utf-8" },
        .{ ".png", "image/png" },
        .{ ".jpg", "image/jpeg" },
        .{ ".jpeg", "image/jpeg" },
        .{ ".gif", "image/gif" },
        .{ ".svg", "image/svg+xml" },
        .{ ".ico", "image/x-icon" },
        .{ ".webp", "image/webp" },
        .{ ".woff", "font/woff" },
        .{ ".woff2", "font/woff2" },
        .{ ".ttf", "font/ttf" },
        .{ ".otf", "font/otf" },
        .{ ".eot", "application/vnd.ms-fontobject" },
        .{ ".pdf", "application/pdf" },
        .{ ".zip", "application/zip" },
        .{ ".gz", "application/gzip" },
        .{ ".tar", "application/x-tar" },
        .{ ".mp3", "audio/mpeg" },
        .{ ".mp4", "video/mp4" },
        .{ ".webm", "video/webm" },
        .{ ".ogg", "audio/ogg" },
        .{ ".wav", "audio/wav" },
        .{ ".avi", "video/x-msvideo" },
        .{ ".mpeg", "video/mpeg" },
        .{ ".wasm", "application/wasm" },
    });

    return content_types.get(extension) orelse "application/octet-stream";
}

test {
    // Import and run tests from http module
    _ = @import("http.zig");
}
