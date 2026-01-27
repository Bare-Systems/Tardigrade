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
        try sendParseError(allocator, writer, err);
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
            try serveFile(allocator, request.uri.path, writer, request.method == .HEAD);
        },
        else => {
            var response = http.Response.methodNotAllowed(allocator, "GET, HEAD");
            defer response.deinit();
            try response.write(writer);
        },
    }
}

fn sendParseError(allocator: std.mem.Allocator, writer: anytype, err: http.ParseError) !void {
    var response = switch (err) {
        error.InvalidMethod => http.Response.notImplemented(allocator),
        error.InvalidVersion => http.Response.httpVersionNotSupported(allocator),
        error.BodyTooLarge => http.Response.payloadTooLarge(allocator),
        error.HeaderTooLarge, error.HeadersTooLarge, error.TooManyHeaders => http.Response.headersTooLarge(allocator),
        else => http.Response.badRequest(allocator, "Malformed request"),
    };
    defer response.deinit();
    try response.write(writer);
}

fn serveFile(allocator: std.mem.Allocator, path: []const u8, writer: anytype, head_only: bool) !void {
    // Prevent path traversal
    if (std.mem.indexOf(u8, path, "..") != null) {
        var response = http.Response.forbidden(allocator);
        defer response.deinit();
        try response.write(writer);
        return;
    }

    const fs_path = if (std.mem.eql(u8, path, "/"))
        "public/index.html"
    else blk: {
        var buffer: [512]u8 = undefined;
        const result = std.fmt.bufPrint(&buffer, "public{s}", .{path}) catch {
            var response = http.Response.uriTooLong(allocator);
            defer response.deinit();
            try response.write(writer);
            return;
        };
        break :blk result;
    };

    var file = std.fs.cwd().openFile(fs_path, .{}) catch {
        var response = http.Response.notFound(allocator);
        defer response.deinit();
        try response.write(writer);
        return;
    };
    defer file.close();

    // Get file size and read content
    const stat = file.stat() catch {
        var response = http.Response.internalServerError(allocator);
        defer response.deinit();
        try response.write(writer);
        return;
    };
    const file_size = stat.size;

    // For small files, read into memory and use response builder
    // For large files, stream directly
    if (file_size <= 1024 * 1024) { // 1MB threshold
        const content = allocator.alloc(u8, file_size) catch {
            var response = http.Response.internalServerError(allocator);
            defer response.deinit();
            try response.write(writer);
            return;
        };
        defer allocator.free(content);

        const bytes_read = file.readAll(content) catch {
            var response = http.Response.internalServerError(allocator);
            defer response.deinit();
            try response.write(writer);
            return;
        };

        const content_type = getContentType(fs_path);
        var response = http.Response.ok(allocator, content[0..bytes_read], content_type);
        defer response.deinit();

        if (head_only) {
            try response.writeHead(writer);
        } else {
            try response.write(writer);
        }
    } else {
        // Stream large files directly
        const content_type = getContentType(fs_path);

        var response = http.Response.init(allocator);
        defer response.deinit();
        _ = response.setStatus(.ok).setContentType(content_type);

        // Manually build response with streaming body
        try writer.print("{s} {d} {s}\r\n", .{
            response.version.toString(),
            response.status.code(),
            response.status.phrase(),
        });

        // Write date
        const timestamp = std.time.timestamp();
        const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = @intCast(timestamp) };
        const day_secs = epoch_secs.getDaySeconds();
        const epoch_day = epoch_secs.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        // Day names starting from Thursday (epoch day 0 = 1970-01-01 = Thursday)
        const day_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
        const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

        const day_of_week = @mod(epoch_day.day, 7);
        const day_name = day_names[day_of_week];
        const month_name = month_names[@intFromEnum(month_day.month) - 1];

        try writer.print("Date: {s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT\r\n", .{
            day_name,
            month_day.day_index + 1, // day_index is 0-based
            month_name,
            year_day.year,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
        });

        try writer.print("Server: {s}/{s}\r\n", .{ http.SERVER_NAME, http.SERVER_VERSION });
        try writer.print("Content-Type: {s}\r\n", .{content_type});
        try writer.print("Content-Length: {d}\r\n", .{file_size});
        try writer.writeAll("\r\n");

        // Stream body (unless HEAD request)
        if (!head_only) {
            var file_reader = file.reader();
            var read_buf: [8192]u8 = undefined;
            while (true) {
                const n = try file_reader.read(&read_buf);
                if (n == 0) break;
                try writer.writeAll(read_buf[0..n]);
            }
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
