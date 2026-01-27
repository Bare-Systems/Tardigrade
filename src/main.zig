const std = @import("std");
const http = @import("http.zig");

const MAX_REQUEST_SIZE = 64 * 1024; // 64KB max request size
const MAX_BODY_SIZE = 1 * 1024 * 1024; // 1MB max body size
const KEEP_ALIVE_TIMEOUT_MS = 5000; // 5 second idle timeout
const MAX_REQUESTS_PER_CONNECTION = 100; // Max requests before closing

pub fn main() !void {
    const address = try std.net.Address.parseIp("0.0.0.0", 8069);

    var server = try std.net.Address.listen(address, .{
        .reuse_address = true,
    });
    defer server.deinit();

    std.log.info("Listening on 0.0.0.0:8069", .{});

    while (true) {
        const conn = try server.accept();
        handleConnection(conn.stream) catch |err| {
            std.log.err("Connection error: {}", .{err});
        };
        conn.stream.close();
    }
}

fn handleConnection(stream: std.net.Stream) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var request_count: usize = 0;

    // Keep-alive loop
    while (request_count < MAX_REQUESTS_PER_CONNECTION) {
        request_count += 1;

        // Read request data with timeout
        var buf: [MAX_REQUEST_SIZE]u8 = undefined;
        const read_result = readRequest(stream, &buf, request_count > 1);

        const total_read = read_result.bytes_read;
        if (total_read == 0) {
            // Connection closed or timeout
            return;
        }

        if (read_result.timed_out) {
            // Timeout on keep-alive, close gracefully
            return;
        }

        const request_data = buf[0..total_read];

        // Parse the request
        const parse_result = http.Request.parse(allocator, request_data, MAX_BODY_SIZE) catch |err| {
            std.log.err("Parse error: {}", .{err});
            try sendParseError(allocator, stream, err, false);
            return; // Close connection on parse error
        };
        var request = parse_result.request;
        defer request.deinit();

        std.log.info("{s} {s} {s}", .{
            request.method.toString(),
            request.uri.path,
            request.version.toString(),
        });

        // Determine if we should keep the connection alive
        const keep_alive = request.keepAlive() and request_count < MAX_REQUESTS_PER_CONNECTION;

        // Handle the request based on method
        switch (request.method) {
            .GET, .HEAD => {
                try serveFile(allocator, request.uri.path, stream, request.method == .HEAD, keep_alive);
            },
            else => {
                var response = http.Response.methodNotAllowed(allocator, "GET, HEAD");
                defer response.deinit();
                _ = response.setConnection(keep_alive);
                try response.write(stream.writer());
            },
        }

        // If not keeping alive, we're done
        if (!keep_alive) {
            return;
        }
    }
}

const ReadResult = struct {
    bytes_read: usize,
    timed_out: bool,
};

fn readRequest(stream: std.net.Stream, buf: []u8, is_keep_alive: bool) ReadResult {
    var total_read: usize = 0;

    // For keep-alive connections, we need to handle timeout for the first read
    // For initial connection, we can wait indefinitely
    if (is_keep_alive) {
        setSocketTimeout(stream.handle, @intCast(KEEP_ALIVE_TIMEOUT_MS / 1000), @intCast((KEEP_ALIVE_TIMEOUT_MS % 1000) * 1000));
    }

    // First read - may timeout on keep-alive
    const first_read = stream.read(buf[0..]) catch |err| {
        if (err == error.WouldBlock) {
            return .{ .bytes_read = 0, .timed_out = true };
        }
        return .{ .bytes_read = 0, .timed_out = false };
    };

    if (first_read == 0) {
        return .{ .bytes_read = 0, .timed_out = false };
    }

    total_read = first_read;

    // Remove timeout for subsequent reads (30 seconds)
    setSocketTimeout(stream.handle, 30, 0);

    // Continue reading until we have complete headers
    while (total_read < buf.len) {
        // Check if we have complete headers
        if (std.mem.indexOf(u8, buf[0..total_read], "\r\n\r\n")) |_| {
            break;
        }

        const n = stream.read(buf[total_read..]) catch {
            break;
        };
        if (n == 0) break;
        total_read += n;
    }

    return .{ .bytes_read = total_read, .timed_out = false };
}

fn setSocketTimeout(handle: std.posix.socket_t, sec: i32, usec: i32) void {
    const timeout = std.posix.timeval{
        .sec = sec,
        .usec = usec,
    };
    std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
}

fn sendParseError(allocator: std.mem.Allocator, stream: std.net.Stream, err: http.ParseError, keep_alive: bool) !void {
    var response = switch (err) {
        error.InvalidMethod => http.Response.notImplemented(allocator),
        error.InvalidVersion => http.Response.httpVersionNotSupported(allocator),
        error.BodyTooLarge => http.Response.payloadTooLarge(allocator),
        error.HeaderTooLarge, error.HeadersTooLarge, error.TooManyHeaders => http.Response.headersTooLarge(allocator),
        else => http.Response.badRequest(allocator, "Malformed request"),
    };
    defer response.deinit();
    _ = response.setConnection(keep_alive);
    try response.write(stream.writer());
}

fn serveFile(allocator: std.mem.Allocator, path: []const u8, stream: std.net.Stream, head_only: bool, keep_alive: bool) !void {
    const writer = stream.writer();

    // Prevent path traversal
    if (std.mem.indexOf(u8, path, "..") != null) {
        var response = http.Response.forbidden(allocator);
        defer response.deinit();
        _ = response.setConnection(keep_alive);
        try response.write(writer);
        return;
    }

    // Build filesystem path
    var path_buffer: [512]u8 = undefined;
    const fs_path = if (std.mem.eql(u8, path, "/"))
        "public"
    else blk: {
        const result = std.fmt.bufPrint(&path_buffer, "public{s}", .{path}) catch {
            var response = http.Response.uriTooLong(allocator);
            defer response.deinit();
            _ = response.setConnection(keep_alive);
            try response.write(writer);
            return;
        };
        // Remove trailing slash for stat check
        if (result.len > 0 and result[result.len - 1] == '/') {
            break :blk result[0 .. result.len - 1];
        }
        break :blk result;
    };

    // Check if path is a directory
    const stat_result = std.fs.cwd().statFile(fs_path) catch {
        var response = http.Response.notFound(allocator);
        defer response.deinit();
        _ = response.setConnection(keep_alive);
        try response.write(writer);
        return;
    };

    if (stat_result.kind == .directory) {
        // If directory and path doesn't end with /, redirect
        if (path.len > 0 and path[path.len - 1] != '/') {
            var redirect_buf: [513]u8 = undefined;
            const redirect_path = std.fmt.bufPrint(&redirect_buf, "{s}/", .{path}) catch {
                var response = http.Response.uriTooLong(allocator);
                defer response.deinit();
                _ = response.setConnection(keep_alive);
                try response.write(writer);
                return;
            };
            var response = http.Response.movedPermanently(allocator, redirect_path);
            defer response.deinit();
            _ = response.setConnection(keep_alive);
            try response.write(writer);
            return;
        }

        // Try index files (use separate buffer to avoid aliasing with fs_path)
        var index_buffer: [512]u8 = undefined;
        const index_path = tryIndexFile(fs_path, &index_buffer);
        if (index_path) |p| {
            return serveFileContent(allocator, p, writer, head_only, keep_alive);
        }

        // No index file found; if auto-index is enabled, serve directory listing
        if (isAutoIndexEnabled()) {
            try serveDirectoryListing(allocator, fs_path, path, writer, head_only, keep_alive);
            return;
        }

        var response = http.Response.notFound(allocator);
        defer response.deinit();
        _ = response.setConnection(keep_alive);
        try response.write(writer);
        return;
    }

    // Regular file
    return serveFileContent(allocator, fs_path, writer, head_only, keep_alive);
}

/// Try to find an index file in the given directory path
fn tryIndexFile(dir_path: []const u8, buffer: *[512]u8) ?[]const u8 {
    const index_files = [_][]const u8{ "/index.html", "/index.htm" };

    for (index_files) |index| {
        const full_path = std.fmt.bufPrint(buffer, "{s}{s}", .{ dir_path, index }) catch continue;
        // Check if file exists
        std.fs.cwd().access(full_path, .{}) catch continue;
        return full_path;
    }
    return null;
}

/// Serve the actual file content
fn serveFileContent(allocator: std.mem.Allocator, fs_path: []const u8, writer: anytype, head_only: bool, keep_alive: bool) !void {
    var file = std.fs.cwd().openFile(fs_path, .{}) catch {
        var response = http.Response.notFound(allocator);
        defer response.deinit();
        _ = response.setConnection(keep_alive);
        try response.write(writer);
        return;
    };
    defer file.close();

    // Get file size and read content
    const stat = file.stat() catch {
        var response = http.Response.internalServerError(allocator);
        defer response.deinit();
        _ = response.setConnection(keep_alive);
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
            _ = response.setConnection(keep_alive);
            try response.write(writer);
            return;
        };
        defer allocator.free(content);

        const bytes_read = file.readAll(content) catch {
            var response = http.Response.internalServerError(allocator);
            defer response.deinit();
            _ = response.setConnection(keep_alive);
            try response.write(writer);
            return;
        };

        const content_type = getContentType(fs_path);
        var response = http.Response.ok(allocator, content[0..bytes_read], content_type);
        defer response.deinit();
        _ = response.setConnection(keep_alive);

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
        _ = response.setStatus(.ok).setContentType(content_type).setConnection(keep_alive);

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
        try writer.print("Connection: {s}\r\n", .{if (keep_alive) "keep-alive" else "close"});
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

/// Return true if environment enables auto-indexing.
fn isAutoIndexEnabled() bool {
    const val = std.os.getenv("SIMPLE_SERVER_AUTO_INDEX");
    if (val) |v| {
        if (v.len == 0) return false;
        const c = v[0];
        if (c == '1' or c == 't' or c == 'T' or c == 'y' or c == 'Y') return true;
    }
    return false;
}

fn htmlEscapeAppend(list: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |b| {
        switch (b) {
            '<' => try list.appendSlice("&lt;"),
            '>' => try list.appendSlice("&gt;"),
            '&' => try list.appendSlice("&amp;"),
            '"' => try list.appendSlice("&quot;"),
            else => try list.append(b),
        }
    }
}

fn urlEncodeAppend(list: *std.ArrayList(u8), s: []const u8) !void {
    const hex = "0123456789ABCDEF";
    for (s) |b| {
        // Encode control, non-ascii, space
        if (b <= 0x20 or b >= 0x7f) {
            try list.append('%');
            try list.append(hex[(b >> 4) & 0xF]);
            try list.append(hex[b & 0xF]);
            continue;
        }

        // Reserved or unsafe characters
        switch (b) {
            '#' , '%' , '?' , '&' , '"' , '\'' , '<' , '>' => {
                try list.append('%');
                try list.append(hex[(b >> 4) & 0xF]);
                try list.append(hex[b & 0xF]);
            },
            else => try list.append(b),
        }
    }
}

/// Generate and write a simple HTML directory listing for `dir_fs_path`.
fn serveDirectoryListing(allocator: std.mem.Allocator, dir_fs_path: []const u8, uri_path: []const u8, writer: anytype, head_only: bool, keep_alive: bool) !void {
    var dir = try std.fs.cwd().openDir(dir_fs_path, .{});
    defer dir.close();

    var list = std.ArrayList(u8).init(allocator);
    defer list.deinit();

    try list.appendSlice("<!doctype html><html><head><meta charset=\"utf-8\">\n");
    try list.appendSlice("<title>Index of ");
    try htmlEscapeAppend(&list, uri_path);
    try list.appendSlice("</title>\n</head><body>\n");
    try list.appendSlice("<h1>Index of ");
    try htmlEscapeAppend(&list, uri_path);
    try list.appendSlice("</h1>\n<pre>\n");

    // Parent link if not root
    if (!(uri_path.len == 1 and uri_path[0] == '/')) {
        try list.appendSlice("<a href=\"../\">../</a>\n");
    }

    var it = dir.iterate();
    while (it.next()) |entry| {
        // name is a []const u8
        const name = entry.name;
        // append link
        try list.appendSlice("<a href=\"");
        // href = uri_path + name (+ '/' if directory)
        try urlEncodeAppend(&list, uri_path);
        try urlEncodeAppend(&list, name);
        if (entry.kind == .directory) {
            try list.append('/');
        }
        try list.appendSlice("\">");
        try htmlEscapeAppend(&list, name);
        if (entry.kind == .directory) {
            try list.append('/');
        }
        try list.appendSlice("</a>\n");
    }

    try list.appendSlice("</pre>\n<hr>\n</body></html>\n");

    var response = http.Response.ok(allocator, list.toOwnedSlice(), "text/html; charset=utf-8");
    defer response.deinit();
    _ = response.setConnection(keep_alive);

    if (head_only) {
        try response.writeHead(writer);
    } else {
        try response.write(writer);
    }
}

test {
    // Import and run tests from http module
    _ = @import("http.zig");
}
