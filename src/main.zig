const std = @import("std");
const http = @import("http.zig");

const MAX_REQUEST_SIZE = 64 * 1024; // 64KB max request size
const MAX_BODY_SIZE = 1 * 1024 * 1024; // 1MB max body size
const KEEP_ALIVE_TIMEOUT_MS = 5000; // 5 second idle timeout
const MAX_REQUESTS_PER_CONNECTION = 100; // Max requests before closing
const AUTO_INDEX = true; // enable directory listings when no index file

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
        const read_result = readRequest(stream, &buf);

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
        // If sendfile failed, fallback to manual streaming below
    }
    return;
}
fn readRequest(stream: std.net.Stream, buf: []u8) struct { bytes_read: usize, timed_out: bool } {
    var total_read: usize = 0;
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
    const correlation_id = try http.correlation.generate(allocator);
    defer allocator.free(correlation_id);

    var response = switch (err) {
        error.InvalidMethod => http.Response.notImplemented(allocator),
        error.InvalidVersion => http.Response.httpVersionNotSupported(allocator),
        error.BodyTooLarge => http.Response.payloadTooLarge(allocator),
        error.HeaderTooLarge, error.HeadersTooLarge, error.TooManyHeaders => http.Response.headersTooLarge(allocator),
        else => http.Response.badRequest(allocator, "Malformed request"),
    };
    defer response.deinit();
    setResponseMeta(&response, keep_alive, correlation_id);
    try response.write(stream.writer());
}

fn serveFile(allocator: std.mem.Allocator, request: *http.Request, stream: std.net.Stream, head_only: bool, keep_alive: bool) !void {
    const writer = stream.writer();
    const path = request.uri.path;
    const correlation_id = try http.correlation.fromHeadersOrGenerate(allocator, &request.headers);
    defer allocator.free(correlation_id);

    // Prevent path traversal
    if (std.mem.indexOf(u8, path, "..") != null) {
        var response = http.Response.forbidden(allocator);
        defer response.deinit();
        setResponseMeta(&response, keep_alive, correlation_id);
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
            setResponseMeta(&response, keep_alive, correlation_id);
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
        setResponseMeta(&response, keep_alive, correlation_id);
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
                setResponseMeta(&response, keep_alive, correlation_id);
                try response.write(writer);
                return;
            };
            var response = http.Response.movedPermanently(allocator, redirect_path);
            defer response.deinit();
            setResponseMeta(&response, keep_alive, correlation_id);
            try response.write(writer);
            return;
        }

        // Try index files (use separate buffer to avoid aliasing with fs_path)
        var index_buffer: [512]u8 = undefined;
        const index_path = tryIndexFile(fs_path, &index_buffer);
        if (index_path) |p| {
            return serveFileContent(allocator, request, p, writer, head_only, keep_alive, correlation_id);
        }

        // No index file found; generate autoindex listing if enabled
        if (AUTO_INDEX or isAutoIndexEnabled()) {
            const body = try http.autoindex.generateAutoIndex(allocator, fs_path, path);
            var response = http.Response.init(allocator);
            _ = response.setStatus(.ok).setBodyOwned(body).setContentType("text/html; charset=utf-8");
            defer response.deinit();
            setResponseMeta(&response, keep_alive, correlation_id);
            if (head_only) {
                try response.writeHead(writer);
            } else {
                try response.write(writer);
            }
            return;
        }

        var response = http.Response.notFound(allocator);
        defer response.deinit();
        setResponseMeta(&response, keep_alive, correlation_id);
        try response.write(writer);
        return;
    }

    // Regular file
    return serveFileContent(allocator, request, fs_path, writer, head_only, keep_alive, correlation_id);
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
pub fn serveFileContent(allocator: std.mem.Allocator, request: *http.Request, fs_path: []const u8, writer: anytype, head_only: bool, keep_alive: bool, disable_sendfile: bool, correlation_id: ?[]const u8) !void {
    const resolved_correlation_id = if (correlation_id) |cid|
        cid
    else
        try http.correlation.fromHeadersOrGenerate(allocator, &request.headers);
    defer if (correlation_id == null) allocator.free(resolved_correlation_id);

    // --- Content-Encoding negotiation ---
    // Only "identity" is supported for now (no compression yet)
    if (request.headers.get("accept-encoding")) |ae| {
        // Accept-Encoding: gzip, deflate, br, identity, *
        // If "identity" or "*" is present, or no header, we serve identity.
        // If only unsupported encodings, return 406.
        var lower_buf: [128]u8 = undefined;
        const lower = if (ae.len <= lower_buf.len)
            std.ascii.lowerString(lower_buf[0..ae.len], ae)
        else
            ae;
        if (!(std.mem.containsAtLeast(u8, lower, 1, "identity") or std.mem.containsAtLeast(u8, lower, 1, "*"))) {
            // Only unsupported encodings requested
            var resp = http.Response.init(allocator);
            _ = resp.setStatus(.not_acceptable).setBodyOwned("406 Not Acceptable: no supported encoding").setContentType("text/plain; charset=utf-8");
            defer resp.deinit();
            setResponseMeta(&resp, keep_alive, resolved_correlation_id);
            if (head_only) {
                try resp.writeHead(writer);
            } else {
                try resp.write(writer);
            }
            return;
        }
    }
    var file = std.fs.cwd().openFile(fs_path, .{}) catch {
        var response = http.Response.notFound(allocator);
        defer response.deinit();
        setResponseMeta(&response, keep_alive, resolved_correlation_id);
        try response.write(writer);
        return;
    };
    defer file.close();

    // Get file size and read content
    const stat = file.stat() catch {
        var response = http.Response.internalServerError(allocator);
        defer response.deinit();
        setResponseMeta(&response, keep_alive, resolved_correlation_id);
        try response.write(writer);
        return;
    };
    const file_size = stat.size;

    // Get file mtime from File.Stat
    var last_mod_str_buf: [64]u8 = undefined;
    var last_mod_slice: []const u8 = "";
    var msecs_opt: ?usize = null;
    // `stat.mtime` is in nanoseconds since epoch
    if (stat.mtime != 0) {
        const msecs: usize = @intCast(@divTrunc(stat.mtime, std.time.ns_per_s));
        msecs_opt = msecs;

        const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = msecs };
        const day_secs = epoch_secs.getDaySeconds();
        const epoch_day = epoch_secs.getEpochDay();
        const year_day = epoch_day.calculateYearDay();

        const day_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
        const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
        const day_of_week = @mod(epoch_day.day, 7);
        const day_name = day_names[day_of_week];
        const month_name = month_names[@intFromEnum(year_day.calculateMonthDay().month) - 1];

        const print_result = std.fmt.bufPrint(&last_mod_str_buf, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
            day_name,
            year_day.calculateMonthDay().day_index + 1,
            month_name,
            year_day.year,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
        }) catch null;
        if (print_result) |s| {
            last_mod_slice = s;
        }
    }

    // Determine Content-Type
    const content_type = getContentType(fs_path);

    // For small files, read into memory and use response builder
    if (file_size <= 1024 * 1024) { // 1MB threshold
        // Read the whole file into memory
        const buf = try allocator.alloc(u8, file_size);
        defer allocator.free(buf);
        if (try file.readAll(buf) != file_size) {
            var response = http.Response.internalServerError(allocator);
            defer response.deinit();
            setResponseMeta(&response, keep_alive, resolved_correlation_id);
            try response.write(writer);
            return;
        }

        var response = http.Response.init(allocator);
        _ = response.setStatus(.ok)
            .setBodyOwned(buf)
            .setContentType(content_type);
        if (last_mod_slice.len != 0) {
            _ = response.setHeader("Last-Modified", last_mod_slice);
        }
        // Generate ETag for in-memory responses (based on size + mtime)
        const etag_buf = try http.etag.generateETag(allocator, file_size, msecs_opt);
        _ = response.setHeader("ETag", etag_buf);
        // If client provided If-None-Match and it matches, return 304
        if (request.headers.get("if-none-match")) |inm| {
            if (http.etag.matchesIfNoneMatch(etag_buf, inm)) {
                var not_mod = http.Response.init(allocator);
                _ = not_mod.setStatus(.not_modified).setHeader("ETag", etag_buf);
                setResponseMeta(&not_mod, keep_alive, resolved_correlation_id);
                allocator.free(etag_buf);
                defer not_mod.deinit();
                if (head_only) {
                    try not_mod.writeHead(writer);
                } else {
                    try not_mod.write(writer);
                }
                return;
            }
        }
        setResponseMeta(&response, keep_alive, resolved_correlation_id);
        defer response.deinit();
        allocator.free(etag_buf);
        if (head_only) {
            try response.writeHead(writer);
        } else {
            try response.write(writer);
        }
        return;
    } else {
        // --- sendfile() zero-copy optimization ---
        // Only for non-range, non-head requests
        if (!disable_sendfile and !head_only and request.headers.get("range") == null) {
            try trySendfile(&file, file_size, writer);
        }
        var response = http.Response.init(allocator);
        if (last_mod_slice.len != 0) {
            _ = response.setHeader("Last-Modified", last_mod_slice);
        }
        // Generate ETag for streaming responses (based on size + mtime)
        const etag_buf = try http.etag.generateETag(allocator, file_size, msecs_opt);
        _ = response.setHeader("ETag", etag_buf);
        // If client provided If-None-Match and it matches, return 304
        if (request.headers.get("if-none-match")) |inm| {
            if (http.etag.matchesIfNoneMatch(etag_buf, inm)) {
                var not_mod = http.Response.init(allocator);
                _ = not_mod.setStatus(.not_modified).setHeader("ETag", etag_buf);
                setResponseMeta(&not_mod, keep_alive, resolved_correlation_id);
                // free our etag buffer now that headers copied
                allocator.free(etag_buf);
                defer not_mod.deinit();
                if (head_only) {
                    try not_mod.writeHead(writer);
                } else {
                    try not_mod.write(writer);
                }
                return;
            }
        }
        // Set Content-Type and Content-Length
        _ = response.setStatus(.ok)
            .setContentType(content_type)
            .setContentLength(file_size);
        setResponseMeta(&response, keep_alive, resolved_correlation_id);
        defer response.deinit();
        allocator.free(etag_buf);

        if (head_only) {
            try response.writeHead(writer);
            return;
        } else {
            try response.writeHead(writer);
            // Stream file in 64KB chunks
            var buf: [64 * 1024]u8 = undefined;
            var remaining = file_size;
            while (remaining > 0) {
                const to_read = if (remaining < buf.len) remaining else buf.len;
                const n = try file.read(buf[0..to_read]);
                if (n == 0) break; // EOF
                try writer.writeAll(buf[0..n]);
                remaining -= n;
            }
            return;
        }
    }
}

fn setResponseMeta(response: *http.Response, keep_alive: bool, correlation_id: []const u8) void {
    _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
}

// Top-level function definition
fn trySendfile(file: anytype, file_size: usize, writer: anytype) !void {
    // Only attempt sendfile if writer is a file-backed stream
    // This function is only called in the real server path, not in tests
    // (tests pass disable_sendfile = true)
    // You may need to adapt this for your platform and file/stream types
    // Example for POSIX file descriptors:
    if (@hasDecl(@TypeOf(writer), "context") and @hasField(@TypeOf(writer.context), "handle")) {
        const out_fd = writer.context.handle;
        const in_fd = file.handle;
        var offset: usize = 0;
        var sent: usize = 0;
        var err: ?anyerror = null;
        if (out_fd != -1 and in_fd != -1) {
            var count: usize = file_size;
            _ = std.os.sendfile(in_fd, out_fd, &offset, &count, null, 0) catch |e| {
                err = e;
                0;
            };
            sent = count;
        }
        if (sent == file_size and err == null) {
            return;
        }
        // If sendfile failed, fallback to manual streaming below
    }
    return;
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

/// Parse a single `Range: bytes=` header. Returns start..end (inclusive) or null on parse error.
pub fn parseRangeHeader(range_hdr: []const u8, total: usize) ?struct { start: usize, end: usize } {
    // Expect prefix "bytes="
    if (!std.mem.startsWith(u8, range_hdr, "bytes=")) return null;
    const spec = range_hdr[6..];
    // Only support single range (no commas)
    if (std.mem.indexOf(u8, spec, ",") != null) return null;

    // Find dash
    const dash = std.mem.indexOf(u8, spec, "-") orelse return null;
    const first = spec[0..dash];
    const second = spec[dash + 1 ..];

    if (first.len == 0) {
        // suffix: -N => last N bytes
        const n = std.fmt.parseInt(usize, second, 10) catch return null;
        if (n == 0) return null;
        if (n > total) return .{ .start = 0, .end = total - 1 };
        const start = total - n;
        return .{ .start = start, .end = total - 1 };
    } else {
        const start = std.fmt.parseInt(usize, first, 10) catch return null;
        if (second.len == 0) {
            if (start >= total) return null;
            return .{ .start = start, .end = total - 1 };
        } else {
            const end = std.fmt.parseInt(usize, second, 10) catch return null;
            if (start > end) return null;
            if (start >= total) return null;
            const clamped_end = if (end >= total) total - 1 else end;
            return .{ .start = start, .end = clamped_end };
        }
    }
}

/// Return true if environment enables auto-indexing.
fn isAutoIndexEnabled() bool {
    const val = std.os.getenv("TARDIGRADE_AUTO_INDEX");
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
            '#', '%', '?', '&', '"', '\'', '<', '>' => {
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
