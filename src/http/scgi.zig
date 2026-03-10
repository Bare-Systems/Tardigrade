const std = @import("std");
const headers_mod = @import("headers.zig");
const Headers = headers_mod.Headers;
const memcached = @import("memcached.zig");

pub const EnvPair = struct {
    name: []const u8,
    value: []const u8,
};

pub const RequestOptions = struct {
    method: []const u8,
    request_uri: []const u8,
    query_string: []const u8 = "",
    path_info: []const u8 = "",
    script_name: []const u8 = "",
    document_root: []const u8 = "",
    content_type: ?[]const u8 = null,
    remote_addr: []const u8 = "",
    remote_port: []const u8 = "",
    server_name: []const u8 = "localhost",
    server_port: []const u8 = "80",
    server_protocol: []const u8 = "HTTP/1.1",
    request_scheme: []const u8 = "http",
    https: bool = false,
    headers: ?*const Headers = null,
    extra_env: []const EnvPair = &.{},
};

pub const Response = struct {
    allocator: std.mem.Allocator,
    status: u16,
    headers: Headers,
    body: []u8,

    pub fn deinit(self: *Response) void {
        self.headers.deinit();
        self.allocator.free(self.body);
        self.* = undefined;
    }

    pub fn contentType(self: *const Response) []const u8 {
        return self.headers.get("content-type") orelse "application/octet-stream";
    }
};

pub fn buildRequest(
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    body: []const u8,
) ![]u8 {
    return buildRequestWithOptions(allocator, .{
        .method = method,
        .request_uri = path,
        .path_info = path,
        .script_name = path,
    }, body);
}

pub fn buildRequestWithOptions(
    allocator: std.mem.Allocator,
    opts: RequestOptions,
    body: []const u8,
) ![]u8 {
    var headers = std.ArrayList(u8).init(allocator);
    defer headers.deinit();

    var len_buf: [32]u8 = undefined;
    const body_len = try std.fmt.bufPrint(&len_buf, "{d}", .{body.len});

    try appendHeader(&headers, "CONTENT_LENGTH", body_len);
    try appendHeader(&headers, "SCGI", "1");
    try appendHeader(&headers, "REQUEST_METHOD", opts.method);
    try appendHeader(&headers, "REQUEST_URI", opts.request_uri);
    try appendHeader(&headers, "QUERY_STRING", opts.query_string);
    try appendHeader(&headers, "PATH_INFO", opts.path_info);
    try appendHeader(&headers, "SCRIPT_NAME", opts.script_name);
    try appendHeader(&headers, "DOCUMENT_ROOT", opts.document_root);
    try appendHeader(&headers, "REMOTE_ADDR", opts.remote_addr);
    try appendHeader(&headers, "REMOTE_PORT", opts.remote_port);
    try appendHeader(&headers, "SERVER_NAME", opts.server_name);
    try appendHeader(&headers, "SERVER_PORT", opts.server_port);
    try appendHeader(&headers, "SERVER_PROTOCOL", opts.server_protocol);
    try appendHeader(&headers, "REQUEST_SCHEME", opts.request_scheme);
    try appendHeader(&headers, "HTTPS", if (opts.https) "on" else "off");
    if (opts.content_type) |content_type| {
        try appendHeader(&headers, "CONTENT_TYPE", content_type);
    }

    if (opts.headers) |req_headers| {
        for (req_headers.iterator()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-type") or
                std.ascii.eqlIgnoreCase(header.name, "content-length"))
            {
                continue;
            }
            const env_name = try headerNameToEnv(allocator, header.name);
            defer allocator.free(env_name);
            try appendHeader(&headers, env_name, header.value);
        }
    }

    for (opts.extra_env) |pair| {
        try appendHeader(&headers, pair.name, pair.value);
    }

    const prefix = try std.fmt.allocPrint(allocator, "{d}:", .{headers.items.len});
    defer allocator.free(prefix);

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.appendSlice(prefix);
    try out.appendSlice(headers.items);
    try out.append(',');
    try out.appendSlice(body);
    return out.toOwnedSlice();
}

pub fn execute(
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    opts: RequestOptions,
    body: []const u8,
) !Response {
    const wire = try buildRequestWithOptions(allocator, opts, body);
    defer allocator.free(wire);

    var stream = try connect(allocator, endpoint);
    defer stream.close();
    try stream.writeAll(wire);
    return readResponse(allocator, &stream);
}

pub fn connect(allocator: std.mem.Allocator, endpoint: []const u8) !std.net.Stream {
    if (unixSocketPath(endpoint)) |path| return std.net.connectUnixSocket(path);
    const ep = try memcached.parseEndpoint(endpoint);
    return std.net.tcpConnectToHost(allocator, ep.host, ep.port);
}

pub fn readResponse(allocator: std.mem.Allocator, stream: *std.net.Stream) !Response {
    const raw = try stream.reader().readAllAlloc(allocator, 2 * 1024 * 1024);
    errdefer allocator.free(raw);
    return parseResponse(allocator, raw);
}

pub fn parseResponse(allocator: std.mem.Allocator, raw: []const u8) !Response {
    if (std.mem.startsWith(u8, raw, "HTTP/")) {
        return parseHttpResponse(allocator, raw);
    }
    return parseCgiLikeResponse(allocator, raw);
}

fn parseHttpResponse(allocator: std.mem.Allocator, raw: []const u8) !Response {
    const header_end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.InvalidResponse;
    const status_end = std.mem.indexOf(u8, raw, "\r\n") orelse return error.InvalidResponse;
    const status_line = raw[0..status_end];

    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next() orelse return error.InvalidResponse;
    const status_text = parts.next() orelse return error.InvalidResponse;
    const status = try std.fmt.parseInt(u16, status_text, 10);

    const header_slice = raw[status_end + 2 .. header_end + 4];
    const headers_block = try allocator.alloc(u8, header_slice.len);
    errdefer allocator.free(headers_block);
    @memcpy(headers_block, header_slice);
    const parsed_headers = try headers_mod.parseHeaders(allocator, headers_block);
    allocator.free(headers_block);

    const body = try allocator.dupe(u8, raw[header_end + 4 ..]);
    errdefer allocator.free(body);
    return .{
        .allocator = allocator,
        .status = status,
        .headers = parsed_headers.headers,
        .body = body,
    };
}

fn parseCgiLikeResponse(allocator: std.mem.Allocator, raw: []const u8) !Response {
    const split = headerBodySplit(raw) orelse return error.InvalidResponse;
    const headers_text = try normalizeHeaderBlock(allocator, raw[0..split.headers_end]);
    defer allocator.free(headers_text);
    var parsed_headers = try headers_mod.parseHeaders(allocator, headers_text);
    const status = parseStatus(parsed_headers.headers.get("status") orelse "");
    const body = try allocator.dupe(u8, raw[split.body_start..]);
    errdefer allocator.free(body);
    return .{
        .allocator = allocator,
        .status = status,
        .headers = parsed_headers.headers,
        .body = body,
    };
}

const HeaderSplit = struct {
    headers_end: usize,
    body_start: usize,
};

fn headerBodySplit(data: []const u8) ?HeaderSplit {
    if (std.mem.indexOf(u8, data, "\r\n\r\n")) |idx| {
        return .{ .headers_end = idx + 2, .body_start = idx + 4 };
    }
    if (std.mem.indexOf(u8, data, "\n\n")) |idx| {
        return .{ .headers_end = idx + 1, .body_start = idx + 2 };
    }
    return null;
}

fn normalizeHeaderBlock(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        const c = raw[i];
        if (c == '\r') {
            try out.append('\r');
            if (i + 1 < raw.len and raw[i + 1] == '\n') {
                try out.append('\n');
                i += 1;
            } else {
                try out.append('\n');
            }
            continue;
        }
        if (c == '\n') {
            try out.appendSlice("\r\n");
            continue;
        }
        try out.append(c);
    }
    if (!std.mem.endsWith(u8, out.items, "\r\n\r\n")) try out.appendSlice("\r\n\r\n");
    return out.toOwnedSlice();
}

fn parseStatus(raw: []const u8) u16 {
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len == 0) return 200;
    const end = std.mem.indexOfScalar(u8, trimmed, ' ') orelse trimmed.len;
    return std.fmt.parseInt(u16, trimmed[0..end], 10) catch 200;
}

fn appendHeader(out: *std.ArrayList(u8), key: []const u8, value: []const u8) !void {
    try out.appendSlice(key);
    try out.append(0);
    try out.appendSlice(value);
    try out.append(0);
}

fn headerNameToEnv(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    var env = try allocator.alloc(u8, "HTTP_".len + name.len);
    @memcpy(env[0.."HTTP_".len], "HTTP_");
    for (name, 0..) |c, i| {
        env["HTTP_".len + i] = switch (c) {
            '-' => '_',
            else => std.ascii.toUpper(c),
        };
    }
    return env;
}

fn unixSocketPath(endpoint: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, endpoint, "unix://")) return endpoint["unix://".len..];
    if (std.mem.startsWith(u8, endpoint, "unix:")) return endpoint["unix:".len..];
    return null;
}

test "buildRequest writes scgi netstring prefix and cgi env" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();
    try headers.append("X-Correlation-ID", "req-123");
    const req = try buildRequestWithOptions(allocator, .{
        .method = "POST",
        .request_uri = "/x?y=1",
        .query_string = "y=1",
        .path_info = "/x",
        .script_name = "/x",
        .content_type = "application/json",
        .remote_addr = "127.0.0.1",
        .server_name = "localhost",
        .headers = &headers,
    }, "{}");
    defer allocator.free(req);
    try std.testing.expect(std.mem.indexOfScalar(u8, req, ':') != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "REQUEST_METHOD\x00POST\x00") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "QUERY_STRING\x00y=1\x00") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "HTTP_X_CORRELATION_ID\x00req-123\x00") != null);
}

test "parseResponse handles CGI-like status and body" {
    const allocator = std.testing.allocator;
    var parsed = try parseResponse(allocator, "Status: 201 Created\r\nContent-Type: text/plain\r\n\r\nhello");
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 201), parsed.status);
    try std.testing.expectEqualStrings("text/plain", parsed.contentType());
    try std.testing.expectEqualStrings("hello", parsed.body);
}

test "parseResponse handles http status line response" {
    const allocator = std.testing.allocator;
    var parsed = try parseResponse(allocator, "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}");
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 202), parsed.status);
    try std.testing.expectEqualStrings("application/json", parsed.contentType());
    try std.testing.expectEqualStrings("{\"ok\":true}", parsed.body);
}
