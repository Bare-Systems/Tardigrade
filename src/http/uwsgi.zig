const std = @import("std");
const headers_mod = @import("headers.zig");
const Headers = headers_mod.Headers;
const memcached = @import("memcached.zig");

pub const EnvPair = struct {
    name: []const u8,
    value: []const u8,
};

pub const RequestOptions = struct {
    modifier1: u8 = 0,
    modifier2: u8 = 0,
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

pub fn buildPacket(
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    body: []const u8,
) ![]u8 {
    return buildPacketWithOptions(allocator, .{
        .method = method,
        .request_uri = path,
        .path_info = path,
        .script_name = path,
    }, body);
}

pub fn buildPacketWithOptions(
    allocator: std.mem.Allocator,
    opts: RequestOptions,
    body: []const u8,
) ![]u8 {
    var vars = std.ArrayList(u8).init(allocator);
    defer vars.deinit();

    var len_buf: [32]u8 = undefined;
    const len_str = try std.fmt.bufPrint(&len_buf, "{d}", .{body.len});
    try appendKv(&vars, "REQUEST_METHOD", opts.method);
    try appendKv(&vars, "REQUEST_URI", opts.request_uri);
    try appendKv(&vars, "QUERY_STRING", opts.query_string);
    try appendKv(&vars, "PATH_INFO", opts.path_info);
    try appendKv(&vars, "SCRIPT_NAME", opts.script_name);
    try appendKv(&vars, "DOCUMENT_ROOT", opts.document_root);
    try appendKv(&vars, "CONTENT_LENGTH", len_str);
    try appendKv(&vars, "REMOTE_ADDR", opts.remote_addr);
    try appendKv(&vars, "REMOTE_PORT", opts.remote_port);
    try appendKv(&vars, "SERVER_NAME", opts.server_name);
    try appendKv(&vars, "SERVER_PORT", opts.server_port);
    try appendKv(&vars, "SERVER_PROTOCOL", opts.server_protocol);
    try appendKv(&vars, "REQUEST_SCHEME", opts.request_scheme);
    try appendKv(&vars, "HTTPS", if (opts.https) "on" else "off");
    if (opts.content_type) |content_type| try appendKv(&vars, "CONTENT_TYPE", content_type);

    if (opts.headers) |req_headers| {
        for (req_headers.iterator()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-type") or
                std.ascii.eqlIgnoreCase(header.name, "content-length"))
            {
                continue;
            }
            const env_name = try headerNameToEnv(allocator, header.name);
            defer allocator.free(env_name);
            try appendKv(&vars, env_name, header.value);
        }
    }
    for (opts.extra_env) |pair| try appendKv(&vars, pair.name, pair.value);

    const size: u16 = @intCast(vars.items.len);
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.append(opts.modifier1);
    try out.append(@intCast(size & 0xff));
    try out.append(@intCast((size >> 8) & 0xff));
    try out.append(opts.modifier2);
    try out.appendSlice(vars.items);
    try out.appendSlice(body);
    return out.toOwnedSlice();
}

pub fn execute(
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    opts: RequestOptions,
    body: []const u8,
) !Response {
    const wire = try buildPacketWithOptions(allocator, opts, body);
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
    if (std.mem.startsWith(u8, raw, "HTTP/")) return parseHttpResponse(allocator, raw);
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
    const body = if (isChunked(parsed_headers.headers.get("transfer-encoding")))
        try decodeChunkedBody(allocator, raw[header_end + 4 ..])
    else
        try allocator.dupe(u8, raw[header_end + 4 ..]);
    errdefer allocator.free(body);
    return .{
        .allocator = allocator,
        .status = status,
        .headers = parsed_headers.headers,
        .body = body,
    };
}

fn isChunked(transfer_encoding: ?[]const u8) bool {
    const value = transfer_encoding orelse return false;
    return std.ascii.indexOfIgnoreCase(value, "chunked") != null;
}

fn decodeChunkedBody(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    var pos: usize = 0;
    while (pos < raw.len) {
        const line_end = std.mem.indexOfPos(u8, raw, pos, "\r\n") orelse return error.InvalidChunkedResponse;
        const size_text = std.mem.trim(u8, raw[pos..line_end], " \t");
        const semi = std.mem.indexOfScalar(u8, size_text, ';') orelse size_text.len;
        const chunk_size = std.fmt.parseInt(usize, size_text[0..semi], 16) catch return error.InvalidChunkedResponse;
        pos = line_end + 2;
        if (chunk_size == 0) {
            return out.toOwnedSlice();
        }
        if (pos + chunk_size + 2 > raw.len) return error.InvalidChunkedResponse;
        try out.appendSlice(raw[pos .. pos + chunk_size]);
        pos += chunk_size;
        if (!std.mem.eql(u8, raw[pos .. pos + 2], "\r\n")) return error.InvalidChunkedResponse;
        pos += 2;
    }
    return error.InvalidChunkedResponse;
}

fn parseCgiLikeResponse(allocator: std.mem.Allocator, raw: []const u8) !Response {
    const split = headerBodySplit(raw) orelse return error.InvalidResponse;
    const headers_text = try normalizeHeaderBlock(allocator, raw[0..split.headers_end]);
    defer allocator.free(headers_text);
    const parsed_headers = try headers_mod.parseHeaders(allocator, headers_text);
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
    if (std.mem.indexOf(u8, data, "\r\n\r\n")) |idx| return .{ .headers_end = idx + 2, .body_start = idx + 4 };
    if (std.mem.indexOf(u8, data, "\n\n")) |idx| return .{ .headers_end = idx + 1, .body_start = idx + 2 };
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

fn appendKv(out: *std.ArrayList(u8), key: []const u8, value: []const u8) !void {
    try out.append(@intCast(key.len & 0xff));
    try out.append(@intCast((key.len >> 8) & 0xff));
    try out.append(@intCast(value.len & 0xff));
    try out.append(@intCast((value.len >> 8) & 0xff));
    try out.appendSlice(key);
    try out.appendSlice(value);
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

test "buildPacket writes uwsgi header and vars" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();
    try headers.append("X-Correlation-ID", "req-123");
    const pkt = try buildPacketWithOptions(allocator, .{
        .method = "POST",
        .request_uri = "/rpc?x=1",
        .query_string = "x=1",
        .path_info = "/rpc",
        .script_name = "/rpc",
        .content_type = "application/json",
        .remote_addr = "127.0.0.1",
        .headers = &headers,
    }, "abc");
    defer allocator.free(pkt);
    try std.testing.expect(pkt.len > 12);
    try std.testing.expectEqual(@as(u8, 0), pkt[0]);
    try std.testing.expect(std.mem.indexOf(u8, pkt, "REQUEST_METHODPOST") != null);
    try std.testing.expect(std.mem.indexOf(u8, pkt, "HTTP_X_CORRELATION_IDreq-123") != null);
}

test "parseResponse handles http status line response" {
    const allocator = std.testing.allocator;
    var parsed = try parseResponse(allocator, "HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}");
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 202), parsed.status);
    try std.testing.expectEqualStrings("application/json", parsed.contentType());
    try std.testing.expectEqualStrings("{\"ok\":true}", parsed.body);
}

test "parseResponse handles cgi style status response" {
    const allocator = std.testing.allocator;
    var parsed = try parseResponse(allocator, "Status: 201 Created\r\nContent-Type: text/plain\r\n\r\nhello");
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 201), parsed.status);
    try std.testing.expectEqualStrings("text/plain", parsed.contentType());
    try std.testing.expectEqualStrings("hello", parsed.body);
}

test "parseResponse decodes chunked http body" {
    const allocator = std.testing.allocator;
    var parsed = try parseResponse(allocator, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n" ++
        "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 200), parsed.status);
    try std.testing.expectEqualStrings("hello world", parsed.body);
}
