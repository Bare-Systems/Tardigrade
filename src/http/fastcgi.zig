const std = @import("std");
const headers_mod = @import("headers.zig");
const Headers = headers_mod.Headers;
const memcached = @import("memcached.zig");

pub const version_1: u8 = 1;

pub const RecordType = enum(u8) {
    begin_request = 1,
    abort_request = 2,
    end_request = 3,
    params = 4,
    stdin = 5,
    stdout = 6,
    stderr = 7,
    data = 8,
    get_values = 9,
    get_values_result = 10,
    unknown_type = 11,
};

pub const responder_role: u16 = 1;
pub const request_complete: u8 = 0;
pub const cant_mpx_conn: u8 = 1;
pub const overloaded: u8 = 2;
pub const unknown_role: u8 = 3;
pub const keep_conn_flag: u8 = 1;

pub const EnvPair = struct {
    name: []const u8,
    value: []const u8,
};

pub const RequestOptions = struct {
    request_id: u16 = 1,
    keep_conn: bool = false,
    method: []const u8,
    script_filename: []const u8,
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
    stderr: []u8,
    app_status: u32,
    protocol_status: u8,

    pub fn deinit(self: *Response) void {
        self.headers.deinit();
        self.allocator.free(self.body);
        self.allocator.free(self.stderr);
        self.* = undefined;
    }

    pub fn contentType(self: *const Response) []const u8 {
        return self.headers.get("content-type") orelse "application/octet-stream";
    }
};

pub const ParseError = error{
    InvalidRecordHeader,
    InvalidRecordLength,
    InvalidEndRequest,
    InvalidResponseHeaders,
    MissingEndRequest,
    MissingHeaderTerminator,
    InvalidStatusHeader,
    TooManyHeaders,
    HeaderTooLarge,
    HeadersTooLarge,
    InvalidHeader,
    IncompleteHeaders,
    OutOfMemory,
};

pub fn buildRequest(
    allocator: std.mem.Allocator,
    method: []const u8,
    script_filename: []const u8,
    request_uri: []const u8,
    body: []const u8,
) ![]u8 {
    return buildRequestWithOptions(allocator, .{
        .method = method,
        .script_filename = script_filename,
        .request_uri = request_uri,
    }, body);
}

pub fn buildRequestWithOptions(
    allocator: std.mem.Allocator,
    opts: RequestOptions,
    body: []const u8,
) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    try appendBeginRequest(&out, opts.request_id, opts.keep_conn);

    var params = std.ArrayList(u8).init(allocator);
    defer params.deinit();

    var len_buf: [32]u8 = undefined;
    const content_length = try std.fmt.bufPrint(&len_buf, "{d}", .{body.len});

    try appendNameValue(&params, "GATEWAY_INTERFACE", "CGI/1.1");
    try appendNameValue(&params, "REQUEST_METHOD", opts.method);
    try appendNameValue(&params, "SCRIPT_FILENAME", opts.script_filename);
    try appendNameValue(&params, "REQUEST_URI", opts.request_uri);
    try appendNameValue(&params, "QUERY_STRING", opts.query_string);
    try appendNameValue(&params, "PATH_INFO", opts.path_info);
    try appendNameValue(&params, "SCRIPT_NAME", if (opts.script_name.len > 0) opts.script_name else opts.path_info);
    try appendNameValue(&params, "DOCUMENT_ROOT", opts.document_root);
    try appendNameValue(&params, "CONTENT_LENGTH", content_length);
    try appendNameValue(&params, "REMOTE_ADDR", opts.remote_addr);
    try appendNameValue(&params, "REMOTE_PORT", opts.remote_port);
    try appendNameValue(&params, "SERVER_NAME", opts.server_name);
    try appendNameValue(&params, "SERVER_PORT", opts.server_port);
    try appendNameValue(&params, "SERVER_PROTOCOL", opts.server_protocol);
    try appendNameValue(&params, "REQUEST_SCHEME", opts.request_scheme);
    try appendNameValue(&params, "HTTPS", if (opts.https) "on" else "off");

    if (opts.content_type) |content_type| {
        try appendNameValue(&params, "CONTENT_TYPE", content_type);
    }

    if (opts.headers) |headers| {
        for (headers.iterator()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-type") or
                std.ascii.eqlIgnoreCase(header.name, "content-length"))
            {
                continue;
            }

            const env_name = try headerNameToEnv(allocator, header.name);
            defer allocator.free(env_name);
            try appendNameValue(&params, env_name, header.value);
        }
    }

    for (opts.extra_env) |pair| {
        try appendNameValue(&params, pair.name, pair.value);
    }

    try appendStreamRecords(&out, .params, opts.request_id, params.items);
    try writeHeader(&out, .params, opts.request_id, 0, 0);
    try appendStreamRecords(&out, .stdin, opts.request_id, body);
    try writeHeader(&out, .stdin, opts.request_id, 0, 0);
    return out.toOwnedSlice();
}

pub fn execute(
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    opts: RequestOptions,
    body: []const u8,
) !Response {
    var stream = try connect(allocator, endpoint);
    defer stream.close();
    return exchange(allocator, &stream, opts, body);
}

pub fn connect(allocator: std.mem.Allocator, endpoint: []const u8) !std.net.Stream {
    return openStream(allocator, endpoint);
}

pub fn exchange(
    allocator: std.mem.Allocator,
    stream: *std.net.Stream,
    opts: RequestOptions,
    body: []const u8,
) !Response {
    const wire = try buildRequestWithOptions(allocator, opts, body);
    defer allocator.free(wire);
    try stream.writeAll(wire);
    return readResponseForRequest(allocator, stream, opts.request_id);
}

pub fn readResponse(allocator: std.mem.Allocator, stream: *std.net.Stream) !Response {
    return readResponseForRequest(allocator, stream, 0);
}

pub fn readResponseForRequest(allocator: std.mem.Allocator, stream: *std.net.Stream, request_id: u16) !Response {
    var raw = std.ArrayList(u8).init(allocator);
    errdefer raw.deinit();
    var buf: [4096]u8 = undefined;
    var saw_end_request = false;

    while (true) {
        const n = try stream.read(&buf);
        if (n == 0) break;
        try raw.appendSlice(buf[0..n]);
        if (raw.items.len > 4 * 1024 * 1024) return error.MessageTooLarge;
        saw_end_request = responseContainsEndRequest(raw.items, request_id);
        if (saw_end_request) break;
    }

    if (!saw_end_request) return error.MissingEndRequest;
    return parseResponseForRequest(allocator, raw.items, request_id);
}

pub fn parseResponse(allocator: std.mem.Allocator, data: []const u8) ParseError!Response {
    return parseResponseForRequest(allocator, data, 0);
}

pub fn parseResponseForRequest(allocator: std.mem.Allocator, data: []const u8, request_id: u16) ParseError!Response {
    var stdout_buf = std.ArrayList(u8).init(allocator);
    errdefer stdout_buf.deinit();
    var stderr_buf = std.ArrayList(u8).init(allocator);
    errdefer stderr_buf.deinit();

    var pos: usize = 0;
    var saw_end_request = false;
    var app_status: u32 = 0;
    var protocol_status: u8 = request_complete;

    while (pos < data.len) {
        if (data.len - pos < 8) return error.InvalidRecordHeader;
        if (data[pos] != version_1) return error.InvalidRecordHeader;

        const record_request_id = std.mem.readInt(u16, data[pos + 2 ..][0..2], .big);
        const record_type: RecordType = @enumFromInt(data[pos + 1]);
        const content_len = std.mem.readInt(u16, data[pos + 4 ..][0..2], .big);
        const padding_len = data[pos + 6];
        const record_len = 8 + content_len + padding_len;
        if (record_len > data.len - pos) return error.InvalidRecordLength;

        const content = data[pos + 8 .. pos + 8 + content_len];
        if (request_id != 0 and record_request_id != request_id) {
            pos += record_len;
            continue;
        }
        switch (record_type) {
            .stdout => try stdout_buf.appendSlice(content),
            .stderr => try stderr_buf.appendSlice(content),
            .end_request => {
                if (content.len < 8) return error.InvalidEndRequest;
                app_status = std.mem.readInt(u32, content[0..4], .big);
                protocol_status = content[4];
                saw_end_request = true;
            },
            else => {},
        }

        pos += record_len;
    }

    if (!saw_end_request) return error.MissingEndRequest;

    const stdout_data = stdout_buf.items;
    const split = headerBodySplit(stdout_data) orelse return error.MissingHeaderTerminator;
    const headers_text = try normalizeHeaderBlock(allocator, stdout_data[0..split.headers_end]);
    defer allocator.free(headers_text);

    const headers_result = headers_mod.parseHeaders(allocator, headers_text) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TooManyHeaders => return error.TooManyHeaders,
        error.HeaderTooLarge => return error.HeaderTooLarge,
        error.HeadersTooLarge => return error.HeadersTooLarge,
        error.InvalidHeader => return error.InvalidHeader,
        error.IncompleteHeaders => return error.IncompleteHeaders,
    };
    var headers = headers_result.headers;
    errdefer headers.deinit();

    const status = parseStatus(headers.get("status") orelse "") catch |err| switch (err) {
        error.InvalidStatusHeader => return error.InvalidStatusHeader,
    };

    const body = try allocator.dupe(u8, stdout_data[split.body_start..]);
    errdefer allocator.free(body);
    const stderr = try stderr_buf.toOwnedSlice();
    errdefer allocator.free(stderr);

    stdout_buf.deinit();
    return .{
        .allocator = allocator,
        .status = if (status == 0) 200 else status,
        .headers = headers,
        .body = body,
        .stderr = stderr,
        .app_status = app_status,
        .protocol_status = protocol_status,
    };
}

fn openStream(allocator: std.mem.Allocator, endpoint: []const u8) !std.net.Stream {
    if (unixSocketPath(endpoint)) |path| {
        return std.net.connectUnixSocket(path);
    }
    const ep = try memcached.parseEndpoint(endpoint);
    return std.net.tcpConnectToHost(allocator, ep.host, ep.port);
}

fn unixSocketPath(endpoint: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, endpoint, "unix://")) return endpoint["unix://".len..];
    if (std.mem.startsWith(u8, endpoint, "unix:")) return endpoint["unix:".len..];
    return null;
}

fn responseContainsEndRequest(data: []const u8, request_id: u16) bool {
    var pos: usize = 0;
    while (pos + 8 <= data.len) {
        if (data[pos] != version_1) return false;
        const record_request_id = std.mem.readInt(u16, data[pos + 2 ..][0..2], .big);
        const content_len = std.mem.readInt(u16, data[pos + 4 ..][0..2], .big);
        const padding_len = data[pos + 6];
        const record_len = 8 + content_len + padding_len;
        if (record_len > data.len - pos) return false;
        if (data[pos + 1] == @intFromEnum(RecordType.end_request) and (request_id == 0 or record_request_id == request_id)) return true;
        pos += record_len;
    }
    return false;
}

fn appendBeginRequest(out: *std.ArrayList(u8), request_id: u16, keep_conn: bool) !void {
    try writeHeader(out, .begin_request, request_id, 8, 0);
    try out.appendSlice(&[_]u8{
        0,                                    responder_role,
        if (keep_conn) keep_conn_flag else 0, 0,
        0,                                    0,
        0,                                    0,
    });
}

fn appendStreamRecords(out: *std.ArrayList(u8), record_type: RecordType, request_id: u16, payload: []const u8) !void {
    var offset: usize = 0;
    while (offset < payload.len) {
        const chunk_len = @min(payload.len - offset, 0xffff);
        try writeHeader(out, record_type, request_id, @intCast(chunk_len), 0);
        try out.appendSlice(payload[offset .. offset + chunk_len]);
        offset += chunk_len;
    }
}

fn writeHeader(out: *std.ArrayList(u8), record_type: RecordType, request_id: u16, content_len: u16, padding_len: u8) !void {
    try out.append(version_1);
    try out.append(@intFromEnum(record_type));
    try out.append(@intCast((request_id >> 8) & 0xff));
    try out.append(@intCast(request_id & 0xff));
    try out.append(@intCast((content_len >> 8) & 0xff));
    try out.append(@intCast(content_len & 0xff));
    try out.append(padding_len);
    try out.append(0);
}

fn appendNameValue(out: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    try appendLength(out, name.len);
    try appendLength(out, value.len);
    try out.appendSlice(name);
    try out.appendSlice(value);
}

fn appendLength(out: *std.ArrayList(u8), len: usize) !void {
    if (len < 128) {
        try out.append(@intCast(len));
        return;
    }

    const encoded = 0x80000000 | @as(u32, @intCast(len));
    try out.append(@intCast((encoded >> 24) & 0xff));
    try out.append(@intCast((encoded >> 16) & 0xff));
    try out.append(@intCast((encoded >> 8) & 0xff));
    try out.append(@intCast(encoded & 0xff));
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
            try out.append('\r');
            try out.append('\n');
            continue;
        }
        try out.append(c);
    }

    if (!std.mem.endsWith(u8, out.items, "\r\n\r\n")) {
        try out.appendSlice("\r\n\r\n");
    }
    return out.toOwnedSlice();
}

fn parseStatus(raw: []const u8) !u16 {
    if (raw.len == 0) return 200;
    const trimmed = std.mem.trim(u8, raw, " \t");
    if (trimmed.len == 0) return 200;
    const end = std.mem.indexOfScalar(u8, trimmed, ' ') orelse trimmed.len;
    return std.fmt.parseInt(u16, trimmed[0..end], 10) catch error.InvalidStatusHeader;
}

test "buildRequestWithOptions emits known-good fcgi layout" {
    const allocator = std.testing.allocator;
    const req = try buildRequestWithOptions(allocator, .{
        .method = "POST",
        .script_filename = "/srv/app.php",
        .request_uri = "/index.php?name=tardi",
        .query_string = "name=tardi",
        .path_info = "/index.php",
        .content_type = "application/json",
        .remote_addr = "127.0.0.1",
        .server_name = "localhost",
        .server_port = "8080",
    }, "{\"hello\":true}");
    defer allocator.free(req);

    try std.testing.expectEqual(@as(u8, version_1), req[0]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(RecordType.begin_request)), req[1]);
    try std.testing.expect(std.mem.indexOf(u8, req, "REQUEST_METHODPOST") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "SCRIPT_FILENAME/srv/app.php") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "QUERY_STRINGname=tardi") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "CONTENT_TYPEapplication/json") != null);
}

test "parseResponse splits headers and body across stdout records" {
    const allocator = std.testing.allocator;
    const part_one = "Status: 201 Created\r\nContent-Ty";
    const part_two = "pe: text/plain\r\n\r\nhello world";
    const stderr_part = "notice";

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try writeHeader(&buf, .stdout, 1, part_one.len, 0);
    try buf.appendSlice(part_one);
    try writeHeader(&buf, .stdout, 1, part_two.len, 0);
    try buf.appendSlice(part_two);
    try writeHeader(&buf, .stderr, 1, stderr_part.len, 0);
    try buf.appendSlice(stderr_part);
    try writeHeader(&buf, .end_request, 1, 8, 0);
    try buf.appendSlice(&[_]u8{ 0, 0, 0, 0, request_complete, 0, 0, 0 });

    var parsed = try parseResponse(allocator, buf.items);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u16, 201), parsed.status);
    try std.testing.expectEqualStrings("text/plain", parsed.contentType());
    try std.testing.expectEqualStrings("hello world", parsed.body);
    try std.testing.expectEqualStrings("notice", parsed.stderr);
}

test "parseResponseForRequest ignores records for other request ids" {
    const allocator = std.testing.allocator;
    const payload = "Status: 200 OK\r\nContent-Type: text/plain\r\n\r\ntarget";
    const ignored = "ignore!";

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try writeHeader(&buf, .stdout, 2, payload.len, 0);
    try buf.appendSlice(payload);
    try writeHeader(&buf, .stdout, 7, ignored.len, 0);
    try buf.appendSlice(ignored);
    try writeHeader(&buf, .end_request, 2, 8, 0);
    try buf.appendSlice(&[_]u8{ 0, 0, 0, 0, request_complete, 0, 0, 0 });
    try writeHeader(&buf, .end_request, 7, 8, 0);
    try buf.appendSlice(&[_]u8{ 0, 0, 0, 0, request_complete, 0, 0, 0 });

    var parsed = try parseResponseForRequest(allocator, buf.items, 2);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 200), parsed.status);
    try std.testing.expectEqualStrings("target", parsed.body);
    try std.testing.expectEqualStrings("", parsed.stderr);
}

test "buildRequest preserves incoming headers as HTTP_* env vars" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();
    try headers.append("Host", "example.test");
    try headers.append("X-Correlation-ID", "req-123");

    const req = try buildRequestWithOptions(allocator, .{
        .method = "GET",
        .script_filename = "/index.php",
        .request_uri = "/",
        .headers = &headers,
    }, "");
    defer allocator.free(req);

    try std.testing.expect(std.mem.indexOf(u8, req, "HTTP_HOSTexample.test") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "HTTP_X_CORRELATION_IDreq-123") != null);
}
