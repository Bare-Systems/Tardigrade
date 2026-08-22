const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const integration_options = @import("integration_options");
const compat = @import("zig_compat");
const hpack = @import("hpack");
const tls_core = @import("tls_core");
const bounded_process = @import("bounded_process.zig");

const test_host = "127.0.0.1";
const valid_bearer_token = "integration-token";
const valid_bearer_hash = "521bc8ca01307d0189b55a19da738e39c7204f7077e0076e803026e32b2f9383";
const http3_curl_path = "/opt/homebrew/opt/curl/bin/curl";
const expected_server_header = "tardigrade/0.4.1";
const http3_retry_attempts: usize = 20;
const http3_retry_delay_ms: u64 = 250;

fn inheritedEnvMap(allocator: std.mem.Allocator) !std.process.Environ.Map {
    const c_environ = std.c.environ;
    var env_count: usize = 0;
    while (c_environ[env_count] != null) : (env_count += 1) {}
    return std.process.Environ.createMap(.{
        .block = .{ .slice = c_environ[0..env_count :null] },
    }, allocator);
}

const EnvPair = struct {
    name: []const u8,
    value: []const u8,
};

const ResponseHeader = struct {
    name: []const u8,
    value: []const u8,
};

const RequestHeader = struct {
    name: []const u8,
    value: []const u8,
};

const RequestSpec = struct {
    method: []const u8,
    path: []const u8,
    body: ?[]const u8,
    headers: []const RequestHeader,
    proxy_ip: ?[]const u8 = null,
    connection_close: bool = true,
};

const UpstreamResponseSpec = struct {
    status_code: u16 = 200,
    headers: []const ResponseHeader = &.{},
    body: []const u8 = "{\"ok\":true}",
    delay_ms: u32 = 0,
    connection_header: []const u8 = "close",
    chunked: bool = false,
    omit_body: bool = false,
    truncate_body_after: ?usize = null,
    /// Emit neither `Content-Length` nor `Transfer-Encoding`, so the body is
    /// delimited by the connection close (HTTP/1.0-style framing).
    close_delimited: bool = false,
};

const FastCgiResponseSpec = struct {
    status_code: u16 = 200,
    headers: []const ResponseHeader = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    body: []const u8 = "ok",
    stderr: []const u8 = "",
    app_status: u32 = 0,
    protocol_status: u8 = 0,
};

const ScgiResponseSpec = struct {
    status_code: u16 = 200,
    headers: []const ResponseHeader = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    body: []const u8 = "ok",
    http_status_line: bool = true,
};

const UwsgiResponseSpec = struct {
    status_code: u16 = 200,
    headers: []const ResponseHeader = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    body: []const u8 = "ok",
    http_status_line: bool = true,
};

const TardigradeOptions = struct {
    const Profile = enum {
        auto,
        generic,
        bearclaw,
    };

    profile: Profile = .auto,
    upstream_port: ?u16 = null,
    auth_token_hashes: ?[]const u8 = valid_bearer_hash,
    rate_limit_rps: ?[]const u8 = "1000",
    rate_limit_burst: ?[]const u8 = "1000",
    config_text: ?[]const u8 = null,
    extra_env: []const EnvPair = &.{},
    ready_proxy_ip: ?[]const u8 = null,
    ready_path: []const u8 = "/",
    ready_https_insecure: bool = false,
    ready_client_cert: ?[]const u8 = null,
    ready_client_key: ?[]const u8 = null,
    ready_status_code: ?u16 = null,
};

const HttpResponse = struct {
    allocator: std.mem.Allocator,
    raw: []u8,
    status_code: u16,
    headers_raw: []const u8,
    body: []const u8,

    fn deinit(self: *HttpResponse) void {
        self.allocator.free(self.raw);
        self.* = undefined;
    }

    fn header(self: *const HttpResponse, name: []const u8) ?[]const u8 {
        return headerValue(self.headers_raw, name);
    }
};

const WebSocketOpCode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

const WebSocketFrame = struct {
    fin: bool,
    opcode: WebSocketOpCode,
    payload: []u8,

    fn deinit(self: *WebSocketFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

const WebSocketClient = struct {
    stream: compat.NetStream,

    fn connect(allocator: std.mem.Allocator, port: u16, path: []const u8, headers: []const RequestHeader) !WebSocketClient {
        var stream = try compat.tcpConnectToHost(allocator, test_host, port);
        errdefer stream.close();
        try setStreamTimeouts(&stream, 5_000);

        var request = std.array_list.Managed(u8).init(allocator);
        defer request.deinit();
        try request.print(
            allocator,
            "GET {s} HTTP/1.1\r\nHost: {s}:{d}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n",
            .{ path, test_host, port },
        );
        for (headers) |header| {
            try request.print("{s}: {s}\r\n", .{ header.name, header.value });
        }
        try request.appendSlice("\r\n");
        try stream.writeAll(request.items);

        const handshake = try readHttpHeadersOnly(allocator, stream);
        defer allocator.free(handshake);
        const status = try parseStatusCode(handshake);
        if (status != 101) return error.WebSocketHandshakeFailed;

        return .{ .stream = stream };
    }

    fn close(self: *WebSocketClient) void {
        self.stream.close();
        self.* = undefined;
    }

    fn sendText(self: *WebSocketClient, payload: []const u8) !void {
        try writeMaskedWebSocketFrame(self.stream.writer(), .text, payload, true);
    }

    fn sendClose(self: *WebSocketClient) !void {
        try writeMaskedWebSocketFrame(self.stream.writer(), .close, "", true);
    }

    fn sendPing(self: *WebSocketClient, payload: []const u8) !void {
        try writeMaskedWebSocketFrame(self.stream.writer(), .ping, payload, true);
    }

    fn readFrame(self: *WebSocketClient, allocator: std.mem.Allocator, max_payload: usize) !WebSocketFrame {
        return readWebSocketFrame(self.stream, allocator, max_payload);
    }
};

const CurlRunResult = struct {
    allocator: std.mem.Allocator,
    stdout: []u8,
    stderr: []u8,
    term: std.process.Child.Term,

    fn deinit(self: *CurlRunResult) void {
        self.allocator.free(self.stdout);
        self.allocator.free(self.stderr);
        self.* = undefined;
    }
};

const RequestCapture = struct {
    allocator: std.mem.Allocator,
    method: []u8,
    path: []u8,
    body: []u8,
    correlation_id: []u8,
    headers_raw: []u8,
    path_history: std.array_list.Managed([]u8),
    body_history: std.array_list.Managed([]u8),
    request_count: u32,

    fn init(allocator: std.mem.Allocator) !RequestCapture {
        return .{
            .allocator = allocator,
            .method = try allocator.dupe(u8, ""),
            .path = try allocator.dupe(u8, ""),
            .body = try allocator.dupe(u8, ""),
            .correlation_id = try allocator.dupe(u8, ""),
            .headers_raw = try allocator.dupe(u8, ""),
            .path_history = std.array_list.Managed([]u8).init(allocator),
            .body_history = std.array_list.Managed([]u8).init(allocator),
            .request_count = 0,
        };
    }

    fn deinit(self: *RequestCapture) void {
        self.allocator.free(self.method);
        self.allocator.free(self.path);
        self.allocator.free(self.body);
        self.allocator.free(self.correlation_id);
        self.allocator.free(self.headers_raw);
        for (self.path_history.items) |path| self.allocator.free(path);
        self.path_history.deinit();
        for (self.body_history.items) |body| self.allocator.free(body);
        self.body_history.deinit();
        self.* = undefined;
    }

    fn reset(self: *RequestCapture) !void {
        self.allocator.free(self.method);
        self.allocator.free(self.path);
        self.allocator.free(self.body);
        self.allocator.free(self.correlation_id);
        self.allocator.free(self.headers_raw);
        for (self.path_history.items) |path| self.allocator.free(path);
        self.path_history.clearRetainingCapacity();
        for (self.body_history.items) |body| self.allocator.free(body);
        self.body_history.clearRetainingCapacity();
        self.method = try self.allocator.dupe(u8, "");
        self.path = try self.allocator.dupe(u8, "");
        self.body = try self.allocator.dupe(u8, "");
        self.correlation_id = try self.allocator.dupe(u8, "");
        self.headers_raw = try self.allocator.dupe(u8, "");
        self.request_count = 0;
    }

    fn record(self: *RequestCapture, message: RawHttpMessage) !void {
        self.allocator.free(self.method);
        self.allocator.free(self.path);
        self.allocator.free(self.body);
        self.allocator.free(self.correlation_id);
        self.allocator.free(self.headers_raw);

        var line_it = std.mem.splitScalar(u8, message.request_line, ' ');
        self.method = try self.allocator.dupe(u8, line_it.next() orelse "");
        self.path = try self.allocator.dupe(u8, line_it.next() orelse "");
        try self.path_history.append(try self.allocator.dupe(u8, self.path));
        self.body = try self.allocator.dupe(u8, message.body);
        try self.body_history.append(try self.allocator.dupe(u8, message.body));
        self.correlation_id = try self.allocator.dupe(u8, headerValue(message.headers_raw, "X-Correlation-ID") orelse "");
        self.headers_raw = try self.allocator.dupe(u8, message.headers_raw);
        self.request_count += 1;
    }
};

const FastCgiCapture = struct {
    allocator: std.mem.Allocator,
    raw: []u8,
    request_count: u32,
    last_request_id: u16,

    fn init(allocator: std.mem.Allocator) !FastCgiCapture {
        return .{
            .allocator = allocator,
            .raw = try allocator.dupe(u8, ""),
            .request_count = 0,
            .last_request_id = 0,
        };
    }

    fn deinit(self: *FastCgiCapture) void {
        self.allocator.free(self.raw);
        self.* = undefined;
    }

    fn reset(self: *FastCgiCapture) !void {
        self.allocator.free(self.raw);
        self.raw = try self.allocator.dupe(u8, "");
        self.request_count = 0;
        self.last_request_id = 0;
    }

    fn record(self: *FastCgiCapture, raw: []const u8) !void {
        self.allocator.free(self.raw);
        self.raw = try self.allocator.dupe(u8, raw);
        self.request_count += 1;
        self.last_request_id = if (raw.len >= 4) std.mem.readInt(u16, raw[2..4], .big) else 0;
    }
};

const ScgiCapture = struct {
    allocator: std.mem.Allocator,
    raw: []u8,
    request_count: u32,

    fn init(allocator: std.mem.Allocator) !ScgiCapture {
        return .{
            .allocator = allocator,
            .raw = try allocator.dupe(u8, ""),
            .request_count = 0,
        };
    }

    fn deinit(self: *ScgiCapture) void {
        self.allocator.free(self.raw);
        self.* = undefined;
    }

    fn record(self: *ScgiCapture, raw: []const u8) !void {
        self.allocator.free(self.raw);
        self.raw = try self.allocator.dupe(u8, raw);
        self.request_count += 1;
    }
};

const UwsgiCapture = struct {
    allocator: std.mem.Allocator,
    raw: []u8,
    request_count: u32,

    fn init(allocator: std.mem.Allocator) !UwsgiCapture {
        return .{
            .allocator = allocator,
            .raw = try allocator.dupe(u8, ""),
            .request_count = 0,
        };
    }

    fn deinit(self: *UwsgiCapture) void {
        self.allocator.free(self.raw);
        self.* = undefined;
    }

    fn record(self: *UwsgiCapture, raw: []const u8) !void {
        self.allocator.free(self.raw);
        self.raw = try self.allocator.dupe(u8, raw);
        self.request_count += 1;
    }
};

const RawTcpCapture = struct {
    allocator: std.mem.Allocator,
    raw: []u8,
    request_count: u32,

    fn init(allocator: std.mem.Allocator) !RawTcpCapture {
        return .{
            .allocator = allocator,
            .raw = try allocator.dupe(u8, ""),
            .request_count = 0,
        };
    }

    fn deinit(self: *RawTcpCapture) void {
        self.allocator.free(self.raw);
        self.* = undefined;
    }

    fn record(self: *RawTcpCapture, raw: []const u8) !void {
        self.allocator.free(self.raw);
        self.raw = try self.allocator.dupe(u8, raw);
        self.request_count += 1;
    }
};

const UpstreamServer = struct {
    allocator: std.mem.Allocator,
    server: compat.NetServer,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    mutex: compat.Mutex = .{},
    active_stream_fd: ?std.posix.fd_t = null,
    capture: RequestCapture,
    responses: []const UpstreamResponseSpec,
    next_response_index: usize,
    /// Set when the fixture listens on AF_UNIX instead of TCP. The path is
    /// borrowed from the caller and unlinked on `stop`.
    socket_path: ?[]const u8 = null,

    fn start(allocator: std.mem.Allocator, responses: []const UpstreamResponseSpec) !UpstreamServer {
        return startOnPort(allocator, 0, responses);
    }

    fn startOnPort(allocator: std.mem.Allocator, listen_port: u16, responses: []const UpstreamResponseSpec) !UpstreamServer {
        const server = try compat.listenTcp(test_host, listen_port);
        return .{
            .allocator = allocator,
            .server = server,
            .thread = null,
            .stop_flag = std.atomic.Value(bool).init(false),
            .capture = try RequestCapture.init(allocator),
            .responses = responses,
            .next_response_index = 0,
        };
    }

    fn startOnUnixSocket(allocator: std.mem.Allocator, socket_path: []const u8, responses: []const UpstreamResponseSpec) !UpstreamServer {
        compat.cwd().deleteFile(socket_path) catch {};
        const server = try compat.listenUnix(socket_path);
        return .{
            .allocator = allocator,
            .server = server,
            .thread = null,
            .stop_flag = std.atomic.Value(bool).init(false),
            .capture = try RequestCapture.init(allocator),
            .responses = responses,
            .next_response_index = 0,
            .socket_path = socket_path,
        };
    }

    fn port(self: *const UpstreamServer) u16 {
        return self.server.port();
    }

    fn run(self: *UpstreamServer) !void {
        self.thread = try std.Thread.spawn(.{}, upstreamThreadMain, .{self});
    }

    fn stop(self: *UpstreamServer) void {
        self.stop_flag.store(true, .seq_cst);
        self.mutex.lock();
        if (self.active_stream_fd) |fd| {
            _ = std.c.shutdown(fd, std.posix.SHUT.RDWR);
        }
        self.mutex.unlock();
        if (self.socket_path) |path| wakeUnixListener(path) else wakeListener(self.port());
        if (self.thread) |thread| thread.join();
        self.server.deinit();
        if (self.socket_path) |path| compat.cwd().deleteFile(path) catch {};
        self.capture.deinit();
        self.* = undefined;
    }

    fn setResponses(self: *UpstreamServer, responses: []const UpstreamResponseSpec) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.responses = responses;
        self.next_response_index = 0;
    }

    fn resetCapture(self: *UpstreamServer) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.capture.reset();
    }

    fn requestCount(self: *UpstreamServer) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.capture.request_count;
    }

    fn capturedHeader(self: *UpstreamServer, name: []const u8) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return headerValue(self.capture.headers_raw, name);
    }

    fn capturedPath(self: *UpstreamServer, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return allocator.dupe(u8, self.capture.path);
    }

    fn capturedPathHistoryAt(self: *UpstreamServer, allocator: std.mem.Allocator, index: usize) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return allocator.dupe(u8, self.capture.path_history.items[index]);
    }

    fn capturedBody(self: *UpstreamServer, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return allocator.dupe(u8, self.capture.body);
    }
};

/// Minimal prior-knowledge HTTP/2 cleartext (h2c) origin, enough to exercise
/// the gateway's h2 upstream client (#139). It reads the connection preface,
/// answers SETTINGS, decodes one request's HEADERS, accumulates DATA until
/// END_STREAM, and replies with HEADERS + DATA. Deliberately not a general h2
/// server: no CONTINUATION, priority, push, or multiplexing beyond one stream
/// per connection.
const H2cUpstreamServer = struct {
    allocator: std.mem.Allocator,
    server: compat.NetServer,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    mutex: compat.Mutex = .{},
    /// Decoded request-header fields of the most recent request, `name: value`
    /// per line, so tests can assert on absent headers too.
    headers_raw: []u8,
    /// Concatenated DATA payload of the most recent request.
    body: []u8,
    request_count: u32,
    response_body: []const u8,

    fn start(allocator: std.mem.Allocator, response_body: []const u8) !H2cUpstreamServer {
        return .{
            .allocator = allocator,
            .server = try compat.listenTcp(test_host, 0),
            .thread = null,
            .stop_flag = std.atomic.Value(bool).init(false),
            .headers_raw = try allocator.dupe(u8, ""),
            .body = try allocator.dupe(u8, ""),
            .request_count = 0,
            .response_body = response_body,
        };
    }

    fn port(self: *const H2cUpstreamServer) u16 {
        return self.server.port();
    }

    fn run(self: *H2cUpstreamServer) !void {
        self.thread = try std.Thread.spawn(.{}, h2cUpstreamThreadMain, .{self});
    }

    fn stop(self: *H2cUpstreamServer) void {
        self.stop_flag.store(true, .seq_cst);
        wakeListener(self.port());
        if (self.thread) |thread| thread.join();
        self.server.deinit();
        self.allocator.free(self.headers_raw);
        self.allocator.free(self.body);
        self.* = undefined;
    }

    fn requestCount(self: *H2cUpstreamServer) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.request_count;
    }

    fn capturedBody(self: *H2cUpstreamServer, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return allocator.dupe(u8, self.body);
    }

    /// True when a `name: value` line is present in the last request's decoded
    /// header block. Used to assert both presence and absence.
    fn capturedHasHeader(self: *H2cUpstreamServer, name: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        var lines = std.mem.splitScalar(u8, self.headers_raw, '\n');
        while (lines.next()) |line| {
            const colon = std.mem.findScalar(u8, line, ':') orelse continue;
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " \t"), name)) return true;
        }
        return false;
    }
};

const H2Frame = struct {
    typ: u8,
    flags: u8,
    stream_id: u31,
    payload: []u8,

    fn deinit(self: *H2Frame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

fn readH2Frame(allocator: std.mem.Allocator, stream: compat.NetStream, timeout_ms: i32) !H2Frame {
    var header: [9]u8 = undefined;
    try readExactWithPoll(stream, &header, timeout_ms);
    const len: usize = (@as(usize, header[0]) << 16) | (@as(usize, header[1]) << 8) | header[2];
    const payload = try allocator.alloc(u8, len);
    errdefer allocator.free(payload);
    if (len > 0) try readExactWithPoll(stream, payload, timeout_ms);
    return .{
        .typ = header[3],
        .flags = header[4],
        .stream_id = @intCast(std.mem.readInt(u32, header[5..9], .big) & 0x7fff_ffff),
        .payload = payload,
    };
}

fn readExactWithPoll(stream: compat.NetStream, out: []u8, timeout_ms: i32) !void {
    var filled: usize = 0;
    while (filled < out.len) {
        const n = try readSocketWithPoll(stream.handle, out[filled..], timeout_ms);
        if (n == 0) return error.UnexpectedEndOfStream;
        filled += n;
    }
}

fn writeH2Frame(stream: compat.NetStream, typ: u8, flags: u8, stream_id: u31, payload: []const u8) !void {
    var header: [9]u8 = undefined;
    header[0] = @intCast((payload.len >> 16) & 0xff);
    header[1] = @intCast((payload.len >> 8) & 0xff);
    header[2] = @intCast(payload.len & 0xff);
    header[3] = typ;
    header[4] = flags;
    std.mem.writeInt(u32, header[5..9], @as(u32, stream_id) & 0x7fff_ffff, .big);
    try stream.writeAll(header[0..]);
    if (payload.len > 0) try stream.writeAll(payload);
}

fn h2cUpstreamThreadMain(server: *H2cUpstreamServer) void {
    while (!server.stop_flag.load(.seq_cst)) {
        const conn = server.server.accept() catch return;
        handleH2cUpstreamConnection(server, conn) catch |err| {
            std.debug.print("h2c upstream handler failed: {}\n", .{err});
        };
        conn.stream.close();
        if (server.stop_flag.load(.seq_cst)) return;
    }
}

fn handleH2cUpstreamConnection(server: *H2cUpstreamServer, conn: compat.NetConnection) !void {
    const allocator = server.allocator;
    const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    var preface_buf: [24]u8 = undefined;
    readExactWithPoll(conn.stream, &preface_buf, 5_000) catch return; // wakeListener probe
    if (!std.mem.eql(u8, &preface_buf, preface)) return;

    try writeH2Frame(conn.stream, 0x4, 0, 0, &.{}); // server SETTINGS
    // Widen the connection-level window so a multi-megabyte upload is bounded
    // by the gateway's relay buffer rather than by this fixture's flow control.
    var inc: [4]u8 = undefined;
    std.mem.writeInt(u32, &inc, 8 * 1024 * 1024, .big);
    try writeH2Frame(conn.stream, 0x8, 0, 0, &inc);

    var body: std.array_list.Managed(u8) = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    var headers_raw: std.array_list.Managed(u8) = std.array_list.Managed(u8).init(allocator);
    defer headers_raw.deinit();
    var request_stream_id: u31 = 0;

    while (true) {
        var frame = readH2Frame(allocator, conn.stream, 5_000) catch return;
        defer frame.deinit(allocator);

        switch (frame.typ) {
            0x4 => { // SETTINGS
                if ((frame.flags & 0x1) == 0) try writeH2Frame(conn.stream, 0x4, 0x1, 0, &.{});
            },
            0x6 => { // PING
                if ((frame.flags & 0x1) == 0) try writeH2Frame(conn.stream, 0x6, 0x1, 0, frame.payload);
            },
            0x1 => { // HEADERS
                request_stream_id = frame.stream_id;
                var decoded = try hpack.decode(allocator, frame.payload);
                defer hpack.deinitDecoded(allocator, &decoded);
                for (decoded.headers) |field| {
                    try headers_raw.appendSlice(field.name);
                    try headers_raw.appendSlice(": ");
                    try headers_raw.appendSlice(field.value);
                    try headers_raw.append('\n');
                }
                if ((frame.flags & 0x1) != 0) break; // END_STREAM: bodiless request
            },
            0x0 => { // DATA
                try body.appendSlice(frame.payload);
                if (frame.payload.len > 0) {
                    // Replenish both windows so the upload keeps flowing.
                    var data_inc: [4]u8 = undefined;
                    std.mem.writeInt(u32, &data_inc, @intCast(frame.payload.len), .big);
                    try writeH2Frame(conn.stream, 0x8, 0, 0, &data_inc);
                    try writeH2Frame(conn.stream, 0x8, 0, frame.stream_id, &data_inc);
                }
                if ((frame.flags & 0x1) != 0) break; // END_STREAM
            },
            0x7 => return, // GOAWAY
            else => {},
        }
    }

    server.mutex.lock();
    allocator.free(server.body);
    server.body = try allocator.dupe(u8, body.items);
    allocator.free(server.headers_raw);
    server.headers_raw = try allocator.dupe(u8, headers_raw.items);
    server.request_count += 1;
    const response_body = server.response_body;
    server.mutex.unlock();

    var length_buf: [24]u8 = undefined;
    const length_value = try std.fmt.bufPrint(&length_buf, "{d}", .{response_body.len});
    const response_headers = [_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
        .{ .name = "content-length", .value = length_value },
    };
    const block = try hpack.encodeLiteralHeaderBlock(allocator, &response_headers);
    defer allocator.free(block);
    try writeH2Frame(conn.stream, 0x1, 0x4, request_stream_id, block); // END_HEADERS
    try writeH2Frame(conn.stream, 0x0, 0x1, request_stream_id, response_body); // END_STREAM

    // GOAWAY tells the gateway not to reuse this connection, then the receive
    // buffer has to be drained before closing: the gateway is still sending
    // WINDOW_UPDATE/SETTINGS-ACK frames this fixture never consumes, and on
    // Linux `close()` with unread data queued sends RST instead of FIN, which
    // discards the response still sitting in the send buffer. That truncates
    // the relayed body downstream, which is a fixture artifact rather than a
    // gateway bug — macOS happens to tolerate it.
    var goaway_payload: [8]u8 = undefined;
    std.mem.writeInt(u32, goaway_payload[0..4], request_stream_id, .big);
    std.mem.writeInt(u32, goaway_payload[4..8], 0, .big); // NO_ERROR
    writeH2Frame(conn.stream, 0x7, 0, 0, &goaway_payload) catch {};
    drainH2Connection(allocator, conn.stream);
}

/// Read and discard whatever the peer has queued, until it closes or goes quiet.
/// Bounded so a peer that keeps the connection parked cannot stall the fixture.
fn drainH2Connection(allocator: std.mem.Allocator, stream: compat.NetStream) void {
    var frames: usize = 0;
    while (frames < 64) : (frames += 1) {
        var frame = readH2Frame(allocator, stream, 250) catch return;
        frame.deinit(allocator);
    }
}

const FastCgiServer = struct {
    allocator: std.mem.Allocator,
    server: compat.NetServer,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    mutex: compat.Mutex = .{},
    capture: FastCgiCapture,
    responses: []const FastCgiResponseSpec,
    next_response_index: usize,
    accepted_connections: u32,

    fn start(allocator: std.mem.Allocator, responses: []const FastCgiResponseSpec) !FastCgiServer {
        const server = try compat.listenTcp(test_host, 0);
        return .{
            .allocator = allocator,
            .server = server,
            .thread = null,
            .stop_flag = std.atomic.Value(bool).init(false),
            .capture = try FastCgiCapture.init(allocator),
            .responses = responses,
            .next_response_index = 0,
            .accepted_connections = 0,
        };
    }

    fn port(self: *const FastCgiServer) u16 {
        return self.server.port();
    }

    fn run(self: *FastCgiServer) !void {
        self.thread = try std.Thread.spawn(.{}, fastCgiThreadMain, .{self});
    }

    fn stop(self: *FastCgiServer) void {
        self.stop_flag.store(true, .seq_cst);
        wakeListener(self.port());
        if (self.thread) |thread| thread.join();
        self.server.deinit();
        self.capture.deinit();
        self.* = undefined;
    }
};

const ScgiServer = struct {
    allocator: std.mem.Allocator,
    server: compat.NetServer,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    mutex: compat.Mutex = .{},
    capture: ScgiCapture,
    responses: []const ScgiResponseSpec,
    next_response_index: usize,

    fn start(allocator: std.mem.Allocator, responses: []const ScgiResponseSpec) !ScgiServer {
        const server = try compat.listenTcp(test_host, 0);
        return .{
            .allocator = allocator,
            .server = server,
            .thread = null,
            .stop_flag = std.atomic.Value(bool).init(false),
            .capture = try ScgiCapture.init(allocator),
            .responses = responses,
            .next_response_index = 0,
        };
    }

    fn port(self: *const ScgiServer) u16 {
        return self.server.port();
    }

    fn run(self: *ScgiServer) !void {
        self.thread = try std.Thread.spawn(.{}, scgiThreadMain, .{self});
    }

    fn stop(self: *ScgiServer) void {
        self.stop_flag.store(true, .seq_cst);
        wakeListener(self.port());
        if (self.thread) |thread| thread.join();
        self.server.deinit();
        self.capture.deinit();
        self.* = undefined;
    }
};

const UwsgiServer = struct {
    allocator: std.mem.Allocator,
    server: compat.NetServer,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    mutex: compat.Mutex = .{},
    capture: UwsgiCapture,
    responses: []const UwsgiResponseSpec,
    next_response_index: usize,

    fn start(allocator: std.mem.Allocator, responses: []const UwsgiResponseSpec) !UwsgiServer {
        const server = try compat.listenTcp(test_host, 0);
        return .{
            .allocator = allocator,
            .server = server,
            .thread = null,
            .stop_flag = std.atomic.Value(bool).init(false),
            .capture = try UwsgiCapture.init(allocator),
            .responses = responses,
            .next_response_index = 0,
        };
    }

    fn port(self: *const UwsgiServer) u16 {
        return self.server.port();
    }

    fn run(self: *UwsgiServer) !void {
        self.thread = try std.Thread.spawn(.{}, uwsgiThreadMain, .{self});
    }

    fn stop(self: *UwsgiServer) void {
        self.stop_flag.store(true, .seq_cst);
        wakeListener(self.port());
        if (self.thread) |thread| thread.join();
        self.server.deinit();
        self.capture.deinit();
        self.* = undefined;
    }
};

const RawTcpServer = struct {
    allocator: std.mem.Allocator,
    server: compat.NetServer,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    mutex: compat.Mutex = .{},
    capture: RawTcpCapture,
    response: []const u8,

    fn start(allocator: std.mem.Allocator, response: []const u8) !RawTcpServer {
        const server = try compat.listenTcp(test_host, 0);
        return .{
            .allocator = allocator,
            .server = server,
            .thread = null,
            .stop_flag = std.atomic.Value(bool).init(false),
            .capture = try RawTcpCapture.init(allocator),
            .response = response,
        };
    }

    fn port(self: *const RawTcpServer) u16 {
        return self.server.port();
    }

    fn run(self: *RawTcpServer) !void {
        self.thread = try std.Thread.spawn(.{}, rawTcpThreadMain, .{self});
    }

    fn stop(self: *RawTcpServer) void {
        self.stop_flag.store(true, .seq_cst);
        wakeListener(self.port());
        if (self.thread) |thread| thread.join();
        self.server.deinit();
        self.capture.deinit();
        self.* = undefined;
    }
};

/// #520: a real upstream that deterministically proves a connection has
/// been accepted, dispatched to a worker, and proxied all the way to it
/// -- and holds it there under the test's own control -- rather than a
/// fixed `delay_ms` sleep (the shape `UpstreamResponseSpec` already
/// supports, used by e.g. `in-flight request completes safely across
/// reload and new requests use new config` above, but not condition-based
/// enough for a proof that must not depend on how long a reload happens
/// to take). `waitEntered` confirms the request truly reached the
/// upstream; `release` lets its response go out only once the caller
/// chooses to, so a request can be held in flight across an arbitrarily
/// long window (here, a real SIGHUP reload race) with no risk of the
/// gate itself timing the proof.
const GatedUpstream = struct {
    allocator: std.mem.Allocator,
    server: compat.NetServer,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    entered: std.atomic.Value(bool),
    release_flag: std.atomic.Value(bool),

    fn start(allocator: std.mem.Allocator) !GatedUpstream {
        const server = try compat.listenTcp(test_host, 0);
        return .{
            .allocator = allocator,
            .server = server,
            .thread = null,
            .stop_flag = std.atomic.Value(bool).init(false),
            .entered = std.atomic.Value(bool).init(false),
            .release_flag = std.atomic.Value(bool).init(false),
        };
    }

    fn port(self: *const GatedUpstream) u16 {
        return self.server.port();
    }

    fn run(self: *GatedUpstream) !void {
        self.thread = try std.Thread.spawn(.{}, gatedUpstreamThreadMain, .{self});
    }

    fn stop(self: *GatedUpstream) void {
        self.stop_flag.store(true, .seq_cst);
        self.release_flag.store(true, .seq_cst);
        wakeListener(self.port());
        if (self.thread) |thread| thread.join();
        self.server.deinit();
        self.* = undefined;
    }

    /// Rearms the gate for another round: must be called before the next
    /// request is sent, never concurrently with one already in flight.
    fn resetGate(self: *GatedUpstream) void {
        self.entered.store(false, .release);
        self.release_flag.store(false, .release);
    }

    fn waitEntered(self: *const GatedUpstream, timeout_ms: u64) !void {
        const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
        while (compat.milliTimestamp() < deadline) {
            if (self.entered.load(.acquire)) return;
            compat.sleepNs(5 * std.time.ns_per_ms);
        }
        return error.GatedUpstreamNotEntered;
    }

    fn release(self: *GatedUpstream) void {
        self.release_flag.store(true, .release);
    }
};

fn gatedUpstreamThreadMain(server: *GatedUpstream) void {
    while (!server.stop_flag.load(.seq_cst)) {
        var conn = server.server.accept() catch |err| {
            if (server.stop_flag.load(.seq_cst)) return;
            std.debug.print("gated upstream accept failed: {}\n", .{err});
            continue;
        };
        defer conn.stream.close();

        const req = readHttpMessage(server.allocator, conn.stream, 1024 * 1024) catch |err| {
            if (server.stop_flag.load(.seq_cst)) return;
            std.debug.print("gated upstream read failed: {}\n", .{err});
            continue;
        };
        defer server.allocator.free(req.raw);
        if (req.request_line.len == 0) continue;

        server.entered.store(true, .release);
        while (!server.release_flag.load(.acquire)) {
            if (server.stop_flag.load(.seq_cst)) return;
            compat.sleepNs(2 * std.time.ns_per_ms);
        }
        if (server.stop_flag.load(.seq_cst)) return;

        const body = "gated-ok";
        var out = std.array_list.Managed(u8).init(server.allocator);
        defer out.deinit();
        out.print("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ body.len, body }) catch continue;
        conn.stream.writeAll(out.items) catch |err| {
            if (server.stop_flag.load(.seq_cst)) return;
            std.debug.print("gated upstream write failed: {}\n", .{err});
            continue;
        };
    }
}

/// #520: drives one real native TLS H1 request against `port`'s `/race`
/// route (proxied to a `GatedUpstream`) on its own thread, so the main
/// test thread can hold a reservation lock and drive a SIGHUP race while
/// this request sits blocked mid-flight at the gate. `done` is a plain
/// atomic the main thread can poll (see `waitForRaceRequestComplete`)
/// without joining the thread first -- joining would block until the
/// gate is released, which is exactly the ordering this proof needs to
/// control explicitly.
const RaceRequestResult = struct {
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    status_ok: bool = false,
    err: ?anyerror = null,
};

fn runTlsRaceRequest(allocator: std.mem.Allocator, port: u16, result: *RaceRequestResult) void {
    defer result.done.store(true, .release);
    const client = PureZigTlsClient.create(allocator, port, "http/1.1") catch |err| {
        result.err = err;
        return;
    };
    defer client.destroy();
    client.writeAllPlain("GET /race HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n") catch |err| {
        result.err = err;
        return;
    };
    const raw = client.readPlainToEnd(allocator, 64 * 1024, 10_000) catch |err| {
        result.err = err;
        return;
    };
    defer allocator.free(raw);
    result.status_ok = containsSubstring(raw, "HTTP/1.1 200 OK");
}

fn waitForRaceRequestComplete(result: *const RaceRequestResult, timeout_ms: u64) !void {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        if (result.done.load(.acquire)) return;
        compat.sleepNs(5 * std.time.ns_per_ms);
    }
    return error.RaceRequestNotObserved;
}

const StartTlsSmtpProcess = struct {
    allocator: std.mem.Allocator,
    child: std.process.Child,
    port: u16,
    dir_rel: []u8,
    script_path: []u8,
    plain_capture_path: []u8,
    tls_capture_path: []u8,
    debug_log_path: []u8,

    fn start(allocator: std.mem.Allocator) !StartTlsSmtpProcess {
        const port = try findFreePort();
        const unique = compat.milliTimestamp();
        const dir_rel = try std.fmt.allocPrint(allocator, ".zig-cache/starttls-smtp-{d}-{d}", .{ port, unique });
        errdefer allocator.free(dir_rel);
        try compat.cwd().makePath(dir_rel);

        const cwd = try compat.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd);
        const dir_abs = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cwd, dir_rel });
        defer allocator.free(dir_abs);

        const script_path = try std.fmt.allocPrint(allocator, "{s}/server.py", .{dir_abs});
        errdefer allocator.free(script_path);
        const plain_capture_path = try std.fmt.allocPrint(allocator, "{s}/plain.txt", .{dir_abs});
        errdefer allocator.free(plain_capture_path);
        const tls_capture_path = try std.fmt.allocPrint(allocator, "{s}/tls.txt", .{dir_abs});
        errdefer allocator.free(tls_capture_path);
        const debug_log_path = try std.fmt.allocPrint(allocator, "{s}/debug.log", .{dir_abs});
        errdefer allocator.free(debug_log_path);
        const cert_path = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/server.crt", .{cwd});
        defer allocator.free(cert_path);
        const key_path = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/server.key", .{cwd});
        defer allocator.free(key_path);

        const script = try std.fmt.allocPrint(allocator,
            \\import socket, ssl
            \\HOST = "127.0.0.1"
            \\PORT = {d}
            \\PLAIN = r"""{s}"""
            \\TLS = r"""{s}"""
            \\DEBUG = r"""{s}"""
            \\CERT = r"""{s}"""
            \\KEY = r"""{s}"""
            \\def log(msg):
            \\    with open(DEBUG, "a") as f:
            \\        f.write(msg + "\\n")
            \\listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            \\listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            \\listener.bind((HOST, PORT))
            \\listener.listen(1)
            \\print("READY", flush=True)
            \\log("ready")
            \\conn, _ = listener.accept()
            \\log("accepted")
            \\conn.sendall(b"220 starttls.integration.test ESMTP\\r\\n")
            \\log("greeting_sent")
            \\plain = conn.recv(4096)
            \\log("plain_recv_1")
            \\with open(PLAIN, "ab") as f:
            \\    f.write(plain)
            \\conn.sendall(b"250-starttls.integration.test\\r\\n250-STARTTLS\\r\\n250 OK\\r\\n")
            \\log("ehlo_reply_sent")
            \\starttls = conn.recv(4096)
            \\log("plain_recv_2")
            \\with open(PLAIN, "ab") as f:
            \\    f.write(starttls)
            \\conn.sendall(b"220 Ready to start TLS\\r\\n")
            \\log("starttls_reply_sent")
            \\ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            \\ctx.load_cert_chain(CERT, KEY)
            \\tls_conn = ctx.wrap_socket(conn, server_side=True)
            \\log("tls_wrapped")
            \\post_tls_ehlo = tls_conn.recv(4096)
            \\log("tls_recv_1")
            \\with open(TLS, "ab") as f:
            \\    f.write(post_tls_ehlo)
            \\tls_conn.sendall(b"250-starttls.integration.test\\r\\n250 AUTH PLAIN\\r\\n")
            \\log("post_tls_reply_sent")
            \\payload = tls_conn.recv(4096)
            \\log("tls_recv_2")
            \\with open(TLS, "ab") as f:
            \\    f.write(payload)
            \\tls_conn.sendall(b"250 queued over tls\\r\\n")
            \\log("payload_reply_sent")
            \\tls_conn.close()
            \\listener.close()
        , .{ port, plain_capture_path, tls_capture_path, debug_log_path, cert_path, key_path });
        defer allocator.free(script);
        {
            var file = try compat.createFileAbsolute(script_path, .{});
            defer file.close();
            try file.writeAll(script);
        }

        var argv = [_][]const u8{ "python3", script_path };
        const child = try std.process.spawn(compat.io(), .{
            .argv = &argv,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .ignore,
        });

        var proc = StartTlsSmtpProcess{
            .allocator = allocator,
            .child = child,
            .port = port,
            .dir_rel = dir_rel,
            .script_path = script_path,
            .plain_capture_path = plain_capture_path,
            .tls_capture_path = tls_capture_path,
            .debug_log_path = debug_log_path,
        };
        errdefer proc.stop();
        try waitUntilChildReady(&proc.child);
        return proc;
    }

    fn stop(self: *StartTlsSmtpProcess) void {
        self.child.kill(compat.io());
        // Keep the temp tree on disk until the SMTP STARTTLS integration path is stable.
        self.allocator.free(self.dir_rel);
        self.allocator.free(self.script_path);
        self.allocator.free(self.plain_capture_path);
        self.allocator.free(self.tls_capture_path);
        self.allocator.free(self.debug_log_path);
        self.* = undefined;
    }

    fn getPort(self: *const StartTlsSmtpProcess) u16 {
        return self.port;
    }

    fn plainCapture(self: *StartTlsSmtpProcess) ![]u8 {
        var file = try compat.openFileAbsolute(self.plain_capture_path, .{});
        defer file.close();
        return try file.readToEndAlloc(self.allocator, 1024 * 1024);
    }

    fn tlsCapture(self: *StartTlsSmtpProcess) ![]u8 {
        var file = try compat.openFileAbsolute(self.tls_capture_path, .{});
        defer file.close();
        return try file.readToEndAlloc(self.allocator, 1024 * 1024);
    }
};

const TardigradeProcess = struct {
    allocator: std.mem.Allocator,
    child: std.process.Child,
    port: u16,
    log_path: []u8,
    config_path: ?[]u8,
    fixture_dir_rel: ?[]u8,

    // #520: split out of `start()` so two (or more) processes can be
    // spawned back-to-back before either is waited on -- `start()` itself
    // spawns *and* blocks until ready, so calling it twice in sequence only
    // ever proves sequential startup/lease-reservation, never genuine
    // contention on the shared snapshot's `${path}.lock`. `start()` below
    // remains the thin, behavior-preserving wrapper every existing caller
    // keeps using unchanged.
    fn spawn(allocator: std.mem.Allocator, options: TardigradeOptions) !TardigradeProcess {
        const port = try findFreePort();
        const cwd = try compat.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd);
        const log_path = try std.fmt.allocPrint(allocator, "{s}/.zig-cache/tardigrade-integration-{d}.log", .{ cwd, port });

        var argv = [_][]const u8{integration_options.tardigrade_bin_path};

        var env_map = try inheritedEnvMap(allocator);
        defer env_map.deinit();

        const port_str = try std.fmt.allocPrint(allocator, "{d}", .{port});
        defer allocator.free(port_str);
        try env_map.put("TARDIGRADE_WORKER_THREADS", "1");

        const use_bearclaw_fixture = switch (options.profile) {
            .generic => false,
            .bearclaw => true,
            .auto => false,
        };

        var config_path: ?[]u8 = null;
        var fixture_dir_rel: ?[]u8 = null;
        if (use_bearclaw_fixture) {
            const prepared = try prepareBearClawFixture(allocator, cwd, port, options, &env_map);
            config_path = prepared.config_path;
            fixture_dir_rel = prepared.fixture_dir_rel;
        }

        // The test harness must own the listen endpoint and log sink even when a
        // profile fixture loads example env files.
        try env_map.put("TARDIGRADE_LISTEN_HOST", test_host);
        try env_map.put("TARDIGRADE_LISTEN_PORT", port_str);
        try env_map.put("TARDIGRADE_ERROR_LOG_PATH", log_path);

        if (options.upstream_port) |upstream_port| {
            const upstream_url = try std.fmt.allocPrint(allocator, "http://{s}:{d}", .{ test_host, upstream_port });
            defer allocator.free(upstream_url);
            try env_map.put("TARDIGRADE_UPSTREAM_BASE_URL", upstream_url);
            try env_map.put("TARDIGRADE_UPSTREAM_CHAT_BASE_URLS", upstream_url);
            try env_map.put("TARDIGRADE_UPSTREAM_COMMANDS_BASE_URLS", upstream_url);
        }
        if (options.auth_token_hashes) |hashes| {
            try env_map.put("TARDIGRADE_AUTH_TOKEN_HASHES", hashes);
        }
        if (options.rate_limit_rps) |rate| {
            try env_map.put("TARDIGRADE_RATE_LIMIT_RPS", rate);
        }
        if (options.rate_limit_burst) |burst| {
            try env_map.put("TARDIGRADE_RATE_LIMIT_BURST", burst);
        }

        if (options.config_text) |config_text| {
            if (use_bearclaw_fixture and config_path != null) {
                const cfg_path = config_path.?;
                const base_config = try compat.cwd().readFileAlloc(allocator, cfg_path, 512 * 1024);
                defer allocator.free(base_config);
                const merged_config = try std.fmt.allocPrint(allocator, "{s}\n\n{s}\n", .{ base_config, config_text });
                defer allocator.free(merged_config);
                try compat.cwd().writeFile(.{ .sub_path = cfg_path, .data = merged_config });
            } else {
                if (fixture_dir_rel) |dir_rel| {
                    compat.cwd().deleteTree(dir_rel) catch {}; // best-effort cleanup; test fixture directory
                    allocator.free(dir_rel);
                    fixture_dir_rel = null;
                }
                if (config_path) |existing| {
                    compat.cwd().deleteFile(existing) catch {}; // best-effort cleanup; test config file
                    allocator.free(existing);
                    config_path = null;
                }
                const cfg_path = try std.fmt.allocPrint(allocator, ".zig-cache/tardigrade-config-{d}.conf", .{port});
                errdefer allocator.free(cfg_path);
                try compat.cwd().writeFile(.{ .sub_path = cfg_path, .data = config_text });
                try env_map.put("TARDIGRADE_CONFIG_PATH", cfg_path);
                config_path = cfg_path;
            }
        }
        for (options.extra_env) |pair| {
            try env_map.put(pair.name, pair.value);
        }
        // Appliance TLS profile: whenever a test enables TLS files without
        // choosing its own server name, supply the fixture identity's name so
        // startup passes the mandatory single-identity policy.
        if (!build_options.tls_openssl_adapter and
            env_map.get("TARDIGRADE_TLS_CERT_PATH") != null and
            env_map.get("TARDIGRADE_TLS_SERVER_NAME") == null)
        {
            try env_map.put("TARDIGRADE_TLS_SERVER_NAME", "tardigrade.test");
        }

        // Pre-create the log file and pass it as the child's initial stderr so
        // that early startup failures (panics or config errors that occur
        // before configureErrorLog redirects fd 2) are captured in the log
        // and visible in test failure output.  configureErrorLog will dup2 the
        // same file to stderr later, which is a harmless no-op.
        const early_stderr: ?std.Io.File = std.Io.Dir.createFileAbsolute(compat.io(), log_path, .{ .truncate = true }) catch null;
        const child = try std.process.spawn(compat.io(), .{
            .argv = &argv,
            .environ_map = &env_map,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = if (early_stderr) |f| .{ .file = f } else .ignore,
        });
        if (early_stderr) |f| f.close(compat.io());

        return TardigradeProcess{
            .allocator = allocator,
            .child = child,
            .port = port,
            .log_path = log_path,
            .config_path = config_path,
            .fixture_dir_rel = fixture_dir_rel,
        };
    }

    fn waitReady(self: *const TardigradeProcess, options: TardigradeOptions) !void {
        try waitUntilReady(self.port, self.log_path, options);
    }

    fn start(allocator: std.mem.Allocator, options: TardigradeOptions) !TardigradeProcess {
        var process = try spawn(allocator, options);
        errdefer process.stop();
        try process.waitReady(options);
        return process;
    }

    fn stop(self: *TardigradeProcess) void {
        self.child.kill(compat.io());
        self.allocator.free(self.log_path);
        if (self.config_path) |path| {
            compat.cwd().deleteFile(path) catch {}; // best-effort cleanup; config file may not exist if setup failed
            self.allocator.free(path);
        }
        if (self.fixture_dir_rel) |path| {
            compat.cwd().deleteTree(path) catch {};
            self.allocator.free(path);
        }
        self.* = undefined;
    }

    fn sendSignal(self: *TardigradeProcess, sig: std.posix.SIG) void {
        std.posix.kill(self.child.id orelse return, sig) catch {};
    }

    fn rewriteConfig(self: *const TardigradeProcess, text: []const u8) !void {
        const path = self.config_path orelse return error.MissingConfigPath;
        try compat.cwd().writeFile(.{ .sub_path = path, .data = text });
    }
};

const PreparedBearClawFixture = struct {
    config_path: []u8,
    fixture_dir_rel: []u8,
};

fn prepareBearClawFixture(
    allocator: std.mem.Allocator,
    cwd: []const u8,
    port: u16,
    options: TardigradeOptions,
    env_map: *std.process.Environ.Map,
) !PreparedBearClawFixture {
    const fixture_tls_enabled = blk: {
        if (options.ready_https_insecure or options.ready_client_cert != null or options.ready_client_key != null) {
            break :blk true;
        }
        for (options.extra_env) |pair| {
            if (std.mem.eql(u8, pair.name, "TARDIGRADE_TLS_CERT_PATH") or
                std.mem.eql(u8, pair.name, "TARDIGRADE_TLS_KEY_PATH") or
                (std.mem.eql(u8, pair.name, "TARDIGRADE_HTTP3_ENABLED") and std.mem.eql(u8, pair.value, "true")))
            {
                break :blk true;
            }
        }
        break :blk false;
    };

    const fixture_dir_rel = try std.fmt.allocPrint(allocator, ".zig-cache/bearclaw-fixture-{d}", .{port});
    errdefer allocator.free(fixture_dir_rel);
    try compat.cwd().makePath(fixture_dir_rel);
    errdefer compat.cwd().deleteTree(fixture_dir_rel) catch {};

    const fixture_dir_abs = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cwd, fixture_dir_rel });
    defer allocator.free(fixture_dir_abs);
    const public_dir_abs = try std.fmt.allocPrint(allocator, "{s}/public", .{fixture_dir_abs});
    defer allocator.free(public_dir_abs);
    const public_dir_rel = try std.fmt.allocPrint(allocator, "{s}/public", .{fixture_dir_rel});
    defer allocator.free(public_dir_rel);
    try compat.cwd().makePath(public_dir_rel);

    const index_rel = try std.fmt.allocPrint(allocator, "{s}/public/index.html", .{fixture_dir_rel});
    defer allocator.free(index_rel);
    try compat.cwd().writeFile(.{
        .sub_path = index_rel,
        .data = "<!doctype html><html><body>bearclaw fixture</body></html>\n",
    });

    const device_registry_abs = try std.fmt.allocPrint(allocator, "{s}/devices.json", .{fixture_dir_abs});
    defer allocator.free(device_registry_abs);
    const session_store_abs = try std.fmt.allocPrint(allocator, "{s}/sessions.json", .{fixture_dir_abs});
    defer allocator.free(session_store_abs);
    const approval_store_abs = try std.fmt.allocPrint(allocator, "{s}/approvals.json", .{fixture_dir_abs});
    defer allocator.free(approval_store_abs);
    const transcript_store_abs = try std.fmt.allocPrint(allocator, "{s}/transcripts.ndjson", .{fixture_dir_abs});
    defer allocator.free(transcript_store_abs);
    {
        var device_file = try compat.createFileAbsolute(device_registry_abs, .{ .truncate = true });
        device_file.close();
    }
    {
        var session_file = try compat.createFileAbsolute(session_store_abs, .{ .truncate = true });
        session_file.close();
    }
    {
        var approval_file = try compat.createFileAbsolute(approval_store_abs, .{ .truncate = true });
        approval_file.close();
    }
    {
        var transcript_file = try compat.createFileAbsolute(transcript_store_abs, .{ .truncate = true });
        transcript_file.close();
    }

    const fixture_name = if (build_options.tls_openssl_adapter) "server" else "native_ed25519";
    const server_cert_abs = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/{s}.crt", .{ cwd, fixture_name });
    defer allocator.free(server_cert_abs);
    const server_key_abs = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/{s}.key", .{ cwd, fixture_name });
    defer allocator.free(server_key_abs);
    const cert_line = try std.fmt.allocPrint(allocator, "tls_cert_path {s};\n", .{server_cert_abs});
    defer allocator.free(cert_line);
    const key_line = try std.fmt.allocPrint(allocator, "tls_key_path {s};\n", .{server_key_abs});
    defer allocator.free(key_line);

    const config_template = try compat.cwd().readFileAlloc(allocator, "examples/bearclaw/tardigrade.conf", 256 * 1024);
    defer allocator.free(config_template);
    const config_text = try std.mem.replaceOwned(u8, allocator, config_template, "/srv/bearclaw/public", public_dir_abs);
    defer allocator.free(config_text);
    const config_text_cert = try std.mem.replaceOwned(u8, allocator, config_text, "/etc/tardigrade/tls/fullchain.pem", server_cert_abs);
    defer allocator.free(config_text_cert);
    const config_text_key = try std.mem.replaceOwned(u8, allocator, config_text_cert, "/etc/tardigrade/tls/privkey.pem", server_key_abs);
    defer allocator.free(config_text_key);
    const final_config_text = if (fixture_tls_enabled)
        try allocator.dupe(u8, config_text_key)
    else blk: {
        const without_ssl = try std.mem.replaceOwned(u8, allocator, config_text_key, "listen 443 ssl;", "listen 443;");
        defer allocator.free(without_ssl);
        const without_cert = try std.mem.replaceOwned(u8, allocator, without_ssl, cert_line, "");
        defer allocator.free(without_cert);
        break :blk try std.mem.replaceOwned(u8, allocator, without_cert, key_line, "");
    };
    errdefer allocator.free(final_config_text);

    const config_path = try std.fmt.allocPrint(allocator, "{s}/tardigrade.conf", .{fixture_dir_rel});
    errdefer {
        compat.cwd().deleteFile(config_path) catch {};
        allocator.free(config_path);
    }
    try compat.cwd().writeFile(.{ .sub_path = config_path, .data = final_config_text });
    allocator.free(final_config_text);
    try env_map.put("TARDIGRADE_CONFIG_PATH", config_path);

    const env_template = try compat.cwd().readFileAlloc(allocator, "examples/bearclaw/tardigrade.env.example", 256 * 1024);
    defer allocator.free(env_template);
    var lines = std.mem.splitScalar(u8, env_template, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.findScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (key.len == 0) continue;
        try env_map.put(key, value);
    }

    try env_map.put("TARDIGRADE_CONFIG_PATH", config_path);
    if (fixture_tls_enabled) {
        try env_map.put("TARDIGRADE_TLS_CERT_PATH", server_cert_abs);
        try env_map.put("TARDIGRADE_TLS_KEY_PATH", server_key_abs);
        if (!build_options.tls_openssl_adapter) {
            // Appliance TLS profile: exactly one configured server name is
            // mandatory whenever TLS files are set.
            try env_map.put("TARDIGRADE_TLS_SERVER_NAME", "tardigrade.test");
        }
    } else {
        _ = env_map.swapRemove("TARDIGRADE_TLS_CERT_PATH");
        _ = env_map.swapRemove("TARDIGRADE_TLS_KEY_PATH");
    }
    try env_map.put("TARDIGRADE_DEVICE_REGISTRY_PATH", device_registry_abs);
    try env_map.put("TARDIGRADE_SESSION_STORE_PATH", session_store_abs);
    try env_map.put("TARDIGRADE_APPROVAL_STORE_PATH", approval_store_abs);
    try env_map.put("TARDIGRADE_TRANSCRIPT_STORE_PATH", transcript_store_abs);
    try env_map.put("TARDIGRADE_AUTH_TOKEN_HASHES", "521bc8ca01307d0189b55a19da738e39c7204f7077e0076e803026e32b2f9383");
    if (options.upstream_port) |upstream_port| {
        const upstream_url = try std.fmt.allocPrint(allocator, "http://{s}:{d}", .{ test_host, upstream_port });
        defer allocator.free(upstream_url);
        try env_map.put("TARDIGRADE_UPSTREAM_BASE_URL", upstream_url);
        try env_map.put("TARDIGRADE_UPSTREAM_CHAT_BASE_URLS", upstream_url);
        try env_map.put("TARDIGRADE_UPSTREAM_COMMANDS_BASE_URLS", upstream_url);
    }

    return .{
        .config_path = config_path,
        .fixture_dir_rel = fixture_dir_rel,
    };
}

const PhpFpmProcess = struct {
    allocator: std.mem.Allocator,
    child: std.process.Child,
    dir_rel: []u8,
    socket_path: []u8,
    script_path: []u8,
    log_path: []u8,
    config_path: []u8,

    fn start(allocator: std.mem.Allocator) !PhpFpmProcess {
        const binary = findPhpFpmBinary() orelse return error.SkipZigTest;
        const cwd = try compat.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd);

        const unique = compat.nanoTimestamp();
        const dir_rel = try std.fmt.allocPrint(allocator, ".zig-cache/php-fpm-{d}", .{unique});
        errdefer allocator.free(dir_rel);
        try compat.cwd().makePath(dir_rel);

        const dir_abs = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cwd, dir_rel });
        defer allocator.free(dir_abs);

        const socket_path = try std.fmt.allocPrint(allocator, "{s}/php-fpm.sock", .{dir_abs});
        errdefer allocator.free(socket_path);
        const log_path = try std.fmt.allocPrint(allocator, "{s}/php-fpm.log", .{dir_abs});
        errdefer allocator.free(log_path);
        const config_path = try std.fmt.allocPrint(allocator, "{s}/php-fpm.conf", .{dir_abs});
        errdefer allocator.free(config_path);
        const script_path = try std.fmt.allocPrint(allocator, "{s}/index.php", .{dir_abs});
        errdefer allocator.free(script_path);
        const config_rel = try std.fmt.allocPrint(allocator, "{s}/php-fpm.conf", .{dir_rel});
        defer allocator.free(config_rel);
        const script_rel = try std.fmt.allocPrint(allocator, "{s}/index.php", .{dir_rel});
        defer allocator.free(script_rel);

        try compat.cwd().writeFile(.{
            .sub_path = script_rel,
            .data =
            \\<?php
            \\header("Content-Type: application/json");
            \\echo json_encode([
            \\  "method" => $_SERVER["REQUEST_METHOD"] ?? "",
            \\  "script" => $_SERVER["SCRIPT_FILENAME"] ?? "",
            \\  "query" => $_SERVER["QUERY_STRING"] ?? "",
            \\  "body" => file_get_contents("php://input"),
            \\], JSON_UNESCAPED_SLASHES);
            ,
        });

        const config_text = try std.fmt.allocPrint(
            allocator,
            \\[global]
            \\daemonize = no
            \\error_log = {s}
            \\pid = {s}/php-fpm.pid
            \\
            \\[www]
            \\listen = {s}
            \\listen.mode = 0666
            \\pm = static
            \\pm.max_children = 1
            \\clear_env = no
            \\catch_workers_output = yes
            \\chdir = {s}
        ,
            .{ log_path, dir_abs, socket_path, dir_abs },
        );
        defer allocator.free(config_text);
        try compat.cwd().writeFile(.{ .sub_path = config_rel, .data = config_text });

        var argv = [_][]const u8{ binary, "--nodaemonize", "--fpm-config", config_path };
        const child = try std.process.spawn(compat.io(), .{
            .argv = &argv,
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });

        var proc = PhpFpmProcess{
            .allocator = allocator,
            .child = child,
            .dir_rel = dir_rel,
            .socket_path = socket_path,
            .script_path = script_path,
            .log_path = log_path,
            .config_path = config_path,
        };
        errdefer proc.stop();
        try waitUntilUnixSocketReady(socket_path, log_path);
        return proc;
    }

    fn stop(self: *PhpFpmProcess) void {
        self.child.kill(compat.io());
        compat.cwd().deleteTree(self.dir_rel) catch {};
        self.allocator.free(self.dir_rel);
        self.allocator.free(self.socket_path);
        self.allocator.free(self.script_path);
        self.allocator.free(self.log_path);
        self.allocator.free(self.config_path);
        self.* = undefined;
    }
};

fn findPhpFpmBinary() ?[]const u8 {
    const candidates = [_][]const u8{
        "/opt/homebrew/opt/php/sbin/php-fpm",
        "/opt/homebrew/sbin/php-fpm",
        "/usr/local/opt/php/sbin/php-fpm",
        "/usr/local/sbin/php-fpm",
        "/opt/homebrew/opt/php@8.5/sbin/php-fpm",
    };
    for (candidates) |candidate| {
        std.fs.accessAbsolute(candidate, .{}) catch continue;
        return candidate;
    }
    return null;
}

fn waitUntilUnixSocketReady(socket_path: []const u8, log_path: []const u8) !void {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        if (std.fs.accessAbsolute(socket_path, .{})) |_| return else |_| {}
        compat.sleepNs(100 * std.time.ns_per_ms);
    }
    _ = log_path;
    return error.Timeout;
}

fn waitUntilChildReady(child: *std.process.Child) !void {
    const stdout = child.stdout orelse return error.Unexpected;
    var buf: [64]u8 = undefined;
    const n = try stdout.read(&buf);
    if (n == 0) return error.EndOfStream;
    if (std.mem.find(u8, buf[0..n], "READY") == null) return error.Unexpected;
}

const RawHttpMessage = struct {
    raw: []u8,
    request_line: []const u8,
    headers_raw: []const u8,
    body: []const u8,
};

fn upstreamThreadMain(server: *UpstreamServer) void {
    while (true) {
        const conn = server.server.accept() catch |err| {
            if (server.stop_flag.load(.seq_cst)) return;
            std.debug.print("upstream accept failed: {}\n", .{err});
            return;
        };
        handleUpstreamConnection(server, conn) catch |err| {
            std.debug.print("upstream handler failed: {}\n", .{err});
        };
        if (server.stop_flag.load(.seq_cst)) return;
    }
}

fn fastCgiThreadMain(server: *FastCgiServer) void {
    while (true) {
        const conn = server.server.accept() catch |err| {
            if (server.stop_flag.load(.seq_cst)) return;
            std.debug.print("fastcgi accept failed: {}\n", .{err});
            return;
        };
        server.mutex.lock();
        server.accepted_connections += 1;
        server.mutex.unlock();
        handleFastCgiConnection(server, conn) catch |err| {
            std.debug.print("fastcgi handler failed: {}\n", .{err});
        };
        if (server.stop_flag.load(.seq_cst)) return;
    }
}

fn scgiThreadMain(server: *ScgiServer) void {
    while (true) {
        const conn = server.server.accept() catch |err| {
            if (server.stop_flag.load(.seq_cst)) return;
            std.debug.print("scgi accept failed: {}\n", .{err});
            return;
        };
        handleScgiConnection(server, conn) catch |err| {
            std.debug.print("scgi handler failed: {}\n", .{err});
        };
        if (server.stop_flag.load(.seq_cst)) return;
    }
}

fn uwsgiThreadMain(server: *UwsgiServer) void {
    while (true) {
        const conn = server.server.accept() catch |err| {
            if (server.stop_flag.load(.seq_cst)) return;
            std.debug.print("uwsgi accept failed: {}\n", .{err});
            return;
        };
        handleUwsgiConnection(server, conn) catch |err| {
            std.debug.print("uwsgi handler failed: {}\n", .{err});
        };
        if (server.stop_flag.load(.seq_cst)) return;
    }
}

fn rawTcpThreadMain(server: *RawTcpServer) void {
    while (!server.stop_flag.load(.seq_cst)) {
        var conn = server.server.accept() catch |err| {
            if (server.stop_flag.load(.seq_cst)) return;
            std.debug.print("raw tcp accept failed: {}\n", .{err});
            continue;
        };
        defer conn.stream.close();

        var buf: [16 * 1024]u8 = undefined;
        const n = conn.stream.read(&buf) catch |err| {
            if (server.stop_flag.load(.seq_cst)) return;
            std.debug.print("raw tcp read failed: {}\n", .{err});
            continue;
        };
        if (n == 0) continue;

        server.mutex.lock();
        server.capture.record(buf[0..n]) catch {};
        const response = server.response;
        server.mutex.unlock();

        conn.stream.writeAll(response) catch |err| {
            if (server.stop_flag.load(.seq_cst)) return;
            std.debug.print("raw tcp write failed: {}\n", .{err});
            continue;
        };
    }
}

fn handleUpstreamConnection(server: *UpstreamServer, conn: compat.NetConnection) !void {
    server.mutex.lock();
    server.active_stream_fd = conn.stream.handle;
    server.mutex.unlock();
    defer {
        server.mutex.lock();
        if (server.active_stream_fd) |fd| {
            if (fd == conn.stream.handle) server.active_stream_fd = null;
        }
        server.mutex.unlock();
        conn.stream.close();
    }
    while (!server.stop_flag.load(.seq_cst)) {
        const req = readHttpMessage(server.allocator, conn.stream, 1024 * 1024) catch |err| switch (err) {
            error.InvalidHttpMessage => return,
            else => return err,
        };
        defer server.allocator.free(req.raw);
        if (req.request_line.len == 0) return;

        const response_spec = blk: {
            server.mutex.lock();
            defer server.mutex.unlock();
            try server.capture.record(req);

            break :blk if (server.responses.len == 0)
                UpstreamResponseSpec{
                    .status_code = 200,
                    .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
                    .body = "{\"ok\":true}",
                }
            else blk_response: {
                const idx = if (server.next_response_index < server.responses.len) server.next_response_index else server.responses.len - 1;
                if (server.next_response_index < server.responses.len) server.next_response_index += 1;
                break :blk_response server.responses[idx];
            };
        };

        if (response_spec.delay_ms > 0) {
            compat.sleepNs(@as(u64, response_spec.delay_ms) * std.time.ns_per_ms);
        }

        const reason = switch (response_spec.status_code) {
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            302 => "Found",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            else => "OK",
        };

        try conn.stream.writer().print("HTTP/1.1 {d} {s}\r\n", .{
            response_spec.status_code,
            reason,
        });
        if (response_spec.chunked) {
            try conn.stream.writer().writeAll("Transfer-Encoding: chunked\r\n");
        } else if (!response_spec.close_delimited) {
            try conn.stream.writer().print("Content-Length: {d}\r\n", .{if (response_spec.omit_body) 0 else response_spec.body.len});
        }
        try conn.stream.writer().print("Connection: {s}\r\n", .{
            response_spec.connection_header,
        });
        for (response_spec.headers) |header| {
            try conn.stream.writer().print("{s}: {s}\r\n", .{ header.name, header.value });
        }
        try conn.stream.writer().writeAll("\r\n");
        if (!response_spec.omit_body) {
            const body_to_write = if (response_spec.truncate_body_after) |limit|
                response_spec.body[0..@min(limit, response_spec.body.len)]
            else
                response_spec.body;
            if (response_spec.chunked) {
                const split = @min(body_to_write.len, @max(@as(usize, 1), body_to_write.len / 2));
                if (split > 0) {
                    try conn.stream.writer().print("{x}\r\n", .{split});
                    try conn.stream.writer().writeAll(body_to_write[0..split]);
                    try conn.stream.writer().writeAll("\r\n");
                }
                if (split < body_to_write.len) {
                    try conn.stream.writer().print("{x}\r\n", .{body_to_write.len - split});
                    try conn.stream.writer().writeAll(body_to_write[split..]);
                    try conn.stream.writer().writeAll("\r\n");
                }
                if (response_spec.truncate_body_after == null) {
                    try conn.stream.writer().writeAll("0\r\n\r\n");
                }
            } else {
                try conn.stream.writer().writeAll(body_to_write);
            }
        }

        if (headerHasToken(req.headers_raw, "Connection", "close") or
            std.ascii.eqlIgnoreCase(response_spec.connection_header, "close"))
        {
            return;
        }
    }
}

fn handleFastCgiConnection(server: *FastCgiServer, conn: compat.NetConnection) !void {
    defer conn.stream.close();
    while (true) {
        const maybe_req = try readFastCgiRequest(server.allocator, conn.stream, 1024 * 1024);
        const req = maybe_req orelse return;
        defer server.allocator.free(req);
        const request_id = fastCgiRequestId(req) orelse 1;

        server.mutex.lock();
        defer server.mutex.unlock();
        try server.capture.record(req);

        const response_spec = if (server.responses.len == 0)
            FastCgiResponseSpec{}
        else blk: {
            const idx = if (server.next_response_index < server.responses.len) server.next_response_index else server.responses.len - 1;
            if (server.next_response_index < server.responses.len) server.next_response_index += 1;
            break :blk server.responses[idx];
        };

        const stdout_payload = try buildFastCgiStdoutPayload(server.allocator, response_spec);
        defer server.allocator.free(stdout_payload);

        if (response_spec.stderr.len > 0) {
            try writeFastCgiRecord(conn.stream.writer(), 7, request_id, response_spec.stderr);
        }
        try writeFastCgiRecord(conn.stream.writer(), 6, request_id, stdout_payload);
        try writeFastCgiRecord(conn.stream.writer(), 6, request_id, "");
        try writeFastCgiEndRequest(conn.stream.writer(), request_id, response_spec.app_status, response_spec.protocol_status);
    }
}

fn handleScgiConnection(server: *ScgiServer, conn: compat.NetConnection) !void {
    defer conn.stream.close();
    const req = try readScgiRequest(server.allocator, conn.stream, 1024 * 1024);
    defer server.allocator.free(req);

    server.mutex.lock();
    defer server.mutex.unlock();
    try server.capture.record(req);

    const response_spec = if (server.responses.len == 0)
        ScgiResponseSpec{}
    else blk: {
        const idx = if (server.next_response_index < server.responses.len) server.next_response_index else server.responses.len - 1;
        if (server.next_response_index < server.responses.len) server.next_response_index += 1;
        break :blk server.responses[idx];
    };

    if (response_spec.http_status_line) {
        try conn.stream.writer().print("HTTP/1.1 {d} {s}\r\n", .{ response_spec.status_code, httpReason(response_spec.status_code) });
    } else {
        try conn.stream.writer().print("Status: {d} {s}\r\n", .{ response_spec.status_code, httpReason(response_spec.status_code) });
    }
    for (response_spec.headers) |header| {
        try conn.stream.writer().print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    try conn.stream.writer().print("\r\n{s}", .{response_spec.body});
}

fn handleUwsgiConnection(server: *UwsgiServer, conn: compat.NetConnection) !void {
    defer conn.stream.close();
    const req = try readUwsgiRequest(server.allocator, conn.stream, 1024 * 1024);
    defer server.allocator.free(req);

    server.mutex.lock();
    defer server.mutex.unlock();
    try server.capture.record(req);

    const response_spec = if (server.responses.len == 0)
        UwsgiResponseSpec{}
    else blk: {
        const idx = if (server.next_response_index < server.responses.len) server.next_response_index else server.responses.len - 1;
        if (server.next_response_index < server.responses.len) server.next_response_index += 1;
        break :blk server.responses[idx];
    };

    if (response_spec.http_status_line) {
        try conn.stream.writer().print("HTTP/1.1 {d} {s}\r\n", .{ response_spec.status_code, httpReason(response_spec.status_code) });
    } else {
        try conn.stream.writer().print("Status: {d} {s}\r\n", .{ response_spec.status_code, httpReason(response_spec.status_code) });
    }
    for (response_spec.headers) |header| {
        try conn.stream.writer().print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    try conn.stream.writer().print("\r\n{s}", .{response_spec.body});
}

fn readSocketWithPoll(handle: std.posix.fd_t, buf: []u8, timeout_ms: i32) !usize {
    var poll_fds = [_]std.posix.pollfd{.{
        .fd = handle,
        .events = std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR,
        .revents = 0,
    }};
    const ready = try std.posix.poll(&poll_fds, timeout_ms);
    if (ready == 0) return error.ReadTimeout;
    return std.posix.read(handle, buf);
}

fn readHttpMessage(allocator: std.mem.Allocator, stream: compat.NetStream, max_bytes: usize) !RawHttpMessage {
    var buf = std.array_list.Managed(u8).init(allocator);
    errdefer buf.deinit();
    var tmp: [4096]u8 = undefined;
    var header_end: ?usize = null;
    var content_length: usize = 0;
    var chunked = false;
    while (true) {
        const read_n = try readSocketWithPoll(stream.handle, &tmp, 5_000);
        if (read_n == 0) break;
        try buf.appendSlice(tmp[0..read_n]);
        if (buf.items.len > max_bytes) return error.MessageTooLarge;

        if (header_end == null) {
            if (std.mem.find(u8, buf.items, "\r\n\r\n")) |idx| {
                header_end = idx + 4;
                content_length = parseContentLength(buf.items[0..idx]);
                if (headerValue(buf.items[0 .. idx + 2], "Transfer-Encoding")) |te| {
                    chunked = std.ascii.eqlIgnoreCase(std.mem.trim(u8, te, " \t\r\n"), "chunked");
                }
            }
        }
        if (header_end) |headers_len| {
            // A chunked upload has no declared length: read until the terminal
            // chunk so the captured body is the whole decoded payload.
            if (chunked) {
                if (std.mem.find(u8, buf.items[headers_len..], "\r\n0\r\n\r\n") != null or
                    std.mem.startsWith(u8, buf.items[headers_len..], "0\r\n\r\n")) break;
            } else if (buf.items.len >= headers_len + content_length) break;
        }
    }

    var raw = try buf.toOwnedSlice();
    errdefer allocator.free(raw);
    const split_idx = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.InvalidHttpMessage;
    const body_start = split_idx + 4;
    if (chunked) {
        // Replace the raw chunk framing with the decoded payload so assertions
        // can compare against what the client actually uploaded.
        const decoded = try decodeChunkedHttpBody(allocator, raw[body_start..]);
        defer allocator.free(decoded);
        const rewritten = try allocator.alloc(u8, body_start + decoded.len);
        @memcpy(rewritten[0..body_start], raw[0..body_start]);
        @memcpy(rewritten[body_start..], decoded);
        allocator.free(raw);
        raw = rewritten;
    }
    const request_line_end = std.mem.find(u8, raw, "\r\n") orelse return error.InvalidHttpMessage;
    return .{
        .raw = raw,
        .request_line = raw[0..request_line_end],
        .headers_raw = raw[0 .. split_idx + 2],
        .body = raw[body_start..],
    };
}

fn readFastCgiRequest(allocator: std.mem.Allocator, stream: compat.NetStream, max_bytes: usize) !?[]u8 {
    var buf = std.array_list.Managed(u8).init(allocator);
    errdefer buf.deinit();
    var tmp: [4096]u8 = undefined;

    while (true) {
        const read_n = try stream.read(&tmp);
        if (read_n == 0) {
            if (buf.items.len == 0) return null;
            break;
        }
        try buf.appendSlice(tmp[0..read_n]);
        if (buf.items.len > max_bytes) return error.MessageTooLarge;
        if (fastCgiRequestComplete(buf.items)) break;
    }

    if (buf.items.len == 0) return null;
    const owned = try buf.toOwnedSlice();
    return owned;
}

fn readScgiRequest(allocator: std.mem.Allocator, stream: compat.NetStream, max_bytes: usize) ![]u8 {
    var buf = std.array_list.Managed(u8).init(allocator);
    errdefer buf.deinit();
    var tmp: [4096]u8 = undefined;
    while (true) {
        const read_n = try stream.read(&tmp);
        if (read_n == 0) break;
        try buf.appendSlice(tmp[0..read_n]);
        if (buf.items.len > max_bytes) return error.MessageTooLarge;
        if (scgiRequestComplete(buf.items)) break;
    }
    return try buf.toOwnedSlice();
}

fn readUwsgiRequest(allocator: std.mem.Allocator, stream: compat.NetStream, max_bytes: usize) ![]u8 {
    var header: [4]u8 = undefined;
    try stream.reader().readNoEof(&header);
    const vars_len = @as(usize, header[1]) | (@as(usize, header[2]) << 8);
    const vars = try allocator.alloc(u8, vars_len);
    defer allocator.free(vars);
    try stream.reader().readNoEof(vars);
    const content_length = uwsgiContentLength(vars);
    const body = try allocator.alloc(u8, content_length);
    defer allocator.free(body);
    try stream.reader().readNoEof(body);

    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    try out.appendSlice(&header);
    try out.appendSlice(vars);
    try out.appendSlice(body);
    if (out.items.len > max_bytes) return error.MessageTooLarge;
    return try out.toOwnedSlice();
}

fn uwsgiContentLength(vars: []const u8) usize {
    var i: usize = 0;
    while (i + 4 <= vars.len) {
        const key_len = @as(usize, vars[i]) | (@as(usize, vars[i + 1]) << 8);
        const value_len = @as(usize, vars[i + 2]) | (@as(usize, vars[i + 3]) << 8);
        const key_start = i + 4;
        const key_end = key_start + key_len;
        const value_end = key_end + value_len;
        if (value_end > vars.len) break;
        const key = vars[key_start..key_end];
        const value = vars[key_end..value_end];
        if (std.mem.eql(u8, key, "CONTENT_LENGTH")) {
            return std.fmt.parseInt(usize, value, 10) catch 0;
        }
        i = value_end;
    }
    return 0;
}

fn scgiRequestComplete(data: []const u8) bool {
    const colon = std.mem.findScalar(u8, data, ':') orelse return false;
    const net_len = std.fmt.parseInt(usize, data[0..colon], 10) catch return false;
    const headers_end = colon + 1 + net_len;
    if (headers_end >= data.len or data[headers_end] != ',') return false;
    const header_blob = data[colon + 1 .. headers_end];
    const content_length = scgiContentLength(header_blob);
    return data.len >= headers_end + 1 + content_length;
}

fn scgiContentLength(header_blob: []const u8) usize {
    var i: usize = 0;
    while (i < header_blob.len) {
        const key_end_rel = std.mem.findScalarPos(u8, header_blob, i, 0) orelse break;
        const key = header_blob[i..key_end_rel];
        const value_start = key_end_rel + 1;
        const value_end_rel = std.mem.findScalarPos(u8, header_blob, value_start, 0) orelse break;
        const value = header_blob[value_start..value_end_rel];
        if (std.mem.eql(u8, key, "CONTENT_LENGTH")) {
            return std.fmt.parseInt(usize, value, 10) catch 0;
        }
        i = value_end_rel + 1;
    }
    return 0;
}

fn fastCgiRequestComplete(data: []const u8) bool {
    var pos: usize = 0;
    while (pos + 8 <= data.len) {
        if (data[pos] != 1) return false;
        const record_type = data[pos + 1];
        const content_len = std.mem.readInt(u16, data[pos + 4 ..][0..2], .big);
        const padding_len = data[pos + 6];
        const record_len = 8 + content_len + padding_len;
        if (record_len > data.len - pos) return false;
        if (record_type == 5 and content_len == 0) return true;
        pos += record_len;
    }
    return false;
}

fn fastCgiRequestId(data: []const u8) ?u16 {
    if (data.len < 4 or data[0] != 1) return null;
    return std.mem.readInt(u16, data[2..4], .big);
}

fn buildFastCgiStdoutPayload(allocator: std.mem.Allocator, spec: FastCgiResponseSpec) ![]u8 {
    var payload = std.array_list.Managed(u8).init(allocator);
    errdefer payload.deinit();
    try payload.print("Status: {d} {s}\r\n", .{ spec.status_code, httpReason(spec.status_code) });
    for (spec.headers) |header| {
        try payload.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    try payload.appendSlice("\r\n");
    try payload.appendSlice(spec.body);
    return payload.toOwnedSlice();
}

fn writeFastCgiRecord(writer: anytype, record_type: u8, request_id: u16, payload: []const u8) !void {
    try writer.writeByte(1);
    try writer.writeByte(record_type);
    try writer.writeByte(@intCast((request_id >> 8) & 0xff));
    try writer.writeByte(@intCast(request_id & 0xff));
    try writer.writeByte(@intCast((payload.len >> 8) & 0xff));
    try writer.writeByte(@intCast(payload.len & 0xff));
    try writer.writeByte(0);
    try writer.writeByte(0);
    try writer.writeAll(payload);
}

fn writeFastCgiEndRequest(writer: anytype, request_id: u16, app_status: u32, protocol_status: u8) !void {
    var body: [8]u8 = .{ 0, 0, 0, 0, protocol_status, 0, 0, 0 };
    std.mem.writeInt(u32, body[0..4], app_status, .big);
    try writeFastCgiRecord(writer, 3, request_id, &body);
}

fn httpReason(status_code: u16) []const u8 {
    return switch (status_code) {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        else => "OK",
    };
}

fn parseContentLength(headers_raw: []const u8) usize {
    const value = headerValue(headers_raw, "Content-Length") orelse return 0;
    return std.fmt.parseInt(usize, value, 10) catch 0;
}

fn headerValue(headers_raw: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, headers_raw, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const sep = std.mem.findScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..sep], " \t");
        if (!std.ascii.eqlIgnoreCase(key, name)) continue;
        return std.mem.trim(u8, line[sep + 1 ..], " \t");
    }
    return null;
}

fn headerHasToken(headers_raw: []const u8, name: []const u8, token: []const u8) bool {
    const value = headerValue(headers_raw, name) orelse return false;
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " \t"), token)) return true;
    }
    return false;
}

fn countHeaderOccurrences(headers_raw: []const u8, name: []const u8) usize {
    var count: usize = 0;
    var lines = std.mem.splitSequence(u8, headers_raw, "\r\n");
    _ = lines.next(); // skip the status line
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const sep = std.mem.findScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..sep], " \t"), name)) count += 1;
    }
    return count;
}

fn cookiePairFromSetCookie(set_cookie: []const u8) []const u8 {
    const end = std.mem.findScalar(u8, set_cookie, ';') orelse set_cookie.len;
    return std.mem.trim(u8, set_cookie[0..end], " \t\r\n");
}

fn sendRequest(allocator: std.mem.Allocator, port: u16, spec: RequestSpec) !HttpResponse {
    var stream = try openRequestStream(allocator, port, spec);
    defer stream.close();
    return readHttpResponse(allocator, stream);
}

fn sendRequestWithTimeout(allocator: std.mem.Allocator, port: u16, spec: RequestSpec, timeout_ms: u64) !HttpResponse {
    var stream = try openRequestStream(allocator, port, spec);
    defer stream.close();
    try setStreamTimeouts(&stream, timeout_ms);
    return readHttpResponse(allocator, stream);
}

fn sendRawRequest(allocator: std.mem.Allocator, port: u16, raw_request: []const u8) !HttpResponse {
    var stream = try compat.tcpConnectToHost(allocator, test_host, port);
    defer stream.close();
    try setStreamTimeouts(&stream, 5_000);
    try stream.writeAll(raw_request);
    return readHttpResponse(allocator, stream);
}

fn openRequestStream(allocator: std.mem.Allocator, port: u16, spec: RequestSpec) !compat.NetStream {
    var stream = try compat.tcpConnectToHost(allocator, test_host, port);
    errdefer stream.close();

    var request = std.array_list.Managed(u8).init(allocator);
    defer request.deinit();
    const body = spec.body orelse "";
    var host_value: []const u8 = undefined;
    var owned_host_value: ?[]u8 = null;
    host_value = blk: {
        for (spec.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "Host")) break :blk header.value;
        }
        const generated = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ test_host, port });
        owned_host_value = generated;
        break :blk generated;
    };
    if (spec.proxy_ip) |proxy_ip| {
        try request.print("PROXY TCP4 {s} 127.0.0.1 12345 {d}\r\n", .{ proxy_ip, port });
    }
    defer if (owned_host_value) |generated| allocator.free(generated);
    try request.print("{s} {s} HTTP/1.1\r\nHost: {s}\r\nConnection: {s}\r\n", .{
        spec.method,
        spec.path,
        host_value,
        if (spec.connection_close) "close" else "keep-alive",
    });
    for (spec.headers) |header| {
        try request.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    if (spec.body != null) {
        try request.print("Content-Length: {d}\r\n", .{body.len});
    }
    try request.appendSlice("\r\n");
    if (spec.body != null) try request.appendSlice(body);

    try stream.writeAll(request.items);
    return stream;
}

fn setStreamTimeouts(stream: *compat.NetStream, timeout_ms: u64) !void {
    const timeout = std.posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    try std.posix.setsockopt(
        stream.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDTIMEO,
        &std.mem.toBytes(timeout),
    );
    try std.posix.setsockopt(
        stream.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVTIMEO,
        &std.mem.toBytes(timeout),
    );
}

fn readHttpResponse(allocator: std.mem.Allocator, stream: compat.NetStream) !HttpResponse {
    var raw_buf = std.array_list.Managed(u8).init(allocator);
    errdefer raw_buf.deinit();
    var tmp: [4096]u8 = undefined;
    var header_end: ?usize = null;
    var target_len: ?usize = null;

    while (true) {
        if (target_len) |needed| {
            if (raw_buf.items.len >= needed) break;
        }
        const n = readSocketWithPoll(stream.handle, &tmp, 5_000) catch |err| switch (err) {
            error.ConnectionResetByPeer => {
                if (raw_buf.items.len > 0) break;
                return err;
            },
            else => return err,
        };
        if (n == 0) break;
        try raw_buf.appendSlice(tmp[0..n]);

        if (header_end == null) {
            if (std.mem.find(u8, raw_buf.items, "\r\n\r\n")) |idx| {
                header_end = idx;
                const headers_raw = raw_buf.items[0 .. idx + 2];
                if (headerValue(headers_raw, "Content-Length")) |content_length_raw| {
                    const content_length = std.fmt.parseInt(usize, content_length_raw, 10) catch return error.InvalidHttpResponse;
                    target_len = idx + 4 + content_length;
                }
            }
        }
    }

    if (target_len) |needed| {
        if (raw_buf.items.len > needed) {
            raw_buf.shrinkRetainingCapacity(needed);
        }
    }

    var raw = try raw_buf.toOwnedSlice();
    errdefer allocator.free(raw);
    const final_header_end = header_end orelse std.mem.find(u8, raw, "\r\n\r\n") orelse return error.InvalidHttpResponse;
    const headers_raw = raw[0 .. final_header_end + 2];
    const body_start = final_header_end + 4;
    if (headerValue(headers_raw, "Transfer-Encoding")) |te| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, te, " \t\r\n"), "chunked")) {
            const decoded = try decodeChunkedHttpBody(allocator, raw[body_start..]);
            defer allocator.free(decoded);
            const rewritten = try allocator.alloc(u8, body_start + decoded.len);
            @memcpy(rewritten[0..body_start], raw[0..body_start]);
            @memcpy(rewritten[body_start..], decoded);
            allocator.free(raw);
            raw = rewritten;
        }
    }
    const rewritten_header_end = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.InvalidHttpResponse;
    const status_end = std.mem.find(u8, raw, "\r\n") orelse return error.InvalidHttpResponse;
    const status_line = raw[0..status_end];
    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next() orelse return error.InvalidHttpResponse;
    const status_text = parts.next() orelse return error.InvalidHttpResponse;
    const status_code = try std.fmt.parseInt(u16, status_text, 10);
    return .{
        .allocator = allocator,
        .raw = raw,
        .status_code = status_code,
        .headers_raw = raw[0 .. rewritten_header_end + 2],
        .body = raw[rewritten_header_end + 4 ..],
    };
}

fn decodeChunkedHttpBody(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    var pos: usize = 0;
    while (true) {
        const line_end_rel = std.mem.find(u8, data[pos..], "\r\n") orelse return error.InvalidHttpResponse;
        const line = data[pos .. pos + line_end_rel];
        const semi = std.mem.findScalar(u8, line, ';');
        const hex = std.mem.trim(u8, if (semi) |idx| line[0..idx] else line, " \t");
        const chunk_len = std.fmt.parseInt(usize, hex, 16) catch return error.InvalidHttpResponse;
        pos += line_end_rel + 2;
        if (chunk_len == 0) break;
        if (pos + chunk_len + 2 > data.len) return error.InvalidHttpResponse;
        try out.appendSlice(data[pos .. pos + chunk_len]);
        pos += chunk_len;
        if (data[pos] != '\r' or data[pos + 1] != '\n') return error.InvalidHttpResponse;
        pos += 2;
    }
    return out.toOwnedSlice();
}

fn readHttpHeadersOnly(allocator: std.mem.Allocator, stream: compat.NetStream) ![]u8 {
    var raw_buf = std.array_list.Managed(u8).init(allocator);
    errdefer raw_buf.deinit();
    var tmp: [1024]u8 = undefined;

    while (true) {
        const n = try stream.read(&tmp);
        if (n == 0) return error.InvalidHttpResponse;
        try raw_buf.appendSlice(tmp[0..n]);
        if (std.mem.find(u8, raw_buf.items, "\r\n\r\n") != null) break;
    }
    return raw_buf.toOwnedSlice();
}

fn writeMaskedWebSocketFrame(writer: anytype, opcode: WebSocketOpCode, payload: []const u8, fin: bool) !void {
    var first: u8 = @intFromEnum(opcode);
    if (fin) first |= 0x80;
    try writer.writeByte(first);

    const mask_key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    if (payload.len < 126) {
        try writer.writeByte(0x80 | @as(u8, @intCast(payload.len)));
    } else if (payload.len <= std.math.maxInt(u16)) {
        try writer.writeByte(0x80 | 126);
        var ext: [2]u8 = undefined;
        std.mem.writeInt(u16, ext[0..2], @intCast(payload.len), .big);
        try writer.writeAll(ext[0..]);
    } else {
        try writer.writeByte(0x80 | 127);
        var ext: [8]u8 = undefined;
        std.mem.writeInt(u64, ext[0..8], payload.len, .big);
        try writer.writeAll(ext[0..]);
    }
    try writer.writeAll(mask_key[0..]);
    for (payload, 0..) |byte, i| {
        try writer.writeByte(byte ^ mask_key[i % mask_key.len]);
    }
}

fn readWebSocketFrame(stream: compat.NetStream, allocator: std.mem.Allocator, max_payload: usize) !WebSocketFrame {
    var hdr: [2]u8 = undefined;
    try readExact(stream, hdr[0..]);
    const fin = (hdr[0] & 0x80) != 0;
    const opcode: WebSocketOpCode = @enumFromInt(@as(u4, @truncate(hdr[0])));
    const masked = (hdr[1] & 0x80) != 0;
    var len: usize = hdr[1] & 0x7F;

    if (len == 126) {
        var ext: [2]u8 = undefined;
        try readExact(stream, ext[0..]);
        len = std.mem.readInt(u16, ext[0..2], .big);
    } else if (len == 127) {
        var ext: [8]u8 = undefined;
        try readExact(stream, ext[0..]);
        len = @intCast(std.mem.readInt(u64, ext[0..8], .big));
    }
    if (len > max_payload) return error.FrameTooLarge;

    var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) try readExact(stream, mask_key[0..]);

    const payload = try allocator.alloc(u8, len);
    errdefer allocator.free(payload);
    try readExact(stream, payload);
    if (masked) {
        for (payload, 0..) |*byte, i| byte.* ^= mask_key[i % mask_key.len];
    }
    return .{ .fin = fin, .opcode = opcode, .payload = payload };
}

fn readExact(stream: compat.NetStream, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = try stream.read(out[off..]);
        if (n == 0) return error.ConnectionClosed;
        off += n;
    }
}

fn waitUntilReady(port: u16, log_path: []const u8, options: TardigradeOptions) !void {
    const ready_path = switch (options.profile) {
        .bearclaw => if (std.mem.eql(u8, options.ready_path, "/")) "/health" else options.ready_path,
        else => options.ready_path,
    };
    const ready_over_https = options.ready_https_insecure or options.profile == .bearclaw;

    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        if (ready_over_https) {
            var resp = (if (!build_options.tls_openssl_adapter and options.ready_client_cert == null and options.ready_client_key == null)
                sendPureZigTlsHttp1Request(std.testing.allocator, port, ready_path)
            else
                sendCurlRequest(std.testing.allocator, port, .{
                    .scheme = "https",
                    .path = ready_path,
                    .insecure = true,
                    .cert = options.ready_client_cert,
                    .key = options.ready_client_key,
                })) catch |err| {
                if (attempts == 99) {
                    const log_data = compat.cwd().readFileAlloc(std.testing.allocator, log_path, 256 * 1024) catch "";
                    defer if (log_data.len > 0) std.testing.allocator.free(log_data);
                    std.debug.print("tardigrade failed to boot: {}\n{s}\n", .{ err, log_data });
                    return err;
                }
                compat.sleepNs(50 * std.time.ns_per_ms);
                continue;
            };
            defer resp.deinit();
            if (options.ready_status_code) |expected| {
                if (resp.status_code == expected) return;
            } else {
                return;
            }
        } else {
            var resp = sendRequest(std.testing.allocator, port, .{
                .method = "GET",
                .path = ready_path,
                .body = null,
                .headers = &.{},
                .proxy_ip = options.ready_proxy_ip,
            }) catch |err| {
                if (attempts == 99) {
                    const log_data = compat.cwd().readFileAlloc(std.testing.allocator, log_path, 256 * 1024) catch "";
                    defer if (log_data.len > 0) std.testing.allocator.free(log_data);
                    std.debug.print("tardigrade failed to boot: {}\n{s}\n", .{ err, log_data });
                    return err;
                }
                compat.sleepNs(50 * std.time.ns_per_ms);
                continue;
            };
            defer resp.deinit();
            if (options.ready_status_code) |expected| {
                if (resp.status_code == expected) return;
            } else {
                return;
            }
        }
        compat.sleepNs(50 * std.time.ns_per_ms);
    }
    return error.ServerNotReady;
}

const CurlRequestSpec = struct {
    method: []const u8 = "GET",
    scheme: []const u8 = "https",
    path: []const u8,
    body: ?[]const u8 = null,
    headers: []const RequestHeader = &.{},
    insecure: bool = false,
    cert: ?[]const u8 = null,
    key: ?[]const u8 = null,
    binary_path: ?[]const u8 = null,
    http3_only: bool = false,
    ssl_sessions_path: ?[]const u8 = null,
    tls_earlydata: bool = false,
    /// Cap the client's maximum TLS version (curl `--tls-max`), e.g. "1.1" to
    /// verify the server rejects a below-minimum handshake.
    tls_max: ?[]const u8 = null,
    /// Trust only this CA certificate (curl `--cacert`) instead of the
    /// system trust store, and perform real chain/hostname verification
    /// (implies not `insecure`). Used to prove an out-of-process client can
    /// actually validate the appliance-transmitted chain (#392).
    cacert: ?[]const u8 = null,
};

fn runCurl(allocator: std.mem.Allocator, port: u16, spec: CurlRequestSpec) !CurlRunResult {
    var argv = std.array_list.Managed([]const u8).init(allocator);
    defer argv.deinit();
    var owned_args = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (owned_args.items) |arg| allocator.free(arg);
        owned_args.deinit();
    }
    try argv.append(spec.binary_path orelse "curl");
    try argv.append("-sS");
    if (spec.http3_only) {
        try argv.append("--http3-only");
    } else {
        try argv.append("--http1.1");
    }
    try argv.append("--connect-timeout");
    try argv.append(if (spec.http3_only) "5" else "2");
    try argv.append("--max-time");
    try argv.append(if (spec.http3_only) "8" else "5");
    try argv.append("-X");
    try argv.append(spec.method);
    try argv.append("-D");
    try argv.append("-");
    if (spec.insecure) try argv.append("-k");
    if (spec.cacert) |cacert| {
        try argv.append("--cacert");
        try argv.append(cacert);
    }
    for (spec.headers) |header| {
        const line = try std.fmt.allocPrint(allocator, "{s}: {s}", .{ header.name, header.value });
        try owned_args.append(line);
        try argv.append("-H");
        try argv.append(line);
    }
    if (spec.body) |body| {
        try argv.append("--data");
        try argv.append(body);
    }
    if (spec.cert) |cert| {
        try argv.append("--cert");
        try argv.append(cert);
    }
    if (spec.key) |key| {
        try argv.append("--key");
        try argv.append(key);
    }
    if (spec.ssl_sessions_path) |path| {
        try argv.append("--ssl-sessions");
        try argv.append(path);
    }
    if (spec.tls_earlydata) {
        try argv.append("--tls-earlydata");
    }
    if (spec.tls_max) |v| {
        try argv.append("--tls-max");
        try argv.append(v);
    }
    const url = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ spec.scheme, test_host, port, spec.path });
    defer allocator.free(url);
    try argv.append(url);

    const run_res = try std.process.run(allocator, compat.io(), .{
        .argv = argv.items,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    return .{
        .allocator = allocator,
        .stdout = run_res.stdout,
        .stderr = run_res.stderr,
        .term = run_res.term,
    };
}

fn spawnCurlProcess(allocator: std.mem.Allocator, port: u16, spec: CurlRequestSpec) !std.process.Child {
    var argv = std.array_list.Managed([]const u8).init(allocator);
    defer argv.deinit();
    var owned_args = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (owned_args.items) |arg| allocator.free(arg);
        owned_args.deinit();
    }

    try argv.append(spec.binary_path orelse "curl");
    try argv.append("-sS");
    if (spec.http3_only) {
        try argv.append("--http3-only");
    } else {
        try argv.append("--http1.1");
    }
    try argv.append("--connect-timeout");
    try argv.append(if (spec.http3_only) "5" else "2");
    try argv.append("--max-time");
    try argv.append(if (spec.http3_only) "8" else "5");
    try argv.append("-X");
    try argv.append(spec.method);
    try argv.append("-D");
    try argv.append("-");
    if (spec.insecure) try argv.append("-k");
    for (spec.headers) |header| {
        const line = try std.fmt.allocPrint(allocator, "{s}: {s}", .{ header.name, header.value });
        try owned_args.append(line);
        try argv.append("-H");
        try argv.append(line);
    }
    if (spec.body) |body| {
        try argv.append("--data");
        try argv.append(body);
    }
    if (spec.cert) |cert| {
        try argv.append("--cert");
        try argv.append(cert);
    }
    if (spec.key) |key| {
        try argv.append("--key");
        try argv.append(key);
    }
    if (spec.ssl_sessions_path) |path| {
        try argv.append("--ssl-sessions");
        try argv.append(path);
    }
    if (spec.tls_earlydata) {
        try argv.append("--tls-earlydata");
    }
    const url = try std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ spec.scheme, test_host, port, spec.path });
    try owned_args.append(url);
    try argv.append(url);

    return std.process.spawn(compat.io(), .{
        .argv = argv.items,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
}

fn sendCurlRequest(allocator: std.mem.Allocator, port: u16, spec: CurlRequestSpec) !HttpResponse {
    var result = try runCurl(allocator, port, spec);
    errdefer result.deinit();
    switch (result.term) {
        .exited => |code| if (code != 0) return error.CurlFailed,
        else => return error.CurlFailed,
    }

    allocator.free(result.stderr);
    return .{
        .allocator = allocator,
        .raw = result.stdout,
        .status_code = try parseStatusCode(result.stdout),
        .headers_raw = result.stdout[0 .. (std.mem.find(u8, result.stdout, "\r\n\r\n") orelse return error.InvalidHttpResponse) + 2],
        .body = result.stdout[(std.mem.find(u8, result.stdout, "\r\n\r\n") orelse return error.InvalidHttpResponse) + 4 ..],
    };
}

fn sendPureZigTlsHttp1Request(allocator: std.mem.Allocator, port: u16, path: []const u8) !HttpResponse {
    const client = try PureZigTlsClient.create(allocator, port, "http/1.1");
    defer client.destroy();

    var request = std.array_list.Managed(u8).init(allocator);
    defer request.deinit();
    try request.print(
        "GET {s} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        .{path},
    );
    try client.writeAllPlain(request.items);

    const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    errdefer allocator.free(raw);
    return httpResponseFromOwnedRaw(allocator, raw);
}

fn httpResponseFromOwnedRaw(allocator: std.mem.Allocator, raw: []u8) !HttpResponse {
    const start = std.mem.find(u8, raw, "HTTP/1.") orelse return error.InvalidHttpResponse;
    if (start != 0) return error.InvalidHttpResponse;
    const header_end = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.InvalidHttpResponse;
    const status_code = try parseStatusCode(raw);
    return .{
        .allocator = allocator,
        .raw = raw,
        .status_code = status_code,
        .headers_raw = raw[0 .. header_end + 2],
        .body = raw[header_end + 4 ..],
    };
}

fn sendHttp3CurlRequestWithSpec(allocator: std.mem.Allocator, port: u16, spec: CurlRequestSpec) !HttpResponse {
    var last_err: ?anyerror = null;
    for (0..http3_retry_attempts) |_| {
        return sendCurlRequest(allocator, port, spec) catch |err| {
            last_err = err;
            compat.sleepNs(http3_retry_delay_ms * std.time.ns_per_ms);
            continue;
        };
    }
    return last_err orelse error.CurlFailed;
}

fn sendHttp3CurlRequest(allocator: std.mem.Allocator, port: u16, path: []const u8) !HttpResponse {
    return sendHttp3CurlRequestWithSpec(allocator, port, .{
        .scheme = "https",
        .path = path,
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
}

fn opensslPresentedSubject(allocator: std.mem.Allocator, port: u16, servername: []const u8) ![]u8 {
    const cmd = try std.fmt.allocPrint(
        allocator,
        // `-nameopt compat`: forces the stable, space-free "CN=value" subject
        // rendering across OpenSSL versions/distros, rather than whatever
        // the locally-linked OpenSSL's default `-nameopt` (which varies
        // between "CN=value" and "CN = value") happens to produce.
        "openssl s_client -connect {s}:{d} -servername {s} -alpn http/1.1 -showcerts </dev/null 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | openssl x509 -noout -subject -nameopt compat",
        .{ test_host, port, servername },
    );
    defer allocator.free(cmd);

    const run_res = try std.process.run(std.heap.page_allocator, compat.io(), .{
        .argv = &.{ "sh", "-lc", cmd },
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    defer std.heap.page_allocator.free(run_res.stderr);

    switch (run_res.term) {
        .exited => |code| if (code != 0) {
            std.heap.page_allocator.free(run_res.stdout);
            return error.OpensslFailed;
        },
        else => {
            std.heap.page_allocator.free(run_res.stdout);
            return error.OpensslFailed;
        },
    }
    defer std.heap.page_allocator.free(run_res.stdout);
    return allocator.dupe(u8, run_res.stdout);
}

fn parseStatusCode(raw: []const u8) !u16 {
    const status_end = std.mem.find(u8, raw, "\r\n") orelse return error.InvalidHttpResponse;
    const status_line = raw[0..status_end];
    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next() orelse return error.InvalidHttpResponse;
    const status_text = parts.next() orelse return error.InvalidHttpResponse;
    return std.fmt.parseInt(u16, status_text, 10);
}

fn waitForUpstreamCount(server: *UpstreamServer, expected: u32, timeout_ms: u64) !void {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        if (server.requestCount() >= expected) return;
        compat.sleepNs(25 * std.time.ns_per_ms);
    }
    return error.Timeout;
}

fn waitForChildExit(pid: std.posix.pid_t, timeout_ms: u64) bool {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        const result = std.posix.waitpid(pid, std.posix.W.NOHANG);
        if (result.pid == pid) return true;
        compat.sleepNs(25 * std.time.ns_per_ms);
    }
    return false;
}

fn waitForPortClosed(port: u16, timeout_ms: u64) !void {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        var stream = compat.tcpConnectToHost(std.testing.allocator, test_host, port) catch return;
        stream.close();
        compat.sleepNs(25 * std.time.ns_per_ms);
    }
    return error.Timeout;
}

fn waitForLogSubstring(allocator: std.mem.Allocator, path: []const u8, needle: []const u8, timeout_ms: u64) !void {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        const contents = blk: {
            if (std.Io.Dir.path.isAbsolute(path)) {
                var file = try compat.openFileAbsolute(path, .{});
                defer file.close();
                break :blk try file.readToEndAlloc(allocator, 256 * 1024);
            }
            break :blk try compat.cwd().readFileAlloc(allocator, path, 256 * 1024);
        };
        defer allocator.free(contents);
        if (std.mem.find(u8, contents, needle) != null) return;
        compat.sleepNs(25 * std.time.ns_per_ms);
    }
    return error.Timeout;
}

fn wakeListener(port: u16) void {
    var stream = compat.tcpConnectToHost(std.testing.allocator, test_host, port) catch return;
    defer stream.close();
    stream.writeAll("GET /__shutdown__ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") catch {};
}

fn wakeUnixListener(path: []const u8) void {
    var stream = compat.connectUnixSocket(path) catch return;
    defer stream.close();
    stream.writeAll("GET /__shutdown__ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n") catch {};
}

/// Wait until something accepts on `port`, for external origins (an `openssl
/// s_server` subprocess) that have no readiness handshake of their own.
fn waitForTcpPort(port: u16, timeout_ms: u64) !void {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        if (compat.tcpConnectToHost(std.testing.allocator, test_host, port)) |connected| {
            var stream = connected;
            stream.close();
            return;
        } else |_| {
            compat.sleepNs(25 * std.time.ns_per_ms);
        }
    }
    return error.OriginNotReady;
}

fn findFreePort() !u16 {
    var server = try compat.listenTcp(test_host, 0);
    defer server.deinit();
    return server.port();
}

const NativeTlsFixturePaths = struct {
    allocator: std.mem.Allocator,
    cert_path: []u8,
    key_path: []u8,

    fn deinit(self: *NativeTlsFixturePaths) void {
        self.allocator.free(self.cert_path);
        self.allocator.free(self.key_path);
        self.* = undefined;
    }
};

fn nativeTlsFixturePaths(allocator: std.mem.Allocator) !NativeTlsFixturePaths {
    const cwd = try compat.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    const cert_path = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/native_ed25519.crt", .{cwd});
    errdefer allocator.free(cert_path);
    const key_path = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/native_ed25519.key", .{cwd});
    return .{
        .allocator = allocator,
        .cert_path = cert_path,
        .key_path = key_path,
    };
}

fn listenerTlsFixturePaths(allocator: std.mem.Allocator) !NativeTlsFixturePaths {
    if (!build_options.tls_openssl_adapter) return nativeTlsFixturePaths(allocator);
    const cwd = try compat.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    const cert_path = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/server.crt", .{cwd});
    errdefer allocator.free(cert_path);
    const key_path = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/server.key", .{cwd});
    return .{
        .allocator = allocator,
        .cert_path = cert_path,
        .key_path = key_path,
    };
}

fn requireNativeTlsProfile() !void {
    if (build_options.tls_openssl_adapter) return error.SkipZigTest;
}

/// #522: the appliance TLS profile explicitly forbids
/// `TARDIGRADE_HTTP3_ENABLE_0RTT` (`edge_config.zig`'s
/// `validateApplianceTlsProfile` rejects it outright as an unsupported
/// appliance configuration), and QUIC's `NativeCredentialStore` credential
/// provider is itself only constructed `if (build_options.tls_openssl_
/// adapter and cfg.http3_enabled ...)` in `edge_gateway.zig` -- native QUIC
/// never links OpenSSL identity objects, but production 0-RTT composition
/// for HTTP/3 is currently reachable only under the `.general` profile (the
/// default `zig build`, no `-Dtls-profile` needed), the mirror image of
/// `requireNativeTlsProfile` above. This is itself part of #522's finding,
/// not a workaround: see the QUIC transport-parameter reachability note on
/// `h3interop.quic.early.*` below.
fn requireGeneralTlsProfile() !void {
    if (!build_options.tls_openssl_adapter) return error.SkipZigTest;
}

/// #369: skip external OpenSSL interop cases when the local toolchain has no
/// `openssl` binary rather than failing -- CI always installs it (see
/// ci.yml), but a stripped-down dev environment should not fail the suite
/// over an optional external peer.
fn requireOpenssl(allocator: std.mem.Allocator) !void {
    var result = try bounded_process.run(allocator, .{
        .argv = &.{ "openssl", "version" },
        .stdout_limit = 4096,
        .stderr_limit = 4096,
        .deadline_ms = 5_000,
    });
    defer result.deinit(allocator);
    if (result.outcome != .normal_exit) return error.SkipZigTest;
}

/// #369: skip cases that generate a throwaway Ed25519 identity at test time
/// when the local `openssl` can't do Ed25519 at all -- macOS's system
/// `openssl` (what GitHub's macos-14 runner resolves to, with no Homebrew
/// OpenSSL preinstalled/linked) is LibreSSL, whose `genpkey` rejects
/// `ed25519` outright ("Algorithm ed25519 not found") and can't even load
/// an externally-supplied Ed25519 key to sign with, let alone generate one.
/// The appliance TLS profile these tests build under requires Ed25519 leaf
/// certificates specifically (`appliance_credentials.zig` hard-rejects any
/// other `key_type`), so there is no alternative algorithm to substitute
/// here the way `generateAlternateServerCert`'s cert itself can use P-256.
fn requireOpensslEd25519(allocator: std.mem.Allocator) !void {
    const dir = try interopSecretsDir(allocator);
    defer allocator.free(dir);
    const probe_path = try std.fmt.allocPrint(allocator, "{s}/ed25519-support-probe-{d}.pem", .{ dir, compat.milliTimestamp() });
    defer allocator.free(probe_path);
    defer compat.cwd().deleteFile(probe_path) catch {};

    var result = try bounded_process.run(allocator, .{
        .argv = &.{ "openssl", "genpkey", "-algorithm", "ed25519", "-out", probe_path },
        .stdout_limit = 4096,
        .stderr_limit = 4096,
        .deadline_ms = 5_000,
    });
    defer result.deinit(allocator);
    if (std.meta.activeTag(result.outcome) != .normal_exit or result.outcome.normal_exit != 0) {
        return error.SkipZigTest;
    }
}

/// #369: drives a real `openssl` subprocess against the native TLS listener.
/// Every call is bounded end to end (spawn, stdin write, read, wait) via
/// `bounded_process`, so a regression here fails with a useful diagnostic
/// instead of hanging CI.
fn runOpenssl(allocator: std.mem.Allocator, args: []const []const u8, stdin_data: ?[]const u8, deadline_ms: u32) !bounded_process.Result {
    var argv = try allocator.alloc([]const u8, args.len + 1);
    defer allocator.free(argv);
    argv[0] = "openssl";
    @memcpy(argv[1..], args);
    return bounded_process.run(allocator, .{
        .argv = argv,
        .stdin = stdin_data,
        // A post-handshake NewSessionTicket is sent asynchronously, after
        // the application response `stdin_data` already elicited. Closing
        // stdin (and therefore signaling `openssl s_client` to shut down)
        // the instant the write returns races that ticket into arriving
        // too late for `-sess_out` to capture it; this bounded pause (not a
        // blind test-level sleep) gives it a chance to land first.
        .stdin_close_delay_ms = if (stdin_data != null) 1_000 else 0,
        .stdout_limit = 256 * 1024,
        .stderr_limit = 256 * 1024,
        .deadline_ms = deadline_ms,
        .accepted_exit_codes = &.{ 0, 1 },
    });
}

fn opensslConnectArg(allocator: std.mem.Allocator, port: u16) ![]u8 {
    return std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{port});
}

/// #369: a resumable OpenSSL session file contains the session master
/// key/PSK (OpenSSL's own `SSL_SESSION`/`sess_id` documentation calls this
/// out explicitly), and a generated alternate credential's private key is
/// obviously secret too. Neither may live under `.zig-cache` -- CI caches
/// that whole tree (`actions/cache` in ci.yml), so a successful job could
/// otherwise leave secret-bearing test artifacts inside a persisted cache
/// blob even though the normal-path `defer deleteFile` cleans them up
/// (cleanup errors are swallowed by design, so it is not a guarantee).
/// Returns a directory outside every cache/artifact path
/// (`$TMPDIR`/`/tmp`, never repo-relative), created with owner-only
/// permissions so a residual file stays inaccessible to other local users
/// even if a specific cleanup step fails.
fn interopSecretsDir(allocator: std.mem.Allocator) ![]u8 {
    const base = compat.getEnvVarOwned(allocator, "TMPDIR") catch try allocator.dupe(u8, "/tmp");
    defer allocator.free(base);
    const trimmed = std.mem.trimEnd(u8, base, "/");
    const path_z = try std.fmt.allocPrintSentinel(allocator, "{s}/tardigrade-tls-interop-secrets", .{trimmed}, 0);
    defer allocator.free(path_z);
    // `std.Io.Dir`'s directory-creation API has no mode parameter; the raw
    // libc call is the only way to request owner-only (0700) permissions.
    const rc = std.c.mkdir(path_z.ptr, 0o700);
    if (rc != 0) {
        switch (std.posix.errno(rc)) {
            .EXIST => {},
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
    return allocator.dupe(u8, path_z);
}

fn opensslSessionPath(allocator: std.mem.Allocator, port: u16, tag: []const u8) ![]u8 {
    const dir = try interopSecretsDir(allocator);
    defer allocator.free(dir);
    return std.fmt.allocPrint(allocator, "{s}/interop-{s}-{d}.sess", .{ dir, tag, port });
}

fn opensslEarlyDataPath(allocator: std.mem.Allocator, port: u16, tag: []const u8) ![]u8 {
    const dir = try interopSecretsDir(allocator);
    defer allocator.free(dir);
    return std.fmt.allocPrint(allocator, "{s}/interop-{s}-{d}.early", .{ dir, tag, port });
}

fn opensslH2GetRequestBytes(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return opensslH2RequestBytes(allocator, "GET", path, "tardigrade.test", "", &.{});
}

fn opensslH2RequestBytes(
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    authority: []const u8,
    body: []const u8,
    extra_headers: []const hpack.HeaderField,
) ![]u8 {
    var request_headers = std.array_list.Managed(hpack.HeaderField).init(allocator);
    defer request_headers.deinit();
    try request_headers.append(.{ .name = ":method", .value = method });
    try request_headers.append(.{ .name = ":path", .value = path });
    try request_headers.append(.{ .name = ":scheme", .value = "https" });
    try request_headers.append(.{ .name = ":authority", .value = authority });
    if (body.len > 0) {
        const len = try std.fmt.allocPrint(allocator, "{d}", .{body.len});
        defer allocator.free(len);
        try request_headers.append(.{ .name = "content-length", .value = len });
        try request_headers.appendSlice(extra_headers);
        return opensslH2RequestBytesFromHeaders(allocator, request_headers.items, body);
    }
    try request_headers.appendSlice(extra_headers);
    return opensslH2RequestBytesFromHeaders(allocator, request_headers.items, body);
}

fn opensslH2RequestBytesFromHeaders(
    allocator: std.mem.Allocator,
    request_headers: []const hpack.HeaderField,
    body: []const u8,
) ![]u8 {
    const request_block = try hpack.encodeLiteralHeaderBlock(allocator, request_headers);
    defer allocator.free(request_block);

    var bytes = std.array_list.Managed(u8).init(allocator);
    errdefer bytes.deinit();
    try bytes.appendSlice("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try appendHttp2Frame(&bytes, 0x4, 0, 0, &.{}); // client SETTINGS
    try appendHttp2Frame(&bytes, 0x4, 0x1, 0, &.{}); // SETTINGS ACK
    const header_flags: u8 = if (body.len == 0) 0x1 | 0x4 else 0x4;
    try appendHttp2Frame(&bytes, 0x1, header_flags, 1, request_block); // HEADERS
    if (body.len > 0) try appendHttp2Frame(&bytes, 0x0, 0x1, 1, body); // DATA END_STREAM
    return bytes.toOwnedSlice();
}

fn pureZigH2GetBody(allocator: std.mem.Allocator, port: u16, headers: []const hpack.HeaderField) ![]u8 {
    const client = try PureZigTlsClient.create(allocator, port, "h2");
    defer client.destroy();

    try client.writeAllPlain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try client.writeHttp2Frame(0x4, 0, 0, &.{}); // client SETTINGS

    const request_block = try hpack.encodeLiteralHeaderBlock(allocator, headers);
    defer allocator.free(request_block);
    try client.writeHttp2Frame(0x1, 0x1 | 0x4, 1, request_block); // END_STREAM | END_HEADERS

    var response_body = std.array_list.Managed(u8).init(allocator);
    errdefer response_body.deinit();

    var frame_count: usize = 0;
    while (frame_count < 12) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);

        switch (frame.typ) {
            0x4 => {
                if ((frame.flags & 0x1) == 0) {
                    try client.writeHttp2Frame(0x4, 0x1, 0, &.{}); // SETTINGS ACK
                }
            },
            0x0 => {
                if (frame.stream_id == 1) {
                    try response_body.appendSlice(frame.payload);
                    if ((frame.flags & 0x1) != 0) return response_body.toOwnedSlice();
                }
            },
            else => {},
        }
    }
    return error.H2ResponseNotFound;
}

fn pureZigH2GetBodyWithWindowUpdates(allocator: std.mem.Allocator, port: u16, headers: []const hpack.HeaderField) ![]u8 {
    const client = try PureZigTlsClient.create(allocator, port, "h2");
    defer client.destroy();

    try client.writeAllPlain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try client.writeHttp2Frame(0x4, 0, 0, &.{}); // client SETTINGS

    const request_block = try hpack.encodeLiteralHeaderBlock(allocator, headers);
    defer allocator.free(request_block);
    try client.writeHttp2Frame(0x1, 0x1 | 0x4, 1, request_block); // END_STREAM | END_HEADERS

    var response_body = std.array_list.Managed(u8).init(allocator);
    errdefer response_body.deinit();

    var frame_count: usize = 0;
    while (frame_count < 64) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);

        switch (frame.typ) {
            0x4 => {
                if ((frame.flags & 0x1) == 0) {
                    try client.writeHttp2Frame(0x4, 0x1, 0, &.{}); // SETTINGS ACK
                }
            },
            0x0 => {
                if (frame.stream_id == 1) {
                    try response_body.appendSlice(frame.payload);
                    if (frame.payload.len > 0) {
                        var inc: [4]u8 = undefined;
                        std.mem.writeInt(u32, inc[0..4], @as(u32, @intCast(frame.payload.len)), .big);
                        try client.writeHttp2Frame(0x8, 0, 0, inc[0..]);
                        try client.writeHttp2Frame(0x8, 0, 1, inc[0..]);
                    }
                    if ((frame.flags & 0x1) != 0) return response_body.toOwnedSlice();
                }
            },
            else => {},
        }
    }
    return error.H2ResponseNotFound;
}

fn pureZigH2PostMultiFrameBody(
    allocator: std.mem.Allocator,
    port: u16,
    headers: []const hpack.HeaderField,
    chunks: []const []const u8,
) ![]u8 {
    const client = try PureZigTlsClient.create(allocator, port, "h2");
    defer client.destroy();

    try client.writeAllPlain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try client.writeHttp2Frame(0x4, 0, 0, &.{}); // client SETTINGS

    const request_block = try hpack.encodeLiteralHeaderBlock(allocator, headers);
    defer allocator.free(request_block);
    try client.writeHttp2Frame(0x1, 0x4, 1, request_block); // END_HEADERS, body follows

    for (chunks, 0..) |chunk, i| {
        const flags: u8 = if (i == chunks.len - 1) 0x1 else 0x0; // END_STREAM on last chunk
        try client.writeHttp2Frame(0x0, flags, 1, chunk);
    }

    var response_body = std.array_list.Managed(u8).init(allocator);
    errdefer response_body.deinit();

    var frame_count: usize = 0;
    while (frame_count < 32) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);

        switch (frame.typ) {
            0x4 => {
                if ((frame.flags & 0x1) == 0) {
                    try client.writeHttp2Frame(0x4, 0x1, 0, &.{}); // SETTINGS ACK
                }
            },
            0x0 => {
                if (frame.stream_id == 1) {
                    try response_body.appendSlice(frame.payload);
                    if ((frame.flags & 0x1) != 0) return response_body.toOwnedSlice();
                }
            },
            else => {},
        }
    }
    return error.H2ResponseNotFound;
}

fn appendHttp2Frame(bytes: *std.array_list.Managed(u8), typ: u8, flags: u8, stream_id: u31, payload: []const u8) !void {
    var header: [9]u8 = undefined;
    header[0] = @intCast((payload.len >> 16) & 0xff);
    header[1] = @intCast((payload.len >> 8) & 0xff);
    header[2] = @intCast(payload.len & 0xff);
    header[3] = typ;
    header[4] = flags;
    std.mem.writeInt(u32, header[5..9], @as(u32, stream_id) & 0x7fff_ffff, .big);
    try bytes.appendSlice(header[0..]);
    try bytes.appendSlice(payload);
}

fn expectOpenSslH2ResponseBody(allocator: std.mem.Allocator, stdout: []const u8, expected_body: []const u8) !void {
    const response_body = try openSslH2ResponseBody(allocator, stdout);
    defer allocator.free(response_body);
    try assertContains(response_body, expected_body);
}

fn expectOpenSslH2ResponseBodyExact(allocator: std.mem.Allocator, stdout: []const u8, expected_body: []const u8) !void {
    const response_body = try openSslH2ResponseBody(allocator, stdout);
    defer allocator.free(response_body);
    try std.testing.expectEqualStrings(expected_body, response_body);
}

fn openSslH2ResponseBody(allocator: std.mem.Allocator, stdout: []const u8) ![]u8 {
    var offset: usize = 0;
    while (offset + 9 <= stdout.len) : (offset += 1) {
        var response_body = std.array_list.Managed(u8).init(allocator);
        errdefer response_body.deinit();
        if (parseOpenSslH2Frames(stdout[offset..], &response_body) catch false) {
            return response_body.toOwnedSlice();
        }
        response_body.deinit();
    }
    return error.H2ResponseNotFound;
}

fn parseOpenSslH2Frames(bytes: []const u8, response_body: *std.array_list.Managed(u8)) !bool {
    var pos: usize = 0;
    var saw_settings = false;
    var saw_response_headers = false;
    var frame_count: usize = 0;
    while (pos + 9 <= bytes.len and frame_count < 12) : (frame_count += 1) {
        const len = (@as(usize, bytes[pos]) << 16) | (@as(usize, bytes[pos + 1]) << 8) | @as(usize, bytes[pos + 2]);
        if (len > 16 * 1024 or pos + 9 + len > bytes.len) return false;
        const typ = bytes[pos + 3];
        const flags = bytes[pos + 4];
        const stream_id = std.mem.readInt(u32, bytes[pos + 5 ..][0..4], .big) & 0x7fff_ffff;
        const payload = bytes[pos + 9 .. pos + 9 + len];
        pos += 9 + len;

        switch (typ) {
            0x4 => {
                if (stream_id != 0) return false;
                if ((flags & 0x1) == 0) saw_settings = true;
            },
            0x1 => {
                if (stream_id == 1) saw_response_headers = true;
            },
            0x0 => {
                if (stream_id == 1) {
                    try response_body.appendSlice(payload);
                    if ((flags & 0x1) != 0) return saw_settings and saw_response_headers;
                }
            },
            else => {},
        }
    }
    return false;
}

fn writeInteropSecretFile(path: []const u8, data: []const u8) !void {
    var file = try compat.cwd().createFile(path, .{
        .truncate = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close();
    try file.writeAll(data);
    try file.flush();
}

fn expectMetricAtLeast(body: []const u8, name: []const u8, labels: []const []const u8, expected: u64) !void {
    try std.testing.expect((prometheusLabeledMetricValue(body, name, labels) orelse 0) >= expected);
}

const openssl_health_request = "GET /healthz HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n";

// ===========================================================================
// #522: external ngtcp2/GnuTLS QUIC/H3 interop.
//
// Unlike `scripts/interop/run-interop.sh` + `tests/h3_interop_tool.zig`
// (the direct `Tls13Backend -> quic.Connection -> H3.Conn` harness for the
// #328 baseline wire-interop matrix), these cases drive the real production
// composition: an external, independently-built ngtcp2/GnuTLS client against
// the actual Tardigrade edge-gateway binary with `TARDIGRADE_HTTP3_ENABLED`,
// exercising the shared native resumption runtime, the process-local replay
// gate, and the shared HTTP early-data safety/routing policy end to end --
// the same production seams the `interop.openssl.h1.*` cases below exercise
// for TCP/H1, over real QUIC 0-RTT packets instead of TLS record early data.
// ===========================================================================

fn findFreeUdpPort() !u16 {
    const fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    if (fd < 0) return error.SocketFailed;
    defer _ = std.c.close(fd);
    const bind_addr = std.c.sockaddr.in{ .family = std.posix.AF.INET, .port = 0, .addr = 0 };
    if (std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(std.c.sockaddr.in)) != 0) return error.BindFailed;
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
    if (std.c.getsockname(fd, @ptrCast(&bound), &bound_len) != 0) return error.GetSockNameFailed;
    return std.mem.bigToNative(u16, bound.port);
}

/// #522: skip the external ngtcp2/GnuTLS H3/QUIC interop cases when the
/// canonical peer (built per `scripts/interop/README.md`, `gtlsclient`) isn't
/// available locally -- like `requireOpenssl`, an optional external peer
/// must never fail a stripped-down dev environment; CI builds it.
///
/// `H3_INTEROP_CLIENT_PATH`, not an ngtcp2-specific name: this file isn't
/// scanned by `scripts/audit-dependencies.sh`, but the CI workflow that sets
/// this variable is, and a peer-specific env var name there would trip the
/// same forbidden-dependency-identifier check that keeps the peer's own
/// packages/repository names confined to scripts/interop/.
fn requireNgtcp2Client(allocator: std.mem.Allocator) ![]u8 {
    const path = compat.getEnvVarOwned(allocator, "H3_INTEROP_CLIENT_PATH") catch return error.SkipZigTest;
    errdefer allocator.free(path);
    var result = bounded_process.run(allocator, .{
        .argv = &.{ path, "--help" },
        .stdout_limit = 16 * 1024,
        .stderr_limit = 16 * 1024,
        .deadline_ms = 5_000,
    }) catch return error.SkipZigTest;
    defer result.deinit(allocator);
    if (std.meta.activeTag(result.outcome) != .normal_exit) return error.SkipZigTest;
    return path;
}

/// #522: the checked-out ngtcp2 `gtlsclient` (every TLS backend's
/// `tls_client_session_*.cc`) sends the literal string "localhost" as TLS
/// SNI whenever the connect host is a numeric IP address, *regardless* of
/// `--sni` -- confirmed directly against this suite's own server (`HOST` is
/// always `test_host` here, an IP) and in the checked-out ngtcp2 source
/// (`if (!config.sni.empty()) { use it } else if (host is numeric) { send
/// "localhost" }`; the observed wire SNI is "localhost" regardless). The
/// intended name is registered too so the response Host-routing config
/// stays readable, and both resolve to the one QUIC-side identity below.
const quic_interop_server_name = "tardigrade.test";
const quic_interop_wire_sni = "localhost";

/// #522: QUIC's `NativeCredentialStore` (`native_tls_connection.zig`, wired
/// in `edge_gateway.zig` only `if (build_options.tls_openssl_adapter and
/// cfg.http3_enabled ...)`) is a multi-identity SNI provider with
/// `unknown_sni_policy=.fail_handshake` -- register both the peer's actual
/// wire SNI (`quic_interop_wire_sni`) and the intended name under the same
/// identity so the handshake succeeds regardless of which one the peer
/// negotiates with.
fn quicSniCertsEnv(allocator: std.mem.Allocator, cert_path: []const u8, key_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}:{s}:{s}|{s}:{s}:{s}", .{
        quic_interop_wire_sni,    cert_path, key_path,
        quic_interop_server_name, cert_path, key_path,
    });
}

const GtlsClientSpec = struct {
    quic_port: u16,
    sni: []const u8 = quic_interop_server_name,
    path: []const u8,
    extra_paths: []const []const u8 = &.{},
    method: []const u8 = "GET",
    body_file: ?[]const u8 = null,
    session_file: []const u8,
    tp_file: []const u8,
    disable_early_data: bool = false,
    wait_for_ticket: bool = false,
    exit_on_first_stream_close: bool = true,
    exit_on_all_streams_close: bool = false,
    deadline_ms: u32 = 15_000,
};

/// #522: drives a real `gtlsclient` subprocess against the native QUIC/H3
/// listener, bounded end to end via `bounded_process` like `runOpenssl`.
/// `--session-file`/`--tp-file` are ngtcp2's TLS-session/QUIC-transport-
/// parameter persistence -- the 0-RTT analogue of openssl's `-sess_out`/
/// `-sess_in`/`-early_data`.
fn runGtlsClient(allocator: std.mem.Allocator, client_path: []const u8, spec: GtlsClientSpec) !bounded_process.Result {
    var argv = std.array_list.Managed([]const u8).init(allocator);
    defer argv.deinit();
    try argv.append(client_path);
    try argv.append("--sni");
    try argv.append(spec.sni);
    try argv.append("--session-file");
    try argv.append(spec.session_file);
    try argv.append("--tp-file");
    try argv.append(spec.tp_file);
    if (spec.disable_early_data) try argv.append("--disable-early-data");
    if (spec.wait_for_ticket) try argv.append("--wait-for-ticket");
    if (spec.exit_on_first_stream_close) try argv.append("--exit-on-first-stream-close");
    if (spec.exit_on_all_streams_close) try argv.append("--exit-on-all-streams-close");
    if (!std.mem.eql(u8, spec.method, "GET")) {
        try argv.append("-m");
        try argv.append(spec.method);
    }
    if (spec.body_file) |p| {
        try argv.append("-d");
        try argv.append(p);
    }
    const port_str = try std.fmt.allocPrint(allocator, "{d}", .{spec.quic_port});
    defer allocator.free(port_str);
    try argv.append(test_host);
    try argv.append(port_str);
    const uri = try std.fmt.allocPrint(allocator, "https://{s}{s}", .{ spec.sni, spec.path });
    defer allocator.free(uri);
    try argv.append(uri);
    var extra_uris = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (extra_uris.items) |extra_uri| allocator.free(extra_uri);
        extra_uris.deinit();
    }
    for (spec.extra_paths) |extra_path| {
        const extra_uri = try std.fmt.allocPrint(allocator, "https://{s}{s}", .{ spec.sni, extra_path });
        errdefer allocator.free(extra_uri);
        try extra_uris.append(extra_uri);
        try argv.append(extra_uri);
    }
    return bounded_process.run(allocator, .{
        .argv = argv.items,
        .stdout_limit = 512 * 1024,
        .stderr_limit = 512 * 1024,
        .deadline_ms = spec.deadline_ms,
        .accepted_exit_codes = &.{ 0, 1 },
    });
}

fn ngtcp2SessionPath(allocator: std.mem.Allocator, port: u16, tag: []const u8) ![]u8 {
    const dir = try interopSecretsDir(allocator);
    defer allocator.free(dir);
    return std.fmt.allocPrint(allocator, "{s}/interop-quic-{s}-{d}.sess", .{ dir, tag, port });
}

fn ngtcp2TpPath(allocator: std.mem.Allocator, port: u16, tag: []const u8) ![]u8 {
    const dir = try interopSecretsDir(allocator);
    defer allocator.free(dir);
    return std.fmt.allocPrint(allocator, "{s}/interop-quic-{s}-{d}.tp", .{ dir, tag, port });
}

/// #522: snapshots the post-handshake session/transport-parameter files so a
/// later run can offer the *identical* early-data-capable state again --
/// `gtlsclient` overwrites `--session-file` in place with a freshly issued
/// ticket after every successful handshake, so a genuine replay (not just a
/// second independently-ticketed reconnect) requires copies taken before
/// that ticket is ever used.
fn snapshotGtlsClientState(allocator: std.mem.Allocator, sess_path: []const u8, tp_path: []const u8, snap_sess_path: []const u8, snap_tp_path: []const u8) !void {
    const sess_data = try compat.cwd().readFileAlloc(allocator, sess_path, 64 * 1024);
    defer allocator.free(sess_data);
    try writeInteropSecretFile(snap_sess_path, sess_data);
    const tp_data = try compat.cwd().readFileAlloc(allocator, tp_path, 64 * 1024);
    defer allocator.free(tp_data);
    try writeInteropSecretFile(snap_tp_path, tp_data);
}

fn appendGtlsHandshakeCryptoBytes(out: *std.array_list.Managed(u8), stderr: []const u8) !void {
    var in_handshake_crypto = false;
    var lines = std.mem.splitScalar(u8, stderr, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, "\r");
        if (std.mem.startsWith(u8, line, "Ordered CRYPTO data in ")) {
            in_handshake_crypto = std.mem.eql(u8, line, "Ordered CRYPTO data in Handshake crypto level");
            continue;
        }
        if (!in_handshake_crypto) continue;
        if (line.len == 0) {
            in_handshake_crypto = false;
            continue;
        }

        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const offset = fields.next() orelse {
            in_handshake_crypto = false;
            continue;
        };
        if (offset.len != 8 or !std.ascii.isHex(offset[0])) {
            in_handshake_crypto = false;
            continue;
        }
        while (fields.next()) |field| {
            if (field.len > 0 and field[0] == '|') break;
            if (field.len != 2) continue;
            if (!std.ascii.isHex(field[0]) or !std.ascii.isHex(field[1])) continue;
            try out.append(try std.fmt.parseInt(u8, field, 16));
        }
    }
}

fn gtlsHandshakeContainsType(bytes: []const u8, handshake_type: u8) bool {
    var index: usize = 0;
    while (index + 4 <= bytes.len) {
        const message_type = bytes[index];
        const len = (@as(usize, bytes[index + 1]) << 16) |
            (@as(usize, bytes[index + 2]) << 8) |
            @as(usize, bytes[index + 3]);
        if (index + 4 + len > bytes.len) break;
        if (message_type == handshake_type) return true;
        index += 4 + len;
    }
    return false;
}

fn assertGtlsSessionReused(allocator: std.mem.Allocator, stderr: []const u8) !void {
    var handshake = std.array_list.Managed(u8).init(allocator);
    defer handshake.deinit();
    try appendGtlsHandshakeCryptoBytes(&handshake, stderr);

    // ngtcp2's own pinned example tests distinguish resumed handshakes by
    // the decrypted server Handshake CRYPTO flight:
    // ServerHello:EncryptedExtensions:Finished. A full handshake contains
    // Certificate (11) and CertificateVerify (15) before Finished.
    try std.testing.expect(gtlsHandshakeContainsType(handshake.items, 8)); // EncryptedExtensions
    try std.testing.expect(gtlsHandshakeContainsType(handshake.items, 20)); // Finished
    try std.testing.expect(!gtlsHandshakeContainsType(handshake.items, 11)); // Certificate
    try std.testing.expect(!gtlsHandshakeContainsType(handshake.items, 15)); // CertificateVerify
}

test "h3interop.quic.resume" {
    try requireGeneralTlsProfile();
    const allocator = std.testing.allocator;
    const client_path = try requireNgtcp2Client(allocator);
    defer allocator.free(client_path);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();
    const sni_certs = try quicSniCertsEnv(allocator, tls_paths.cert_path, tls_paths.key_path);
    defer allocator.free(sni_certs);

    // A proxied route (not a local `return`) so the resumed request's
    // exactly-once execution is observable at a real application/upstream
    // seam, not merely inferred from the QUIC/TLS acceptance decision.
    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "readiness", .connection_header = "close" },
        .{ .body = "full-handshake", .connection_header = "close" },
        .{ .body = "resumed", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    const quic_port = try findFreeUdpPort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/safe",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = quic_interop_server_name },
            .{ .name = "TARDIGRADE_TLS_SNI_CERTS", .value = sni_certs },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
        },
    });
    defer tardigrade.stop();

    const sess_path = try ngtcp2SessionPath(allocator, quic_port, "resume");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};
    const tp_path = try ngtcp2TpPath(allocator, quic_port, "resume");
    defer allocator.free(tp_path);
    defer compat.cwd().deleteFile(tp_path) catch {};

    // 1-2: real production `http3_runtime.Runtime` (via the edge-gateway
    // binary), real ngtcp2/GnuTLS client, initial full QUIC/TLS 1.3
    // handshake, production-issued resumption state captured to disk.
    var first = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/safe",
        .session_file = sess_path,
        .tp_file = tp_path,
        .wait_for_ticket = true,
    });
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try assertContains(first.stderr, "[:status: 200]");
    try upstream.resetCapture();

    // 3-4: reconnect with early data explicitly disabled -- an authoritative
    // *resumed* 1-RTT connection, not 0-RTT and not a second full handshake
    // misclassified as resumption.
    var second = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/safe",
        .session_file = sess_path,
        .tp_file = tp_path,
        .disable_early_data = true,
    });
    defer second.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(second.outcome));
    try assertContains(second.stderr, "[:status: 200]");

    // 5: independent, peer-side proof of resumption from the pinned
    // external peer's own decrypted server Handshake CRYPTO trace, not from
    // anything Tardigrade reports about itself.
    try assertGtlsSessionReused(allocator, second.stderr);

    // 6: exactly-once application/upstream execution for the resumed
    // request, observed at the real upstream seam.
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    // 7-8: Tardigrade's own typed QUIC resumption outcome -- not just a
    // second successful handshake -- independently reports `accepted`. No
    // accepted 0-RTT packet proves this was ordinary 1-RTT resumption, not
    // early data.
    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"quic\"", "outcome=\"accepted\"" }, 1);
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(metrics.body, "tardigrade_quic_zero_rtt_packet_total", &.{"outcome=\"accepted\""}) orelse 0);
}

test "h3interop.quic.early.accepted" {
    try requireGeneralTlsProfile();
    const allocator = std.testing.allocator;
    const client_path = try requireNgtcp2Client(allocator);
    defer allocator.free(client_path);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();
    const sni_certs = try quicSniCertsEnv(allocator, tls_paths.cert_path, tls_paths.key_path);
    defer allocator.free(sni_certs);

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "readiness", .connection_header = "close" },
        .{ .body = "ticket-bootstrap", .connection_header = "close" },
        .{ .body = "safe-early", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    const quic_port = try findFreeUdpPort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/safe",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = quic_interop_server_name },
            .{ .name = "TARDIGRADE_TLS_SNI_CERTS", .value = sni_certs },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE", .value = "process_local" },
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_HTTP3_ENABLE_0RTT", .value = "true" },
        },
    });
    defer tardigrade.stop();

    const sess_path = try ngtcp2SessionPath(allocator, quic_port, "early-accepted");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};
    const tp_path = try ngtcp2TpPath(allocator, quic_port, "early-accepted");
    defer allocator.free(tp_path);
    defer compat.cwd().deleteFile(tp_path) catch {};

    var first = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/safe",
        .session_file = sess_path,
        .tp_file = tp_path,
        .wait_for_ticket = true,
    });
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try upstream.resetCapture();

    // Reconnect with early data left enabled (the default once a captured
    // session+transport-parameter file are supplied): the peer sends the
    // GET as real QUIC 0-RTT packets, proven independently by the peer's own
    // `type=0RTT` frame log alongside Tardigrade's authoritative acceptance.
    var early = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/safe",
        .session_file = sess_path,
        .tp_file = tp_path,
    });
    defer early.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(early.outcome));
    try assertContains(early.stderr, "type=0RTT");
    // `[:status: N]` is a plain logged header line, safe to substring-match;
    // the response *body* dump below it is hex+ASCII wrapped at 16-byte
    // offsets and must not be matched this way -- a short body like the
    // JSON error text can straddle a wrap boundary and split apart.
    try assertContains(early.stderr, "[:status: 200]");
    // Exactly-once application/upstream execution, observed at the real
    // upstream seam -- not inferred from the QUIC/TLS acceptance decision.
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"quic\"", "outcome=\"accepted\"" }, 1);
    try expectMetricAtLeast(metrics.body, "tardigrade_quic_early_data_decision_total", &.{"decision=\"accepted\""}, 1);
    try expectMetricAtLeast(metrics.body, "tardigrade_quic_zero_rtt_packet_total", &.{"outcome=\"accepted\""}, 1);
    // Proxied via `proxy_early_data rfc8470;` (matching
    // `interop.openssl.h1.early.accepted`'s own assertion): a proxied
    // replay-safe early request is forwarded with the RFC 8470 marker, not
    // executed locally, so the decision label is `forwarded`.
    try expectMetricAtLeast(metrics.body, "tardigrade_http_early_data_decisions_total", &.{ "protocol=\"h3\"", "decision=\"forwarded\"" }, 1);
}

test "h3interop.quic.early.unsafe_425" {
    try requireGeneralTlsProfile();
    const allocator = std.testing.allocator;
    const client_path = try requireNgtcp2Client(allocator);
    defer allocator.free(client_path);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();
    const sni_certs = try quicSniCertsEnv(allocator, tls_paths.cert_path, tls_paths.key_path);
    defer allocator.free(sni_certs);

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "readiness", .connection_header = "close" },
        .{ .body = "ticket-bootstrap", .connection_header = "close" },
        .{ .body = "ordinary-after-425", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    const quic_port = try findFreeUdpPort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/safe",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = quic_interop_server_name },
            .{ .name = "TARDIGRADE_TLS_SNI_CERTS", .value = sni_certs },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE", .value = "process_local" },
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_HTTP3_ENABLE_0RTT", .value = "true" },
        },
    });
    defer tardigrade.stop();

    const sess_path = try ngtcp2SessionPath(allocator, quic_port, "early-unsafe");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};
    const tp_path = try ngtcp2TpPath(allocator, quic_port, "early-unsafe");
    defer allocator.free(tp_path);
    defer compat.cwd().deleteFile(tp_path) catch {};
    const body_path = try std.fmt.allocPrint(allocator, "{s}.body", .{sess_path});
    defer allocator.free(body_path);
    defer compat.cwd().deleteFile(body_path) catch {};
    try writeInteropSecretFile(body_path, "x");

    var first = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/safe",
        .session_file = sess_path,
        .tp_file = tp_path,
        .wait_for_ticket = true,
    });
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try upstream.resetCapture();

    // POST is never method-safe (`http/early_data.zig`'s `methodSafe`
    // accepts only GET/HEAD) regardless of the route's `replay_safe`
    // marking -- the same shared HTTP-level policy the H1 case below
    // exercises, not a QUIC-specific safety mechanism.
    var early = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/safe",
        .method = "POST",
        .body_file = body_path,
        .session_file = sess_path,
        .tp_file = tp_path,
    });
    defer early.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(early.outcome));
    try assertContains(early.stderr, "type=0RTT");
    // See the accepted case above: match the plain logged status header,
    // not the hex+ASCII body dump (the JSON error text can straddle a
    // 16-byte wrap boundary and split apart mid-substring).
    try assertContains(early.stderr, "[:status: 425]");
    // Rejected before any application/upstream side effect.
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    // The QUIC/TLS layer still authoritatively accepted the early data --
    // the rejection is the shared HTTP-level safety policy, not a
    // replay/compatibility failure being misattributed.
    try expectMetricAtLeast(metrics.body, "tardigrade_quic_zero_rtt_packet_total", &.{"outcome=\"accepted\""}, 1);
    try expectMetricAtLeast(metrics.body, "tardigrade_http_early_data_decisions_total", &.{ "protocol=\"h3\"", "decision=\"too_early\"" }, 1);

    // `gtlsclient` has one method/body for all URIs in an invocation and
    // opens every configured stream as soon as stream credit is available;
    // its `--delay-stream` option delays every stream until 1-RTT. It
    // cannot express "early unsafe POST, then ordinary GET" on one
    // connection. The production H3 runtime's same-connection post-425
    // behavior is covered by `http3 (#523): ... ordinary post-handshake
    // requests still work`; this live external-peer check proves the
    // exact same route remains usable for ordinary H3 immediately after
    // the external early-POST 425, with one upstream side effect.
    var ordinary = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/safe",
        .session_file = sess_path,
        .tp_file = tp_path,
        .disable_early_data = true,
    });
    defer ordinary.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(ordinary.outcome));
    // `[:status: 200]` is a plain logged header line, safe to substring
    // match; the response body dump is hex+ASCII wrapped at 16-byte
    // offsets, so a short body string can straddle a wrap boundary and
    // split apart (hit this exact class of bug earlier in this file) --
    // the upstream request count below is the robust exactly-once proof.
    try assertContains(ordinary.stderr, "[:status: 200]");
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
}

test "h3interop.quic.early.replay_fallback" {
    try requireGeneralTlsProfile();
    const allocator = std.testing.allocator;
    const client_path = try requireNgtcp2Client(allocator);
    defer allocator.free(client_path);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();
    const sni_certs = try quicSniCertsEnv(allocator, tls_paths.cert_path, tls_paths.key_path);
    defer allocator.free(sni_certs);

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "readiness", .connection_header = "close" },
        .{ .body = "ticket-bootstrap", .connection_header = "close" },
        .{ .body = "safe-early", .connection_header = "close" },
        .{ .body = "after-replay", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    const quic_port = try findFreeUdpPort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/safe",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = quic_interop_server_name },
            .{ .name = "TARDIGRADE_TLS_SNI_CERTS", .value = sni_certs },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE", .value = "process_local" },
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_HTTP3_ENABLE_0RTT", .value = "true" },
        },
    });
    defer tardigrade.stop();

    const sess_path = try ngtcp2SessionPath(allocator, quic_port, "replay");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};
    const tp_path = try ngtcp2TpPath(allocator, quic_port, "replay");
    defer allocator.free(tp_path);
    defer compat.cwd().deleteFile(tp_path) catch {};

    var first = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/safe",
        .session_file = sess_path,
        .tp_file = tp_path,
        .wait_for_ticket = true,
    });
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));

    // Snapshot the post-bootstrap ticket/transport-parameter state *before*
    // either early attempt below can consume/overwrite it -- both attempts
    // must offer the bit-identical early data for the second to be a
    // genuine replay rather than an independently-ticketed reconnect.
    const replay_a_sess = try std.fmt.allocPrint(allocator, "{s}.replay-a", .{sess_path});
    defer allocator.free(replay_a_sess);
    defer compat.cwd().deleteFile(replay_a_sess) catch {};
    const replay_a_tp = try std.fmt.allocPrint(allocator, "{s}.replay-a", .{tp_path});
    defer allocator.free(replay_a_tp);
    defer compat.cwd().deleteFile(replay_a_tp) catch {};
    try snapshotGtlsClientState(allocator, sess_path, tp_path, replay_a_sess, replay_a_tp);
    const replay_b_sess = try std.fmt.allocPrint(allocator, "{s}.replay-b", .{sess_path});
    defer allocator.free(replay_b_sess);
    defer compat.cwd().deleteFile(replay_b_sess) catch {};
    const replay_b_tp = try std.fmt.allocPrint(allocator, "{s}.replay-b", .{tp_path});
    defer allocator.free(replay_b_tp);
    defer compat.cwd().deleteFile(replay_b_tp) catch {};
    try snapshotGtlsClientState(allocator, sess_path, tp_path, replay_b_sess, replay_b_tp);

    try upstream.resetCapture();
    var early = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/safe",
        .session_file = replay_a_sess,
        .tp_file = replay_a_tp,
    });
    defer early.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(early.outcome));
    try assertContains(early.stderr, "[:status: 200]");
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    var metrics_before_replay = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics_before_replay.deinit();
    const accepted_before_replay = prometheusLabeledMetricValue(
        metrics_before_replay.body,
        "tardigrade_quic_zero_rtt_packet_total",
        &.{"outcome=\"accepted\""},
    ) orelse 0;
    try std.testing.expect(accepted_before_replay > 0);

    // Replay the identical early attempt (bit-identical ticket/transport
    // state, never touched by the first attempt above) within the same
    // Tardigrade process. RFC 9001 Section 4.6.1/RFC 9000: a rejected 0-RTT PSK
    // offer does not fail the connection -- the peer transparently falls
    // back to an ordinary 1-RTT handshake and (by design, in every
    // conformant client including this one) retransmits the same request
    // over it once established. So this run's own request *does* reach the
    // upstream again, but safely: the replayed *early* data itself is
    // never re-executed (`zero_rtt_packet_total{outcome="accepted"}` stays
    // at 1, not 2, checked below), and the second upstream hit is the
    // legitimate 1-RTT fallback response, not a duplicate of the first.
    var replay = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/safe",
        .session_file = replay_b_sess,
        .tp_file = replay_b_tp,
    });
    defer replay.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(replay.outcome));
    try assertContains(replay.stderr, "[:status: 200]");
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    // The replay-specific typed outcome, not a generic ticket/key miss.
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"duplicate\""}, 1);
    // No additional accepted 0-RTT packets across the replay attempt. The
    // first valid early request may occupy more than one QUIC packet, so
    // compare the accepted-packet counter before/after replay rather than
    // equating "one request" with "one packet".
    const accepted_after_replay = prometheusLabeledMetricValue(
        metrics.body,
        "tardigrade_quic_zero_rtt_packet_total",
        &.{"outcome=\"accepted\""},
    ) orelse 0;
    try std.testing.expectEqual(accepted_before_replay, accepted_after_replay);

    // The otherwise-valid connection remains usable for an ordinary,
    // non-early 1-RTT H3 request afterward (an explicit, separate
    // reconnect, distinct from the automatic in-connection fallback above).
    var fallback = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/safe",
        .session_file = sess_path,
        .tp_file = tp_path,
        .disable_early_data = true,
    });
    defer fallback.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(fallback.outcome));
    try assertContains(fallback.stderr, "[:status: 200]");
    try std.testing.expectEqual(@as(u32, 3), upstream.requestCount());
}

test "interop.openssl.h1.resume" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
        },
    });
    defer tardigrade.stop();

    const connect_arg = try opensslConnectArg(allocator, tardigrade.port);
    defer allocator.free(connect_arg);
    const sess_path = try opensslSessionPath(allocator, tardigrade.port, "h1-resume");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};

    // 1-4: real Tardigrade native TLS listener, real `openssl s_client`,
    // initial full handshake, OpenSSL-managed session-file capture.
    var first = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        sess_path,
    }, openssl_health_request, 10_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try assertContains(first.stdout, "New, TLSv1.3");
    try assertContains(first.stdout, "HTTP/1.1 200 OK");
    try assertContains(first.stdout, "alive");

    // 5-6: reconnect using the OpenSSL-captured session; must actually
    // resume, not merely succeed via a second full handshake.
    var second = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_in",
        sess_path,
    }, openssl_health_request, 10_000);
    defer second.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(second.outcome));
    // Authoritative OpenSSL-side indicator: `SSL_session_reused()` backs
    // this "Reused"/"New" line for TLS 1.3 the same way it does for 1.2 --
    // a second full handshake would print "New" again, not "Reused".
    try assertContains(second.stdout, "Reused, TLSv1.3");

    // 7-8: the resumed connection actually served the request.
    try assertContains(second.stdout, "HTTP/1.1 200 OK");
    try assertContains(second.stdout, "alive");

    // Authoritative Tardigrade-side indicator, independent of OpenSSL's own
    // report: production resumption-outcome metrics, not a second successful
    // handshake being misclassified as resumption.
    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try std.testing.expect((prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0) >= 1);
}

test "interop.openssl.h1.early.accepted" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "readiness", .connection_header = "close" },
        .{ .body = "ticket-bootstrap", .connection_header = "close" },
        .{ .body = "safe-early", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/safe",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE", .value = "process_local" },
        },
    });
    defer tardigrade.stop();

    const connect_arg = try opensslConnectArg(allocator, tardigrade.port);
    defer allocator.free(connect_arg);
    const sess_path = try opensslSessionPath(allocator, tardigrade.port, "h1-early-accepted");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};
    const early_path = try opensslEarlyDataPath(allocator, tardigrade.port, "h1-early-accepted");
    defer allocator.free(early_path);
    defer compat.cwd().deleteFile(early_path) catch {};
    try writeInteropSecretFile(early_path, "GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");

    var first = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        sess_path,
    }, "GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n", 10_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try assertContains(first.stdout, "New, TLSv1.3");
    try assertContains(first.stdout, "HTTP/1.1 200 OK");

    var session_secrets = try opensslSessionSecrets(allocator, sess_path);
    defer session_secrets.deinit();
    try upstream.resetCapture();

    var early = try runOpenssl(allocator, &.{
        "s_client",        "-connect",    connect_arg,
        "-alpn",           "http/1.1",    "-servername",
        "tardigrade.test", "-tls1_3",     "-sess_in",
        sess_path,         "-early_data", early_path,
    }, "", 10_000);
    defer early.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(early.outcome));
    try assertContains(early.stdout, "Reused, TLSv1.3");
    try assertContains(early.stdout, "HTTP/1.1 200 OK");
    try assertContains(early.stdout, "safe-early");
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"accepted\""}, 1);
    try expectMetricAtLeast(metrics.body, "tardigrade_http_early_data_decisions_total", &.{ "protocol=\"h1\"", "decision=\"forwarded\"" }, 1);

    const log = try compat.cwd().readFileAlloc(allocator, tardigrade.log_path, 4 * 1024 * 1024);
    defer allocator.free(log);
    try assertHexAbsentCaseInsensitive(allocator, log, session_secrets.resumption_psk_hex);
    try assertHexAbsentCaseInsensitive(allocator, log, session_secrets.ticket_hex);
}

test "interop.openssl.h1.early.unsafe_425" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "readiness", .connection_header = "close" },
        .{ .body = "ticket-bootstrap", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/safe",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE", .value = "process_local" },
        },
    });
    defer tardigrade.stop();

    const connect_arg = try opensslConnectArg(allocator, tardigrade.port);
    defer allocator.free(connect_arg);
    const sess_path = try opensslSessionPath(allocator, tardigrade.port, "h1-early-unsafe");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};
    const early_path = try opensslEarlyDataPath(allocator, tardigrade.port, "h1-early-unsafe");
    defer allocator.free(early_path);
    defer compat.cwd().deleteFile(early_path) catch {};
    try writeInteropSecretFile(early_path, "POST /work HTTP/1.1\r\nHost: tardigrade.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

    var first = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        sess_path,
    }, "GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n", 10_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try upstream.resetCapture();

    var early = try runOpenssl(allocator, &.{
        "s_client",        "-connect",    connect_arg,
        "-alpn",           "http/1.1",    "-servername",
        "tardigrade.test", "-tls1_3",     "-sess_in",
        sess_path,         "-early_data", early_path,
    }, "", 10_000);
    defer early.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(early.outcome));
    try assertContains(early.stdout, "Reused, TLSv1.3");
    try assertContains(early.stdout, "HTTP/1.1 425 Too Early");
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"accepted\""}, 1);
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"duplicate\""}) orelse 0);
    try expectMetricAtLeast(metrics.body, "tardigrade_http_early_data_decisions_total", &.{ "protocol=\"h1\"", "decision=\"too_early\"" }, 1);
}

test "interop.openssl.h1.early.replay_fallback" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "readiness", .connection_header = "close" },
        .{ .body = "ticket-bootstrap", .connection_header = "close" },
        .{ .body = "safe-early", .connection_header = "close" },
        .{ .body = "after-replay", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/early",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE", .value = "process_local" },
        },
    });
    defer tardigrade.stop();

    const connect_arg = try opensslConnectArg(allocator, tardigrade.port);
    defer allocator.free(connect_arg);
    const sess_path = try opensslSessionPath(allocator, tardigrade.port, "h1-early-replay");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};
    const early_path = try opensslEarlyDataPath(allocator, tardigrade.port, "h1-early-replay");
    defer allocator.free(early_path);
    defer compat.cwd().deleteFile(early_path) catch {};
    try writeInteropSecretFile(early_path, "GET /early HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: keep-alive\r\n\r\n");

    var first = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        sess_path,
    }, "GET /early HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n", 10_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try upstream.resetCapture();

    var accepted = try runOpenssl(allocator, &.{
        "s_client",        "-connect",    connect_arg,
        "-alpn",           "http/1.1",    "-servername",
        "tardigrade.test", "-tls1_3",     "-sess_in",
        sess_path,         "-early_data", early_path,
    }, "", 10_000);
    defer accepted.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(accepted.outcome));
    try assertContains(accepted.stdout, "HTTP/1.1 200 OK");
    try assertContains(accepted.stdout, "safe-early");
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    var replay = try runOpenssl(allocator, &.{
        "s_client",        "-connect",    connect_arg,
        "-alpn",           "http/1.1",    "-servername",
        "tardigrade.test", "-tls1_3",     "-sess_in",
        sess_path,         "-early_data", early_path,
    }, "GET /after HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n", 10_000);
    defer replay.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(replay.outcome));
    try assertContains(replay.stdout, "Reused, TLSv1.3");
    try assertContains(replay.stdout, "HTTP/1.1 200 OK");
    try assertContains(replay.stdout, "after-replay");
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());
    const first_path = try upstream.capturedPathHistoryAt(allocator, 0);
    defer allocator.free(first_path);
    const second_path = try upstream.capturedPathHistoryAt(allocator, 1);
    defer allocator.free(second_path);
    try std.testing.expectEqualStrings("/early", first_path);
    try std.testing.expectEqualStrings("/after", second_path);

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"accepted\""}, 1);
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"duplicate\""}, 1);
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"accepted\"" }, 2);
}

test "interop.openssl.h2.tls_resume" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "resumed-h2-upstream-body-521",
        .connection_header = "close",
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-resume {{
        \\    proxy_pass http://{s}:{d}/h2-resume;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();

    const connect_arg = try opensslConnectArg(allocator, tardigrade.port);
    defer allocator.free(connect_arg);
    const sess_path = try opensslSessionPath(allocator, tardigrade.port, "h2-resume");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};

    var first = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "h2",       "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        sess_path,
    }, "", 10_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try assertContains(first.stdout, "New, TLSv1.3");
    try assertContains(first.stdout, "ALPN protocol: h2");
    try upstream.resetCapture();

    var before_metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer before_metrics.deinit();
    const accepted_before = prometheusLabeledMetricValue(before_metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0;

    const h2_request = try opensslH2GetRequestBytes(allocator, "/h2-resume");
    defer allocator.free(h2_request);

    var second = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "h2",       "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_in",
        sess_path,
    }, h2_request, 10_000);
    defer second.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(second.outcome));
    try assertContains(second.stdout, "Reused, TLSv1.3");
    try assertContains(second.stdout, "ALPN protocol: h2");
    try expectOpenSslH2ResponseBody(allocator, second.stdout, "resumed-h2-upstream-body-521");
    try waitForUpstreamCount(&upstream, 1, 2_000);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
    const resumed_path = try upstream.capturedPathHistoryAt(allocator, 0);
    defer allocator.free(resumed_path);
    try std.testing.expectEqualStrings("/h2-resume", resumed_path);

    var h2_metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer h2_metrics.deinit();
    const accepted_after = prometheusLabeledMetricValue(h2_metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0;
    try std.testing.expect(accepted_after >= accepted_before + 1);
}

test "proxy.circuit_breaker_opens_fast_fails_and_recovers" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .status_code = 500, .body = "fail-1", .connection_header = "close" },
        .{ .status_code = 500, .body = "fail-2", .connection_header = "close" },
        .{ .status_code = 200, .body = "recovered", .delay_ms = 3_000, .connection_header = "close" },
        .{ .status_code = 200, .body = "closed-again", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /cb {{
        \\    proxy_pass http://{s}:{d}/cb;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_WORKER_THREADS", .value = "2" },
            .{ .name = "TARDIGRADE_CB_THRESHOLD", .value = "2" },
            .{ .name = "TARDIGRADE_CB_TIMEOUT_MS", .value = "250" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    var first = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/cb", .body = null, .headers = &.{} });
    defer first.deinit();
    try std.testing.expectEqual(@as(u16, 500), first.status_code);

    var second = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/cb", .body = null, .headers = &.{} });
    defer second.deinit();
    try std.testing.expectEqual(@as(u16, 500), second.status_code);
    try waitForUpstreamCount(&upstream, 2, 2_000);

    var open = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/cb", .body = null, .headers = &.{} });
    defer open.deinit();
    try std.testing.expectEqual(@as(u16, 503), open.status_code);
    try assertContains(open.body, "\"code\":\"upstream_circuit_open\"");
    compat.sleepNs(50 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());

    const ProbeResult = struct {
        status: u16 = 0,
        body_matched: bool = false,
        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        err: ?anyerror = null,

        fn run(self: *@This(), port: u16) void {
            defer self.done.store(true, .release);
            var response = sendRequestWithTimeout(std.heap.page_allocator, port, .{ .method = "GET", .path = "/cb", .body = null, .headers = &.{} }, 8_000) catch |err| {
                self.err = err;
                return;
            };
            defer response.deinit();
            self.status = response.status_code;
            self.body_matched = std.mem.find(u8, response.body, "recovered") != null or std.mem.find(u8, response.body, "\"code\":\"upstream_circuit_open\"") != null;
        }
    };

    compat.sleepNs(300 * std.time.ns_per_ms);
    var probe_a = ProbeResult{};
    const thread_a = try std.Thread.spawn(.{}, ProbeResult.run, .{ &probe_a, tardigrade.port });
    try waitForUpstreamCount(&upstream, 3, 2_000);
    try std.testing.expect(!probe_a.done.load(.acquire));

    var probe_b = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/cb", .body = null, .headers = &.{} });
    defer probe_b.deinit();
    thread_a.join();

    if (probe_a.err) |err| return err;
    try std.testing.expect(probe_a.body_matched);
    const ok_a: u8 = if (probe_a.status == 200) 1 else 0;
    const ok_b: u8 = if (probe_b.status_code == 200) 1 else 0;
    const open_a: u8 = if (probe_a.status == 503) 1 else 0;
    const open_b: u8 = if (probe_b.status_code == 503) 1 else 0;
    const ok_count: u8 = ok_a + ok_b;
    const open_count: u8 = open_a + open_b;
    try std.testing.expectEqual(@as(u8, 1), ok_count);
    try std.testing.expectEqual(@as(u8, 1), open_count);
    try std.testing.expectEqual(@as(u32, 3), upstream.requestCount());

    var after_probe = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/cb", .body = null, .headers = &.{} });
    defer after_probe.deinit();
    try std.testing.expectEqual(@as(u16, 200), after_probe.status_code);
    try assertContains(after_probe.body, "closed-again");
    try std.testing.expectEqual(@as(u32, 4), upstream.requestCount());
}

test "interop.openssl.h2.proxy_request_translation_is_secret_safe" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var fixture = try GenericFixtureDir.create(allocator, "h2-proxy-transcript");
    defer fixture.deinit();
    const transcript_path = try fixture.joinAbs("transcripts.ndjson");
    defer allocator.free(transcript_path);
    {
        var transcript_file = try compat.createFileAbsolute(transcript_path, .{ .truncate = true });
        transcript_file.close();
    }

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "h2-proxy-translated-body-521",
        .connection_header = "close",
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-proxy {{
        \\    proxy_pass http://{s}:{d}/h2-proxy;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_TRANSCRIPT_STORE_PATH", .value = transcript_path },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const connect_arg = try opensslConnectArg(allocator, tardigrade.port);
    defer allocator.free(connect_arg);
    const secret_token = "h2-secret-token-521";
    const h2_request = try opensslH2RequestBytes(allocator, "POST", "/h2-proxy?x=1", "h2-authority.test", "h2-body-521", &.{
        .{ .name = "authorization", .value = "Bearer " ++ secret_token },
        .{ .name = "x-h2-extra", .value = "kept" },
    });
    defer allocator.free(h2_request);

    var result = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "h2",       "-servername",
        "tardigrade.test", "-tls1_3",
    }, h2_request, 10_000);
    defer result.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(result.outcome));
    try assertContains(result.stdout, "ALPN protocol: h2");
    try expectOpenSslH2ResponseBody(allocator, result.stdout, "h2-proxy-translated-body-521");
    try waitForUpstreamCount(&upstream, 1, 2_000);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
    const path = try upstream.capturedPathHistoryAt(allocator, 0);
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/h2-proxy?x=1", path);
    try std.testing.expectEqualStrings("h2-authority.test", upstream.capturedHeader("Host").?);
    try std.testing.expectEqualStrings("kept", upstream.capturedHeader("X-H2-Extra").?);
    const captured_body = try upstream.capturedBody(allocator);
    defer allocator.free(captured_body);
    try std.testing.expectEqualStrings("h2-body-521", captured_body);

    var transcript = try compat.openFileAbsolute(transcript_path, .{});
    defer transcript.close();
    const transcript_body = try transcript.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(transcript_body);
    try assertContains(transcript_body, "h2-body-521");
    try std.testing.expect(std.mem.indexOf(u8, transcript_body, secret_token) == null);
}

test "interop.openssl.h2.auth_required_proxy_fails_closed" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-private {{
        \\    proxy_pass http://{s}:{d}/h2-private;
        \\    auth required;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const connect_arg = try opensslConnectArg(allocator, tardigrade.port);
    defer allocator.free(connect_arg);
    const h2_request = try opensslH2GetRequestBytes(allocator, "/h2-private");
    defer allocator.free(h2_request);

    var result = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "h2",       "-servername",
        "tardigrade.test", "-tls1_3",
    }, h2_request, 10_000);
    defer result.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(result.outcome));
    try expectOpenSslH2ResponseBody(allocator, result.stdout, "\"code\":\"unauthorized\"");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.h2.proxy_malformed_authority_rejected_before_upstream" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-authority {{
        \\    proxy_pass http://{s}:{d}/h2-authority;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    // A CRLF-bearing `:authority` must never be interpolated into the raw
    // `Host: {authority}` text the synthetic HTTP/1 request is built from --
    // otherwise it smuggles a second, attacker-controlled header past HPACK.
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-authority" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test\r\nX-Injected: evil" },
    };
    // The connection is torn down without ever producing a response, so the
    // specific transport-level error observed by the client can vary; what
    // matters is that the request never succeeds and never reaches upstream.
    if (pureZigH2GetBody(allocator, tardigrade.port, headers[0..])) |body| {
        allocator.free(body);
        return error.TestUnexpectedSuccess;
    } else |_| {}
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.h2.proxy_oversized_body_across_data_frames_rejected_boundedly" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-body-limit {{
        \\    proxy_pass http://{s}:{d}/h2-body-limit;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_MAX_BODY_SIZE", .value = "24" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/h2-body-limit" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    // Three 20-byte DATA frames (60 bytes total) against a 24-byte limit:
    // the second frame alone would already exceed it, so the ingestion-time
    // guard must stop buffering well before the whole body is resident.
    const chunk = "12345678901234567890"[0..20];
    const chunks = [_][]const u8{ chunk, chunk, chunk };
    const body = try pureZigH2PostMultiFrameBody(allocator, tardigrade.port, headers[0..], chunks[0..]);
    defer allocator.free(body);
    try assertContains(body, "\"code\":\"invalid_request\"");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.h2.proxy_connection_memory_cap_rejects_before_per_stream_cap" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream1 = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream1.stop();
    try upstream1.run();

    var upstream3 = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream3.stop();
    try upstream3.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-conn-mem-1 {{
        \\    proxy_pass http://{s}:{d}/h2-conn-mem-1;
        \\}}
        \\
        \\location = /h2-conn-mem-3 {{
        \\    proxy_pass http://{s}:{d}/h2-conn-mem-3;
        \\}}
    , .{ test_host, upstream1.port(), test_host, upstream3.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
            // Per-stream cap is generous; the connection-wide cap is not.
            .{ .name = "TARDIGRADE_MAX_BODY_SIZE", .value = "2000" },
            .{ .name = "TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES", .value = "1500" },
        },
    });
    defer tardigrade.stop();
    try upstream1.resetCapture();
    try upstream3.resetCapture();

    const client = try PureZigTlsClient.create(allocator, tardigrade.port, "h2");
    defer client.destroy();

    try client.writeAllPlain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try client.writeHttp2Frame(0x4, 0, 0, &.{}); // client SETTINGS

    const headers1 = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/h2-conn-mem-1" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const request_block1 = try hpack.encodeLiteralHeaderBlock(allocator, headers1[0..]);
    defer allocator.free(request_block1);
    try client.writeHttp2Frame(0x1, 0x4, 1, request_block1); // END_HEADERS only, body follows

    const chunk = try allocator.alloc(u8, 1000);
    defer allocator.free(chunk);
    @memset(chunk, 'x');
    // Stream 1 stays open (no END_STREAM) so its 1,000 already-buffered
    // bytes keep counting against the connection-wide cap while stream 3's
    // DATA is evaluated -- and since it's never dispatched, it never
    // reaches its own upstream either.
    try client.writeHttp2Frame(0x0, 0, 1, chunk);

    const headers3 = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/h2-conn-mem-3" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const request_block3 = try hpack.encodeLiteralHeaderBlock(allocator, headers3[0..]);
    defer allocator.free(request_block3);
    try client.writeHttp2Frame(0x1, 0x4, 3, request_block3); // END_HEADERS only, body follows
    // Stream 3's own body (1,000 bytes) is well under the 2,000-byte
    // per-stream cap, but 1,000 (stream 1, still buffered) + 1,000 (this)
    // exceeds the 1,500-byte connection cap.
    try client.writeHttp2Frame(0x0, 0x1, 3, chunk); // END_STREAM

    var stream3_body = std.array_list.Managed(u8).init(allocator);
    defer stream3_body.deinit();
    var stream3_done = false;

    var frame_count: usize = 0;
    while (frame_count < 32 and !stream3_done) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);
        switch (frame.typ) {
            0x4 => {
                if ((frame.flags & 0x1) == 0) try client.writeHttp2Frame(0x4, 0x1, 0, &.{});
            },
            0x0 => {
                if (frame.stream_id == 3) {
                    try stream3_body.appendSlice(frame.payload);
                    if ((frame.flags & 0x1) != 0) stream3_done = true;
                }
            },
            else => {},
        }
    }

    try std.testing.expect(stream3_done);
    try assertContains(stream3_body.items, "\"code\":\"invalid_request\"");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream1.requestCount());
    try std.testing.expectEqual(@as(u32, 0), upstream3.requestCount());
}

test "interop.h2.proxy_mismatched_content_length_rejected_before_upstream" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-cl-mismatch {{
        \\    proxy_pass http://{s}:{d}/h2-cl-mismatch;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    // Declares 5 bytes but sends 10: RFC 9113 §8.1.1 requires these to
    // match. Letting `Request.parse` trust the declared value would
    // silently truncate the request and desync framing rather than error.
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/h2-cl-mismatch" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
        .{ .name = "content-length", .value = "5" },
    };
    const chunks = [_][]const u8{"0123456789"};
    if (pureZigH2PostMultiFrameBody(allocator, tardigrade.port, headers[0..], chunks[0..])) |body| {
        allocator.free(body);
        return error.TestUnexpectedSuccess;
    } else |_| {}
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.h2.proxy_transfer_encoding_header_rejected_before_upstream" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-te-forbidden {{
        \\    proxy_pass http://{s}:{d}/h2-te-forbidden;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    // RFC 9113 §8.2.2: `transfer-encoding` (like `connection`, `upgrade`,
    // etc.) is a connection-specific field forbidden in HTTP/2 messages.
    // HPACK decoding doesn't itself reject it, so a client can smuggle one
    // through; letting HTTP/1 `Request.parse` reinterpret it as chunked
    // framing would desync request framing entirely.
    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/h2-te-forbidden" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
        .{ .name = "transfer-encoding", .value = "chunked" },
    };
    const chunks = [_][]const u8{"irrelevant-body"};
    if (pureZigH2PostMultiFrameBody(allocator, tardigrade.port, headers[0..], chunks[0..])) |body| {
        allocator.free(body);
        return error.TestUnexpectedSuccess;
    } else |_| {}
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.h2.settings_window_delta_overflow_on_active_stream_sends_goaway" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const large_response = try allocator.alloc(u8, 80 * 1024);
    defer allocator.free(large_response);
    for (large_response, 0..) |*b, i| {
        b.* = @as(u8, 'a') + @as(u8, @intCast(i % 26));
    }

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = large_response,
        .connection_header = "close",
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-settings-overflow {{
        \\    proxy_pass http://{s}:{d}/h2-settings-overflow;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();

    const client = try PureZigTlsClient.create(allocator, tardigrade.port, "h2");
    defer client.destroy();

    try client.writeAllPlain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try client.writeHttp2Frame(0x4, 0, 0, &.{}); // client SETTINGS (default window)

    const headers1 = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-settings-overflow" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const request_block1 = try hpack.encodeLiteralHeaderBlock(allocator, headers1[0..]);
    defer allocator.free(request_block1);
    try client.writeHttp2Frame(0x1, 0x1 | 0x4, 1, request_block1); // END_STREAM | END_HEADERS

    var saw_goaway = false;
    var stream1_bytes: usize = 0;
    var sent_followup = false;

    var frame_count: usize = 0;
    while (frame_count < 32 and !saw_goaway) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);
        switch (frame.typ) {
            0x4 => {
                if ((frame.flags & 0x1) == 0) try client.writeHttp2Frame(0x4, 0x1, 0, &.{});
            },
            0x0 => {
                if (frame.stream_id == 1) {
                    stream1_bytes += frame.payload.len;
                    if (!sent_followup and stream1_bytes > 0) {
                        sent_followup = true;
                        // Push stream 1's send window to exactly
                        // maxInt(i32) (it was fully drained to 0 by the
                        // initial blocked burst, so this lands exactly on
                        // the ceiling without itself overflowing).
                        var inc: [4]u8 = undefined;
                        std.mem.writeInt(u32, inc[0..4], 0x7FFFFFFF, .big);
                        try client.writeHttp2Frame(0x8, 0, 1, inc[0..]);
                        // A single-unit positive SETTINGS_INITIAL_WINDOW_SIZE
                        // delta now overflows that already-maxed window.
                        var settings_payload: [6]u8 = undefined;
                        std.mem.writeInt(u16, settings_payload[0..2], 0x4, .big);
                        std.mem.writeInt(u32, settings_payload[2..6], 65_536, .big);
                        try client.writeHttp2Frame(0x4, 0, 0, settings_payload[0..]);
                    }
                }
            },
            0x7 => { // GOAWAY
                try std.testing.expect(frame.payload.len >= 8);
                const err_code = std.mem.readInt(u32, frame.payload[4..8], .big);
                try std.testing.expectEqual(@as(u32, 3), err_code); // FLOW_CONTROL_ERROR
                saw_goaway = true;
            },
            else => {},
        }
    }

    try std.testing.expect(saw_goaway);
}

test "interop.h2.stream_overflow_rst_releases_connection_memory_accounting" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream1 = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream1.stop();
    try upstream1.run();

    var upstream3 = try UpstreamServer.start(allocator, &.{.{ .body = "stream3-ok" }});
    defer upstream3.stop();
    try upstream3.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-overflow-mem-1 {{
        \\    proxy_pass http://{s}:{d}/h2-overflow-mem-1;
        \\}}
        \\
        \\location = /h2-overflow-mem-3 {{
        \\    proxy_pass http://{s}:{d}/h2-overflow-mem-3;
        \\}}
    , .{ test_host, upstream1.port(), test_host, upstream3.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_MAX_BODY_SIZE", .value = "2000" },
            .{ .name = "TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES", .value = "2000" },
        },
    });
    defer tardigrade.stop();
    try upstream1.resetCapture();
    try upstream3.resetCapture();

    const client = try PureZigTlsClient.create(allocator, tardigrade.port, "h2");
    defer client.destroy();

    try client.writeAllPlain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try client.writeHttp2Frame(0x4, 0, 0, &.{}); // client SETTINGS

    const headers1 = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/h2-overflow-mem-1" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const request_block1 = try hpack.encodeLiteralHeaderBlock(allocator, headers1[0..]);
    defer allocator.free(request_block1);
    try client.writeHttp2Frame(0x1, 0x4, 1, request_block1); // END_HEADERS only, body follows

    const chunk1 = try allocator.alloc(u8, 1500);
    defer allocator.free(chunk1);
    @memset(chunk1, 'x');
    // Stream 1 stays open (no END_STREAM); its 1,500 buffered bytes count
    // against the connection-wide cap until the stream is torn down.
    try client.writeHttp2Frame(0x0, 0, 1, chunk1);

    // Stream 1's send window was never touched by any outbound flush (it
    // was never dispatched), so a single max increment alone overflows it:
    // 65,535 + 0x7FFFFFFF > maxInt(i32).
    var inc: [4]u8 = undefined;
    std.mem.writeInt(u32, inc[0..4], 0x7FFFFFFF, .big);
    try client.writeHttp2Frame(0x8, 0, 1, inc[0..]);

    var saw_rst_stream1 = false;
    var frame_count: usize = 0;
    while (frame_count < 16 and !saw_rst_stream1) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);
        switch (frame.typ) {
            0x4 => {
                if ((frame.flags & 0x1) == 0) try client.writeHttp2Frame(0x4, 0x1, 0, &.{});
            },
            0x3 => { // RST_STREAM
                if (frame.stream_id == 1) saw_rst_stream1 = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_rst_stream1);

    // On the *same* connection: if stream 1's RST_STREAM cleanup didn't
    // release its bytes from the connection-memory accounting, this
    // well-under-cap request would be spuriously rejected too
    // (1,500 stale + 1,500 new > 2,000 cap).
    const headers3 = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/h2-overflow-mem-3" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const request_block3 = try hpack.encodeLiteralHeaderBlock(allocator, headers3[0..]);
    defer allocator.free(request_block3);
    try client.writeHttp2Frame(0x1, 0x4, 3, request_block3); // END_HEADERS only, body follows

    const chunk3 = try allocator.alloc(u8, 1500);
    defer allocator.free(chunk3);
    @memset(chunk3, 'y');
    try client.writeHttp2Frame(0x0, 0x1, 3, chunk3); // END_STREAM

    var stream3_body = std.array_list.Managed(u8).init(allocator);
    defer stream3_body.deinit();
    var stream3_done = false;

    frame_count = 0;
    while (frame_count < 16 and !stream3_done) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);
        switch (frame.typ) {
            0x4 => {
                if ((frame.flags & 0x1) == 0) try client.writeHttp2Frame(0x4, 0x1, 0, &.{});
            },
            0x0 => {
                if (frame.stream_id == 3) {
                    try stream3_body.appendSlice(frame.payload);
                    if ((frame.flags & 0x1) != 0) stream3_done = true;
                }
            },
            else => {},
        }
    }

    try std.testing.expect(stream3_done);
    try assertContains(stream3_body.items, "stream3-ok");
    try waitForUpstreamCount(&upstream3, 1, 2_000);
    try std.testing.expectEqual(@as(u32, 1), upstream3.requestCount());
    try std.testing.expectEqual(@as(u32, 0), upstream1.requestCount());
}

test "interop.h2.proxy_response_waits_for_window_update" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const large_response = try allocator.alloc(u8, 80 * 1024);
    defer allocator.free(large_response);
    for (large_response, 0..) |*b, i| {
        b.* = @as(u8, 'a') + @as(u8, @intCast(i % 26));
    }

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = large_response,
        .connection_header = "close",
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-large {{
        \\    proxy_pass http://{s}:{d}/h2-large;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-large" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const body = try pureZigH2GetBodyWithWindowUpdates(allocator, tardigrade.port, headers[0..]);
    defer allocator.free(body);
    try std.testing.expectEqualStrings(large_response, body);
    try waitForUpstreamCount(&upstream, 1, 2_000);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
}

test "interop.h2.proxy_multiplexed_streams_complete_after_window_update" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const large_response = try allocator.alloc(u8, 80 * 1024);
    defer allocator.free(large_response);
    for (large_response, 0..) |*b, i| {
        b.* = @as(u8, 'a') + @as(u8, @intCast(i % 26));
    }

    var large_upstream = try UpstreamServer.start(allocator, &.{.{
        .body = large_response,
        .connection_header = "close",
    }});
    defer large_upstream.stop();
    try large_upstream.run();

    var small_upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "h2-mux-small-body",
        .connection_header = "close",
    }});
    defer small_upstream.stop();
    try small_upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-mux-large {{
        \\    proxy_pass http://{s}:{d}/h2-mux-large;
        \\}}
        \\
        \\location = /h2-mux-small {{
        \\    proxy_pass http://{s}:{d}/h2-mux-small;
        \\}}
    , .{ test_host, large_upstream.port(), test_host, small_upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();
    try large_upstream.resetCapture();
    try small_upstream.resetCapture();

    const client = try PureZigTlsClient.create(allocator, tardigrade.port, "h2");
    defer client.destroy();

    try client.writeAllPlain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try client.writeHttp2Frame(0x4, 0, 0, &.{}); // client SETTINGS

    // Stream 1: a response bigger than the 65,535-byte default connection
    // and stream send windows, so it blocks mid-flight on the server side.
    const large_headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-mux-large" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const large_block = try hpack.encodeLiteralHeaderBlock(allocator, large_headers[0..]);
    defer allocator.free(large_block);
    try client.writeHttp2Frame(0x1, 0x1 | 0x4, 1, large_block); // END_STREAM | END_HEADERS

    // Stream 3: sent right behind stream 1, while its response is still
    // flow-control blocked server-side. A response writer that reads the
    // connection itself (instead of leaving the central frame loop as the
    // sole reader) would consume and drop these HEADERS.
    const small_headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-mux-small" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const small_block = try hpack.encodeLiteralHeaderBlock(allocator, small_headers[0..]);
    defer allocator.free(small_block);
    try client.writeHttp2Frame(0x1, 0x1 | 0x4, 3, small_block); // END_STREAM | END_HEADERS

    var stream1_body = std.array_list.Managed(u8).init(allocator);
    defer stream1_body.deinit();
    var stream3_body = std.array_list.Managed(u8).init(allocator);
    defer stream3_body.deinit();
    var stream1_done = false;
    var stream3_done = false;
    var granted_more_credit = false;

    var frame_count: usize = 0;
    while (frame_count < 64 and !(stream1_done and stream3_done)) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);

        switch (frame.typ) {
            0x4 => { // SETTINGS
                if ((frame.flags & 0x1) == 0) try client.writeHttp2Frame(0x4, 0x1, 0, &.{});
            },
            0x0 => { // DATA
                if (frame.stream_id == 1) {
                    try stream1_body.appendSlice(frame.payload);
                    if ((frame.flags & 0x1) != 0) stream1_done = true;
                } else if (frame.stream_id == 3) {
                    try stream3_body.appendSlice(frame.payload);
                    if ((frame.flags & 0x1) != 0) stream3_done = true;
                }
                // Once stream 1 has produced its initial (blocked) burst,
                // grant enough credit on both the connection and stream 1
                // for everything outstanding to finish.
                if (!granted_more_credit and stream1_body.items.len > 0 and !stream1_done) {
                    granted_more_credit = true;
                    var inc: [4]u8 = undefined;
                    std.mem.writeInt(u32, inc[0..4], @as(u32, @intCast(large_response.len)), .big);
                    try client.writeHttp2Frame(0x8, 0, 0, inc[0..]); // connection WINDOW_UPDATE
                    try client.writeHttp2Frame(0x8, 0, 1, inc[0..]); // stream 1 WINDOW_UPDATE
                }
            },
            else => {},
        }
    }

    try std.testing.expect(stream1_done);
    try std.testing.expect(stream3_done);
    try std.testing.expectEqualStrings(large_response, stream1_body.items);
    try std.testing.expectEqualStrings("h2-mux-small-body", stream3_body.items);
    try waitForUpstreamCount(&large_upstream, 1, 2_000);
    try waitForUpstreamCount(&small_upstream, 1, 2_000);
    try std.testing.expectEqual(@as(u32, 1), large_upstream.requestCount());
    try std.testing.expectEqual(@as(u32, 1), small_upstream.requestCount());
}

test "interop.h2.proxy_response_respects_peer_initial_window_size" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const large_response = try allocator.alloc(u8, 20 * 1024);
    defer allocator.free(large_response);
    for (large_response, 0..) |*b, i| {
        b.* = @as(u8, 'a') + @as(u8, @intCast(i % 26));
    }

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = large_response,
        .connection_header = "close",
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-small-window {{
        \\    proxy_pass http://{s}:{d}/h2-small-window;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const client = try PureZigTlsClient.create(allocator, tardigrade.port, "h2");
    defer client.destroy();

    try client.writeAllPlain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    // Advertise a 1 KiB initial stream window before opening any stream --
    // the server must honor it as the DATA sender rather than assuming its
    // own hard-coded default.
    var settings_payload: [6]u8 = undefined;
    std.mem.writeInt(u16, settings_payload[0..2], 0x4, .big);
    std.mem.writeInt(u32, settings_payload[2..6], 1024, .big);
    try client.writeHttp2Frame(0x4, 0, 0, settings_payload[0..]);

    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-small-window" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const request_block = try hpack.encodeLiteralHeaderBlock(allocator, headers[0..]);
    defer allocator.free(request_block);
    try client.writeHttp2Frame(0x1, 0x1 | 0x4, 1, request_block); // END_STREAM | END_HEADERS

    var received = std.array_list.Managed(u8).init(allocator);
    defer received.deinit();
    var done = false;
    var granted_more = false;

    var frame_count: usize = 0;
    while (frame_count < 64 and !done) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);
        switch (frame.typ) {
            0x4 => {
                if ((frame.flags & 0x1) == 0) try client.writeHttp2Frame(0x4, 0x1, 0, &.{});
            },
            0x0 => {
                if (frame.stream_id == 1) {
                    try received.appendSlice(frame.payload);
                    if ((frame.flags & 0x1) != 0) done = true;
                    if (!granted_more and !done) {
                        // Must never emit more than the 1 KiB grant before
                        // any WINDOW_UPDATE arrives.
                        try std.testing.expect(received.items.len <= 1024);
                        if (received.items.len == 1024) {
                            granted_more = true;
                            var inc: [4]u8 = undefined;
                            std.mem.writeInt(u32, inc[0..4], @as(u32, @intCast(large_response.len)), .big);
                            try client.writeHttp2Frame(0x8, 0, 0, inc[0..]); // connection WINDOW_UPDATE
                            try client.writeHttp2Frame(0x8, 0, 1, inc[0..]); // stream 1 WINDOW_UPDATE
                        }
                    }
                }
            },
            else => {},
        }
    }

    try std.testing.expect(done);
    try std.testing.expectEqualStrings(large_response, received.items);
    try waitForUpstreamCount(&upstream, 1, 2_000);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
}

test "interop.h2.window_update_connection_overflow_sends_goaway" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();

    const client = try PureZigTlsClient.create(allocator, tardigrade.port, "h2");
    defer client.destroy();

    try client.writeAllPlain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try client.writeHttp2Frame(0x4, 0, 0, &.{}); // client SETTINGS

    // Finish the initial SETTINGS/ACK handshake before injecting the
    // overflowing WINDOW_UPDATE. Interleaving the two races the server's
    // GOAWAY-triggered teardown against the client's own SETTINGS ACK: on
    // some schedules the connection closes before the ACK write lands,
    // which the test would otherwise misreport as a harness socket error
    // rather than as evidence about the (already-correct) GOAWAY behavior.
    var saw_server_settings = false;
    var saw_client_settings_ack = false;
    var setup_frame_count: usize = 0;
    while ((!saw_server_settings or !saw_client_settings_ack) and setup_frame_count < 16) : (setup_frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);
        if (frame.typ != 0x4) continue;
        if ((frame.flags & 0x1) != 0) {
            saw_client_settings_ack = true;
        } else {
            saw_server_settings = true;
            try client.writeHttp2Frame(0x4, 0x1, 0, &.{});
        }
    }
    try std.testing.expect(saw_server_settings);
    try std.testing.expect(saw_client_settings_ack);

    // The connection-level window starts at 65,535; this legal 31-bit
    // increment alone pushes it past 2^31-1.
    var inc: [4]u8 = undefined;
    std.mem.writeInt(u32, inc[0..4], 0x7FFFFFFF, .big);
    try client.writeHttp2Frame(0x8, 0, 0, inc[0..]);

    // Past this point the client sends nothing further: it only waits for
    // and validates the server's GOAWAY. Sending a SETTINGS ACK here would
    // reopen the same teardown race this test exists to close.
    var saw_goaway = false;
    var frame_count: usize = 0;
    while (frame_count < 16 and !saw_goaway) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);
        switch (frame.typ) {
            0x7 => { // GOAWAY
                try std.testing.expect(frame.payload.len >= 8);
                const err_code = std.mem.readInt(u32, frame.payload[4..8], .big);
                try std.testing.expectEqual(@as(u32, 3), err_code); // FLOW_CONTROL_ERROR
                saw_goaway = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_goaway);
}

test "interop.h2.window_update_stream_overflow_sends_rst_stream" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    // Large enough that stream 1's response is still flow-control blocked
    // (and therefore still tracked in the server's stream table) when the
    // overflowing WINDOW_UPDATE for that same stream arrives -- a response
    // that completed immediately would already have been cleaned up.
    const large_response = try allocator.alloc(u8, 80 * 1024);
    defer allocator.free(large_response);
    for (large_response, 0..) |*b, i| {
        b.* = @as(u8, 'a') + @as(u8, @intCast(i % 26));
    }

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = large_response,
        .connection_header = "close",
    }});
    defer upstream.stop();
    try upstream.run();

    // The native H2 listener only dispatches `proxy_pass` locations (a
    // `return`-style location like `/healthz` isn't reachable over H2 and
    // would just 404), so stream 3 needs its own real proxy_pass target.
    var other_upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "h2-stream-overflow-other-body",
        .connection_header = "close",
    }});
    defer other_upstream.stop();
    try other_upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-stream-overflow {{
        \\    proxy_pass http://{s}:{d}/h2-stream-overflow;
        \\}}
        \\
        \\location = /h2-stream-overflow-other {{
        \\    proxy_pass http://{s}:{d}/h2-stream-overflow-other;
        \\}}
    , .{ test_host, upstream.port(), test_host, other_upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();

    const client = try PureZigTlsClient.create(allocator, tardigrade.port, "h2");
    defer client.destroy();

    try client.writeAllPlain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try client.writeHttp2Frame(0x4, 0, 0, &.{}); // client SETTINGS

    const headers1 = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-stream-overflow" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const request_block1 = try hpack.encodeLiteralHeaderBlock(allocator, headers1[0..]);
    defer allocator.free(request_block1);
    try client.writeHttp2Frame(0x1, 0x1 | 0x4, 1, request_block1); // END_STREAM | END_HEADERS

    // The connection itself must survive: a second, unrelated stream should
    // still be served normally afterward.
    const headers3 = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-stream-overflow-other" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const request_block3 = try hpack.encodeLiteralHeaderBlock(allocator, headers3[0..]);
    defer allocator.free(request_block3);
    try client.writeHttp2Frame(0x1, 0x1 | 0x4, 3, request_block3);

    var saw_rst_stream1 = false;
    var stream1_bytes: usize = 0;
    var stream3_body = std.array_list.Managed(u8).init(allocator);
    defer stream3_body.deinit();
    var stream3_done = false;
    // By the time stream 1's blocked burst is observed, its window has
    // already been fully drained to 0, so a single max (0x7FFFFFFF)
    // increment only reaches exactly maxInt(i32) -- not past it. Two
    // back-to-back max increments, sent reactively (not blasted upfront
    // before any read, which risks a write/read deadlock against the
    // server's own blocked ~64 KiB burst), are needed to actually overflow.
    var sent_overflow_updates = false;

    var frame_count: usize = 0;
    while (frame_count < 64 and !(saw_rst_stream1 and stream3_done)) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);
        switch (frame.typ) {
            0x4 => {
                if ((frame.flags & 0x1) == 0) try client.writeHttp2Frame(0x4, 0x1, 0, &.{});
            },
            0x3 => { // RST_STREAM
                if (frame.stream_id == 1) {
                    try std.testing.expect(frame.payload.len >= 4);
                    const err_code = std.mem.readInt(u32, frame.payload[0..4], .big);
                    try std.testing.expectEqual(@as(u32, 3), err_code); // FLOW_CONTROL_ERROR
                    saw_rst_stream1 = true;
                }
            },
            0x0 => { // DATA
                if (frame.stream_id == 1) {
                    stream1_bytes += frame.payload.len;
                    if (!sent_overflow_updates and stream1_bytes > 0) {
                        sent_overflow_updates = true;
                        var inc: [4]u8 = undefined;
                        std.mem.writeInt(u32, inc[0..4], 0x7FFFFFFF, .big);
                        try client.writeHttp2Frame(0x8, 0, 1, inc[0..]);
                        try client.writeHttp2Frame(0x8, 0, 1, inc[0..]);
                        // The connection-level send window is shared across
                        // every stream, and stream 1's burst already drained
                        // it to 0. Stream 3's own (untouched) response is
                        // therefore also parked pending flow control -- it
                        // needs its own, non-overflowing connection-level
                        // grant to complete, independent of stream 1's fate.
                        var conn_inc: [4]u8 = undefined;
                        std.mem.writeInt(u32, conn_inc[0..4], 4096, .big);
                        try client.writeHttp2Frame(0x8, 0, 0, conn_inc[0..]);
                    }
                } else if (frame.stream_id == 3) {
                    try stream3_body.appendSlice(frame.payload);
                    if ((frame.flags & 0x1) != 0) stream3_done = true;
                }
            },
            else => {},
        }
    }

    try std.testing.expect(saw_rst_stream1);
    try std.testing.expect(stream3_done);
    try assertContains(stream3_body.items, "h2-stream-overflow-other-body");
    try waitForUpstreamCount(&other_upstream, 1, 2_000);
    try std.testing.expectEqual(@as(u32, 1), other_upstream.requestCount());
}

test "interop.h2.proxy_acl_denial_has_no_upstream_side_effect" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-acl {{
        \\    proxy_pass http://{s}:{d}/h2-acl;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_ACCESS_CONTROL", .value = "deny 127.0.0.1/32" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-acl" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const body = try pureZigH2GetBody(allocator, tardigrade.port, headers[0..]);
    defer allocator.free(body);
    try assertContains(body, "\"code\":\"forbidden\"");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.h2.proxy_rate_limit_denial_has_no_upstream_side_effect" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "rate-ok" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-rate {{
        \\    proxy_pass http://{s}:{d}/h2-rate;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_RATE_LIMIT_RPS", .value = "0.001" },
            .{ .name = "TARDIGRADE_RATE_LIMIT_BURST", .value = "2" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-rate" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const allowed_body = try pureZigH2GetBody(allocator, tardigrade.port, headers[0..]);
    defer allocator.free(allowed_body);
    try assertContains(allowed_body, "rate-ok");
    try waitForUpstreamCount(&upstream, 1, 2_000);
    try upstream.resetCapture();

    const denied_body = try pureZigH2GetBody(allocator, tardigrade.port, headers[0..]);
    defer allocator.free(denied_body);
    try assertContains(denied_body, "\"code\":\"rate_limited\"");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.h2.proxy_rate_limit_is_identity_scoped" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "identity-rate-ok" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-identity-rate {{
        \\    proxy_pass http://{s}:{d}/h2-identity-rate;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_RATE_LIMIT_RPS", .value = "0.001" },
            .{ .name = "TARDIGRADE_RATE_LIMIT_BURST", .value = "1" },
            // sha256("integration-token") and sha256("integration-token-2").
            .{
                .name = "TARDIGRADE_AUTH_TOKEN_HASHES",
                .value = "521bc8ca01307d0189b55a19da738e39c7204f7077e0076e803026e32b2f9383,633f4358ff60604f75ccd699fc0f9cf6c6e8d3554c3623dd824bd9011d99fe12",
            },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const headers_identity1 = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-identity-rate" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
        .{ .name = "authorization", .value = "Bearer integration-token" },
    };
    const headers_identity2 = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-identity-rate" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
        .{ .name = "authorization", .value = "Bearer integration-token-2" },
    };

    // The first request from identity 1 consumes its single-request burst.
    const first = try pureZigH2GetBody(allocator, tardigrade.port, headers_identity1[0..]);
    defer allocator.free(first);
    try assertContains(first, "identity-rate-ok");

    // A second, immediate request from the *same* identity is rate-limited.
    const second = try pureZigH2GetBody(allocator, tardigrade.port, headers_identity1[0..]);
    defer allocator.free(second);
    try assertContains(second, "\"code\":\"rate_limited\"");

    // A request from a *different* identity -- from the same client IP,
    // within the same window -- must not share identity 1's bucket. If H2
    // still rate-limited by IP alone (identity always null), this would
    // also 429.
    const third = try pureZigH2GetBody(allocator, tardigrade.port, headers_identity2[0..]);
    defer allocator.free(third);
    try assertContains(third, "identity-rate-ok");

    try waitForUpstreamCount(&upstream, 2, 2_000);
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());
}

test "interop.h2.proxy_retry_orchestration_fails_closed" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-retry {{
        \\    proxy_pass http://{s}:{d}/h2-retry;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS", .value = "2" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-retry" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const body = try pureZigH2GetBody(allocator, tardigrade.port, headers[0..]);
    defer allocator.free(body);
    try assertContains(body, "\"code\":\"h2_proxy_policy_unsupported\"");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.h2.proxy_passive_health_tracking_fails_closed" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-passive-health {{
        \\    proxy_pass http://{s}:{d}/h2-passive-health;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
            // Passive health is opt-in; once configured, H1's
            // handleLocationProxyPass wrapper records failure/success around
            // every proxied request. The direct H2 executor has no equivalent,
            // so it must fail closed rather than silently never participating.
            .{ .name = "TARDIGRADE_UPSTREAM_MAX_FAILS", .value = "3" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-passive-health" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const body = try pureZigH2GetBody(allocator, tardigrade.port, headers[0..]);
    defer allocator.free(body);
    try assertContains(body, "\"code\":\"h2_proxy_policy_unsupported\"");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.h2.proxy_circuit_breaker_fails_closed" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-circuit-breaker {{
        \\    proxy_pass http://{s}:{d}/h2-circuit-breaker;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_UPSTREAM_MAX_FAILS", .value = "0" },
            .{ .name = "TARDIGRADE_CB_THRESHOLD", .value = "3" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-circuit-breaker" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const body = try pureZigH2GetBody(allocator, tardigrade.port, headers[0..]);
    defer allocator.free(body);
    try assertContains(body, "\"code\":\"h2_proxy_policy_unsupported\"");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.h2.proxy_pre_route_middleware_fails_closed" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-mirror {{
        \\    proxy_pass http://{s}:{d}/h2-mirror;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
            // A mirror rule is pre-route middleware H1 runs via
            // `runMiddlewarePipeline` before any proxy side effect. It need
            // not even match this request's path -- its mere presence in the
            // config means H1 and H2 could diverge on this route, so the
            // narrow H2 executor must fail closed whenever *any* such rule
            // is configured, not just when it happens to apply here.
            .{ .name = "TARDIGRADE_MIRROR_RULES", .value = "POST|^/never-matches$|http://127.0.0.1:9/mirror" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-mirror" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const body = try pureZigH2GetBody(allocator, tardigrade.port, headers[0..]);
    defer allocator.free(body);
    try assertContains(body, "\"code\":\"h2_proxy_policy_unsupported\"");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.h2.proxy_location_streaming_override_fails_closed" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "must-not-run" }});
    defer upstream.stop();
    try upstream.run();

    // The global streaming mode stays at its "off" default; only this
    // location overrides it to `full`. The fail-closed check must inspect
    // the matched location's *effective* policy, not just the global mode,
    // or this override would silently bypass it over H2.
    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location = /h2-stream-override {{
        \\    proxy_pass http://{s}:{d}/h2-stream-override;
        \\    proxy_streaming full;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-stream-override" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
    };
    const body = try pureZigH2GetBody(allocator, tardigrade.port, headers[0..]);
    defer allocator.free(body);
    try assertContains(body, "\"code\":\"h2_proxy_policy_unsupported\"");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "interop.openssl.ticket.expired" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
            // Shortest allowed lifetime so a bounded, real sleep (not a
            // simulated clock) proves expiry deterministically.
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_TICKET_LIFETIME_SECONDS", .value = "1" },
        },
    });
    defer tardigrade.stop();

    const connect_arg = try opensslConnectArg(allocator, tardigrade.port);
    defer allocator.free(connect_arg);
    const sess_path = try opensslSessionPath(allocator, tardigrade.port, "ticket-expired");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};

    var first = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        sess_path,
    }, openssl_health_request, 10_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try assertContains(first.stdout, "New, TLSv1.3");

    // Advance past the 1-second ticket lifetime on the real wall clock the
    // production runtime uses (`systemNowUnixMs`) -- there is no injectable
    // clock at this external boundary.
    compat.sleepNs(2 * std.time.ns_per_s);

    var second = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_in",
        sess_path,
    }, openssl_health_request, 10_000);
    defer second.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(second.outcome));
    // The expired ticket must not resume: a full handshake, not "Reused".
    try assertContains(second.stdout, "New, TLSv1.3");
    // Connection remains usable via full handshake.
    try assertContains(second.stdout, "HTTP/1.1 200 OK");
    try assertContains(second.stdout, "alive");

    // A fresh, usable ticket may still be issued afterward.
    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try std.testing.expect((prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_ticket_issue_total", &.{
        "transport=\"record\"",
        "mode=\"stateful\"",
        "result=\"success\"",
    }) orelse 0) >= 2);
    // The expired-ticket reconnect must never have been counted as accepted.
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0);
}

test "interop.openssl.sni_mismatch" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    // The appliance TLS profile (the only profile the native listener builds
    // under, see `requireNativeTlsProfile`) supports exactly one identity --
    // `TARDIGRADE_TLS_SNI_CERTS` is rejected outright at startup. So "SNI
    // mismatch" here means the only meaningful, honest external case: a
    // client presenting any SNI other than the configured one, ticket or
    // not, and proving the ticket does not somehow bypass that gate.
    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
        },
    });
    defer tardigrade.stop();

    const connect_arg = try opensslConnectArg(allocator, tardigrade.port);
    defer allocator.free(connect_arg);
    const sess_path = try opensslSessionPath(allocator, tardigrade.port, "sni-mismatch");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};

    var first = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        sess_path,
    }, openssl_health_request, 10_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try assertContains(first.stdout, "HTTP/1.1 200 OK");

    var mismatch = try runOpenssl(allocator, &.{
        "s_client",             "-connect", connect_arg,
        "-alpn",                "http/1.1", "-servername",
        "unknown.example.test", "-tls1_3",  "-sess_in",
        sess_path,
    }, openssl_health_request, 10_000);
    defer mismatch.deinit(allocator);
    // Deterministic rejection (RFC 9846 handshake_failure), not a silently
    // authenticated ticket: no request is ever served under the wrong name.
    try std.testing.expect(!containsSubstring(mismatch.stdout, "HTTP/1.1 200"));
    try std.testing.expect(!containsSubstring(mismatch.stdout, "alive"));
    try std.testing.expect(containsSubstring(mismatch.stdout, "alert") or containsSubstring(mismatch.stderr, "alert"));
    // No secret ticket/PSK material in the failure diagnostics.
    try std.testing.expect(!containsSubstring(mismatch.stdout, "TLS session ticket") and !containsSubstring(mismatch.stderr, "TLS session ticket"));

    // The listener remains usable via the correct SNI afterward.
    var recovered = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-quiet",
    }, openssl_health_request, 10_000);
    defer recovered.deinit(allocator);
    try assertContains(recovered.stdout, "HTTP/1.1 200 OK");

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0);
}

test "interop.openssl.alpn_mismatch" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();

    const connect_arg = try opensslConnectArg(allocator, tardigrade.port);
    defer allocator.free(connect_arg);
    const sess_path = try opensslSessionPath(allocator, tardigrade.port, "alpn-mismatch");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};

    // Ticket obtained under h2.
    var first = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "h2",       "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        sess_path,
    }, "", 10_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try assertContains(first.stdout, "ALPN protocol: h2");

    // Reconnect offering only http/1.1: the old h2-scoped ticket must not be
    // silently reused under a different negotiated protocol.
    var second = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_in",
        sess_path,
    }, openssl_health_request, 10_000);
    defer second.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(second.outcome));
    try assertContains(second.stdout, "New, TLSv1.3");
    try assertContains(second.stdout, "ALPN protocol: http/1.1");
    try assertContains(second.stdout, "HTTP/1.1 200 OK");
    try assertContains(second.stdout, "alive");

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0);
}

// #369/#521: a resumption-specific external cipher mismatch is unreachable
// through the production native TLS listener today. The native profile only
// advertises TLS_AES_128_GCM_SHA256, and cipher negotiation completes before
// PSK/session compatibility evaluation. If the client still offers that suite,
// there is no mismatch; if the client excludes it, the ordinary handshake fails
// before a stored session can reach `session.evaluateCompatibility`. Keep the
// deterministic `ResumeMismatch.cipher_suite_mismatch` coverage in
// `src/tls/session.zig`, but do not add a test-only second cipher or mutate
// protected session state solely to force an impossible external row.

fn containsSubstring(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

test "interop.openssl.ticket.tampered" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            // Stateless mode specifically: the wire ticket is
            // `ticket_protection`'s AEAD-authenticated envelope, the
            // "opaque ticket/session bytes" the acceptance criteria for
            // this case calls out. (Stateful mode's ticket is instead a
            // random cache-lookup handle with no ciphertext to tamper --
            // corrupting it would just be an ordinary cache-miss test.)
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
        },
    });
    defer tardigrade.stop();

    const connect_arg = try opensslConnectArg(allocator, tardigrade.port);
    defer allocator.free(connect_arg);
    const sess_path = try opensslSessionPath(allocator, tardigrade.port, "ticket-tampered");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};

    var first = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        sess_path,
    }, openssl_health_request, 10_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));

    // Tamper the OpenSSL-managed session file's own opaque ticket bytes in
    // place, without touching any other field: locate `ticket_protection`'s
    // public, non-secret magic ("TDTK") with a plain byte search (not a
    // DER TLV walk of the surrounding structure), then flip a byte a fixed
    // distance past the envelope's own fixed header -- inside the actual
    // AEAD ciphertext, not the nonce or a byte a blind offset could land on
    // in a DER length/tag field instead (which would just make OpenSSL's
    // own local session-file loader refuse to even attempt the connection,
    // proving nothing about the server).
    const secret_fingerprint = try tamperOpensslTicketFile(allocator, sess_path);
    var fingerprint_hex: [64]u8 = undefined;
    const fingerprint_hex_slice = std.fmt.bufPrint(&fingerprint_hex, "{x}", .{secret_fingerprint}) catch unreachable;

    var second = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_arg,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_in",
        sess_path,
    }, openssl_health_request, 10_000);
    defer second.deinit(allocator);
    // No crash: the process still terminates normally either way.
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(second.outcome));
    // No successful resumption using the corrupted state.
    try std.testing.expect(!containsSubstring(second.stdout, "Reused, TLSv1.3"));
    // Safe fallback: connection remains usable via a full handshake.
    try assertContains(second.stdout, "New, TLSv1.3");
    try assertContains(second.stdout, "HTTP/1.1 200 OK");
    try assertContains(second.stdout, "alive");
    // No secret-bearing diagnostic: the still-authentic ciphertext bytes
    // right next to the flipped one never reach the server's own log, the
    // client's stdout, or the client's stderr. (Checking for the generic
    // string "TLS session ticket" instead would be the wrong assertion --
    // the fallback full handshake legitimately issues and displays a
    // brand-new ticket of its own, which is not a leak of the old one.)
    const server_log = try compat.cwd().readFileAlloc(allocator, tardigrade.log_path, 4 * 1024 * 1024);
    defer allocator.free(server_log);
    try std.testing.expect(!containsSubstring(server_log, fingerprint_hex_slice));
    try std.testing.expect(!containsSubstring(second.stdout, fingerprint_hex_slice));
    try std.testing.expect(!containsSubstring(second.stderr, fingerprint_hex_slice));

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0);
}

/// #369: decodes an OpenSSL-managed `-sess_out` PEM file's base64 body to
/// the raw `SSL_SESSION_ASN1` DER bytes.
fn decodeOpensslSessionFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const pem = try compat.cwd().readFileAlloc(allocator, path, 64 * 1024);
    defer allocator.free(pem);

    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    var lines = std.mem.splitScalar(u8, pem, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "-----")) continue;
        try body.appendSlice(std.mem.trim(u8, line, " \r\t"));
    }

    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(body.items);
    const raw = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(raw);
    try decoder.decode(raw, body.items);
    return raw;
}

/// #369: a non-secret-in-itself fingerprint of a captured ticket -- 32
/// authentic ciphertext bytes starting right at the ciphertext, i.e. right
/// after `ticket_protection`'s fixed 36-byte header (magic + version +
/// AEAD id + reserved + key id + nonce, see `writeHeader`) -- for asserting
/// that a log or diagnostic never echoes the actual secret ticket bytes,
/// as opposed to merely checking for the generic string "TLS session
/// ticket" (which a legitimate fresh reissue would also trip for an
/// unrelated reason).
fn opensslSessionTicketFingerprint(allocator: std.mem.Allocator, path: []const u8) ![32]u8 {
    const raw = try decodeOpensslSessionFile(allocator, path);
    defer allocator.free(raw);
    const ticket_start = std.mem.indexOf(u8, raw, "TDTK") orelse return error.TicketMagicNotFound;
    const ciphertext_start = ticket_start + tls_core.ticket_protection.fixed_header_len;
    if (ciphertext_start + 32 >= raw.len) return error.TicketTooShortToFingerprint;
    var fingerprint: [32]u8 = undefined;
    @memcpy(&fingerprint, raw[ciphertext_start..][0..32]);
    return fingerprint;
}

const OpenSslSessionSecrets = struct {
    allocator: std.mem.Allocator,
    resumption_psk_hex: []u8,
    ticket_hex: []u8,

    fn deinit(self: *OpenSslSessionSecrets) void {
        self.allocator.free(self.resumption_psk_hex);
        self.allocator.free(self.ticket_hex);
        self.* = undefined;
    }
};

fn opensslSessionSecrets(allocator: std.mem.Allocator, path: []const u8) !OpenSslSessionSecrets {
    var result = try runOpenssl(allocator, &.{
        "sess_id", "-in", path, "-text", "-noout",
    }, null, 10_000);
    defer result.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(result.outcome));

    const resumption_psk_hex = try opensslSessionLineHex(allocator, result.stdout, "Resumption PSK:");
    errdefer allocator.free(resumption_psk_hex);
    const ticket_hex = try opensslSessionTicketHexBlock(allocator, result.stdout);
    errdefer allocator.free(ticket_hex);

    return .{
        .allocator = allocator,
        .resumption_psk_hex = resumption_psk_hex,
        .ticket_hex = ticket_hex,
    };
}

fn opensslSessionLineHex(allocator: std.mem.Allocator, text: []const u8, marker: []const u8) ![]u8 {
    const marker_start = std.mem.indexOf(u8, text, marker) orelse return error.SessionSecretNotFound;
    const value_start = marker_start + marker.len;
    const line_end = std.mem.indexOfScalarPos(u8, text, value_start, '\n') orelse text.len;
    const raw = std.mem.trim(u8, text[value_start..line_end], " \t\r");
    try validateHexSecret(raw);
    return allocator.dupe(u8, raw);
}

fn opensslSessionTicketHexBlock(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const marker = "TLS session ticket:";
    const marker_start = std.mem.indexOf(u8, text, marker) orelse return error.SessionTicketNotFound;
    var lines = std.mem.splitScalar(u8, text[marker_start + marker.len ..], '\n');
    var hex = std.array_list.Managed(u8).init(allocator);
    errdefer hex.deinit();

    while (lines.next()) |line_raw| {
        const line = compat.trimRight(u8, line_raw, " \t\r");
        if (line.len == 0) {
            if (hex.items.len > 0) break;
            continue;
        }
        if (line[0] != ' ' and line[0] != '\t') {
            if (hex.items.len > 0) break;
            continue;
        }
        const dash = std.mem.indexOfScalar(u8, line, '-') orelse {
            if (hex.items.len > 0) break;
            continue;
        };
        const bytes_text = std.mem.trim(u8, line[dash + 1 ..], " \t");
        var consumed = false;
        var i: usize = 0;
        while (i < bytes_text.len) {
            const c = bytes_text[i];
            if (std.ascii.isHex(c)) {
                try hex.append(c);
                consumed = true;
            } else if (c == ' ' or c == '\t') {
                // OpenSSL separates hex byte pairs with spaces.
            } else {
                break;
            }
            i += 1;
        }
        if (!consumed and hex.items.len > 0) break;
    }

    try validateHexSecret(hex.items);
    return hex.toOwnedSlice();
}

fn validateHexSecret(raw: []const u8) !void {
    if (raw.len < 32 or raw.len % 2 != 0) return error.SessionSecretMalformed;
    for (raw) |c| {
        if (!std.ascii.isHex(c)) return error.SessionSecretMalformed;
    }
}

fn assertHexAbsentCaseInsensitive(allocator: std.mem.Allocator, haystack: []const u8, hex: []const u8) !void {
    const haystack_lower = try allocator.dupe(u8, haystack);
    defer allocator.free(haystack_lower);
    _ = std.ascii.lowerString(haystack_lower, haystack_lower);
    const hex_lower = try allocator.dupe(u8, hex);
    defer allocator.free(hex_lower);
    _ = std.ascii.lowerString(hex_lower, hex_lower);
    try std.testing.expect(!containsSubstring(haystack_lower, hex_lower));
}

const persistent_ticket_key_fixture_hex = "101112131415161718191a1b1c1d1e1f";
const persistent_ticket_key_fixture_id_hex = "000102030405060708090a0b0c0d0e0f";

fn persistentTicketKeySnapshotPath(allocator: std.mem.Allocator, port: u16, tag: []const u8) ![]u8 {
    const dir = try interopSecretsDir(allocator);
    defer allocator.free(dir);
    return std.fmt.allocPrint(allocator, "{s}/interop-{s}-{d}-ticket-keys.json", .{ dir, tag, port });
}

fn writePersistentTicketKeySnapshot(allocator: std.mem.Allocator, path: []const u8) !void {
    const now = compat.milliTimestamp();
    const snapshot = try std.fmt.allocPrint(
        allocator,
        "{{\"version\":1,\"generation\":1,\"keys\":[{{\"id\":\"000102030405060708090a0b0c0d0e0f\",\"aead\":\"aes_128_gcm\",\"key\":\"101112131415161718191a1b1c1d1e1f\",\"not_before_unix_ms\":{d},\"encrypt_until_unix_ms\":{d},\"decrypt_until_unix_ms\":{d},\"nonce_lease\":{{\"prefix\":\"51800000\",\"start\":0,\"end_exclusive\":4096}}}}]}}",
        .{ now - 60_000, now + 25 * 60 * 60 * 1000, now + 26 * 60 * 60 * 1000 },
    );
    defer {
        std.crypto.secureZero(u8, snapshot);
        allocator.free(snapshot);
    }
    try writeInteropSecretFile(path, snapshot);
}

/// #519: one key entry for a hand-built multi-key persistent snapshot file
/// (`writePersistentTicketKeySnapshotKeys`), used where the fixed single-key
/// `writePersistentTicketKeySnapshot` above (generation 1, one wide-open
/// validity window) can't express what a test needs: distinct not_before/
/// encrypt_until/decrypt_until windows per key (rotation overlap), or a
/// deliberately invalid nonce lease (failed-reload coverage).
const TicketKeyLeaseFixture = struct {
    prefix_hex: []const u8,
    start: u64,
    end_exclusive: u64,
};

const TicketKeyFixture = struct {
    id_hex: []const u8,
    key_hex: []const u8,
    not_before_unix_ms: i64,
    encrypt_until_unix_ms: i64,
    decrypt_until_unix_ms: i64,
    // `null` for a key that must never encrypt again (a retiring key
    // carried forward into a new generation decrypt-only, its
    // `encrypt_until` already in the past): `ReloadableKeyRing`'s per-key-id
    // ledger records the *full declared width* of every nonce lease a key
    // was ever installed with as that key's permanent high-water mark, not
    // merely how far its counter actually advanced -- so replaying the same
    // (or any non-advanced) lease range for a key that already used it in a
    // prior generation is rejected as `OverlappingNonceLease`, even though
    // it is the very same key, unchanged. A retiring key has no need to
    // encrypt again, so it needs no lease at all; this is exactly the shape
    // `persistentKeyConfig(&key_n, ..., null)` uses for the rotated-out key
    // in `resumption_runtime.zig`'s own "#512 ... rotates, and retires old
    // tickets" unit test.
    nonce_lease: ?TicketKeyLeaseFixture = null,
};

fn writePersistentTicketKeySnapshotKeys(
    allocator: std.mem.Allocator,
    path: []const u8,
    generation: u64,
    keys: []const TicketKeyFixture,
) !void {
    var out = std.array_list.Managed(u8).init(allocator);
    defer {
        std.crypto.secureZero(u8, out.items);
        out.deinit();
    }
    try out.print("{{\"version\":1,\"generation\":{d},\"keys\":[", .{generation});
    for (keys, 0..) |k, i| {
        if (i > 0) try out.append(',');
        try out.print(
            "{{\"id\":\"{s}\",\"aead\":\"aes_128_gcm\",\"key\":\"{s}\",\"not_before_unix_ms\":{d},\"encrypt_until_unix_ms\":{d},\"decrypt_until_unix_ms\":{d}",
            .{ k.id_hex, k.key_hex, k.not_before_unix_ms, k.encrypt_until_unix_ms, k.decrypt_until_unix_ms },
        );
        if (k.nonce_lease) |lease| {
            try out.print(
                ",\"nonce_lease\":{{\"prefix\":\"{s}\",\"start\":{d},\"end_exclusive\":{d}}}",
                .{ lease.prefix_hex, lease.start, lease.end_exclusive },
            );
        }
        try out.append('}');
    }
    try out.appendSlice("]}");
    try writeInteropSecretFile(path, out.items);
}

/// #519: the durable, file-backed lease window `reserveNonceLeasesInFile`
/// (`ticket_key_snapshot.zig`) advances on every accepted startup/reload --
/// read back here, by key id, so `restart.persistent.ticket_survives` can
/// assert two independent process incarnations actually reserved disjoint
/// windows from the same on-disk file, rather than merely asserting each
/// process *worked*.
const LeaseWindow = struct { generation: u64, start: u64, end_exclusive: u64 };

fn readTicketKeyLeaseWindow(allocator: std.mem.Allocator, path: []const u8, id_hex: []const u8) !LeaseWindow {
    const bytes = try compat.cwd().readFileAlloc(allocator, path, 64 * 1024);
    defer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    const generation: u64 = @intCast(root.get("generation").?.integer);
    const keys = root.get("keys").?.array.items;
    for (keys) |key_value| {
        const key_obj = key_value.object;
        const id = (key_obj.get("id") orelse continue).string;
        if (!std.ascii.eqlIgnoreCase(id, id_hex)) continue;
        const lease = (key_obj.get("nonce_lease") orelse continue).object;
        return .{
            .generation = generation,
            .start = @intCast(lease.get("start").?.integer),
            .end_exclusive = @intCast(lease.get("end_exclusive").?.integer),
        };
    }
    return error.KeyIdNotFound;
}

/// #519: `ticket_protection.parseEnvelope`'s own fixed field offsets (magic
/// [0..4], version[4], aead[5], reserved[6..8], key_id[8..24], nonce
/// [24..36]) applied directly to a captured `ClientTicketState.ticket`'s raw
/// bytes -- the same public, non-secret envelope metadata
/// `tamperOpensslTicketFile` above locates by magic search, not the AEAD
/// ciphertext/tag that follows it. Used to prove restart/rotation lease
/// disjointness at the (key_id, nonce) granularity #519 asks for, without
/// ever inspecting the encrypted session state itself.
// `ticket_protection.zig`'s internal `provider.aead_nonce_len` (12, for the
// `aes_128_gcm` suite every fixture in this file uses) isn't re-exported
// through `tls_core`; the envelope's fixed field width is stable regardless.
const ticket_nonce_len = 12;

const TicketEnvelopeIds = struct {
    key_id: [tls_core.ticket_protection.key_id_len]u8,
    nonce: [ticket_nonce_len]u8,
};

fn extractTicketEnvelopeIds(ticket: *const tls_core.session.ClientTicketState) TicketEnvelopeIds {
    const raw = ticket.ticket.slice();
    var out: TicketEnvelopeIds = undefined;
    @memcpy(&out.key_id, raw[8..24]);
    @memcpy(&out.nonce, raw[24..36]);
    return out;
}

/// #520: the AEAD nonce's fixed 4-byte prefix (`TicketKeyLeaseFixture.
/// prefix_hex`) is immediately followed by the big-endian 8-byte counter
/// `NonceLease.reserve` actually draws from -- decoding it lets the
/// multi-process soak assert an issued ticket's counter falls inside a
/// specific reserved `[start, end_exclusive)` window, not merely that two
/// sampled nonces happen to differ.
fn ticketNonceCounter(ids: TicketEnvelopeIds) u64 {
    return std.mem.readInt(u64, ids.nonce[4..12], .big);
}

/// #520: O(n^2) is fine here -- every #520 case caps its ticket sample
/// count in the low tens (smoke) to low hundreds (heavy), never enough for
/// a quadratic scan over `(key_id, nonce)` tuples to matter, and a shared
/// `std.AutoHashMap` key type big enough to hold both fields would need
/// nearly as much bespoke plumbing as this direct comparison.
fn assertNoDuplicateTicketIds(tuples: []const TicketEnvelopeIds) !void {
    for (tuples, 0..) |a, i| {
        for (tuples[i + 1 ..]) |b| {
            const same = std.mem.eql(u8, &a.key_id, &b.key_id) and std.mem.eql(u8, &a.nonce, &b.nonce);
            try std.testing.expect(!same);
        }
    }
}

/// #520: which of the two lease windows a process installed at concurrent
/// startup is scheduling-dependent (whichever process wins the
/// `${path}.lock` race first reserves `[w, 2w)`; the other reserves
/// `[2w, 3w)`) -- the soak must not assume which one any given process
/// actually got, only that every ticket it issues stays inside exactly one
/// of the two, and that the two real processes land in different ones.
const ReservedWindow = struct { start: u64, end_exclusive: u64 };

fn resolveReservedWindow(counter: u64, lease_width: u64) !ReservedWindow {
    if (counter >= lease_width and counter < 2 * lease_width) return .{ .start = lease_width, .end_exclusive = 2 * lease_width };
    if (counter >= 2 * lease_width and counter < 3 * lease_width) return .{ .start = 2 * lease_width, .end_exclusive = 3 * lease_width };
    return error.NonceCounterOutsideReservedWindows;
}

/// #520: a real full handshake against `port`, capturing only the issued
/// ticket's public envelope ids -- the repeated shape Case 1's concurrent-
/// reservation and rotation phases both need many times over, factored out
/// rather than inlining a fresh capture closure at each call site the way
/// earlier #519 tests do (those each call it once or twice; #520 calls it
/// in loops).
fn issueTicketIds(allocator: std.mem.Allocator, port: u16) !TicketEnvelopeIds {
    const IdCapture = struct {
        ids: ?TicketEnvelopeIds = null,

        fn now(_: *anyopaque) i64 {
            return 2_000;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.ids = extractTicketEnvelopeIds(ticket);
        }
    };
    var capture = IdCapture{};
    const client = try PureZigTlsClient.createWithOptions(allocator, port, "http/1.1", "tardigrade.test", .{
        .ticket_consumer = .{ .ctx = &capture, .nowUnixMsFn = IdCapture.now, .onTicketFn = IdCapture.onTicket },
    });
    defer client.destroy();
    try client.writeAllPlain(openssl_health_request);
    const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(raw);
    try assertContains(raw, "HTTP/1.1 200 OK");
    return capture.ids orelse error.NoTicketIssued;
}

/// #520: same connection shape as `issueTicketIds`, but tolerates
/// best-effort issuance failure (`NonceLeaseExhausted`) by returning `null`
/// instead of erroring -- `soak.persistent.nonce_lease_exhaustion` drives a
/// batch of ordinary connections *through* the point where issuance starts
/// failing, and a failed issuance must not tear down the otherwise-valid
/// connection (asserted by the caller still checking for `200 OK` here).
fn issueTicketIdsOptional(allocator: std.mem.Allocator, port: u16) !?TicketEnvelopeIds {
    const IdCapture = struct {
        ids: ?TicketEnvelopeIds = null,

        fn now(_: *anyopaque) i64 {
            return 2_000;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.ids = extractTicketEnvelopeIds(ticket);
        }
    };
    var capture = IdCapture{};
    const client = try PureZigTlsClient.createWithOptions(allocator, port, "http/1.1", "tardigrade.test", .{
        .ticket_consumer = .{ .ctx = &capture, .nowUnixMsFn = IdCapture.now, .onTicketFn = IdCapture.onTicket },
    });
    defer client.destroy();
    try client.writeAllPlain(openssl_health_request);
    const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(raw);
    try assertContains(raw, "HTTP/1.1 200 OK");
    return capture.ids;
}

/// #520: issues a real ticket and clones it out to an owned, caller-freed
/// `ClientTicketState` -- the retained-sample-ticket shape Case 1's
/// rotation phases and Case 2's exhaustion case both need (offered again
/// later, across a reload or past exhaustion, to prove it still resumes).
fn issueAndRetainTicket(allocator: std.mem.Allocator, port: u16) !tls_core.session.ClientTicketState {
    const Capture = struct {
        allocator: std.mem.Allocator,
        retained: tls_core.session.ClientTicketState = .{},

        fn now(_: *anyopaque) i64 {
            return 2_000;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.retained.deinit();
            self.retained = .{};
            ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
        }
    };
    var capture = Capture{ .allocator = allocator };
    defer capture.retained.deinit();
    const client = try PureZigTlsClient.createWithOptions(allocator, port, "http/1.1", "tardigrade.test", .{
        .ticket_consumer = .{ .ctx = &capture, .nowUnixMsFn = Capture.now, .onTicketFn = Capture.onTicket },
    });
    defer client.destroy();
    try client.writeAllPlain(openssl_health_request);
    const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(raw);
    try assertContains(raw, "HTTP/1.1 200 OK");
    var out: tls_core.session.ClientTicketState = .{};
    try capture.retained.cloneInto(allocator, &out);
    return out;
}

/// #520: offers a clone of `ticket` (offering `ticket` itself would `move`
/// it out from under the caller, who typically still needs it for a later
/// offer in the same soak round) and asserts the resumption is actually PSK
/// -authenticated, not merely that the safe full-handshake fallback served
/// the request.
fn resumeTicketExpectAccepted(allocator: std.mem.Allocator, port: u16, ticket: *const tls_core.session.ClientTicketState) !void {
    var offer_clone: tls_core.session.ClientTicketState = .{};
    defer offer_clone.deinit();
    try ticket.cloneInto(allocator, &offer_clone);
    var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&offer_clone);
    errdefer offers.deinit();
    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2_500;
        }
    };
    const client = try PureZigTlsClient.createWithOptions(allocator, port, "http/1.1", "tardigrade.test", .{
        .psk_offers = &offers,
        .psk_now_ctx = &clock_dummy,
        .psk_now_fn = ClientClock.now,
    });
    defer client.destroy();
    try std.testing.expect(client.backend.core.psk_authenticated);
    try client.writeAllPlain(openssl_health_request);
    const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(raw);
    try assertContains(raw, "HTTP/1.1 200 OK");
}

/// #520: a one-shot labeled-metric read (unlike `waitForLabeledMetricAtLeast`,
/// which polls) -- used to capture a before/after baseline around a bounded
/// batch, per the exhaustion case's own "metrics-polling trap" note: a
/// delta across a batch, not a poll after every single connection.
fn currentLabeledMetric(allocator: std.mem.Allocator, port: u16, name: []const u8, labels: []const []const u8) !u64 {
    var metrics = try sendPureZigTlsHttp1Request(allocator, port, "/status/metrics");
    defer metrics.deinit();
    return prometheusLabeledMetricValue(metrics.body, name, labels) orelse 0;
}

/// #520: `edge_gateway.zig` logs this fixed, secret-free marker every
/// time a process is about to call `reserveNonceLeasesInFile` -- once at
/// startup, and once per SIGHUP reload -- so it accumulates one more
/// occurrence in a process's log per real reservation attempt over that
/// process's lifetime. Counting occurrences (not just presence) is what
/// lets a caller detect "this specific round's attempt has started",
/// not just "some attempt, ever, has started".
const reservation_attempt_marker = "persistent ticket-key reservation attempt starting";

fn countReservationAttemptMarkers(allocator: std.mem.Allocator, log_path: []const u8) usize {
    const log_data = compat.cwd().readFileAlloc(allocator, log_path, 16 * 1024 * 1024) catch return 0;
    defer allocator.free(log_data);
    var count: usize = 0;
    var idx: usize = 0;
    while (std.mem.indexOfPos(u8, log_data, idx, reservation_attempt_marker)) |pos| {
        count += 1;
        idx = pos + reservation_attempt_marker.len;
    }
    return count;
}

/// #520: the observable arrival signal for the concurrent-startup
/// reservation barrier -- polls a spawned-but-not-yet-waited-on process's
/// own log file (already captured from its earliest stderr output, per
/// `TardigradeProcess.spawn`'s `early_stderr` redirect, independent of
/// whether its HTTP listener has started serving yet) for at least
/// `minimum` occurrences of the marker `edge_gateway.zig` logs immediately
/// before calling `reserveNonceLeasesInFile` -- whose own first action is
/// acquiring `${path}.lock`. Waiting for this on *both* processes before
/// releasing a barrier lock the test holds is a real observed-arrival
/// condition, not a fixed delay: a fixed sleep can never rule out a
/// slower process reaching the lock attempt after the barrier was already
/// released, silently turning the intended race back into sequential
/// reservation. Used both for the initial concurrent-startup reservation
/// (`minimum = 1`) and, per round, to confirm *that round's* SIGHUP
/// handler specifically has reached the same point (`minimum` = the
/// count observed just before this round's signal was sent, plus one).
fn waitForReservationAttemptCount(allocator: std.mem.Allocator, log_path: []const u8, minimum: usize, timeout_ms: u64) !void {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        if (countReservationAttemptMarkers(allocator, log_path) >= minimum) return;
        compat.sleepNs(10 * std.time.ns_per_ms);
    }
    return error.ReservationAttemptNotObserved;
}

/// #520 heavy tier: keeps real full-handshake/ticket-issuance traffic
/// flowing against one process for as long as `stop` is clear, started
/// before either SIGHUP is sent and stopped only after both processes'
/// own `reload_accepted` has been confirmed -- so its collected samples
/// necessarily span the whole round, before and after the transition.
///
/// Every issued ticket is validated to belong to one of the round's two
/// known key ids (the complete outgoing or complete incoming generation,
/// never anything else) -- this is the only invariant a concurrently
/// running worker can check safely; the stricter "incoming key only
/// after *this process's own* `reload_accepted`" boundary is instead
/// proven by an explicit, synchronous, single-shot probe the main thread
/// issues immediately after observing that metric (see the round loop
/// below) -- sampling an in-flight worker's own notion of "before or
/// after acceptance" is inherently racy (a request can legitimately begin
/// before acceptance and only finish reading after it, or vice versa),
/// so it cannot establish that boundary correctly no matter which side of
/// the request it is sampled on.
///
/// Deliberately does *not* attempt to prove a worker *starts and
/// completes a brand-new connection* while the reload SIGHUP handler is
/// confirmed blocked on the shared reservation lock. `edge_gateway.run`'s
/// single-threaded event loop owns accepting and dispatching connections
/// as well as (synchronously) `hotReloadConfig`, so blocking that one
/// thread on the lock blocks *new* accepts for that process -- but
/// `edge_gateway.run` also has a separate `WorkerPool`, so a connection
/// *already* accepted and dispatched to a worker before the block began
/// can keep making progress regardless (see `GatedUpstream` below, which
/// proves exactly that with a request dispatched ahead of time and held
/// under this test's control). A `ChurnWorker`'s own next connection
/// attempt is always a *new* one with no such guarantee, so requiring it
/// to complete specifically while blocked would be requiring a new
/// accept during the one window that's provably unavailable. An earlier
/// revision required exactly that and reliably hung for the full bounded
/// test timeout, confirming new accepts really do stall -- the fix was
/// not to give up on proving overlap, but to prove it with a request
/// that was already in flight (`GatedUpstream`) rather than with churn's
/// own fresh reconnect loop.
///
/// `saw_outgoing`/`saw_incoming` are published only once a matching
/// ticket has *also* been retained in `results`, so a visible flag always
/// corresponds to a concrete sample -- the round loop waits for
/// `saw_outgoing` on both workers before ever touching the reservation
/// barrier (proving real pre-reload traffic without depending on thread
/// scheduling luck) and, symmetrically, for `saw_incoming` on both
/// workers only *after* the barrier is released and both processes have
/// independently reported `reload_accepted` (when their event loops are
/// again free to make socket progress) before stopping them -- so
/// `expectSpansBothGenerations` below is a redundant final consistency
/// check over the retained samples, not the primary proof.
///
/// Uses `std.heap.page_allocator` rather than `std.testing.allocator`:
/// the latter is not safe to call concurrently from multiple threads,
/// and `results`/`failure` are only ever read by the main thread after
/// `std.Thread.join()`, so no cross-thread synchronization on them is
/// needed (only the two atomic flags are read while the worker may still
/// be running). A worker records the first error it hits (an issuance
/// failure or an unexpected key id) and stops immediately, rather than
/// silently swallowing it and leaving the caller to mistake an empty
/// result set for a healthy run.
const ChurnWorker = struct {
    port: u16,
    stop: *std.atomic.Value(bool),
    outgoing_key_id_hex: []const u8,
    incoming_key_id_hex: []const u8,
    saw_outgoing: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    saw_incoming: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    results: std.array_list.Managed(TicketEnvelopeIds),
    failure: ?anyerror = null,

    fn init(port: u16, stop: *std.atomic.Value(bool), outgoing_key_id_hex: []const u8, incoming_key_id_hex: []const u8) ChurnWorker {
        return .{
            .port = port,
            .stop = stop,
            .outgoing_key_id_hex = outgoing_key_id_hex,
            .incoming_key_id_hex = incoming_key_id_hex,
            .results = std.array_list.Managed(TicketEnvelopeIds).init(std.heap.page_allocator),
        };
    }

    fn deinit(self: *ChurnWorker) void {
        self.results.deinit();
    }

    fn run(self: *ChurnWorker) void {
        while (!self.stop.load(.acquire)) {
            const ids = issueTicketIds(std.heap.page_allocator, self.port) catch |err| {
                // `WouldBlock` is transient local contention -- this
                // worker's own tight reconnect loop briefly outpacing the
                // single dispatched worker thread `TARDIGRADE_WORKER_
                // THREADS=1` provides (e.g. while the gated race request
                // above is deliberately occupying it), not a server-side
                // correctness failure. Retrying past it (with a short
                // pause so the retry doesn't just recreate the same
                // contention) keeps the proof honest without papering
                // over a real issuance/connection failure, which remains
                // fatal exactly as before.
                if (err == error.WouldBlock) {
                    compat.sleepNs(2 * std.time.ns_per_ms);
                    continue;
                }
                self.failure = err;
                return;
            };
            const hex = std.fmt.bytesToHex(ids.key_id, .lower);
            const is_incoming = std.mem.eql(u8, self.incoming_key_id_hex, &hex);
            const is_outgoing = std.mem.eql(u8, self.outgoing_key_id_hex, &hex);
            if (!is_incoming and !is_outgoing) {
                self.failure = error.ChurnObservedUnexpectedKeyId;
                return;
            }
            self.results.append(ids) catch |err| {
                self.failure = err;
                return;
            };
            // Published only after the successful ticket has also been
            // retained above, so a visible flag always corresponds to a
            // concrete sample in `results`.
            if (is_outgoing) self.saw_outgoing.store(true, .release);
            if (is_incoming) self.saw_incoming.store(true, .release);
        }
    }
};

/// #520: bounded wait for a `ChurnWorker` to have observed a successful
/// ticket from a given generation -- safe to call while the worker thread
/// is still running (a plain atomic flag, not `results.items.len`).
fn waitForChurnGenerationSeen(seen: *const std.atomic.Value(bool), timeout_ms: u64) !void {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        if (seen.load(.acquire)) return;
        compat.sleepNs(5 * std.time.ns_per_ms);
    }
    return error.ChurnGenerationNotObserved;
}

/// #520: asserts `tuples` contains at least one ticket sealed under each
/// of the two given key ids -- a final consistency check that the
/// retained sample set agrees with the `saw_outgoing`/`saw_incoming`
/// flags `waitForChurnGenerationSeen` already waited on; the achievable
/// proof that continuous churn traffic actually spanned a round's
/// generation transition, used in place of an unobservable "completed
/// while the reload handler was confirmed blocked" claim.
fn expectSpansBothGenerations(tuples: []const TicketEnvelopeIds, outgoing_key_id_hex: []const u8, incoming_key_id_hex: []const u8) !void {
    var saw_outgoing = false;
    var saw_incoming = false;
    for (tuples) |ids| {
        const hex = std.fmt.bytesToHex(ids.key_id, .lower);
        if (std.mem.eql(u8, outgoing_key_id_hex, &hex)) saw_outgoing = true;
        if (std.mem.eql(u8, incoming_key_id_hex, &hex)) saw_incoming = true;
    }
    try std.testing.expect(saw_outgoing);
    try std.testing.expect(saw_incoming);
}

/// #369: flips one byte inside the opaque ticket envelope of an
/// OpenSSL-managed `-sess_out` PEM file, in place. Locates
/// `ticket_protection`'s public, non-secret magic (`"TDTK"`) with a plain
/// byte search -- this is a magic-prefixed-blob search, not a DER TLV
/// walk of the surrounding `SSL_SESSION_ASN1` structure -- then flips a
/// byte a small, fixed distance past the envelope's fixed 36-byte header
/// (`ticket_protection.fixed_header_len`: magic/version/AEAD id/reserved/
/// key id/nonce), landing inside the actual AEAD ciphertext rather than
/// the nonce or a length-prefix byte a naive offset could hit instead.
fn tamperOpensslTicketFile(allocator: std.mem.Allocator, path: []const u8) ![32]u8 {
    const raw = try decodeOpensslSessionFile(allocator, path);
    defer allocator.free(raw);

    const magic = "TDTK";
    const ticket_start = std.mem.indexOf(u8, raw, magic) orelse return error.TicketMagicNotFound;
    const ciphertext_start = ticket_start + tls_core.ticket_protection.fixed_header_len;
    // A few bytes into the ciphertext, comfortably clear of the header
    // fields before it and the AEAD tag after it for any realistic
    // ticket size.
    const flip_at = ciphertext_start + 8;
    if (flip_at + 32 >= raw.len) return error.TicketTooShortToTamper;
    // A fingerprint of the still-authentic ciphertext right after the flip
    // point, captured before corrupting it, so the caller can assert this
    // secret material never reaches a log line -- not merely that the
    // string "TLS session ticket" is absent, which a normal fresh-ticket
    // reissue on the fallback handshake would trip for an unrelated reason.
    var fingerprint: [32]u8 = undefined;
    @memcpy(&fingerprint, raw[flip_at + 1 ..][0..32]);
    raw[flip_at] ^= 0xff;

    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(raw.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = encoder.encode(encoded, raw);

    var out = std.array_list.Managed(u8).init(allocator);
    defer out.deinit();
    try out.appendSlice("-----BEGIN SSL SESSION PARAMETERS-----\n");
    var i: usize = 0;
    while (i < encoded.len) : (i += 64) {
        try out.appendSlice(encoded[i..@min(i + 64, encoded.len)]);
        try out.append('\n');
    }
    try out.appendSlice("-----END SSL SESSION PARAMETERS-----\n");
    try compat.cwd().writeFile(.{ .sub_path = path, .data = out.items });
    return fingerprint;
}

/// #369: a throwaway self-signed Ed25519 identity for `restart.cert_change.
/// ticket_rejected`, generated at test time via a real `openssl req`
/// subprocess (mirroring `scripts/interop/gen-certs.sh`'s convention) rather
/// than checking in a fixture -- this test only needs *a* different key
/// under the *same* subject/SAN, not any particular one.
const GeneratedCert = struct {
    cert_path: []u8,
    key_path: []u8,
    allocator: std.mem.Allocator,

    fn deinit(self: *GeneratedCert) void {
        compat.cwd().deleteFile(self.cert_path) catch {};
        compat.cwd().deleteFile(self.key_path) catch {};
        self.allocator.free(self.cert_path);
        self.allocator.free(self.key_path);
        self.* = undefined;
    }
};

fn generateAlternateServerCert(allocator: std.mem.Allocator, server_name: []const u8) !GeneratedCert {
    const dir = try interopSecretsDir(allocator);
    defer allocator.free(dir);
    const unique = compat.milliTimestamp();
    const cert_path = try std.fmt.allocPrint(allocator, "{s}/interop-restart-cert-{d}.pem", .{ dir, unique });
    errdefer allocator.free(cert_path);
    // The private key: same reasoning as `interopSecretsDir` -- outside
    // any cached path even though it is a throwaway test-only identity.
    const key_path = try std.fmt.allocPrint(allocator, "{s}/interop-restart-key-{d}.pem", .{ dir, unique });
    errdefer allocator.free(key_path);
    const san_arg = try std.fmt.allocPrint(allocator, "subjectAltName=DNS:{s}", .{server_name});
    defer allocator.free(san_arg);
    const subj_arg = try std.fmt.allocPrint(allocator, "/CN={s}", .{server_name});
    defer allocator.free(subj_arg);

    // Deliberately *not* `runOpenssl`: that helper accepts exit codes {0,1}
    // for every caller, which is specifically an `s_client`
    // "unexpected eof while reading" shutdown-noise tolerance -- wrong for
    // `openssl req`, where exit 1 is a real failure. Checking only
    // `std.meta.activeTag(result.outcome) != .normal_exit` after routing
    // through that shared tolerance would have silently treated a failed
    // generation as success (the tag is `.normal_exit` regardless of *which*
    // accepted code it carries), leaving no cert file at `cert_path` for
    // `TardigradeProcess.start()` to load -- caught in CI (#511), not
    // locally, since the exact failure was environment-specific.
    // Ed25519 specifically: the appliance TLS profile's identity loader
    // (`appliance_credentials.zig`) hard-rejects any other leaf key
    // algorithm, so there is no alternative curve to substitute here (the
    // way a generic native-profile cert could use P-256). Callers must
    // gate on `requireOpensslEd25519` first -- macOS's system `openssl`
    // (what GitHub's macos-14 runner resolves to, with no Homebrew OpenSSL
    // preinstalled/linked) is LibreSSL, which cannot generate, load, or
    // sign with an Ed25519 key at all. `-nodes`, not `-noenc` -- the
    // latter is an OpenSSL-3.x-only spelling older/LibreSSL forks of
    // `req` don't recognize, for whatever installations do support
    // Ed25519 but predate that flag.
    var argv = [_][]const u8{
        "openssl", "req",     "-x509",                              "-newkey", "ed25519",
        "-keyout", key_path,  "-out",                               cert_path, "-days",
        "1",       "-nodes",  "-subj",                              subj_arg,  "-addext",
        san_arg,
        // Without an explicit override, this OpenSSL's default x509
        // extensions mark a self-signed cert as `CA:TRUE`, which the
        // appliance profile's strict leaf-certificate loader rejects
        // outright (`appliance_credentials.zig`: a CA cert is never a
        // valid leaf identity).
          "-addext", "basicConstraints=critical,CA:FALSE",
    };
    var result = try bounded_process.run(allocator, .{
        .argv = &argv,
        .stdout_limit = 64 * 1024,
        .stderr_limit = 64 * 1024,
        .deadline_ms = 10_000,
    });
    defer result.deinit(allocator);
    if (std.meta.activeTag(result.outcome) != .normal_exit or result.outcome.normal_exit != 0) {
        std.debug.print("openssl req (alternate cert generation) failed: {s}\n", .{result.diagnostic});
        return error.CertGenerationFailed;
    }

    // Ground truth, not another guess: different openssl builds encode a
    // "the same flags, the same algorithm" Ed25519 certificate differently
    // enough that Tardigrade's own strict appliance X.509 parser can still
    // reject it (`error.MalformedCertificateDer`) even once generation
    // itself succeeds -- hit twice in CI (#511) with two different openssl
    // builds on the same macOS runner class. Rather than guess a third
    // time at exactly which encoding quirk a given environment has, ask
    // the real validator directly via the production `tardi check`
    // subcommand (the same one `native TLS listener appliance check
    // command validates credentials without binding` already exercises)
    // and skip gracefully if it disagrees, instead of failing CI on an
    // environment-specific openssl encoding difference this test was
    // never meant to be about.
    try verifyApplianceAcceptsCredential(allocator, cert_path, key_path, server_name);

    return .{ .allocator = allocator, .cert_path = cert_path, .key_path = key_path };
}

fn verifyApplianceAcceptsCredential(allocator: std.mem.Allocator, cert_path: []const u8, key_path: []const u8, server_name: []const u8) !void {
    const config_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tardigrade-altcert-check-{d}.conf", .{compat.nanoTimestamp()});
    defer {
        compat.cwd().deleteFile(config_rel) catch {};
        allocator.free(config_rel);
    }
    try compat.cwd().writeFile(.{ .sub_path = config_rel, .data = "" });

    var env_map = try inheritedEnvMap(allocator);
    defer env_map.deinit();
    // `check` never binds a listener, so this port only needs to satisfy
    // ordinary range validation, not actually be free.
    try env_map.put("TARDIGRADE_LISTEN_HOST", test_host);
    try env_map.put("TARDIGRADE_LISTEN_PORT", "18080");
    try env_map.put("TARDIGRADE_TLS_CERT_PATH", cert_path);
    try env_map.put("TARDIGRADE_TLS_KEY_PATH", key_path);
    try env_map.put("TARDIGRADE_TLS_SERVER_NAME", server_name);

    // Through the same bounded spawn/wait/reap contract as every other
    // external process this suite drives -- `std.process.run` waits
    // synchronously with no deadline, which would let a `check` hang (a
    // parser/I/O regression, say) block this test until the outer CI job
    // timeout instead of failing with a useful diagnostic.
    var checked = try bounded_process.run(allocator, .{
        .argv = &.{ integration_options.tardigrade_bin_path, "check", config_rel },
        .environ_map = &env_map,
        .stdout_limit = 64 * 1024,
        .stderr_limit = 64 * 1024,
        .deadline_ms = 10_000,
    });
    defer checked.deinit(allocator);
    // "nonzero means this fixture is unsuitable -> skip" only after the
    // child has actually terminated within the bound above -- a timeout
    // or launch failure is a real test infrastructure problem and must
    // fail loudly, not be silently folded into the same skip path.
    //
    // `bounded_process` only classifies an exit as `.normal_exit` when the
    // code is in `accepted_exit_codes` (default `&.{0}`), so `check`'s
    // nonzero failure exit surfaces as `.unexpected_exit_code`, not
    // `.normal_exit(nonzero)` -- both branches below must be checked.
    if (std.meta.activeTag(checked.outcome) == .unexpected_exit_code) {
        return error.SkipZigTest;
    }
    if (std.meta.activeTag(checked.outcome) != .normal_exit) {
        std.debug.print("tardi check did not exit normally: {s}\n", .{checked.diagnostic});
        return error.ApplianceCheckDidNotExitNormally;
    }
}

test "restart.ephemeral.ticket_miss and restart.ephemeral.fresh_ticket" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
    ;
    // The currently supported restart policy is the ephemeral stateless
    // ticket key: a fresh process has no way to decrypt a ticket the
    // previous process issued (#510/#369 docs). Stateful mode's cache-miss
    // shape is a different, already-covered concern.
    const extra_env = &[_]EnvPair{
        .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
        .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
        .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
        .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
    };

    // 1-2: start process A, establish a connection, and obtain a ticket.
    var process_a = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = extra_env,
    });
    var process_a_running = true;
    defer if (process_a_running) process_a.stop();

    const connect_a = try opensslConnectArg(allocator, process_a.port);
    defer allocator.free(connect_a);
    const sess_path = try opensslSessionPath(allocator, process_a.port, "restart-ephemeral");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};

    var first = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_a,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        sess_path,
    }, openssl_health_request, 10_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try assertContains(first.stdout, "HTTP/1.1 200 OK");

    const fingerprint = try opensslSessionTicketFingerprint(allocator, sess_path);
    var fingerprint_hex: [64]u8 = undefined;
    const fingerprint_hex_slice = std.fmt.bufPrint(&fingerprint_hex, "{x}", .{fingerprint}) catch unreachable;
    // `stop()` frees and invalidates the whole struct, including
    // `log_path` -- capture an owned copy first so the log is still
    // readable after A is gone.
    const log_a_path = try allocator.dupe(u8, process_a.log_path);
    defer allocator.free(log_a_path);

    // 3: terminate process A cleanly -- a real process boundary, not
    // `Runtime.deinit()`/`Runtime.init()` reused inside one test object.
    process_a.stop();
    process_a_running = false;

    // 4: start process B with the same operator configuration. It gets its
    // own naturally fresh ephemeral stateless ticket key (a new process, no
    // shared memory with A) purely by existing as a separate process --
    // nothing here loads or carries over any state from A.
    var process_b = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = extra_env,
    });
    defer process_b.stop();

    const connect_b = try opensslConnectArg(allocator, process_b.port);
    defer allocator.free(connect_b);

    // 5-7: reconnect to B with A's ticket. It must resolve as a miss, not
    // authenticate, and the connection must remain usable via a full
    // handshake.
    var second = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_b,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_in",
        sess_path,
    }, openssl_health_request, 10_000);
    defer second.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(second.outcome));
    try assertContains(second.stdout, "New, TLSv1.3");
    try assertContains(second.stdout, "HTTP/1.1 200 OK");
    try assertContains(second.stdout, "alive");

    // The reconnect above must have actually been *caused* by a real
    // server-side miss on A's old key, not merely have succeeded for some
    // other reason (e.g. OpenSSL silently dropping the offer): assert the
    // typed miss outcome now, on B's own metrics, before doing anything
    // that could also move `accepted` and blur which reconnect caused
    // which delta. B is a fresh process, so this is B's first and only
    // resumption attempt so far -- an absolute count, not a delta, is
    // exact here.
    var post_miss_metrics = try sendPureZigTlsHttp1Request(allocator, process_b.port, "/status/metrics");
    defer post_miss_metrics.deinit();
    try std.testing.expect((prometheusLabeledMetricValue(post_miss_metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"miss\"",
    }) orelse 0) >= 1);
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(post_miss_metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0);

    // 8-9: process B issues its own fresh, usable ticket, proven by a real
    // resumed reconnect within B's lifetime -- not merely a metric.
    const b_sess_path = try opensslSessionPath(allocator, process_b.port, "restart-ephemeral-fresh");
    defer allocator.free(b_sess_path);
    defer compat.cwd().deleteFile(b_sess_path) catch {};
    var third = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_b,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        b_sess_path,
    }, openssl_health_request, 10_000);
    defer third.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(third.outcome));

    var fourth = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_b,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_in",
        b_sess_path,
    }, openssl_health_request, 10_000);
    defer fourth.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(fourth.outcome));
    try assertContains(fourth.stdout, "Reused, TLSv1.3");
    try assertContains(fourth.stdout, "HTTP/1.1 200 OK");

    // 9: bounded miss/fallback metrics recorded for the restart, and B's
    // real resumption of its own ticket, both on B's own metrics endpoint.
    var metrics = try sendPureZigTlsHttp1Request(allocator, process_b.port, "/status/metrics");
    defer metrics.deinit();
    try std.testing.expect((prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0) >= 1);

    // 10: no raw ticket identity in either process's log output.
    const log_a = try compat.cwd().readFileAlloc(allocator, log_a_path, 4 * 1024 * 1024);
    defer allocator.free(log_a);
    const log_b = try compat.cwd().readFileAlloc(allocator, process_b.log_path, 4 * 1024 * 1024);
    defer allocator.free(log_b);
    try std.testing.expect(!containsSubstring(log_a, fingerprint_hex_slice));
    try std.testing.expect(!containsSubstring(log_b, fingerprint_hex_slice));
}

test "restart.persistent.early_startup_quarantine" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const key_path_probe_port = try findFreePort();
    const ticket_keys_path = try persistentTicketKeySnapshotPath(allocator, key_path_probe_port, "persistent-early-quarantine");
    defer allocator.free(ticket_keys_path);
    defer compat.cwd().deleteFile(ticket_keys_path) catch {};
    defer {
        const lock_path = std.fmt.allocPrint(allocator, "{s}.lock", .{ticket_keys_path}) catch null;
        if (lock_path) |path| {
            compat.cwd().deleteFile(path) catch {};
            allocator.free(path);
        }
    }
    try writePersistentTicketKeySnapshot(allocator, ticket_keys_path);

    var upstream_a = try UpstreamServer.start(allocator, &.{
        .{ .body = "a-readiness", .connection_header = "close" },
        .{ .body = "a-ticket", .connection_header = "close" },
    });
    defer upstream_a.stop();
    try upstream_a.run();
    const config_a = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}}
    , .{ test_host, upstream_a.port() });
    defer allocator.free(config_a);

    var process_a = try TardigradeProcess.start(allocator, .{
        .config_text = config_a,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH", .value = ticket_keys_path },
            .{ .name = "TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE", .value = "process_local" },
        },
    });
    var process_a_running = true;
    defer if (process_a_running) process_a.stop();

    compat.sleepNs(61 * std.time.ns_per_s);

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_runtime = try tls_core.resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 2_000;
            }
        }.now },
        client_provider.cryptoProvider(),
    );
    defer client_runtime.deinit();

    const TicketCapture = struct {
        allocator: std.mem.Allocator,
        runtime: *tls_core.resumption_runtime.Runtime,
        retained: tls_core.session.ClientTicketState = .{},
        count: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 2_000;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.retained.deinit();
            self.retained = .{};
            ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
            _ = self.runtime.storeClientTicket(ticket);
            self.count += 1;
        }
    };

    var capture = TicketCapture{ .allocator = allocator, .runtime = &client_runtime };
    defer capture.retained.deinit();

    const first_client = try PureZigTlsClient.createWithOptions(allocator, process_a.port, "http/1.1", "tardigrade.test", .{
        .ticket_consumer = .{
            .ctx = &capture,
            .nowUnixMsFn = TicketCapture.now,
            .onTicketFn = TicketCapture.onTicket,
        },
    });
    defer first_client.destroy();
    try first_client.writeAllPlain("GET /ticket HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    const first_raw = try first_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(first_raw);
    try assertContains(first_raw, "HTTP/1.1 200 OK");
    try std.testing.expect(capture.count > 0);
    try std.testing.expectEqual(tls_core.session.EarlyDataPolicy{ .early_data_capable = 16 * 1024 }, capture.retained.common.early_data);

    var ordinary_ticket: tls_core.session.ClientTicketState = .{};
    defer ordinary_ticket.deinit();
    try capture.retained.cloneInto(allocator, &ordinary_ticket);
    var early_ticket: tls_core.session.ClientTicketState = .{};
    defer early_ticket.deinit();
    try capture.retained.cloneInto(allocator, &early_ticket);

    const log_a_path = try allocator.dupe(u8, process_a.log_path);
    defer allocator.free(log_a_path);
    process_a.stop();
    process_a_running = false;

    var upstream_b = try UpstreamServer.start(allocator, &.{
        .{ .body = "b-readiness", .connection_header = "close" },
        .{ .body = "ordinary-after-quarantine", .connection_header = "close" },
    });
    defer upstream_b.stop();
    try upstream_b.run();
    const config_b = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}}
    , .{ test_host, upstream_b.port() });
    defer allocator.free(config_b);

    var process_b = try TardigradeProcess.start(allocator, .{
        .config_text = config_b,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH", .value = ticket_keys_path },
            .{ .name = "TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE", .value = "process_local" },
        },
    });
    defer process_b.stop();

    try upstream_b.resetCapture();

    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2_500;
        }
    };

    var ordinary_offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
    try ordinary_offers.push(&ordinary_ticket);
    errdefer ordinary_offers.deinit();
    const ordinary_client = try PureZigTlsClient.createWithOptions(allocator, process_b.port, "http/1.1", "tardigrade.test", .{
        .psk_offers = &ordinary_offers,
        .psk_now_ctx = &clock_dummy,
        .psk_now_fn = ClientClock.now,
    });
    defer ordinary_client.destroy();
    try std.testing.expect(ordinary_client.backend.core.psk_authenticated);
    try ordinary_client.writeAllPlain("GET /ordinary HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    const ordinary_raw = try ordinary_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(ordinary_raw);
    try assertContains(ordinary_raw, "HTTP/1.1 200 OK");
    try assertContains(ordinary_raw, "ordinary-after-quarantine");
    try std.testing.expectEqual(@as(u32, 1), upstream_b.requestCount());
    const path = try upstream_b.capturedPathHistoryAt(allocator, 0);
    defer allocator.free(path);
    try std.testing.expectEqualStrings("/ordinary", path);
    try upstream_b.resetCapture();

    var early_offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
    try early_offers.push(&early_ticket);
    errdefer early_offers.deinit();
    const early_client = try PureZigTlsClient.createWithOptions(allocator, process_b.port, "http/1.1", "tardigrade.test", .{
        .psk_offers = &early_offers,
        .psk_now_ctx = &clock_dummy,
        .psk_now_fn = ClientClock.now,
        .early_data_intent = .{ .enabled = true, .max_bytes = 4096 },
        .return_after_early_data_ready = true,
    });
    defer early_client.destroy();
    try early_client.writeAllPlain("GET /early HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    try early_client.driveUntilOpen(5_000);
    try std.testing.expectEqual(@as(u32, 0), upstream_b.requestCount());

    var metrics = try sendPureZigTlsHttp1Request(allocator, process_b.port, "/status/metrics");
    defer metrics.deinit();
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"initial_load_success\""}, 1);
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_ticket_resolve_total", &.{ "mode=\"stateless\"", "result=\"success\"" }, 1);
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"accepted\"" }, 1);
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"startup_quarantine\""}, 1);
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"accepted\""}) orelse 0);

    const log_a = try compat.cwd().readFileAlloc(allocator, log_a_path, 4 * 1024 * 1024);
    defer allocator.free(log_a);
    const log_b = try compat.cwd().readFileAlloc(allocator, process_b.log_path, 4 * 1024 * 1024);
    defer allocator.free(log_b);
    try assertHexAbsentCaseInsensitive(allocator, log_a, persistent_ticket_key_fixture_hex);
    try assertHexAbsentCaseInsensitive(allocator, log_b, persistent_ticket_key_fixture_hex);
}

// Named `restart_and_credential_change`, not `cert_change`: process A and
// B are both `stateless` mode, so B constructs its own fresh ephemeral
// ticket-protection key regardless of which credential it serves -- B
// cannot decrypt A's ticket at all, for the same ephemeral-key-loss reason
// `restart.ephemeral.ticket_miss` already covers, *before* any recovered
// session's certificate/auth-binding field could ever be inspected. This
// test would pass unchanged even if certificate-binding compatibility
// checking were completely broken, so it must not be read as proving that
// check. What it does prove: swapping the served credential across a
// restart is *also* safe -- the old ticket still doesn't authenticate, and
// the miss is still a real server-side miss (see the shared metric
// assertion below), not an accident of the credential swap silently
// producing some other rejection path. True certificate/auth-binding-change
// coverage (the same ephemeral key, a different certificate) needs either a
// live credential-reload path that preserves the resumption runtime across
// the swap -- the appliance profile this suite builds under explicitly
// forbids `TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS` -- or a persistent
// keyring that survives a restart, which does not exist in production
// today (see docs/RESUMPTION_TEST_PLAN.md's rotation section). Both are
// deferred.
test "restart.restart_and_credential_change.ticket_rejected" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpenssl(allocator);
    try requireOpensslEd25519(allocator);

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();
    var alt_cert = try generateAlternateServerCert(allocator, "tardigrade.test");
    defer alt_cert.deinit();

    const config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
    ;

    // Process A: credential generation A, issue a ticket.
    var process_a = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
        },
    });
    var process_a_running = true;
    defer if (process_a_running) process_a.stop();

    const connect_a = try opensslConnectArg(allocator, process_a.port);
    defer allocator.free(connect_a);
    const sess_path = try opensslSessionPath(allocator, process_a.port, "restart-cert-change");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};

    var first = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_a,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_out",
        sess_path,
    }, openssl_health_request, 10_000);
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try assertContains(first.stdout, "HTTP/1.1 200 OK");

    process_a.stop();
    process_a_running = false;

    // Process B: same server_name, a different credential generation, and
    // (as with `restart.ephemeral.*`) its own naturally fresh ephemeral
    // ticket key regardless.
    var process_b = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = alt_cert.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = alt_cert.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
        },
    });
    defer process_b.stop();

    const connect_b = try opensslConnectArg(allocator, process_b.port);
    defer allocator.free(connect_b);

    // The old ticket must not authenticate against the new credential.
    var second = try runOpenssl(allocator, &.{
        "s_client",        "-connect", connect_b,
        "-alpn",           "http/1.1", "-servername",
        "tardigrade.test", "-tls1_3",  "-sess_in",
        sess_path,
    }, openssl_health_request, 10_000);
    defer second.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(second.outcome));
    try std.testing.expect(!containsSubstring(second.stdout, "Reused, TLSv1.3"));
    try assertContains(second.stdout, "New, TLSv1.3");
    try assertContains(second.stdout, "HTTP/1.1 200 OK");
    try assertContains(second.stdout, "alive");

    // Same causal check as `restart.ephemeral.ticket_miss`: this must be a
    // real server-side miss, not merely "some rejection happened."
    var metrics = try sendPureZigTlsHttp1Request(allocator, process_b.port, "/status/metrics");
    defer metrics.deinit();
    try std.testing.expect((prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"miss\"",
    }) orelse 0) >= 1);
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0);
}

// #519: the composed production proof `restart.persistent.early_startup_
// quarantine` (#513/#369) does not cover -- that test only proves the
// *quarantine* boundary survives a restart. This proves the persistent
// ticket-key policy's actual headline guarantee: a real process restart,
// against the same on-disk snapshot with *no manual lease editing*, both
// preserves an already-issued ticket's resumability and durably reserves a
// disjoint nonce-lease window before the fresh process ever issues its own
// ticket -- so the two processes can never emit a colliding (key_id, nonce)
// AEAD nonce for the same key, even though both share the identical
// long-lived secret key material.
test "restart.persistent.ticket_survives" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const key_path_probe_port = try findFreePort();
    const ticket_keys_path = try persistentTicketKeySnapshotPath(allocator, key_path_probe_port, "persistent-restart-survives");
    defer allocator.free(ticket_keys_path);
    defer compat.cwd().deleteFile(ticket_keys_path) catch {};
    defer {
        const lock_path = std.fmt.allocPrint(allocator, "{s}.lock", .{ticket_keys_path}) catch null;
        if (lock_path) |path| {
            compat.cwd().deleteFile(path) catch {};
            allocator.free(path);
        }
    }
    try writePersistentTicketKeySnapshot(allocator, ticket_keys_path);

    const config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
    ;
    const extra_env = &[_]EnvPair{
        .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
        .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
        .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
        .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
        .{ .name = "TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH", .value = ticket_keys_path },
    };

    // Ground truth before any process exists: `writePersistentTicketKeySnapshot`'s
    // own fixture lease window (see its literal above).
    const before_any_start = try readTicketKeyLeaseWindow(allocator, ticket_keys_path, persistent_ticket_key_fixture_id_hex);
    try std.testing.expectEqual(@as(u64, 0), before_any_start.start);
    try std.testing.expectEqual(@as(u64, 4096), before_any_start.end_exclusive);

    // 2: start process A. Startup alone (`loadPersistentTicketKeysFromFile`,
    // reached because no fingerprint is installed yet) durably reserves A's
    // issuance lease in the file before any connection exists.
    var process_a = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = extra_env,
    });
    var process_a_running = true;
    defer if (process_a_running) process_a.stop();

    const after_a_start = try readTicketKeyLeaseWindow(allocator, ticket_keys_path, persistent_ticket_key_fixture_id_hex);
    try std.testing.expectEqual(before_any_start.end_exclusive, after_a_start.start);
    try std.testing.expect(after_a_start.end_exclusive > after_a_start.start);

    // 2 (continued): issue a real stateless ticket from A, capturing only
    // the public envelope metadata (key id, nonce) #519 asks for -- never
    // the AEAD ciphertext/tag, and never logged.
    const TicketCapture = struct {
        allocator: std.mem.Allocator,
        retained: tls_core.session.ClientTicketState = .{},

        fn now(_: *anyopaque) i64 {
            return 2_000;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.retained.deinit();
            self.retained = .{};
            ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
        }
    };

    var capture_a = TicketCapture{ .allocator = allocator };
    defer capture_a.retained.deinit();

    const client_a = try PureZigTlsClient.createWithOptions(allocator, process_a.port, "http/1.1", "tardigrade.test", .{
        .ticket_consumer = .{
            .ctx = &capture_a,
            .nowUnixMsFn = TicketCapture.now,
            .onTicketFn = TicketCapture.onTicket,
        },
    });
    defer client_a.destroy();
    try client_a.writeAllPlain(openssl_health_request);
    const a_raw = try client_a.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(a_raw);
    try assertContains(a_raw, "HTTP/1.1 200 OK");
    try std.testing.expect(capture_a.retained.ticket.slice().len > 0);

    var ticket_a: tls_core.session.ClientTicketState = .{};
    defer ticket_a.deinit();
    try capture_a.retained.cloneInto(allocator, &ticket_a);
    const ids_a = extractTicketEnvelopeIds(&ticket_a);

    // 3: terminate A -- a real process boundary.
    process_a.stop();
    process_a_running = false;

    // 4: start B from the same on-disk snapshot, same env, no manual lease
    // edits of any kind.
    var process_b = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = extra_env,
    });
    defer process_b.stop();

    // 5: B's own startup must have reserved a *new, non-overlapping* lease
    // window -- durable, file-backed state, not merely "B also works".
    const after_b_start = try readTicketKeyLeaseWindow(allocator, ticket_keys_path, persistent_ticket_key_fixture_id_hex);
    try std.testing.expectEqual(after_a_start.end_exclusive, after_b_start.start);
    try std.testing.expect(after_b_start.start >= after_a_start.end_exclusive);
    try std.testing.expect(after_b_start.end_exclusive > after_b_start.start);

    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2_500;
        }
    };

    // 6-7: A's still-valid ticket resumes on B -- the persistent key
    // decrypts it even though B never shared any in-memory state with A.
    var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&ticket_a);
    errdefer offers.deinit();
    const resumed_client = try PureZigTlsClient.createWithOptions(allocator, process_b.port, "http/1.1", "tardigrade.test", .{
        .psk_offers = &offers,
        .psk_now_ctx = &clock_dummy,
        .psk_now_fn = ClientClock.now,
    });
    defer resumed_client.destroy();
    try std.testing.expect(resumed_client.backend.core.psk_authenticated);
    try resumed_client.writeAllPlain(openssl_health_request);
    const resumed_raw = try resumed_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(resumed_raw);
    try assertContains(resumed_raw, "HTTP/1.1 200 OK");

    var resume_metrics = try sendPureZigTlsHttp1Request(allocator, process_b.port, "/status/metrics");
    defer resume_metrics.deinit();
    try expectMetricAtLeast(resume_metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"accepted\"" }, 1);

    // 8-9: B issues its own fresh ticket. Same key (only one key in this
    // fixture, so key_id must match), but its nonce must be distinct from
    // every A-issued nonce -- guaranteed structurally by step 5's disjoint
    // lease windows, and asserted directly here at the wire-visible
    // (key_id, nonce) granularity #519 asks for.
    var capture_b = TicketCapture{ .allocator = allocator };
    defer capture_b.retained.deinit();
    const client_b = try PureZigTlsClient.createWithOptions(allocator, process_b.port, "http/1.1", "tardigrade.test", .{
        .ticket_consumer = .{
            .ctx = &capture_b,
            .nowUnixMsFn = TicketCapture.now,
            .onTicketFn = TicketCapture.onTicket,
        },
    });
    defer client_b.destroy();
    try client_b.writeAllPlain(openssl_health_request);
    const b_raw = try client_b.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(b_raw);
    try assertContains(b_raw, "HTTP/1.1 200 OK");

    const ids_b = extractTicketEnvelopeIds(&capture_b.retained);
    try std.testing.expectEqualSlices(u8, &ids_a.key_id, &ids_b.key_id);
    try std.testing.expect(!std.mem.eql(u8, &ids_a.nonce, &ids_b.nonce));
    // The nonce's low 8 bytes are the per-key counter `NonceLease.reserve`
    // draws from (see the fixed 4-byte prefix + big-endian counter format);
    // B's counter must fall inside B's own reserved window, not merely
    // "differ from A's one sample" -- a stronger, non-coincidental proof of
    // disjointness.
    const b_nonce_counter = std.mem.readInt(u64, ids_b.nonce[4..12], .big);
    try std.testing.expect(b_nonce_counter >= after_b_start.start and b_nonce_counter < after_b_start.end_exclusive);
}

// #519: drives the real SIGHUP config-reload path (the same one `location
// block reload takes effect for new requests after sighup` above uses) to
// rotate a persistent stateless keyring from generation N to N+1 on a live
// process, composing what `resumption_runtime.zig`'s own in-process unit
// suite (`#512 persistent stateless runtime loads configured keys, rotates,
// and retires old tickets`, etc.) already proves against a bare `Runtime`
// with an injected clock, into the real production reload path with a real
// wall clock. Also composes the `encrypt_until`/`decrypt_until` boundary
// pair live: N's `encrypt_until` is already in the past at the moment N+1
// is installed (so it never re-encrypts), and N's `decrypt_until` is a
// short, deterministic few seconds out so a real (bounded) sleep can prove
// the grace window actually closes. `not_before` and the
// `session.issued_at + lifetime` boundary are deliberately not re-proven
// here: both are exact single-key timing facts already covered end to end
// (`not_before` by `#512`'s own unit suite; ticket-lifetime expiry by
// `interop.openssl.ticket.expired`) and neither depends on rotation itself.
test "rotation.persistent.n_to_n_plus_1" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const key_path_probe_port = try findFreePort();
    const ticket_keys_path = try persistentTicketKeySnapshotPath(allocator, key_path_probe_port, "persistent-rotation-n-to-np1");
    defer allocator.free(ticket_keys_path);
    defer compat.cwd().deleteFile(ticket_keys_path) catch {};
    defer {
        const lock_path = std.fmt.allocPrint(allocator, "{s}.lock", .{ticket_keys_path}) catch null;
        if (lock_path) |path| {
            compat.cwd().deleteFile(path) catch {};
            allocator.free(path);
        }
    }

    const key_n_id = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
    const key_n_secret = "c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1";
    const key_np1_id = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";
    const key_np1_secret = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2";

    // A ticket only seals successfully when the sealing key's own
    // `decrypt_until` outlives the session's `issued_at + ticket_lifetime`
    // (`ticket_protection.ticketExpiresWithinKey`) -- a real, independent
    // validity constraint from anything this test otherwise controls. The
    // default ticket lifetime is 24h, so the short, deterministic key
    // windows this rotation test needs (seconds, not hours) require an
    // explicit short ticket lifetime too, or every issuance would silently
    // fail closed with `TicketOutlivesKey` before ever reaching the wire.
    const gen1_now = compat.milliTimestamp();
    try writePersistentTicketKeySnapshotKeys(allocator, ticket_keys_path, 1, &.{
        .{
            .id_hex = key_n_id,
            .key_hex = key_n_secret,
            .not_before_unix_ms = gen1_now - 60_000,
            .encrypt_until_unix_ms = gen1_now + 90_000,
            .decrypt_until_unix_ms = gen1_now + 90_000,
            .nonce_lease = .{ .prefix_hex = "e3000000", .start = 0, .end_exclusive = 1_000_000 },
        },
    });

    const config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
    ;
    const extra_env = &[_]EnvPair{
        .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
        .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
        .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
        .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
        .{ .name = "TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH", .value = ticket_keys_path },
        .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_TICKET_LIFETIME_SECONDS", .value = "10" },
    };
    const ticket_lifetime_seconds: i64 = 10;

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = extra_env,
    });
    defer tardigrade.stop();

    const RotationTicketCapture = struct {
        allocator: std.mem.Allocator,
        retained: tls_core.session.ClientTicketState = .{},

        fn now(_: *anyopaque) i64 {
            return 2_000;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.retained.deinit();
            self.retained = .{};
            ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
        }
    };

    // 1-2: obtain a real ticket under generation N.
    var capture_n = RotationTicketCapture{ .allocator = allocator };
    defer capture_n.retained.deinit();
    {
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .ticket_consumer = .{ .ctx = &capture_n, .nowUnixMsFn = RotationTicketCapture.now, .onTicketFn = RotationTicketCapture.onTicket },
        });
        defer client.destroy();
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
    }
    var ticket_n: tls_core.session.ClientTicketState = .{};
    defer ticket_n.deinit();
    try capture_n.retained.cloneInto(allocator, &ticket_n);
    const ids_n = extractTicketEnvelopeIds(&ticket_n);
    try std.testing.expectEqualStrings(key_n_id, &std.fmt.bytesToHex(ids_n.key_id, .lower));

    // 3: atomically replace the configured snapshot with N+1 while retaining
    // N decrypt-only for a short, deterministic grace window. N's own
    // `encrypt_until` is already in the past at this moment, so it can never
    // be selected to encrypt a new ticket again from here on -- and since it
    // will never encrypt again, it carries forward with `nonce_lease =
    // null` rather than replaying its original (or any) lease range: the
    // keyring's per-key-id ledger permanently remembers the full declared
    // width of every lease a key was ever installed with, so replaying any
    // such range for a key that already used it in a prior generation is
    // rejected as `OverlappingNonceLease`, even for the very same,
    // unchanged key. See `TicketKeyFixture.nonce_lease`'s doc comment.
    const gen2_now = compat.milliTimestamp();
    const grace_window_ms: i64 = 5_000;
    try writePersistentTicketKeySnapshotKeys(allocator, ticket_keys_path, 2, &.{
        .{
            .id_hex = key_n_id,
            .key_hex = key_n_secret,
            .not_before_unix_ms = gen1_now - 60_000,
            .encrypt_until_unix_ms = gen2_now - 100,
            .decrypt_until_unix_ms = gen2_now + grace_window_ms,
        },
        .{
            .id_hex = key_np1_id,
            .key_hex = key_np1_secret,
            .not_before_unix_ms = gen2_now - 100,
            .encrypt_until_unix_ms = gen2_now + 60_000,
            .decrypt_until_unix_ms = gen2_now + 60_000,
            .nonce_lease = .{ .prefix_hex = "f4000000", .start = 0, .end_exclusive = 1_000_000 },
        },
    });

    // 4: trigger the real production reload path. A bounded poll, not a
    // fixed settle sleep, so a slower-than-usual reload can't race a
    // fixed-delay assertion.
    tardigrade.sendSignal(std.posix.SIG.HUP);
    try waitForLabeledMetricAtLeast(allocator, tardigrade.port, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_accepted\""}, 1, 5_000);

    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2_500;
        }
    };

    // 5: the old N ticket resumes during the overlap grace window.
    // `ClientPskOfferSet.push` *moves* its argument (zero-valued on
    // success), and `ticket_n` is offered again below after the grace
    // window closes -- so each offer pushes a fresh clone, never `ticket_n`
    // itself.
    {
        var offer_clone: tls_core.session.ClientTicketState = .{};
        defer offer_clone.deinit();
        try ticket_n.cloneInto(allocator, &offer_clone);
        var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
        try offers.push(&offer_clone);
        errdefer offers.deinit();
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .psk_offers = &offers,
            .psk_now_ctx = &clock_dummy,
            .psk_now_fn = ClientClock.now,
        });
        defer client.destroy();
        try std.testing.expect(client.backend.core.psk_authenticated);
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
    }
    var mid_metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer mid_metrics.deinit();
    const accepted_during_overlap = prometheusLabeledMetricValue(mid_metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"accepted\"" }) orelse 0;
    try std.testing.expect(accepted_during_overlap >= 1);

    // 6: newly issued tickets use N+1 only.
    var capture_np1 = RotationTicketCapture{ .allocator = allocator };
    defer capture_np1.retained.deinit();
    {
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .ticket_consumer = .{ .ctx = &capture_np1, .nowUnixMsFn = RotationTicketCapture.now, .onTicketFn = RotationTicketCapture.onTicket },
        });
        defer client.destroy();
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
    }
    const ids_np1 = extractTicketEnvelopeIds(&capture_np1.retained);
    try std.testing.expectEqualStrings(key_np1_id, &std.fmt.bytesToHex(ids_np1.key_id, .lower));
    try std.testing.expect(!std.mem.eql(u8, &ids_np1.key_id, &ids_n.key_id));

    // `session.issued_at + lifetime` boundary, composed live: a ticket
    // issued now (under N+1, whose own `decrypt_until` is 60s out --
    // comfortably past this phase's ~12s span, so the key itself is never
    // in question here) resumes before the process-wide 10s ticket
    // lifetime elapses, and falls back to a full handshake once it does.
    //
    // `ticket_protection.Protector.resolveInner` checks the decoded
    // session's own `isExpired(now)` *inside* the resolve/decrypt step
    // itself (session.zig's expiry, not `evaluateCompatibility`'s), and
    // `resumption_runtime.resolverResolve` folds every resolve rejection --
    // expired, not-yet-valid, unknown key, or retired key alike -- into the
    // same `miss` outcome and `ticket_resolve_total{result="rejected"}`;
    // there is no separate metrics bucket distinguishing "expired" from
    // "retired key" today. So attribution here comes from this phase's own
    // construction, verified concretely rather than merely asserted: N+1's
    // `decrypt_until` is 60s out (only ~12s will have elapsed), and a fresh
    // ticket issued immediately after the rejected offer below is asserted
    // to still be sealed under N+1 -- proof the key itself is still fully
    // alive and usable, so the preceding rejection cannot have been key
    // retirement.
    var capture_np1_lifetime = RotationTicketCapture{ .allocator = allocator };
    defer capture_np1_lifetime.retained.deinit();
    {
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .ticket_consumer = .{ .ctx = &capture_np1_lifetime, .nowUnixMsFn = RotationTicketCapture.now, .onTicketFn = RotationTicketCapture.onTicket },
        });
        defer client.destroy();
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
    }
    var ticket_np1_lifetime: tls_core.session.ClientTicketState = .{};
    defer ticket_np1_lifetime.deinit();
    try capture_np1_lifetime.retained.cloneInto(allocator, &ticket_np1_lifetime);

    {
        var offer_clone: tls_core.session.ClientTicketState = .{};
        defer offer_clone.deinit();
        try ticket_np1_lifetime.cloneInto(allocator, &offer_clone);
        var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
        try offers.push(&offer_clone);
        errdefer offers.deinit();
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .psk_offers = &offers,
            .psk_now_ctx = &clock_dummy,
            .psk_now_fn = ClientClock.now,
        });
        defer client.destroy();
        try std.testing.expect(client.backend.core.psk_authenticated);
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
    }
    const miss_before_expiry = blk: {
        var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
        defer metrics.deinit();
        break :blk prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"miss\"" }) orelse 0;
    };

    // A bounded real sleep past the 10s process-wide ticket lifetime --
    // there is no injectable clock at this real-process boundary (the same
    // constraint `interop.openssl.ticket.expired` documents).
    compat.sleepNs(@as(u64, @intCast(ticket_lifetime_seconds)) * std.time.ns_per_s + 2 * std.time.ns_per_s);

    {
        var offer_clone: tls_core.session.ClientTicketState = .{};
        defer offer_clone.deinit();
        try ticket_np1_lifetime.cloneInto(allocator, &offer_clone);
        var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
        try offers.push(&offer_clone);
        errdefer offers.deinit();
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .psk_offers = &offers,
            .psk_now_ctx = &clock_dummy,
            .psk_now_fn = ClientClock.now,
        });
        defer client.destroy();
        // Not selected/binder-verified, same as an auth-binding mismatch:
        // `selectPsk` skips an ineligible (here: expired) candidate before
        // ever reaching binder verification.
        try std.testing.expect(!client.backend.core.psk_authenticated);
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
    }
    var lifetime_metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer lifetime_metrics.deinit();
    try std.testing.expect((prometheusLabeledMetricValue(lifetime_metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"miss\"" }) orelse 0) > miss_before_expiry);

    // The concrete "not key retirement" proof: N+1 itself is still fully
    // alive immediately afterward -- a fresh ticket issued right now is
    // still sealed under N+1's own key id, which could not be true if N+1
    // had actually been retired.
    {
        var capture = RotationTicketCapture{ .allocator = allocator };
        defer capture.retained.deinit();
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .ticket_consumer = .{ .ctx = &capture, .nowUnixMsFn = RotationTicketCapture.now, .onTicketFn = RotationTicketCapture.onTicket },
        });
        defer client.destroy();
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
        const ids = extractTicketEnvelopeIds(&capture.retained);
        try std.testing.expectEqualStrings(key_np1_id, &std.fmt.bytesToHex(ids.key_id, .lower));
    }

    // The lifetime-boundary phase above legitimately added one more
    // `accepted` resumption (the before-expiry offer), so step 7's own
    // "did this last offer really not resume" check below must compare
    // against a freshly captured baseline, not the one from step 5's
    // overlap-window check.
    const accepted_before_grace_close = blk: {
        var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
        defer metrics.deinit();
        break :blk prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"accepted\"" }) orelse 0;
    };

    // 7: wait past N's `decrypt_until` grace boundary, then prove retired N
    // is never used for new encryption *and* no longer resolves at all --
    // composing the live decrypt_until boundary itself, not merely
    // asserting the reload succeeded.
    compat.sleepNs(@as(u64, @intCast(grace_window_ms)) * std.time.ns_per_ms + 2 * std.time.ns_per_s);

    {
        var offer_clone: tls_core.session.ClientTicketState = .{};
        defer offer_clone.deinit();
        try ticket_n.cloneInto(allocator, &offer_clone);
        var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
        try offers.push(&offer_clone);
        errdefer offers.deinit();
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .psk_offers = &offers,
            .psk_now_ctx = &clock_dummy,
            .psk_now_fn = ClientClock.now,
        });
        defer client.destroy();
        // The retired key is gone entirely, not merely "not preferred": a
        // full handshake, not a second resumption, must serve this request.
        try std.testing.expect(!client.backend.core.psk_authenticated);
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
    }

    var final_metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer final_metrics.deinit();
    try expectMetricAtLeast(final_metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"miss\"" }, 1);
    // The overlap-window accept count must not have grown from this last,
    // post-grace-window offer -- it really did fall back, not resume again.
    try std.testing.expectEqual(accepted_before_grace_close, prometheusLabeledMetricValue(final_metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"accepted\"" }) orelse 0);

    // `not_before` boundary, composed live: reload to a generation N+2 whose
    // new key isn't valid *yet* (a short, deterministic future activation
    // time), while N+1 remains encryption-capable right up to that instant
    // -- a clean, non-overlapping handoff (N+1's `encrypt_until` set to
    // exactly N+2's `not_before`), never simultaneously eligible, which
    // `Snapshot.activeEncryptionKey` would otherwise reject outright as
    // `AmbiguousActiveEncryptionKey`. Fresh issuance must stay on N+1 before
    // the boundary, then switch to N+2 once it arrives.
    const key_np2_id = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    const key_np2_secret = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";
    // N+1's own nonce-lease window must be *advanced past* its currently
    // installed one, not merely replayed verbatim (see the doc comment on
    // step 3 above for the same ledger reasoning) -- the file's currently
    // declared range *is* the ledger's recorded ceiling for this key id
    // exactly, so reusing it as-is collides with `OverlappingNonceLease`
    // just as replaying the stale original range would; only a strictly
    // later window (the same doubling-by-width advance
    // `reserveNonceLeasesInFile` itself performs) is accepted. It still
    // needs to encrypt for a few more seconds here, so (unlike retired N
    // above) it keeps a lease rather than dropping it.
    const key_np1_prior_lease = try readTicketKeyLeaseWindow(allocator, ticket_keys_path, key_np1_id);
    const key_np1_lease_width = key_np1_prior_lease.end_exclusive - key_np1_prior_lease.start;
    const key_np1_advanced_lease_start = key_np1_prior_lease.end_exclusive;
    const key_np1_advanced_lease_end = key_np1_prior_lease.end_exclusive + key_np1_lease_width;
    const gen3_now = compat.milliTimestamp();
    const not_before_boundary_ms: i64 = gen3_now + 4_000;
    const reload_accepted_before_gen3 = blk: {
        var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
        defer metrics.deinit();
        break :blk prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_accepted\""}) orelse 0;
    };
    try writePersistentTicketKeySnapshotKeys(allocator, ticket_keys_path, 3, &.{
        .{
            .id_hex = key_np1_id,
            .key_hex = key_np1_secret,
            .not_before_unix_ms = gen2_now - 100,
            .encrypt_until_unix_ms = not_before_boundary_ms,
            .decrypt_until_unix_ms = not_before_boundary_ms + 120_000,
            .nonce_lease = .{ .prefix_hex = "f4000000", .start = key_np1_advanced_lease_start, .end_exclusive = key_np1_advanced_lease_end },
        },
        .{
            .id_hex = key_np2_id,
            .key_hex = key_np2_secret,
            .not_before_unix_ms = not_before_boundary_ms,
            .encrypt_until_unix_ms = not_before_boundary_ms + 120_000,
            .decrypt_until_unix_ms = not_before_boundary_ms + 120_000,
            .nonce_lease = .{ .prefix_hex = "f5000000", .start = 0, .end_exclusive = 1_000_000 },
        },
    });
    tardigrade.sendSignal(std.posix.SIG.HUP);
    try waitForLabeledMetricAtLeast(allocator, tardigrade.port, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_accepted\""}, reload_accepted_before_gen3 + 1, 5_000);

    // Before the boundary: fresh issuance is still N+1.
    {
        var capture = RotationTicketCapture{ .allocator = allocator };
        defer capture.retained.deinit();
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .ticket_consumer = .{ .ctx = &capture, .nowUnixMsFn = RotationTicketCapture.now, .onTicketFn = RotationTicketCapture.onTicket },
        });
        defer client.destroy();
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
        const ids = extractTicketEnvelopeIds(&capture.retained);
        try std.testing.expectEqualStrings(key_np1_id, &std.fmt.bytesToHex(ids.key_id, .lower));
    }

    // A bounded real sleep past N+2's `not_before` boundary.
    compat.sleepNs(4_500 * std.time.ns_per_ms);

    // After the boundary: fresh issuance has switched to N+2.
    {
        var capture = RotationTicketCapture{ .allocator = allocator };
        defer capture.retained.deinit();
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .ticket_consumer = .{ .ctx = &capture, .nowUnixMsFn = RotationTicketCapture.now, .onTicketFn = RotationTicketCapture.onTicket },
        });
        defer client.destroy();
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
        const ids = extractTicketEnvelopeIds(&capture.retained);
        try std.testing.expectEqualStrings(key_np2_id, &std.fmt.bytesToHex(ids.key_id, .lower));
    }
}

// #519: representative failure classes for a SIGHUP reload attempt against
// a live process running persistent ticket keys -- not an exhaustive replay
// of every `ticket_key_snapshot.zig` malformed-input unit case (those stay
// there), but the composed proof that a rejected candidate at each class
// never disturbs the live keyring, config, or credential: an
// already-issued ticket keeps resuming across every rejected attempt, a
// ticket issued only *after* every attempt still uses the original key
// (nothing partially applied), and the reload metric records a bounded,
// secret-free failure outcome each time.
//
// This test does not additionally attempt to bundle a TLS credential change
// into a failing SIGHUP: `requireNativeTlsProfile` gates every test in this
// file to the appliance TLS profile build (the only profile where
// `build_options.tls_openssl_adapter` is false), and inspecting
// `edge_gateway.run`/`gateway_shutdown.hotReloadConfig` shows the appliance
// profile's real served identity (`appliance_credentials.ApplianceCredentials`,
// held in `appliance_identity`) is loaded once at startup and never touched
// by `hotReloadConfig` at all -- the `native_credentials`/`NativeCredentialStore`
// two-phase prepare/commit path this criterion originally had in mind is
// wired up only for the non-appliance (general) profile, and there only for
// QUIC/H3 (`edge_gateway.zig`'s `if (build_options.tls_openssl_adapter and
// cfg.http3_enabled ...)`), so it is never reachable here regardless of
// what this test attempts. `rotation.persistent.quic_credential_reload_
// atomicity` below exercises that real path instead, over a real external
// QUIC peer; `rotation.persistent.certificate_binding_change` proves the
// credential-binding side of this through the restart composition the
// appliance profile does support. What this test still demonstrates,
// honestly: every sub-case below leaves `ticket0` (bound to the one
// credential this process ever serves) resuming successfully, so the
// previous certificate credential and the previous ticket state both
// visibly survive every rejected reload here, even though none of these
// attempts ever touches the credential itself.
test "rotation.persistent.failed_reload_keeps_old_state" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const key_path_probe_port = try findFreePort();
    const ticket_keys_path = try persistentTicketKeySnapshotPath(allocator, key_path_probe_port, "persistent-failed-reload");
    defer allocator.free(ticket_keys_path);
    defer compat.cwd().deleteFile(ticket_keys_path) catch {};
    defer {
        const lock_path = std.fmt.allocPrint(allocator, "{s}.lock", .{ticket_keys_path}) catch null;
        if (lock_path) |path| {
            compat.cwd().deleteFile(path) catch {};
            allocator.free(path);
        }
    }

    const k0_id = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";
    const k0_secret = "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5";
    const baseline_now = compat.milliTimestamp();
    try writePersistentTicketKeySnapshotKeys(allocator, ticket_keys_path, 5, &.{
        .{
            .id_hex = k0_id,
            .key_hex = k0_secret,
            .not_before_unix_ms = baseline_now - 60_000,
            .encrypt_until_unix_ms = baseline_now + 3_600_000,
            .decrypt_until_unix_ms = baseline_now + 3_600_000,
            .nonce_lease = .{ .prefix_hex = "11110000", .start = 0, .end_exclusive = 1_000_000 },
        },
    });

    const config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
    ;
    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH", .value = ticket_keys_path },
            // See `ticketExpiresWithinKey` in `ticket_protection.zig`: a
            // ticket only seals when the key's own `decrypt_until` outlives
            // `issued_at + ticket_lifetime`. The default lifetime is 24h,
            // far beyond this fixture's deliberately short 1h key window.
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_TICKET_LIFETIME_SECONDS", .value = "60" },
        },
    });
    defer tardigrade.stop();

    var baseline_metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer baseline_metrics.deinit();
    try expectMetricAtLeast(baseline_metrics.body, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"initial_load_success\""}, 1);

    const FailedReloadTicketCapture = struct {
        allocator: std.mem.Allocator,
        retained: tls_core.session.ClientTicketState = .{},

        fn now(_: *anyopaque) i64 {
            return 2_000;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.retained.deinit();
            self.retained = .{};
            ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
        }
    };

    var capture0 = FailedReloadTicketCapture{ .allocator = allocator };
    defer capture0.retained.deinit();
    {
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .ticket_consumer = .{ .ctx = &capture0, .nowUnixMsFn = FailedReloadTicketCapture.now, .onTicketFn = FailedReloadTicketCapture.onTicket },
        });
        defer client.destroy();
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
    }
    var ticket0: tls_core.session.ClientTicketState = .{};
    defer ticket0.deinit();
    try capture0.retained.cloneInto(allocator, &ticket0);

    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2_500;
        }
    };

    // Offers `ticket0` against the live process and asserts it still
    // resumes (real PSK authentication plus a real HTTP round-trip) --
    // proof that the previously valid ticket state was untouched by
    // whatever rejected reload attempt preceded this call.
    const assertTicket0StillResumes = struct {
        fn run(alloc: std.mem.Allocator, port: u16, ticket: *const tls_core.session.ClientTicketState, now_ctx: *u8) !void {
            // `ClientPskOfferSet.push` moves its argument (zero-valued on
            // success); this helper is called repeatedly against the same
            // `ticket0`, so each call offers a fresh clone and leaves the
            // caller's retained `ticket0` untouched.
            var offer_clone: tls_core.session.ClientTicketState = .{};
            defer offer_clone.deinit();
            try ticket.cloneInto(alloc, &offer_clone);
            var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
            try offers.push(&offer_clone);
            errdefer offers.deinit();
            const client = try PureZigTlsClient.createWithOptions(alloc, port, "http/1.1", "tardigrade.test", .{
                .psk_offers = &offers,
                .psk_now_ctx = now_ctx,
                .psk_now_fn = ClientClock.now,
            });
            defer client.destroy();
            try std.testing.expect(client.backend.core.psk_authenticated);
            try client.writeAllPlain(openssl_health_request);
            const raw = try client.readPlainToEnd(alloc, 64 * 1024, 5_000);
            defer alloc.free(raw);
            try assertContains(raw, "HTTP/1.1 200 OK");
        }
    }.run;

    // Captures the labeled `reload_rejected` counter, sends SIGHUP, then
    // requires the counter to have advanced by at least one *from that
    // captured baseline* (a bounded poll, not a fixed settle sleep) before
    // asserting `ticket0` still resumes. Per-attempt, not cumulative: an
    // earlier sub-case's rejection can never mask a later sub-case that
    // silently fails to reject (a fixed `>= 1` against the running total
    // would not catch that, since it would already be satisfied).
    const rejectSighupAndVerify = struct {
        fn run(alloc: std.mem.Allocator, proc: *TardigradeProcess, ticket: *const tls_core.session.ClientTicketState, now_ctx: *u8) !void {
            const before = blk: {
                var metrics = try sendPureZigTlsHttp1Request(alloc, proc.port, "/status/metrics");
                defer metrics.deinit();
                break :blk prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_rejected\""}) orelse 0;
            };
            proc.sendSignal(std.posix.SIG.HUP);
            try waitForLabeledMetricAtLeast(alloc, proc.port, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_rejected\""}, before + 1, 5_000);
            try assertTicket0StillResumes(alloc, proc.port, ticket, now_ctx);
        }
    }.run;

    // Sub-case 1: unreadable replacement -- the configured path exists but
    // is a directory, not a regular file, so it genuinely cannot be
    // *opened/read* as a snapshot at all (unlike an oversized-but-otherwise-
    // readable file, which fails a size guard instead -- a different
    // `ticket_key_snapshot.LoadError` class, and not what "unreadable"
    // means). Deterministic on every supported environment regardless of
    // permissions or which user/container CI runs the test as, unlike a
    // permission-bit trick that a root/rootless-container CI job can
    // silently fail to enforce. The valid snapshot is moved aside and
    // restored afterward rather than deleted, since deleting the path
    // outright would also work but is already a distinct, separately
    // observed condition below (this path both "exists" and "cannot be
    // consumed", where a missing path only demonstrates the latter).
    {
        const backup_path = try std.fmt.allocPrint(allocator, "{s}.bak", .{ticket_keys_path});
        defer allocator.free(backup_path);
        try compat.cwd().rename(ticket_keys_path, compat.cwd(), backup_path);
        // Restores the valid snapshot on every exit path, including a
        // `MetricThresholdNotReached` bail-out below, so a failure here
        // doesn't leave the configured path stuck as an empty directory
        // for whatever runs next.
        errdefer {
            compat.cwd().deleteTree(ticket_keys_path) catch {};
            compat.cwd().rename(backup_path, compat.cwd(), ticket_keys_path) catch {};
        }
        try compat.cwd().makePath(ticket_keys_path);

        // On macOS/Linux as built here, `edge_config.validate`'s own
        // `TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH` existence check
        // (`validateOptionalFileChecked`, an `openFile` that itself
        // succeeds on a directory) passes, and the rejection actually
        // happens one layer in, at `ticket_key_snapshot.loadFromFile`'s own
        // `readFileAlloc` -- which fails to read a directory as file
        // content -- landing on the ticket-key-specific
        // `reload_rejected` outcome (and, since every rejection in that
        // branch of `hotReloadConfig` also calls the shared
        // `state.metricsRecordReloadFailure()`, the general
        // `tardigrade_reload_failure_total` counter too, confirmed
        // together in practice). Checking both rather than assuming either
        // one keeps this robust against a platform/`std.Io.Dir` version
        // where the earlier existence check itself rejects a directory
        // instead.
        const general_before = blk: {
            var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
            defer metrics.deinit();
            break :blk prometheusMetricValue(metrics.body, "tardigrade_reload_failure_total") orelse 0;
        };
        const ticket_key_before = blk: {
            var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
            defer metrics.deinit();
            break :blk prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_rejected\""}) orelse 0;
        };
        tardigrade.sendSignal(std.posix.SIG.HUP);
        const deadline = compat.milliTimestamp() + 5_000;
        while (true) {
            var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
            defer metrics.deinit();
            const general_after = prometheusMetricValue(metrics.body, "tardigrade_reload_failure_total") orelse 0;
            const ticket_key_after = prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_rejected\""}) orelse 0;
            if (general_after >= general_before + 1 or ticket_key_after >= ticket_key_before + 1) break;
            if (compat.milliTimestamp() >= deadline) return error.MetricThresholdNotReached;
            compat.sleepNs(25 * std.time.ns_per_ms);
        }

        compat.cwd().deleteTree(ticket_keys_path) catch {};
        try compat.cwd().rename(backup_path, compat.cwd(), ticket_keys_path);
    }
    try assertTicket0StillResumes(allocator, tardigrade.port, &ticket0, &clock_dummy);

    // Sub-case 2: malformed JSON.
    try writeInteropSecretFile(ticket_keys_path, "{not valid json");
    try rejectSighupAndVerify(allocator, &tardigrade, &ticket0, &clock_dummy);

    // Sub-case 3: semantically invalid keyring -- an otherwise well-formed
    // key with an invalid nonce lease (`start >= end_exclusive`), rejected
    // by `ticket_protection.NonceLease.init`, not by JSON parsing.
    try writePersistentTicketKeySnapshotKeys(allocator, ticket_keys_path, 6, &.{
        .{
            .id_hex = k0_id,
            .key_hex = k0_secret,
            .not_before_unix_ms = baseline_now - 60_000,
            .encrypt_until_unix_ms = baseline_now + 3_600_000,
            .decrypt_until_unix_ms = baseline_now + 3_600_000,
            .nonce_lease = .{ .prefix_hex = "11110000", .start = 100, .end_exclusive = 100 },
        },
    });
    try rejectSighupAndVerify(allocator, &tardigrade, &ticket0, &clock_dummy);

    // Sub-case 4: stale generation -- otherwise identical, valid key
    // content, but a generation number not newer than the currently
    // installed one (5). Reusing the baseline's own lease range unchanged
    // is fine here (unlike `rotation.persistent.n_to_n_plus_1`'s carried-
    // forward key): staleness is checked before the ledger/overlap check
    // (`ReloadableKeyRing.validateInstallCandidate`), so this is rejected
    // for the intended reason regardless.
    try writePersistentTicketKeySnapshotKeys(allocator, ticket_keys_path, 3, &.{
        .{
            .id_hex = k0_id,
            .key_hex = k0_secret,
            .not_before_unix_ms = baseline_now - 60_000,
            .encrypt_until_unix_ms = baseline_now + 3_600_000,
            .decrypt_until_unix_ms = baseline_now + 3_600_000,
            .nonce_lease = .{ .prefix_hex = "11110000", .start = 0, .end_exclusive = 1_000_000 },
        },
    });
    try rejectSighupAndVerify(allocator, &tardigrade, &ticket0, &clock_dummy);

    // After four rejected attempts, a *freshly issued* ticket must still be
    // sealed under the original key id -- proof that nothing was partially
    // applied to the live keyring across any of them.
    {
        var capture = FailedReloadTicketCapture{ .allocator = allocator };
        defer capture.retained.deinit();
        const client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .ticket_consumer = .{ .ctx = &capture, .nowUnixMsFn = FailedReloadTicketCapture.now, .onTicketFn = FailedReloadTicketCapture.onTicket },
        });
        defer client.destroy();
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
        const ids = extractTicketEnvelopeIds(&capture.retained);
        try std.testing.expectEqualStrings(k0_id, &std.fmt.bytesToHex(ids.key_id, .lower));
    }
}

// #519: with persistent ticket keys, a restart no longer implies key loss
// (unlike `restart.restart_and_credential_change.ticket_rejected`, whose own
// doc comment explains it cannot prove certificate/auth-binding rejection
// for exactly this reason -- both processes there are ephemeral, so B can
// never decrypt A's ticket at all, and its own comment names a persistent
// keyring surviving a restart as exactly the missing production capability
// that would let a real cert-binding test exist). This is a restart, not a
// SIGHUP reload, deliberately: inspecting `edge_gateway.run`/
// `gateway_shutdown.hotReloadConfig` shows the appliance TLS profile's real
// served identity (`appliance_credentials.ApplianceCredentials`) is loaded
// once at startup and never touched by any reload path at all, so there is
// no live way to change the served credential without a restart under this
// profile -- exactly the "supported reload/restart composition" #519 asks
// for. Process B here reuses process A's ticket-keys file unedited (the
// same durable-lease-reservation contract `restart.persistent.ticket_survives`
// exercises), so the persistent key is unchanged across the restart and
// decryption genuinely succeeds; the only thing that can reject A's old
// ticket on B is `session.evaluateCompatibility`'s `auth_binding` check.
// `tls13_backend.selectPsk` only reaches that check, and only records
// `.incompatible` (as opposed to `.miss`), for an identity that actually
// resolved -- so the `incompatible` resumption outcome alongside a
// successful ticket-resolve metric is the live, composed proof this is a
// compatibility rejection, not an unknown-key/decryption miss.
test "rotation.persistent.certificate_binding_change" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpensslEd25519(allocator);

    var cred_a = try generateAlternateServerCert(allocator, "tardigrade.test");
    defer cred_a.deinit();
    var cred_b = try generateAlternateServerCert(allocator, "tardigrade.test");
    defer cred_b.deinit();

    const key_path_probe_port = try findFreePort();
    const ticket_keys_path = try persistentTicketKeySnapshotPath(allocator, key_path_probe_port, "persistent-cert-binding-change");
    defer allocator.free(ticket_keys_path);
    defer compat.cwd().deleteFile(ticket_keys_path) catch {};
    defer {
        const lock_path = std.fmt.allocPrint(allocator, "{s}.lock", .{ticket_keys_path}) catch null;
        if (lock_path) |path| {
            compat.cwd().deleteFile(path) catch {};
            allocator.free(path);
        }
    }
    try writePersistentTicketKeySnapshot(allocator, ticket_keys_path);

    const config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
    ;
    const extra_env = &[_]EnvPair{
        .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
        .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
        .{ .name = "TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH", .value = ticket_keys_path },
    };

    var process_a = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &(extra_env.* ++ [_]EnvPair{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = cred_a.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = cred_a.key_path },
        }),
    });
    var process_a_running = true;
    defer if (process_a_running) process_a.stop();

    const CertBindingTicketCapture = struct {
        allocator: std.mem.Allocator,
        retained: tls_core.session.ClientTicketState = .{},

        fn now(_: *anyopaque) i64 {
            return 2_000;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.retained.deinit();
            self.retained = .{};
            ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
        }
    };

    // Issue a ticket while process A serves credential A.
    var capture_a = CertBindingTicketCapture{ .allocator = allocator };
    defer capture_a.retained.deinit();
    {
        const client = try PureZigTlsClient.createWithOptions(allocator, process_a.port, "http/1.1", "tardigrade.test", .{
            .ticket_consumer = .{ .ctx = &capture_a, .nowUnixMsFn = CertBindingTicketCapture.now, .onTicketFn = CertBindingTicketCapture.onTicket },
        });
        defer client.destroy();
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
    }
    var ticket_a: tls_core.session.ClientTicketState = .{};
    defer ticket_a.deinit();
    try capture_a.retained.cloneInto(allocator, &ticket_a);

    // A real process boundary, not `Runtime.deinit()`/`Runtime.init()` reused
    // inside one test object.
    process_a.stop();
    process_a_running = false;

    // Process B: same server_name, same on-disk persistent ticket-key
    // snapshot (unedited), but credential B. B's own startup durably
    // reserves its own nonce-lease window from the same file (as in
    // `restart.persistent.ticket_survives`), so it can decrypt A's ticket.
    var process_b = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &(extra_env.* ++ [_]EnvPair{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = cred_b.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = cred_b.key_path },
        }),
    });
    defer process_b.stop();

    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2_500;
        }
    };

    // Offer the A ticket to B, which now serves credential B.
    var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&ticket_a);
    errdefer offers.deinit();
    const client = try PureZigTlsClient.createWithOptions(allocator, process_b.port, "http/1.1", "tardigrade.test", .{
        .psk_offers = &offers,
        .psk_now_ctx = &clock_dummy,
        .psk_now_fn = ClientClock.now,
    });
    defer client.destroy();
    // Not selected/binder-verified: `selectPsk` skips straight past an
    // incompatible candidate without ever reaching binder verification, so
    // this is not merely "psk_authenticated happens to be false."
    try std.testing.expect(!client.backend.core.psk_authenticated);
    // Safe full-handshake fallback: the connection still works.
    try client.writeAllPlain(openssl_health_request);
    const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(raw);
    try assertContains(raw, "HTTP/1.1 200 OK");
    try assertContains(raw, "alive");

    var metrics = try sendPureZigTlsHttp1Request(allocator, process_b.port, "/status/metrics");
    defer metrics.deinit();
    // The compatibility/auth-binding outcome specifically, not a decryption
    // miss -- both asserted on B's own metrics, B's first and only
    // resumption attempt so far, so an absolute count is exact here.
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"incompatible\"" }, 1);
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"accepted\"" }) orelse 0);
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"record\"", "outcome=\"miss\"" }) orelse 0);
    // The ticket-resolve layer (key lookup + decrypt) genuinely succeeded --
    // ruling out "unknown key"/decryption failure as the actual cause.
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_ticket_resolve_total", &.{ "mode=\"stateless\"", "result=\"success\"" }, 1);
}

// #519: the general-profile counterpart to `rotation.persistent.failed_
// reload_keeps_old_state` above, exercising the two-phase credential
// prepare/commit path that test's own doc comment explains is unreachable
// under the appliance profile. `edge_gateway.zig` only constructs
// `native_credentials` (`http.native_tls_connection.NativeCredentialStore`)
// under the *general* profile (`build_options.tls_openssl_adapter`), and
// only for QUIC/H3 (`if (build_options.tls_openssl_adapter and
// cfg.http3_enabled and edge_config.hasTlsFiles(cfg))`) -- TCP/H1 under the
// general profile always serves through the OpenSSL-adapter
// `TlsTerminator` instead, which owns its own independent session
// cache/tickets and never touches `native_resumption_runtime` or persistent
// ticket keys at all. So this composed proof necessarily drives real
// QUIC/H3 (the same `gtlsclient` subprocess harness `h3interop.quic.*`
// above uses), not TCP.
//
// Bundles a credential swap with a broken ticket-key candidate in the same
// SIGHUP. This composition -- TLS files configured, so `edge_gateway.zig`
// also constructs the OpenSSL-adapter `TlsTerminator` for TCP/H1 alongside
// `native_credentials` for H3 -- is a mixed OpenSSL-TCP/native-HTTP3 build
// (#629): since `TARDIGRADE_TLS_CERT_PATH`/`_KEY_PATH` are unchanged (only
// the file *content* at that path changes, from A's bytes to B's),
// `hotReloadConfig`'s `nativeCredentialPathsChanged` comparator sees no
// change and doesn't reject outright, but `mixed_credential_owners` being
// true also means `native_credentials.prepareReloadFromFiles` is never
// called at all here (skipped, not called-then-discarded) -- #629 made
// same-path content changes inert for this composition specifically so H3
// can never silently diverge from stable TCP. The ticket-key step, which
// runs independently of that guard, still fails on the broken candidate and
// rejects the whole reload, so the observable outcome (previous ticket
// state and served credential both unchanged) matches what this test always
// asserted; only the internal mechanism changed.
//
// Verifies, against the real external ngtcp2/GnuTLS peer, not merely
// Tardigrade's own report of itself: (1) the previous ticket state is
// still live -- offering the pre-reload session/ticket resumes
// authoritatively (the peer's own decrypted Handshake CRYPTO trace, via
// `assertGtlsSessionReused`) -- and (2) that resumption could only succeed
// if the served certificate is still credential A: a resumed connection's
// auth-binding check compares the ticket's stored binding against
// whichever credential the server is *actually* serving (see
// `rotation.persistent.certificate_binding_change` above for the same
// mechanism proven directly), so credential B having been silently
// committed would make this same offer fail to resume instead. Verifying
// the served certificate fingerprint by an independent, direct channel
// (e.g. inspecting the peer's own certificate chain) is not attempted here
// -- `gtlsclient` (`tests/h3_interop_tool.zig`) does not currently expose
// the negotiated leaf certificate, only handshake CRYPTO bytes and the
// resumption/early-data outcome -- so this is the honest scope: the
// credential-unchanged claim is verified through the same auth-binding
// mechanism, not a second, independent proof.
test "rotation.persistent.quic_credential_reload_atomicity" {
    try requireGeneralTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpensslEd25519(allocator);
    const client_path = try requireNgtcp2Client(allocator);
    defer allocator.free(client_path);

    var cred_a = try generateAlternateServerCert(allocator, quic_interop_server_name);
    defer cred_a.deinit();
    var cred_b = try generateAlternateServerCert(allocator, quic_interop_server_name);
    defer cred_b.deinit();
    const sni_certs = try quicSniCertsEnv(allocator, cred_a.cert_path, cred_a.key_path);
    defer allocator.free(sni_certs);

    const key_path_probe_port = try findFreePort();
    const ticket_keys_path = try persistentTicketKeySnapshotPath(allocator, key_path_probe_port, "persistent-quic-reload-atomicity");
    defer allocator.free(ticket_keys_path);
    defer compat.cwd().deleteFile(ticket_keys_path) catch {};
    defer {
        const lock_path = std.fmt.allocPrint(allocator, "{s}.lock", .{ticket_keys_path}) catch null;
        if (lock_path) |path| {
            compat.cwd().deleteFile(path) catch {};
            allocator.free(path);
        }
    }
    try writePersistentTicketKeySnapshot(allocator, ticket_keys_path);

    const config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
    ;
    const quic_port = try findFreeUdpPort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = cred_a.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = cred_a.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = quic_interop_server_name },
            .{ .name = "TARDIGRADE_TLS_SNI_CERTS", .value = sni_certs },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH", .value = ticket_keys_path },
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
        },
    });
    defer tardigrade.stop();

    const sess_path = try ngtcp2SessionPath(allocator, quic_port, "cred-reload-atomicity");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};
    const tp_path = try ngtcp2TpPath(allocator, quic_port, "cred-reload-atomicity");
    defer allocator.free(tp_path);
    defer compat.cwd().deleteFile(tp_path) catch {};

    // 1: a real full QUIC/TLS 1.3 handshake under credential A, persistent
    // ticket-key-protected resumption state captured to disk.
    var first = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/healthz",
        .session_file = sess_path,
        .tp_file = tp_path,
        .wait_for_ticket = true,
    });
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    try assertContains(first.stderr, "[:status: 200]");

    // 2: swap the served credential's file *content* at its unchanged path
    // (the general profile has no path/name credential-change guard to
    // reject this reload outright the way the appliance profile's
    // `applianceCredentialConfigChanged` would) together with a broken
    // ticket-key candidate, in one SIGHUP.
    {
        const cert_bytes = try compat.cwd().readFileAlloc(allocator, cred_b.cert_path, 64 * 1024);
        defer allocator.free(cert_bytes);
        try compat.cwd().writeFile(.{ .sub_path = cred_a.cert_path, .data = cert_bytes });
        const key_bytes = try compat.cwd().readFileAlloc(allocator, cred_b.key_path, 64 * 1024);
        defer {
            std.crypto.secureZero(u8, key_bytes);
            allocator.free(key_bytes);
        }
        try compat.cwd().writeFile(.{ .sub_path = cred_a.key_path, .data = key_bytes });
    }
    try writeInteropSecretFile(ticket_keys_path, "{not valid json");
    tardigrade.sendSignal(std.posix.SIG.HUP);
    try waitForLabeledMetricAtLeast(allocator, tardigrade.port, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_rejected\""}, 1, 5_000);

    // 3: reconnect with the pre-reload session/ticket. A real resumed
    // connection here is only possible if both the ticket state *and* the
    // served credential are still what they were before the rejected
    // reload attempt.
    var second = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/healthz",
        .session_file = sess_path,
        .tp_file = tp_path,
        .disable_early_data = true,
    });
    defer second.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(second.outcome));
    try assertContains(second.stderr, "[:status: 200]");
    try assertGtlsSessionReused(allocator, second.stderr);

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try expectMetricAtLeast(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"quic\"", "outcome=\"accepted\"" }, 1);
    try std.testing.expectEqual(@as(u64, 0), prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{ "transport=\"quic\"", "outcome=\"incompatible\"" }) orelse 0);
}

// #629: real-process companion to the gateway_shutdown.zig unit tests'
// rejection coverage. Those prove the whole reload is rejected when
// `TLS_CERT_PATH`/`TLS_KEY_PATH`/SNI *configuration* changes; this proves
// the two remaining review-required cases the unit tests cannot reach on
// their own (a from-scratch `hotReloadConfig` call that proceeds to success
// hangs in a bare `zig test` context for reasons unrelated to #629 -- see
// that file's comments): (1) an unrelated, ordinarily-reloadable field still
// takes effect when both TLS surfaces are live and their shared configured
// path is unchanged, and (2) an invalid same-path credential-file
// replacement cannot partially publish to either surface -- because
// `mixed_credential_owners` being true means `hotReloadConfig` never even
// attempts to read the native H3 credential files here, not merely that a
// read failed and was discarded.
//
// Named under the `rotation.` prefix (not a bare `hotReloadConfig ...` name)
// so `zig build test-integration-resumption-interop` -- the required
// general-profile CI job that already provisions the external ngtcp2/GnuTLS
// H3 peer -- actually exercises it; the generic `test-integration` step is
// not a required PR check. H3 identity is verified the same way
// `rotation.persistent.quic_credential_reload_atomicity` above proves it:
// a resumed connection's auth-binding check only succeeds if the served
// credential is unchanged, since `gtlsclient` doesn't expose the negotiated
// leaf certificate directly (see that test's own doc comment) -- a direct
// external proof H3 never picked up the invalid same-path replacement, not
// an inference from the accepted reload alone.
test "rotation.mixed_identity.same_path_invalid_replacement_and_unrelated_reload" {
    try requireGeneralTlsProfile();
    const allocator = std.testing.allocator;
    try requireOpensslEd25519(allocator);
    const client_path = try requireNgtcp2Client(allocator);
    defer allocator.free(client_path);

    // Both stable TCP and native HTTP/3 are constructed from this exact
    // same configured path (matching `edge_gateway.run()`'s production
    // wiring), so they start on the same identity by construction and this
    // is a genuine mixed OpenSSL-TCP/native-HTTP3 composition. A throwaway
    // generated identity, not a checked-in fixture, since this test
    // overwrites the file content in place below.
    var cred_a = try generateAlternateServerCert(allocator, quic_interop_server_name);
    defer cred_a.deinit();

    const first_responses = [_]UpstreamResponseSpec{.{ .body = "first-location" }};
    const second_responses = [_]UpstreamResponseSpec{.{ .body = "second-location" }};
    var first_upstream = try UpstreamServer.start(allocator, &first_responses);
    defer first_upstream.stop();
    try first_upstream.run();
    var second_upstream = try UpstreamServer.start(allocator, &second_responses);
    defer second_upstream.stop();
    try second_upstream.run();

    const initial_config = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\location /dynamic/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, first_upstream.port() });
    defer allocator.free(initial_config);

    const quic_port = try findFreeUdpPort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    // The external H3 peer sends SNI for `quic_interop_server_name`; without
    // registering that hostname in the native SNI provider, unknown SNI fails
    // closed and the initial handshake never gets past `NoApplicableCredential`
    // (see the sibling `rotation.persistent.quic_credential_reload_atomicity`
    // fixture above, which sets this for the same reason).
    const sni_certs = try quicSniCertsEnv(allocator, cred_a.cert_path, cred_a.key_path);
    defer allocator.free(sni_certs);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = initial_config,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = cred_a.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = cred_a.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = quic_interop_server_name },
            .{ .name = "TARDIGRADE_TLS_SNI_CERTS", .value = sni_certs },
            // Ephemeral (not persistent) resumption keys are enough here:
            // that state is process-owned and untouched by `hotReloadConfig`
            // regardless of #629, so a SIGHUP can't rotate it out from under
            // this test either way -- only a resumable ticket is needed to
            // prove the credential binding below.
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
        },
    });
    defer tardigrade.stop();

    // TCP is genuinely serving identity A over a real handshake before any
    // reload.
    const subject_before = try opensslPresentedSubject(allocator, tardigrade.port, quic_interop_server_name);
    defer allocator.free(subject_before);
    try assertContains(subject_before, quic_interop_server_name);

    var first_response = try sendCurlRequest(allocator, tardigrade.port, .{ .path = "/dynamic/test", .insecure = true });
    defer first_response.deinit();
    try assertContains(first_response.body, "first-location");

    const sess_path = try ngtcp2SessionPath(allocator, quic_port, "mixed-identity-reload");
    defer allocator.free(sess_path);
    defer compat.cwd().deleteFile(sess_path) catch {};
    const tp_path = try ngtcp2TpPath(allocator, quic_port, "mixed-identity-reload");
    defer allocator.free(tp_path);
    defer compat.cwd().deleteFile(tp_path) catch {};

    // 1: a real full QUIC/TLS 1.3 handshake under credential A, capturing a
    // resumable ticket.
    var first = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/healthz",
        .session_file = sess_path,
        .tp_file = tp_path,
        .wait_for_ticket = true,
    });
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(first.outcome));
    if (std.mem.indexOf(u8, first.stderr, "[:status: 200]") == null) {
        std.debug.print("rotation.mixed_identity: first gtlsclient outcome={any} stderr={s}\n", .{ first.outcome, first.stderr });
    }
    try assertContains(first.stderr, "[:status: 200]");

    // 2: overwrite the *same* configured cert/key path with unparsable
    // bytes -- not even a different valid identity -- and change an
    // unrelated, ordinarily-reloadable field, in the same SIGHUP.
    try compat.cwd().writeFile(.{ .sub_path = cred_a.cert_path, .data = "not a certificate\n" });
    try compat.cwd().writeFile(.{ .sub_path = cred_a.key_path, .data = "not a key\n" });
    const updated_config = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\location /dynamic/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, second_upstream.port() });
    defer allocator.free(updated_config);
    try tardigrade.rewriteConfig(updated_config);
    tardigrade.sendSignal(std.posix.SIG.HUP);
    compat.sleepNs(300 * std.time.ns_per_ms);

    // 3: the reload as a whole succeeded -- the credential portion was
    // never touched at all (skipped by `mixed_credential_owners`), not
    // merely attempted and rejected -- and the unrelated field took effect.
    var status = try sendCurlRequest(allocator, tardigrade.port, .{ .path = "/tardigrade/reload/status", .insecure = true });
    defer status.deinit();
    try assertContains(status.body, "\"ok\":true");

    var second_response = try sendCurlRequest(allocator, tardigrade.port, .{ .path = "/dynamic/test", .insecure = true });
    defer second_response.deinit();
    try assertContains(second_response.body, "second-location");

    // 4: TCP is still serving identity A over a real handshake.
    const subject_after = try opensslPresentedSubject(allocator, tardigrade.port, quic_interop_server_name);
    defer allocator.free(subject_after);
    try assertContains(subject_after, quic_interop_server_name);

    // 5: reconnect with the pre-reload session/ticket over the real H3/QUIC
    // path. A resumed connection is only possible if the served credential
    // is still what it was before the SIGHUP -- a direct, external proof
    // that H3 never picked up the invalid same-path replacement either.
    var second = try runGtlsClient(allocator, client_path, .{
        .quic_port = quic_port,
        .path = "/healthz",
        .session_file = sess_path,
        .tp_file = tp_path,
        .disable_early_data = true,
    });
    defer second.deinit(allocator);
    try std.testing.expectEqual(std.meta.Tag(bounded_process.Outcome).normal_exit, std.meta.activeTag(second.outcome));
    if (std.mem.indexOf(u8, second.stderr, "[:status: 200]") == null) {
        std.debug.print("rotation.mixed_identity: second gtlsclient outcome={any} stderr={s}\n", .{ second.outcome, second.stderr });
    }
    try assertContains(second.stderr, "[:status: 200]");
    try assertGtlsSessionReused(allocator, second.stderr);
}

/// #369: `TARDIGRADE_SOAK_HEAVY=1` scales `soak.reconnect_resumption` up
/// from its CI-smoke iteration count to the heavy-tier count. Unset (the
/// default) keeps the normal `zig build test-integration-resumption-interop`
/// run fast and deterministic.
fn soakHeavyEnabled() bool {
    const value = compat.getEnvVarOwned(std.heap.page_allocator, "TARDIGRADE_SOAK_HEAVY") catch return false;
    defer std.heap.page_allocator.free(value);
    return std.mem.eql(u8, value, "1");
}

// soak.reconnect_resumption: repeated full-handshake -> ticket -> resumed
// reconnect cycles against one long-lived process, tracking the counts
// #369 requires. There is no accepted-0-RTT/rejected-0-RTT leg here --
// native TCP 0-RTT is not a production capability yet (see #510 and
// docs/RESUMPTION_TEST_PLAN.md), so this soak's cycle is the part of the
// documented `full handshake -> ticket issuance -> resumed reconnect ->
// repeat` loop that production code actually supports today.
//
// `/healthz` is proxied to a real loopback origin rather than served by a
// static `return` directive, and the exactly-once invariant below is
// counted by that origin's own atomic request counter -- not by the
// client observing a successful HTTP response. A client-side response
// counter cannot distinguish "the server dispatched this request exactly
// once" from "the server dispatched it twice but only one response made
// it back"; only a counter incremented inside the real
// application/upstream dispatch hook can.
//
// Known gap: there is no exposed gauge for server-side resumption-cache
// occupancy (only issuance/outcome counters), so "memory/cache growth
// converges to configured bounds" is proven here only via the *cache's
// own* bounded-capacity unit tests (`test-session-cache`, #364) plus this
// loop never regressing the counted invariants below over many iterations
// -- not via a live occupancy sample. Documented rather than asserted on a
// metric that does not exist.
test "soak.reconnect_resumption" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "alive", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const iterations: usize = if (soakHeavyEnabled()) 2_000 else 40;

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_runtime = try tls_core.resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 2_000;
            }
        }.now },
        client_provider.cryptoProvider(),
    );
    defer client_runtime.deinit();

    const SoakTicketCapture = struct {
        allocator: std.mem.Allocator,
        runtime: *tls_core.resumption_runtime.Runtime,
        retained: tls_core.session.ClientTicketState = .{},

        fn now(_: *anyopaque) i64 {
            return 2_000;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.retained.deinit();
            self.retained = .{};
            ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
            _ = self.runtime.storeClientTicket(ticket);
        }
    };

    var accepted_count: usize = 0;

    var iter: usize = 0;
    while (iter < iterations) : (iter += 1) {
        var capture = SoakTicketCapture{ .allocator = allocator, .runtime = &client_runtime };
        defer capture.retained.deinit();

        const first_client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .ticket_consumer = .{
                .ctx = &capture,
                .nowUnixMsFn = SoakTicketCapture.now,
                .onTicketFn = SoakTicketCapture.onTicket,
            },
        });
        defer first_client.destroy();
        try first_client.writeAllPlain(openssl_health_request);
        const first_raw = try first_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(first_raw);
        try assertContains(first_raw, "HTTP/1.1 200 OK");

        const candidate: tls_core.session.CandidateContext = .{
            .cipher_suite = capture.retained.common.cipher_suite,
            .server_name = if (capture.retained.common.server_name) |*s| s.slice() else null,
            .application_protocol = if (capture.retained.common.application_protocol) |*a| a.slice() else null,
            .auth_binding = capture.retained.common.auth_binding,
            .transport_compat = null,
            .application_compat = null,
        };
        var lookup = client_runtime.lookupClientOffers(candidate);
        defer lookup.deinit();
        if (lookup != .hit) return error.NoTicketOfferedThisIteration;

        var clock_dummy: u8 = 0;
        const SoakClientClock = struct {
            fn now(_: *anyopaque) i64 {
                return 2_500;
            }
        };
        const resumed_client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
            .psk_lease = &lookup.hit,
            .psk_now_ctx = &clock_dummy,
            .psk_now_fn = SoakClientClock.now,
        });
        defer resumed_client.destroy();
        if (resumed_client.backend.core.psk_authenticated) accepted_count += 1;
        try resumed_client.writeAllPlain(openssl_health_request);
        const resumed_raw = try resumed_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(resumed_raw);
        try assertContains(resumed_raw, "HTTP/1.1 200 OK");
    }

    // Required invariant: application executions == legitimate requests
    // expected to execute, exactly -- two per iteration, one per
    // connection -- counted by the real origin's own atomic counter,
    // incremented only inside its actual dispatch handler
    // (`handleUpstreamConnection`), never derived from the client having
    // observed a successful response.
    const execution_count = upstream.requestCount();
    try std.testing.expectEqual(@as(u32, @intCast(iterations * 2)), execution_count);
    // Every resumed reconnect actually resumed -- a soak that silently
    // degraded to full handshakes partway through would still pass a
    // looser ">= some fraction" check.
    try std.testing.expectEqual(iterations, accepted_count);

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    const accepted_metric = prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0;
    try std.testing.expect(accepted_metric >= iterations);

    // #369 artifact requirement: record the seed/iteration/result triple
    // for reproduction. This loop is already fully deterministic (fixed
    // synthetic clock, no randomness in the connect pattern), so there is
    // no PRNG seed to report beyond the iteration count itself.
    std.debug.print(
        "soak.reconnect_resumption: iterations={d} accepted={d} executions={d} heavy={}\n",
        .{ iterations, accepted_count, execution_count, soakHeavyEnabled() },
    );
}

// #520: closes the remaining multi-process persistent-key rows from #369's
// resumption/0-RTT validation matrix. #519 (Slice 4, above) proved a
// single process's own restart/rotation/reload lifecycle against a
// persistent snapshot; this proves the same guarantees hold when *two
// real, live* Tardigrade processes share one on-disk snapshot and
// genuinely contend its `${path}.lock` -- both at concurrent startup and
// across concurrent SIGHUP rotation -- not merely in sequence.
//
// Deliberately scoped to two processes rather than the issue's suggested
// heavy-tier three: `ticket_key_snapshot.reserveNonceLeasesInFile`
// serializes entirely on one exclusive file lock, so a third contender
// adds more races on the *same* lock, not a qualitatively different one,
// and generalizing every phase below from named `process_a`/`process_b` to
// an N-process loop would roughly double this test's size for that
// marginal property. `TARDIGRADE_SOAK_HEAVY=1` instead scales rotation-
// round count and per-round ticket sample size -- the properties the
// acceptance criteria actually call out ("materially increases...
// rotation... churn"), not the exact process count.
test "soak.persistent.multi_process_nonce_safety" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const key_path_probe_port = try findFreePort();
    const ticket_keys_path = try persistentTicketKeySnapshotPath(allocator, key_path_probe_port, "soak-multi-process-nonce-safety");
    defer allocator.free(ticket_keys_path);
    defer compat.cwd().deleteFile(ticket_keys_path) catch {};
    defer {
        const lock_path = std.fmt.allocPrint(allocator, "{s}.lock", .{ticket_keys_path}) catch null;
        if (lock_path) |path| {
            compat.cwd().deleteFile(path) catch {};
            allocator.free(path);
        }
    }

    // Generously wide: ordinary readiness/metrics connections issuing
    // their own best-effort tickets along the way must never accidentally
    // exhaust this and turn this soak into the (deliberately separate)
    // exhaustion case below.
    const lease_width: u64 = 1_000_000;

    // A small fixed pool of distinct key identities -- one active
    // generation-1 key plus up to seven successor keys, comfortably
    // covering both the smoke tier's 2 rotation rounds and the heavy
    // tier's 6. Generated as comptime literals rather than at runtime:
    // every round's *new* key must be one this file has never declared
    // before (`TicketKeyFixture.nonce_lease`'s doc comment -- a key's
    // declared lease width is a permanent per-key-id ledger entry), and a
    // small fixed pool sidesteps runtime hex-string allocation/lifetime
    // bookkeeping for what is otherwise a bounded, known-in-advance count.
    const key_ids = [_][]const u8{
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
        "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
        "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4",
        "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
        "a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6",
        "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
    };
    const key_secrets = [_][]const u8{
        "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
        "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
        "b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3",
        "b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4",
        "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5",
        "b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6",
        "b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7",
    };
    const key_prefixes = [_][]const u8{
        "61000000", "62000000", "63000000", "64000000", "65000000", "66000000", "67000000",
    };

    const gen1_now = compat.milliTimestamp();
    try writePersistentTicketKeySnapshotKeys(allocator, ticket_keys_path, 1, &.{
        .{
            .id_hex = key_ids[0],
            .key_hex = key_secrets[0],
            .not_before_unix_ms = gen1_now - 60_000,
            // Comfortably longer than the default 24h ticket lifetime --
            // `ticket_protection.ticketExpiresWithinKey` silently refuses
            // to seal any ticket whose `issued_at + ticket_lifetime` would
            // outlive the sealing key's own `decrypt_until` (`TicketOutlivesKey`),
            // so a shorter window here would fail every issuance in this
            // test closed before it ever reached the wire (see #519's
            // `rotation.persistent.n_to_n_plus_1` for the same pitfall).
            .encrypt_until_unix_ms = gen1_now + 25 * 60 * 60 * 1000,
            .decrypt_until_unix_ms = gen1_now + 26 * 60 * 60 * 1000,
            .nonce_lease = .{ .prefix_hex = key_prefixes[0], .start = 0, .end_exclusive = lease_width },
        },
    });

    // One gated upstream per process, proxied to from a `/race` route
    // declared in that process's own config -- the heavy tier's real
    // worker-overlap proof below drives one request through each of
    // these, per round, and holds it there under the test's own control
    // while the reservation lock is held. Created (and their `/race`
    // route wired) regardless of tier, since the process's own config
    // is fixed at startup and can't be changed per-round; only the
    // smoke tier simply never drives traffic through it.
    //
    // `std.heap.page_allocator`, not `allocator` (`std.testing.
    // allocator`): the gate's own thread allocates/frees concurrently
    // with the main test thread, and `std.testing.allocator`'s backing
    // `DebugAllocator` is not safe for concurrent use from multiple
    // threads (Zig 0.16 still lists that as planned, not implemented) --
    // the same reason `ChurnWorker` already uses `std.heap.page_
    // allocator` for its own thread's allocations.
    var gate_a = try GatedUpstream.start(std.heap.page_allocator);
    defer gate_a.stop();
    try gate_a.run();
    var gate_b = try GatedUpstream.start(std.heap.page_allocator);
    defer gate_b.stop();
    try gate_b.run();

    const config_text_a = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\location = /race {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, gate_a.port() });
    defer allocator.free(config_text_a);
    const config_text_b = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\location = /race {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, gate_b.port() });
    defer allocator.free(config_text_b);

    const shared_extra_env = &[_]EnvPair{
        .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
        .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
        .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
        .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
        .{ .name = "TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH", .value = ticket_keys_path },
    };
    const process_options_a = TardigradeOptions{
        .config_text = config_text_a,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = shared_extra_env,
    };
    const process_options_b = TardigradeOptions{
        .config_text = config_text_b,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = shared_extra_env,
    };

    // Phase 1: *forced*, not merely likely, concurrent startup reservation.
    // `spawn()`-then-`spawn()` alone only makes concurrent reservation
    // probable -- on an unlucky scheduling order, process A could fully
    // complete `reserveNonceLeasesInFile()` before B ever reaches that
    // code, and every assertion below would still pass even if
    // `${path}.lock` serialization were entirely broken, since the two
    // reservations happened sequentially by accident. To make the test
    // fail deterministically if that serialization is ever removed, this
    // test itself first acquires `${ticket_keys_path}.lock` -- the exact
    // same `createFile(..., .lock = .exclusive)` call
    // `ticket_key_snapshot.acquireReservationLock` uses, so it is a real
    // OS-level advisory lock that genuinely blocks both children's own
    // in-startup reservation attempt, not a test-only substitute. The lock
    // is released only once `waitForReservationAttempt` has observed, on
    // *both* processes, the secret-free marker `edge_gateway.zig` logs
    // immediately before entering the reservation path -- a real observed-
    // arrival condition, not a fixed delay that could still let a slower
    // process reach the lock attempt only after an early release.
    const startup_barrier_lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{ticket_keys_path});
    defer allocator.free(startup_barrier_lock_path);
    var startup_barrier = try compat.cwd().createFile(startup_barrier_lock_path, .{
        .read = true,
        .truncate = false,
        .permissions = .fromMode(0o600),
        .lock = .exclusive,
    });

    var process_a = try TardigradeProcess.spawn(allocator, process_options_a);
    defer process_a.stop();
    var process_b = try TardigradeProcess.spawn(allocator, process_options_b);
    defer process_b.stop();

    try waitForReservationAttemptCount(allocator, process_a.log_path, 1, 5_000);
    try waitForReservationAttemptCount(allocator, process_b.log_path, 1, 5_000);
    startup_barrier.close();

    try process_a.waitReady(process_options_a);
    try process_b.waitReady(process_options_b);

    const after_both_start = try readTicketKeyLeaseWindow(allocator, ticket_keys_path, key_ids[0]);
    try std.testing.expectEqual(@as(u64, 1), after_both_start.generation);
    try std.testing.expectEqual(2 * lease_width, after_both_start.start);
    try std.testing.expectEqual(3 * lease_width, after_both_start.end_exclusive);

    var all_tuples = std.array_list.Managed(TicketEnvelopeIds).init(allocator);
    defer all_tuples.deinit();

    const samples_per_process: usize = if (soakHeavyEnabled()) 32 else 8;

    var ids_a = std.array_list.Managed(TicketEnvelopeIds).init(allocator);
    defer ids_a.deinit();
    var ids_b = std.array_list.Managed(TicketEnvelopeIds).init(allocator);
    defer ids_b.deinit();

    var i: usize = 0;
    while (i < samples_per_process) : (i += 1) {
        const ids = try issueTicketIds(allocator, process_a.port);
        try std.testing.expectEqualStrings(key_ids[0], &std.fmt.bytesToHex(ids.key_id, .lower));
        try all_tuples.append(ids);
        try ids_a.append(ids);
    }
    i = 0;
    while (i < samples_per_process) : (i += 1) {
        const ids = try issueTicketIds(allocator, process_b.port);
        try std.testing.expectEqualStrings(key_ids[0], &std.fmt.bytesToHex(ids.key_id, .lower));
        try all_tuples.append(ids);
        try ids_b.append(ids);
    }
    try assertNoDuplicateTicketIds(all_tuples.items);

    // Each process's emitted nonce counters stay inside exactly one of the
    // two disjoint reserved windows -- which one is scheduling-dependent
    // (whichever process won the lock race first gets `[w, 2w)`), so this
    // resolves each process's own window from its own first sample rather
    // than assuming an ordering.
    const a_window = try resolveReservedWindow(ticketNonceCounter(ids_a.items[0]), lease_width);
    for (ids_a.items) |ids| {
        const counter = ticketNonceCounter(ids);
        try std.testing.expect(counter >= a_window.start and counter < a_window.end_exclusive);
    }
    const b_window = try resolveReservedWindow(ticketNonceCounter(ids_b.items[0]), lease_width);
    for (ids_b.items) |ids| {
        const counter = ticketNonceCounter(ids);
        try std.testing.expect(counter >= b_window.start and counter < b_window.end_exclusive);
    }
    try std.testing.expect(a_window.start != b_window.start);

    // Phase 2: concurrent generation rotation, `rounds` times. Each round
    // retires the previously-active key (`nonce_lease = null` -- it will
    // never encrypt again, so it needs no lease at all, matching #519's
    // own rotation-lease rule) and installs a fresh encryption-capable
    // successor with its own `[0, lease_width)` lease.
    const rounds: usize = if (soakHeavyEnabled()) 6 else 2;
    try std.testing.expect(rounds < key_ids.len);

    var retiring_index: usize = 0;
    var current_generation: u64 = 1;

    var round: usize = 0;
    while (round < rounds) : (round += 1) {
        const new_index = round + 1;
        const new_generation = current_generation + 1;

        // Retain a small bounded sample ticket from the outgoing
        // generation before rotating -- proves in-flight state survives
        // the reload, on both processes, below.
        var sample_ticket = try issueAndRetainTicket(allocator, process_a.port);
        defer sample_ticket.deinit();

        const round_now = compat.milliTimestamp();
        try writePersistentTicketKeySnapshotKeys(allocator, ticket_keys_path, new_generation, &.{
            .{
                .id_hex = key_ids[retiring_index],
                .key_hex = key_secrets[retiring_index],
                .not_before_unix_ms = round_now - 3_600_000,
                .encrypt_until_unix_ms = round_now - 100,
                // A generous overlap grace window: #520 is proving
                // concurrent multi-process rotation safety, not
                // re-proving the grace-window-closes boundary #519's
                // `rotation.persistent.n_to_n_plus_1` already covers.
                .decrypt_until_unix_ms = round_now + 120_000,
                .nonce_lease = null,
            },
            .{
                .id_hex = key_ids[new_index],
                .key_hex = key_secrets[new_index],
                .not_before_unix_ms = round_now - 100,
                // Same 24h-ticket-lifetime headroom as the generation-1 key
                // above -- this key must seal fresh tickets for the rest of
                // the soak.
                .encrypt_until_unix_ms = round_now + 25 * 60 * 60 * 1000,
                .decrypt_until_unix_ms = round_now + 26 * 60 * 60 * 1000,
                .nonce_lease = .{ .prefix_hex = key_prefixes[new_index], .start = 0, .end_exclusive = lease_width },
            },
        });

        const reload_accepted_before_a = try currentLabeledMetric(allocator, process_a.port, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_accepted\""});
        const reload_accepted_before_b = try currentLabeledMetric(allocator, process_b.port, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_accepted\""});

        // Heavy tier only: keep real request/ticket-issuance traffic
        // flowing against *both* processes across the reload race below.
        //
        // The cleanup defer is registered *before* any fallible operation
        // that could unwind this scope (`std.Thread.spawn`, the
        // `waitForLabeledMetricAtLeast` polls below) -- if reload never
        // reaches `reload_accepted` (exactly the failure this soak wants
        // to diagnose), the workers must still be signaled to stop and
        // joined here, not left running against stack-owned state after
        // the enclosing `process_*` defers kill the children out from
        // under them. `churn_thread_{a,b}` are set back to `null` once
        // explicitly joined on the success path below so this deferred
        // block's own join calls become harmless no-ops rather than an
        // illegal double-join.
        var churn_stop = std.atomic.Value(bool).init(false);
        var churn_a: ?ChurnWorker = null;
        var churn_b: ?ChurnWorker = null;
        var churn_thread_a: ?std.Thread = null;
        var churn_thread_b: ?std.Thread = null;
        defer {
            churn_stop.store(true, .release);
            if (churn_thread_a) |t| t.join();
            if (churn_thread_b) |t| t.join();
            if (churn_a) |*w| w.deinit();
            if (churn_b) |*w| w.deinit();
        }
        if (soakHeavyEnabled()) {
            churn_a = ChurnWorker.init(process_a.port, &churn_stop, key_ids[retiring_index], key_ids[new_index]);
            churn_thread_a = try std.Thread.spawn(.{}, ChurnWorker.run, .{&churn_a.?});
            churn_b = ChurnWorker.init(process_b.port, &churn_stop, key_ids[retiring_index], key_ids[new_index]);
            churn_thread_b = try std.Thread.spawn(.{}, ChurnWorker.run, .{&churn_b.?});

            // Establishes the pre-reload half of the continuity proof
            // deterministically, while both event loops are completely
            // free to process socket I/O -- must happen before touching
            // the reservation barrier below, since waiting for churn
            // progress once `hotReloadConfig` has blocked on it is
            // architecturally impossible (see `ChurnWorker`'s doc
            // comment). Without this, `expectSpansBothGenerations` at the
            // end of the round could fail purely on thread-scheduling
            // luck if neither worker happened to be scheduled before
            // reload began.
            try waitForChurnGenerationSeen(&churn_a.?.saw_outgoing, 5_000);
            try waitForChurnGenerationSeen(&churn_b.?.saw_outgoing, 5_000);
        }

        // The real worker-overlap proof #520 asks for, heavy tier only:
        // `edge_gateway.run` has a separate `WorkerPool` alongside its
        // single-threaded event loop, so once a native H1 connection has
        // actually been accepted and dispatched (`advanceNativeHttp1`
        // running on a worker, `WaitingEncryptedHttpConnection.waitFor`
        // polling its own fd directly), it can keep making progress even
        // while the main loop is blocked inside synchronous
        // `hotReloadConfig` -- blocking that one thread only prevents
        // *new* accepts, not already-dispatched work. `gate_{a,b}` proxy
        // one real request per process to a point held entirely under
        // this test's control, so `waitEntered` below deterministically
        // proves each request has already been accepted, dispatched, and
        // proxied all the way to its upstream *before* either reload
        // begins -- a real condition, not a fixed delay.
        //
        // The cleanup defer releases both gates and joins any spawned
        // race thread unconditionally, registered before the fallible
        // spawns/waits below -- if a later `try` in this round fails
        // (reload never reaching `reload_accepted`, say), a race thread
        // left blocked waiting on a never-released gate must not leak
        // past this scope, the same lesson the churn-worker lifetime fix
        // already applied.
        var race_result_a = RaceRequestResult{};
        var race_result_b = RaceRequestResult{};
        var race_thread_a: ?std.Thread = null;
        var race_thread_b: ?std.Thread = null;
        defer {
            gate_a.release();
            gate_b.release();
            if (race_thread_a) |t| t.join();
            if (race_thread_b) |t| t.join();
        }
        if (soakHeavyEnabled()) {
            gate_a.resetGate();
            gate_b.resetGate();
            // `std.heap.page_allocator`, not `allocator`: this thread runs
            // concurrently with the main test thread (and the gate's own
            // thread), and `std.testing.allocator` is not safe for
            // concurrent use -- same reasoning as `GatedUpstream.start`
            // above and `ChurnWorker` elsewhere in this file.
            race_thread_a = try std.Thread.spawn(.{}, runTlsRaceRequest, .{ std.heap.page_allocator, process_a.port, &race_result_a });
            race_thread_b = try std.Thread.spawn(.{}, runTlsRaceRequest, .{ std.heap.page_allocator, process_b.port, &race_result_b });
            try gate_a.waitEntered(5_000);
            try gate_b.waitEntered(5_000);
        }

        // Forces the two real SIGHUP handlers to genuinely block on
        // `${ticket_keys_path}.lock` at the same time, exactly the same
        // technique the concurrent-startup phase above uses: this test
        // acquires the lock itself, *before* sending either signal, using
        // the same `createFile(..., .lock = .exclusive)` call production
        // uses. `reservation_marker_count_before_{a,b}` snapshots each
        // process's own reservation-attempt log-marker count immediately
        // before this round's signal, so `waitForReservationAttemptCount`
        // below can detect *this round's* attempt specifically (the
        // marker also fired once at startup and once per earlier round),
        // not an already-satisfied earlier one.
        const reservation_marker_count_before_a = countReservationAttemptMarkers(allocator, process_a.log_path);
        const reservation_marker_count_before_b = countReservationAttemptMarkers(allocator, process_b.log_path);
        var reload_barrier = try compat.cwd().createFile(startup_barrier_lock_path, .{
            .read = true,
            .truncate = false,
            .permissions = .fromMode(0o600),
            .lock = .exclusive,
        });

        // Sent back-to-back, without waiting between them.
        process_a.sendSignal(std.posix.SIG.HUP);
        process_b.sendSignal(std.posix.SIG.HUP);

        // Both real SIGHUP handlers have now reached
        // `reserveNonceLeasesInFile` and are demonstrably blocked on the
        // lock this test still holds -- not merely "probably racing".
        try waitForReservationAttemptCount(allocator, process_a.log_path, reservation_marker_count_before_a + 1, 5_000);
        try waitForReservationAttemptCount(allocator, process_b.log_path, reservation_marker_count_before_b + 1, 5_000);

        // Both main event loops are now confirmed blocked in reload --
        // but each gated request (heavy tier only) was already accepted
        // and dispatched to a worker *before* that happened, so releasing
        // it here and requiring its completion *before* the lock itself
        // is released is the actual proof that real request/ticket-
        // adjacent traffic was genuinely in flight during the reload
        // race, not merely before or after it. `ChurnWorker`'s own
        // connections deliberately are not required to complete here
        // (see its doc comment): only an *already-dispatched* connection
        // can make progress while the main loop is blocked, and a churn
        // worker's next connection attempt has no such guarantee.
        if (soakHeavyEnabled()) {
            gate_a.release();
            gate_b.release();
            try waitForRaceRequestComplete(&race_result_a, 5_000);
            try waitForRaceRequestComplete(&race_result_b, 5_000);
        }

        reload_barrier.close();

        if (soakHeavyEnabled()) {
            race_thread_a.?.join();
            race_thread_b.?.join();
            race_thread_a = null;
            race_thread_b = null;
            if (race_result_a.err) |err| return err;
            if (race_result_b.err) |err| return err;
            try std.testing.expect(race_result_a.status_ok);
            try std.testing.expect(race_result_b.status_ok);
        }

        // Now that the lock is released, both processes' real
        // reservations proceed and each (eventually) reports its own
        // `reload_accepted` independently. Immediately after observing
        // *that specific process's* acceptance, an explicit, synchronous,
        // single-shot probe -- not sampled off a concurrently running
        // churn worker, which cannot safely establish this boundary no
        // matter which side of a request it samples -- proves fresh
        // issuance is already exclusively the incoming key.
        try waitForLabeledMetricAtLeast(allocator, process_a.port, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_accepted\""}, reload_accepted_before_a + 1, 5_000);
        const post_accept_ids_a = try issueTicketIds(allocator, process_a.port);
        try std.testing.expectEqualStrings(key_ids[new_index], &std.fmt.bytesToHex(post_accept_ids_a.key_id, .lower));
        try all_tuples.append(post_accept_ids_a);

        try waitForLabeledMetricAtLeast(allocator, process_b.port, "tardigrade_tls_ticket_key_reload_total", &.{"outcome=\"reload_accepted\""}, reload_accepted_before_b + 1, 5_000);
        const post_accept_ids_b = try issueTicketIds(allocator, process_b.port);
        try std.testing.expectEqualStrings(key_ids[new_index], &std.fmt.bytesToHex(post_accept_ids_b.key_id, .lower));
        try all_tuples.append(post_accept_ids_b);
        try assertNoDuplicateTicketIds(all_tuples.items);

        if (soakHeavyEnabled()) {
            // Establishes the post-reload half of the continuity proof.
            // The reservation barrier has already been released and both
            // processes have independently reported `reload_accepted`,
            // so their event loops are free to process socket I/O again
            // here -- waiting for churn progress at this point cannot
            // recreate the held-lock deadlock.
            try waitForChurnGenerationSeen(&churn_a.?.saw_incoming, 5_000);
            try waitForChurnGenerationSeen(&churn_b.?.saw_incoming, 5_000);

            churn_stop.store(true, .release);
            churn_thread_a.?.join();
            churn_thread_b.?.join();
            churn_thread_a = null;
            churn_thread_b = null;

            // A silently swallowed issuance failure could leave a worker
            // with zero samples while the test still sails through the
            // post-reload probes below -- assert both stayed healthy and
            // actually produced traffic, not merely that they didn't
            // observe a wrong key id.
            try std.testing.expect(churn_a.?.failure == null);
            try std.testing.expect(churn_b.?.failure == null);
            try std.testing.expect(churn_a.?.results.items.len > 0);
            try std.testing.expect(churn_b.?.results.items.len > 0);

            // Traffic actually spanned the transition: each worker's
            // collected samples include both the outgoing and the
            // incoming generation's key id, not merely "some traffic
            // happened at some point in the round".
            try expectSpansBothGenerations(churn_a.?.results.items, key_ids[retiring_index], key_ids[new_index]);
            try expectSpansBothGenerations(churn_b.?.results.items, key_ids[retiring_index], key_ids[new_index]);

            for (churn_a.?.results.items) |ids| try all_tuples.append(ids);
            for (churn_b.?.results.items) |ids| try all_tuples.append(ids);
            try assertNoDuplicateTicketIds(all_tuples.items);
        }

        const lease_after_round = try readTicketKeyLeaseWindow(allocator, ticket_keys_path, key_ids[new_index]);
        try std.testing.expectEqual(new_generation, lease_after_round.generation);
        try std.testing.expectEqual(2 * lease_width, lease_after_round.start);
        try std.testing.expectEqual(3 * lease_width, lease_after_round.end_exclusive);

        // In-flight safety: the retained sample ticket from the outgoing
        // generation still resumes on *both* processes, immediately after
        // each has independently reported `reload_accepted`.
        try resumeTicketExpectAccepted(allocator, process_a.port, &sample_ticket);
        try resumeTicketExpectAccepted(allocator, process_b.port, &sample_ticket);

        var round_ids_a = std.array_list.Managed(TicketEnvelopeIds).init(allocator);
        defer round_ids_a.deinit();
        var round_ids_b = std.array_list.Managed(TicketEnvelopeIds).init(allocator);
        defer round_ids_b.deinit();

        var s: usize = 0;
        while (s < samples_per_process) : (s += 1) {
            const ids_new_a = try issueTicketIds(allocator, process_a.port);
            try std.testing.expectEqualStrings(key_ids[new_index], &std.fmt.bytesToHex(ids_new_a.key_id, .lower));
            try all_tuples.append(ids_new_a);
            try round_ids_a.append(ids_new_a);

            const ids_new_b = try issueTicketIds(allocator, process_b.port);
            try std.testing.expectEqualStrings(key_ids[new_index], &std.fmt.bytesToHex(ids_new_b.key_id, .lower));
            try all_tuples.append(ids_new_b);
            try round_ids_b.append(ids_new_b);
        }
        try assertNoDuplicateTicketIds(all_tuples.items);

        const round_a_window = try resolveReservedWindow(ticketNonceCounter(round_ids_a.items[0]), lease_width);
        for (round_ids_a.items) |ids| {
            const counter = ticketNonceCounter(ids);
            try std.testing.expect(counter >= round_a_window.start and counter < round_a_window.end_exclusive);
        }
        const round_b_window = try resolveReservedWindow(ticketNonceCounter(round_ids_b.items[0]), lease_width);
        for (round_ids_b.items) |ids| {
            const counter = ticketNonceCounter(ids);
            try std.testing.expect(counter >= round_b_window.start and counter < round_b_window.end_exclusive);
        }
        try std.testing.expect(round_a_window.start != round_b_window.start);

        retiring_index = new_index;
        current_generation = new_generation;
    }

    // #369 artifact requirement: bounded, secret-free diagnostics for
    // reproduction -- never key ids/nonces/paths.
    std.debug.print(
        "soak.persistent.multi_process_nonce_safety: heavy={} rounds={d} samples_per_process={d} lease_width={d} final_generation={d} tuples={d}\n",
        .{ soakHeavyEnabled(), rounds, samples_per_process, lease_width, current_generation, all_tuples.items.len },
    );
}

// #520: separate from the large-lease soak above so a failure says
// exactly what broke. Drives real, bounded full-handshake traffic against
// process A until its own deliberately tiny reserved nonce-lease window is
// exhausted, then proves the production `NonceLeaseExhausted` failure path
// is safely isolated: issuance stops, but decryption, resumption, and
// ordinary handshakes on A are unaffected, and process B's own disjoint
// reservation is untouched.
test "soak.persistent.nonce_lease_exhaustion" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const key_path_probe_port = try findFreePort();
    const ticket_keys_path = try persistentTicketKeySnapshotPath(allocator, key_path_probe_port, "soak-nonce-lease-exhaustion");
    defer allocator.free(ticket_keys_path);
    defer compat.cwd().deleteFile(ticket_keys_path) catch {};
    defer {
        const lock_path = std.fmt.allocPrint(allocator, "{s}.lock", .{ticket_keys_path}) catch null;
        if (lock_path) |path| {
            compat.cwd().deleteFile(path) catch {};
            allocator.free(path);
        }
    }

    const lease_width: u64 = 16;
    const key_id = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
    const key_secret = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1";

    const gen1_now = compat.milliTimestamp();
    try writePersistentTicketKeySnapshotKeys(allocator, ticket_keys_path, 1, &.{
        .{
            .id_hex = key_id,
            .key_hex = key_secret,
            .not_before_unix_ms = gen1_now - 60_000,
            // Comfortably longer than the default 24h ticket lifetime --
            // see the matching comment in `soak.persistent.multi_process_
            // nonce_safety` above for why a shorter window here would
            // silently fail every issuance closed (`TicketOutlivesKey`).
            .encrypt_until_unix_ms = gen1_now + 25 * 60 * 60 * 1000,
            .decrypt_until_unix_ms = gen1_now + 26 * 60 * 60 * 1000,
            .nonce_lease = .{ .prefix_hex = "71000000", .start = 0, .end_exclusive = lease_width },
        },
    });

    const config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
    ;
    const process_options = TardigradeOptions{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH", .value = ticket_keys_path },
        },
    };

    var process_a = try TardigradeProcess.start(allocator, process_options);
    defer process_a.stop();
    var process_b = try TardigradeProcess.start(allocator, process_options);
    defer process_b.stop();

    var tuples = std.array_list.Managed(TicketEnvelopeIds).init(allocator);
    defer tuples.deinit();

    // A real ticket issued from A before exhausting its local
    // reservation: must remain resumable after A can no longer mint a new
    // one.
    var pre_exhaustion_ticket = try issueAndRetainTicket(allocator, process_a.port);
    defer pre_exhaustion_ticket.deinit();
    try tuples.append(extractTicketEnvelopeIds(&pre_exhaustion_ticket));

    const failed_before = try currentLabeledMetric(allocator, process_a.port, "tardigrade_tls_ticket_issue_total", &.{ "transport=\"record\"", "mode=\"stateless\"", "result=\"failed\"" });

    // Bounded batches, not a per-connection metrics poll: `/status/metrics`
    // is itself reached over a real TLS connection that can attempt its
    // own best-effort ticket issuance, so polling the failure counter
    // after every single request would conflate that with the batch's own
    // consumption. A's own just-reserved window is at most `lease_width`
    // wide (minus whatever its startup readiness check and the
    // pre-exhaustion ticket above already consumed), so a handful of
    // bounded batches comfortably reaches it without depending on the
    // exact remaining count.
    const batch_size: usize = 8;
    const max_batches: usize = 6;
    var exhausted = false;
    var batch: usize = 0;
    while (batch < max_batches and !exhausted) : (batch += 1) {
        var n: usize = 0;
        while (n < batch_size) : (n += 1) {
            if (try issueTicketIdsOptional(allocator, process_a.port)) |ids| {
                try tuples.append(ids);
            }
        }
        const failed_now = try currentLabeledMetric(allocator, process_a.port, "tardigrade_tls_ticket_issue_total", &.{ "transport=\"record\"", "mode=\"stateless\"", "result=\"failed\"" });
        if (failed_now > failed_before) exhausted = true;
    }
    try std.testing.expect(exhausted);

    try assertNoDuplicateTicketIds(tuples.items);

    // Exhaustion stopped new issuance, but did not tear down the
    // connections that hit it (`issueTicketIdsOptional` already asserted
    // every one of them still got `200 OK`) and does not disturb
    // decryption of a ticket issued before the window closed.
    try resumeTicketExpectAccepted(allocator, process_a.port, &pre_exhaustion_ticket);

    // A brand-new ordinary full handshake to A remains usable.
    {
        const client = try PureZigTlsClient.create(allocator, process_a.port, "http/1.1");
        defer client.destroy();
        try client.writeAllPlain(openssl_health_request);
        const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(raw);
        try assertContains(raw, "HTTP/1.1 200 OK");
    }

    // B's own disjoint local reservation is untouched by A exhausting its
    // own -- B still issues fresh tickets normally, and B's own failure
    // counter stays at zero throughout.
    const ids_b = try issueTicketIds(allocator, process_b.port);
    try std.testing.expectEqualStrings(key_id, &std.fmt.bytesToHex(ids_b.key_id, .lower));
    try tuples.append(ids_b);
    try assertNoDuplicateTicketIds(tuples.items);

    const failed_b = try currentLabeledMetric(allocator, process_b.port, "tardigrade_tls_ticket_issue_total", &.{ "transport=\"record\"", "mode=\"stateless\"", "result=\"failed\"" });
    try std.testing.expectEqual(@as(u64, 0), failed_b);
}

// #520: proves the process-local early-data replay scope
// `docs/OBSERVABILITY.md` already documents is the real production
// behavior, not just prose: two real processes share one persistent
// ticket-key snapshot (so either can decrypt a ticket the other issued)
// but keep independent `process_local` replay stores, so the exact same
// replay identity is legitimately accepted once by *each* process,
// independently, while a same-process replay is still rejected as a
// duplicate.
test "soak.replay.process_local_scope" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    const key_path_probe_port = try findFreePort();
    const ticket_keys_path = try persistentTicketKeySnapshotPath(allocator, key_path_probe_port, "soak-replay-process-local-scope");
    defer allocator.free(ticket_keys_path);
    defer compat.cwd().deleteFile(ticket_keys_path) catch {};
    defer {
        const lock_path = std.fmt.allocPrint(allocator, "{s}.lock", .{ticket_keys_path}) catch null;
        if (lock_path) |path| {
            compat.cwd().deleteFile(path) catch {};
            allocator.free(path);
        }
    }
    try writePersistentTicketKeySnapshot(allocator, ticket_keys_path);

    // Smoke: one replay identity. Heavy: several, after paying the real
    // startup-quarantine wait once -- fixed-size response arrays sized for
    // the heavy-tier max avoid runtime allocator lifetime bookkeeping for
    // what is otherwise a small, known-in-advance count.
    const max_identities = 4;
    const identity_count: usize = if (soakHeavyEnabled()) max_identities else 1;

    // Every identity iteration bootstraps its own fresh ticket through A
    // (one more real upstream hit each time), then drives one early+
    // after-replay pair through A and another through B -- so A needs 3
    // response slots per identity (bootstrap, early, after-replay) and B
    // needs 2 (early, after-replay), each laid out in the exact temporal
    // order those connections actually arrive in, not grouped by response
    // type.
    var upstream_a_specs: [1 + 3 * max_identities]UpstreamResponseSpec = undefined;
    upstream_a_specs[0] = .{ .body = "a-ready", .connection_header = "close" };
    var upstream_b_specs: [1 + 2 * max_identities]UpstreamResponseSpec = undefined;
    upstream_b_specs[0] = .{ .body = "b-ready", .connection_header = "close" };
    for (0..identity_count) |idx| {
        upstream_a_specs[1 + idx * 3] = .{ .body = "a-bootstrap", .connection_header = "close" };
        upstream_a_specs[1 + idx * 3 + 1] = .{ .body = "a-early", .connection_header = "close" };
        upstream_a_specs[1 + idx * 3 + 2] = .{ .body = "a-after-replay", .connection_header = "close" };
        upstream_b_specs[1 + idx * 2] = .{ .body = "b-early", .connection_header = "close" };
        upstream_b_specs[1 + idx * 2 + 1] = .{ .body = "b-after-replay", .connection_header = "close" };
    }

    var upstream_a = try UpstreamServer.start(allocator, upstream_a_specs[0 .. 1 + 3 * identity_count]);
    defer upstream_a.stop();
    try upstream_a.run();
    var upstream_b = try UpstreamServer.start(allocator, upstream_b_specs[0 .. 1 + 2 * identity_count]);
    defer upstream_b.stop();
    try upstream_b.run();

    const config_a = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}}
    , .{ test_host, upstream_a.port() });
    defer allocator.free(config_a);
    const config_b = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}}
    , .{ test_host, upstream_b.port() });
    defer allocator.free(config_b);

    // Same certificate/key on both -- ticket auth-binding
    // (`session.evaluateCompatibility`) requires the identical served
    // credential for the PSK to authenticate at all on either process.
    const shared_extra_env = &[_]EnvPair{
        .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
        .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
        .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
        .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
        .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateless" },
        .{ .name = "TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH", .value = ticket_keys_path },
        .{ .name = "TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE", .value = "process_local" },
    };
    const options_a = TardigradeOptions{
        .config_text = config_a,
        .ready_https_insecure = true,
        .ready_path = "/safe",
        .extra_env = shared_extra_env,
    };
    const options_b = TardigradeOptions{
        .config_text = config_b,
        .ready_https_insecure = true,
        .ready_path = "/safe",
        .extra_env = shared_extra_env,
    };

    // Concurrent startup, then a single shared quarantine wait: the
    // production early-data policy's startup quarantine
    // (`age_skew_tolerance_ms = 60_000`) is real and not shortened for
    // this test -- #518 already covers the fresh-process-rejects-during-
    // quarantine behavior; this test owns the after-quarantine
    // per-process scope. Both processes pay the ~60s wait once, together,
    // since both were already started before it begins.
    var process_a = try TardigradeProcess.spawn(allocator, options_a);
    defer process_a.stop();
    var process_b = try TardigradeProcess.spawn(allocator, options_b);
    defer process_b.stop();
    try process_a.waitReady(options_a);
    try process_b.waitReady(options_b);

    compat.sleepNs(61 * std.time.ns_per_s);

    try upstream_a.resetCapture();
    try upstream_b.resetCapture();

    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2_500;
        }
    };

    var identity: usize = 0;
    while (identity < identity_count) : (identity += 1) {
        // Per-identity metric *deltas*, captured fresh each iteration --
        // not a cumulative `>= 1` check. With `identity_count > 1`, a
        // cumulative check would still pass even if later identities
        // stopped emitting replay events entirely (identity 0's own
        // increment alone would satisfy it forever after); an exact
        // before/after delta for each of the four actions below is the
        // invariant #520 actually asks for. `/status/metrics` reads do not
        // themselves create replay-store accepted/duplicate events, so
        // these deltas are exact, not merely bounded.
        const a_accepted_before = try currentLabeledMetric(allocator, process_a.port, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"accepted\""});
        const a_duplicate_before = try currentLabeledMetric(allocator, process_a.port, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"duplicate\""});
        const b_accepted_before = try currentLabeledMetric(allocator, process_b.port, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"accepted\""});
        const b_duplicate_before = try currentLabeledMetric(allocator, process_b.port, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"duplicate\""});

        const TicketCapture = struct {
            allocator: std.mem.Allocator,
            retained: tls_core.session.ClientTicketState = .{},

            fn now(_: *anyopaque) i64 {
                return 2_000;
            }

            fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
                const self: *@This() = @ptrCast(@alignCast(ctx));
                self.retained.deinit();
                self.retained = .{};
                ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
            }
        };
        var capture = TicketCapture{ .allocator = allocator };
        defer capture.retained.deinit();

        // Bootstrap: a plain (non-early) handshake against A mints the one
        // ticket identity this iteration replays four ways below.
        const bootstrap_client = try PureZigTlsClient.createWithOptions(allocator, process_a.port, "http/1.1", "tardigrade.test", .{
            .ticket_consumer = .{ .ctx = &capture, .nowUnixMsFn = TicketCapture.now, .onTicketFn = TicketCapture.onTicket },
        });
        defer bootstrap_client.destroy();
        try bootstrap_client.writeAllPlain("GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
        const bootstrap_raw = try bootstrap_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
        defer allocator.free(bootstrap_raw);
        try assertContains(bootstrap_raw, "HTTP/1.1 200 OK");
        try assertContains(bootstrap_raw, "a-bootstrap");
        try std.testing.expectEqual(tls_core.session.EarlyDataPolicy{ .early_data_capable = 16 * 1024 }, capture.retained.common.early_data);

        var base_ticket: tls_core.session.ClientTicketState = .{};
        defer base_ticket.deinit();
        try capture.retained.cloneInto(allocator, &base_ticket);

        try upstream_a.resetCapture();

        // A, first use: the exact same identity, offered as early data to
        // A for the first time -- accepted exactly once.
        {
            var clone: tls_core.session.ClientTicketState = .{};
            defer clone.deinit();
            try base_ticket.cloneInto(allocator, &clone);
            var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
            try offers.push(&clone);
            errdefer offers.deinit();
            const client = try PureZigTlsClient.createWithOptions(allocator, process_a.port, "http/1.1", "tardigrade.test", .{
                .psk_offers = &offers,
                .psk_now_ctx = &clock_dummy,
                .psk_now_fn = ClientClock.now,
                .early_data_intent = .{ .enabled = true, .max_bytes = 4096 },
                .return_after_early_data_ready = true,
            });
            defer client.destroy();
            try client.writeAllPlain("GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
            const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
            defer allocator.free(raw);
            try assertContains(raw, "HTTP/1.1 200 OK");
            try assertContains(raw, "a-early");
            try std.testing.expectEqual(@as(u32, 1), upstream_a.requestCount());
        }
        try std.testing.expectEqual(a_accepted_before + 1, try currentLabeledMetric(allocator, process_a.port, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"accepted\""}));

        // A, replay: the identical identity offered again to A. Rejected
        // as a duplicate -- the early bytes never reach upstream (request
        // count below only grows by the explicit follow-up request) -- but
        // the PSK/session itself remains valid and the connection safely
        // falls back to a full 1-RTT resumed handshake.
        {
            var clone: tls_core.session.ClientTicketState = .{};
            defer clone.deinit();
            try base_ticket.cloneInto(allocator, &clone);
            var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
            try offers.push(&clone);
            errdefer offers.deinit();
            const client = try PureZigTlsClient.createWithOptions(allocator, process_a.port, "http/1.1", "tardigrade.test", .{
                .psk_offers = &offers,
                .psk_now_ctx = &clock_dummy,
                .psk_now_fn = ClientClock.now,
                .early_data_intent = .{ .enabled = true, .max_bytes = 4096 },
                .return_after_early_data_ready = true,
            });
            defer client.destroy();
            try client.writeAllPlain("GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: keep-alive\r\n\r\n");
            try client.driveUntilOpen(5_000);
            try std.testing.expect(client.backend.core.psk_authenticated);
            try client.writeAllPlain("GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
            const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
            defer allocator.free(raw);
            try assertContains(raw, "HTTP/1.1 200 OK");
            try assertContains(raw, "a-after-replay");
            try std.testing.expectEqual(@as(u32, 2), upstream_a.requestCount());
        }
        try std.testing.expectEqual(a_duplicate_before + 1, try currentLabeledMetric(allocator, process_a.port, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"duplicate\""}));

        try upstream_b.resetCapture();

        // B, first use: B's own independent process-local replay store has
        // never seen this identity -- accepted once, even though A already
        // consumed it above. The documented `process_local` scope, proven
        // live rather than asserted only in prose.
        {
            var clone: tls_core.session.ClientTicketState = .{};
            defer clone.deinit();
            try base_ticket.cloneInto(allocator, &clone);
            var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
            try offers.push(&clone);
            errdefer offers.deinit();
            const client = try PureZigTlsClient.createWithOptions(allocator, process_b.port, "http/1.1", "tardigrade.test", .{
                .psk_offers = &offers,
                .psk_now_ctx = &clock_dummy,
                .psk_now_fn = ClientClock.now,
                .early_data_intent = .{ .enabled = true, .max_bytes = 4096 },
                .return_after_early_data_ready = true,
            });
            defer client.destroy();
            try client.writeAllPlain("GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
            const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
            defer allocator.free(raw);
            try assertContains(raw, "HTTP/1.1 200 OK");
            try assertContains(raw, "b-early");
            try std.testing.expectEqual(@as(u32, 1), upstream_b.requestCount());
        }
        try std.testing.expectEqual(b_accepted_before + 1, try currentLabeledMetric(allocator, process_b.port, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"accepted\""}));

        // B, replay: rejected as a duplicate too, same as A above.
        {
            var clone: tls_core.session.ClientTicketState = .{};
            defer clone.deinit();
            try base_ticket.cloneInto(allocator, &clone);
            var offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
            try offers.push(&clone);
            errdefer offers.deinit();
            const client = try PureZigTlsClient.createWithOptions(allocator, process_b.port, "http/1.1", "tardigrade.test", .{
                .psk_offers = &offers,
                .psk_now_ctx = &clock_dummy,
                .psk_now_fn = ClientClock.now,
                .early_data_intent = .{ .enabled = true, .max_bytes = 4096 },
                .return_after_early_data_ready = true,
            });
            defer client.destroy();
            try client.writeAllPlain("GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: keep-alive\r\n\r\n");
            try client.driveUntilOpen(5_000);
            try std.testing.expect(client.backend.core.psk_authenticated);
            try client.writeAllPlain("GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
            const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
            defer allocator.free(raw);
            try assertContains(raw, "HTTP/1.1 200 OK");
            try assertContains(raw, "b-after-replay");
            try std.testing.expectEqual(@as(u32, 2), upstream_b.requestCount());
        }
        try std.testing.expectEqual(b_duplicate_before + 1, try currentLabeledMetric(allocator, process_b.port, "tardigrade_tls_early_data_replay_total", &.{"outcome=\"duplicate\""}));

        try upstream_a.resetCapture();
        try upstream_b.resetCapture();
    }

    const log_a = try compat.cwd().readFileAlloc(allocator, process_a.log_path, 4 * 1024 * 1024);
    defer allocator.free(log_a);
    const log_b = try compat.cwd().readFileAlloc(allocator, process_b.log_path, 4 * 1024 * 1024);
    defer allocator.free(log_b);
    try assertHexAbsentCaseInsensitive(allocator, log_a, persistent_ticket_key_fixture_hex);
    try assertHexAbsentCaseInsensitive(allocator, log_b, persistent_ticket_key_fixture_hex);
}

test "#510 native tcp production 0-rtt reaches h1 safety gate and replay fallback" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "readiness", .connection_header = "close" },
        .{ .body = "ticket-bootstrap", .connection_header = "close" },
        .{ .body = "ticket-bootstrap", .connection_header = "close" },
        .{ .body = "safe-early", .connection_header = "keep-alive" },
        .{ .body = "safe-after-replay", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    proxy_pass http://{s}:{d};
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/safe",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE", .value = "process_local" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_runtime = try tls_core.resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 2_000;
            }
        }.now },
        client_provider.cryptoProvider(),
    );
    defer client_runtime.deinit();

    const TicketCapture = struct {
        allocator: std.mem.Allocator,
        runtime: *tls_core.resumption_runtime.Runtime,
        retained: tls_core.session.ClientTicketState = .{},
        ticket_count: u32 = 0,

        fn now(_: *anyopaque) i64 {
            return 2_000;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.retained.deinit();
            self.retained = .{};
            ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
            _ = self.runtime.storeClientTicket(ticket);
            self.ticket_count += 1;
        }
    };

    var capture = TicketCapture{ .allocator = allocator, .runtime = &client_runtime };
    defer capture.retained.deinit();

    const first_client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
        .ticket_consumer = .{
            .ctx = &capture,
            .nowUnixMsFn = TicketCapture.now,
            .onTicketFn = TicketCapture.onTicket,
        },
    });
    defer first_client.destroy();
    try first_client.writeAllPlain("GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    const first_raw = try first_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(first_raw);
    try assertContains(first_raw, "HTTP/1.1 200 OK");
    try first_client.driveUntilTicketCount(&capture.ticket_count, 1, 5_000);
    try std.testing.expectEqual(tls_core.session.EarlyDataPolicy{ .early_data_capable = 16 * 1024 }, capture.retained.common.early_data);

    var safe_ticket: tls_core.session.ClientTicketState = .{};
    defer safe_ticket.deinit();
    try capture.retained.cloneInto(allocator, &safe_ticket);
    var replay_ticket: tls_core.session.ClientTicketState = .{};
    defer replay_ticket.deinit();
    try capture.retained.cloneInto(allocator, &replay_ticket);

    const unsafe_ticket_client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
        .ticket_consumer = .{
            .ctx = &capture,
            .nowUnixMsFn = TicketCapture.now,
            .onTicketFn = TicketCapture.onTicket,
        },
    });
    defer unsafe_ticket_client.destroy();
    try unsafe_ticket_client.writeAllPlain("GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    const unsafe_ticket_raw = try unsafe_ticket_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(unsafe_ticket_raw);
    try assertContains(unsafe_ticket_raw, "HTTP/1.1 200 OK");
    try unsafe_ticket_client.driveUntilTicketCount(&capture.ticket_count, 2, 5_000);
    try std.testing.expectEqual(tls_core.session.EarlyDataPolicy{ .early_data_capable = 16 * 1024 }, capture.retained.common.early_data);

    var unsafe_ticket: tls_core.session.ClientTicketState = .{};
    defer unsafe_ticket.deinit();
    try capture.retained.cloneInto(allocator, &unsafe_ticket);
    try std.testing.expect(!std.mem.eql(u8, unsafe_ticket.ticket.slice(), safe_ticket.ticket.slice()));
    try upstream.resetCapture();

    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2_500;
        }
    };

    var safe_offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
    try safe_offers.push(&safe_ticket);
    errdefer safe_offers.deinit();
    const accepted_client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
        .psk_offers = &safe_offers,
        .psk_now_ctx = &clock_dummy,
        .psk_now_fn = ClientClock.now,
        .early_data_intent = .{ .enabled = true, .max_bytes = 4096 },
        .return_after_early_data_ready = true,
    });
    defer accepted_client.destroy();
    try accepted_client.writeAllPlain("GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    const accepted_raw = try accepted_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(accepted_raw);
    try assertContains(accepted_raw, "HTTP/1.1 200 OK");
    try assertContains(accepted_raw, "safe-early");
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    var unsafe_offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
    try unsafe_offers.push(&unsafe_ticket);
    errdefer unsafe_offers.deinit();
    const unsafe_client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
        .psk_offers = &unsafe_offers,
        .psk_now_ctx = &clock_dummy,
        .psk_now_fn = ClientClock.now,
        .early_data_intent = .{ .enabled = true, .max_bytes = 4096 },
        .return_after_early_data_ready = true,
    });
    defer unsafe_client.destroy();
    try unsafe_client.writeAllPlain("POST /work HTTP/1.1\r\nHost: tardigrade.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    const unsafe_raw = try unsafe_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(unsafe_raw);
    try assertContains(unsafe_raw, "HTTP/1.1 425 Too Early");
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    var replay_offers: tls_core.pre_shared_key.ClientPskOfferSet = .{};
    try replay_offers.push(&replay_ticket);
    errdefer replay_offers.deinit();
    const replay_client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
        .psk_offers = &replay_offers,
        .psk_now_ctx = &clock_dummy,
        .psk_now_fn = ClientClock.now,
        .early_data_intent = .{ .enabled = true, .max_bytes = 4096 },
        .return_after_early_data_ready = true,
    });
    defer replay_client.destroy();
    try replay_client.writeAllPlain("POST /work HTTP/1.1\r\nHost: tardigrade.test\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n");
    try replay_client.driveUntilOpen(5_000);
    try replay_client.writeAllPlain("GET /safe HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    const replay_raw = try replay_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(replay_raw);
    try assertContains(replay_raw, "HTTP/1.1 200 OK");
    try assertContains(replay_raw, "safe-after-replay");
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());
    const first_path = try upstream.capturedPathHistoryAt(allocator, 0);
    defer allocator.free(first_path);
    const second_path = try upstream.capturedPathHistoryAt(allocator, 1);
    defer allocator.free(second_path);
    try std.testing.expectEqualStrings("/safe", first_path);
    try std.testing.expectEqualStrings("/safe", second_path);
}

const PureZigTlsClient = struct {
    const Options = struct {
        ticket_consumer: ?tls_core.tls13_backend.Tls13Backend.SessionTicketConsumer = null,
        ticket_limits: tls_core.session.Limits = tls_core.session.Limits.default,
        psk_lease: ?*tls_core.pre_shared_key.ClientOfferLease = null,
        psk_offers: ?*tls_core.pre_shared_key.ClientPskOfferSet = null,
        psk_now_ctx: ?*anyopaque = null,
        psk_now_fn: ?*const fn (*anyopaque) i64 = null,
        early_data_intent: tls_core.tls13_backend.ClientEarlyDataIntent = .{},
        return_after_early_data_ready: bool = false,
    };

    allocator: std.mem.Allocator,
    stream: compat.NetStream,
    entropy_source: tls_core.production_crypto.OsEntropy = .{},
    crypto_provider_state: tls_core.production_crypto.Provider = undefined,
    backend: tls_core.tls13_backend.Tls13Backend = undefined,
    record: tls_core.encrypted_stream.PureZigRecordStream = undefined,

    fn create(allocator: std.mem.Allocator, port: u16, alpn: []const u8) !*PureZigTlsClient {
        return createWithServerName(allocator, port, alpn, null);
    }

    fn createWithServerName(allocator: std.mem.Allocator, port: u16, alpn: []const u8, server_name: ?[]const u8) !*PureZigTlsClient {
        return createWithOptions(allocator, port, alpn, server_name, .{});
    }

    fn createWithOptions(allocator: std.mem.Allocator, port: u16, alpn: []const u8, server_name: ?[]const u8, options: Options) !*PureZigTlsClient {
        const self = try allocator.create(PureZigTlsClient);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .stream = try compat.tcpConnectToHost(allocator, test_host, port),
        };
        errdefer self.stream.close();
        try setNonBlockingFd(self.stream.handle);

        self.crypto_provider_state = tls_core.production_crypto.Provider.init(self.entropy_source.entropy());
        self.backend = tls_core.tls13_backend.Tls13Backend.initClientConfigured(
            try tls_core.production_crypto.freshHandshakeEntropy(),
            self.cryptoProviderState().cryptoProvider(),
            .insecure_no_verification,
            tls_core.tls13_backend.recordConfig(alpnPolicy(alpn)),
            .{ .server_name = server_name },
        );
        if (options.ticket_consumer != null or options.psk_lease != null or options.psk_offers != null) {
            try self.backend.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore });
        }
        if (options.psk_lease != null and options.psk_offers != null) return error.InvalidTestSetup;
        if (options.ticket_consumer) |consumer| {
            try self.backend.setSessionTicketConsumer(allocator, options.ticket_limits, consumer);
        }
        if (options.psk_lease) |lease| {
            try self.backend.setClientPskOfferLease(
                lease,
                options.psk_now_ctx orelse return error.InvalidTestSetup,
                options.psk_now_fn orelse return error.InvalidTestSetup,
            );
        }
        if (options.psk_offers) |offers| {
            try self.backend.setClientPskOffers(
                offers,
                options.psk_now_ctx orelse return error.InvalidTestSetup,
                options.psk_now_fn orelse return error.InvalidTestSetup,
            );
        }
        if (options.early_data_intent.enabled) {
            try self.backend.setClientEarlyDataIntent(options.early_data_intent);
        }
        self.record = try tls_core.encrypted_stream.PureZigRecordStream.initWithCarrierAndBackend(
            allocator,
            .client,
            self.cryptoProviderState().cryptoProvider(),
            .tls_aes_128_gcm_sha256,
            self.carrier(),
            self.backend.backend(),
        );
        self.record.allow_unverified_certificate = true;
        try self.record.setExpectedAlpn(alpn);
        if (options.return_after_early_data_ready) {
            try self.driveUntilEarlyDataReady(5_000);
            return self;
        }
        try self.driveUntilOpen(5_000);
        return self;
    }

    fn expectHandshakeFailure(allocator: std.mem.Allocator, port: u16, alpn: []const u8) !void {
        return expectHandshakeFailureWithServerName(allocator, port, alpn, null);
    }

    fn expectHandshakeFailureWithServerName(allocator: std.mem.Allocator, port: u16, alpn: []const u8, server_name: ?[]const u8) !void {
        const self = try allocator.create(PureZigTlsClient);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .stream = try compat.tcpConnectToHost(allocator, test_host, port),
        };
        defer self.destroy();
        try setNonBlockingFd(self.stream.handle);

        self.crypto_provider_state = tls_core.production_crypto.Provider.init(self.entropy_source.entropy());
        self.backend = tls_core.tls13_backend.Tls13Backend.initClientConfigured(
            try tls_core.production_crypto.freshHandshakeEntropy(),
            self.cryptoProviderState().cryptoProvider(),
            .insecure_no_verification,
            tls_core.tls13_backend.recordConfig(alpnPolicy(alpn)),
            .{ .server_name = server_name },
        );
        self.record = try tls_core.encrypted_stream.PureZigRecordStream.initWithCarrierAndBackend(
            allocator,
            .client,
            self.cryptoProviderState().cryptoProvider(),
            .tls_aes_128_gcm_sha256,
            self.carrier(),
            self.backend.backend(),
        );
        self.record.allow_unverified_certificate = true;
        try self.record.setExpectedAlpn(alpn);

        const deadline = compat.milliTimestamp() + 5_000;
        while (compat.milliTimestamp() < deadline) {
            _ = self.record.drive() catch return;
            if (self.record.applicationDataOpen()) return error.TestUnexpectedResult;
            try self.waitForReadiness(100);
        }
        return error.ReadTimeout;
    }

    fn destroy(self: *PureZigTlsClient) void {
        self.record.deinit();
        self.backend.deinit();
        self.stream.close();
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    fn cryptoProviderState(self: *PureZigTlsClient) *tls_core.production_crypto.Provider {
        return &self.crypto_provider_state;
    }

    fn carrier(self: *PureZigTlsClient) tls_core.encrypted_stream.Carrier {
        return .{
            .ptr = self,
            .readFn = carrierRead,
            .writeFn = carrierWrite,
            .closeFn = null,
            .owns_handle = false,
        };
    }

    fn driveUntilOpen(self: *PureZigTlsClient, timeout_ms: u64) !void {
        const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
        while (compat.milliTimestamp() < deadline) {
            const driven = try self.record.drive();
            if (self.record.applicationDataOpen()) return;
            if (!driven.made_progress) try self.waitForReadiness(100);
        }
        return error.ReadTimeout;
    }

    fn driveUntilEarlyDataReady(self: *PureZigTlsClient, timeout_ms: u64) !void {
        const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
        while (compat.milliTimestamp() < deadline) {
            const driven = try self.record.drive();
            if (self.backend.earlyDataAttempted() and self.record.stream().readiness().can_write_plaintext) return;
            if (self.record.applicationDataOpen()) return error.EarlyDataNotAttempted;
            if (!driven.made_progress) try self.waitForReadiness(100);
        }
        return error.ReadTimeout;
    }

    fn driveUntilTicketCount(self: *PureZigTlsClient, ticket_count: *const u32, expected: u32, timeout_ms: u64) !void {
        const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
        while (compat.milliTimestamp() < deadline) {
            if (ticket_count.* >= expected) return;
            const driven = self.record.drive() catch |err| switch (err) {
                error.EndOfStream, error.TruncatedStream => break,
                else => return err,
            };
            if (!driven.made_progress) self.waitForReadiness(100) catch |err| switch (err) {
                error.ConnectionResetByPeer => break,
                error.WouldBlock => {},
                else => return err,
            };
        }
        if (ticket_count.* >= expected) return;
        return error.ReadTimeout;
    }

    fn writeAllPlain(self: *PureZigTlsClient, bytes: []const u8) !void {
        var offset: usize = 0;
        const deadline = compat.milliTimestamp() + 5_000;
        while (offset < bytes.len and compat.milliTimestamp() < deadline) {
            const encrypted = self.record.stream();
            const n = encrypted.write(bytes[offset..]) catch |err| switch (err) {
                error.WouldBlock => {
                    try self.driveAndWait(100);
                    continue;
                },
                else => return err,
            };
            offset += n;
            _ = try self.record.drive();
        }
        if (offset < bytes.len) return error.WriteFailed;
    }

    fn readPlainToEnd(self: *PureZigTlsClient, allocator: std.mem.Allocator, max_bytes: usize, timeout_ms: u64) ![]u8 {
        const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
        var out = std.array_list.Managed(u8).init(allocator);
        errdefer out.deinit();
        var tmp: [4096]u8 = undefined;
        while (compat.milliTimestamp() < deadline) {
            const encrypted = self.record.stream();
            const n = encrypted.read(&tmp) catch |err| switch (err) {
                error.WouldBlock => {
                    self.driveAndWait(100) catch |drive_err| switch (drive_err) {
                        error.EndOfStream, error.TruncatedStream => break,
                        error.WouldBlock => if (out.items.len > 0) break else continue,
                        else => return drive_err,
                    };
                    continue;
                },
                error.EndOfStream, error.TruncatedStream => break,
                else => return err,
            };
            if (n == 0) break;
            try out.appendSlice(tmp[0..n]);
            if (out.items.len > max_bytes) return error.MessageTooLarge;
        }
        if (out.items.len == 0) return error.ReadTimeout;
        return out.toOwnedSlice();
    }

    fn readExactPlain(self: *PureZigTlsClient, out: []u8, timeout_ms: u64) !void {
        const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
        var offset: usize = 0;
        while (offset < out.len and compat.milliTimestamp() < deadline) {
            const encrypted = self.record.stream();
            const n = encrypted.read(out[offset..]) catch |err| switch (err) {
                error.WouldBlock => {
                    try self.driveAndWait(100);
                    continue;
                },
                else => return err,
            };
            if (n == 0) return error.ConnectionClosed;
            offset += n;
        }
        if (offset < out.len) return error.ReadTimeout;
    }

    fn writeHttp2Frame(self: *PureZigTlsClient, typ: u8, flags: u8, stream_id: u31, payload: []const u8) !void {
        var header: [9]u8 = undefined;
        header[0] = @intCast((payload.len >> 16) & 0xff);
        header[1] = @intCast((payload.len >> 8) & 0xff);
        header[2] = @intCast(payload.len & 0xff);
        header[3] = typ;
        header[4] = flags;
        std.mem.writeInt(u32, header[5..9], @as(u32, stream_id) & 0x7fff_ffff, .big);
        try self.writeAllPlain(header[0..]);
        try self.writeAllPlain(payload);
    }

    fn readHttp2Frame(self: *PureZigTlsClient, allocator: std.mem.Allocator, max_payload: usize, timeout_ms: u64) !Http2WireFrame {
        var header: [9]u8 = undefined;
        try self.readExactPlain(header[0..], timeout_ms);
        const len = (@as(usize, header[0]) << 16) | (@as(usize, header[1]) << 8) | @as(usize, header[2]);
        if (len > max_payload) return error.MessageTooLarge;
        const sid = std.mem.readInt(u32, header[5..9], .big) & 0x7fff_ffff;
        const payload = try allocator.alloc(u8, len);
        errdefer allocator.free(payload);
        try self.readExactPlain(payload, timeout_ms);
        return .{
            .typ = header[3],
            .flags = header[4],
            .stream_id = @intCast(sid),
            .payload = payload,
        };
    }

    fn driveAndWait(self: *PureZigTlsClient, timeout_ms: u64) !void {
        const driven = try self.record.drive();
        if (!driven.made_progress) try self.waitForReadiness(timeout_ms);
    }

    fn waitForReadiness(self: *PureZigTlsClient, timeout_ms: u64) !void {
        const readiness = self.record.readiness();
        var events: i16 = std.posix.POLL.ERR | std.posix.POLL.HUP;
        if (readiness.wants_read) events |= std.posix.POLL.IN;
        if (readiness.wants_write) events |= std.posix.POLL.OUT;
        var fds = [_]std.posix.pollfd{.{
            .fd = self.stream.handle,
            .events = events,
            .revents = 0,
        }};
        const ready = try std.posix.poll(&fds, @intCast(@max(@as(u64, 1), timeout_ms)));
        if (ready == 0) return error.WouldBlock;
        if ((fds[0].revents & std.posix.POLL.ERR) != 0) return error.ConnectionResetByPeer;
    }

    fn carrierRead(ptr: *anyopaque, out: []u8) tls_core.encrypted_stream.Error!usize {
        const self: *PureZigTlsClient = @ptrCast(@alignCast(ptr));
        return readFdNonblocking(self.stream.handle, out);
    }

    fn carrierWrite(ptr: *anyopaque, bytes: []const u8) tls_core.encrypted_stream.Error!usize {
        const self: *PureZigTlsClient = @ptrCast(@alignCast(ptr));
        return writeFdNonblocking(self.stream.handle, bytes);
    }
};

const tardigrade_test_alpns = [_]tls_core.algorithms.ProtocolName{.{ .bytes = "tardigrade-test" }};

fn alpnPolicy(alpn: []const u8) tls_core.policy.Policy {
    if (std.mem.eql(u8, alpn, "h2")) return tls_core.policy.Policy.recordH2Only();
    if (std.mem.eql(u8, alpn, "http/1.1")) return tls_core.policy.Policy.recordHttp1Only(false);
    if (std.mem.eql(u8, alpn, "tardigrade-test")) {
        return tls_core.policy.Policy.fromCapabilities(.record, tls_core.tls13_backend.native_capabilities, &tardigrade_test_alpns);
    }
    var policy = tls_core.policy.Policy.recordDefault();
    policy.alpn_protocols = &.{};
    return policy;
}

const Http2WireFrame = struct {
    typ: u8,
    flags: u8,
    stream_id: u31,
    payload: []u8,

    fn deinit(self: *Http2WireFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.* = undefined;
    }
};

fn setNonBlockingFd(fd: std.posix.fd_t) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const status_flags = linux.fcntl(fd, linux.F.GETFL, 0);
        if (linux.errno(status_flags) != .SUCCESS) return error.FcntlFailed;
        const nonblock: usize = @intCast(@as(u32, @bitCast(linux.O{ .NONBLOCK = true })));
        const rc = linux.fcntl(fd, linux.F.SETFL, status_flags | nonblock);
        if (linux.errno(rc) != .SUCCESS) return error.FcntlFailed;
    } else {
        const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (status_flags < 0) return error.FcntlFailed;
        const nonblock = @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
        if (std.c.fcntl(fd, std.c.F.SETFL, status_flags | nonblock) < 0) return error.FcntlFailed;
    }
}

fn readFdNonblocking(fd: std.posix.fd_t, out: []u8) tls_core.encrypted_stream.Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.read(fd, out.ptr, out.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketReadFailed,
        };
    }
    const rc = std.c.read(fd, out.ptr, out.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketReadFailed;
    }
    return @intCast(rc);
}

fn writeFdNonblocking(fd: std.posix.fd_t, bytes: []const u8) tls_core.encrypted_stream.Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.write(fd, bytes.ptr, bytes.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketWriteFailed,
        };
    }
    const rc = std.c.write(fd, bytes.ptr, bytes.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketWriteFailed;
    }
    return @intCast(rc);
}

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    var count: usize = 0;
    var start: usize = 0;
    while (std.mem.find(u8, haystack[start..], needle)) |rel| {
        count += 1;
        start += rel + needle.len;
    }
    return count;
}

fn hs256Jwt(allocator: std.mem.Allocator, secret: []const u8, payload_json: []const u8) ![]u8 {
    const header_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    const enc = std.base64.url_safe_no_pad.Encoder;

    var header_buf: [128]u8 = undefined;
    var payload_buf: [512]u8 = undefined;
    const header_b64 = enc.encode(header_buf[0..enc.calcSize(header_json.len)], header_json);
    const payload_b64 = enc.encode(payload_buf[0..enc.calcSize(payload_json.len)], payload_json);
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
    defer allocator.free(signing_input);

    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, signing_input, secret);
    var sig_buf: [128]u8 = undefined;
    const sig_b64 = enc.encode(sig_buf[0..enc.calcSize(mac.len)], mac[0..]);
    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ signing_input, sig_b64 });
}

fn deviceSignature(allocator: std.mem.Allocator, key: []const u8, method: []const u8, path: []const u8, ts_str: []const u8, body: []const u8) ![]u8 {
    const signed = try std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n{s}\n{s}", .{ key, method, path, ts_str, body });
    defer allocator.free(signed);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(signed, &digest, .{});
    return std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&digest)});
}

fn jsonStringField(allocator: std.mem.Allocator, body: []const u8, key: []const u8) !?[]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const value = parsed.value.object.get(key) orelse return null;
    if (value != .string) return null;
    return try allocator.dupe(u8, value.string);
}

fn jsonU64Field(allocator: std.mem.Allocator, body: []const u8, key: []const u8) !?u64 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const value = parsed.value.object.get(key) orelse return null;
    return switch (value) {
        .integer => |n| if (n < 0) null else @as(u64, @intCast(n)),
        else => null,
    };
}

fn assertContains(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.find(u8, haystack, needle) != null);
}

fn waitForBodyContains(allocator: std.mem.Allocator, port: u16, path: []const u8, headers: []const RequestHeader, needle: []const u8, timeout_ms: u64) !void {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        var response = sendRequest(allocator, port, .{
            .method = "GET",
            .path = path,
            .body = null,
            .headers = headers,
        }) catch {
            compat.sleepNs(50 * std.time.ns_per_ms);
            continue;
        };
        defer response.deinit();
        if (std.mem.find(u8, response.body, needle) != null) return;
        compat.sleepNs(50 * std.time.ns_per_ms);
    }
    return error.Timeout;
}

fn waitForWebSocketFrameContains(ws: *WebSocketClient, allocator: std.mem.Allocator, needle: []const u8, attempts: usize) !WebSocketFrame {
    var remaining = attempts;
    while (remaining > 0) : (remaining -= 1) {
        var frame = try ws.readFrame(allocator, 8192);
        if (std.mem.find(u8, frame.payload, needle) != null) return frame;
        frame.deinit(allocator);
    }
    return error.Timeout;
}

fn waitForHttp3Configured(port: u16, timeout_ms: u64) !void {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        var response = sendCurlRequest(std.testing.allocator, port, .{
            .scheme = "https",
            .path = "/health",
            .insecure = true,
        }) catch |err| {
            if (err == error.CurlFailed or err == error.InvalidHttpResponse) {
                compat.sleepNs(100 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
        defer response.deinit();
        if (response.status_code == 200 and std.mem.find(u8, response.body, "\"http3_status\":\"configured\"") != null) return;
        compat.sleepNs(100 * std.time.ns_per_ms);
    }
    return error.Timeout;
}

fn prometheusMetricValue(body: []const u8, name: []const u8) ?u64 {
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (!std.mem.startsWith(u8, line, name)) continue;
        if (line.len == name.len) continue;
        if (line[name.len] != ' ') continue;
        return std.fmt.parseInt(u64, std.mem.trim(u8, line[name.len + 1 ..], " \t"), 10) catch null;
    }
    return null;
}

fn prometheusLabeledMetricValue(body: []const u8, name: []const u8, labels: []const []const u8) ?u64 {
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (!std.mem.startsWith(u8, line, name)) continue;
        if (line.len == name.len or line[name.len] != '{') continue;
        const end_labels = std.mem.indexOfScalarPos(u8, line, name.len, '}') orelse continue;
        const label_text = line[name.len + 1 .. end_labels];
        var matched = true;
        for (labels) |label| {
            if (std.mem.indexOf(u8, label_text, label) == null) {
                matched = false;
                break;
            }
        }
        if (!matched) continue;
        const value_text = std.mem.trim(u8, line[end_labels + 1 ..], " \t");
        return std.fmt.parseInt(u64, value_text, 10) catch null;
    }
    return null;
}

fn baseOptions(upstream_port: u16) TardigradeOptions {
    return .{
        .profile = .bearclaw,
        .upstream_port = upstream_port,
    };
}

fn bearClawProfile(options: TardigradeOptions) TardigradeOptions {
    var updated = options;
    updated.profile = .bearclaw;
    return updated;
}

fn authProxyConfig(allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\location = /health {{
        \\    return 200 ok;
        \\}}
        \\
        \\location = /v1/chat {{
        \\    proxy_pass /v1/chat;
        \\    auth required;
        \\}}
    , .{});
}

const ConcurrentRequestResult = struct {
    status_code: u16 = 0,
    body_contains_ok: bool = false,
    err: ?anyerror = null,
};

const ConcurrentRequestContext = struct {
    port: u16,
    start_flag: *const std.atomic.Value(bool),
    result: *ConcurrentRequestResult,
};

const ConcurrentAuthRateResult = struct {
    status_code: u16 = 0,
    err: ?anyerror = null,
    body_contains_ok: bool = false,
};

const ConcurrentAuthRateContext = struct {
    port: u16,
    start_flag: *const std.atomic.Value(bool),
    result: *ConcurrentAuthRateResult,
    auth_header_name: []const u8,
    auth_header_value: []const u8,
};

fn concurrentChatRequestMain(ctx: *ConcurrentRequestContext) void {
    while (!ctx.start_flag.load(.seq_cst)) {
        std.Thread.yield() catch {};
    }

    var response = sendRequest(std.heap.page_allocator, ctx.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"concurrent\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    }) catch |err| {
        ctx.result.err = err;
        return;
    };
    defer response.deinit();
    ctx.result.status_code = response.status_code;
    ctx.result.body_contains_ok = std.mem.find(u8, response.body, "\"ok\":true") != null;
}

fn concurrentAuthRateRequestMain(ctx: *ConcurrentAuthRateContext) void {
    while (!ctx.start_flag.load(.seq_cst)) {
        std.Thread.yield() catch {};
    }

    var response = sendRequestWithTimeout(std.heap.page_allocator, ctx.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"contention\"}",
        .headers = &.{
            .{ .name = ctx.auth_header_name, .value = ctx.auth_header_value },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    }, 15000) catch |err| {
        ctx.result.err = err;
        return;
    };
    defer response.deinit();
    ctx.result.status_code = response.status_code;
    ctx.result.body_contains_ok = std.mem.find(u8, response.body, "\"ok\":true") != null;
}

test "core gateway integration covers health metrics auth proxying invalid json and correlation ids" {
    return error.SkipZigTest;
}

test "mux websocket metrics and channel caps are enforced" {
    return error.SkipZigTest;
}

test "prometheus metrics endpoint exposes counters and can require auth" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .profile = .generic,
        .config_text = config_text,
    });
    defer tardigrade.stop();

    var metrics_before = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer metrics_before.deinit();
    try std.testing.expectEqual(@as(u16, 200), metrics_before.status_code);
    try std.testing.expect(std.mem.find(u8, metrics_before.body, "# TYPE tardigrade_requests_total counter") != null);
    try std.testing.expect(std.mem.find(u8, metrics_before.body, "# TYPE tardigrade_request_latency_ms histogram") != null);
    try std.testing.expect(std.mem.find(u8, metrics_before.body, "tardigrade_request_latency_ms_bucket{le=\"1\"}") != null);
    try std.testing.expect(std.mem.find(u8, metrics_before.body, "# TYPE tardigrade_worker_active_jobs gauge") != null);
    try std.testing.expect(std.mem.find(u8, metrics_before.body, "# TYPE tardigrade_worker_queued_jobs gauge") != null);
    const requests_before = prometheusMetricValue(metrics_before.body, "tardigrade_requests_total") orelse return error.InvalidHttpResponse;
    const status_2xx_before = prometheusMetricValue(metrics_before.body, "tardigrade_requests_2xx_total") orelse return error.InvalidHttpResponse;
    const worker_threads = prometheusMetricValue(metrics_before.body, "tardigrade_worker_threads") orelse return error.InvalidHttpResponse;
    try std.testing.expect(worker_threads >= 1);

    var proxy_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/demo",
        .body = null,
        .headers = &.{},
    });
    defer proxy_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), proxy_response.status_code);

    var metrics_after = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer metrics_after.deinit();
    const requests_after = prometheusMetricValue(metrics_after.body, "tardigrade_requests_total") orelse return error.InvalidHttpResponse;
    const status_2xx_after = prometheusMetricValue(metrics_after.body, "tardigrade_requests_2xx_total") orelse return error.InvalidHttpResponse;
    try std.testing.expect(requests_after >= requests_before + 2);
    try std.testing.expect(status_2xx_after >= status_2xx_before + 2);

    var protected = try TardigradeProcess.start(allocator, .{
        .profile = .generic,
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_METRICS_REQUIRE_AUTH", .value = "true" },
        },
    });
    defer protected.stop();

    var unauthorized = try sendRequest(allocator, protected.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer unauthorized.deinit();
    try std.testing.expectEqual(@as(u16, 401), unauthorized.status_code);

    var authorized = try sendRequest(allocator, protected.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
        },
    });
    defer authorized.deinit();
    try std.testing.expectEqual(@as(u16, 200), authorized.status_code);
    try std.testing.expect(std.mem.find(u8, authorized.body, "tardigrade_requests_total") != null);
}

test "bearclaw fixture serves chat over https with bearer auth and transcript persistence" {
    if (!build_options.tls_openssl_adapter) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true,\"source\":\"bearclaw-upstream\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    var options = bearClawProfile(baseOptions(upstream.port()));
    options.ready_https_insecure = true;

    var tardigrade = try TardigradeProcess.start(allocator, options);
    defer tardigrade.stop();

    var unauthorized = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/v1/chat",
        .method = "POST",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Host", .value = "api.example.com" },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
    });
    defer unauthorized.deinit();
    try std.testing.expectEqual(@as(u16, 401), unauthorized.status_code);

    var authorized = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/v1/chat",
        .method = "POST",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Host", .value = "api.example.com" },
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
    });
    defer authorized.deinit();
    try std.testing.expectEqual(@as(u16, 200), authorized.status_code);
    try assertContains(authorized.body, "\"source\":\"bearclaw-upstream\"");

    const fixture_dir = tardigrade.fixture_dir_rel orelse return error.TestUnexpectedResult;
    const transcript_rel = try std.fmt.allocPrint(allocator, "{s}/transcripts.ndjson", .{fixture_dir});
    defer allocator.free(transcript_rel);
    const transcript = try compat.cwd().readFileAlloc(allocator, transcript_rel, 1024 * 1024);
    defer allocator.free(transcript);
    try assertContains(transcript, "\"scope\":\"chat\"");
    try assertContains(transcript, "\"route\":\"/v1/chat\"");
    try std.testing.expect(std.mem.find(u8, transcript, valid_bearer_token) == null);

    var transcript_list = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/bearclaw/transcripts?limit=5",
        .method = "GET",
        .headers = &.{
            .{ .name = "Host", .value = "api.example.com" },
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
        },
        .insecure = true,
    });
    defer transcript_list.deinit();
    try std.testing.expectEqual(@as(u16, 200), transcript_list.status_code);
    try assertContains(transcript_list.body, "\"transcripts\":[");
    try assertContains(transcript_list.body, "\"route\":\"/v1/chat\"");

    var transcript_detail = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/bearclaw/transcripts/1",
        .method = "GET",
        .headers = &.{
            .{ .name = "Host", .value = "api.example.com" },
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
        },
        .insecure = true,
    });
    defer transcript_detail.deinit();
    try std.testing.expectEqual(@as(u16, 200), transcript_detail.status_code);
    try assertContains(transcript_detail.body, "\"transcript\":{");
    try assertContains(transcript_detail.body, "\"request_body\":\"{\\\"message\\\":\\\"hello\\\"}\"");
}

test "bearclaw transcript append path errors do not fail the request" {
    if (!build_options.tls_openssl_adapter) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true,\"source\":\"bearclaw-upstream\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    var options = bearClawProfile(baseOptions(upstream.port()));
    options.ready_https_insecure = true;
    options.extra_env = &.{
        .{ .name = "TARDIGRADE_TRANSCRIPT_STORE_PATH", .value = "/dev/null/transcripts.ndjson" },
    };

    var tardigrade = try TardigradeProcess.start(allocator, options);
    defer tardigrade.stop();

    var authorized = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/bearclaw/v1/chat",
        .method = "POST",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Host", .value = "api.example.com" },
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
    });
    defer authorized.deinit();
    try std.testing.expectEqual(@as(u16, 200), authorized.status_code);
    try assertContains(authorized.body, "\"source\":\"bearclaw-upstream\"");
}

// TC-TARDIGRADE-002 + TC-TARDIGRADE-004
test "bearclaw edge prefix routes health without auth and enforces auth on v1 paths" {
    if (!build_options.tls_openssl_adapter) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "{\"status\":\"ok\",\"service\":\"bareclaw\"}", .headers = &.{.{ .name = "Content-Type", .value = "application/json" }} },
        .{ .body = "{\"ok\":true,\"source\":\"bearclaw-upstream\"}", .headers = &.{.{ .name = "Content-Type", .value = "application/json" }} },
    });
    defer upstream.stop();
    try upstream.run();

    var options = bearClawProfile(baseOptions(upstream.port()));
    options.ready_https_insecure = true;

    var tardigrade = try TardigradeProcess.start(allocator, options);
    defer tardigrade.stop();

    // TC-TARDIGRADE-002: /bearclaw/health proxied without requiring auth.
    var health_no_auth = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/bearclaw/health",
        .method = "GET",
        .headers = &.{.{ .name = "Host", .value = "api.example.com" }},
        .insecure = true,
    });
    defer health_no_auth.deinit();
    try std.testing.expectEqual(@as(u16, 200), health_no_auth.status_code);
    try assertContains(health_no_auth.body, "bareclaw");
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    const health_path = try upstream.capturedPath(allocator);
    defer allocator.free(health_path);
    try std.testing.expectEqualStrings("/health", health_path);

    // TC-TARDIGRADE-004: /bearclaw/v1/* requires auth — no token → 401.
    var api_no_auth = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/bearclaw/v1/chat",
        .method = "POST",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Host", .value = "api.example.com" },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
    });
    defer api_no_auth.deinit();
    try std.testing.expectEqual(@as(u16, 401), api_no_auth.status_code);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    // TC-TARDIGRADE-004: malformed or invalid bearer → 403.
    var api_invalid_auth = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/bearclaw/v1/chat",
        .method = "POST",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Host", .value = "api.example.com" },
            .{ .name = "Authorization", .value = "Bearer wrong-token" },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
    });
    defer api_invalid_auth.deinit();
    try std.testing.expectEqual(@as(u16, 403), api_invalid_auth.status_code);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    // TC-TARDIGRADE-004: /bearclaw/v1/* with valid auth → proxied, 200.
    var api_authorized = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/bearclaw/v1/chat",
        .method = "POST",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Host", .value = "api.example.com" },
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
    });
    defer api_authorized.deinit();
    try std.testing.expectEqual(@as(u16, 200), api_authorized.status_code);
    try assertContains(api_authorized.body, "\"source\":\"bearclaw-upstream\"");
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());

    const api_path = try upstream.capturedPath(allocator);
    defer allocator.free(api_path);
    try std.testing.expectEqualStrings("/v1/chat", api_path);
}

test "jwt auth forwards asserted identity headers upstream" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true,\"source\":\"bearclaw-upstream\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try authProxyConfig(allocator);
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .profile = .generic,
        .upstream_port = upstream.port(),
        .auth_token_hashes = null,
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_JWT_SECRET", .value = "stage-2c-secret" },
            .{ .name = "TARDIGRADE_JWT_ISSUER", .value = "bearclaw-web" },
            .{ .name = "TARDIGRADE_JWT_AUDIENCE", .value = "bearclaw-api" },
        },
    });
    defer tardigrade.stop();

    const jwt = try hs256Jwt(
        allocator,
        "stage-2c-secret",
        "{\"sub\":\"user-42\",\"iss\":\"bearclaw-web\",\"aud\":\"bearclaw-api\",\"scope\":\"bearclaw.operator\",\"device_id\":\"bearclaw-web\",\"exp\":4102444800}",
    );
    defer allocator.free(jwt);
    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{jwt});
    defer allocator.free(auth_header);

    var api_authorized = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = auth_header },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer api_authorized.deinit();
    try std.testing.expectEqual(@as(u16, 200), api_authorized.status_code);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
    try std.testing.expectEqualStrings("user-42", upstream.capturedHeader("X-Tardigrade-User-ID").?);
    try std.testing.expectEqualStrings("bearclaw-web", upstream.capturedHeader("X-Tardigrade-Device-ID").?);
    try std.testing.expectEqualStrings("bearclaw.operator", upstream.capturedHeader("X-Tardigrade-Scopes").?);
    try std.testing.expectEqualStrings("user-42", upstream.capturedHeader("X-Tardigrade-Auth-Identity").?);
}

test "jwt auth rejects malformed bearer and invalid signature without proxying" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true,\"source\":\"bearclaw-upstream\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try authProxyConfig(allocator);
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .profile = .generic,
        .upstream_port = upstream.port(),
        .auth_token_hashes = null,
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_JWT_SECRET", .value = "stage-2c-jwt-secret" },
            .{ .name = "TARDIGRADE_JWT_ISSUER", .value = "bearclaw-web" },
            .{ .name = "TARDIGRADE_JWT_AUDIENCE", .value = "bearclaw-api" },
        },
    });
    defer tardigrade.stop();

    var malformed = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer invalid token" },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer malformed.deinit();
    try std.testing.expectEqual(@as(u16, 403), malformed.status_code);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());

    const invalid_signature_jwt = try hs256Jwt(
        allocator,
        "wrong-secret",
        "{\"sub\":\"user-42\",\"iss\":\"bearclaw-web\",\"aud\":\"bearclaw-api\",\"scope\":\"bearclaw.operator\",\"device_id\":\"bearclaw-web\",\"exp\":4102444800}",
    );
    defer allocator.free(invalid_signature_jwt);
    const invalid_signature_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{invalid_signature_jwt});
    defer allocator.free(invalid_signature_header);

    var invalid_signature = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = invalid_signature_header },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer invalid_signature.deinit();
    try std.testing.expectEqual(@as(u16, 403), invalid_signature.status_code);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "inbound X-Tardigrade headers are stripped and unauthenticated requests are not proxied" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true,\"source\":\"bearclaw-upstream\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try authProxyConfig(allocator);
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .profile = .generic,
        .upstream_port = upstream.port(),
        .auth_token_hashes = null,
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_JWT_SECRET", .value = "stage-2c-strip-secret" },
            .{ .name = "TARDIGRADE_JWT_ISSUER", .value = "bearclaw-web" },
            .{ .name = "TARDIGRADE_JWT_AUDIENCE", .value = "bearclaw-api" },
        },
    });
    defer tardigrade.stop();

    const jwt = try hs256Jwt(
        allocator,
        "stage-2c-strip-secret",
        "{\"sub\":\"real-user\",\"iss\":\"bearclaw-web\",\"aud\":\"bearclaw-api\",\"scope\":\"bearclaw.operator\",\"device_id\":\"real-device\",\"exp\":4102444800}",
    );
    defer allocator.free(jwt);
    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{jwt});
    defer allocator.free(auth_header);

    // Authenticated request with forged identity headers — upstream should see
    // Tardigrade's asserted values, not the forged ones.
    var forged = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = auth_header },
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "X-Tardigrade-User-ID", .value = "forged-user" },
            .{ .name = "X-Tardigrade-Auth-Identity", .value = "forged-identity" },
            .{ .name = "X-Tardigrade-Scopes", .value = "forged.scope" },
        },
    });
    defer forged.deinit();
    try std.testing.expectEqual(@as(u16, 200), forged.status_code);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
    // Forged values must be overwritten by Tardigrade's real asserted values.
    try std.testing.expectEqualStrings("real-user", upstream.capturedHeader("X-Tardigrade-User-ID").?);
    try std.testing.expectEqualStrings("real-user", upstream.capturedHeader("X-Tardigrade-Auth-Identity").?);
    try std.testing.expectEqualStrings("bearclaw.operator", upstream.capturedHeader("X-Tardigrade-Scopes").?);

    // Unauthenticated request to a protected path must be rejected at the edge
    // and never reach the upstream (request count stays at 1).
    var rejected = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer rejected.deinit();
    try std.testing.expectEqual(@as(u16, 401), rejected.status_code);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    // Invalid bearer must produce 403 and also not reach the upstream.
    var forbidden = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer invalid-token" },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer forbidden.deinit();
    try std.testing.expectEqual(@as(u16, 403), forbidden.status_code);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
}

test "proxy requests strip hop-by-hop headers before reaching upstreams" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
    });
    defer tardigrade.stop();

    const raw_request =
        "GET /proxy/test HTTP/1.1\r\n" ++
        "Host: 127.0.0.1\r\n" ++
        "User-Agent: integration-client/1.0\r\n" ++
        "Connection: X-Test-Hop, X-Another-Hop, keep-alive\r\n" ++
        "Keep-Alive: timeout=5\r\n" ++
        "Proxy-Authenticate: Basic realm=\"upstream\"\r\n" ++
        "Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n" ++
        "TE: trailers\r\n" ++
        "Trailer: X-Trailer-Test\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "Upgrade: websocket\r\n" ++
        "X-Test-Hop: secret-one\r\n" ++
        "X-Another-Hop: secret-two\r\n" ++
        "X-Custom-Pass: still-here\r\n" ++
        "\r\n";

    var response = try sendRawRequest(allocator, tardigrade.port, raw_request);
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
    try std.testing.expect(upstream.capturedHeader("Connection") == null);
    try std.testing.expect(upstream.capturedHeader("Keep-Alive") == null);
    try std.testing.expect(upstream.capturedHeader("Proxy-Authenticate") == null);
    try std.testing.expect(upstream.capturedHeader("Proxy-Authorization") == null);
    try std.testing.expect(upstream.capturedHeader("TE") == null);
    try std.testing.expect(upstream.capturedHeader("Trailer") == null);
    try std.testing.expect(upstream.capturedHeader("Transfer-Encoding") == null);
    try std.testing.expect(upstream.capturedHeader("Upgrade") == null);
    try std.testing.expect(upstream.capturedHeader("X-Test-Hop") == null);
    try std.testing.expect(upstream.capturedHeader("X-Another-Hop") == null);
    try std.testing.expectEqualStrings("integration-client/1.0", upstream.capturedHeader("User-Agent").?);
    try std.testing.expectEqualStrings("still-here", upstream.capturedHeader("X-Custom-Pass").?);
}

test "upstream fixture serves multiple requests on one keep-alive connection" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "fixture-first", .connection_header = "keep-alive" },
        .{ .body = "fixture-second", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    var stream = try compat.tcpConnectToHost(allocator, test_host, upstream.port());
    defer stream.close();
    try setStreamTimeouts(&stream, 5_000);

    try stream.writeAll(
        "GET /first HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: keep-alive\r\n\r\n",
    );
    var first = try readHttpResponse(allocator, stream);
    defer first.deinit();
    try std.testing.expectEqual(@as(u16, 200), first.status_code);
    try assertContains(first.body, "fixture-first");
    try std.testing.expect(headerHasToken(first.headers_raw, "Connection", "keep-alive"));

    try stream.writeAll(
        "GET /second HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n\r\n",
    );
    var second = try readHttpResponse(allocator, stream);
    defer second.deinit();
    try std.testing.expectEqual(@as(u16, 200), second.status_code);
    try assertContains(second.body, "fixture-second");

    try waitForUpstreamCount(&upstream, 2, 2_000);
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());
}

test "proxy evicts stale pooled upstream connection after backend restart" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"version\":\"old\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .connection_header = "keep-alive",
    }});
    defer upstream.stop();
    try upstream.run();

    const upstream_port = upstream.port();
    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream_port });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS", .value = "1" },
        },
    });
    defer tardigrade.stop();

    var first = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/version",
        .body = null,
        .headers = &.{},
    });
    defer first.deinit();
    try std.testing.expectEqual(@as(u16, 200), first.status_code);
    try std.testing.expectEqualStrings("{\"version\":\"old\"}", first.body);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    upstream.stop();
    upstream = try UpstreamServer.startOnPort(allocator, upstream_port, &.{.{
        .body = "{\"version\":\"new\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    try upstream.run();

    var second = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/version",
        .body = null,
        .headers = &.{},
    });
    defer second.deinit();
    try std.testing.expectEqual(@as(u16, 200), second.status_code);
    try std.testing.expectEqualStrings("{\"version\":\"new\"}", second.body);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    var third = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/version",
        .body = null,
        .headers = &.{},
    });
    defer third.deinit();
    try std.testing.expectEqual(@as(u16, 200), third.status_code);
    try std.testing.expectEqualStrings("{\"version\":\"new\"}", third.body);
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());
}

test "proxy does not replay non-idempotent request on stale pooled upstream connection after backend restart" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"version\":\"old\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .connection_header = "keep-alive",
    }});
    defer upstream.stop();
    try upstream.run();

    const upstream_port = upstream.port();
    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream_port });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS", .value = "1" },
        },
    });
    defer tardigrade.stop();

    var first = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/version",
        .body = null,
        .headers = &.{},
    });
    defer first.deinit();
    try std.testing.expectEqual(@as(u16, 200), first.status_code);
    try std.testing.expectEqualStrings("{\"version\":\"old\"}", first.body);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    upstream.stop();
    upstream = try UpstreamServer.startOnPort(allocator, upstream_port, &.{.{
        .body = "{\"version\":\"new\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    try upstream.run();

    var post = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/proxy/version",
        .body = "{\"write\":true}",
        .headers = &.{},
    });
    defer post.deinit();
    try std.testing.expectEqual(@as(u16, 502), post.status_code);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());

    var second = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/version",
        .body = null,
        .headers = &.{},
    });
    defer second.deinit();
    try std.testing.expectEqual(@as(u16, 200), second.status_code);
    try std.testing.expectEqualStrings("{\"version\":\"new\"}", second.body);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
}

test "proxy forwards POST with an explicit zero-length body" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/proxy/login",
        .body = "",
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
}

test "proxy preserves large buffered upstream body bytes exactly" {
    const allocator = std.testing.allocator;
    const prefix = "/*! tailwindcss v4.1.4 | MIT License | integration */\n";
    const payload_len = prefix.len + 24 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memcpy(payload[0..prefix.len], prefix);
    for (payload[prefix.len..], 0..) |*byte, idx| {
        byte.* = @intCast('a' + @as(u8, @intCast(idx % 26)));
    }

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = payload,
        .headers = &.{.{ .name = "Content-Type", .value = "text/css" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/assets/tailwind.css",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqual(@as(usize, payload_len), response.body.len);
    try std.testing.expectEqualStrings(payload, response.body);
}

test "proxy buffered response limit can exceed request parser cap" {
    const allocator = std.testing.allocator;
    const payload_len = 300 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 'x');

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = payload,
        .headers = &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES", .value = "393216" },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/payload.bin",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqual(@as(usize, payload_len), response.body.len);
    try std.testing.expectEqualStrings(payload, response.body);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
}

test "proxy streaming mode relays upstream body beyond buffered cap" {
    const allocator = std.testing.allocator;
    const payload_len = 1024 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, idx| {
        byte.* = @intCast('a' + @as(u8, @intCast(idx % 26)));
    }

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = payload,
        .headers = &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "response" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
            .{ .name = "TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES", .value = "65536" },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/large.bin",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqual(@as(usize, payload_len), response.body.len);
    try std.testing.expectEqualStrings(payload, response.body);
    try std.testing.expectEqualStrings("chunked", response.header("Transfer-Encoding").?);

    var metrics = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer metrics.deinit();
    const streamed = prometheusMetricValue(metrics.body, "tardigrade_proxy_streaming_requests_total") orelse return error.InvalidHttpResponse;
    const buffered = prometheusMetricValue(metrics.body, "tardigrade_proxy_buffered_requests_total") orelse return error.InvalidHttpResponse;
    try std.testing.expect(streamed >= 1);
    try std.testing.expectEqual(@as(u64, 0), buffered);
}

test "proxy route streaming policy overrides global mode" {
    const allocator = std.testing.allocator;
    const payload_len = 256 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 'x');

    var streaming_upstream = try UpstreamServer.start(allocator, &.{.{
        .body = payload,
        .headers = &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
    }});
    defer streaming_upstream.stop();
    try streaming_upstream.run();

    const streaming_config = try std.fmt.allocPrint(allocator,
        \\location /stream/ {{
        \\    proxy_pass http://{s}:{d};
        \\    proxy_streaming response;
        \\}}
    , .{ test_host, streaming_upstream.port() });
    defer allocator.free(streaming_config);

    var streaming_tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = streaming_config,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "off" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
            .{ .name = "TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES", .value = "65536" },
        },
    });
    defer streaming_tardigrade.stop();

    var streamed_response = try sendRequest(allocator, streaming_tardigrade.port, .{
        .method = "GET",
        .path = "/stream/large.bin",
        .body = null,
        .headers = &.{},
    });
    defer streamed_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), streamed_response.status_code);
    try std.testing.expectEqual(@as(usize, payload_len), streamed_response.body.len);

    var streaming_metrics = try sendRequest(allocator, streaming_tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer streaming_metrics.deinit();
    const streamed = prometheusMetricValue(streaming_metrics.body, "tardigrade_proxy_streaming_requests_total") orelse return error.InvalidHttpResponse;
    try std.testing.expect(streamed >= 1);

    var buffered_upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "small buffered response",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    }});
    defer buffered_upstream.stop();
    try buffered_upstream.run();

    const buffered_config = try std.fmt.allocPrint(allocator,
        \\location /compat/ {{
        \\    proxy_pass http://{s}:{d};
        \\    proxy_streaming off;
        \\}}
    , .{ test_host, buffered_upstream.port() });
    defer allocator.free(buffered_config);

    var buffered_tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = buffered_config,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "full" },
        },
    });
    defer buffered_tardigrade.stop();

    var buffered_response = try sendRequest(allocator, buffered_tardigrade.port, .{
        .method = "POST",
        .path = "/compat/small.txt",
        .body = "request body",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    });
    defer buffered_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), buffered_response.status_code);
    try std.testing.expectEqualStrings("small buffered response", buffered_response.body);

    var buffered_metrics = try sendRequest(allocator, buffered_tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer buffered_metrics.deinit();
    try std.testing.expect(std.mem.find(u8, buffered_metrics.body, "tardigrade_proxy_streaming_fallback_total{reason=\"policy_disabled\"} 2") != null);
}

test "proxy streaming mode handles chunked and no-body upstream responses" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{
        .{
            .body = "chunked upstream payload",
            .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
            .chunked = true,
        },
        .{
            .body = "head body must not be forwarded",
            .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
        },
        .{
            .status_code = 204,
            .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
            .omit_body = true,
        },
        .{
            .status_code = 304,
            .headers = &.{.{ .name = "ETag", .value = "\"abc\"" }},
            .omit_body = true,
        },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "response" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "2048" },
        },
    });
    defer tardigrade.stop();

    var chunked = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/chunked",
        .body = null,
        .headers = &.{},
    });
    defer chunked.deinit();
    try std.testing.expectEqual(@as(u16, 200), chunked.status_code);
    try std.testing.expectEqualStrings("chunked upstream payload", chunked.body);
    try std.testing.expectEqualStrings("chunked", chunked.header("Transfer-Encoding").?);

    var head = try sendRequest(allocator, tardigrade.port, .{
        .method = "HEAD",
        .path = "/proxy/head",
        .body = null,
        .headers = &.{},
    });
    defer head.deinit();
    try std.testing.expectEqual(@as(u16, 200), head.status_code);
    try std.testing.expectEqual(@as(usize, 0), head.body.len);
    try std.testing.expect(head.header("Transfer-Encoding") == null);

    var no_content = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/no-content",
        .body = null,
        .headers = &.{},
    });
    defer no_content.deinit();
    try std.testing.expectEqual(@as(u16, 204), no_content.status_code);
    try std.testing.expectEqual(@as(usize, 0), no_content.body.len);
    try std.testing.expect(no_content.header("Transfer-Encoding") == null);

    var not_modified = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/not-modified",
        .body = null,
        .headers = &.{},
    });
    defer not_modified.deinit();
    try std.testing.expectEqual(@as(u16, 304), not_modified.status_code);
    try std.testing.expectEqual(@as(usize, 0), not_modified.body.len);
    try std.testing.expect(not_modified.header("Transfer-Encoding") == null);
}

test "proxy streaming mode records upstream abort after partial body" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "abcdef",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
        .truncate_body_after = 3,
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "response" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "1024" },
        },
    });
    defer tardigrade.stop();

    try std.testing.expectError(error.InvalidHttpResponse, sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/truncated",
        .body = null,
        .headers = &.{},
    }));

    var metrics = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer metrics.deinit();
    const upstream_aborts = prometheusMetricValue(metrics.body, "tardigrade_proxy_upstream_aborts_total") orelse return error.InvalidHttpResponse;
    try std.testing.expect(upstream_aborts >= 1);
}

test "proxy full streaming mode relays fixed-length upload beyond request buffer cap" {
    const allocator = std.testing.allocator;
    const payload_len = 768 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, idx| {
        byte.* = @intCast('0' + @as(u8, @intCast(idx % 10)));
    }

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "uploaded",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /upload {{
        \\    proxy_pass http://{s}:{d}/upload;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "full" },
            .{ .name = "TARDIGRADE_WORKER_THREADS", .value = "2" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
            .{ .name = "TARDIGRADE_PROXY_BUFFER_PER_STREAM_LOW_WATERMARK_BYTES", .value = "1024" },
            .{ .name = "TARDIGRADE_PROXY_BUFFER_PER_STREAM_HIGH_WATERMARK_BYTES", .value = "2048" },
            .{ .name = "TARDIGRADE_PROXY_BUFFER_PER_STREAM_HARD_LIMIT_BYTES", .value = "65536" },
            .{ .name = "TARDIGRADE_MAX_BODY_SIZE", .value = "1048576" },
        },
    });
    defer tardigrade.stop();

    var upload_stream = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
    defer upload_stream.close();
    try setStreamTimeouts(&upload_stream, 5_000);
    const upload_head = try std.fmt.allocPrint(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: {d}\r\n\r\n",
        .{ test_host, tardigrade.port, payload.len },
    );
    defer allocator.free(upload_head);
    const initial_prefix_len = 32 * 1024;
    const initial_request = try std.mem.concat(allocator, u8, &.{ upload_head, payload[0..initial_prefix_len] });
    defer allocator.free(initial_request);
    try upload_stream.writeAll(initial_request);

    var saw_active_upload = false;
    var metrics_attempt: usize = 0;
    while (metrics_attempt < 20 and !saw_active_upload) : (metrics_attempt += 1) {
        var active_metrics = try sendRequest(allocator, tardigrade.port, .{
            .method = "GET",
            .path = "/status/metrics",
            .body = "",
            .headers = &.{},
        });
        defer active_metrics.deinit();
        saw_active_upload =
            std.mem.find(u8, active_metrics.body, "tardigrade_buffered_bytes_current{direction=\"downstream_to_upstream\",scope=\"stream\"} 16384") != null and
            std.mem.find(u8, active_metrics.body, "tardigrade_buffered_bytes_current{direction=\"downstream_to_upstream\",scope=\"global\"} 16384") != null and
            std.mem.find(u8, active_metrics.body, "tardigrade_buffered_bytes_current{direction=\"upstream_to_downstream\",scope=\"stream\"} 0") != null;
        if (!saw_active_upload) compat.sleepNs(25 * std.time.ns_per_ms);
    }
    try std.testing.expect(saw_active_upload);

    // The parked upload's relay buffer is charged to its HTTP/1 origin, not
    // only to the process (#140): a fixed buffer bounds one request, but the
    // scope concurrency to one origin can multiply is the origin. Safe to
    // sample after the loop — the upload is blocked on bytes this test has not
    // sent yet, so the gauge cannot move under us.
    const origin_label = try std.fmt.allocPrint(allocator, "upstream=\"http:{s}:{d}\"", .{ test_host, upstream.port() });
    defer allocator.free(origin_label);
    {
        var origin_metrics = try sendRequest(allocator, tardigrade.port, .{
            .method = "GET",
            .path = "/status/metrics",
            .body = "",
            .headers = &.{},
        });
        defer origin_metrics.deinit();
        try std.testing.expectEqual(@as(?u64, 16384), prometheusLabeledMetricValue(
            origin_metrics.body,
            "tardigrade_upstream_pool_buffered_bytes",
            &.{ origin_label, "direction=\"downstream_to_upstream\"" },
        ));
    }

    try upload_stream.writeAll(payload[initial_prefix_len..]);
    var response = try readHttpResponse(allocator, upload_stream);
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("uploaded", response.body);

    const captured = try upstream.capturedBody(allocator);
    defer allocator.free(captured);
    try std.testing.expectEqual(@as(usize, payload_len), captured.len);
    try std.testing.expectEqualStrings(payload, captured);

    var metrics = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = "",
        .headers = &.{},
    });
    defer metrics.deinit();
    try std.testing.expect(std.mem.find(u8, metrics.body, "tardigrade_buffer_high_watermark_events_total{direction=\"upstream_to_downstream\",scope=\"stream\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, metrics.body, "tardigrade_buffer_high_watermark_events_total{direction=\"downstream_to_upstream\",scope=\"stream\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, metrics.body, "tardigrade_buffered_bytes_current{direction=\"upstream_to_downstream\",scope=\"global\"} 0") != null);
    try std.testing.expect(std.mem.find(u8, metrics.body, "tardigrade_buffered_bytes_current{direction=\"downstream_to_upstream\",scope=\"global\"} 0") != null);
    // The origin's account drained with the exchange, in both directions.
    inline for (.{ "direction=\"downstream_to_upstream\"", "direction=\"upstream_to_downstream\"" }) |direction| {
        try std.testing.expectEqual(@as(?u64, 0), prometheusLabeledMetricValue(
            metrics.body,
            "tardigrade_upstream_pool_buffered_bytes",
            &.{ origin_label, direction },
        ));
    }
}

test "concurrent http1 uploads to one origin are bounded by the per-origin buffer cap" {
    const allocator = std.testing.allocator;
    const payload_len = 256 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 'c');

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "first uploaded" },
        .{ .body = "unused" },
        .{ .body = "unused" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /upload {{
        \\    proxy_pass http://{s}:{d}/upload;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    // The upload relay buffer floors at 16 KiB, so a per-origin cap just over
    // that admits one upload to this origin at a time and refuses a second.
    // Nothing about a single request would ever refuse it — only the aggregate
    // can. The per-stream hard limit has to leave room for a full window plus
    // a relay buffer (2048 + 16384), and the per-origin floor is that hard
    // limit, which is why both are 18432 rather than a bare 16384.
    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "full" },
            .{ .name = "TARDIGRADE_WORKER_THREADS", .value = "4" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
            .{ .name = "TARDIGRADE_PROXY_BUFFER_PER_STREAM_LOW_WATERMARK_BYTES", .value = "1024" },
            .{ .name = "TARDIGRADE_PROXY_BUFFER_PER_STREAM_HIGH_WATERMARK_BYTES", .value = "2048" },
            .{ .name = "TARDIGRADE_PROXY_BUFFER_PER_STREAM_HARD_LIMIT_BYTES", .value = "18432" },
            .{ .name = "TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES", .value = "18432" },
            .{ .name = "TARDIGRADE_MAX_BODY_SIZE", .value = "1048576" },
        },
    });
    defer tardigrade.stop();

    const upload_head = try std.fmt.allocPrint(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: {d}\r\n\r\n",
        .{ test_host, tardigrade.port, payload.len },
    );
    defer allocator.free(upload_head);

    // Head only, no body bytes yet: the relay's fixed 16 KiB buffer is then the
    // whole of what this upload holds, which is what lets the cap be set to
    // exactly one upload. (Body bytes arriving with the head would be reserved
    // on top of it.) Upload one parks there until this test sends the rest.
    var first = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
    defer first.close();
    try setStreamTimeouts(&first, 10_000);
    try first.writeAll(upload_head);

    const origin_label = try std.fmt.allocPrint(allocator, "upstream=\"http:{s}:{d}\"", .{ test_host, upstream.port() });
    defer allocator.free(origin_label);
    var origin_saturated = false;
    var attempt: usize = 0;
    while (attempt < 40 and !origin_saturated) : (attempt += 1) {
        var active_metrics = try sendRequest(allocator, tardigrade.port, .{
            .method = "GET",
            .path = "/status/metrics",
            .body = "",
            .headers = &.{},
        });
        defer active_metrics.deinit();
        origin_saturated = prometheusLabeledMetricValue(
            active_metrics.body,
            "tardigrade_upstream_pool_buffered_bytes",
            &.{ origin_label, "direction=\"downstream_to_upstream\"" },
        ) == @as(u64, 16384);
        if (!origin_saturated) compat.sleepNs(25 * std.time.ns_per_ms);
    }
    try std.testing.expect(origin_saturated);

    // Upload two meets a full origin. The refusal is local saturation raised
    // before the response head is committed, so it is a clean 503 rather than
    // a status blamed on a perfectly healthy origin.
    var second = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
    defer second.close();
    try setStreamTimeouts(&second, 10_000);
    try second.writeAll(upload_head);
    var refused = try readHttpResponse(allocator, second);
    defer refused.deinit();
    try std.testing.expectEqual(@as(u16, 503), refused.status_code);
    try std.testing.expect(std.mem.find(u8, refused.body, "proxy_buffer_saturated") != null);

    // The parked upload was untouched by the refusal and still completes.
    try first.writeAll(payload);
    var accepted = try readHttpResponse(allocator, first);
    defer accepted.deinit();
    try std.testing.expectEqual(@as(u16, 200), accepted.status_code);

    var metrics = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = "",
        .headers = &.{},
    });
    defer metrics.deinit();
    // The refusal was counted at the origin scope, and every reservation came
    // back: the cap bounded memory rather than latching it.
    try std.testing.expect((prometheusLabeledMetricValue(
        metrics.body,
        "tardigrade_upstream_pool_buffer_limit_exceeded_total",
        &.{ origin_label, "direction=\"downstream_to_upstream\"" },
    ) orelse 0) >= 1);
    try std.testing.expect((prometheusLabeledMetricValue(
        metrics.body,
        "tardigrade_buffer_limit_exceeded_total",
        &.{ "direction=\"downstream_to_upstream\"", "scope=\"origin\"" },
    ) orelse 0) >= 1);
    try std.testing.expectEqual(@as(?u64, 0), prometheusLabeledMetricValue(
        metrics.body,
        "tardigrade_upstream_pool_buffered_bytes",
        &.{ origin_label, "direction=\"downstream_to_upstream\"" },
    ));
}

test "proxy full streaming upload works for server block route override" {
    const allocator = std.testing.allocator;
    const payload_len = 384 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 'v');

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "vhost uploaded",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\server {{
        \\    server_name uploads.example.test;
        \\    location /upload {{
        \\        proxy_pass http://{s}:{d}/upload;
        \\        proxy_streaming full;
        \\    }}
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "off" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
            .{ .name = "TARDIGRADE_MAX_BODY_SIZE", .value = "524288" },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/upload",
        .body = payload,
        .headers = &.{
            .{ .name = "Host", .value = "uploads.example.test" },
            .{ .name = "Content-Type", .value = "application/octet-stream" },
        },
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("vhost uploaded", response.body);

    const captured = try upstream.capturedBody(allocator);
    defer allocator.free(captured);
    try std.testing.expectEqual(@as(usize, payload_len), captured.len);
    try std.testing.expectEqualStrings(payload, captured);
}

test "proxy full streaming mode relays a chunked upload without buffering it" {
    const allocator = std.testing.allocator;
    const payload_len = 512 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, idx| {
        byte.* = @intCast('a' + @as(u8, @intCast(idx % 26)));
    }

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "chunked uploaded",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /upload {{
        \\    proxy_pass http://{s}:{d}/upload;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "full" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
            .{ .name = "TARDIGRADE_MAX_BODY_SIZE", .value = "1048576" },
        },
    });
    defer tardigrade.stop();

    var upload_stream = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
    defer upload_stream.close();
    try setStreamTimeouts(&upload_stream, 5_000);

    const head = try std.fmt.allocPrint(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
        .{ test_host, tardigrade.port },
    );
    defer allocator.free(head);
    try upload_stream.writeAll(head);

    // Send the body as many small chunks with an extension and a trailer, all
    // of which the relay must consume and re-frame rather than forward.
    var offset: usize = 0;
    const chunk_len = 16 * 1024;
    while (offset < payload_len) {
        const take = @min(chunk_len, payload_len - offset);
        var size_line_buf: [64]u8 = undefined;
        const size_line = try std.fmt.bufPrint(&size_line_buf, "{x};tag=stream\r\n", .{take});
        try upload_stream.writeAll(size_line);
        try upload_stream.writeAll(payload[offset .. offset + take]);
        try upload_stream.writeAll("\r\n");
        offset += take;
    }
    try upload_stream.writeAll("0\r\nX-Upload-Checksum: ignored\r\n\r\n");

    var response = try readHttpResponse(allocator, upload_stream);
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("chunked uploaded", response.body);

    // The upstream saw chunked framing (so the gateway re-framed rather than
    // buffering to compute a Content-Length) and the exact decoded payload.
    try std.testing.expectEqualStrings("chunked", upstream.capturedHeader("Transfer-Encoding").?);
    try std.testing.expect(upstream.capturedHeader("Content-Length") == null);
    const captured = try upstream.capturedBody(allocator);
    defer allocator.free(captured);
    try std.testing.expectEqual(@as(usize, payload_len), captured.len);
    try std.testing.expectEqualStrings(payload, captured);

    var metrics = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer metrics.deinit();
    const streamed = prometheusMetricValue(metrics.body, "tardigrade_proxy_streaming_requests_total") orelse return error.InvalidHttpResponse;
    try std.testing.expect(streamed >= 1);
    try std.testing.expect(std.mem.find(u8, metrics.body, "tardigrade_proxy_streaming_fallback_total{reason=\"missing_content_length\"} 0") != null);
}

test "proxy full streaming mode relays a chunked upload to an h2c upstream as DATA" {
    const allocator = std.testing.allocator;
    const payload_len = 384 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, idx| {
        byte.* = @intCast('a' + @as(u8, @intCast(idx % 26)));
    }

    var upstream = try H2cUpstreamServer.start(allocator, "h2c chunked uploaded");
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /upload {{
        \\    proxy_pass http://{s}:{d}/upload;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "full" },
            // Prior-knowledge h2c: the upstream is plain HTTP, so this is the
            // only way to reach relayStreamingUploadToHttp2 without TLS ALPN.
            .{ .name = "TARDIGRADE_UPSTREAM_PROTOCOL", .value = "h2c" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
            .{ .name = "TARDIGRADE_MAX_BODY_SIZE", .value = "1048576" },
        },
        // Probe a gateway-local path so readiness never reaches the origin and
        // the request-count assertion below stays exact.
        .ready_path = "/status/metrics",
    });
    defer tardigrade.stop();

    var upload_stream = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
    defer upload_stream.close();
    try setStreamTimeouts(&upload_stream, 10_000);

    const head = try std.fmt.allocPrint(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
        .{ test_host, tardigrade.port },
    );
    defer allocator.free(head);
    try upload_stream.writeAll(head);

    var offset: usize = 0;
    const chunk_len = 16 * 1024;
    while (offset < payload_len) {
        const take = @min(chunk_len, payload_len - offset);
        var size_line_buf: [64]u8 = undefined;
        const size_line = try std.fmt.bufPrint(&size_line_buf, "{x};tag=stream\r\n", .{take});
        try upload_stream.writeAll(size_line);
        try upload_stream.writeAll(payload[offset .. offset + take]);
        try upload_stream.writeAll("\r\n");
        offset += take;
    }
    try upload_stream.writeAll("0\r\nX-Upload-Checksum: ignored\r\n\r\n");

    var response = try readHttpResponse(allocator, upload_stream);
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("h2c chunked uploaded", response.body);

    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
    // HTTP/2 carries no transfer coding, and the gateway must not invent a
    // Content-Length it cannot know for an unterminated chunked upload.
    try std.testing.expect(!upstream.capturedHasHeader("content-length"));
    try std.testing.expect(!upstream.capturedHasHeader("transfer-encoding"));
    // END_STREAM (not a length) delimited the body, and every decoded byte
    // arrived exactly once.
    const captured = try upstream.capturedBody(allocator);
    defer allocator.free(captured);
    try std.testing.expectEqual(@as(usize, payload_len), captured.len);
    try std.testing.expectEqualStrings(payload, captured);

    var metrics = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer metrics.deinit();
    const streamed = prometheusMetricValue(metrics.body, "tardigrade_proxy_streaming_requests_total") orelse return error.InvalidHttpResponse;
    try std.testing.expect(streamed >= 1);
}

test "proxy full streaming mode rejects malformed and oversized chunked uploads" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "unreachable",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /upload {{
        \\    proxy_pass http://{s}:{d}/upload;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "full" },
            .{ .name = "TARDIGRADE_MAX_BODY_SIZE", .value = "4096" },
        },
    });
    defer tardigrade.stop();

    // Chunk payload not followed by CRLF: client framing fault, not an origin
    // failure, so it must surface as 400 rather than 502.
    {
        var stream = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
        defer stream.close();
        try setStreamTimeouts(&stream, 5_000);
        const request = try std.fmt.allocPrint(
            allocator,
            "POST /upload HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloBROKEN\r\n0\r\n\r\n",
            .{ test_host, tardigrade.port },
        );
        defer allocator.free(request);
        try stream.writeAll(request);
        var response = try readHttpResponse(allocator, stream);
        defer response.deinit();
        try std.testing.expectEqual(@as(u16, 400), response.status_code);
    }

    // Decoded payload past TARDIGRADE_MAX_BODY_SIZE must be rejected mid-relay.
    {
        var stream = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
        defer stream.close();
        try setStreamTimeouts(&stream, 5_000);
        const head = try std.fmt.allocPrint(
            allocator,
            "POST /upload HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n",
            .{ test_host, tardigrade.port },
        );
        defer allocator.free(head);
        try stream.writeAll(head);
        const chunk = "800\r\n" ++ ("z" ** 2048) ++ "\r\n";
        // Two 2 KiB chunks fit the 4 KiB budget; the third must be refused.
        stream.writeAll(chunk) catch {};
        stream.writeAll(chunk) catch {};
        stream.writeAll(chunk) catch {};
        stream.writeAll("0\r\n\r\n") catch {};
        var response = try readHttpResponse(allocator, stream);
        defer response.deinit();
        try std.testing.expectEqual(@as(u16, 413), response.status_code);
    }
}

test "proxy streaming mode relays a close-delimited upstream response" {
    const allocator = std.testing.allocator;
    const payload_len = 256 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 'c');

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = payload,
        .headers = &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
        .close_delimited = true,
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "response" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
            .{ .name = "TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES", .value = "65536" },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/close-delimited.bin",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    // Relayed downstream with chunked framing, so the client still gets an
    // explicit end-of-message rather than depending on the connection close.
    try std.testing.expectEqualStrings("chunked", response.header("Transfer-Encoding").?);
    try std.testing.expectEqual(@as(usize, payload_len), response.body.len);
    try std.testing.expectEqualStrings(payload, response.body);
}

test "proxy streaming mode records a client abort during a large response" {
    const allocator = std.testing.allocator;
    const payload_len = 4 * 1024 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 'q');

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = payload,
        .headers = &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "response" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
        },
    });
    defer tardigrade.stop();

    {
        var stream = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
        defer stream.close();
        try setStreamTimeouts(&stream, 5_000);
        const request = try std.fmt.allocPrint(
            allocator,
            "GET /proxy/huge.bin HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\n\r\n",
            .{ test_host, tardigrade.port },
        );
        defer allocator.free(request);
        try stream.writeAll(request);
        // Read only the head plus a little body, then close mid-transfer.
        var scratch: [4096]u8 = undefined;
        _ = stream.read(&scratch) catch {};
    }

    try waitForMetricAtLeast(allocator, tardigrade.port, "tardigrade_proxy_client_aborts_total", 1, 5_000);
}

test "proxy full streaming mode records a client abort during an upload" {
    const allocator = std.testing.allocator;
    const payload_len = 512 * 1024;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "never completed",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /upload {{
        \\    proxy_pass http://{s}:{d}/upload;
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "full" },
            .{ .name = "TARDIGRADE_MAX_BODY_SIZE", .value = "1048576" },
        },
    });
    defer tardigrade.stop();

    {
        var stream = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
        defer stream.close();
        try setStreamTimeouts(&stream, 5_000);
        const head = try std.fmt.allocPrint(
            allocator,
            "POST /upload HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n",
            .{ test_host, tardigrade.port, payload_len },
        );
        defer allocator.free(head);
        try stream.writeAll(head);
        // Promise 512 KiB, deliver 1 KiB, then hang up.
        const partial = try allocator.alloc(u8, 1024);
        defer allocator.free(partial);
        @memset(partial, 'p');
        try stream.writeAll(partial);
    }

    try waitForMetricAtLeast(allocator, tardigrade.port, "tardigrade_proxy_client_aborts_total", 1, 5_000);
}

test "proxy streaming mode streams over a unix socket upstream" {
    const allocator = std.testing.allocator;
    const payload_len = 256 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, idx| {
        byte.* = @intCast('A' + @as(u8, @intCast(idx % 26)));
    }

    // AF_UNIX paths are capped near 104 bytes and the config loader requires an
    // absolute one, so the repo-relative .zig-cache scratch dir is not usable.
    const socket_path = try std.fmt.allocPrint(allocator, "/tmp/tg-stream-{d}.sock", .{compat.milliTimestamp()});
    defer allocator.free(socket_path);

    var upstream = try UpstreamServer.startOnUnixSocket(allocator, socket_path, &.{.{
        .body = payload,
        .headers = &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
    }});
    defer upstream.stop();
    try upstream.run();

    // A Unix-socket upstream is selected by the base URL; the location keeps a
    // relative proxy_pass so the socket path resolves for the route.
    const upstream_base_url = try std.fmt.allocPrint(allocator, "unix:{s}", .{socket_path});
    defer allocator.free(upstream_base_url);

    const config_text =
        \\location /proxy/ {
        \\    proxy_pass /upstream/;
        \\}
    ;

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_BASE_URL", .value = upstream_base_url },
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "response" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
            .{ .name = "TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES", .value = "65536" },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/large.bin",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqual(@as(usize, payload_len), response.body.len);
    try std.testing.expectEqualStrings(payload, response.body);

    var metrics = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer metrics.deinit();
    // A Unix-socket target is no longer a reason to buffer: the response
    // streamed past the buffered cap with no fallback event.
    const streamed = prometheusMetricValue(metrics.body, "tardigrade_proxy_streaming_requests_total") orelse return error.InvalidHttpResponse;
    try std.testing.expect(streamed >= 1);
    try std.testing.expect(std.mem.find(u8, metrics.body, "tardigrade_proxy_streaming_fallback_total{reason=\"unsupported_route_type\"} 0") != null);
}

test "proxy streaming mode streams from an upstream requiring a client certificate" {
    const allocator = std.testing.allocator;
    // The appliance profile stubs the upstream TLS client out entirely
    // (`UpstreamTlsConn.connect` returns `error.ContextInitFailed`), so *no*
    // HTTPS upstream works there — buffered or streaming. Upstream mTLS is only
    // reachable under the general profile.
    try requireGeneralTlsProfile();
    try requireOpenssl(allocator);

    // `openssl s_server -Verify 1` refuses any peer without a certificate
    // signed by the test CA, so a successful exchange proves the streaming
    // relay presented the configured upstream client certificate.
    const server_cert = try applianceFixturePath(allocator, "server.crt");
    defer allocator.free(server_cert);
    const server_key = try applianceFixturePath(allocator, "server.key");
    defer allocator.free(server_key);
    const ca_cert = try applianceFixturePath(allocator, "ca.crt");
    defer allocator.free(ca_cert);
    const client_cert = try applianceFixturePath(allocator, "client.crt");
    defer allocator.free(client_cert);
    const client_key = try applianceFixturePath(allocator, "client.key");
    defer allocator.free(client_key);

    // `-WWW` serves files from its working directory and, since it sends no
    // Content-Length, close-delimits the body — which also exercises that
    // framing over mTLS.
    var origin_dir = try GenericFixtureDir.create(allocator, "mtls-stream-origin");
    defer origin_dir.deinit();
    const payload_len = 256 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 'm');
    try origin_dir.writeRel("large.bin", payload);

    const origin_port = try findFreePort();
    const accept_arg = try std.fmt.allocPrint(allocator, "{d}", .{origin_port});
    defer allocator.free(accept_arg);

    var argv = [_][]const u8{
        "openssl", "s_server",
        "-accept", accept_arg,
        "-cert",   server_cert,
        "-key",    server_key,
        "-CAfile", ca_cert,
        "-Verify", "1",
        // The upstream TLS client requires a negotiated protocol, so the origin
        // has to answer the ALPN offer like any real HTTPS backend.
        "-alpn",   "http/1.1",
        "-WWW",    "-quiet",
    };
    var origin = try std.process.spawn(compat.io(), .{
        .argv = &argv,
        .cwd = .{ .path = origin_dir.dir_abs },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer origin.kill(compat.io());
    try waitForTcpPort(origin_port, 5_000);

    const upstream_url = try std.fmt.allocPrint(allocator, "https://{s}:{d}", .{ test_host, origin_port });
    defer allocator.free(upstream_url);

    const config_text =
        \\location /secure/ {
        \\    proxy_pass /;
        \\}
    ;

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_BASE_URL", .value = upstream_url },
            // The fixture leaf carries DNS:localhost; hostname verification
            // matches DNS SANs, so name the origin rather than its IP.
            .{ .name = "TARDIGRADE_UPSTREAM_TLS_SERVER_NAME", .value = "localhost" },
            .{ .name = "TARDIGRADE_UPSTREAM_TLS_CLIENT_CERT", .value = client_cert },
            .{ .name = "TARDIGRADE_UPSTREAM_TLS_CLIENT_KEY", .value = client_key },
            .{ .name = "TARDIGRADE_UPSTREAM_TLS_CA_BUNDLE", .value = ca_cert },
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "response" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
            // Well below the payload: a buffered relay would fail this request
            // instead of streaming it.
            .{ .name = "TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES", .value = "32768" },
        },
        .ready_path = "/status/metrics",
    });
    defer tardigrade.stop();

    var response = try sendRequestWithTimeout(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/secure/large.bin",
        .body = null,
        .headers = &.{},
    }, 15_000);
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqual(@as(usize, payload_len), response.body.len);
    try std.testing.expectEqualStrings(payload, response.body);

    var metrics = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer metrics.deinit();
    const streamed = prometheusMetricValue(metrics.body, "tardigrade_proxy_streaming_requests_total") orelse return error.InvalidHttpResponse;
    try std.testing.expect(streamed >= 1);
    // An mTLS upstream is no longer a reason to buffer, so nothing fell back.
    const buffered = prometheusMetricValue(metrics.body, "tardigrade_proxy_buffered_requests_total") orelse return error.InvalidHttpResponse;
    try std.testing.expectEqual(@as(u64, 0), buffered);
}

test "proxy streaming falls back with a retries_configured reason when retries are enabled" {
    const allocator = std.testing.allocator;
    const payload_len = 128 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 'r');

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = payload,
        .headers = &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "response" },
            .{ .name = "TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS", .value = "2" },
            .{ .name = "TARDIGRADE_UPSTREAM_RETRY_IDEMPOTENT_ONLY", .value = "false" },
            .{ .name = "TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES", .value = "1048576" },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/retryable.bin",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqual(@as(usize, payload_len), response.body.len);

    var metrics = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer metrics.deinit();
    const fallbacks = prometheusMetricValue(metrics.body, "tardigrade_proxy_streaming_fallback_total{reason=\"retries_configured\"}") orelse return error.InvalidHttpResponse;
    try std.testing.expect(fallbacks >= 1);
    const buffered = prometheusMetricValue(metrics.body, "tardigrade_proxy_buffered_requests_total") orelse return error.InvalidHttpResponse;
    try std.testing.expect(buffered >= 1);
}

test "proxy buffered response limit returns stable 502 when upstream body exceeds cap" {
    const allocator = std.testing.allocator;
    const payload_len = 300 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 'y');

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = payload,
        .headers = &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES", .value = "131072" },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/payload.bin",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 502), response.status_code);
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());
}

test "raising proxy buffered response limit does not relax request parsing" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES", .value = "393216" },
        },
    });
    defer tardigrade.stop();

    const oversized_path_len = 270 * 1024;
    const oversized_path = try allocator.alloc(u8, oversized_path_len);
    defer allocator.free(oversized_path);
    oversized_path[0] = '/';
    for (oversized_path[1..]) |*byte| byte.* = 'a';

    var raw_request = std.array_list.Managed(u8).init(allocator);
    defer raw_request.deinit();
    try raw_request.print("GET {s} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", .{oversized_path});

    var response = try sendRawRequest(allocator, tardigrade.port, raw_request.items);
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 400), response.status_code);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "parser abuse requests are rejected before reaching upstreams" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
    });
    defer tardigrade.stop();

    var duplicate_cl = try sendRawRequest(
        allocator,
        tardigrade.port,
        "POST /proxy/test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\nhello!!",
    );
    defer duplicate_cl.deinit();
    try std.testing.expectEqual(@as(u16, 400), duplicate_cl.status_code);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());

    var obs_fold = try sendRawRequest(
        allocator,
        tardigrade.port,
        "GET /proxy/test HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Test: good\r\n\tX-Folded: nope\r\n\r\n",
    );
    defer obs_fold.deinit();
    try std.testing.expectEqual(@as(u16, 400), obs_fold.status_code);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());

    var many_headers_request = std.array_list.Managed(u8).init(allocator);
    defer many_headers_request.deinit();
    try many_headers_request.appendSlice("GET /proxy/test HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    for (0..105) |idx| {
        try many_headers_request.print("X-Test-{d}: value\r\n", .{idx});
    }
    try many_headers_request.appendSlice("\r\n");
    var many_headers = try sendRawRequest(allocator, tardigrade.port, many_headers_request.items);
    defer many_headers.deinit();
    try std.testing.expectEqual(@as(u16, 431), many_headers.status_code);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());

    const long_path = try std.fmt.allocPrint(allocator, "/proxy/{s}", .{"a" ** 9000});
    defer allocator.free(long_path);
    const long_request = try std.fmt.allocPrint(allocator, "GET {s} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", .{long_path});
    defer allocator.free(long_request);
    var oversized_request_line = try sendRawRequest(allocator, tardigrade.port, long_request);
    defer oversized_request_line.deinit();
    try std.testing.expectEqual(@as(u16, 400), oversized_request_line.status_code);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());
}

test "rate limiting uses asserted identity for shared nat clients" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "{\"ok\":true,\"user\":\"user-42\"}", .headers = &.{.{ .name = "Content-Type", .value = "application/json" }} },
        .{ .body = "{\"ok\":true,\"user\":\"user-84\"}", .headers = &.{.{ .name = "Content-Type", .value = "application/json" }} },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try authProxyConfig(allocator);
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .profile = .generic,
        .upstream_port = upstream.port(),
        .auth_token_hashes = null,
        .rate_limit_rps = "0.001",
        .rate_limit_burst = "1",
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_JWT_SECRET", .value = "stage-3a-secret" },
            .{ .name = "TARDIGRADE_JWT_ISSUER", .value = "bearclaw-web" },
            .{ .name = "TARDIGRADE_JWT_AUDIENCE", .value = "bearclaw-api" },
        },
    });
    defer tardigrade.stop();

    const jwt_a = try hs256Jwt(
        allocator,
        "stage-3a-secret",
        "{\"sub\":\"user-42\",\"iss\":\"bearclaw-web\",\"aud\":\"bearclaw-api\",\"scope\":\"bearclaw.operator\",\"device_id\":\"bearclaw-web\",\"exp\":4102444800}",
    );
    defer allocator.free(jwt_a);
    const jwt_b = try hs256Jwt(
        allocator,
        "stage-3a-secret",
        "{\"sub\":\"user-84\",\"iss\":\"bearclaw-web\",\"aud\":\"bearclaw-api\",\"scope\":\"bearclaw.operator\",\"device_id\":\"bearclaw-web\",\"exp\":4102444800}",
    );
    defer allocator.free(jwt_b);
    const auth_a = try std.fmt.allocPrint(allocator, "Bearer {s}", .{jwt_a});
    defer allocator.free(auth_a);
    const auth_b = try std.fmt.allocPrint(allocator, "Bearer {s}", .{jwt_b});
    defer allocator.free(auth_b);

    var first_a = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"hello from user 42\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = auth_a },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer first_a.deinit();
    try std.testing.expectEqual(@as(u16, 200), first_a.status_code);

    var second_a = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"second request same identity\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = auth_a },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer second_a.deinit();
    try std.testing.expectEqual(@as(u16, 429), second_a.status_code);

    var first_b = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"hello from user 84\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = auth_b },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer first_b.deinit();
    try std.testing.expectEqual(@as(u16, 200), first_b.status_code);
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());
}

test "proxy requests preserve safe request ids and structured access logs include upstream metadata" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "{\"ok\":true}", .headers = &.{.{ .name = "Content-Type", .value = "application/json" }} },
        .{ .body = "{\"ok\":true}", .headers = &.{.{ .name = "Content-Type", .value = "application/json" }} },
        .{ .body = "{\"ok\":true}", .headers = &.{.{ .name = "Content-Type", .value = "application/json" }} },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .profile = .generic,
        .config_text = config_text,
    });
    defer tardigrade.stop();

    var generated = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/generated",
        .body = null,
        .headers = &.{},
    });
    defer generated.deinit();
    const generated_request_id = generated.header("X-Request-ID") orelse return error.InvalidHttpResponse;
    const generated_correlation_id = generated.header("X-Correlation-ID") orelse return error.InvalidHttpResponse;
    try std.testing.expect(generated_request_id.len > 0);
    try std.testing.expectEqualStrings(generated_request_id, generated_correlation_id);
    try std.testing.expectEqualStrings(generated_request_id, upstream.capturedHeader("X-Request-ID").?);
    try std.testing.expectEqualStrings(generated_request_id, upstream.capturedHeader("X-Correlation-ID").?);

    const valid_request_id = "tg-1778460305668-bfebecb410803023";
    var preserved = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/preserved",
        .body = null,
        .headers = &.{
            .{ .name = "X-Request-ID", .value = valid_request_id },
        },
    });
    defer preserved.deinit();
    try std.testing.expectEqualStrings(valid_request_id, preserved.header("X-Request-ID").?);
    try std.testing.expectEqualStrings(valid_request_id, preserved.header("X-Correlation-ID").?);
    try std.testing.expectEqualStrings(valid_request_id, upstream.capturedHeader("X-Request-ID").?);
    try std.testing.expectEqualStrings(valid_request_id, upstream.capturedHeader("X-Correlation-ID").?);

    const upstream_addr = try std.fmt.allocPrint(allocator, "\"upstream_addr\":\"{s}:{d}\"", .{ test_host, upstream.port() });
    defer allocator.free(upstream_addr);
    const upstream_status = "\"upstream_status\":200";
    const response_bytes = "\"response_bytes\":11";
    const request_id_log = try std.fmt.allocPrint(allocator, "\"request_id\":\"{s}\"", .{valid_request_id});
    defer allocator.free(request_id_log);
    try waitForLogSubstring(allocator, tardigrade.log_path, request_id_log, 2_000);
    try waitForLogSubstring(allocator, tardigrade.log_path, upstream_addr, 2_000);
    try waitForLogSubstring(allocator, tardigrade.log_path, upstream_status, 2_000);
    try waitForLogSubstring(allocator, tardigrade.log_path, response_bytes, 2_000);

    var replaced = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/replaced",
        .body = null,
        .headers = &.{
            .{ .name = "X-Request-ID", .value = "bad id" },
        },
    });
    defer replaced.deinit();
    const replaced_request_id = replaced.header("X-Request-ID") orelse return error.InvalidHttpResponse;
    try std.testing.expect(replaced_request_id.len > 0);
    try std.testing.expect(!std.mem.eql(u8, replaced_request_id, "bad id"));
    try std.testing.expect(std.mem.findScalar(u8, replaced_request_id, ' ') == null);
    try std.testing.expectEqualStrings(replaced_request_id, replaced.header("X-Correlation-ID").?);
    try std.testing.expectEqualStrings(replaced_request_id, upstream.capturedHeader("X-Request-ID").?);
    try std.testing.expectEqualStrings(replaced_request_id, upstream.capturedHeader("X-Correlation-ID").?);
}

test "sticky affinity cookie pins relative proxy_pass upstream and sets secure defaults" {
    const allocator = std.testing.allocator;

    var first_upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "first-upstream-a" },
        .{ .body = "first-upstream-b" },
    });
    defer first_upstream.stop();
    try first_upstream.run();

    var second_upstream = try UpstreamServer.start(allocator, &.{.{ .body = "second-upstream" }});
    defer second_upstream.stop();
    try second_upstream.run();

    const upstream_urls = try std.fmt.allocPrint(
        allocator,
        "http://{s}:{d},http://{s}:{d}",
        .{ test_host, first_upstream.port(), test_host, second_upstream.port() },
    );
    defer allocator.free(upstream_urls);
    const config_text = try allocator.dupe(u8,
        \\location /sticky/ {
        \\    proxy_pass /upstream/;
        \\}
    );
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_BASE_URLS", .value = upstream_urls },
            .{ .name = "TARDIGRADE_UPSTREAM_LB_ALGORITHM", .value = "round_robin" },
            .{ .name = "TARDIGRADE_TRUST_SHARED_SECRET", .value = "stage-3b-secret" },
        },
    });
    defer tardigrade.stop();

    var first_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/sticky/demo",
        .body = null,
        .headers = &.{},
    });
    defer first_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), first_response.status_code);
    const set_cookie = first_response.header("Set-Cookie") orelse return error.MissingSetCookie;
    try std.testing.expect(std.mem.find(u8, set_cookie, "HttpOnly") != null);
    try std.testing.expect(std.mem.find(u8, set_cookie, "Secure") != null);
    try std.testing.expect(std.mem.find(u8, set_cookie, "SameSite=Lax") != null);

    var second_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/sticky/demo",
        .body = null,
        .headers = &.{.{ .name = "Cookie", .value = cookiePairFromSetCookie(set_cookie) }},
    });
    defer second_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), second_response.status_code);
    try std.testing.expectEqual(@as(u32, 2), first_upstream.requestCount());
    try std.testing.expectEqual(@as(u32, 0), second_upstream.requestCount());
}

test "sticky affinity ignores tampered cookie and rotates to a healthy upstream" {
    const allocator = std.testing.allocator;

    var first_upstream = try UpstreamServer.start(allocator, &.{.{ .body = "first-upstream" }});
    defer first_upstream.stop();
    try first_upstream.run();

    var second_upstream = try UpstreamServer.start(allocator, &.{.{ .body = "second-upstream" }});
    defer second_upstream.stop();
    try second_upstream.run();

    const upstream_urls = try std.fmt.allocPrint(
        allocator,
        "http://{s}:{d},http://{s}:{d}",
        .{ test_host, first_upstream.port(), test_host, second_upstream.port() },
    );
    defer allocator.free(upstream_urls);
    const config_text = try allocator.dupe(u8,
        \\location /sticky/ {
        \\    proxy_pass /upstream/;
        \\}
    );
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_BASE_URLS", .value = upstream_urls },
            .{ .name = "TARDIGRADE_UPSTREAM_LB_ALGORITHM", .value = "round_robin" },
            .{ .name = "TARDIGRADE_TRUST_SHARED_SECRET", .value = "stage-3b-secret" },
        },
    });
    defer tardigrade.stop();

    var first_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/sticky/demo",
        .body = null,
        .headers = &.{},
    });
    defer first_response.deinit();
    const cookie_pair = cookiePairFromSetCookie(first_response.header("Set-Cookie") orelse return error.MissingSetCookie);
    const tampered_cookie = try allocator.dupe(u8, cookie_pair);
    defer allocator.free(tampered_cookie);
    tampered_cookie[tampered_cookie.len - 1] = if (tampered_cookie[tampered_cookie.len - 1] == 'a') 'b' else 'a';

    var second_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/sticky/demo",
        .body = null,
        .headers = &.{.{ .name = "Cookie", .value = tampered_cookie }},
    });
    defer second_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), second_response.status_code);
    try std.testing.expectEqual(@as(u32, 1), first_upstream.requestCount());
    try std.testing.expectEqual(@as(u32, 1), second_upstream.requestCount());
}

test "sticky affinity remaps unhealthy upstream cookies to a healthy backend" {
    const allocator = std.testing.allocator;

    var first_upstream = try UpstreamServer.start(allocator, &.{
        .{ .status_code = 200, .body = "first-upstream" },
        .{ .status_code = 500, .body = "first-failed" },
    });
    defer first_upstream.stop();
    try first_upstream.run();

    var second_upstream = try UpstreamServer.start(allocator, &.{.{ .status_code = 200, .body = "second-upstream" }});
    defer second_upstream.stop();
    try second_upstream.run();

    const upstream_urls = try std.fmt.allocPrint(
        allocator,
        "http://{s}:{d},http://{s}:{d}",
        .{ test_host, first_upstream.port(), test_host, second_upstream.port() },
    );
    defer allocator.free(upstream_urls);
    const config_text = try allocator.dupe(u8,
        \\location /sticky/ {
        \\    proxy_pass /upstream/;
        \\}
    );
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_BASE_URLS", .value = upstream_urls },
            .{ .name = "TARDIGRADE_UPSTREAM_LB_ALGORITHM", .value = "round_robin" },
            .{ .name = "TARDIGRADE_TRUST_SHARED_SECRET", .value = "stage-3b-secret" },
            .{ .name = "TARDIGRADE_UPSTREAM_MAX_FAILS", .value = "1" },
            .{ .name = "TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS", .value = "60000" },
        },
    });
    defer tardigrade.stop();

    var first_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/sticky/demo",
        .body = null,
        .headers = &.{},
    });
    defer first_response.deinit();
    const cookie_pair = cookiePairFromSetCookie(first_response.header("Set-Cookie") orelse return error.MissingSetCookie);

    var second_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/sticky/demo",
        .body = null,
        .headers = &.{.{ .name = "Cookie", .value = cookie_pair }},
    });
    defer second_response.deinit();
    try std.testing.expectEqual(@as(u16, 500), second_response.status_code);

    var third_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/sticky/demo",
        .body = null,
        .headers = &.{.{ .name = "Cookie", .value = cookie_pair }},
    });
    defer third_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), third_response.status_code);
    try std.testing.expectEqual(@as(u32, 2), first_upstream.requestCount());
    try std.testing.expectEqual(@as(u32, 1), second_upstream.requestCount());
    try std.testing.expect(!std.mem.eql(u8, cookie_pair, cookiePairFromSetCookie(third_response.header("Set-Cookie") orelse return error.MissingSetCookie)));
}

const GenericFixtureDir = struct {
    allocator: std.mem.Allocator,
    dir_rel: []u8,
    dir_abs: []u8,

    fn create(allocator: std.mem.Allocator, prefix: []const u8) !GenericFixtureDir {
        const cwd = try compat.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd);
        const unique = compat.nanoTimestamp();
        const dir_rel = try std.fmt.allocPrint(allocator, ".zig-cache/{s}-{d}", .{ prefix, unique });
        errdefer allocator.free(dir_rel);
        try compat.cwd().makePath(dir_rel);
        errdefer compat.cwd().deleteTree(dir_rel) catch {};
        const dir_abs = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cwd, dir_rel });
        errdefer allocator.free(dir_abs);
        return .{ .allocator = allocator, .dir_rel = dir_rel, .dir_abs = dir_abs };
    }

    fn joinRel(self: GenericFixtureDir, suffix: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.dir_rel, suffix });
    }

    fn joinAbs(self: GenericFixtureDir, suffix: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.dir_abs, suffix });
    }

    fn writeRel(self: GenericFixtureDir, suffix: []const u8, data: []const u8) !void {
        const rel = try self.joinRel(suffix);
        defer self.allocator.free(rel);
        if (std.Io.Dir.path.dirname(rel)) |parent| try compat.cwd().makePath(parent);
        try compat.cwd().writeFile(.{ .sub_path = rel, .data = data });
    }

    fn deinit(self: *GenericFixtureDir) void {
        compat.cwd().deleteTree(self.dir_rel) catch {};
        self.allocator.free(self.dir_rel);
        self.allocator.free(self.dir_abs);
        self.* = undefined;
    }
};

test "return config directive issues redirect with request_uri expansion" {
    const allocator = std.testing.allocator;

    const config_text =
        \\location /legacy/ {
        \\    return 301 https://example.com/redirected;
        \\}
    ;

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/legacy/path?q=1",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 301), response.status_code);
    try std.testing.expectEqualStrings("https://example.com/redirected", response.header("Location").?);
}

test "split upstream /ursa mount strips mount prefix and preserves redirects" {
    const allocator = std.testing.allocator;

    const ui_responses = [_]UpstreamResponseSpec{
        .{
            .status_code = 303,
            .headers = &.{
                .{ .name = "Location", .value = "/ursa/auth/login?next=%2F" },
                .{ .name = "Content-Type", .value = "text/plain; charset=utf-8" },
            },
            .body = "",
        },
        .{
            .status_code = 200,
            .headers = &.{.{ .name = "Content-Type", .value = "text/html; charset=utf-8" }},
            .body = "<html>login</html>",
        },
    };
    const c2_responses = [_]UpstreamResponseSpec{
        .{
            .status_code = 200,
            .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
            .body = "{\"status\":\"healthy\"}",
        },
        .{
            .status_code = 200,
            .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
            .body = "{\"registered\":true}",
        },
        .{
            .status_code = 200,
            .headers = &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
            .body = "payload",
        },
    };

    var ui_upstream = try UpstreamServer.start(allocator, &ui_responses);
    defer ui_upstream.stop();
    try ui_upstream.run();

    var c2_upstream = try UpstreamServer.start(allocator, &c2_responses);
    defer c2_upstream.stop();
    try c2_upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /ursa/health {{
        \\    proxy_pass http://{s}:{d};
        \\}}
        \\location = /ursa/register {{
        \\    proxy_pass http://{s}:{d};
        \\}}
        \\location ^~ /ursa/download/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
        \\location /ursa/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{
        test_host, c2_upstream.port(),
        test_host, c2_upstream.port(),
        test_host, c2_upstream.port(),
        test_host, ui_upstream.port(),
    });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
    });
    defer tardigrade.stop();

    var health = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/ursa/health",
        .body = null,
        .headers = &.{},
    });
    defer health.deinit();
    try std.testing.expectEqual(@as(u16, 200), health.status_code);
    try std.testing.expectEqualStrings("{\"status\":\"healthy\"}", health.body);
    try std.testing.expectEqual(@as(u32, 0), ui_upstream.requestCount());

    var register = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/ursa/register",
        .body = "{\"hostname\":\"TEST\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    });
    defer register.deinit();
    try std.testing.expectEqual(@as(u16, 200), register.status_code);
    try std.testing.expectEqualStrings("{\"registered\":true}", register.body);

    var download = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/ursa/download/file.bin",
        .body = null,
        .headers = &.{},
    });
    defer download.deinit();
    try std.testing.expectEqual(@as(u16, 200), download.status_code);
    try std.testing.expectEqualStrings("payload", download.body);

    var root = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/ursa/",
        .body = null,
        .headers = &.{},
    });
    defer root.deinit();
    try std.testing.expectEqual(@as(u16, 303), root.status_code);
    try std.testing.expectEqualStrings("/ursa/auth/login?next=%2F", root.header("Location").?);

    var login = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/ursa/auth/login",
        .body = null,
        .headers = &.{},
    });
    defer login.deinit();
    try std.testing.expectEqual(@as(u16, 200), login.status_code);
    try std.testing.expectEqualStrings("<html>login</html>", login.body);

    const c2_path_0 = try c2_upstream.capturedPathHistoryAt(allocator, 0);
    defer allocator.free(c2_path_0);
    try std.testing.expectEqualStrings("/health", c2_path_0);

    const c2_path_1 = try c2_upstream.capturedPathHistoryAt(allocator, 1);
    defer allocator.free(c2_path_1);
    try std.testing.expectEqualStrings("/register", c2_path_1);

    const c2_path_2 = try c2_upstream.capturedPathHistoryAt(allocator, 2);
    defer allocator.free(c2_path_2);
    try std.testing.expectEqualStrings("/download/file.bin", c2_path_2);

    const ui_path_0 = try ui_upstream.capturedPathHistoryAt(allocator, 0);
    defer allocator.free(ui_path_0);
    try std.testing.expectEqualStrings("/", ui_path_0);

    const ui_path_1 = try ui_upstream.capturedPathHistoryAt(allocator, 1);
    defer allocator.free(ui_path_1);
    try std.testing.expectEqualStrings("/auth/login", ui_path_1);
}

test "if return directive redirects on host match" {
    return error.SkipZigTest;
}

test "location block reload takes effect for new requests after sighup" {
    const allocator = std.testing.allocator;

    const first_responses = [_]UpstreamResponseSpec{.{ .body = "first-location" }};
    const second_responses = [_]UpstreamResponseSpec{.{ .body = "second-location" }};

    var first_upstream = try UpstreamServer.start(allocator, &first_responses);
    defer first_upstream.stop();
    try first_upstream.run();

    var second_upstream = try UpstreamServer.start(allocator, &second_responses);
    defer second_upstream.stop();
    try second_upstream.run();

    const initial_config = try std.fmt.allocPrint(allocator,
        \\location /dynamic/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, first_upstream.port() });
    defer allocator.free(initial_config);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = initial_config,
    });
    defer tardigrade.stop();

    var first_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/dynamic/test",
        .body = null,
        .headers = &.{},
    });
    defer first_response.deinit();
    try std.testing.expectEqualStrings("first-location", first_response.body);

    const updated_config = try std.fmt.allocPrint(allocator,
        \\location /dynamic/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, second_upstream.port() });
    defer allocator.free(updated_config);

    try tardigrade.rewriteConfig(updated_config);
    tardigrade.sendSignal(std.posix.SIG.HUP);
    compat.sleepNs(300 * std.time.ns_per_ms);

    var second_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/dynamic/test",
        .body = null,
        .headers = &.{},
    });
    defer second_response.deinit();
    try std.testing.expectEqualStrings("second-location", second_response.body);
}

test "in-flight request completes safely across reload and new requests use new config" {
    const allocator = std.testing.allocator;

    const first_responses = [_]UpstreamResponseSpec{.{ .body = "first-location", .delay_ms = 700 }};
    const second_responses = [_]UpstreamResponseSpec{.{ .body = "second-location" }};

    var first_upstream = try UpstreamServer.start(allocator, &first_responses);
    defer first_upstream.stop();
    try first_upstream.run();

    var second_upstream = try UpstreamServer.start(allocator, &second_responses);
    defer second_upstream.stop();
    try second_upstream.run();

    const initial_config = try std.fmt.allocPrint(allocator,
        \\location /dynamic/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, first_upstream.port() });
    defer allocator.free(initial_config);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = initial_config,
    });
    defer tardigrade.stop();

    const InFlightResult = struct {
        response: ?HttpResponse = null,
        err: ?anyerror = null,
    };
    var in_flight = InFlightResult{};
    const RequestRunner = struct {
        fn run(ctx: *InFlightResult, alloc: std.mem.Allocator, port: u16) void {
            ctx.response = sendRequest(alloc, port, .{
                .method = "GET",
                .path = "/dynamic/test",
                .body = null,
                .headers = &.{},
            }) catch |err| {
                ctx.err = err;
                return;
            };
        }
    };

    var request_thread = try std.Thread.spawn(.{}, RequestRunner.run, .{ &in_flight, std.heap.page_allocator, tardigrade.port });
    try waitForUpstreamCount(&first_upstream, 1, 2_000);

    const updated_config = try std.fmt.allocPrint(allocator,
        \\location /dynamic/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, second_upstream.port() });
    defer allocator.free(updated_config);

    try tardigrade.rewriteConfig(updated_config);
    tardigrade.sendSignal(std.posix.SIG.HUP);
    compat.sleepNs(300 * std.time.ns_per_ms);

    var second_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/dynamic/test",
        .body = null,
        .headers = &.{},
    });
    defer second_response.deinit();
    try std.testing.expectEqualStrings("second-location", second_response.body);

    request_thread.join();
    if (in_flight.err) |err| return err;
    var first_response = in_flight.response orelse return error.InvalidHttpResponse;
    defer first_response.deinit();
    try std.testing.expectEqualStrings("first-location", first_response.body);
}

test "location blocks integration routes requests to matching upstreams" {
    const allocator = std.testing.allocator;

    var exact_upstream = try UpstreamServer.start(allocator, &.{.{ .body = "exact-upstream" }});
    defer exact_upstream.stop();
    try exact_upstream.run();

    var prefix_upstream = try UpstreamServer.start(allocator, &.{.{ .body = "prefix-upstream" }});
    defer prefix_upstream.stop();
    try prefix_upstream.run();

    var regex_upstream = try UpstreamServer.start(allocator, &.{.{ .body = "regex-upstream" }});
    defer regex_upstream.stop();
    try regex_upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /exact {{
        \\    proxy_pass http://{s}:{d};
        \\}}
        \\
        \\location ^~ /prefix/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
        \\
        \\location ~ ^/re/.+$ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{
        test_host,
        exact_upstream.port(),
        test_host,
        prefix_upstream.port(),
        test_host,
        regex_upstream.port(),
    });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
    });
    defer tardigrade.stop();

    var exact_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/exact",
        .body = null,
        .headers = &.{},
    });
    defer exact_response.deinit();
    try std.testing.expectEqualStrings("exact-upstream", exact_response.body);

    var prefix_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/prefix/item",
        .body = null,
        .headers = &.{},
    });
    defer prefix_response.deinit();
    try std.testing.expectEqualStrings("prefix-upstream", prefix_response.body);

    var regex_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/re/value",
        .body = null,
        .headers = &.{},
    });
    defer regex_response.deinit();
    try std.testing.expectEqualStrings("regex-upstream", regex_response.body);
}

test "server blocks integration routes hosts to separate upstreams with default fallback" {
    return error.SkipZigTest;
}

test "static file integration serves configured index html" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-root");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "<html><body>index fixture</body></html>\n");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/index.html",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "index fixture");
}

test "static file integration serves default index.html when root is set without index or try_files (#437)" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-root-default-index");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "<html><body>default index fixture</body></html>\n");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "default index fixture");
}

test "static file integration resolves nested directory index relative to the requested directory (#437)" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-root-nested-index");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "root index\n");
    try fixture.writeRel("public/docs/index.html", "docs index\n");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var root_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/",
        .body = null,
        .headers = &.{},
    });
    defer root_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), root_response.status_code);
    try assertContains(root_response.body, "root index");

    var docs_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/docs/",
        .body = null,
        .headers = &.{},
    });
    defer docs_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), docs_response.status_code);
    try assertContains(docs_response.body, "docs index");
}

test "static file integration resolves nested directory index under alias prefix (#437)" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-alias-nested-index");
    defer fixture.deinit();
    try fixture.writeRel("assets/docs/index.html", "alias docs index\n");

    const assets_abs = try fixture.joinAbs("assets");
    defer allocator.free(assets_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location /assets/ {{
        \\    alias {s};
        \\}}
    , .{assets_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/assets/docs/",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "alias docs index");
}

test "static file integration does not fall back to the root index for a nonexistent directory (#437)" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-root-missing-dir");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "root index\n");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/missing/",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 404), response.status_code);
}

test "static file integration prefers an existing index over autoindex when both are enabled (#437)" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-index-over-autoindex");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "index wins\n");
    try fixture.writeRel("public/other.txt", "other");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri;
        \\    autoindex on;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "index wins");
}

test "static file integration index opt-out allows autoindex to run (#437)" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-index-optout-autoindex");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "should not be served\n");
    try fixture.writeRel("public/other.txt", "other");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    index "";
        \\    autoindex on;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "other.txt");
}

test "static file integration serves large files over plain http" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-large");
    defer fixture.deinit();

    const payload_len = 256 * 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @intCast(i % 251);
    try fixture.writeRel("public/large.bin", payload);

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/large.bin",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqual(@as(usize, payload_len), response.body.len);
    try std.testing.expect(std.mem.eql(u8, payload, response.body));
}

test "top-level try_files serves index html and rejects encoded traversal" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-top-level");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "<html><body>root fixture</body></html>\n");
    try fixture.writeRel("secret.txt", "do not leak\n");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\root {s};
        \\try_files $uri /index.html;
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var index_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/",
        .body = null,
        .headers = &.{},
    });
    defer index_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), index_response.status_code);
    try assertContains(index_response.body, "root fixture");

    var traversal_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/%2e%2e/secret.txt",
        .body = null,
        .headers = &.{},
    });
    defer traversal_response.deinit();
    try std.testing.expectEqual(@as(u16, 403), traversal_response.status_code);
}

test "security headers are emitted with safe defaults (#175)" {
    // Locks in the production-safe security-header posture so a future change
    // cannot silently weaken it. These are default-on and applied to every
    // response (here a `return` terminal).
    const allocator = std.testing.allocator;
    const config_text =
        \\location = /r {
        \\    return 200 ok;
        \\}
    ;
    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/r",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("DENY", response.header("X-Frame-Options") orelse "");
    try std.testing.expectEqualStrings("nosniff", response.header("X-Content-Type-Options") orelse "");
    try std.testing.expectEqualStrings("default-src 'self'", response.header("Content-Security-Policy") orelse "");
    try std.testing.expectEqualStrings("strict-origin-when-cross-origin", response.header("Referrer-Policy") orelse "");
    try std.testing.expectEqualStrings("camera=(), microphone=(), geolocation=()", response.header("Permissions-Policy") orelse "");
    // X-XSS-Protection is intentionally "0" (disabled; CSP is the modern control).
    try std.testing.expectEqualStrings("0", response.header("X-XSS-Protection") orelse "");
    try std.testing.expectEqualStrings("same-origin", response.header("Cross-Origin-Opener-Policy") orelse "");
    try std.testing.expectEqualStrings("same-origin", response.header("Cross-Origin-Resource-Policy") orelse "");
}

test "security headers can be disabled via config (#175)" {
    const allocator = std.testing.allocator;
    const config_text =
        \\location = /r {
        \\    return 200 ok;
        \\}
    ;
    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{.{ .name = "TARDIGRADE_SECURITY_HEADERS", .value = "false" }},
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/r",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    // The full default set must be absent when disabled.
    try std.testing.expect(response.header("X-Frame-Options") == null);
    try std.testing.expect(response.header("X-Content-Type-Options") == null);
    try std.testing.expect(response.header("Content-Security-Policy") == null);
    try std.testing.expect(response.header("Referrer-Policy") == null);
    try std.testing.expect(response.header("Permissions-Policy") == null);
    try std.testing.expect(response.header("X-XSS-Protection") == null);
    try std.testing.expect(response.header("Cross-Origin-Opener-Policy") == null);
    try std.testing.expect(response.header("Cross-Origin-Resource-Policy") == null);
}

test "security headers do not override or duplicate upstream-provided values (#175)" {
    // When a proxied upstream sets its own security headers, the gateway must
    // preserve them (setHeaderIfAbsent / writeSecurityHeadersFiltered) rather
    // than overwrite or duplicate — while still filling in the ones the upstream
    // omitted.
    const allocator = std.testing.allocator;
    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true}",
        .headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
            // Non-canonical case on purpose: the filter must dedupe
            // case-insensitively (no canonical-cased duplicate added).
            .{ .name = "x-frame-options", .value = "SAMEORIGIN" },
            .{ .name = "content-security-policy", .value = "default-src 'none'" },
        },
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/x",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    // Upstream values win, each present exactly once (not the gateway defaults
    // DENY / "default-src 'self'", and not duplicated even across header casing).
    try std.testing.expectEqualStrings("SAMEORIGIN", response.header("X-Frame-Options") orelse "");
    try std.testing.expectEqualStrings("default-src 'none'", response.header("Content-Security-Policy") orelse "");
    try std.testing.expectEqual(@as(usize, 1), countHeaderOccurrences(response.headers_raw, "X-Frame-Options"));
    try std.testing.expectEqual(@as(usize, 1), countHeaderOccurrences(response.headers_raw, "Content-Security-Policy"));
    // Headers the upstream did NOT set are still filled with the gateway default,
    // exactly once — proving the filter is selective, not "skip all if the
    // upstream provided any". Covers both an early and a later default.
    try std.testing.expectEqualStrings("nosniff", response.header("X-Content-Type-Options") orelse "");
    try std.testing.expectEqual(@as(usize, 1), countHeaderOccurrences(response.headers_raw, "X-Content-Type-Options"));
    try std.testing.expectEqualStrings("camera=(), microphone=(), geolocation=()", response.header("Permissions-Policy") orelse "");
    try std.testing.expectEqual(@as(usize, 1), countHeaderOccurrences(response.headers_raw, "Permissions-Policy"));
}

test "HSTS header is emitted on HTTPS responses when enabled (#175)" {
    const allocator = std.testing.allocator;
    var tls_paths = try listenerTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_HSTS_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();

    var response = if (build_options.tls_openssl_adapter)
        try sendCurlRequest(allocator, tardigrade.port, .{
            .scheme = "https",
            .path = "/healthz",
            .insecure = true,
        })
    else
        try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/healthz");
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    // Default HSTS is a 1-year max-age with includeSubDomains on (preload off).
    // Lock the exact value so the policy can't weaken or `preload` can't turn on
    // without an explicit config change.
    try std.testing.expectEqualStrings("max-age=31536000; includeSubDomains", response.header("Strict-Transport-Security") orelse "");
}

test "TLS 1.1 client is rejected when the minimum version is 1.2 (#175)" {
    if (!build_options.tls_openssl_adapter) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const cwd = try compat.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    const cert_path = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/server.crt", .{cwd});
    defer allocator.free(cert_path);
    const key_path = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/server.key", .{cwd});
    defer allocator.free(key_path);

    // Default TARDIGRADE_TLS_MIN_VERSION is 1.2 (not overridden here).
    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = key_path },
        },
    });
    defer tardigrade.stop();

    // Positive control: a client capped at TLS 1.2 still connects. This proves
    // curl's --tls-max path works locally, so the 1.1 failure below is the
    // server rejecting the version rather than a client-side curl quirk.
    var tls12 = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/healthz",
        .insecure = true,
        .tls_max = "1.2",
    });
    defer tls12.deinit();
    try std.testing.expectEqual(@as(u16, 200), tls12.status_code);

    // Same curl option path, same listener, same route — but a client capped at
    // TLS 1.1 has no shared version with the 1.2-minimum server, so the
    // handshake must fail (curl exits non-zero).
    var capped = try runCurl(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/healthz",
        .insecure = true,
        .tls_max = "1.1",
    });
    defer capped.deinit();
    const rejected = switch (capped.term) {
        .exited => |code| code != 0,
        else => true,
    };
    try std.testing.expect(rejected);
}

test "location rewrite action falls through to try_files (#201)" {
    // Guards the routeRequest fall-through after a location `.rewrite` action:
    // the action mutates the path and does NOT return, so control must reach the
    // top-level try_files fallback. A stray early-return in a pipeline refactor
    // would break this.
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "rewrite-fallthrough");
    defer fixture.deinit();
    try fixture.writeRel("public/served.html", "rewritten target\n");
    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);

    const config_text = try std.fmt.allocPrint(allocator,
        \\root {s};
        \\location /old {{
        \\    rewrite /old /served.html last;
        \\}}
        \\try_files $uri =404;
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/old",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    // Rewrote /old -> /served.html and fell through to try_files, which served it.
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "rewritten target");
}

test "static file integration rejects symlink escape outside root" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-symlink-escape");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "<html><body>safe</body></html>\n");
    try fixture.writeRel("secret.txt", "do not leak\n");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const secret_abs = try fixture.joinAbs("secret.txt");
    defer allocator.free(secret_abs);
    const symlink_abs = try fixture.joinAbs("public/linked-secret.txt");
    defer allocator.free(symlink_abs);
    try std.Io.Dir.symLinkAbsolute(compat.io(), secret_abs, symlink_abs, .{});

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/linked-secret.txt",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 403), response.status_code);
}

test "static file integration returns 304 for matching If-Modified-Since" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-ims");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "ims fixture\n");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var initial = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/index.html",
        .body = null,
        .headers = &.{},
    });
    defer initial.deinit();
    const last_modified = initial.header("Last-Modified").?;

    var cached = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/index.html",
        .body = null,
        .headers = &.{.{ .name = "If-Modified-Since", .value = last_modified }},
    });
    defer cached.deinit();
    try std.testing.expectEqual(@as(u16, 304), cached.status_code);
}

test "static file integration returns partial content for range request" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-range");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "abcdefghi");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/index.html",
        .body = null,
        .headers = &.{.{ .name = "Range", .value = "bytes=0-3" }},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 206), response.status_code);
    try std.testing.expectEqualStrings("abcd", response.body);
}

test "listener sharding starts real gateway with reuse-port shards and exports per-shard metrics (#137)" {
    switch (builtin.os.tag) {
        .linux, .freebsd => {},
        else => return,
    }

    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "listener-shards-startup");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "sharded listener ok\n");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{.{ .name = "TARDIGRADE_LISTENER_SHARDS", .value = "4" }},
    });
    defer tardigrade.stop();

    try waitForLogSubstring(allocator, tardigrade.log_path, "Listener sharding enabled: 4 shards", 5_000);

    var served = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/index.html",
        .body = null,
        .headers = &.{},
    });
    defer served.deinit();
    try std.testing.expectEqual(@as(u16, 200), served.status_code);
    try assertContains(served.body, "sharded listener ok");

    for (0..200) |_| {
        var churn = try sendRequest(allocator, tardigrade.port, .{
            .method = "GET",
            .path = "/index.html",
            .body = null,
            .headers = &.{},
        });
        try std.testing.expectEqual(@as(u16, 200), churn.status_code);
        churn.deinit();
    }

    var metrics = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    });
    defer metrics.deinit();
    try std.testing.expectEqual(@as(u16, 200), metrics.status_code);
    try std.testing.expectEqual(@as(u64, 4), prometheusMetricValue(metrics.body, "tardigrade_listener_shards") orelse 0);
    var nonzero_accept_shards: usize = 0;
    for (0..4) |shard| {
        const shard_label = try std.fmt.allocPrint(allocator, "shard=\"{d}\"", .{shard});
        defer allocator.free(shard_label);

        const accept_count = prometheusLabeledMetricValue(metrics.body, "tardigrade_accepts_total", &.{shard_label}) orelse return error.InvalidHttpResponse;
        if (accept_count > 0) nonzero_accept_shards += 1;

        try std.testing.expect(prometheusLabeledMetricValue(metrics.body, "tardigrade_accept_errors_total", &.{ shard_label, "reason=\"poll\"" }) != null);
        try std.testing.expect(prometheusLabeledMetricValue(metrics.body, "tardigrade_accept_errors_total", &.{ shard_label, "reason=\"accept\"" }) != null);
        try std.testing.expect(prometheusLabeledMetricValue(metrics.body, "tardigrade_accept_batch_size_count", &.{shard_label}) != null);
        try std.testing.expect(prometheusLabeledMetricValue(metrics.body, "tardigrade_accept_batches_total", &.{shard_label}) != null);
        try std.testing.expect(prometheusLabeledMetricValue(metrics.body, "tardigrade_accept_fairness_yields_total", &.{shard_label}) != null);
    }
    try std.testing.expect(nonzero_accept_shards > 1);
}

test "static file integration returns autoindex listing when enabled" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-autoindex");
    defer fixture.deinit();
    try fixture.writeRel("public/a.txt", "a");
    try fixture.writeRel("public/b.txt", "b");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    autoindex on;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "a.txt");
    try assertContains(response.body, "b.txt");
}

test "static file integration serves configured custom 404 error page" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "static-error-page");
    defer fixture.deinit();
    try fixture.writeRel("public/errors/404.html", "<html><body>custom not found</body></html>\n");

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\    error_page 404 /errors/404.html;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/missing.html",
        .body = null,
        .headers = &.{.{ .name = "Accept", .value = "text/html" }},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 404), response.status_code);
    try assertContains(response.body, "custom not found");
}

// ---------------------------------------------------------------------------
// Graceful reload / drain / shutdown correctness under load (#170).
// ---------------------------------------------------------------------------

fn sendKeepAliveGet(stream: *compat.NetStream, allocator: std.mem.Allocator, port: u16, path: []const u8) !void {
    const req = try std.fmt.allocPrint(allocator, "GET {s} HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: keep-alive\r\n\r\n", .{ path, test_host, port });
    defer allocator.free(req);
    try stream.writeAll(req);
}

test "reload while serving short static requests drops no in-flight request (#170)" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "reload-static-serving");
    defer fixture.deinit();
    try fixture.writeRel("a/index.html", "site-A\n");
    try fixture.writeRel("b/index.html", "site-B\n");
    const root_a = try fixture.joinAbs("a");
    defer allocator.free(root_a);
    const root_b = try fixture.joinAbs("b");
    defer allocator.free(root_b);

    const config_a = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{root_a});
    defer allocator.free(config_a);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_a });
    defer tardigrade.stop();

    const Hammer = struct {
        port: u16,
        stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        ok: usize = 0,
        fail: usize = 0,
        fn run(self: *@This()) void {
            const a = std.heap.page_allocator;
            while (!self.stop_flag.load(.acquire)) {
                var resp = sendRequest(a, self.port, .{ .method = "GET", .path = "/index.html", .body = null, .headers = &.{} }) catch {
                    self.fail += 1;
                    continue;
                };
                defer resp.deinit();
                if (resp.status_code == 200) self.ok += 1 else self.fail += 1;
            }
        }
    };
    var hammer = Hammer{ .port = tardigrade.port };
    const thread = try std.Thread.spawn(.{}, Hammer.run, .{&hammer});

    // Let requests flow, reload to root B mid-stream, let more flow.
    compat.sleepNs(150 * std.time.ns_per_ms);
    const config_b = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{root_b});
    defer allocator.free(config_b);
    try tardigrade.rewriteConfig(config_b);
    tardigrade.sendSignal(std.posix.SIG.HUP);
    compat.sleepNs(300 * std.time.ns_per_ms);

    hammer.stop_flag.store(true, .release);
    thread.join();

    // The core guarantee: every request served across the reload succeeded.
    try std.testing.expect(hammer.ok > 0);
    try std.testing.expectEqual(@as(usize, 0), hammer.fail);

    // New requests reflect the reloaded config.
    var after = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/index.html", .body = null, .headers = &.{} });
    defer after.deinit();
    try std.testing.expectEqual(@as(u16, 200), after.status_code);
    try assertContains(after.body, "site-B");

    var status = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/tardigrade/reload/status", .body = null, .headers = &.{} });
    defer status.deinit();
    try assertContains(status.body, "\"ok\":true");
}

test "reload while proxying a long upstream response preserves the in-flight body (#170)" {
    const allocator = std.testing.allocator;

    // ~48 KiB body so the transfer is non-trivial and clearly in flight.
    const long_body = try allocator.alloc(u8, 48 * 1024);
    defer allocator.free(long_body);
    for (long_body, 0..) |*b, i| b.* = @intCast(i % 251);

    const first_responses = [_]UpstreamResponseSpec{.{ .body = long_body, .delay_ms = 400 }};
    const second_responses = [_]UpstreamResponseSpec{.{ .body = "second-upstream" }};

    var first_upstream = try UpstreamServer.start(allocator, &first_responses);
    defer first_upstream.stop();
    try first_upstream.run();
    var second_upstream = try UpstreamServer.start(allocator, &second_responses);
    defer second_upstream.stop();
    try second_upstream.run();

    const config_a = try std.fmt.allocPrint(allocator,
        \\location /p/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, first_upstream.port() });
    defer allocator.free(config_a);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_a });
    defer tardigrade.stop();

    const Result = struct { response: ?HttpResponse = null, err: ?anyerror = null };
    var result = Result{};
    const Runner = struct {
        fn run(ctx: *Result, port: u16) void {
            ctx.response = sendRequestWithTimeout(std.heap.page_allocator, port, .{
                .method = "GET",
                .path = "/p/big",
                .body = null,
                .headers = &.{},
            }, 5_000) catch |err| {
                ctx.err = err;
                return;
            };
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{ &result, tardigrade.port });
    try waitForUpstreamCount(&first_upstream, 1, 2_000);

    // Reload to a different upstream while the long response is in flight.
    const config_b = try std.fmt.allocPrint(allocator,
        \\location /p/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, second_upstream.port() });
    defer allocator.free(config_b);
    try tardigrade.rewriteConfig(config_b);
    tardigrade.sendSignal(std.posix.SIG.HUP);

    thread.join();
    if (result.err) |err| return err;
    // Let the reload settle before issuing the post-reload request.
    compat.sleepNs(300 * std.time.ns_per_ms);
    var in_flight = result.response orelse return error.InvalidHttpResponse;
    defer in_flight.deinit();
    // The in-flight request completes intact on the old upstream's full body.
    try std.testing.expectEqual(@as(u16, 200), in_flight.status_code);
    try std.testing.expectEqual(long_body.len, in_flight.body.len);
    try std.testing.expect(std.mem.eql(u8, long_body, in_flight.body));

    // New requests are routed to the reloaded upstream.
    var after = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/p/big", .body = null, .headers = &.{} });
    defer after.deinit();
    try assertContains(after.body, "second-upstream");
}

test "reload while a client is uploading a request body completes the upload (#170)" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "upload-ack" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /upload/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    // Deterministic 4 KiB upload body sent in two halves with a reload in between.
    const body = try allocator.alloc(u8, 4096);
    defer allocator.free(body);
    for (body, 0..) |*b, i| b.* = @intCast((i * 7) % 256);

    var stream = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
    defer stream.close();
    try setStreamTimeouts(&stream, 5_000);

    const head = try std.fmt.allocPrint(allocator, "POST /upload/data HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\nContent-Length: {d}\r\n\r\n", .{ test_host, tardigrade.port, body.len });
    defer allocator.free(head);
    try stream.writeAll(head);
    try stream.writeAll(body[0 .. body.len / 2]);

    // Reload mid-upload.
    try tardigrade.rewriteConfig(config_text);
    tardigrade.sendSignal(std.posix.SIG.HUP);
    compat.sleepNs(150 * std.time.ns_per_ms);

    // Finish the upload; it must still complete against the original config.
    try stream.writeAll(body[body.len / 2 ..]);
    var response = try readHttpResponse(allocator, stream);
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "upload-ack");

    // The upstream received the full, intact body.
    const captured = try upstream.capturedBody(allocator);
    defer allocator.free(captured);
    try std.testing.expectEqual(body.len, captured.len);
    try std.testing.expect(std.mem.eql(u8, body, captured));
}

test "reload succeeds while active upstream health checks are running (#170)" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "svc-ok" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /svc/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_ACTIVE_PROBE_INTERVAL_MS", .value = "100" },
            .{ .name = "TARDIGRADE_UPSTREAM_ACTIVE_PROBE_PATH", .value = "/" },
        },
    });
    defer tardigrade.stop();

    // Let a few active health probes run before reloading.
    compat.sleepNs(350 * std.time.ns_per_ms);
    try tardigrade.rewriteConfig(config_text);
    tardigrade.sendSignal(std.posix.SIG.HUP);
    compat.sleepNs(350 * std.time.ns_per_ms);

    // Reload must have succeeded and the gateway keeps serving.
    var status = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/tardigrade/reload/status", .body = null, .headers = &.{} });
    defer status.deinit();
    try assertContains(status.body, "\"ok\":true");

    var svc = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/svc/x", .body = null, .headers = &.{} });
    defer svc.deinit();
    try std.testing.expectEqual(@as(u16, 200), svc.status_code);
    try assertContains(svc.body, "svc-ok");
}

test "reload does not disrupt a parked keepalive connection (#170)" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "reload-keepalive-park");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "parked-site\n");
    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        // Keep the idle keepalive connection from being reaped during the test.
        .extra_env = &.{.{ .name = "TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS", .value = "30000" }},
    });
    defer tardigrade.stop();

    var stream = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
    defer stream.close();
    try setStreamTimeouts(&stream, 5_000);

    // First request on the keepalive connection.
    try sendKeepAliveGet(&stream, allocator, tardigrade.port, "/index.html");
    var resp1 = try readHttpResponse(allocator, stream);
    defer resp1.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp1.status_code);

    // Let the idle connection park off the worker pool, then reload.
    compat.sleepNs(250 * std.time.ns_per_ms);
    try tardigrade.rewriteConfig(config_text);
    tardigrade.sendSignal(std.posix.SIG.HUP);
    compat.sleepNs(300 * std.time.ns_per_ms);

    // The parked connection must still serve a second request after the reload.
    try sendKeepAliveGet(&stream, allocator, tardigrade.port, "/index.html");
    var resp2 = try readHttpResponse(allocator, stream);
    defer resp2.deinit();
    try std.testing.expectEqual(@as(u16, 200), resp2.status_code);
    try assertContains(resp2.body, "parked-site");
}

test "graceful shutdown drains an active in-flight request before exiting (#170)" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "slow-ok", .delay_ms = 700 }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location /slow/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        // Generous drain window so the 700ms request finishes during drain.
        .extra_env = &.{.{ .name = "TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS", .value = "3000" }},
    });
    defer tardigrade.stop();

    const Result = struct { response: ?HttpResponse = null, err: ?anyerror = null };
    var result = Result{};
    const Runner = struct {
        fn run(ctx: *Result, port: u16) void {
            ctx.response = sendRequestWithTimeout(std.heap.page_allocator, port, .{
                .method = "GET",
                .path = "/slow/job",
                .body = null,
                .headers = &.{},
            }, 5_000) catch |err| {
                ctx.err = err;
                return;
            };
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{ &result, tardigrade.port });
    // Ensure the request is in flight at the upstream before shutting down.
    try waitForUpstreamCount(&upstream, 1, 2_000);

    tardigrade.sendSignal(std.posix.SIG.TERM);

    thread.join();
    if (result.err) |err| return err;
    var response = result.response orelse return error.InvalidHttpResponse;
    defer response.deinit();
    // The active request completed during drain rather than being dropped.
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "slow-ok");

    // And the process actually shut down (listener stopped accepting).
    try waitForPortClosed(tardigrade.port, 5_000);
    try waitForLogSubstring(allocator, tardigrade.log_path, "Graceful shutdown complete", 3_000);
}

test "graceful shutdown completes promptly with a slow client connected (#170)" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "shutdown-slow-client");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "ok\n");
    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            // The client socket recv timeout is governed by keep_alive_timeout_ms;
            // bound it (and the drain window) so a stalled read is force-timed-out
            // and shutdown stays prompt.
            .{ .name = "TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS", .value = "400" },
            .{ .name = "TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS", .value = "500" },
        },
    });
    defer tardigrade.stop();

    // A slow client that opens a connection and sends only a partial request
    // (no terminating blank line), then stalls.
    var slow = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
    defer slow.close();
    const partial = try std.fmt.allocPrint(allocator, "GET /index.html HTTP/1.1\r\nHost: {s}:{d}\r\n", .{ test_host, tardigrade.port });
    defer allocator.free(partial);
    try slow.writeAll(partial);
    compat.sleepNs(50 * std.time.ns_per_ms);

    tardigrade.sendSignal(std.posix.SIG.TERM);

    // Shutdown must complete in bounded time despite the stalled client.
    // waitForPortClosed is the primary timing gate (5 s); there is no separate
    // elapsed assertion because clock skew and CI scheduler variance make the
    // wall-clock measurement unreliable as an assertion.
    try waitForPortClosed(tardigrade.port, 5_000);
    try waitForLogSubstring(allocator, tardigrade.log_path, "Graceful shutdown complete", 3_000);
}

test "invalid reload leaves the previous config active (#170)" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "original-upstream" }});
    defer upstream.stop();
    try upstream.run();

    const valid_config = try std.fmt.allocPrint(allocator,
        \\location /svc/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(valid_config);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = valid_config });
    defer tardigrade.stop();

    var before = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/svc/x", .body = null, .headers = &.{} });
    defer before.deinit();
    try assertContains(before.body, "original-upstream");

    // Rewrite the config to syntactically invalid content and reload.
    try tardigrade.rewriteConfig("this_is_not_valid_config_without_a_terminator\n");
    tardigrade.sendSignal(std.posix.SIG.HUP);
    compat.sleepNs(300 * std.time.ns_per_ms);

    // The previous (valid) config must still be active and serving.
    var after = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/svc/x", .body = null, .headers = &.{} });
    defer after.deinit();
    try std.testing.expectEqual(@as(u16, 200), after.status_code);
    try assertContains(after.body, "original-upstream");

    // Reload status reports failure with the previous config kept.
    var status = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/tardigrade/reload/status", .body = null, .headers = &.{} });
    defer status.deinit();
    try assertContains(status.body, "\"ok\":false");
}

test "invalid TLS buffer reload keeps previous config limits active (#355)" {
    const allocator = std.testing.allocator;
    const defaults = tls_core.encrypted_stream.BufferLimits.defaults();
    const custom_high = defaults.outbound_ciphertext.low + 1;

    const valid_config = try std.fmt.allocPrint(allocator,
        \\location /healthz {{
        \\    return 200 alive;
        \\}}
        \\tls_outbound_ciphertext_low_watermark_bytes {d};
        \\tls_outbound_ciphertext_high_watermark_bytes {d};
        \\tls_outbound_ciphertext_hard_limit_bytes {d};
    , .{
        defaults.outbound_ciphertext.low,
        custom_high,
        defaults.outbound_ciphertext.hard,
    });
    defer allocator.free(valid_config);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = valid_config,
        .ready_path = "/healthz",
    });
    defer tardigrade.stop();

    const active_high_line = try std.fmt.allocPrint(allocator, "tardigrade_tls_buffer_config_limit_bytes{{queue=\"outbound_ciphertext\",limit=\"high\"}} {d}\n", .{custom_high});
    defer allocator.free(active_high_line);
    const rejected_high_line = try std.fmt.allocPrint(allocator, "tardigrade_tls_buffer_config_limit_bytes{{queue=\"outbound_ciphertext\",limit=\"high\"}} {d}\n", .{defaults.outbound_ciphertext.low});
    defer allocator.free(rejected_high_line);
    const rejected_hard_line = try std.fmt.allocPrint(allocator, "tardigrade_tls_buffer_config_limit_bytes{{queue=\"outbound_ciphertext\",limit=\"hard\"}} {d}\n", .{std.math.maxInt(usize)});
    defer allocator.free(rejected_hard_line);

    var initial_metrics = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/status/metrics", .body = null, .headers = &.{} });
    defer initial_metrics.deinit();
    try std.testing.expectEqual(@as(u16, 200), initial_metrics.status_code);
    try assertContains(initial_metrics.body, active_high_line);

    const invalid_configs = [_][]const u8{
        \\location /healthz {
        \\    return 200 alive;
        \\}
        \\tls_outbound_ciphertext_high_watermark_bytes not-a-number;
        ,
        try std.fmt.allocPrint(allocator,
            \\location /healthz {{
            \\    return 200 alive;
            \\}}
            \\tls_outbound_ciphertext_low_watermark_bytes {d};
            \\tls_outbound_ciphertext_high_watermark_bytes {d};
            \\tls_outbound_ciphertext_hard_limit_bytes {d};
        , .{
            defaults.outbound_ciphertext.low,
            defaults.outbound_ciphertext.low,
            defaults.outbound_ciphertext.hard,
        }),
        try std.fmt.allocPrint(allocator,
            \\location /healthz {{
            \\    return 200 alive;
            \\}}
            \\tls_outbound_ciphertext_low_watermark_bytes 1;
            \\tls_outbound_ciphertext_high_watermark_bytes 2;
            \\tls_outbound_ciphertext_hard_limit_bytes {d};
        , .{std.math.maxInt(usize)}),
    };
    defer allocator.free(invalid_configs[1]);
    defer allocator.free(invalid_configs[2]);

    for (invalid_configs, 1..) |invalid_config, expected_failures| {
        try tardigrade.rewriteConfig(invalid_config);
        tardigrade.sendSignal(std.posix.SIG.HUP);
        try waitForMetricAtLeast(allocator, tardigrade.port, "tardigrade_reload_failure_total", expected_failures, 3_000);

        var status = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/tardigrade/reload/status", .body = null, .headers = &.{} });
        defer status.deinit();
        try assertContains(status.body, "\"ok\":false");

        var health = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/healthz", .body = null, .headers = &.{} });
        defer health.deinit();
        try std.testing.expectEqual(@as(u16, 200), health.status_code);
        try assertContains(health.body, "alive");

        var metrics = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/status/metrics", .body = null, .headers = &.{} });
        defer metrics.deinit();
        try assertContains(metrics.body, active_high_line);
        try std.testing.expect(std.mem.find(u8, metrics.body, rejected_high_line) == null);
        try std.testing.expect(std.mem.find(u8, metrics.body, rejected_hard_line) == null);
    }
}

test "hot reload does not warn about restart-only store paths when they are unchanged (#191)" {
    const allocator = std.testing.allocator;

    // Use a fixture dir for absolute paths; the store files do not need to exist.
    var fixture = try GenericFixtureDir.create(allocator, "reload-restart-only-paths");
    defer fixture.deinit();

    const session_path = try fixture.joinAbs("sessions.json");
    defer allocator.free(session_path);
    const approval_path = try fixture.joinAbs("approvals.json");
    defer allocator.free(approval_path);
    const transcript_path = try fixture.joinAbs("transcripts.ndjson");
    defer allocator.free(transcript_path);

    // Start with all four restart-only fields populated via environment.
    var tardigrade = try TardigradeProcess.start(allocator, .{
        .extra_env = &.{
            .{ .name = "TARDIGRADE_SESSION_STORE_PATH", .value = session_path },
            .{ .name = "TARDIGRADE_APPROVAL_STORE_PATH", .value = approval_path },
            .{ .name = "TARDIGRADE_TRANSCRIPT_STORE_PATH", .value = transcript_path },
            .{ .name = "TARDIGRADE_APPROVAL_ESCALATION_WEBHOOK", .value = "http://127.0.0.1:19999/hook" },
        },
    });
    defer tardigrade.stop();

    // Trigger a reload. Because env vars are fixed for a running process, the same
    // paths/URL are re-read at reload time — the comparison should see no change and
    // emit no "restart required" warnings.
    tardigrade.sendSignal(std.posix.SIG.HUP);
    try waitForLogSubstring(allocator, tardigrade.log_path, "configuration hot-reload applied", 3_000);

    const log_contents = try compat.cwd().readFileAlloc(allocator, tardigrade.log_path, 256 * 1024);
    defer allocator.free(log_contents);
    if (std.mem.indexOf(u8, log_contents, "restart required") != null) {
        std.debug.print("unexpected 'restart required' warning in log:\n{s}\n", .{log_contents});
        return error.SpuriousRestartRequiredWarning;
    }
}

test "static website with binary image assets loads correctly end-to-end and across reload (#170)" {
    const allocator = std.testing.allocator;
    var fixture = try GenericFixtureDir.create(allocator, "full-website");
    defer fixture.deinit();

    // A small but complete static site: markup, stylesheet, script, and binary
    // image assets (PNG + JPEG) plus a text SVG.
    try fixture.writeRel("public/index.html",
        \\<!doctype html><html><head><title>Tardigrade Site</title>
        \\<link rel="stylesheet" href="/style.css"></head>
        \\<body><img src="/img/logo.png"><img src="/img/photo.jpg">
        \\<img src="/img/icon.svg"><script src="/app.js"></script></body></html>
    );
    try fixture.writeRel("public/style.css", "body{background:#fff;color:#111}\n");
    try fixture.writeRel("public/app.js", "console.log('tardigrade');\n");
    try fixture.writeRel("public/img/icon.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>\n");

    // Binary PNG: 8-byte signature + deterministic payload.
    var png_bytes: [8 + 1024]u8 = undefined;
    @memcpy(png_bytes[0..8], &[_]u8{ 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A });
    for (png_bytes[8..], 0..) |*b, i| b.* = @intCast(i % 256);
    try fixture.writeRel("public/img/logo.png", &png_bytes);

    // Binary JPEG: SOI + payload + EOI markers.
    var jpg_bytes: [4 + 2048 + 2]u8 = undefined;
    @memcpy(jpg_bytes[0..4], &[_]u8{ 0xFF, 0xD8, 0xFF, 0xE0 });
    for (jpg_bytes[4 .. jpg_bytes.len - 2], 0..) |*b, i| b.* = @intCast((i * 3) % 256);
    jpg_bytes[jpg_bytes.len - 2] = 0xFF;
    jpg_bytes[jpg_bytes.len - 1] = 0xD9;
    try fixture.writeRel("public/img/photo.jpg", &jpg_bytes);

    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);
    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    const Asset = struct { path: []const u8, content_type: []const u8 };
    const text_assets = [_]Asset{
        .{ .path = "/index.html", .content_type = "text/html" },
        .{ .path = "/style.css", .content_type = "text/css" },
        .{ .path = "/app.js", .content_type = "application/javascript" },
        .{ .path = "/img/icon.svg", .content_type = "image/svg+xml" },
    };
    for (text_assets) |asset| {
        var resp = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = asset.path, .body = null, .headers = &.{} });
        defer resp.deinit();
        try std.testing.expectEqual(@as(u16, 200), resp.status_code);
        const ct = resp.header("Content-Type") orelse return error.MissingContentType;
        try assertContains(ct, asset.content_type);
        try std.testing.expect(resp.body.len > 0);
    }

    // Binary image assets must arrive byte-for-byte with the right content type.
    {
        var resp = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/img/logo.png", .body = null, .headers = &.{} });
        defer resp.deinit();
        try std.testing.expectEqual(@as(u16, 200), resp.status_code);
        const ct = resp.header("Content-Type") orelse return error.MissingContentType;
        try assertContains(ct, "image/png");
        try std.testing.expectEqual(png_bytes.len, resp.body.len);
        try std.testing.expect(std.mem.eql(u8, &png_bytes, resp.body));
    }
    {
        var resp = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/img/photo.jpg", .body = null, .headers = &.{} });
        defer resp.deinit();
        try std.testing.expectEqual(@as(u16, 200), resp.status_code);
        const ct = resp.header("Content-Type") orelse return error.MissingContentType;
        try assertContains(ct, "image/jpeg");
        try std.testing.expectEqual(jpg_bytes.len, resp.body.len);
        try std.testing.expect(std.mem.eql(u8, &jpg_bytes, resp.body));
    }

    // After a reload, the images still load intact.
    try tardigrade.rewriteConfig(config_text);
    tardigrade.sendSignal(std.posix.SIG.HUP);
    compat.sleepNs(300 * std.time.ns_per_ms);

    var png_after = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/img/logo.png", .body = null, .headers = &.{} });
    defer png_after.deinit();
    try std.testing.expectEqual(@as(u16, 200), png_after.status_code);
    try std.testing.expect(std.mem.eql(u8, &png_bytes, png_after.body));
}

// ---------------------------------------------------------------------------
// Keepalive worker starvation (#204).
// ---------------------------------------------------------------------------

test "idle keepalive connections parked off the worker pool do not starve active requests (#204)" {
    // Before the parking implementation, each idle keepalive connection held a
    // worker thread blocked in read(). With 2 workers and 4 idle clients only 2
    // new requests could be served at a time; the rest queued or failed. With
    // parking, idle connections sit in the event loop and workers are free for
    // active requests regardless of how many clients are parked.
    const allocator = std.testing.allocator;

    var fixture = try GenericFixtureDir.create(allocator, "keepalive-starvation");
    defer fixture.deinit();
    try fixture.writeRel("public/index.html", "ok\n");
    const public_abs = try fixture.joinAbs("public");
    defer allocator.free(public_abs);

    const config_text = try std.fmt.allocPrint(allocator,
        \\location / {{
        \\    root {s};
        \\    try_files $uri /index.html;
        \\}}
    , .{public_abs});
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            // 2 workers — deliberately fewer than the number of idle connections we'll open.
            .{ .name = "TARDIGRADE_WORKER_THREADS", .value = "2" },
            // Long keepalive so parked connections are never reaped during the test.
            .{ .name = "TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS", .value = "30000" },
        },
    });
    defer tardigrade.stop();

    // Open IDLE_COUNT keepalive connections and park them all.
    const IDLE_COUNT = 4; // > 2 workers
    var idle_streams: [IDLE_COUNT]compat.NetStream = undefined;
    var idle_open: usize = 0;
    defer {
        var i: usize = 0;
        while (i < idle_open) : (i += 1) idle_streams[i].close();
    }

    for (0..IDLE_COUNT) |i| {
        idle_streams[i] = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
        idle_open += 1;
        try setStreamTimeouts(&idle_streams[i], 5_000);
        // Send one request to establish the keepalive; the connection parks after
        // the response is written and the worker returns to the pool.
        try sendKeepAliveGet(&idle_streams[i], allocator, tardigrade.port, "/index.html");
        var resp = try readHttpResponse(allocator, idle_streams[i]);
        defer resp.deinit();
        try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    }

    // Allow time for all idle connections to complete their park transition
    // (the worker finishes writing the response, calls repark/event loop arm).
    compat.sleepNs(150 * std.time.ns_per_ms);

    // Fire ACTIVE_COUNT new requests from independent connections concurrently.
    // In the old blocking model the 2 workers would be held by the first 2 idle
    // connections; here all requests must complete successfully.
    const ACTIVE_COUNT = 4;
    const ActiveResult = struct { ok: bool = false };
    var results: [ACTIVE_COUNT]ActiveResult = [_]ActiveResult{.{}} ** ACTIVE_COUNT;
    const ActiveRunner = struct {
        fn run(ctx: *ActiveResult, port: u16) void {
            var resp = sendRequest(std.heap.page_allocator, port, .{
                .method = "GET",
                .path = "/index.html",
                .body = null,
                .headers = &.{},
            }) catch return;
            defer resp.deinit();
            ctx.ok = resp.status_code == 200;
        }
    };
    var threads: [ACTIVE_COUNT]std.Thread = undefined;
    for (0..ACTIVE_COUNT) |i| {
        threads[i] = try std.Thread.spawn(.{}, ActiveRunner.run, .{ &results[i], tardigrade.port });
    }
    for (0..ACTIVE_COUNT) |i| threads[i].join();

    for (results) |r| {
        try std.testing.expect(r.ok);
    }

    // Parked connections must still serve a follow-up request after the active
    // burst — confirms the parking/resume cycle is not corrupted by concurrency.
    for (0..IDLE_COUNT) |i| {
        try sendKeepAliveGet(&idle_streams[i], allocator, tardigrade.port, "/index.html");
        var resp = try readHttpResponse(allocator, idle_streams[i]);
        defer resp.deinit();
        try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    }
}

// ---------------------------------------------------------------------------
// Failure-mode / chaos harness (#169)
//
// These tests intentionally break origins and clients, then assert that the
// gateway fails safely: it returns a defined status (or closes the connection),
// keeps its single worker available for unrelated requests (no starvation),
// leaves no leaked client connections (bounded active-connection gauge), and
// emits the relevant observability signals.  They reuse the mock-origin and
// live-process harness above and share the `failure:` name prefix so they can
// be run in isolation via `zig build test-failure`.
// ---------------------------------------------------------------------------

/// Config fragment used by most failure tests: a dependency-free `/healthz`
/// route to probe worker liveness plus a `/proxy/` mount pointed at `upstream`.
fn failureProbeConfig(allocator: std.mem.Allocator, upstream_host: []const u8, upstream_port: u16) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ upstream_host, upstream_port });
}

/// Assert the gateway's single worker still serves an unrelated route promptly
/// (i.e. the failure did not wedge or starve it).
fn assertGatewayServesHealthz(allocator: std.mem.Allocator, port: u16) !void {
    var health = try sendRequestWithTimeout(allocator, port, .{
        .method = "GET",
        .path = "/healthz",
        .body = null,
        .headers = &.{},
    }, 5_000);
    defer health.deinit();
    try std.testing.expectEqual(@as(u16, 200), health.status_code);
    try assertContains(health.body, "alive");
}

/// Assert the metrics endpoint is scrapeable and that client connections have
/// drained back to a small bound — a large or growing gauge would indicate a
/// leaked socket or wedged worker.
fn assertGatewayNotLeaking(allocator: std.mem.Allocator, port: u16) !void {
    var metrics = try sendRequestWithTimeout(allocator, port, .{
        .method = "GET",
        .path = "/status/metrics",
        .body = null,
        .headers = &.{},
    }, 5_000);
    defer metrics.deinit();
    try std.testing.expectEqual(@as(u16, 200), metrics.status_code);
    const active = prometheusMetricValue(metrics.body, "tardigrade_active_connections") orelse
        return error.MissingActiveConnectionsMetric;
    // At most the in-flight metrics request plus a little slack; failures must
    // not accumulate half-open connections.
    try std.testing.expect(active <= 4);
}

/// Poll the metrics endpoint until `name` reaches at least `minimum`.
fn waitForMetricAtLeast(
    allocator: std.mem.Allocator,
    port: u16,
    name: []const u8,
    minimum: u64,
    timeout_ms: u64,
) !void {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        var metrics = sendRequestWithTimeout(allocator, port, .{
            .method = "GET",
            .path = "/status/metrics",
            .body = null,
            .headers = &.{},
        }, 5_000) catch {
            compat.sleepNs(25 * std.time.ns_per_ms);
            continue;
        };
        defer metrics.deinit();
        if (prometheusMetricValue(metrics.body, name)) |value| {
            if (value >= minimum) return;
        }
        compat.sleepNs(25 * std.time.ns_per_ms);
    }
    return error.MetricThresholdNotReached;
}

/// #519: like `waitForMetricAtLeast`, but for a *labeled* Prometheus metric
/// (`prometheusLabeledMetricValue`) and over the real native TLS listener
/// (`sendPureZigTlsHttp1Request`) rather than a plaintext port -- every
/// `rotation.persistent.*` SIGHUP case polls this instead of a fixed settle
/// sleep, so a slower-than-usual reload can't race a fixed-delay assertion
/// into a false pass or a false failure.
fn waitForLabeledMetricAtLeast(
    allocator: std.mem.Allocator,
    port: u16,
    name: []const u8,
    labels: []const []const u8,
    minimum: u64,
    timeout_ms: u64,
) !void {
    const deadline = compat.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (compat.milliTimestamp() < deadline) {
        var metrics = sendPureZigTlsHttp1Request(allocator, port, "/status/metrics") catch {
            compat.sleepNs(25 * std.time.ns_per_ms);
            continue;
        };
        defer metrics.deinit();
        if (prometheusLabeledMetricValue(metrics.body, name, labels)) |value| {
            if (value >= minimum) return;
        }
        compat.sleepNs(25 * std.time.ns_per_ms);
    }
    return error.MetricThresholdNotReached;
}

test "failure: origin down before connect returns 5xx and gateway stays healthy" {
    const allocator = std.testing.allocator;

    // Reserve a port and never listen on it so the upstream connect is refused.
    const dead_port = try findFreePort();

    const config_text = try failureProbeConfig(allocator, test_host, dead_port);
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS", .value = "500" },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequestWithTimeout(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/anything",
        .body = null,
        .headers = &.{},
    }, 5_000);
    defer response.deinit();
    // A dead origin must surface as a gateway error, never a hang or a 200.
    try std.testing.expect(response.status_code >= 502 and response.status_code <= 504);

    try assertGatewayServesHealthz(allocator, tardigrade.port);
    try assertGatewayNotLeaking(allocator, tardigrade.port);
}

test "failure: origin that accepts but never responds times out without wedging the worker" {
    const allocator = std.testing.allocator;

    // Origin accepts the connection but stalls far longer than the read budget.
    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "too-late", .delay_ms = 1_500 }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try failureProbeConfig(allocator, test_host, upstream.port());
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            // Bound the upstream read so a silent origin is force-timed-out. The
            // per-attempt socket timeout is derived from the connect timeout.
            .{ .name = "TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS", .value = "400" },
            .{ .name = "TARDIGRADE_UPSTREAM_TIMEOUT_MS", .value = "400" },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequestWithTimeout(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/stall",
        .body = null,
        .headers = &.{},
    }, 5_000);
    defer response.deinit();
    // A stalled origin must map to a bounded gateway error, not a client hang.
    try std.testing.expect(response.status_code == 502 or response.status_code == 504);

    try assertGatewayServesHealthz(allocator, tardigrade.port);
    try assertGatewayNotLeaking(allocator, tardigrade.port);
}

test "failure: origin closing mid-response yields 502 in buffered mode (#269)" {
    const allocator = std.testing.allocator;

    // Advertise a full Content-Length (10) but close after emitting a 4-byte
    // prefix. The buffered path must surface the premature close as a bad
    // gateway rather than forwarding a body shorter than the advertised length.
    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "abcdefghij",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
        .truncate_body_after = 4,
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try failureProbeConfig(allocator, test_host, upstream.port());
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    var response = try sendRequestWithTimeout(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/truncated",
        .body = null,
        .headers = &.{},
    }, 5_000);
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 502), response.status_code);

    try assertGatewayServesHealthz(allocator, tardigrade.port);
    try assertGatewayNotLeaking(allocator, tardigrade.port);
}

test "failure: origin sending malformed response headers fails as a bounded 5xx" {
    const allocator = std.testing.allocator;

    // Not a valid HTTP response: garbage where a status line belongs, framed
    // with a blank line so the gateway treats it as a complete (unparseable)
    // head rather than waiting for more data.
    var origin = try RawTcpServer.start(allocator, "GARBAGE not-http bytes\r\n\r\n");
    defer origin.stop();
    try origin.run();

    const config_text = try failureProbeConfig(allocator, test_host, origin.port());
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            // Bound the upstream read so a garbage response resolves to a
            // defined gateway error promptly instead of stalling the worker.
            .{ .name = "TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS", .value = "500" },
            .{ .name = "TARDIGRADE_UPSTREAM_TIMEOUT_MS", .value = "500" },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequestWithTimeout(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/garbage",
        .body = null,
        .headers = &.{},
    }, 5_000);
    defer response.deinit();
    // Garbage must never be passed through as a success; it resolves to a bad
    // gateway (502) or, when the read window elapses first, a gateway timeout
    // (504).
    try std.testing.expect(response.status_code == 502 or response.status_code == 504);

    try assertGatewayServesHealthz(allocator, tardigrade.port);
    try assertGatewayNotLeaking(allocator, tardigrade.port);
}

test "failure: client abort mid-upload does not wedge the worker" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{ .body = "{\"ok\":true}" }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try failureProbeConfig(allocator, test_host, upstream.port());
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            // Bound the client read so a stalled/aborted upload is timed out and
            // the single worker is released for the follow-up probe.
            .{ .name = "TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS", .value = "500" },
        },
    });
    defer tardigrade.stop();

    // Announce a large body, send only a fragment, then hang up mid-upload.
    {
        var abort_stream = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
        defer abort_stream.close();
        const partial = try std.fmt.allocPrint(
            allocator,
            "POST /proxy/upload HTTP/1.1\r\nHost: {s}:{d}\r\nContent-Length: 100000\r\nConnection: close\r\n\r\npartial-body-only",
            .{ test_host, tardigrade.port },
        );
        defer allocator.free(partial);
        try abort_stream.writeAll(partial);
        // Scope exit drops the connection without sending the promised bytes.
    }

    // The single worker must remain able to serve unrelated requests.
    try assertGatewayServesHealthz(allocator, tardigrade.port);
    try assertGatewayNotLeaking(allocator, tardigrade.port);
}

test "failure: client abort mid-download is cleaned up and recorded" {
    const allocator = std.testing.allocator;

    // A response far larger than any socket buffer so the gateway is still
    // writing when the client disappears, guaranteeing an observed abort.
    const big_len = 4 * 1024 * 1024;
    const payload = try allocator.alloc(u8, big_len);
    defer allocator.free(payload);
    @memset(payload, 'z');

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = payload,
        .headers = &.{.{ .name = "Content-Type", .value = "application/octet-stream" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try failureProbeConfig(allocator, test_host, upstream.port());
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_STREAMING_MODE", .value = "response" },
            .{ .name = "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", .value = "4096" },
            .{ .name = "TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES", .value = "65536" },
        },
    });
    defer tardigrade.stop();

    // Open a proxied download, read only a small prefix, then abandon it.
    {
        var stream = try openRequestStream(allocator, tardigrade.port, .{
            .method = "GET",
            .path = "/proxy/large.bin",
            .body = null,
            .headers = &.{},
        });
        defer stream.close();
        try setStreamTimeouts(&stream, 5_000);
        var sink: [1024]u8 = undefined;
        _ = try stream.read(&sink);
        // Scope exit closes the socket mid-stream without draining the body.
    }

    // The downstream abort must be observed and the worker must recover.
    try waitForMetricAtLeast(allocator, tardigrade.port, "tardigrade_proxy_client_aborts_total", 1, 5_000);
    try assertGatewayServesHealthz(allocator, tardigrade.port);
    try assertGatewayNotLeaking(allocator, tardigrade.port);
}

test "failure: unreachable access log sink does not fail requests" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    // Point the access-log syslog sink at a closed UDP endpoint; log emission
    // must never block or fail the request path.
    const dead_sink_port = try findFreePort();
    const sink = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ test_host, dead_sink_port });
    defer allocator.free(sink);

    const config_text = try failureProbeConfig(allocator, test_host, upstream.port());
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_ACCESS_LOG_SYSLOG_UDP", .value = sink },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequestWithTimeout(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/proxy/logged",
        .body = null,
        .headers = &.{},
    }, 5_000);
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "\"ok\":true");

    try assertGatewayNotLeaking(allocator, tardigrade.port);
}

test "failure: metrics endpoint stays responsive under concurrent proxy load" {
    const allocator = std.testing.allocator;

    var upstream = try UpstreamServer.start(allocator, &.{.{
        .body = "{\"ok\":true}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.stop();
    try upstream.run();

    const config_text = try failureProbeConfig(allocator, test_host, upstream.port());
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{ .config_text = config_text });
    defer tardigrade.stop();

    const WORKERS = 6;
    var stop_flag = std.atomic.Value(bool).init(false);
    const LoadContext = struct {
        port: u16,
        stop: *std.atomic.Value(bool),
    };
    const LoadRunner = struct {
        fn run(ctx: LoadContext) void {
            while (!ctx.stop.load(.seq_cst)) {
                var r = sendRequest(std.heap.page_allocator, ctx.port, .{
                    .method = "GET",
                    .path = "/proxy/ping",
                    .body = null,
                    .headers = &.{},
                }) catch continue;
                r.deinit();
            }
        }
    };

    var threads: [WORKERS]std.Thread = undefined;
    for (0..WORKERS) |i| {
        threads[i] = try std.Thread.spawn(.{}, LoadRunner.run, .{LoadContext{ .port = tardigrade.port, .stop = &stop_flag }});
    }
    defer {
        stop_flag.store(true, .seq_cst);
        for (0..WORKERS) |i| threads[i].join();
    }

    // Every scrape performed while proxy traffic is in flight must succeed and
    // expose well-formed counters.
    var scrape: usize = 0;
    while (scrape < 8) : (scrape += 1) {
        var metrics = try sendRequestWithTimeout(allocator, tardigrade.port, .{
            .method = "GET",
            .path = "/status/metrics",
            .body = null,
            .headers = &.{},
        }, 5_000);
        defer metrics.deinit();
        try std.testing.expectEqual(@as(u16, 200), metrics.status_code);
        try std.testing.expect(prometheusMetricValue(metrics.body, "tardigrade_requests_total") != null);
        try std.testing.expect(prometheusMetricValue(metrics.body, "tardigrade_active_connections") != null);
    }
}

test "native TLS listener dispatches ALPN http/1.1 through keepalive requests" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "native-h1-first", .connection_header = "keep-alive" },
        .{ .body = "native-h1-second", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    const client = try PureZigTlsClient.create(allocator, tardigrade.port, "http/1.1");
    defer client.destroy();
    try client.writeAllPlain("GET /proxy/one HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n");

    const first_raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(first_raw);
    try waitForUpstreamCount(&upstream, 1, 2_000);
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(first_raw, "HTTP/1.1 200 OK"));
    try assertContains(first_raw, "native-h1-first");

    try client.writeAllPlain("GET /proxy/two HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");

    const second_raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(second_raw);

    try waitForUpstreamCount(&upstream, 2, 5_000);
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(second_raw, "HTTP/1.1 200 OK"));
    try assertContains(second_raw, "native-h1-second");
}

test "native TLS listener dispatches ALPN h2 through HTTP/2 frames" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_HTTP1_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "true" },
        },
    });
    defer tardigrade.stop();

    const client = try PureZigTlsClient.create(allocator, tardigrade.port, "h2");
    defer client.destroy();

    try client.writeAllPlain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    try client.writeHttp2Frame(0x4, 0, 0, &.{}); // client SETTINGS

    const request_headers = [_]hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/h2-listener" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "127.0.0.1" },
    };
    const request_block = try hpack.encodeLiteralHeaderBlock(allocator, request_headers[0..]);
    defer allocator.free(request_block);
    try client.writeHttp2Frame(0x1, 0x1 | 0x4, 1, request_block); // END_STREAM | END_HEADERS

    var saw_settings = false;
    var saw_response_headers = false;
    var response_body = std.array_list.Managed(u8).init(allocator);
    defer response_body.deinit();

    var frame_count: usize = 0;
    while (frame_count < 8) : (frame_count += 1) {
        var frame = try client.readHttp2Frame(allocator, 16 * 1024, 5_000);
        defer frame.deinit(allocator);

        switch (frame.typ) {
            0x4 => {
                if ((frame.flags & 0x1) == 0) {
                    saw_settings = true;
                    try client.writeHttp2Frame(0x4, 0x1, 0, &.{}); // SETTINGS ACK
                }
            },
            0x1 => {
                if (frame.stream_id == 1) saw_response_headers = true;
            },
            0x0 => {
                if (frame.stream_id == 1) {
                    try response_body.appendSlice(frame.payload);
                    if ((frame.flags & 0x1) != 0) break;
                }
            },
            else => {},
        }
    }

    try std.testing.expect(saw_settings);
    try std.testing.expect(saw_response_headers);
    try assertContains(response_body.items, "\"error\":\"not_found\"");
}

test "native TLS listener rejects unsupported ALPN before HTTP dispatch" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "negative-control", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    try PureZigTlsClient.expectHandshakeFailure(allocator, tardigrade.port, "tardigrade-test");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());

    var control = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/proxy/control");
    defer control.deinit();
    try std.testing.expectEqual(@as(u16, 200), control.status_code);
    try assertContains(control.body, "negative-control");
    try waitForUpstreamCount(&upstream, 1, 2_000);
}

test "failure: malformed and stalled TLS handshakes are rejected without wedging the listener (#270)" {
    const allocator = std.testing.allocator;

    // Absolute paths to the shared TLS fixture; presence of both cert and key is
    // what enables TLS termination on the listener (edge_config.hasTlsFiles).
    var tls_paths = try listenerTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        // Probe readiness over TLS (curl -k), matching the enabled terminator.
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            // Bound a stalled handshake tightly so the (single, harness-default)
            // worker cannot be pinned by a peer that never finishes the
            // handshake.
            .{ .name = "TARDIGRADE_TLS_HANDSHAKE_TIMEOUT_MS", .value = "500" },
        },
    });
    defer tardigrade.stop();

    // Fire a burst of broken handshakes at the TLS port: raw non-TLS garbage and
    // a truncated TLS record header, each closed immediately so SSL_accept fails
    // on EOF. None of these must crash or wedge the listener.
    const broken_payloads = [_][]const u8{
        "this is definitely not a tls client hello\r\n\r\n",
        // TLS handshake record (type 0x16, TLS 1.0 version) advertising a length
        // far larger than the handful of bytes actually sent.
        "\x16\x03\x01\x02\x00\x01\x00\x01\xfc",
        // Bare record header, nothing else.
        "\x16\x03\x01",
    };
    for (broken_payloads) |payload| {
        var attempt: usize = 0;
        while (attempt < 3) : (attempt += 1) {
            var s = compat.tcpConnectToHost(allocator, test_host, tardigrade.port) catch continue;
            s.writeAll(payload) catch {};
            s.close();
        }
    }

    // A partial ClientHello held open for the rest of the test. With a single
    // worker, an unbounded handshake here would pin it and hang the valid
    // request below — so the control request succeeding *is* the assertion that
    // the stalled handshake is bounded by TARDIGRADE_TLS_HANDSHAKE_TIMEOUT_MS.
    var stalled = try compat.tcpConnectToHost(allocator, test_host, tardigrade.port);
    defer stalled.close();
    try stalled.writeAll("\x16\x03\x01\x00\x50\x01\x00\x00\x4c\x03\x03");

    // The listener still terminates a valid TLS request end-to-end.
    var response = if (build_options.tls_openssl_adapter)
        try sendCurlRequest(allocator, tardigrade.port, .{
            .scheme = "https",
            .path = "/healthz",
            .insecure = true,
        })
    else
        try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/healthz");
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "alive");

    // The failure is observable: broken handshakes are logged.
    try waitForLogSubstring(
        allocator,
        tardigrade.log_path,
        if (build_options.tls_openssl_adapter) "tls handshake error" else "native tls handshake failed",
        3_000,
    );

    // And no half-open handshakes leaked — active connections stay bounded.
    var metrics = if (build_options.tls_openssl_adapter)
        try sendCurlRequest(allocator, tardigrade.port, .{
            .scheme = "https",
            .path = "/status/metrics",
            .insecure = true,
        })
    else
        try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try std.testing.expectEqual(@as(u16, 200), metrics.status_code);
    const active = prometheusMetricValue(metrics.body, "tardigrade_active_connections") orelse
        return error.MissingActiveConnectionsMetric;
    try std.testing.expect(active <= 4);
}

// ---------------------------------------------------------------------------
// Appliance TLS profile (#392): the strict Ed25519 provisioned identity
// through the production native listener.
// ---------------------------------------------------------------------------

fn applianceFixturePath(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const cwd = try compat.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    return std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/{s}", .{ cwd, name });
}

/// Spawn tardigrade with the given TLS env and expect startup to fail before
/// the listener ever accepts a connection, with `expected_log` in the error
/// log. Used for credential preflight failures (mismatched or malformed key).
fn expectApplianceStartupFailure(
    allocator: std.mem.Allocator,
    key_fixture: []const u8,
    expected_log: []const u8,
) !void {
    const cert_path = try applianceFixturePath(allocator, "native_ed25519.crt");
    defer allocator.free(cert_path);
    const key_path = try applianceFixturePath(allocator, key_fixture);
    defer allocator.free(key_path);

    const port = try findFreePort();
    const cwd = try compat.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    const log_path = try std.fmt.allocPrint(allocator, "{s}/.zig-cache/tardigrade-appliance-fail-{d}.log", .{ cwd, port });
    defer allocator.free(log_path);
    const config_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tardigrade-appliance-fail-{d}.conf", .{port});
    defer {
        compat.cwd().deleteFile(config_rel) catch {};
        allocator.free(config_rel);
    }
    try compat.cwd().writeFile(.{ .sub_path = config_rel, .data = "" });

    const port_str = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(port_str);

    var env_map = try inheritedEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("TARDIGRADE_CONFIG_PATH", config_rel);
    try env_map.put("TARDIGRADE_LISTEN_HOST", test_host);
    try env_map.put("TARDIGRADE_LISTEN_PORT", port_str);
    try env_map.put("TARDIGRADE_ERROR_LOG_PATH", log_path);
    try env_map.put("TARDIGRADE_WORKER_THREADS", "1");
    try env_map.put("TARDIGRADE_TLS_CERT_PATH", cert_path);
    try env_map.put("TARDIGRADE_TLS_KEY_PATH", key_path);
    try env_map.put("TARDIGRADE_TLS_SERVER_NAME", "tardigrade.test");

    var argv = [_][]const u8{integration_options.tardigrade_bin_path};
    const early_stderr: ?std.Io.File = std.Io.Dir.createFileAbsolute(compat.io(), log_path, .{ .truncate = true }) catch null;
    var child = try std.process.spawn(compat.io(), .{
        .argv = &argv,
        .environ_map = &env_map,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = if (early_stderr) |f| .{ .file = f } else .ignore,
    });
    if (early_stderr) |f| f.close(compat.io());

    const term = try child.wait(compat.io());
    switch (term) {
        .exited => |code| try std.testing.expect(code != 0),
        else => {},
    }
    try waitForLogSubstring(allocator, log_path, expected_log, 3_000);

    // The listener never came up: connecting must fail.
    if (compat.tcpConnectToHost(allocator, test_host, port)) |conn| {
        var open_stream = conn;
        open_stream.close();
        return error.TestUnexpectedResult;
    } else |_| {}
}

test "native TLS listener appliance identity serves the exact configured SNI" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
        },
    });
    defer tardigrade.stop();

    const client = try PureZigTlsClient.createWithServerName(allocator, tardigrade.port, "http/1.1", "tardigrade.test");
    defer client.destroy();
    try client.writeAllPlain("GET /healthz HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    const raw = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(raw);
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(raw, "HTTP/1.1 200 OK"));
    try assertContains(raw, "alive");
}

test "#488: native TLS listener resumes and serves HTTP traffic with production metrics" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
            .{ .name = "TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE", .value = "stateful" },
        },
    });
    defer tardigrade.stop();

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_runtime = try tls_core.resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 2_000;
            }
        }.now },
        client_provider.cryptoProvider(),
    );
    defer client_runtime.deinit();

    const TicketCapture = struct {
        allocator: std.mem.Allocator,
        runtime: *tls_core.resumption_runtime.Runtime,
        retained: tls_core.session.ClientTicketState = .{},
        stored: tls_core.session_cache.StoreResult = undefined,
        count: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 2_000;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.retained.deinit();
            self.retained = .{};
            ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
            self.stored = self.runtime.storeClientTicket(ticket);
            self.count += 1;
        }
    };
    var capture = TicketCapture{ .allocator = allocator, .runtime = &client_runtime };
    defer capture.retained.deinit();

    const first_client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
        .ticket_consumer = .{
            .ctx = &capture,
            .nowUnixMsFn = TicketCapture.now,
            .onTicketFn = TicketCapture.onTicket,
        },
    });
    defer first_client.destroy();
    try first_client.writeAllPlain("GET /healthz HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    const first_raw = try first_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(first_raw);
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(first_raw, "HTTP/1.1 200 OK"));
    try assertContains(first_raw, "alive");
    try std.testing.expect(capture.count > 0);
    try std.testing.expectEqual(tls_core.session_cache.StoreResult.stored, capture.stored);

    const candidate: tls_core.session.CandidateContext = .{
        .cipher_suite = capture.retained.common.cipher_suite,
        .server_name = if (capture.retained.common.server_name) |*s| s.slice() else null,
        .application_protocol = if (capture.retained.common.application_protocol) |*a| a.slice() else null,
        .auth_binding = capture.retained.common.auth_binding,
        .transport_compat = null,
        .application_compat = null,
    };
    var lookup = client_runtime.lookupClientOffers(candidate);
    defer lookup.deinit();
    try std.testing.expect(lookup == .hit);
    try std.testing.expectEqual(@as(usize, 1), lookup.hit.offers.len);

    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2_500;
        }
    };
    const resumed_client = try PureZigTlsClient.createWithOptions(allocator, tardigrade.port, "http/1.1", "tardigrade.test", .{
        .psk_lease = &lookup.hit,
        .psk_now_ctx = &clock_dummy,
        .psk_now_fn = ClientClock.now,
    });
    defer resumed_client.destroy();
    try std.testing.expect(resumed_client.backend.core.psk_authenticated);
    try resumed_client.writeAllPlain("GET /healthz HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    const resumed_raw = try resumed_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(resumed_raw);
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(resumed_raw, "HTTP/1.1 200 OK"));
    try assertContains(resumed_raw, "alive");

    var metrics = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/status/metrics");
    defer metrics.deinit();
    try std.testing.expectEqual(@as(u16, 200), metrics.status_code);
    try std.testing.expect((prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_ticket_issue_total", &.{
        "transport=\"record\"",
        "mode=\"stateful\"",
        "result=\"success\"",
    }) orelse 0) >= 1);
    try std.testing.expect((prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_ticket_resolve_total", &.{
        "mode=\"stateful\"",
        "result=\"success\"",
    }) orelse 0) >= 1);
    try std.testing.expect((prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_attempt_total", &.{
        "transport=\"record\"",
    }) orelse 0) >= 1);
    try std.testing.expect((prometheusLabeledMetricValue(metrics.body, "tardigrade_tls_resumption_outcome_total", &.{
        "transport=\"record\"",
        "outcome=\"accepted\"",
    }) orelse 0) >= 1);
}

test "native TLS listener appliance rejects unknown SNI before HTTP dispatch" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    var upstream = try UpstreamServer.start(allocator, &.{
        .{ .body = "sni-negative-control", .connection_header = "close" },
    });
    defer upstream.stop();
    try upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\
        \\location /proxy/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = config_text,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = tls_paths.cert_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = tls_paths.key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
            .{ .name = "TARDIGRADE_HTTP2_ENABLED", .value = "false" },
        },
    });
    defer tardigrade.stop();
    try upstream.resetCapture();

    // An unknown non-empty SNI fails the handshake; no HTTP parser or
    // upstream request is ever reached.
    try PureZigTlsClient.expectHandshakeFailureWithServerName(allocator, tardigrade.port, "http/1.1", "unknown.example.test");
    compat.sleepNs(200 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), upstream.requestCount());

    // Control: absent SNI selects the one default identity.
    var control = try sendPureZigTlsHttp1Request(allocator, tardigrade.port, "/proxy/control");
    defer control.deinit();
    try std.testing.expectEqual(@as(u16, 200), control.status_code);
    try assertContains(control.body, "sni-negative-control");
    try waitForUpstreamCount(&upstream, 1, 2_000);
}

test "native TLS listener appliance refuses startup with a mismatched key" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try expectApplianceStartupFailure(allocator, "native_ed25519_mismatch.key", "error.KeyCertificateMismatch");
}

test "native TLS listener appliance refuses startup with an unsupported key algorithm" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;
    try expectApplianceStartupFailure(allocator, "native_p256.key", "error.UnsupportedPrivateKeyAlgorithm");
}

test "appliance run --daemon rejects a mismatched key synchronously, without ever backgrounding" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    const cert_path = try applianceFixturePath(allocator, "native_ed25519.crt");
    defer allocator.free(cert_path);
    const key_path = try applianceFixturePath(allocator, "native_ed25519_mismatch.key");
    defer allocator.free(key_path);

    const port = try findFreePort();
    const config_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tardigrade-appliance-daemon-fail-{d}.conf", .{port});
    defer {
        compat.cwd().deleteFile(config_rel) catch {};
        allocator.free(config_rel);
    }
    try compat.cwd().writeFile(.{ .sub_path = config_rel, .data = "" });
    const port_str = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(port_str);

    var env_map = try inheritedEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("TARDIGRADE_CONFIG_PATH", config_rel);
    try env_map.put("TARDIGRADE_LISTEN_HOST", test_host);
    try env_map.put("TARDIGRADE_LISTEN_PORT", port_str);
    try env_map.put("TARDIGRADE_WORKER_THREADS", "1");
    try env_map.put("TARDIGRADE_TLS_CERT_PATH", cert_path);
    try env_map.put("TARDIGRADE_TLS_KEY_PATH", key_path);
    try env_map.put("TARDIGRADE_TLS_SERVER_NAME", "tardigrade.test");

    // `--daemon` without `--daemonized` is the foreground invocation that
    // decides whether to fork a background process; run it directly (not
    // detached) so the test observes exactly what the invoking shell would.
    const run_res = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "run", "-c", config_rel, "--daemon" },
        .environ_map = &env_map,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(run_res.stdout);
    defer allocator.free(run_res.stderr);

    try std.testing.expectEqual(std.process.Child.Term{ .exited = 2 }, run_res.term);
    try assertContains(run_res.stderr, "KeyCertificateMismatch");
    // No "started ... in background" success message — the parent never
    // reached the fork.
    try std.testing.expect(std.mem.indexOf(u8, run_res.stdout, "started tardigrade in background") == null);

    // Give a wrongly-spawned background process a moment to bind, then
    // confirm nothing is listening.
    compat.sleepNs(300 * std.time.ns_per_ms);
    if (compat.tcpConnectToHost(allocator, test_host, port)) |conn| {
        var open_stream = conn;
        open_stream.close();
        return error.TestUnexpectedResult;
    } else |_| {}
}

test "appliance master mode rejects a mismatched key before writing a PID file or spawning workers" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    const cert_path = try applianceFixturePath(allocator, "native_ed25519.crt");
    defer allocator.free(cert_path);
    const key_path = try applianceFixturePath(allocator, "native_ed25519_mismatch.key");
    defer allocator.free(key_path);

    const port = try findFreePort();
    const cwd = try compat.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    const pid_path = try std.fmt.allocPrint(allocator, "{s}/.zig-cache/tardigrade-appliance-master-fail-{d}.pid", .{ cwd, port });
    defer allocator.free(pid_path);
    defer compat.cwd().deleteFile(pid_path) catch {};
    const config_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tardigrade-appliance-master-fail-{d}.conf", .{port});
    defer {
        compat.cwd().deleteFile(config_rel) catch {};
        allocator.free(config_rel);
    }
    try compat.cwd().writeFile(.{ .sub_path = config_rel, .data = "" });
    const port_str = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(port_str);

    var env_map = try inheritedEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("TARDIGRADE_CONFIG_PATH", config_rel);
    try env_map.put("TARDIGRADE_LISTEN_HOST", test_host);
    try env_map.put("TARDIGRADE_LISTEN_PORT", port_str);
    try env_map.put("TARDIGRADE_WORKER_THREADS", "1");
    try env_map.put("TARDIGRADE_TLS_CERT_PATH", cert_path);
    try env_map.put("TARDIGRADE_TLS_KEY_PATH", key_path);
    try env_map.put("TARDIGRADE_TLS_SERVER_NAME", "tardigrade.test");
    try env_map.put("TARDIGRADE_MASTER_PROCESS_ENABLED", "true");
    try env_map.put("TARDIGRADE_PID_FILE", pid_path);

    const run_res = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "run", "-c", config_rel },
        .environ_map = &env_map,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(run_res.stdout);
    defer allocator.free(run_res.stderr);

    try std.testing.expectEqual(std.process.Child.Term{ .exited = 2 }, run_res.term);
    try assertContains(run_res.stderr, "KeyCertificateMismatch");

    // The master process never got far enough to write a PID file, spawn a
    // worker, or bind the listener it would otherwise respawn workers for.
    try std.testing.expectError(error.FileNotFound, compat.cwd().statFile(pid_path));
    if (compat.tcpConnectToHost(allocator, test_host, port)) |conn| {
        var open_stream = conn;
        open_stream.close();
        return error.TestUnexpectedResult;
    } else |_| {}
}

test "native TLS listener appliance check command validates credentials without binding" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    const cert_path = try applianceFixturePath(allocator, "native_ed25519.crt");
    defer allocator.free(cert_path);
    const key_path = try applianceFixturePath(allocator, "native_ed25519.key");
    defer allocator.free(key_path);
    const mismatch_key_path = try applianceFixturePath(allocator, "native_ed25519_mismatch.key");
    defer allocator.free(mismatch_key_path);

    const config_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tardigrade-appliance-check-{d}.conf", .{compat.nanoTimestamp()});
    defer {
        compat.cwd().deleteFile(config_rel) catch {};
        allocator.free(config_rel);
    }
    try compat.cwd().writeFile(.{ .sub_path = config_rel, .data = "" });

    // Occupy the configured listen port ourselves: a passing check proves the
    // command never binds a listener socket.
    const port = try findFreePort();
    const address = try std.Io.net.IpAddress.parse(test_host, port);
    var occupied = try address.listen(compat.io(), .{ .reuse_address = false });
    defer occupied.deinit(compat.io());
    const port_str = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(port_str);

    var env_map = try inheritedEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("TARDIGRADE_LISTEN_HOST", test_host);
    try env_map.put("TARDIGRADE_LISTEN_PORT", port_str);
    try env_map.put("TARDIGRADE_TLS_CERT_PATH", cert_path);
    try env_map.put("TARDIGRADE_TLS_KEY_PATH", key_path);
    try env_map.put("TARDIGRADE_TLS_SERVER_NAME", "tardigrade.test");

    const valid = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "check", config_rel },
        .environ_map = &env_map,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(valid.stdout);
    defer allocator.free(valid.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, valid.term);
    try assertContains(valid.stdout, "configuration valid");

    // Mismatched key: deterministic configuration-invalid failure.
    try env_map.put("TARDIGRADE_TLS_KEY_PATH", mismatch_key_path);
    const mismatched = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "check", config_rel },
        .environ_map = &env_map,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(mismatched.stdout);
    defer allocator.free(mismatched.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 2 }, mismatched.term);
    try assertContains(mismatched.stderr, "KeyCertificateMismatch");

    // Missing server name: rejected by the appliance configuration policy.
    try env_map.put("TARDIGRADE_TLS_KEY_PATH", key_path);
    _ = env_map.swapRemove("TARDIGRADE_TLS_SERVER_NAME");
    const unnamed = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "check", config_rel },
        .environ_map = &env_map,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(unnamed.stdout);
    defer allocator.free(unnamed.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 2 }, unnamed.term);
}

test "appliance hot reload rejects turning TLS on for a server that started plaintext" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        // No TLS env at all: the process starts in plaintext, so
        // `worker_ctx.native_tls_provider`/`ApplianceCredentials` are never
        // constructed. `TardigradeProcess.start`'s auto-injected
        // TARDIGRADE_TLS_SERVER_NAME only fires when a TLS cert path is
        // also present in the environment, so it stays unset here too.
    });
    defer tardigrade.stop();

    var before = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/healthz",
        .body = null,
        .headers = &.{},
    });
    defer before.deinit();
    try std.testing.expectEqual(@as(u16, 200), before.status_code);
    try assertContains(before.body, "alive");

    // Rewrite the config file to turn TLS on with a fully valid appliance
    // identity, then reload. The reload must be rejected (there is no
    // `ApplianceCredentials` owner to construct or graft onto a running
    // WorkerContext at runtime) rather than publishing a TLS-marked config
    // while new connections silently continue over plaintext.
    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();
    const updated_config = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\tls_cert_path {s};
        \\tls_key_path {s};
        \\tls_server_name tardigrade.test;
    , .{ tls_paths.cert_path, tls_paths.key_path });
    defer allocator.free(updated_config);
    try tardigrade.rewriteConfig(updated_config);
    tardigrade.sendSignal(std.posix.SIG.HUP);

    try waitForLogSubstring(
        allocator,
        tardigrade.log_path,
        "config reload rejected: appliance TLS credential configuration",
        3_000,
    );

    // New connections still succeed over plain HTTP: the reload never
    // took effect, so the listener's behavior is unchanged.
    var after = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/healthz",
        .body = null,
        .headers = &.{},
    });
    defer after.deinit();
    try std.testing.expectEqual(@as(u16, 200), after.status_code);
    try assertContains(after.body, "alive");
}

test "appliance hot reload rejects turning TLS off for a server that started with TLS" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    var tls_paths = try nativeTlsFixturePaths(allocator);
    defer tls_paths.deinit();

    // The TLS identity is configured entirely through config-file directives
    // (no TARDIGRADE_TLS_* in the process environment): a live process's
    // environment cannot be changed by editing the config file, so an
    // env-seeded identity would make a reload that edits the file a no-op
    // rather than a genuine test of the rejection path. With no competing
    // env var, `edge_config.loadFromEnv` reads the file override both at
    // startup and at reload, so removing the directive is a real change.
    const initial_config = try std.fmt.allocPrint(allocator,
        \\location = /healthz {{
        \\    return 200 alive;
        \\}}
        \\tls_cert_path {s};
        \\tls_key_path {s};
        \\tls_server_name tardigrade.test;
    , .{ tls_paths.cert_path, tls_paths.key_path });
    defer allocator.free(initial_config);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text = initial_config,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
    });
    defer tardigrade.stop();

    const client = try PureZigTlsClient.createWithServerName(allocator, tardigrade.port, "http/1.1", "tardigrade.test");
    defer client.destroy();
    try client.writeAllPlain("GET /healthz HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    const before = try client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(before);
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(before, "HTTP/1.1 200 OK"));
    try assertContains(before, "alive");

    // Rewrite the config file dropping every TLS directive, then reload.
    // This must be rejected — the running provider and identity stay active.
    const updated_config =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
    ;
    try tardigrade.rewriteConfig(updated_config);
    tardigrade.sendSignal(std.posix.SIG.HUP);

    try waitForLogSubstring(
        allocator,
        tardigrade.log_path,
        "config reload rejected: appliance TLS credential configuration",
        3_000,
    );

    // The TLS listener is still there and still authenticates with the
    // original identity.
    const second_client = try PureZigTlsClient.createWithServerName(allocator, tardigrade.port, "http/1.1", "tardigrade.test");
    defer second_client.destroy();
    try second_client.writeAllPlain("GET /healthz HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n");
    const after = try second_client.readPlainToEnd(allocator, 64 * 1024, 5_000);
    defer allocator.free(after);
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(after, "HTTP/1.1 200 OK"));
    try assertContains(after, "alive");
}

test "an independent client trusting only the root validates the transmitted leaf+intermediate chain and hostname" {
    try requireNativeTlsProfile();
    const allocator = std.testing.allocator;

    // `openssl s_client` runs as a separate process from the appliance
    // binary (which links no OpenSSL/libcrypto): this is exactly the
    // "out-of-process client" proof that the transmitted leaf+intermediate
    // chain is actually walkable to a trusted root, not merely two
    // independently well-formed certificates (#392 review). It is given
    // only the root CA as a trust anchor — not the server's own chain.
    const ca_path = try applianceFixturePath(allocator, "native_ed25519_ca.crt");
    defer allocator.free(ca_path);
    const chain_path = try applianceFixturePath(allocator, "native_ed25519_chain.crt");
    defer allocator.free(chain_path);
    const key_path = try applianceFixturePath(allocator, "native_ed25519.key");
    defer allocator.free(key_path);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .config_text =
        \\location = /healthz {
        \\    return 200 alive;
        \\}
        ,
        .ready_https_insecure = true,
        .ready_path = "/healthz",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = chain_path },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = key_path },
            .{ .name = "TARDIGRADE_TLS_SERVER_NAME", .value = "tardigrade.test" },
        },
    });
    defer tardigrade.stop();

    const port_str = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{tardigrade.port});
    defer allocator.free(port_str);
    const run_res = std.process.run(allocator, compat.io(), .{
        .argv = &.{
            "openssl",         "s_client",
            "-connect",        port_str,
            "-tls1_3",         "-alpn",
            "http/1.1",        "-CAfile",
            ca_path,           "-verify_hostname",
            "tardigrade.test", "-verify_return_error",
            "-brief",
        },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch |err| {
        // `openssl` may be unavailable on some CI runners; the appliance
        // credential loader itself is still covered by the pure-Zig client
        // tests above. Do not fail the suite over a missing test tool.
        if (err == error.FileNotFound) return error.SkipZigTest;
        return err;
    };
    defer allocator.free(run_res.stdout);
    defer allocator.free(run_res.stderr);

    // The client closes without sending a request (empty stdin), so the
    // process may exit nonzero on the abrupt shutdown after a successful
    // handshake — the trust/hostname verdict is what this test proves.
    // `openssl s_client -brief` writes the session summary to stderr.
    try assertContains(run_res.stderr, "Verification: OK");
    try assertContains(run_res.stderr, "Verified peername: tardigrade.test");
}

test "a post-validation runtime failure is not misreported as a configuration error" {
    // `AccessDenied`/`FileNotFound` are both legitimate configuration-error
    // classes (a config-referenced path that doesn't exist or isn't
    // readable) *and* plausible runtime failures unrelated to config at all
    // (here: the PID file's directory not being writable). `run`'s error
    // classification is phase-based, not name-based: once
    // `edge_config.validate` and the appliance credential preflight have
    // already succeeded, a later failure of the same error name must report
    // as a runtime failure (exit 1), never "configuration validation
    // failed" (exit 2). This is independent of the appliance profile, so it
    // is not gated by requireNativeTlsProfile.
    const allocator = std.testing.allocator;

    const cwd = try compat.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    const readonly_dir = try std.fmt.allocPrintSentinel(allocator, "{s}/.zig-cache/tardigrade-readonly-pid-{d}", .{ cwd, compat.nanoTimestamp() }, 0);
    defer allocator.free(readonly_dir);
    try compat.cwd().makePath(readonly_dir);
    // The directory must exist (so PID-file creation gets past
    // ensureParentPath's auto-create step) but not be writable.
    try std.testing.expectEqual(@as(c_int, 0), std.c.chmod(readonly_dir.ptr, 0o555));
    defer {
        _ = std.c.chmod(readonly_dir.ptr, 0o755);
        compat.cwd().deleteTree(readonly_dir) catch {};
    }
    const pid_path = try std.fmt.allocPrint(allocator, "{s}/tardi.pid", .{readonly_dir});
    defer allocator.free(pid_path);

    // Skip rather than false-fail when the filesystem/user doesn't actually
    // enforce the permission bit (e.g. tests running as root).
    const probe_path = try std.fmt.allocPrint(allocator, "{s}/probe", .{readonly_dir});
    defer allocator.free(probe_path);
    if (compat.createFileAbsolute(probe_path, .{})) |probe_file| {
        var f = probe_file;
        f.close();
        compat.cwd().deleteFile(probe_path) catch {};
        return error.SkipZigTest;
    } else |_| {}

    const config_rel = try std.fmt.allocPrint(allocator, ".zig-cache/tardigrade-runtime-fail-{d}.conf", .{compat.nanoTimestamp()});
    defer {
        compat.cwd().deleteFile(config_rel) catch {};
        allocator.free(config_rel);
    }
    try compat.cwd().writeFile(.{ .sub_path = config_rel, .data = "" });

    const port = try findFreePort();
    const port_str = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(port_str);

    var env_map = try inheritedEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("TARDIGRADE_CONFIG_PATH", config_rel);
    try env_map.put("TARDIGRADE_LISTEN_HOST", test_host);
    try env_map.put("TARDIGRADE_LISTEN_PORT", port_str);
    try env_map.put("TARDIGRADE_PID_FILE", pid_path);
    // No TLS configured: this property holds for the general run path, not
    // only the appliance credential preflight.
    _ = env_map.swapRemove("TARDIGRADE_TLS_CERT_PATH");
    _ = env_map.swapRemove("TARDIGRADE_TLS_KEY_PATH");

    const run_res = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "run", "-c", config_rel },
        .environ_map = &env_map,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(run_res.stdout);
    defer allocator.free(run_res.stderr);

    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, run_res.term);
    try assertContains(run_res.stderr, "tardigrade exited");
    try assertContains(run_res.stderr, "AccessDenied");
    try std.testing.expect(std.mem.indexOf(u8, run_res.stderr, "configuration validation failed") == null);
}

// #162: `tardi init <profile>` real generated-config validation. These
// spawn the actual built binary rather than re-implementing a mini
// validator, so they prove the exact bytes an operator gets from
// `tardi init <profile> > tardigrade.conf` are accepted by the exact
// production `tardi check` path -- not a stand-in for it.

const init_profile_names = [_][]const u8{ "static", "proxy", "tls", "metrics", "prod" };
const init_profile_aliases = [_][]const u8{ "static-site", "reverse-proxy", "tls-termination", "metrics-enabled", "production-baseline" };

test "init emits config bytes only to stdout with empty stderr for every canonical profile and alias" {
    const allocator = std.testing.allocator;
    for (init_profile_names) |name| try expectInitStdoutOnly(allocator, name);
    for (init_profile_aliases) |name| try expectInitStdoutOnly(allocator, name);
}

fn expectInitStdoutOnly(allocator: std.mem.Allocator, profile_arg: []const u8) !void {
    const res = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "init", profile_arg },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, res.term);
    try std.testing.expectEqualStrings("", res.stderr);
    try assertContains(res.stdout, "# Tardigrade profile:");
    try std.testing.expect(std.mem.endsWith(u8, res.stdout, "\n"));
}

test "init proxy and its descriptive alias reverse-proxy are byte-identical" {
    const allocator = std.testing.allocator;
    const canonical = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "init", "proxy" },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(canonical.stdout);
    defer allocator.free(canonical.stderr);

    const alias = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "init", "reverse-proxy" },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(alias.stdout);
    defer allocator.free(alias.stderr);

    try std.testing.expectEqualStrings(canonical.stdout, alias.stdout);
}

test "init rejects an unknown profile by name and lists the valid ones" {
    const allocator = std.testing.allocator;
    const res = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "init", "kubernetes" },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, res.term);
    try std.testing.expectEqualStrings("", res.stdout);
    try assertContains(res.stderr, "unknown config profile 'kubernetes'");
    try assertContains(res.stderr, "static, proxy, tls, metrics, prod");
}

test "init rejects too many positional arguments and a missing profile" {
    const allocator = std.testing.allocator;
    const too_many = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "init", "proxy", "static" },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(too_many.stdout);
    defer allocator.free(too_many.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, too_many.term);
    try assertContains(too_many.stderr, "too many positional arguments");

    const missing = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "init" },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(missing.stdout);
    defer allocator.free(missing.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 1 }, missing.term);
    try assertContains(missing.stderr, "missing config profile");
}

test "init -h and --help print usage without generating a config" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "-h", "--help" }) |flag| {
        const res = try std.process.run(allocator, compat.io(), .{
            .argv = &.{ integration_options.tardigrade_bin_path, "init", flag },
            .stdout_limit = .limited(64 * 1024),
            .stderr_limit = .limited(64 * 1024),
        });
        defer allocator.free(res.stdout);
        defer allocator.free(res.stderr);
        try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, res.term);
        try std.testing.expect(std.mem.indexOf(u8, res.stdout, "# Tardigrade profile:") == null);
        try assertContains(res.stdout, "tardi init <profile>");
    }
}

/// Writes `data` to a fresh `.zig-cache`-relative path so callers get an
/// isolated real file the production `check`/`init` file-writing paths can
/// exercise, cleaned up automatically.
fn writeTempConfig(allocator: std.mem.Allocator, label: []const u8, data: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(allocator, ".zig-cache/tardigrade-init-{s}-{d}.conf", .{ label, compat.nanoTimestamp() });
    errdefer allocator.free(path);
    try compat.cwd().writeFile(.{ .sub_path = path, .data = data });
    return path;
}

fn expectInitProfileGeneratesCheckableConfig(allocator: std.mem.Allocator, profile: []const u8) !void {
    const generated = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "init", profile },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(generated.stdout);
    defer allocator.free(generated.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, generated.term);

    const config_path = try writeTempConfig(allocator, profile, generated.stdout);
    defer {
        compat.cwd().deleteFile(config_path) catch {};
        allocator.free(config_path);
    }

    const checked = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "check", config_path },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(checked.stdout);
    defer allocator.free(checked.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, checked.term);
    try assertContains(checked.stdout, "configuration valid");
    // Regression for #168: every canonical profile declares exactly two
    // top-level `location` blocks (`= /health` and `/`), none of them
    // wrapped in a `server { }` block. `check`'s summary previously
    // undercounted these as "location blocks: 0" because it only summed
    // server_blocks[].location_blocks, ignoring the config's own top-level
    // location_blocks -- the field every `tardi init` profile actually
    // populates.
    try assertContains(checked.stdout, "location blocks: 2");

    const printed = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "print-config", "-c", config_path },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(printed.stdout);
    defer allocator.free(printed.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, printed.term);
    try assertContains(printed.stdout, "location blocks: 2");
}

test "init static, proxy, and metrics profiles pass the real tardi check with no external prerequisites" {
    const allocator = std.testing.allocator;
    try expectInitProfileGeneratesCheckableConfig(allocator, "static");
    try expectInitProfileGeneratesCheckableConfig(allocator, "proxy");
    try expectInitProfileGeneratesCheckableConfig(allocator, "metrics");
}

fn expectInitTlsProfileGeneratesCheckableConfig(allocator: std.mem.Allocator, profile: []const u8, upstream_base_url: ?[]const u8) !void {
    const generated = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "init", profile },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(generated.stdout);
    defer allocator.free(generated.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, generated.term);
    try assertContains(generated.stdout, "/etc/tardigrade/tls/fullchain.pem");
    try assertContains(generated.stdout, "/etc/tardigrade/tls/privkey.pem");

    // The generated profile intentionally points at operator-owned
    // credential paths that do not exist on this machine (#162's contract:
    // no embedded/fake credentials). Validation of the real artifact
    // therefore substitutes the repository's own fixture cert/key -- the
    // same Ed25519 pair the appliance credential preflight tests already
    // trust -- rather than weakening or skipping `tardi check`.
    const cert_path = try applianceFixturePath(allocator, "native_ed25519.crt");
    defer allocator.free(cert_path);
    const key_path = try applianceFixturePath(allocator, "native_ed25519.key");
    defer allocator.free(key_path);

    const with_cert = try std.mem.replaceOwned(u8, allocator, generated.stdout, "/etc/tardigrade/tls/fullchain.pem", cert_path);
    defer allocator.free(with_cert);
    const substituted = try std.mem.replaceOwned(u8, allocator, with_cert, "/etc/tardigrade/tls/privkey.pem", key_path);
    defer allocator.free(substituted);

    const config_path = try writeTempConfig(allocator, profile, substituted);
    defer {
        compat.cwd().deleteFile(config_path) catch {};
        allocator.free(config_path);
    }

    var env_map = try inheritedEnvMap(allocator);
    defer env_map.deinit();
    // The fixture's leaf identity is CN/SAN `tardigrade.test`; the
    // appliance credential preflight matches this against the configured
    // server name (see `verifyApplianceAcceptsCredential` above).
    try env_map.put("TARDIGRADE_TLS_SERVER_NAME", "tardigrade.test");
    if (upstream_base_url) |url| try env_map.put("TARDIGRADE_UPSTREAM_BASE_URL", url);

    const checked = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "check", config_path },
        .environ_map = &env_map,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(checked.stdout);
    defer allocator.free(checked.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, checked.term);
    try assertContains(checked.stdout, "configuration valid");
    // See the matching #168 regression comment in
    // expectInitProfileGeneratesCheckableConfig above: both the `tls` and
    // `prod` templates also declare exactly two top-level location blocks.
    try assertContains(checked.stdout, "location blocks: 2");

    const printed = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "print-config", "-c", config_path },
        .environ_map = &env_map,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(printed.stdout);
    defer allocator.free(printed.stderr);
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, printed.term);
    try assertContains(printed.stdout, "location blocks: 2");
}

test "init tls profile passes the real tardi check once real TLS fixtures are supplied" {
    try expectInitTlsProfileGeneratesCheckableConfig(std.testing.allocator, "tls", null);
}

test "init prod profile passes the real tardi check with TLS fixtures and a test upstream" {
    try expectInitTlsProfileGeneratesCheckableConfig(std.testing.allocator, "prod", "http://127.0.0.1:3000");
}

// #163: `tardi explain <field>`. These spawn the actual built binary against
// a real child environment rather than exercising config_reference.zig's
// pure functions in-process, so they prove the strongest form of the
// secret-leak regression required by #163 -- that a sentinel genuinely
// present in the environment `tardi explain` runs under never reaches
// stdout or stderr, closing the gap a purely-static assertion cannot.
fn expectExplainNeverLeaksLiveSecret(allocator: std.mem.Allocator, field: []const u8, env_name: []const u8) !void {
    const sentinel = "super-secret-test-value";

    var env_map = try inheritedEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put(env_name, sentinel);

    const res = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "explain", field },
        .environ_map = &env_map,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, res.term);
    try assertContains(res.stdout, env_name);
    try std.testing.expect(std.mem.indexOf(u8, res.stdout, sentinel) == null);
    try std.testing.expect(std.mem.indexOf(u8, res.stderr, sentinel) == null);
}

test "explain jwt_secret never leaks a live TARDIGRADE_JWT_SECRET value from the process environment" {
    try expectExplainNeverLeaksLiveSecret(std.testing.allocator, "jwt_secret", "TARDIGRADE_JWT_SECRET");
}

test "explain trust_shared_secret never leaks a live TARDIGRADE_TRUST_SHARED_SECRET value from the process environment" {
    try expectExplainNeverLeaksLiveSecret(std.testing.allocator, "trust_shared_secret", "TARDIGRADE_TRUST_SHARED_SECRET");
}

test "explain never touches a config file: an invalid TARDIGRADE_CONFIG_PATH does not affect the result" {
    const allocator = std.testing.allocator;
    var env_map = try inheritedEnvMap(allocator);
    defer env_map.deinit();
    try env_map.put("TARDIGRADE_CONFIG_PATH", "/nonexistent/path/tardigrade.conf");

    const res = try std.process.run(allocator, compat.io(), .{
        .argv = &.{ integration_options.tardigrade_bin_path, "explain", "listen" },
        .environ_map = &env_map,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer allocator.free(res.stdout);
    defer allocator.free(res.stderr);

    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, res.term);
    try assertContains(res.stdout, "listen");
    try std.testing.expectEqualStrings("", res.stderr);
}
