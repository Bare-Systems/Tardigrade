const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const integration_options = @import("integration_options");
const compat = @import("zig_compat");
const hpack = @import("hpack");
const tls_core = @import("tls_core");

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
    capture: RequestCapture,
    responses: []const UpstreamResponseSpec,
    next_response_index: usize,

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

    fn port(self: *const UpstreamServer) u16 {
        return self.server.port();
    }

    fn run(self: *UpstreamServer) !void {
        self.thread = try std.Thread.spawn(.{}, upstreamThreadMain, .{self});
    }

    fn stop(self: *UpstreamServer) void {
        self.stop_flag.store(true, .seq_cst);
        wakeListener(self.port());
        if (self.thread) |thread| thread.join();
        self.server.deinit();
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

    fn start(allocator: std.mem.Allocator, options: TardigradeOptions) !TardigradeProcess {
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

        var proc = TardigradeProcess{
            .allocator = allocator,
            .child = child,
            .port = port,
            .log_path = log_path,
            .config_path = config_path,
            .fixture_dir_rel = fixture_dir_rel,
        };
        errdefer proc.stop();
        try waitUntilReady(port, log_path, options);
        return proc;
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

    const fixture_name = if (build_options.tls_openssl_adapter) "server" else "native_p256";
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
    defer conn.stream.close();
    const req = try readHttpMessage(server.allocator, conn.stream, 1024 * 1024);
    defer server.allocator.free(req.raw);
    if (req.request_line.len == 0) return;

    server.mutex.lock();
    defer server.mutex.unlock();
    try server.capture.record(req);

    const response_spec = if (server.responses.len == 0)
        UpstreamResponseSpec{
            .status_code = 200,
            .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
            .body = "{\"ok\":true}",
        }
    else blk: {
        const idx = if (server.next_response_index < server.responses.len) server.next_response_index else server.responses.len - 1;
        if (server.next_response_index < server.responses.len) server.next_response_index += 1;
        break :blk server.responses[idx];
    };

    if (response_spec.delay_ms > 0) {
        compat.sleepNs(@as(u64, response_spec.delay_ms) * std.time.ns_per_ms);
    }

    const reason = switch (response_spec.status_code) {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        302 => "Found",
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
    } else {
        try conn.stream.writer().print("Content-Length: {d}\r\n", .{if (response_spec.omit_body) 0 else response_spec.body.len});
    }
    try conn.stream.writer().print("Connection: {s}\r\n", .{
        response_spec.connection_header,
    });
    for (response_spec.headers) |header| {
        try conn.stream.writer().print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    try conn.stream.writer().writeAll("\r\n");
    if (response_spec.omit_body) return;
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
    while (true) {
        const read_n = try readSocketWithPoll(stream.handle, &tmp, 5_000);
        if (read_n == 0) break;
        try buf.appendSlice(tmp[0..read_n]);
        if (buf.items.len > max_bytes) return error.MessageTooLarge;

        if (header_end == null) {
            if (std.mem.find(u8, buf.items, "\r\n\r\n")) |idx| {
                header_end = idx + 4;
                content_length = parseContentLength(buf.items[0..idx]);
            }
        }
        if (header_end) |headers_len| {
            if (buf.items.len >= headers_len + content_length) break;
        }
    }

    const raw = try buf.toOwnedSlice();
    const split_idx = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.InvalidHttpMessage;
    const request_line_end = std.mem.find(u8, raw, "\r\n") orelse return error.InvalidHttpMessage;
    const headers_raw = raw[0 .. split_idx + 2];
    const body_start = split_idx + 4;
    return .{
        .raw = raw,
        .request_line = raw[0..request_line_end],
        .headers_raw = headers_raw,
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
        "openssl s_client -connect {s}:{d} -servername {s} -showcerts </dev/null 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' | openssl x509 -noout -subject",
        .{ test_host, port, servername },
    );
    defer allocator.free(cmd);

    const run_res = try std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &.{ "sh", "-lc", cmd },
        .max_output_bytes = 1024 * 1024,
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
    const cert_path = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/native_p256.crt", .{cwd});
    errdefer allocator.free(cert_path);
    const key_path = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/native_p256.key", .{cwd});
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

const PureZigTlsClient = struct {
    allocator: std.mem.Allocator,
    stream: compat.NetStream,
    entropy_source: tls_core.production_crypto.OsEntropy = .{},
    crypto_provider_state: tls_core.production_crypto.Provider = undefined,
    backend: tls_core.tls13_backend.Tls13Backend = undefined,
    record: tls_core.encrypted_stream.PureZigRecordStream = undefined,

    fn create(allocator: std.mem.Allocator, port: u16, alpn: []const u8) !*PureZigTlsClient {
        const self = try allocator.create(PureZigTlsClient);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .stream = try compat.tcpConnectToHost(allocator, test_host, port),
        };
        errdefer self.stream.close();
        try setNonBlockingFd(self.stream.handle);

        self.crypto_provider_state = tls_core.production_crypto.Provider.init(self.entropy_source.entropy());
        self.backend = tls_core.tls13_backend.Tls13Backend.initClient(
            try tls_core.production_crypto.freshHandshakeEntropy(),
            .insecure_no_verification,
            .{ .record = .{ .alpn = alpnPolicy(alpn) } },
        );
        self.record = tls_core.encrypted_stream.PureZigRecordStream.initWithCarrierAndBackend(
            .client,
            self.cryptoProviderState().cryptoProvider(),
            .tls_aes_128_gcm_sha256,
            self.carrier(),
            self.backend.backend(),
        );
        self.record.allow_unverified_certificate = true;
        try self.record.setExpectedAlpn(alpn);
        try self.driveUntilOpen(5_000);
        return self;
    }

    fn expectHandshakeFailure(allocator: std.mem.Allocator, port: u16, alpn: []const u8) !void {
        const self = try allocator.create(PureZigTlsClient);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .stream = try compat.tcpConnectToHost(allocator, test_host, port),
        };
        defer self.destroy();
        try setNonBlockingFd(self.stream.handle);

        self.crypto_provider_state = tls_core.production_crypto.Provider.init(self.entropy_source.entropy());
        self.backend = tls_core.tls13_backend.Tls13Backend.initClient(
            try tls_core.production_crypto.freshHandshakeEntropy(),
            .insecure_no_verification,
            .{ .record = .{ .alpn = alpnPolicy(alpn) } },
        );
        self.record = tls_core.encrypted_stream.PureZigRecordStream.initWithCarrierAndBackend(
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

fn alpnPolicy(alpn: []const u8) tls_core.tls13_backend.AlpnPolicy {
    if (std.mem.eql(u8, alpn, "h2")) return tls_core.tls13_backend.recordAlpnPolicy("h2");
    if (std.mem.eql(u8, alpn, "http/1.1")) return tls_core.tls13_backend.recordAlpnPolicy("http/1.1");
    if (std.mem.eql(u8, alpn, "tardigrade-test")) return tls_core.tls13_backend.recordAlpnPolicy("tardigrade-test");
    return .{ .protocols = &.{} };
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

    try waitForUpstreamCount(&upstream, 2, 2_000);
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
