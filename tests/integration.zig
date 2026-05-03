const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const integration_options = @import("integration_options");

const test_host = "127.0.0.1";
const valid_bearer_token = "integration-token";
const valid_bearer_hash = "521bc8ca01307d0189b55a19da738e39c7204f7077e0076e803026e32b2f9383";
const http3_curl_path = "/opt/homebrew/opt/curl/bin/curl";
const http3_resumption_client_bin_path = integration_options.http3_resumption_client_bin_path;
const http3_osslclient_bin_path = integration_options.http3_osslclient_bin_path;
const expected_server_header = "tardigrade/0.4.1";
const http3_retry_attempts: usize = 20;
const http3_retry_delay_ms: u64 = 250;

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
    stream: std.net.Stream,

    fn connect(allocator: std.mem.Allocator, port: u16, path: []const u8, headers: []const RequestHeader) !WebSocketClient {
        const address = try std.net.Address.parseIp(test_host, port);
        var stream = try std.net.tcpConnectToAddress(address);
        errdefer stream.close();
        try setStreamTimeouts(&stream, 5_000);

        var request = std.ArrayList(u8).init(allocator);
        defer request.deinit();
        try request.writer().print(
            "GET {s} HTTP/1.1\r\nHost: {s}:{d}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n",
            .{ path, test_host, port },
        );
        for (headers) |header| {
            try request.writer().print("{s}: {s}\r\n", .{ header.name, header.value });
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
    path_history: std.ArrayList([]u8),
    body_history: std.ArrayList([]u8),
    request_count: u32,

    fn init(allocator: std.mem.Allocator) !RequestCapture {
        return .{
            .allocator = allocator,
            .method = try allocator.dupe(u8, ""),
            .path = try allocator.dupe(u8, ""),
            .body = try allocator.dupe(u8, ""),
            .correlation_id = try allocator.dupe(u8, ""),
            .headers_raw = try allocator.dupe(u8, ""),
            .path_history = std.ArrayList([]u8).init(allocator),
            .body_history = std.ArrayList([]u8).init(allocator),
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
    server: std.net.Server,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    mutex: std.Thread.Mutex = .{},
    capture: RequestCapture,
    responses: []const UpstreamResponseSpec,
    next_response_index: usize,

    fn start(allocator: std.mem.Allocator, responses: []const UpstreamResponseSpec) !UpstreamServer {
        const address = try std.net.Address.parseIp(test_host, 0);
        const server = try std.net.Address.listen(address, .{ .reuse_address = true });
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
        return self.server.listen_address.getPort();
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
};

const FastCgiServer = struct {
    allocator: std.mem.Allocator,
    server: std.net.Server,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    mutex: std.Thread.Mutex = .{},
    capture: FastCgiCapture,
    responses: []const FastCgiResponseSpec,
    next_response_index: usize,
    accepted_connections: u32,

    fn start(allocator: std.mem.Allocator, responses: []const FastCgiResponseSpec) !FastCgiServer {
        const address = try std.net.Address.parseIp(test_host, 0);
        const server = try std.net.Address.listen(address, .{ .reuse_address = true });
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
        return self.server.listen_address.getPort();
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
    server: std.net.Server,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    mutex: std.Thread.Mutex = .{},
    capture: ScgiCapture,
    responses: []const ScgiResponseSpec,
    next_response_index: usize,

    fn start(allocator: std.mem.Allocator, responses: []const ScgiResponseSpec) !ScgiServer {
        const address = try std.net.Address.parseIp(test_host, 0);
        const server = try std.net.Address.listen(address, .{ .reuse_address = true });
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
        return self.server.listen_address.getPort();
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
    server: std.net.Server,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    mutex: std.Thread.Mutex = .{},
    capture: UwsgiCapture,
    responses: []const UwsgiResponseSpec,
    next_response_index: usize,

    fn start(allocator: std.mem.Allocator, responses: []const UwsgiResponseSpec) !UwsgiServer {
        const address = try std.net.Address.parseIp(test_host, 0);
        const server = try std.net.Address.listen(address, .{ .reuse_address = true });
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
        return self.server.listen_address.getPort();
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
    server: std.net.Server,
    thread: ?std.Thread,
    stop_flag: std.atomic.Value(bool),
    mutex: std.Thread.Mutex = .{},
    capture: RawTcpCapture,
    response: []const u8,

    fn start(allocator: std.mem.Allocator, response: []const u8) !RawTcpServer {
        const address = try std.net.Address.parseIp(test_host, 0);
        const server = try std.net.Address.listen(address, .{ .reuse_address = true });
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
        return self.server.listen_address.getPort();
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
        const unique = std.time.milliTimestamp();
        const dir_rel = try std.fmt.allocPrint(allocator, ".zig-cache/starttls-smtp-{d}-{d}", .{ port, unique });
        errdefer allocator.free(dir_rel);
        try std.fs.cwd().makePath(dir_rel);

        const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
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
            var file = try std.fs.createFileAbsolute(script_path, .{});
            defer file.close();
            try file.writeAll(script);
        }

        var argv = [_][]const u8{ "python3", script_path };
        var child = std.process.Child.init(&argv, allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        try child.spawn();

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
        _ = self.child.kill() catch {};
        _ = self.child.wait() catch {};
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
        var file = try std.fs.openFileAbsolute(self.plain_capture_path, .{});
        defer file.close();
        return try file.readToEndAlloc(self.allocator, 1024 * 1024);
    }

    fn tlsCapture(self: *StartTlsSmtpProcess) ![]u8 {
        var file = try std.fs.openFileAbsolute(self.tls_capture_path, .{});
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
        const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd);
        const log_path = try std.fmt.allocPrint(allocator, "{s}/.zig-cache/tardigrade-integration-{d}.log", .{ cwd, port });

        var argv = [_][]const u8{integration_options.tardigrade_bin_path};
        var child = std.process.Child.init(&argv, allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;

        var env_map = try std.process.getEnvMap(allocator);
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
                const base_config = try std.fs.cwd().readFileAlloc(allocator, cfg_path, 512 * 1024);
                defer allocator.free(base_config);
                const merged_config = try std.fmt.allocPrint(allocator, "{s}\n\n{s}\n", .{ base_config, config_text });
                defer allocator.free(merged_config);
                try std.fs.cwd().writeFile(.{ .sub_path = cfg_path, .data = merged_config });
            } else {
                if (fixture_dir_rel) |dir_rel| {
                    std.fs.cwd().deleteTree(dir_rel) catch {};
                    allocator.free(dir_rel);
                    fixture_dir_rel = null;
                }
                if (config_path) |existing| {
                    std.fs.cwd().deleteFile(existing) catch {};
                    allocator.free(existing);
                    config_path = null;
                }
                const cfg_path = try std.fmt.allocPrint(allocator, ".zig-cache/tardigrade-config-{d}.conf", .{port});
                errdefer allocator.free(cfg_path);
                try std.fs.cwd().writeFile(.{ .sub_path = cfg_path, .data = config_text });
                try env_map.put("TARDIGRADE_CONFIG_PATH", cfg_path);
                config_path = cfg_path;
            }
        }
        for (options.extra_env) |pair| {
            try env_map.put(pair.name, pair.value);
        }

        child.env_map = &env_map;
        try child.spawn();

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
        _ = self.child.kill() catch {};
        _ = self.child.wait() catch {};
        self.allocator.free(self.log_path);
        if (self.config_path) |path| {
            std.fs.cwd().deleteFile(path) catch {};
            self.allocator.free(path);
        }
        if (self.fixture_dir_rel) |path| {
            std.fs.cwd().deleteTree(path) catch {};
            self.allocator.free(path);
        }
        self.* = undefined;
    }

    fn sendSignal(self: *TardigradeProcess, sig: u8) void {
        std.posix.kill(self.child.id, sig) catch {};
    }

    fn rewriteConfig(self: *const TardigradeProcess, text: []const u8) !void {
        const path = self.config_path orelse return error.MissingConfigPath;
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = text });
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
    env_map: *std.process.EnvMap,
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
    try std.fs.cwd().makePath(fixture_dir_rel);
    errdefer std.fs.cwd().deleteTree(fixture_dir_rel) catch {};

    const fixture_dir_abs = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ cwd, fixture_dir_rel });
    defer allocator.free(fixture_dir_abs);
    const public_dir_abs = try std.fmt.allocPrint(allocator, "{s}/public", .{fixture_dir_abs});
    defer allocator.free(public_dir_abs);
    const public_dir_rel = try std.fmt.allocPrint(allocator, "{s}/public", .{fixture_dir_rel});
    defer allocator.free(public_dir_rel);
    try std.fs.cwd().makePath(public_dir_rel);

    const index_rel = try std.fmt.allocPrint(allocator, "{s}/public/index.html", .{fixture_dir_rel});
    defer allocator.free(index_rel);
    try std.fs.cwd().writeFile(.{
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
        var device_file = try std.fs.createFileAbsolute(device_registry_abs, .{ .truncate = true });
        device_file.close();
    }
    {
        var session_file = try std.fs.createFileAbsolute(session_store_abs, .{ .truncate = true });
        session_file.close();
    }
    {
        var approval_file = try std.fs.createFileAbsolute(approval_store_abs, .{ .truncate = true });
        approval_file.close();
    }
    {
        var transcript_file = try std.fs.createFileAbsolute(transcript_store_abs, .{ .truncate = true });
        transcript_file.close();
    }

    const server_cert_abs = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/server.crt", .{cwd});
    defer allocator.free(server_cert_abs);
    const server_key_abs = try std.fmt.allocPrint(allocator, "{s}/tests/fixtures/tls/server.key", .{cwd});
    defer allocator.free(server_key_abs);
    const cert_line = try std.fmt.allocPrint(allocator, "tls_cert_path {s};\n", .{server_cert_abs});
    defer allocator.free(cert_line);
    const key_line = try std.fmt.allocPrint(allocator, "tls_key_path {s};\n", .{server_key_abs});
    defer allocator.free(key_line);

    const config_template = try std.fs.cwd().readFileAlloc(allocator, "examples/bearclaw/tardigrade.conf", 256 * 1024);
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
        std.fs.cwd().deleteFile(config_path) catch {};
        allocator.free(config_path);
    }
    try std.fs.cwd().writeFile(.{ .sub_path = config_path, .data = final_config_text });
    allocator.free(final_config_text);
    try env_map.put("TARDIGRADE_CONFIG_PATH", config_path);

    const env_template = try std.fs.cwd().readFileAlloc(allocator, "examples/bearclaw/tardigrade.env.example", 256 * 1024);
    defer allocator.free(env_template);
    var lines = std.mem.splitScalar(u8, env_template, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
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
        _ = env_map.remove("TARDIGRADE_TLS_CERT_PATH");
        _ = env_map.remove("TARDIGRADE_TLS_KEY_PATH");
    }
    try env_map.put("TARDIGRADE_DEVICE_REGISTRY_PATH", device_registry_abs);
    try env_map.put("TARDIGRADE_SESSION_STORE_PATH", session_store_abs);
    try env_map.put("TARDIGRADE_APPROVAL_STORE_PATH", approval_store_abs);
    try env_map.put("TARDIGRADE_TRANSCRIPT_STORE_PATH", transcript_store_abs);
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
        const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd);

        const unique = std.time.nanoTimestamp();
        const dir_rel = try std.fmt.allocPrint(allocator, ".zig-cache/php-fpm-{d}", .{unique});
        errdefer allocator.free(dir_rel);
        try std.fs.cwd().makePath(dir_rel);

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

        try std.fs.cwd().writeFile(.{
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
        try std.fs.cwd().writeFile(.{ .sub_path = config_rel, .data = config_text });

        var argv = [_][]const u8{ binary, "--nodaemonize", "--fpm-config", config_path };
        var child = std.process.Child.init(&argv, allocator);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        try child.spawn();

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
        _ = self.child.kill() catch {};
        _ = self.child.wait() catch {};
        std.fs.cwd().deleteTree(self.dir_rel) catch {};
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
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    _ = log_path;
    return error.Timeout;
}

fn waitUntilChildReady(child: *std.process.Child) !void {
    const stdout = child.stdout orelse return error.Unexpected;
    var buf: [64]u8 = undefined;
    const n = try stdout.read(&buf);
    if (n == 0) return error.EndOfStream;
    if (std.mem.indexOf(u8, buf[0..n], "READY") == null) return error.Unexpected;
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

fn handleUpstreamConnection(server: *UpstreamServer, conn: std.net.Server.Connection) !void {
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
        std.time.sleep(@as(u64, response_spec.delay_ms) * std.time.ns_per_ms);
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

    try conn.stream.writer().print("HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\n", .{
        response_spec.status_code,
        reason,
        response_spec.body.len,
    });
    for (response_spec.headers) |header| {
        try conn.stream.writer().print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    try conn.stream.writer().print("\r\n{s}", .{response_spec.body});
}

fn handleFastCgiConnection(server: *FastCgiServer, conn: std.net.Server.Connection) !void {
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

fn handleScgiConnection(server: *ScgiServer, conn: std.net.Server.Connection) !void {
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

fn handleUwsgiConnection(server: *UwsgiServer, conn: std.net.Server.Connection) !void {
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

fn readHttpMessage(allocator: std.mem.Allocator, stream: std.net.Stream, max_bytes: usize) !RawHttpMessage {
    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    var tmp: [4096]u8 = undefined;
    var header_end: ?usize = null;
    var content_length: usize = 0;

    while (true) {
        const read_n = try stream.read(&tmp);
        if (read_n == 0) break;
        try buf.appendSlice(tmp[0..read_n]);
        if (buf.items.len > max_bytes) return error.MessageTooLarge;

        if (header_end == null) {
            if (std.mem.indexOf(u8, buf.items, "\r\n\r\n")) |idx| {
                header_end = idx + 4;
                content_length = parseContentLength(buf.items[0..idx]);
            }
        }
        if (header_end) |headers_len| {
            if (buf.items.len >= headers_len + content_length) break;
        }
    }

    const raw = try buf.toOwnedSlice();
    const split_idx = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.InvalidHttpMessage;
    const request_line_end = std.mem.indexOf(u8, raw, "\r\n") orelse return error.InvalidHttpMessage;
    const headers_raw = raw[0 .. split_idx + 2];
    const body_start = split_idx + 4;
    return .{
        .raw = raw,
        .request_line = raw[0..request_line_end],
        .headers_raw = headers_raw,
        .body = raw[body_start..],
    };
}

fn readFastCgiRequest(allocator: std.mem.Allocator, stream: std.net.Stream, max_bytes: usize) !?[]u8 {
    var buf = std.ArrayList(u8).init(allocator);
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

fn readScgiRequest(allocator: std.mem.Allocator, stream: std.net.Stream, max_bytes: usize) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
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

fn readUwsgiRequest(allocator: std.mem.Allocator, stream: std.net.Stream, max_bytes: usize) ![]u8 {
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

    var out = std.ArrayList(u8).init(allocator);
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
    const colon = std.mem.indexOfScalar(u8, data, ':') orelse return false;
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
        const key_end_rel = std.mem.indexOfScalarPos(u8, header_blob, i, 0) orelse break;
        const key = header_blob[i..key_end_rel];
        const value_start = key_end_rel + 1;
        const value_end_rel = std.mem.indexOfScalarPos(u8, header_blob, value_start, 0) orelse break;
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
    var payload = std.ArrayList(u8).init(allocator);
    errdefer payload.deinit();
    try payload.writer().print("Status: {d} {s}\r\n", .{ spec.status_code, httpReason(spec.status_code) });
    for (spec.headers) |header| {
        try payload.writer().print("{s}: {s}\r\n", .{ header.name, header.value });
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
        const sep = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const key = std.mem.trim(u8, line[0..sep], " \t");
        if (!std.ascii.eqlIgnoreCase(key, name)) continue;
        return std.mem.trim(u8, line[sep + 1 ..], " \t");
    }
    return null;
}

fn cookiePairFromSetCookie(set_cookie: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, set_cookie, ';') orelse set_cookie.len;
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
    const address = try std.net.Address.parseIp(test_host, port);
    var stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    try setStreamTimeouts(&stream, 5_000);
    try stream.writeAll(raw_request);
    return readHttpResponse(allocator, stream);
}

fn openRequestStream(allocator: std.mem.Allocator, port: u16, spec: RequestSpec) !std.net.Stream {
    const address = try std.net.Address.parseIp(test_host, port);
    var stream = try std.net.tcpConnectToAddress(address);
    errdefer stream.close();

    var request = std.ArrayList(u8).init(allocator);
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
        try request.writer().print("PROXY TCP4 {s} 127.0.0.1 12345 {d}\r\n", .{ proxy_ip, port });
    }
    defer if (owned_host_value) |generated| allocator.free(generated);
    try request.writer().print("{s} {s} HTTP/1.1\r\nHost: {s}\r\nConnection: {s}\r\n", .{
        spec.method,
        spec.path,
        host_value,
        if (spec.connection_close) "close" else "keep-alive",
    });
    for (spec.headers) |header| {
        try request.writer().print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    if (spec.body != null) {
        try request.writer().print("Content-Length: {d}\r\n", .{body.len});
    }
    try request.appendSlice("\r\n");
    if (spec.body != null) try request.appendSlice(body);

    try stream.writeAll(request.items);
    return stream;
}

fn setStreamTimeouts(stream: *std.net.Stream, timeout_ms: u64) !void {
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

fn readHttpResponse(allocator: std.mem.Allocator, stream: std.net.Stream) !HttpResponse {
    var raw_buf = std.ArrayList(u8).init(allocator);
    errdefer raw_buf.deinit();
    var tmp: [4096]u8 = undefined;
    var header_end: ?usize = null;
    var target_len: ?usize = null;

    while (true) {
        if (target_len) |needed| {
            if (raw_buf.items.len >= needed) break;
        }
        const n = stream.read(&tmp) catch |err| switch (err) {
            error.ConnectionResetByPeer => {
                if (raw_buf.items.len > 0) break;
                return err;
            },
            else => return err,
        };
        if (n == 0) break;
        try raw_buf.appendSlice(tmp[0..n]);

        if (header_end == null) {
            if (std.mem.indexOf(u8, raw_buf.items, "\r\n\r\n")) |idx| {
                header_end = idx;
                const headers_raw = raw_buf.items[0 .. idx + 2];
                if (headerValue(headers_raw, "Content-Length")) |content_length_raw| {
                    const content_length = std.fmt.parseInt(usize, content_length_raw, 10) catch return error.InvalidHttpResponse;
                    target_len = idx + 4 + content_length;
                }
            }
        }
    }

    const raw = try raw_buf.toOwnedSlice();
    errdefer allocator.free(raw);
    const final_header_end = header_end orelse std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.InvalidHttpResponse;
    const status_end = std.mem.indexOf(u8, raw, "\r\n") orelse return error.InvalidHttpResponse;
    const status_line = raw[0..status_end];
    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next() orelse return error.InvalidHttpResponse;
    const status_text = parts.next() orelse return error.InvalidHttpResponse;
    const status_code = try std.fmt.parseInt(u16, status_text, 10);
    return .{
        .allocator = allocator,
        .raw = raw,
        .status_code = status_code,
        .headers_raw = raw[0 .. final_header_end + 2],
        .body = raw[final_header_end + 4 ..],
    };
}

fn readHttpHeadersOnly(allocator: std.mem.Allocator, stream: std.net.Stream) ![]u8 {
    var raw_buf = std.ArrayList(u8).init(allocator);
    errdefer raw_buf.deinit();
    var tmp: [1024]u8 = undefined;

    while (true) {
        const n = try stream.read(&tmp);
        if (n == 0) return error.InvalidHttpResponse;
        try raw_buf.appendSlice(tmp[0..n]);
        if (std.mem.indexOf(u8, raw_buf.items, "\r\n\r\n") != null) break;
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

fn readWebSocketFrame(stream: std.net.Stream, allocator: std.mem.Allocator, max_payload: usize) !WebSocketFrame {
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

fn readExact(stream: std.net.Stream, out: []u8) !void {
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
            var resp = sendCurlRequest(std.testing.allocator, port, .{
                .scheme = "https",
                .path = ready_path,
                .insecure = true,
                .cert = options.ready_client_cert,
                .key = options.ready_client_key,
            }) catch |err| {
                if (attempts == 99) {
                    const log_data = std.fs.cwd().readFileAlloc(std.testing.allocator, log_path, 256 * 1024) catch "";
                    defer if (log_data.len > 0) std.testing.allocator.free(log_data);
                    std.debug.print("tardigrade failed to boot: {}\n{s}\n", .{ err, log_data });
                    return err;
                }
                std.time.sleep(50 * std.time.ns_per_ms);
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
                    const log_data = std.fs.cwd().readFileAlloc(std.testing.allocator, log_path, 256 * 1024) catch "";
                    defer if (log_data.len > 0) std.testing.allocator.free(log_data);
                    std.debug.print("tardigrade failed to boot: {}\n{s}\n", .{ err, log_data });
                    return err;
                }
                std.time.sleep(50 * std.time.ns_per_ms);
                continue;
            };
            defer resp.deinit();
            if (options.ready_status_code) |expected| {
                if (resp.status_code == expected) return;
            } else {
                return;
            }
        }
        std.time.sleep(50 * std.time.ns_per_ms);
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
};

fn runCurl(allocator: std.mem.Allocator, port: u16, spec: CurlRequestSpec) !CurlRunResult {
    var argv = std.ArrayList([]const u8).init(allocator);
    defer argv.deinit();
    var owned_args = std.ArrayList([]u8).init(allocator);
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
    defer allocator.free(url);
    try argv.append(url);

    const run_res = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv.items,
        .max_output_bytes = 1024 * 1024,
    });
    return .{
        .allocator = allocator,
        .stdout = run_res.stdout,
        .stderr = run_res.stderr,
        .term = run_res.term,
    };
}

fn spawnCurlProcess(allocator: std.mem.Allocator, port: u16, spec: CurlRequestSpec) !std.process.Child {
    var argv = std.ArrayList([]const u8).init(allocator);
    defer argv.deinit();
    var owned_args = std.ArrayList([]u8).init(allocator);
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

    var child = std.process.Child.init(argv.items, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    return child;
}

fn sendCurlRequest(allocator: std.mem.Allocator, port: u16, spec: CurlRequestSpec) !HttpResponse {
    var result = try runCurl(allocator, port, spec);
    errdefer result.deinit();
    switch (result.term) {
        .Exited => |code| if (code != 0) return error.CurlFailed,
        else => return error.CurlFailed,
    }

    allocator.free(result.stderr);
    return .{
        .allocator = allocator,
        .raw = result.stdout,
        .status_code = try parseStatusCode(result.stdout),
        .headers_raw = result.stdout[0 .. (std.mem.indexOf(u8, result.stdout, "\r\n\r\n") orelse return error.InvalidHttpResponse) + 2],
        .body = result.stdout[(std.mem.indexOf(u8, result.stdout, "\r\n\r\n") orelse return error.InvalidHttpResponse) + 4 ..],
    };
}

fn sendHttp3CurlRequestWithSpec(allocator: std.mem.Allocator, port: u16, spec: CurlRequestSpec) !HttpResponse {
    var last_err: ?anyerror = null;
    for (0..http3_retry_attempts) |_| {
        return sendCurlRequest(allocator, port, spec) catch |err| {
            last_err = err;
            std.time.sleep(http3_retry_delay_ms * std.time.ns_per_ms);
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
        .Exited => |code| if (code != 0) {
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
    const status_end = std.mem.indexOf(u8, raw, "\r\n") orelse return error.InvalidHttpResponse;
    const status_line = raw[0..status_end];
    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next() orelse return error.InvalidHttpResponse;
    const status_text = parts.next() orelse return error.InvalidHttpResponse;
    return std.fmt.parseInt(u16, status_text, 10);
}

fn waitForUpstreamCount(server: *UpstreamServer, expected: u32, timeout_ms: u64) !void {
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (std.time.milliTimestamp() < deadline) {
        if (server.requestCount() >= expected) return;
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    return error.Timeout;
}

fn waitForChildExit(pid: std.posix.pid_t, timeout_ms: u64) bool {
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (std.time.milliTimestamp() < deadline) {
        const result = std.posix.waitpid(pid, std.posix.W.NOHANG);
        if (result.pid == pid) return true;
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    return false;
}

fn waitForPortClosed(port: u16, timeout_ms: u64) !void {
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    const address = try std.net.Address.parseIp(test_host, port);
    while (std.time.milliTimestamp() < deadline) {
        var stream = std.net.tcpConnectToAddress(address) catch return;
        stream.close();
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    return error.Timeout;
}

fn waitForLogSubstring(allocator: std.mem.Allocator, path: []const u8, needle: []const u8, timeout_ms: u64) !void {
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (std.time.milliTimestamp() < deadline) {
        const contents = blk: {
            if (std.fs.path.isAbsolute(path)) {
                var file = try std.fs.openFileAbsolute(path, .{});
                defer file.close();
                break :blk try file.readToEndAlloc(allocator, 256 * 1024);
            }
            break :blk try std.fs.cwd().readFileAlloc(allocator, path, 256 * 1024);
        };
        defer allocator.free(contents);
        if (std.mem.indexOf(u8, contents, needle) != null) return;
        std.time.sleep(25 * std.time.ns_per_ms);
    }
    return error.Timeout;
}

fn wakeListener(port: u16) void {
    const address = std.net.Address.parseIp(test_host, port) catch return;
    var stream = std.net.tcpConnectToAddress(address) catch return;
    defer stream.close();
    stream.writeAll("GET /__shutdown__ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n") catch {};
}

fn findFreePort() !u16 {
    const address = try std.net.Address.parseIp(test_host, 0);
    var server = try std.net.Address.listen(address, .{ .reuse_address = true });
    defer server.deinit();
    return server.listen_address.getPort();
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
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
}

fn waitForBodyContains(allocator: std.mem.Allocator, port: u16, path: []const u8, headers: []const RequestHeader, needle: []const u8, timeout_ms: u64) !void {
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (std.time.milliTimestamp() < deadline) {
        var response = sendRequest(allocator, port, .{
            .method = "GET",
            .path = path,
            .body = null,
            .headers = headers,
        }) catch {
            std.time.sleep(50 * std.time.ns_per_ms);
            continue;
        };
        defer response.deinit();
        if (std.mem.indexOf(u8, response.body, needle) != null) return;
        std.time.sleep(50 * std.time.ns_per_ms);
    }
    return error.Timeout;
}

fn waitForWebSocketFrameContains(ws: *WebSocketClient, allocator: std.mem.Allocator, needle: []const u8, attempts: usize) !WebSocketFrame {
    var remaining = attempts;
    while (remaining > 0) : (remaining -= 1) {
        var frame = try ws.readFrame(allocator, 8192);
        if (std.mem.indexOf(u8, frame.payload, needle) != null) return frame;
        frame.deinit(allocator);
    }
    return error.Timeout;
}

fn waitForHttp3Configured(port: u16, timeout_ms: u64) !void {
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (std.time.milliTimestamp() < deadline) {
        var response = sendCurlRequest(std.testing.allocator, port, .{
            .scheme = "https",
            .path = "/health",
            .insecure = true,
        }) catch |err| {
            if (err == error.CurlFailed or err == error.InvalidHttpResponse) {
                std.time.sleep(100 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
        defer response.deinit();
        if (response.status_code == 200 and std.mem.indexOf(u8, response.body, "\"http3_status\":\"configured\"") != null) return;
        std.time.sleep(100 * std.time.ns_per_ms);
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
    ctx.result.body_contains_ok = std.mem.indexOf(u8, response.body, "\"ok\":true") != null;
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
    ctx.result.body_contains_ok = std.mem.indexOf(u8, response.body, "\"ok\":true") != null;
}

test "core gateway integration covers health metrics auth proxying invalid json and correlation ids" {
    return error.SkipZigTest;
}

test "mux websocket metrics and channel caps are enforced" {
    return error.SkipZigTest;
}

test "bearclaw fixture serves chat over https with bearer auth and transcript persistence" {
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
    const transcript = try std.fs.cwd().readFileAlloc(allocator, transcript_rel, 1024 * 1024);
    defer allocator.free(transcript);
    try assertContains(transcript, "\"scope\":\"chat\"");
    try assertContains(transcript, "\"route\":\"/v1/chat\"");
    try std.testing.expect(std.mem.indexOf(u8, transcript, valid_bearer_token) == null);

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

test "bearclaw transcript append logs path errors without failing the request" {
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
        .{ .name = "TARDIGRADE_TRANSCRIPT_STORE_PATH", .value = "/" },
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

    std.time.sleep(100 * std.time.ns_per_ms);
    const log_file = try std.fs.openFileAbsolute(tardigrade.log_path, .{});
    defer log_file.close();
    const log_data = try log_file.readToEndAlloc(allocator, 256 * 1024);
    defer allocator.free(log_data);
    try assertContains(log_data, "transcript store append failed");
}

// TC-TARDIGRADE-002 + TC-TARDIGRADE-004
test "bearclaw edge prefix routes health without auth and enforces auth on v1 paths" {
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
    try std.testing.expectEqualStrings("still-here", upstream.capturedHeader("X-Custom-Pass").?);
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

    const valid_request_id = "req-abc-123";
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
    try std.testing.expect(std.mem.indexOfScalar(u8, replaced_request_id, ' ') == null);
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
    try std.testing.expect(std.mem.indexOf(u8, set_cookie, "HttpOnly") != null);
    try std.testing.expect(std.mem.indexOf(u8, set_cookie, "Secure") != null);
    try std.testing.expect(std.mem.indexOf(u8, set_cookie, "SameSite=Lax") != null);

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
        const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd);
        const unique = std.time.nanoTimestamp();
        const dir_rel = try std.fmt.allocPrint(allocator, ".zig-cache/{s}-{d}", .{ prefix, unique });
        errdefer allocator.free(dir_rel);
        try std.fs.cwd().makePath(dir_rel);
        errdefer std.fs.cwd().deleteTree(dir_rel) catch {};
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
        if (std.fs.path.dirname(rel)) |parent| try std.fs.cwd().makePath(parent);
        try std.fs.cwd().writeFile(.{ .sub_path = rel, .data = data });
    }

    fn deinit(self: *GenericFixtureDir) void {
        std.fs.cwd().deleteTree(self.dir_rel) catch {};
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
    std.time.sleep(300 * std.time.ns_per_ms);

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
    std.time.sleep(300 * std.time.ns_per_ms);

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
    try std.fs.symLinkAbsolute(secret_abs, symlink_abs, .{});

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
