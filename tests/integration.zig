const std = @import("std");
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
    upstream_port: ?u16 = null,
    auth_token_hashes: ?[]const u8 = valid_bearer_hash,
    rate_limit_rps: ?[]const u8 = "1000",
    rate_limit_burst: ?[]const u8 = "1000",
    config_text: ?[]const u8 = null,
    extra_env: []const EnvPair = &.{},
    ready_proxy_ip: ?[]const u8 = null,
    ready_https_insecure: bool = false,
    ready_client_cert: ?[]const u8 = null,
    ready_client_key: ?[]const u8 = null,
    ready_status_code: u16 = 200,
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

const TardigradeProcess = struct {
    allocator: std.mem.Allocator,
    child: std.process.Child,
    port: u16,
    log_path: []u8,
    config_path: ?[]u8,

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
        try env_map.put("TARDIGRADE_LISTEN_HOST", test_host);
        try env_map.put("TARDIGRADE_LISTEN_PORT", port_str);
        try env_map.put("TARDIGRADE_ERROR_LOG_PATH", log_path);
        try env_map.put("TARDIGRADE_WORKER_THREADS", "1");

        if (options.upstream_port) |upstream_port| {
            const upstream_url = try std.fmt.allocPrint(allocator, "http://{s}:{d}", .{ test_host, upstream_port });
            defer allocator.free(upstream_url);
            try env_map.put("TARDIGRADE_UPSTREAM_BASE_URL", upstream_url);
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

        var config_path: ?[]u8 = null;
        if (options.config_text) |config_text| {
            const cfg_path = try std.fmt.allocPrint(allocator, ".zig-cache/tardigrade-config-{d}.conf", .{port});
            errdefer allocator.free(cfg_path);
            try std.fs.cwd().writeFile(.{ .sub_path = cfg_path, .data = config_text });
            try env_map.put("TARDIGRADE_CONFIG_PATH", cfg_path);
            config_path = cfg_path;
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
        };
        errdefer proc.stop();
        try waitUntilReady(port, log_path, options);
        return proc;
    }

    fn stop(self: *TardigradeProcess) void {
        _ = self.child.kill() catch {};
        _ = self.child.wait() catch {};
        self.allocator.free(self.log_path);
        if (self.config_path) |path| self.allocator.free(path);
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
            .headers = &.{ .{ .name = "Content-Type", .value = "application/json" } },
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

fn waitUntilReady(port: u16, log_path: []const u8, options: TardigradeOptions) !void {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        if (options.ready_https_insecure) {
            var resp = sendCurlRequest(std.testing.allocator, port, .{
                .scheme = "https",
                .path = "/health",
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
            if (resp.status_code == options.ready_status_code) return;
        } else {
            var resp = sendRequest(std.testing.allocator, port, .{
                .method = "GET",
                .path = "/health",
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
            if (resp.status_code == options.ready_status_code) return;
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
    return .{ .upstream_port = upstream_port };
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
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"message\":\"hello upstream\"}",
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    var tardigrade = try TardigradeProcess.start(allocator, baseOptions(upstream.port()));
    defer tardigrade.stop();

    var health = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/health", .body = null, .headers = &.{} });
    defer health.deinit();
    try std.testing.expectEqual(@as(u16, 200), health.status_code);
    try std.testing.expectEqualStrings("application/json", health.header("Content-Type").?);
    try assertContains(health.body, "\"status\":\"ok\"");

    var metrics = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/metrics", .body = null, .headers = &.{} });
    defer metrics.deinit();
    try std.testing.expectEqual(@as(u16, 200), metrics.status_code);
    try std.testing.expectEqualStrings("text/plain; version=0.0.4; charset=utf-8", metrics.header("Content-Type").?);
    try assertContains(metrics.body, "tardigrade_requests_total");

    var unauthorized = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    });
    defer unauthorized.deinit();
    try std.testing.expectEqual(@as(u16, 401), unauthorized.status_code);
    try assertContains(unauthorized.body, "\"code\":\"unauthorized\"");

    var bad_token = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer wrong-token" },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer bad_token.deinit();
    try std.testing.expectEqual(@as(u16, 401), bad_token.status_code);

    const correlation_id = "req-integration-123";
    var proxied = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"hello upstream\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "X-Correlation-ID", .value = correlation_id },
        },
    });
    defer proxied.deinit();
    try std.testing.expectEqual(@as(u16, 200), proxied.status_code);
    try std.testing.expectEqualStrings(correlation_id, proxied.header("X-Correlation-ID").?);
    try assertContains(proxied.body, "hello upstream");

    upstream.mutex.lock();
    defer upstream.mutex.unlock();
    try std.testing.expectEqual(@as(u32, 1), upstream.capture.request_count);
    try std.testing.expectEqualStrings("POST", upstream.capture.method);
    try std.testing.expectEqualStrings("/v1/chat", upstream.capture.path);
    try std.testing.expectEqualStrings(correlation_id, upstream.capture.correlation_id);

    var invalid_json = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{not-json}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer invalid_json.deinit();
    try std.testing.expectEqual(@as(u16, 400), invalid_json.status_code);
    try assertContains(invalid_json.body, "\"code\":\"invalid_request\"");

    var explicit_corr = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/health",
        .body = null,
        .headers = &.{.{ .name = "X-Correlation-ID", .value = "req-health-explicit" }},
    });
    defer explicit_corr.deinit();
    try std.testing.expectEqualStrings("req-health-explicit", explicit_corr.header("X-Correlation-ID").?);

    var generated_corr = try sendRequest(allocator, tardigrade.port, .{ .method = "GET", .path = "/health", .body = null, .headers = &.{} });
    defer generated_corr.deinit();
    const generated = generated_corr.header("X-Correlation-ID") orelse return error.MissingCorrelationId;
    try std.testing.expect(std.mem.startsWith(u8, generated, "tg-"));
}

test "jwt auth integration covers valid expired and issuer mismatch tokens" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"jwt\":true}",
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .auth_token_hashes = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_JWT_SECRET", .value = "jwt-secret" },
            .{ .name = "TARDIGRADE_JWT_ISSUER", .value = "issuer-a" },
            .{ .name = "TARDIGRADE_JWT_AUDIENCE", .value = "aud-a" },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    const valid_payload = "{\"sub\":\"user-1\",\"iss\":\"issuer-a\",\"aud\":\"aud-a\",\"exp\":4102444800}";
    const expired_payload = "{\"sub\":\"user-1\",\"iss\":\"issuer-a\",\"aud\":\"aud-a\",\"exp\":1}";
    const wrong_issuer_payload = "{\"sub\":\"user-1\",\"iss\":\"issuer-b\",\"aud\":\"aud-a\",\"exp\":4102444800}";
    const valid_jwt = try hs256Jwt(allocator, "jwt-secret", valid_payload);
    defer allocator.free(valid_jwt);
    const expired_jwt = try hs256Jwt(allocator, "jwt-secret", expired_payload);
    defer allocator.free(expired_jwt);
    const wrong_issuer_jwt = try hs256Jwt(allocator, "jwt-secret", wrong_issuer_payload);
    defer allocator.free(wrong_issuer_jwt);
    const valid_auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{valid_jwt});
    defer allocator.free(valid_auth);

    var valid_resp = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"jwt works\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = valid_auth },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer valid_resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), valid_resp.status_code);

    const expired_auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{expired_jwt});
    defer allocator.free(expired_auth);
    var expired_resp = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"expired\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = expired_auth },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer expired_resp.deinit();
    try std.testing.expectEqual(@as(u16, 401), expired_resp.status_code);

    const wrong_issuer_auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{wrong_issuer_jwt});
    defer allocator.free(wrong_issuer_auth);
    var wrong_issuer_resp = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"wrong issuer\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = wrong_issuer_auth },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer wrong_issuer_resp.deinit();
    try std.testing.expectEqual(@as(u16, 401), wrong_issuer_resp.status_code);
}

test "device auth and session integration cover register create use revoke" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"message\":\"authorized\"}",
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const registry_path = try std.fmt.allocPrint(allocator, ".zig-cache/device-registry-{d}.txt", .{std.time.nanoTimestamp()});
    defer allocator.free(registry_path);

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_DEVICE_REGISTRY_PATH", .value = registry_path },
            .{ .name = "TARDIGRADE_DEVICE_AUTH_REQUIRED", .value = "true" },
            .{ .name = "TARDIGRADE_SESSION_TTL", .value = "3600" },
            .{ .name = "TARDIGRADE_SESSION_MAX", .value = "10" },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var missing_device = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"no device\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer missing_device.deinit();
    try std.testing.expectEqual(@as(u16, 401), missing_device.status_code);

    var register_resp = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/devices/register",
        .body = "{\"device_id\":\"device-1\",\"public_key\":\"shared-device-key\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer register_resp.deinit();
    try std.testing.expectEqual(@as(u16, 201), register_resp.status_code);

    const chat_body = "{\"message\":\"device auth\"}";
    const session_create_body = "{\"device_id\":\"device-1\"}";

    var device_resp: HttpResponse = undefined;
    var device_ok = false;
    var chat_ts_keep: ?[]u8 = null;
    var chat_sig_keep: ?[]u8 = null;
    defer {
        if (chat_ts_keep) |value| allocator.free(value);
        if (chat_sig_keep) |value| allocator.free(value);
    }
    for (0..5) |_| {
        const ts_str = try std.fmt.allocPrint(allocator, "{d}", .{std.time.timestamp()});
        const signature = try deviceSignature(allocator, "shared-device-key", "POST", "/v1/chat", ts_str, chat_body);
        device_resp = try sendRequest(allocator, tardigrade.port, .{
            .method = "POST",
            .path = "/v1/chat",
            .body = chat_body,
            .headers = &.{
                .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "X-Device-ID", .value = "device-1" },
                .{ .name = "X-Device-Timestamp", .value = ts_str },
                .{ .name = "X-Device-Signature", .value = signature },
            },
        });
        if (device_resp.status_code == 200) {
            chat_ts_keep = ts_str;
            chat_sig_keep = signature;
            device_ok = true;
            break;
        }
        allocator.free(ts_str);
        allocator.free(signature);
        device_resp.deinit();
        std.time.sleep(100 * std.time.ns_per_ms);
    }
    try std.testing.expect(device_ok);
    defer device_resp.deinit();
    try std.testing.expectEqual(@as(u16, 200), device_resp.status_code);

    const session_create_ts = try std.fmt.allocPrint(allocator, "{d}", .{std.time.timestamp()});
    defer allocator.free(session_create_ts);
    const session_create_sig = try deviceSignature(allocator, "shared-device-key", "POST", "/v1/sessions", session_create_ts, session_create_body);
    defer allocator.free(session_create_sig);

    var session_create = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/sessions",
        .body = session_create_body,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "X-Device-ID", .value = "device-1" },
            .{ .name = "X-Device-Timestamp", .value = session_create_ts },
            .{ .name = "X-Device-Signature", .value = session_create_sig },
        },
    });
    defer session_create.deinit();
    try std.testing.expectEqual(@as(u16, 201), session_create.status_code);
    const session_token = session_create.header("X-Session-Token") orelse return error.MissingSessionToken;
    const owned_session_token = try allocator.dupe(u8, session_token);
    defer allocator.free(owned_session_token);

    var session_chat = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = chat_body,
        .headers = &.{
            .{ .name = "X-Session-Token", .value = owned_session_token },
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "X-Device-ID", .value = "device-1" },
            .{ .name = "X-Device-Timestamp", .value = chat_ts_keep.? },
            .{ .name = "X-Device-Signature", .value = chat_sig_keep.? },
        },
    });
    defer session_chat.deinit();
    try std.testing.expectEqual(@as(u16, 200), session_chat.status_code);

    const revoke_ts = try std.fmt.allocPrint(allocator, "{d}", .{std.time.timestamp()});
    defer allocator.free(revoke_ts);
    const revoke_sig = try deviceSignature(allocator, "shared-device-key", "DELETE", "/v1/sessions", revoke_ts, "");
    defer allocator.free(revoke_sig);

    var revoke = try sendRequest(allocator, tardigrade.port, .{
        .method = "DELETE",
        .path = "/v1/sessions",
        .body = null,
        .headers = &.{
            .{ .name = "X-Session-Token", .value = owned_session_token },
            .{ .name = "X-Device-ID", .value = "device-1" },
            .{ .name = "X-Device-Timestamp", .value = revoke_ts },
            .{ .name = "X-Device-Signature", .value = revoke_sig },
        },
    });
    defer revoke.deinit();
    try std.testing.expectEqual(@as(u16, 200), revoke.status_code);
    try assertContains(revoke.body, "\"revoked\":true");

    var revoked_chat = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = chat_body,
        .headers = &.{
            .{ .name = "X-Session-Token", .value = owned_session_token },
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "X-Device-ID", .value = "device-1" },
            .{ .name = "X-Device-Timestamp", .value = chat_ts_keep.? },
            .{ .name = "X-Device-Signature", .value = chat_sig_keep.? },
        },
    });
    defer revoked_chat.deinit();
    try std.testing.expectEqual(@as(u16, 401), revoked_chat.status_code);
}

test "rate limiter integration covers retry-after reset and per-ip isolation" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true}",
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .rate_limit_rps = "1",
        .rate_limit_burst = "1",
        .extra_env = &.{.{ .name = "TARDIGRADE_PROXY_PROTOCOL", .value = "v1" }},
        .ready_proxy_ip = "10.0.0.254",
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var first = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"rate one\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .proxy_ip = "10.0.0.1",
    });
    defer first.deinit();
    try std.testing.expectEqual(@as(u16, 200), first.status_code);

    var second = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"rate two\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .proxy_ip = "10.0.0.1",
    });
    defer second.deinit();
    try std.testing.expectEqual(@as(u16, 429), second.status_code);
    try std.testing.expectEqualStrings("1", second.header("Retry-After").?);

    var other_ip = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"rate other ip\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .proxy_ip = "10.0.0.2",
    });
    defer other_ip.deinit();
    try std.testing.expectEqual(@as(u16, 200), other_ip.status_code);

    std.time.sleep(1100 * std.time.ns_per_ms);

    var third = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"rate reset\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .proxy_ip = "10.0.0.1",
    });
    defer third.deinit();
    try std.testing.expectEqual(@as(u16, 200), third.status_code);
}

test "active health integration marks a failing upstream down and reroutes traffic" {
    const allocator = std.testing.allocator;

    const failing_responses = [_]UpstreamResponseSpec{.{
        .status_code = 503,
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"backend\":\"bad\"}",
    }};
    const healthy_responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"backend\":\"good\"}",
    }};
    var bad_upstream = try UpstreamServer.start(allocator, &failing_responses);
    defer bad_upstream.stop();
    try bad_upstream.run();
    var good_upstream = try UpstreamServer.start(allocator, &healthy_responses);
    defer good_upstream.stop();
    try good_upstream.run();

    const upstream_urls = try std.fmt.allocPrint(
        allocator,
        "http://{s}:{d},http://{s}:{d}",
        .{ test_host, bad_upstream.port(), test_host, good_upstream.port() },
    );
    defer allocator.free(upstream_urls);
    const bad_url = try std.fmt.allocPrint(allocator, "http://{s}:{d}", .{ test_host, bad_upstream.port() });
    defer allocator.free(bad_url);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_BASE_URLS", .value = upstream_urls },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_INTERVAL_MS", .value = "100" },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_TIMEOUT_MS", .value = "200" },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_THRESHOLD", .value = "2" },
            .{ .name = "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_THRESHOLD", .value = "2" },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    const down_needle = try std.fmt.allocPrint(allocator, "\"url\":\"{s}\",\"healthy\":false", .{bad_url});
    defer allocator.free(down_needle);
    try waitForBodyContains(allocator, tardigrade.port, "/admin/upstreams", &.{
        .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
    }, down_needle, 3000);

    var health = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/health",
        .body = null,
        .headers = &.{},
    });
    defer health.deinit();
    try assertContains(health.body, "\"upstream_status\":\"degraded\"");
    try assertContains(health.body, "\"upstream_unhealthy_backends\":1");

    try bad_upstream.resetCapture();
    try good_upstream.resetCapture();

    var chat = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"route around down backend\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer chat.deinit();
    try std.testing.expectEqual(@as(u16, 200), chat.status_code);
    try assertContains(chat.body, "\"backend\":\"good\"");

    std.time.sleep(250 * std.time.ns_per_ms);

    {
        bad_upstream.mutex.lock();
        defer bad_upstream.mutex.unlock();
        for (bad_upstream.capture.path_history.items) |path| {
            try std.testing.expect(!std.mem.eql(u8, path, "/v1/chat"));
        }
    }
    var good_saw_chat = false;
    {
        good_upstream.mutex.lock();
        defer good_upstream.mutex.unlock();
        for (good_upstream.capture.path_history.items) |path| {
            if (std.mem.eql(u8, path, "/v1/chat")) good_saw_chat = true;
        }
    }
    try std.testing.expect(good_saw_chat);
}

test "active health integration marks a recovered upstream back up after probe successes" {
    const allocator = std.testing.allocator;

    var failing_responses = [_]UpstreamResponseSpec{.{
        .status_code = 503,
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"backend\":\"recovering\"}",
    }};
    const healthy_responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"backend\":\"stable\"}",
    }};
    var recovering_upstream = try UpstreamServer.start(allocator, &failing_responses);
    defer recovering_upstream.stop();
    try recovering_upstream.run();
    var stable_upstream = try UpstreamServer.start(allocator, &healthy_responses);
    defer stable_upstream.stop();
    try stable_upstream.run();

    const upstream_urls = try std.fmt.allocPrint(
        allocator,
        "http://{s}:{d},http://{s}:{d}",
        .{ test_host, recovering_upstream.port(), test_host, stable_upstream.port() },
    );
    defer allocator.free(upstream_urls);
    const recovering_url = try std.fmt.allocPrint(allocator, "http://{s}:{d}", .{ test_host, recovering_upstream.port() });
    defer allocator.free(recovering_url);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_BASE_URLS", .value = upstream_urls },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_INTERVAL_MS", .value = "100" },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_TIMEOUT_MS", .value = "200" },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_THRESHOLD", .value = "2" },
            .{ .name = "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_THRESHOLD", .value = "2" },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    const down_needle = try std.fmt.allocPrint(allocator, "\"url\":\"{s}\",\"healthy\":false", .{recovering_url});
    defer allocator.free(down_needle);
    try waitForBodyContains(allocator, tardigrade.port, "/admin/upstreams", &.{
        .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
    }, down_needle, 3000);

    const recovered_responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"backend\":\"recovering\"}",
    }};
    failing_responses[0] = recovered_responses[0];
    recovering_upstream.setResponses(&failing_responses);

    const up_needle = try std.fmt.allocPrint(
        allocator,
        "\"url\":\"{s}\",\"healthy\":true,\"unhealthy_until_ms\":0,\"active_status\":\"up\"",
        .{recovering_url},
    );
    defer allocator.free(up_needle);
    try waitForBodyContains(allocator, tardigrade.port, "/admin/upstreams", &.{
        .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
    }, up_needle, 4000);

    try recovering_upstream.resetCapture();
    var attempts: usize = 0;
    while (attempts < 6) : (attempts += 1) {
        var chat = try sendRequest(allocator, tardigrade.port, .{
            .method = "POST",
            .path = "/v1/chat",
            .body = "{\"message\":\"recovered backend should return\"}",
            .headers = &.{
                .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
                .{ .name = "Content-Type", .value = "application/json" },
            },
        });
        defer chat.deinit();
        try std.testing.expectEqual(@as(u16, 200), chat.status_code);
    }

    recovering_upstream.mutex.lock();
    defer recovering_upstream.mutex.unlock();
    var saw_chat = false;
    for (recovering_upstream.capture.path_history.items) |path| {
        if (std.mem.eql(u8, path, "/v1/chat")) saw_chat = true;
    }
    try std.testing.expect(saw_chat);
}

test "active health integration honors per-upstream success status overrides" {
    const allocator = std.testing.allocator;

    const not_modified_responses = [_]UpstreamResponseSpec{.{
        .status_code = 304,
        .body = "",
    }};
    var override_upstream = try UpstreamServer.start(allocator, &not_modified_responses);
    defer override_upstream.stop();
    try override_upstream.run();
    var default_upstream = try UpstreamServer.start(allocator, &not_modified_responses);
    defer default_upstream.stop();
    try default_upstream.run();

    const upstream_urls = try std.fmt.allocPrint(
        allocator,
        "http://{s}:{d},http://{s}:{d}",
        .{ test_host, override_upstream.port(), test_host, default_upstream.port() },
    );
    defer allocator.free(upstream_urls);
    const override_url = try std.fmt.allocPrint(allocator, "http://{s}:{d}", .{ test_host, override_upstream.port() });
    defer allocator.free(override_url);
    const default_url = try std.fmt.allocPrint(allocator, "http://{s}:{d}", .{ test_host, default_upstream.port() });
    defer allocator.free(default_url);
    const overrides = try std.fmt.allocPrint(allocator, "{s}|304", .{override_url});
    defer allocator.free(overrides);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UPSTREAM_BASE_URLS", .value = upstream_urls },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_INTERVAL_MS", .value = "100" },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_TIMEOUT_MS", .value = "200" },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_THRESHOLD", .value = "1" },
            .{ .name = "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_THRESHOLD", .value = "1" },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_SUCCESS_STATUS_OVERRIDES", .value = overrides },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    const override_ok = try std.fmt.allocPrint(
        allocator,
        "\"url\":\"{s}\",\"healthy\":true,\"unhealthy_until_ms\":0,\"active_status\":\"up\"",
        .{override_url},
    );
    defer allocator.free(override_ok);
    try waitForBodyContains(allocator, tardigrade.port, "/admin/upstreams", &.{
        .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
    }, override_ok, 3000);

    const default_down = try std.fmt.allocPrint(allocator, "\"url\":\"{s}\",\"healthy\":false", .{default_url});
    defer allocator.free(default_down);
    try waitForBodyContains(allocator, tardigrade.port, "/admin/upstreams", &.{
        .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
    }, default_down, 3000);
}

test "proxy cache integration covers hit and stale revalidation" {
    const allocator = std.testing.allocator;

    const cache_headers = [_]ResponseHeader{.{ .name = "Content-Type", .value = "application/json" }};
    const first_plan = [_]UpstreamResponseSpec{.{ .headers = &cache_headers, .body = "{\"version\":1}" }, .{ .headers = &cache_headers, .body = "{\"version\":2}" }};
    var upstream = try UpstreamServer.start(allocator, &first_plan);
    defer upstream.stop();
    try upstream.run();

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_CACHE_TTL_SECONDS", .value = "1" },
            .{ .name = "TARDIGRADE_PROXY_CACHE_STALE_WHILE_REVALIDATE_SECONDS", .value = "5" },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    try upstream.resetCapture();
    var fresh = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"cache me\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer fresh.deinit();
    try std.testing.expectEqual(@as(u16, 200), fresh.status_code);
    try assertContains(fresh.body, "\"version\":1");

    var hit = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"cache me\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer hit.deinit();
    try std.testing.expectEqual(@as(u16, 200), hit.status_code);
    if (hit.header("X-Proxy-Cache")) |cache_header| {
        try std.testing.expectEqualStrings("HIT", cache_header);
    }
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    std.time.sleep(1100 * std.time.ns_per_ms);

    var stale = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"cache me\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer stale.deinit();
    try std.testing.expectEqual(@as(u16, 200), stale.status_code);
    try std.testing.expectEqualStrings("STALE", stale.header("X-Proxy-Cache").?);
    try assertContains(stale.body, "\"version\":1");

    try waitForUpstreamCount(&upstream, 2, 1000);
    std.time.sleep(200 * std.time.ns_per_ms);

    var refreshed = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"cache me\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer refreshed.deinit();
    try std.testing.expectEqual(@as(u16, 200), refreshed.status_code);
    try assertContains(refreshed.body, "\"version\":2");
}

test "proxy integration forwards upstream path headers and transformed body" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"forwarded\":true}",
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{.{ .name = "TARDIGRADE_PROXY_PROTOCOL", .value = "v1" }},
        .ready_proxy_ip = "10.9.0.254",
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    const correlation_id = "proxy-forward-123";
    var proxied = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"forward me\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "Host", .value = "public.example.test" },
            .{ .name = "X-Correlation-ID", .value = correlation_id },
            .{ .name = "X-Forwarded-For", .value = "198.51.100.7" },
        },
        .proxy_ip = "10.9.0.1",
    });
    defer proxied.deinit();
    try std.testing.expectEqual(@as(u16, 200), proxied.status_code);
    try assertContains(proxied.body, "\"forwarded\":true");

    upstream.mutex.lock();
    defer upstream.mutex.unlock();
    try std.testing.expectEqual(@as(u32, 1), upstream.capture.request_count);
    try std.testing.expectEqualStrings("POST", upstream.capture.method);
    try std.testing.expectEqualStrings("/v1/chat", upstream.capture.path);
    try std.testing.expectEqualStrings("{\"message\":\"forward me\"}", upstream.capture.body);
    try std.testing.expectEqualStrings(correlation_id, upstream.capture.correlation_id);
    try std.testing.expectEqualStrings("198.51.100.7, 198.51.100.7", headerValue(upstream.capture.headers_raw, "X-Forwarded-For").?);
    try std.testing.expectEqualStrings("198.51.100.7", headerValue(upstream.capture.headers_raw, "X-Real-IP").?);
    try std.testing.expectEqualStrings("public.example.test", headerValue(upstream.capture.headers_raw, "X-Forwarded-Host").?);
    try std.testing.expectEqualStrings(valid_bearer_hash, headerValue(upstream.capture.headers_raw, "X-Tardigrade-Auth-Identity").?);
}

test "proxy cache integration skips caching upstream no-store responses" {
    const allocator = std.testing.allocator;

    const cache_headers = [_]ResponseHeader{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "Cache-Control", .value = "no-store" },
    };
    const responses = [_]UpstreamResponseSpec{
        .{ .headers = &cache_headers, .body = "{\"version\":1}" },
        .{ .headers = &cache_headers, .body = "{\"version\":2}" },
    };
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_PROXY_CACHE_TTL_SECONDS", .value = "30" },
            .{ .name = "TARDIGRADE_PROXY_CACHE_STALE_WHILE_REVALIDATE_SECONDS", .value = "30" },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var first = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"dont cache\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer first.deinit();
    try std.testing.expectEqual(@as(u16, 200), first.status_code);
    try assertContains(first.body, "\"version\":1");

    var second = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"dont cache\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer second.deinit();
    try std.testing.expectEqual(@as(u16, 200), second.status_code);
    try assertContains(second.body, "\"version\":2");
    try std.testing.expect(upstream.requestCount() >= 2);
    try std.testing.expect(second.header("X-Proxy-Cache") == null);
}

test "proxy integration retries once on upstream 5xx" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{
        .{
            .status_code = 502,
            .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
            .body = "{\"error\":\"temporary\"}",
        },
        .{
            .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
            .body = "{\"retried\":true}",
        },
    };
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{.{ .name = "TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS", .value = "2" }},
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"retry me\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "\"retried\":true");
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());
}

test "proxy integration follows a single upstream redirect" {
    const allocator = std.testing.allocator;

    const redirect_headers = [_]ResponseHeader{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "Location", .value = "http://127.0.0.1:1/v1/chat/final" },
    };
    var location_buf: [128]u8 = undefined;

    const first = UpstreamResponseSpec{
        .status_code = 307,
        .headers = &redirect_headers,
        .body = "",
    };
    const second = UpstreamResponseSpec{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"redirected\":true}",
    };
    var responses = [_]UpstreamResponseSpec{ first, second };
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const location = try std.fmt.bufPrint(&location_buf, "http://{s}:{d}/v1/chat/final", .{ test_host, upstream.port() });
    responses[0].headers = &.{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "Location", .value = location },
    };
    upstream.setResponses(&responses);

    var tardigrade = try TardigradeProcess.start(allocator, baseOptions(upstream.port()));
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"follow redirect\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "\"redirected\":true");
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());
    upstream.mutex.lock();
    defer upstream.mutex.unlock();
    try std.testing.expectEqualStrings("/v1/chat/final", upstream.capture.path);
}

test "fastcgi integration returns parsed response and forwards cgi env" {
    const allocator = std.testing.allocator;

    const responses = [_]FastCgiResponseSpec{
        .{
            .status_code = 201,
            .headers = &.{
                .{ .name = "Content-Type", .value = "text/plain; charset=utf-8" },
                .{ .name = "X-FastCGI-Reply", .value = "ok" },
            },
            .body = "hello-fastcgi",
        },
    };
    var fcgi = try FastCgiServer.start(allocator, &responses);
    defer fcgi.stop();
    try fcgi.run();

    const upstream = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ test_host, fcgi.port() });
    defer allocator.free(upstream);
    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_FASTCGI_UPSTREAM", .value = upstream },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/backend/fastcgi?name=tardi",
        .body = "{\"hello\":true}",
        .headers = &.{
            .{ .name = "Host", .value = "gateway.integration.test:9000" },
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "X-Real-IP", .value = "127.0.0.1" },
            .{ .name = "X-FastCGI-Script-Filename", .value = "/srv/app.php" },
            .{ .name = "X-FastCGI-Path-Info", .value = "/index.php" },
            .{ .name = "X-Correlation-ID", .value = "fcgi-req-123" },
        },
    });
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 201), response.status_code);
    try std.testing.expectEqualStrings("text/plain; charset=utf-8", response.header("Content-Type").?);
    try std.testing.expectEqualStrings("ok", response.header("X-FastCGI-Reply").?);
    try assertContains(response.body, "hello-fastcgi");

    fcgi.mutex.lock();
    defer fcgi.mutex.unlock();
    try assertContains(fcgi.capture.raw, "REQUEST_METHODPOST");
    try assertContains(fcgi.capture.raw, "SCRIPT_FILENAME/srv/app.php");
    try assertContains(fcgi.capture.raw, "QUERY_STRINGname=tardi");
    try assertContains(fcgi.capture.raw, "CONTENT_TYPEapplication/json");
    try assertContains(fcgi.capture.raw, "REMOTE_ADDR127.0.0.1");
    try assertContains(fcgi.capture.raw, "SERVER_NAMEgateway.integration.test");
    try assertContains(fcgi.capture.raw, "HTTP_X_CORRELATION_IDfcgi-req-123");
}

test "fastcgi integration logs stderr and maps non-zero end_request to 502" {
    const allocator = std.testing.allocator;

    const responses = [_]FastCgiResponseSpec{
        .{
            .status_code = 200,
            .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
            .body = "ignored",
            .stderr = "php warning: boom",
            .app_status = 1,
        },
    };
    var fcgi = try FastCgiServer.start(allocator, &responses);
    defer fcgi.stop();
    try fcgi.run();

    const upstream = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ test_host, fcgi.port() });
    defer allocator.free(upstream);
    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_FASTCGI_UPSTREAM", .value = upstream },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/backend/fastcgi",
        .body = "{}",
        .headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 502), response.status_code);

    std.time.sleep(100 * std.time.ns_per_ms);
    const log_data = try std.fs.cwd().readFileAlloc(allocator, tardigrade.log_path, 256 * 1024);
    defer allocator.free(log_data);
    try assertContains(log_data, "fastcgi stderr");
    try assertContains(log_data, "php warning: boom");
    try assertContains(log_data, "fastcgi end_request failure");
}

test "fastcgi integration reuses upstream connection across sequential requests" {
    const allocator = std.testing.allocator;

    const responses = [_]FastCgiResponseSpec{
        .{ .body = "first" },
        .{ .body = "second" },
    };
    var fcgi = try FastCgiServer.start(allocator, &responses);
    defer fcgi.stop();
    try fcgi.run();

    const upstream = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ test_host, fcgi.port() });
    defer allocator.free(upstream);
    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_FASTCGI_UPSTREAM", .value = upstream },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var first = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/backend/fastcgi",
        .body = "one",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    });
    defer first.deinit();
    try std.testing.expectEqual(@as(u16, 200), first.status_code);
    try assertContains(first.body, "first");

    var second = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/backend/fastcgi",
        .body = "two",
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    });
    defer second.deinit();
    try std.testing.expectEqual(@as(u16, 200), second.status_code);
    try assertContains(second.body, "second");

    fcgi.mutex.lock();
    defer fcgi.mutex.unlock();
    try std.testing.expectEqual(@as(u32, 2), fcgi.capture.request_count);
    try std.testing.expectEqual(@as(u32, 1), fcgi.accepted_connections);
    try std.testing.expectEqual(@as(u16, 2), fcgi.capture.last_request_id);
}

test "fastcgi config directives drive upstream params and index defaults" {
    const allocator = std.testing.allocator;

    const responses = [_]FastCgiResponseSpec{
        .{ .body = "config-fastcgi" },
    };
    var fcgi = try FastCgiServer.start(allocator, &responses);
    defer fcgi.stop();
    try fcgi.run();

    const upstream = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ test_host, fcgi.port() });
    defer allocator.free(upstream);
    const config_text = try std.fmt.allocPrint(
        allocator,
        \\root /srv/www;
        \\fastcgi_pass {s};
        \\fastcgi_param APP_ENV production;
        \\fastcgi_param APP_ROLE api;
        \\fastcgi_index home.php;
        \\scgi_pass 127.0.0.1:4100;
        \\uwsgi_pass 127.0.0.1:4200;
    ,
        .{upstream},
    );
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .upstream_port = null,
        .config_text = config_text,
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/backend/fastcgi?name=config",
        .body = "{\"cfg\":true}",
        .headers = &.{
            .{ .name = "Host", .value = "gateway.integration.test" },
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "X-FastCGI-Path-Info", .value = "/app/" },
        },
    });
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "config-fastcgi");

    fcgi.mutex.lock();
    defer fcgi.mutex.unlock();
    try assertContains(fcgi.capture.raw, "SCRIPT_FILENAME/srv/www/app/home.php");
    try assertContains(fcgi.capture.raw, "DOCUMENT_ROOT/srv/www");
    try assertContains(fcgi.capture.raw, "APP_ENVproduction");
    try assertContains(fcgi.capture.raw, "APP_ROLEapi");
}

test "fastcgi integration with real php-fpm socket returns parsed response" {
    var php_fpm = try PhpFpmProcess.start(std.testing.allocator);
    defer php_fpm.stop();

    const upstream = try std.fmt.allocPrint(std.testing.allocator, "unix:{s}", .{php_fpm.socket_path});
    defer std.testing.allocator.free(upstream);

    var tardigrade = try TardigradeProcess.start(std.testing.allocator, .{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_FASTCGI_UPSTREAM", .value = upstream },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequest(std.testing.allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/backend/fastcgi?name=real",
        .body = "hello=php",
        .headers = &.{
            .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
            .{ .name = "X-FastCGI-Script-Filename", .value = php_fpm.script_path },
            .{ .name = "X-FastCGI-Script-Name", .value = "/index.php" },
            .{ .name = "X-FastCGI-Path-Info", .value = "/index.php" },
        },
    });
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("application/json", response.header("Content-Type").?);
    try assertContains(response.body, "\"method\":\"POST\"");
    try assertContains(response.body, "\"script\":\"");
    try assertContains(response.body, "\"query\":\"name=real\"");
    try assertContains(response.body, "\"body\":\"hello=php\"");
}

test "rewrite integration transparently rewrites captured path to health" {
    const allocator = std.testing.allocator;

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_REWRITE_RULES", .value = "GET|^/old/(.*)$|/$1|last" },
        },
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/old/health",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("application/json", response.header("Content-Type").?);
    try assertContains(response.body, "\"status\":\"ok\"");
}

test "rewrite config directive rewrites captured path to health" {
    const allocator = std.testing.allocator;

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .upstream_port = null,
        .config_text = "rewrite ^/legacy/(.*)$ /$1 last;",
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/legacy/health",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "\"status\":\"ok\"");
}

test "return config directive issues redirect with request_uri expansion" {
    const allocator = std.testing.allocator;

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .upstream_port = null,
        .config_text = "return 301 https://example.com$request_uri;",
        .ready_status_code = 301,
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/legacy/path?x=1",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 301), response.status_code);
    try std.testing.expectEqualStrings("https://example.com/legacy/path?x=1", response.header("Location").?);
}

test "if rewrite directive rewrites request_uri match transparently" {
    const allocator = std.testing.allocator;

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .upstream_port = null,
        .config_text = "if ($request_uri ~* ^/legacy/(.*)$) rewrite /$1 last;",
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/legacy/health",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "\"status\":\"ok\"");
}

test "if return directive redirects on host match" {
    const allocator = std.testing.allocator;

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .upstream_port = null,
        .config_text = "if ($http_host ~* ^admin\\.example\\.com$) return 301 https://example.com$request_uri;",
    });
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/health?x=1",
        .body = null,
        .headers = &.{.{ .name = "Host", .value = "Admin.Example.Com" }},
    });
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 301), response.status_code);
    try std.testing.expectEqualStrings("https://example.com/health?x=1", response.header("Location").?);
}

test "scgi integration returns parsed response and forwards cgi env" {
    const allocator = std.testing.allocator;

    const responses = [_]ScgiResponseSpec{
        .{
            .status_code = 202,
            .headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "X-SCGI-Reply", .value = "ok" },
            },
            .body = "{\"scgi\":true}",
            .http_status_line = true,
        },
    };
    var scgi = try ScgiServer.start(allocator, &responses);
    defer scgi.stop();
    try scgi.run();

    const upstream = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ test_host, scgi.port() });
    defer allocator.free(upstream);
    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_SCGI_UPSTREAM", .value = upstream },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/backend/scgi?name=tardi",
        .body = "{\"hello\":true}",
        .headers = &.{
            .{ .name = "Host", .value = "gateway.integration.test:9001" },
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "X-Real-IP", .value = "127.0.0.1" },
            .{ .name = "X-SCGI-Path-Info", .value = "/app" },
            .{ .name = "X-SCGI-Script-Name", .value = "/app" },
            .{ .name = "X-Correlation-ID", .value = "scgi-req-123" },
        },
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 202), response.status_code);
    try std.testing.expectEqualStrings("application/json", response.header("Content-Type").?);
    try std.testing.expectEqualStrings("ok", response.header("X-SCGI-Reply").?);
    try assertContains(response.body, "\"scgi\":true");

    scgi.mutex.lock();
    defer scgi.mutex.unlock();
    try assertContains(scgi.capture.raw, "REQUEST_METHOD\x00POST\x00");
    try assertContains(scgi.capture.raw, "QUERY_STRING\x00name=tardi\x00");
    try assertContains(scgi.capture.raw, "CONTENT_TYPE\x00application/json\x00");
    try assertContains(scgi.capture.raw, "REMOTE_ADDR\x00127.0.0.1\x00");
    try assertContains(scgi.capture.raw, "SERVER_NAME\x00gateway.integration.test\x00");
    try assertContains(scgi.capture.raw, "HTTP_X_CORRELATION_ID\x00scgi-req-123\x00");
}

test "uwsgi integration returns parsed response and forwards vars" {
    const allocator = std.testing.allocator;

    const responses = [_]UwsgiResponseSpec{
        .{
            .status_code = 201,
            .headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
                .{ .name = "X-uWSGI-Reply", .value = "ok" },
            },
            .body = "{\"uwsgi\":true}",
            .http_status_line = true,
        },
    };
    var uwsgi = try UwsgiServer.start(allocator, &responses);
    defer uwsgi.stop();
    try uwsgi.run();

    const upstream = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ test_host, uwsgi.port() });
    defer allocator.free(upstream);
    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UWSGI_UPSTREAM", .value = upstream },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/backend/uwsgi?name=tardi",
        .body = "{\"hello\":true}",
        .headers = &.{
            .{ .name = "Host", .value = "gateway.integration.test:9002" },
            .{ .name = "Content-Type", .value = "application/json" },
            .{ .name = "X-Real-IP", .value = "127.0.0.1" },
            .{ .name = "X-uWSGI-Path-Info", .value = "/app" },
            .{ .name = "X-uWSGI-Script-Name", .value = "/app" },
            .{ .name = "X-Correlation-ID", .value = "uwsgi-req-123" },
        },
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 201), response.status_code);
    try std.testing.expectEqualStrings("application/json", response.header("Content-Type").?);
    try std.testing.expectEqualStrings("ok", response.header("X-uWSGI-Reply").?);
    try assertContains(response.body, "\"uwsgi\":true");

    uwsgi.mutex.lock();
    defer uwsgi.mutex.unlock();
    try assertContains(uwsgi.capture.raw, "REQUEST_METHODPOST");
    try assertContains(uwsgi.capture.raw, "QUERY_STRINGname=tardi");
    try assertContains(uwsgi.capture.raw, "CONTENT_TYPEapplication/json");
    try assertContains(uwsgi.capture.raw, "REMOTE_ADDR127.0.0.1");
    try assertContains(uwsgi.capture.raw, "SERVER_NAMEgateway.integration.test");
    try assertContains(uwsgi.capture.raw, "HTTP_X_CORRELATION_IDuwsgi-req-123");
}

test "uwsgi integration decodes chunked upstream body" {
    const allocator = std.testing.allocator;

    const responses = [_]UwsgiResponseSpec{
        .{
            .status_code = 200,
            .headers = &.{
                .{ .name = "Transfer-Encoding", .value = "chunked" },
                .{ .name = "Content-Type", .value = "text/plain" },
            },
            .body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            .http_status_line = true,
        },
    };
    var uwsgi = try UwsgiServer.start(allocator, &responses);
    defer uwsgi.stop();
    try uwsgi.run();

    const upstream = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ test_host, uwsgi.port() });
    defer allocator.free(upstream);
    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_UWSGI_UPSTREAM", .value = upstream },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/backend/uwsgi",
        .body = "",
        .headers = &.{},
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expect(response.header("Transfer-Encoding") == null);
    try std.testing.expectEqualStrings("hello world", response.body);
}

test "tls integration serves health over https with self-signed certificate" {
    const allocator = std.testing.allocator;

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var response = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/health",
        .insecure = true,
    });
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "\"status\":\"ok\"");
}

test "http3 configured gateway advertises alt-svc on http health responses" {
    const allocator = std.testing.allocator;
    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/health",
        .body = null,
        .headers = &.{},
    });
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    const expected_alt_svc = try std.fmt.allocPrint(allocator, "h3=\":{d}\"", .{quic_port});
    defer allocator.free(expected_alt_svc);
    try std.testing.expectEqualStrings(expected_alt_svc, response.header("Alt-Svc").?);
    try assertContains(response.body, "\"http3_status\":\"config_incomplete\"");
    const expected_quic_port = try std.fmt.allocPrint(allocator, "\"http3_quic_port\":{d}", .{quic_port});
    defer allocator.free(expected_quic_port);
    try assertContains(response.body, expected_quic_port);
    try assertContains(response.body, "\"http3_handshake_state\":\"config_incomplete\"");
    try assertContains(response.body, "\"http3_stream_bytes_received\":0");
    try assertContains(response.body, "\"http3_requests_completed\":0");
    try assertContains(response.body, "\"http3_native_read_calls\":0");
    try assertContains(response.body, "\"http3_last_error_name\":\"-\"");
}

test "http3 integration serves health over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_HTTP3_ENABLE_0RTT", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    var response = try sendHttp3CurlRequest(allocator, quic_port, "/health");
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings(expected_server_header, response.header("server").?);
    const content_length = try std.fmt.parseInt(usize, response.header("content-length").?, 10);
    try std.testing.expect(content_length > 0);
    try assertContains(response.body, "\"status\":\"ok\"");
    try assertContains(response.body, "\"service\":\"tardigrade-edge\"");
}

test "http3 integration resumes session with 0-rtt over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    if (http3_resumption_client_bin_path.len == 0) return error.SkipZigTest;
    if (http3_osslclient_bin_path.len == 0) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_resumption_client_bin_path, .{}) catch return error.SkipZigTest;
    std.fs.accessAbsolute(http3_osslclient_bin_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_HTTP3_ENABLE_0RTT", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    const request_url = try std.fmt.allocPrint(allocator, "https://{s}:{d}/health", .{ test_host, quic_port });
    defer allocator.free(request_url);

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{
            http3_resumption_client_bin_path,
            http3_osslclient_bin_path,
            request_url,
            "200",
        },
        .max_output_bytes = 256 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.UnexpectedTermination,
    }
    try assertContains(result.stdout, "\"warm_status\":200");
    try assertContains(result.stdout, "\"resumed_status\":200");
    try assertContains(result.stdout, "\"resumed_zero_rtt_count\":");
}

test "http3 integration serves prometheus metrics over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    var response = try sendHttp3CurlRequest(allocator, quic_port, "/metrics");
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("text/plain; version=0.0.4; charset=utf-8", response.header("content-type").?);
    try assertContains(response.body, "tardigrade_requests_total");
}

test "http3 integration routes configured location blocks over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const responses = [_]UpstreamResponseSpec{.{ .body = "http3-location-upstream" }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /quic-location {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{ test_host, upstream.port() });
    defer allocator.free(config_text);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .config_text = config_text,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    var response = try sendHttp3CurlRequest(allocator, quic_port, "/quic-location");
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqualStrings("http3-location-upstream", response.body);

    upstream.mutex.lock();
    defer upstream.mutex.unlock();
    try std.testing.expectEqual(@as(u32, 1), upstream.capture.request_count);
    try std.testing.expectEqualStrings("/quic-location", upstream.capture.path);
}

test "http3 integration proxies chat over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"reply\":\"ok\"}",
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    var unauthorized = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/chat",
        .method = "POST",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer unauthorized.deinit();
    try std.testing.expectEqual(@as(u16, 401), unauthorized.status_code);
    try assertContains(unauthorized.body, "\"code\":\"unauthorized\"");

    var authorized = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/chat",
        .method = "POST",
        .body = "{\"message\":\"hello\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer authorized.deinit();
    try std.testing.expectEqual(@as(u16, 200), authorized.status_code);
    try assertContains(authorized.body, "\"reply\":\"ok\"");
    upstream.mutex.lock();
    defer upstream.mutex.unlock();
    try std.testing.expectEqualStrings("/v1/chat", upstream.capture.path);
    try assertContains(upstream.capture.body, "\"message\":\"hello\"");
}

test "http3 integration proxies commands over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"result\":\"ok\"}",
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    const command_body = "{\"command\":\"status\",\"params\":{}}";

    var unauthorized = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/commands",
        .method = "POST",
        .body = command_body,
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer unauthorized.deinit();
    try std.testing.expectEqual(@as(u16, 401), unauthorized.status_code);
    try assertContains(unauthorized.body, "\"code\":\"unauthorized\"");

    var authorized = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/commands",
        .method = "POST",
        .body = command_body,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer authorized.deinit();
    try std.testing.expectEqual(@as(u16, 200), authorized.status_code);
    try assertContains(authorized.body, "\"result\":\"ok\"");
    upstream.mutex.lock();
    defer upstream.mutex.unlock();
    try std.testing.expectEqualStrings("/v1/status", upstream.capture.path);
    try assertContains(upstream.capture.body, "\"command\":\"status\"");
}

test "http3 integration serves command status over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"result\":\"ok\"}",
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    const command_id = "cmd-http3-status";
    const command_body = "{\"command\":\"status\",\"params\":{},\"command_id\":\"" ++ command_id ++ "\"}";

    var execute = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/commands",
        .method = "POST",
        .body = command_body,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer execute.deinit();
    try std.testing.expectEqual(@as(u16, 200), execute.status_code);

    var unauthorized = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/commands/status?command_id=" ++ command_id,
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer unauthorized.deinit();
    try std.testing.expectEqual(@as(u16, 401), unauthorized.status_code);
    try assertContains(unauthorized.body, "\"code\":\"unauthorized\"");

    var status = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/commands/status?command_id=" ++ command_id,
        .headers = &.{.{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer status.deinit();
    try std.testing.expectEqual(@as(u16, 200), status.status_code);
    try assertContains(status.body, "\"command_id\":\"" ++ command_id ++ "\"");
    try assertContains(status.body, "\"status\":\"completed\"");
}

test "http3 integration serves approvals workflow over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
            .{ .name = "TARDIGRADE_POLICY_APPROVAL_ROUTES", .value = "POST|/v1/commands" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    const request_body = "{\"method\":\"POST\",\"path\":\"/v1/commands\",\"command_id\":\"cmd-approval-http3\"}";

    var unauthorized_request = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/approvals/request",
        .method = "POST",
        .body = request_body,
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer unauthorized_request.deinit();
    try std.testing.expectEqual(@as(u16, 401), unauthorized_request.status_code);

    var request_resp = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/approvals/request",
        .method = "POST",
        .body = request_body,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer request_resp.deinit();
    try std.testing.expectEqual(@as(u16, 202), request_resp.status_code);
    const token_key = "\"approval_token\":\"";
    const token_start = std.mem.indexOf(u8, request_resp.body, token_key) orelse return error.InvalidHttpResponse;
    const token_rest = request_resp.body[token_start + token_key.len ..];
    const token_end = std.mem.indexOfScalar(u8, token_rest, '"') orelse return error.InvalidHttpResponse;
    const approval_token = try allocator.dupe(u8, token_rest[0..token_end]);
    defer allocator.free(approval_token);

    const status_path = try std.fmt.allocPrint(allocator, "/v1/approvals/status?approval_token={s}", .{approval_token});
    defer allocator.free(status_path);
    var pending_status = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = status_path,
        .headers = &.{.{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer pending_status.deinit();
    try std.testing.expectEqual(@as(u16, 200), pending_status.status_code);
    try assertContains(pending_status.body, "\"status\":\"pending\"");

    const respond_body = try std.fmt.allocPrint(allocator, "{{\"approval_token\":\"{s}\",\"decision\":\"approve\"}}", .{approval_token});
    defer allocator.free(respond_body);
    var respond = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/approvals/respond",
        .method = "POST",
        .body = respond_body,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer respond.deinit();
    try std.testing.expectEqual(@as(u16, 200), respond.status_code);
    try assertContains(respond.body, "\"status\":\"approved\"");

    var approved_status = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = status_path,
        .headers = &.{.{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer approved_status.deinit();
    try std.testing.expectEqual(@as(u16, 200), approved_status.status_code);
    try assertContains(approved_status.body, "\"status\":\"approved\"");
}

test "http3 integration manages sessions over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
            .{ .name = "TARDIGRADE_SESSION_TTL", .value = "3600" },
            .{ .name = "TARDIGRADE_SESSION_MAX", .value = "16" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    var unauthorized_create = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/sessions",
        .method = "POST",
        .body = "{\"device_id\":\"http3-device\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer unauthorized_create.deinit();
    try std.testing.expectEqual(@as(u16, 401), unauthorized_create.status_code);

    var create = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/sessions",
        .method = "POST",
        .body = "{\"device_id\":\"http3-device\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer create.deinit();
    try std.testing.expectEqual(@as(u16, 201), create.status_code);
    const session_token = create.header("x-session-token") orelse return error.MissingSessionToken;
    const owned_session_token = try allocator.dupe(u8, session_token);
    defer allocator.free(owned_session_token);
    try assertContains(create.body, "\"session_token\":\"");

    var list = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/sessions",
        .headers = &.{.{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer list.deinit();
    try std.testing.expectEqual(@as(u16, 200), list.status_code);
    try assertContains(list.body, "\"active_sessions\":1");

    var revoke = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/sessions",
        .method = "DELETE",
        .headers = &.{.{ .name = "X-Session-Token", .value = owned_session_token }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer revoke.deinit();
    try std.testing.expectEqual(@as(u16, 200), revoke.status_code);
    try assertContains(revoke.body, "\"revoked\":true");

    var list_after = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/sessions",
        .headers = &.{.{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer list_after.deinit();
    try std.testing.expectEqual(@as(u16, 200), list_after.status_code);
    try assertContains(list_after.body, "\"active_sessions\":0");
}

test "http3 integration registers devices and refreshes sessions over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const registry_path = try std.fmt.allocPrint(allocator, ".zig-cache/http3-device-registry-{d}.txt", .{std.time.nanoTimestamp()});
    defer allocator.free(registry_path);

    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
            .{ .name = "TARDIGRADE_DEVICE_REGISTRY_PATH", .value = registry_path },
            .{ .name = "TARDIGRADE_SESSION_TTL", .value = "3600" },
            .{ .name = "TARDIGRADE_SESSION_MAX", .value = "16" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    var unauthorized_register = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/devices/register",
        .method = "POST",
        .body = "{\"device_id\":\"device-h3\",\"public_key\":\"pub-h3\"}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer unauthorized_register.deinit();
    try std.testing.expectEqual(@as(u16, 401), unauthorized_register.status_code);

    var register = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/devices/register",
        .method = "POST",
        .body = "{\"device_id\":\"device-h3\",\"public_key\":\"pub-h3\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer register.deinit();
    try std.testing.expectEqual(@as(u16, 201), register.status_code);
    try assertContains(register.body, "\"registered\":true");

    var create = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/sessions",
        .method = "POST",
        .body = "{\"device_id\":\"device-h3\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer create.deinit();
    try std.testing.expectEqual(@as(u16, 201), create.status_code);
    const session_token = create.header("x-session-token") orelse return error.MissingSessionToken;
    const owned_session_token = try allocator.dupe(u8, session_token);
    defer allocator.free(owned_session_token);

    var missing_refresh = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/sessions/refresh",
        .method = "POST",
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer missing_refresh.deinit();
    try std.testing.expectEqual(@as(u16, 400), missing_refresh.status_code);

    var refresh = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/sessions/refresh",
        .method = "POST",
        .headers = &.{.{ .name = "X-Session-Token", .value = owned_session_token }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer refresh.deinit();
    try std.testing.expectEqual(@as(u16, 200), refresh.status_code);
    try assertContains(refresh.body, "\"session_token\":\"");
    try assertContains(refresh.body, "\"access_ttl_seconds\":");
    try assertContains(refresh.body, "\"refresh_ttl_seconds\":");
    const refreshed_token = refresh.header("x-session-token") orelse return error.MissingSessionToken;
    try std.testing.expect(refreshed_token.len > 0);
}

test "http3 integration purges proxy cache over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const responses = [_]UpstreamResponseSpec{
        .{ .headers = &.{.{ .name = "Content-Type", .value = "application/json" }}, .body = "{\"version\":1}" },
        .{ .headers = &.{.{ .name = "Content-Type", .value = "application/json" }}, .body = "{\"version\":2}" },
    };
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
            .{ .name = "TARDIGRADE_PROXY_CACHE_TTL_SECONDS", .value = "30" },
            .{ .name = "TARDIGRADE_PROXY_CACHE_STALE_WHILE_REVALIDATE_SECONDS", .value = "30" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    const chat_body = "{\"message\":\"purge http3 cache\"}";

    var first = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/v1/chat",
        .method = "POST",
        .body = chat_body,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
    });
    defer first.deinit();
    try std.testing.expectEqual(@as(u16, 200), first.status_code);
    try assertContains(first.body, "\"version\":1");

    var hit = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/v1/chat",
        .method = "POST",
        .body = chat_body,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
    });
    defer hit.deinit();
    try std.testing.expectEqual(@as(u16, 200), hit.status_code);
    try assertContains(hit.body, "\"version\":1");
    try std.testing.expectEqual(@as(u32, 1), upstream.requestCount());

    var unauthorized_purge = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/cache/purge",
        .method = "POST",
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer unauthorized_purge.deinit();
    try std.testing.expectEqual(@as(u16, 401), unauthorized_purge.status_code);

    var purge = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/v1/cache/purge",
        .method = "POST",
        .headers = &.{.{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token }},
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer purge.deinit();
    try std.testing.expectEqual(@as(u16, 200), purge.status_code);
    try assertContains(purge.body, "\"purged\":1");

    var after_purge = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/v1/chat",
        .method = "POST",
        .body = chat_body,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
    });
    defer after_purge.deinit();
    try std.testing.expectEqual(@as(u16, 200), after_purge.status_code);
    try assertContains(after_purge.body, "\"version\":2");
    try std.testing.expectEqual(@as(u32, 2), upstream.requestCount());
}

test "http3 integration multiplexes parallel requests on one connection" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    const out_health_path = try std.fmt.allocPrint(allocator, ".zig-cache/http3-parallel-health-{d}.out", .{quic_port});
    defer allocator.free(out_health_path);
    const out_metrics_path = try std.fmt.allocPrint(allocator, ".zig-cache/http3-parallel-metrics-{d}.out", .{quic_port});
    defer allocator.free(out_metrics_path);
    std.fs.cwd().deleteFile(out_health_path) catch {};
    std.fs.cwd().deleteFile(out_metrics_path) catch {};
    defer std.fs.cwd().deleteFile(out_health_path) catch {};
    defer std.fs.cwd().deleteFile(out_metrics_path) catch {};

    const health_url = try std.fmt.allocPrint(allocator, "https://{s}:{d}/health", .{ test_host, quic_port });
    defer allocator.free(health_url);
    const metrics_url = try std.fmt.allocPrint(allocator, "https://{s}:{d}/metrics/json", .{ test_host, quic_port });
    defer allocator.free(metrics_url);

    var parallel_ok = false;
    var last_parallel_err: ?anyerror = null;
    for (0..http3_retry_attempts) |_| {
        const run_res = try std.process.Child.run(.{
            .allocator = allocator,
            .argv = &.{
                http3_curl_path,
                "--http3-only",
                "-k",
                "--parallel",
                "--parallel-max",
                "2",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "5",
                "--max-time",
                "8",
                "-o",
                out_health_path,
                health_url,
                "-o",
                out_metrics_path,
                metrics_url,
            },
            .max_output_bytes = 1024 * 1024,
        });
        defer allocator.free(run_res.stdout);
        defer allocator.free(run_res.stderr);
        switch (run_res.term) {
            .Exited => |code| {
                if (code == 0) {
                    parallel_ok = true;
                    break;
                }
                last_parallel_err = error.CurlFailed;
            },
            else => last_parallel_err = error.CurlFailed,
        }
        std.fs.cwd().deleteFile(out_health_path) catch {};
        std.fs.cwd().deleteFile(out_metrics_path) catch {};
        std.time.sleep(http3_retry_delay_ms * std.time.ns_per_ms);
    }
    if (!parallel_ok) return last_parallel_err orelse error.CurlFailed;

    const health_body = try std.fs.cwd().readFileAlloc(allocator, out_health_path, 1024 * 1024);
    defer allocator.free(health_body);
    const metrics_body = try std.fs.cwd().readFileAlloc(allocator, out_metrics_path, 1024 * 1024);
    defer allocator.free(metrics_body);
    try assertContains(health_body, "\"status\":\"ok\"");
    try assertContains(metrics_body, "\"total_requests\":");

    var runtime_health = try sendCurlRequest(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/health",
        .insecure = true,
    });
    defer runtime_health.deinit();
    try assertContains(runtime_health.body, "\"http3_native_connections\":1");
    try assertContains(runtime_health.body, "\"http3_handshakes_completed\":1");
    try assertContains(runtime_health.body, "\"http3_requests_completed\":2");
}

test "http3 integration serves authenticated admin routes over quic" {
    if (!build_options.enable_http3_ngtcp2) return error.SkipZigTest;
    std.fs.accessAbsolute(http3_curl_path, .{}) catch return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true}",
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const quic_port = try findFreePort();
    const quic_port_str = try std.fmt.allocPrint(allocator, "{d}", .{quic_port});
    defer allocator.free(quic_port_str);

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_HTTP3_ENABLED", .value = "true" },
            .{ .name = "TARDIGRADE_QUIC_PORT", .value = quic_port_str },
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_INTERVAL_MS", .value = "100" },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_TIMEOUT_MS", .value = "200" },
            .{ .name = "TARDIGRADE_UPSTREAM_HEALTH_THRESHOLD", .value = "1" },
            .{ .name = "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_THRESHOLD", .value = "1" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();
    try waitForHttp3Configured(tardigrade.port, 5000);

    var unauthorized = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/admin/routes",
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
    });
    defer unauthorized.deinit();
    try std.testing.expectEqual(@as(u16, 401), unauthorized.status_code);
    try assertContains(unauthorized.body, "\"code\":\"unauthorized\"");

    var authorized = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/admin/routes",
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
        },
    });
    defer authorized.deinit();
    try std.testing.expectEqual(@as(u16, 200), authorized.status_code);
    try assertContains(authorized.body, "/health");
    try assertContains(authorized.body, "/metrics");

    var connections = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/admin/connections",
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
        },
    });
    defer connections.deinit();
    try std.testing.expectEqual(@as(u16, 200), connections.status_code);
    try assertContains(connections.body, "\"active\":");
    try assertContains(connections.body, "\"tracked_ip_buckets\":");

    var upstreams = try sendHttp3CurlRequestWithSpec(allocator, quic_port, .{
        .scheme = "https",
        .path = "/admin/upstreams",
        .insecure = true,
        .binary_path = http3_curl_path,
        .http3_only = true,
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
        },
    });
    defer upstreams.deinit();
    try std.testing.expectEqual(@as(u16, 200), upstreams.status_code);
    try assertContains(upstreams.body, "\"upstreams\":[");
}

test "tls integration rejects client signed by unrecognized ca" {
    const allocator = std.testing.allocator;

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
            .{ .name = "TARDIGRADE_TLS_CLIENT_CA_PATH", .value = "tests/fixtures/tls/ca.crt" },
            .{ .name = "TARDIGRADE_TLS_CLIENT_VERIFY", .value = "true" },
        },
        .ready_https_insecure = true,
        .ready_client_cert = "tests/fixtures/tls/client.crt",
        .ready_client_key = "tests/fixtures/tls/client.key",
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var rogue = try runCurl(allocator, tardigrade.port, .{
        .scheme = "https",
        .path = "/health",
        .insecure = true,
        .cert = "tests/fixtures/tls/rogue_client.crt",
        .key = "tests/fixtures/tls/rogue_client.key",
    });
    defer rogue.deinit();
    switch (rogue.term) {
        .Exited => |code| try std.testing.expect(code != 0),
        else => try std.testing.expect(true),
    }
}

test "tls integration routes SNI hostnames to the configured certificate" {
    const allocator = std.testing.allocator;

    const opts = TardigradeOptions{
        .upstream_port = null,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
            .{ .name = "TARDIGRADE_TLS_SNI_CERTS", .value = "sni.integration.test:tests/fixtures/tls/alt_server.crt:tests/fixtures/tls/alt_server.key" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    const sni_subject = try opensslPresentedSubject(allocator, tardigrade.port, "sni.integration.test");
    defer allocator.free(sni_subject);
    try assertContains(sni_subject, "sni.integration.test");

    const default_subject = try opensslPresentedSubject(allocator, tardigrade.port, "unknown.integration.test");
    defer allocator.free(default_subject);
    try assertContains(default_subject, "127.0.0.1");
}

test "tls graceful shutdown integration sends connection close on inflight response" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"tls_shutdown\":true}",
        .delay_ms = 350,
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_TLS_CERT_PATH", .value = "tests/fixtures/tls/server.crt" },
            .{ .name = "TARDIGRADE_TLS_KEY_PATH", .value = "tests/fixtures/tls/server.key" },
        },
        .ready_https_insecure = true,
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);

    const curl_spec = CurlRequestSpec{
        .method = "POST",
        .scheme = "https",
        .path = "/v1/chat",
        .body = "{\"message\":\"tls drain\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .insecure = true,
    };
    var curl_child = try spawnCurlProcess(allocator, tardigrade.port, curl_spec);

    std.time.sleep(100 * std.time.ns_per_ms);
    tardigrade.sendSignal(std.posix.SIG.TERM);

    var stdout: std.ArrayListUnmanaged(u8) = .empty;
    defer stdout.deinit(allocator);
    var stderr: std.ArrayListUnmanaged(u8) = .empty;
    defer stderr.deinit(allocator);
    try curl_child.collectOutput(allocator, &stdout, &stderr, 1024 * 1024);
    const term = try curl_child.wait();
    switch (term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.CurlFailed,
    }

    const raw = stdout.items;
    if (stderr.items.len > 0) {
        std.debug.print("curl stderr: {s}\n", .{stderr.items});
    }
    const header_end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.InvalidHttpResponse;
    const headers_raw = raw[0 .. header_end + 2];
    const body = raw[header_end + 4 ..];
    try std.testing.expectEqual(@as(u16, 200), try parseStatusCode(raw));
    try std.testing.expectEqualStrings("close", headerValue(headers_raw, "Connection").?);
    try assertContains(body, "\"tls_shutdown\":true");

    _ = tardigrade.child.wait() catch {};
    tardigrade.allocator.free(tardigrade.log_path);
    if (tardigrade.config_path) |path| tardigrade.allocator.free(path);
}

test "concurrency integration handles 100 concurrent chat requests without corruption" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"concurrent\":true}",
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    var tardigrade = try TardigradeProcess.start(allocator, baseOptions(upstream.port()));
    defer tardigrade.stop();

    var start_flag = std.atomic.Value(bool).init(false);
    var results: [100]ConcurrentRequestResult = [_]ConcurrentRequestResult{.{}} ** 100;
    var contexts: [100]ConcurrentRequestContext = undefined;
    var threads: [100]std.Thread = undefined;

    for (&contexts, &results, 0..) |*ctx, *result, i| {
        ctx.* = .{
            .port = tardigrade.port,
            .start_flag = &start_flag,
            .result = result,
        };
        threads[i] = try std.Thread.spawn(.{}, concurrentChatRequestMain, .{ctx});
    }

    start_flag.store(true, .seq_cst);
    for (threads) |thread| thread.join();

    for (results) |result| {
        try std.testing.expect(result.err == null);
        try std.testing.expectEqual(@as(u16, 200), result.status_code);
        try std.testing.expect(result.body_contains_ok);
    }
}

test "concurrency integration rejects requests when worker queue is saturated" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"queued\":true}",
        .delay_ms = 300,
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_WORKER_THREADS", .value = "1" },
            .{ .name = "TARDIGRADE_WORKER_QUEUE_SIZE", .value = "1" },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var start_flag = std.atomic.Value(bool).init(false);
    var results: [8]ConcurrentRequestResult = [_]ConcurrentRequestResult{.{}} ** 8;
    var contexts: [8]ConcurrentRequestContext = undefined;
    var threads: [8]std.Thread = undefined;

    for (&contexts, &results, 0..) |*ctx, *result, i| {
        ctx.* = .{
            .port = tardigrade.port,
            .start_flag = &start_flag,
            .result = result,
        };
        threads[i] = try std.Thread.spawn(.{}, concurrentChatRequestMain, .{ctx});
    }

    start_flag.store(true, .seq_cst);
    for (threads) |thread| thread.join();

    var saw_overload = false;
    for (results) |result| {
        if (result.err != null) {
            saw_overload = true;
            continue;
        }
        if (result.status_code == 503) saw_overload = true;
    }
    try std.testing.expect(saw_overload);

    var metrics = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/metrics",
        .body = null,
        .headers = &.{},
    });
    defer metrics.deinit();
    try std.testing.expectEqual(@as(u16, 200), metrics.status_code);
    const queue_rejections = prometheusMetricValue(metrics.body, "tardigrade_queue_rejections_total") orelse return error.MissingMetric;
    try std.testing.expect(queue_rejections > 0);
}

test "concurrency integration drains queued requests in accept order under saturation" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"ordered\":true}",
        .delay_ms = 150,
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .extra_env = &.{
            .{ .name = "TARDIGRADE_WORKER_THREADS", .value = "1" },
            .{ .name = "TARDIGRADE_WORKER_QUEUE_SIZE", .value = "8" },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    const bodies = [_][]const u8{
        "{\"message\":\"order-1\"}",
        "{\"message\":\"order-2\"}",
        "{\"message\":\"order-3\"}",
        "{\"message\":\"order-4\"}",
    };
    var streams: [bodies.len]std.net.Stream = undefined;
    var opened: usize = 0;
    defer {
        for (streams[0..opened]) |stream| {
            var s = stream;
            s.close();
        }
    }

    for (bodies, 0..) |body, i| {
        streams[i] = try openRequestStream(allocator, tardigrade.port, .{
            .method = "POST",
            .path = "/v1/chat",
            .body = body,
            .headers = &.{
                .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
                .{ .name = "Content-Type", .value = "application/json" },
            },
        });
        opened += 1;
    }

    for (streams) |stream| {
        var response = try readHttpResponse(allocator, stream);
        defer response.deinit();
        try std.testing.expectEqual(@as(u16, 200), response.status_code);
        try assertContains(response.body, "\"ordered\":true");
    }

    try waitForUpstreamCount(&upstream, bodies.len, 2000);
    upstream.mutex.lock();
    defer upstream.mutex.unlock();
    try std.testing.expectEqual(bodies.len, upstream.capture.body_history.items.len);
    for (bodies, 0..) |body, i| {
        try std.testing.expectEqualStrings(body, upstream.capture.body_history.items[i]);
    }
}

test "concurrency integration avoids deadlock under concurrent auth and rate checks" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"contention\":true}",
        .delay_ms = 25,
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    const opts = TardigradeOptions{
        .upstream_port = upstream.port(),
        .rate_limit_rps = "10000",
        .rate_limit_burst = "10000",
        .extra_env = &.{
            .{ .name = "TARDIGRADE_WORKER_THREADS", .value = "8" },
            .{ .name = "TARDIGRADE_SESSION_TTL", .value = "3600" },
            .{ .name = "TARDIGRADE_SESSION_MAX", .value = "128" },
        },
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var session_create = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/sessions",
        .body = "{\"device_id\":\"contention-device\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer session_create.deinit();
    try std.testing.expectEqual(@as(u16, 201), session_create.status_code);
    const session_token = session_create.header("X-Session-Token") orelse return error.MissingSessionToken;
    const owned_session_token = try allocator.dupe(u8, session_token);
    defer allocator.free(owned_session_token);

    var start_flag = std.atomic.Value(bool).init(false);
    var results: [32]ConcurrentAuthRateResult = [_]ConcurrentAuthRateResult{.{}} ** 32;
    var contexts: [32]ConcurrentAuthRateContext = undefined;
    var threads: [32]std.Thread = undefined;

    for (&contexts, &results, 0..) |*ctx, *result, i| {
        const use_session = (i % 2) == 1;
        ctx.* = .{
            .port = tardigrade.port,
            .start_flag = &start_flag,
            .result = result,
            .auth_header_name = if (use_session) "X-Session-Token" else "Authorization",
            .auth_header_value = if (use_session) owned_session_token else "Bearer " ++ valid_bearer_token,
        };
        threads[i] = try std.Thread.spawn(.{}, concurrentAuthRateRequestMain, .{ctx});
    }

    start_flag.store(true, .seq_cst);
    for (threads) |thread| thread.join();

    for (results) |result| {
        try std.testing.expect(result.err == null);
        try std.testing.expectEqual(@as(u16, 200), result.status_code);
        try std.testing.expect(result.body_contains_ok);
    }
    try std.testing.expect(upstream.requestCount() >= results.len);
}

test "config reload integration updates upstream and rate limit without dropping inflight request" {
    const allocator = std.testing.allocator;

    const upstream1_responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"upstream\":1}",
        .delay_ms = 350,
    }};
    const upstream2_responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"upstream\":2}",
    }};
    var upstream1 = try UpstreamServer.start(allocator, &upstream1_responses);
    defer upstream1.stop();
    try upstream1.run();
    var upstream2 = try UpstreamServer.start(allocator, &upstream2_responses);
    defer upstream2.stop();
    try upstream2.run();

    const initial_config = try std.fmt.allocPrint(allocator,
        "upstream_base_url http://{s}:{d};\nrate_limit_rps 1000;\nrate_limit_burst 1000;\n",
        .{ test_host, upstream1.port() },
    );
    defer allocator.free(initial_config);

    const opts = TardigradeOptions{
        .upstream_port = null,
        .auth_token_hashes = valid_bearer_hash,
        .rate_limit_rps = null,
        .rate_limit_burst = null,
        .config_text = initial_config,
        .extra_env = &.{.{ .name = "TARDIGRADE_PROXY_PROTOCOL", .value = "v1" }},
        .ready_proxy_ip = "10.1.0.254",
    };
    var tardigrade = try TardigradeProcess.start(allocator, opts);
    defer tardigrade.stop();

    var in_flight_stream = try openRequestStream(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"reload in flight\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .proxy_ip = "10.1.0.1",
    });
    defer in_flight_stream.close();

    const reloaded_config = try std.fmt.allocPrint(allocator,
        "upstream_base_url http://{s}:{d};\nrate_limit_rps 1;\nrate_limit_burst 1;\n",
        .{ test_host, upstream2.port() },
    );
    defer allocator.free(reloaded_config);
    try tardigrade.rewriteConfig(reloaded_config);
    tardigrade.sendSignal(std.posix.SIG.HUP);

    var inflight_response = try readHttpResponse(allocator, in_flight_stream);
    defer inflight_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), inflight_response.status_code);
    try assertContains(inflight_response.body, "\"upstream\":1");

    var post_reload = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"after reload\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .proxy_ip = "10.1.0.2",
    });
    defer post_reload.deinit();
    try std.testing.expectEqual(@as(u16, 200), post_reload.status_code);
    try assertContains(post_reload.body, "\"upstream\":2");

    var limited = try sendRequest(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"after reload second\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .proxy_ip = "10.1.0.2",
    });
    defer limited.deinit();
    try std.testing.expectEqual(@as(u16, 429), limited.status_code);
}

test "graceful shutdown integration lets inflight request finish before exit" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"shutdown\":true}",
        .delay_ms = 350,
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    var tardigrade = try TardigradeProcess.start(allocator, baseOptions(upstream.port()));
    var child_reaped = false;
    defer {
        if (!child_reaped) {
            _ = tardigrade.child.kill() catch {};
            _ = tardigrade.child.wait() catch {};
        }
        tardigrade.allocator.free(tardigrade.log_path);
        if (tardigrade.config_path) |path| tardigrade.allocator.free(path);
    }

    var stream = try openRequestStream(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"finish before exit\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    tardigrade.sendSignal(std.posix.SIG.TERM);
    var response = try readHttpResponse(allocator, stream);
    defer response.deinit();
    stream.close();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "\"shutdown\":true");

    _ = tardigrade.child.wait() catch {};
    child_reaped = true;
}

test "graceful shutdown integration sends connection close on keep-alive inflight response" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"keepalive_shutdown\":true}",
        .delay_ms = 350,
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    var tardigrade = try TardigradeProcess.start(allocator, baseOptions(upstream.port()));
    var child_reaped = false;
    defer {
        if (!child_reaped) {
            _ = tardigrade.child.kill() catch {};
            _ = tardigrade.child.wait() catch {};
        }
        tardigrade.allocator.free(tardigrade.log_path);
        if (tardigrade.config_path) |path| tardigrade.allocator.free(path);
    }

    var stream = try openRequestStream(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"close after drain\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
        .connection_close = false,
    });
    tardigrade.sendSignal(std.posix.SIG.TERM);

    var response = try readHttpResponse(allocator, stream);
    defer response.deinit();
    stream.close();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "\"keepalive_shutdown\":true");
    try std.testing.expectEqualStrings("close", response.header("Connection").?);

    _ = tardigrade.child.wait() catch {};
    child_reaped = true;
}

test "graceful shutdown integration exits promptly after drain completes" {
    const allocator = std.testing.allocator;

    const responses = [_]UpstreamResponseSpec{.{
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        .body = "{\"ok\":true,\"drain_exit\":true}",
        .delay_ms = 350,
    }};
    var upstream = try UpstreamServer.start(allocator, &responses);
    defer upstream.stop();
    try upstream.run();

    var tardigrade = try TardigradeProcess.start(allocator, baseOptions(upstream.port()));
    var child_reaped = false;
    defer {
        if (!child_reaped) {
            _ = tardigrade.child.kill() catch {};
            _ = tardigrade.child.wait() catch {};
        }
        tardigrade.allocator.free(tardigrade.log_path);
        if (tardigrade.config_path) |path| tardigrade.allocator.free(path);
    }

    var stream = try openRequestStream(allocator, tardigrade.port, .{
        .method = "POST",
        .path = "/v1/chat",
        .body = "{\"message\":\"drain and exit\"}",
        .headers = &.{
            .{ .name = "Authorization", .value = "Bearer " ++ valid_bearer_token },
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    tardigrade.sendSignal(std.posix.SIG.TERM);

    var response = try readHttpResponse(allocator, stream);
    defer response.deinit();
    stream.close();
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try assertContains(response.body, "\"drain_exit\":true");

    try std.testing.expect(waitForChildExit(tardigrade.child.id, 2000));
    child_reaped = true;
    try waitForPortClosed(tardigrade.port, 250);

    const log_data = try std.fs.cwd().readFileAlloc(allocator, tardigrade.log_path, 256 * 1024);
    defer allocator.free(log_data);
    try assertContains(log_data, "Graceful shutdown complete");
}

test "location blocks integration routes requests to matching upstreams" {
    const allocator = std.testing.allocator;

    const exact_responses = [_]UpstreamResponseSpec{.{ .body = "exact-upstream" }};
    const prefix_responses = [_]UpstreamResponseSpec{.{ .body = "prefix-upstream" }};
    const regex_responses = [_]UpstreamResponseSpec{.{ .body = "regex-upstream" }};

    var exact_upstream = try UpstreamServer.start(allocator, &exact_responses);
    defer exact_upstream.stop();
    try exact_upstream.run();

    var prefix_upstream = try UpstreamServer.start(allocator, &prefix_responses);
    defer prefix_upstream.stop();
    try prefix_upstream.run();

    var regex_upstream = try UpstreamServer.start(allocator, &regex_responses);
    defer regex_upstream.stop();
    try regex_upstream.run();

    const config_text = try std.fmt.allocPrint(allocator,
        \\location = /exact {{
        \\    proxy_pass http://{s}:{d};
        \\}}
        \\location ^~ /prefix/ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
        \\location ~ ^/re/(.*)$ {{
        \\    proxy_pass http://{s}:{d};
        \\}}
    , .{
        test_host, exact_upstream.port(),
        test_host, prefix_upstream.port(),
        test_host, regex_upstream.port(),
    });
    defer allocator.free(config_text);

    var tardigrade = try TardigradeProcess.start(allocator, .{
        .upstream_port = null,
        .auth_token_hashes = null,
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
    try std.testing.expectEqual(@as(u16, 200), exact_response.status_code);
    try std.testing.expectEqualStrings("exact-upstream", exact_response.body);

    var prefix_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/prefix/item",
        .body = null,
        .headers = &.{},
    });
    defer prefix_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), prefix_response.status_code);
    try std.testing.expectEqualStrings("prefix-upstream", prefix_response.body);

    var regex_response = try sendRequest(allocator, tardigrade.port, .{
        .method = "GET",
        .path = "/re/value",
        .body = null,
        .headers = &.{},
    });
    defer regex_response.deinit();
    try std.testing.expectEqual(@as(u16, 200), regex_response.status_code);
    try std.testing.expectEqualStrings("regex-upstream", regex_response.body);

    try std.testing.expectEqual(@as(u32, 1), exact_upstream.capture.request_count);
    try std.testing.expectEqual(@as(u32, 1), prefix_upstream.capture.request_count);
    try std.testing.expectEqual(@as(u32, 1), regex_upstream.capture.request_count);
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
        .upstream_port = null,
        .auth_token_hashes = null,
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

    try std.testing.expectEqual(@as(u32, 1), first_upstream.capture.request_count);
    try std.testing.expectEqual(@as(u32, 1), second_upstream.capture.request_count);
}
