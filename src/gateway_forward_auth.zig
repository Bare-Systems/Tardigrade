//! Per-location external authorization subrequests (`forward_auth`, #761).
//!
//! Before a protected location's action runs, Tardigrade sends a bounded
//! HTTP/1.1 subrequest to the configured auth endpoint and acts on its status:
//!
//! - 2xx allows the request. Headers named by `forward_auth_upstream_headers`
//!   are copied from the auth response onto the upstream request; client
//!   copies of those names are always removed first so they cannot be forged.
//! - 3xx and 4xx deny it. The auth service's status, body, `Content-Type`,
//!   `Location` (3xx), `WWW-Authenticate` (401) and any
//!   `forward_auth_client_headers` are relayed to the client.
//! - Anything else (timeout, connect failure, 1xx/5xx, malformed or oversized
//!   response) fails closed with the configured `forward_auth_failure_status`.
//!
//! This module decides; the H1, H2 and H3 dispatchers apply the decision in
//! their own response shape. All three run it after rate limiting and
//! `auth required`, and before mirrors, retries or the location action.

const std = @import("std");
const compat = @import("zig_compat");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const ga = @import("gateway_auth.zig");
const gp = @import("gateway_proxy.zig");
const gph = @import("gateway_proxy_headers.zig");

pub const ForwardAuth = http.location_router.ForwardAuth;
pub const Outcome = http.metrics.ForwardAuthOutcome;

/// Largest auth response (headers + body) Tardigrade will buffer.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const DEFAULT_TIMEOUT_MS: u32 = 5_000;
const MAX_TRACESTATE_BYTES: usize = 512;

/// The original request, in protocol-neutral form.
pub const Input = struct {
    method: []const u8,
    /// Original request target (path plus optional query).
    uri: []const u8,
    host: ?[]const u8,
    /// "http" or "https", as seen by the client.
    proto: []const u8,
    /// Client address after trusted-proxy resolution.
    client_ip: []const u8,
    correlation_id: []const u8,
    headers: *const http.Headers,
    /// The buffered request body, or null when it is not available (a
    /// streamed upload). Only consulted when `max_body_bytes > 0`.
    body: ?[]const u8,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Decision = struct {
    arena: std.heap.ArenaAllocator,
    outcome: Outcome,
    /// Client-facing status for `denied` and failure outcomes.
    status: u16 = 200,
    /// Allowed: header values to place on the upstream request.
    upstream_headers: []const Header = &.{},
    /// Denied: headers to relay to the client.
    client_headers: []const Header = &.{},
    /// Denied: the auth service's body. Failures leave it empty and callers
    /// render a JSON API error from `errorCode()`/`errorMessage()`.
    body: []const u8 = "",
    content_type: ?[]const u8 = null,
    /// Failures: the transport error or auth status behind the outcome, for
    /// logs only (static string, never client-facing).
    cause: []const u8 = "",

    pub fn deinit(self: *Decision) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn allowed(self: *const Decision) bool {
        return self.outcome == .allowed;
    }

    /// True when the auth service itself answered with a denial whose body
    /// and headers should be relayed; false for Tardigrade-generated failures.
    pub fn relaysAuthResponse(self: *const Decision) bool {
        return self.outcome == .denied;
    }

    pub fn errorCode(self: *const Decision) []const u8 {
        return switch (self.outcome) {
            .allowed, .denied => "",
            .timeout => "auth_timeout",
            .unavailable, .invalid_response => "auth_unavailable",
            .body_too_large => "payload_too_large",
        };
    }

    pub fn errorMessage(self: *const Decision) []const u8 {
        return switch (self.outcome) {
            .allowed, .denied => "",
            .timeout => "Authorization service timed out",
            .unavailable, .invalid_response => "Authorization service unavailable",
            .body_too_large => "Request body too large for authorization",
        };
    }
};

/// Ask the auth service about `input`. Never returns a transport error:
/// every failure becomes a fail-closed `Decision`. Only allocation failure
/// propagates.
pub fn authorize(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    fa: *const ForwardAuth,
    input: Input,
) error{OutOfMemory}!Decision {
    var decision = Decision{ .arena = std.heap.ArenaAllocator.init(allocator), .outcome = .invalid_response };
    errdefer decision.arena.deinit();
    const arena = decision.arena.allocator();

    var send_body: []const u8 = "";
    if (fa.max_body_bytes > 0) {
        // `streamingUploadEligibilityBeforeBodyRead` keeps body-forwarding
        // locations buffered, so a null body means there was none to read.
        const body = input.body orelse "";
        if (body.len > fa.max_body_bytes) return failWith(decision, .body_too_large, 413);
        send_body = body;
    }

    const uri = std.Uri.parse(fa.url) catch return failWith(decision, .invalid_response, fa.failure_status);
    const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    if (!is_https and !std.ascii.eqlIgnoreCase(uri.scheme, "http")) return failWith(decision, .invalid_response, fa.failure_status);
    if (!ga.authSubrequestUriSafe(uri)) return failWith(decision, .invalid_response, fa.failure_status);
    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const decoded_host = (uri.getHost(&host_buf) catch return failWith(decision, .invalid_response, fa.failure_status)).bytes;
    if (!ga.authSubrequestBytesSafe(decoded_host, false)) return failWith(decision, .invalid_response, fa.failure_status);
    const host = ga.unbracketUriHost(decoded_host);
    const port = uri.port orelse if (is_https) @as(u16, 443) else @as(u16, 80);

    var headers = std.array_list.Managed(std.http.Header).init(arena);
    try appendAuthRequestHeaders(&headers, input, send_body.len > 0);

    const timeout_ms = effectiveTimeoutMs(cfg, fa);
    var response = gp.executeBoundedBufferedTcpHttpRequest(
        allocator,
        host,
        port,
        if (is_https) ga.authSubrequestTlsOptions(cfg) else null,
        uri,
        if (send_body.len > 0) "POST" else "GET",
        headers.items,
        send_body,
        null,
        MAX_RESPONSE_BYTES,
        timeout_ms,
        timeout_ms,
        null,
        null,
        false,
    ) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        var failed = failWith(decision, classifyTransportError(err), fa.failure_status);
        failed.cause = @errorName(err);
        return failed;
    };
    defer response.deinit(allocator);

    const status = response.status_code;
    if (status >= 200 and status < 300) {
        decision.outcome = .allowed;
        decision.upstream_headers = try collectHeaders(arena, &response, fa.upstream_headers, &.{});
        return decision;
    }
    if (status >= 300 and status < 500) {
        decision.outcome = .denied;
        decision.status = status;
        const implicit: []const []const u8 = if (status == 401)
            &.{"www-authenticate"}
        else if (status < 400)
            &.{"location"}
        else
            &.{};
        decision.client_headers = try collectHeaders(arena, &response, fa.client_headers, implicit);
        decision.body = try arena.dupe(u8, response.body);
        if (response.headerValue("content-type")) |content_type| {
            if (http.headers.isValidHeaderValue(content_type)) decision.content_type = try arena.dupe(u8, content_type);
        }
        return decision;
    }
    var failed = failWith(decision, if (status >= 500) .unavailable else .invalid_response, fa.failure_status);
    failed.cause = if (status >= 500) "auth service 5xx" else "unexpected auth status";
    return failed;
}

fn failWith(decision: Decision, outcome: Outcome, status: u16) Decision {
    var out = decision;
    out.outcome = outcome;
    out.status = status;
    return out;
}

fn effectiveTimeoutMs(cfg: *const edge_config.EdgeConfig, fa: *const ForwardAuth) u32 {
    if (fa.timeout_ms > 0) return fa.timeout_ms;
    if (cfg.upstream_response_timeout_ms > 0) return cfg.upstream_response_timeout_ms;
    if (cfg.upstream_timeout_ms > 0) return cfg.upstream_timeout_ms;
    return DEFAULT_TIMEOUT_MS;
}

fn classifyTransportError(err: anyerror) Outcome {
    return switch (err) {
        error.Timeout, error.WouldBlock, error.ConnectionTimedOut => .timeout,
        error.ConnectionFailed,
        error.ConnectionRefused,
        error.NetworkUnreachable,
        error.HostUnreachable,
        error.AddressNotAvailable,
        error.UnknownHostName,
        error.TemporaryNameServerFailure,
        error.NameServerFailure,
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        error.UpstreamUnavailable,
        => .unavailable,
        else => .invalid_response,
    };
}

/// Headers sent to the auth service. Client end-to-end headers are forwarded
/// under the same hop-by-hop and trust rules as a proxied request (so
/// `Authorization`, `Cookie` and `Accept` reach it), and Tardigrade then
/// asserts the original request's metadata in both the Traefik/Caddy
/// (`X-Forwarded-*`) and NGINX (`X-Original-*`) conventions.
fn appendAuthRequestHeaders(
    headers: *std.array_list.Managed(std.http.Header),
    input: Input,
    has_body: bool,
) !void {
    const arena = headers.allocator;
    const request_headers = input.headers.iterator();
    for (request_headers) |header| {
        if (header.name.len > 0 and header.name[0] == ':') continue;
        if (gph.shouldSkipUpstreamRequestHeader(header.name, null)) continue;
        if (gph.anyConnectionHeaderReferencesHeader(request_headers, header.name)) continue;
        if (isAssertedAuthRequestHeader(header.name)) continue;
        if (!has_body and isBodyHeader(header.name)) continue;
        try headers.append(.{ .name = header.name, .value = header.value });
    }

    try headers.append(.{ .name = "X-Forwarded-Method", .value = input.method });
    try headers.append(.{ .name = "X-Forwarded-Proto", .value = input.proto });
    if (input.host) |host| {
        const trimmed = std.mem.trim(u8, host, " \t");
        if (trimmed.len > 0 and http.headers.isValidHeaderValue(trimmed)) {
            try headers.append(.{ .name = "X-Forwarded-Host", .value = trimmed });
        }
    }
    try headers.append(.{ .name = "X-Forwarded-Uri", .value = input.uri });
    try headers.append(.{ .name = "X-Forwarded-For", .value = input.client_ip });
    try headers.append(.{ .name = "X-Real-IP", .value = input.client_ip });
    try headers.append(.{ .name = "X-Original-Method", .value = input.method });
    try headers.append(.{ .name = "X-Original-URI", .value = input.uri });
    try gph.appendRequestIdHeaders(headers, input.correlation_id);

    // W3C trace context: continue a valid inbound trace as a child span,
    // otherwise start one. An invalid inbound traceparent is never echoed.
    const trace = if (http.trace_context.parse(input.headers.get("traceparent"))) |parent|
        http.trace_context.childSpan(parent)
    else
        http.trace_context.generate();
    const traceparent_buf = try arena.alloc(u8, 55);
    const traceparent = trace.format(traceparent_buf);
    if (traceparent.len > 0) try headers.append(.{ .name = "traceparent", .value = traceparent });
    if (http.trace_context.parse(input.headers.get("traceparent")) != null) {
        if (input.headers.get("tracestate")) |tracestate| {
            if (tracestate.len <= MAX_TRACESTATE_BYTES) try headers.append(.{ .name = "tracestate", .value = tracestate });
        }
    }
}

fn isAssertedAuthRequestHeader(name: []const u8) bool {
    const asserted = [_][]const u8{
        "forwarded",      "x-forwarded-method", "x-forwarded-uri", "x-original-method",
        "x-original-uri", "traceparent",        "tracestate",      "expect",
    };
    for (asserted) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    return false;
}

fn isBodyHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "content-type") or
        std.ascii.eqlIgnoreCase(name, "content-encoding");
}

/// Copy every occurrence of each allowlisted header from the auth response.
/// Values that are not valid field values are dropped rather than relayed.
fn collectHeaders(
    arena: std.mem.Allocator,
    response: *const gp.BufferedUpstreamResponse,
    configured: []const []const u8,
    implicit: []const []const u8,
) ![]const Header {
    var out = std.ArrayList(Header).empty;
    for (response.headers) |header| {
        if (!nameListed(header.name, configured) and !nameListed(header.name, implicit)) continue;
        if (!http.headers.isValidHeaderValue(header.value)) continue;
        try out.append(arena, .{
            .name = try arena.dupe(u8, header.name),
            .value = try arena.dupe(u8, header.value),
        });
    }
    return out.toOwnedSlice(arena);
}

fn nameListed(name: []const u8, names: []const []const u8) bool {
    for (names) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    return false;
}

/// Apply an allow decision to a mutable request header set: drop every client
/// copy of each configured upstream header, then add the auth service's values.
/// Stripping happens even when the auth response omits the header, so a
/// client can never supply a value the upstream would attribute to auth.
pub fn applyUpstreamHeaders(headers: *http.Headers, fa: *const ForwardAuth, decision: *const Decision) !void {
    for (fa.upstream_headers) |name| headers.remove(name);
    for (decision.upstream_headers) |header| try headers.append(header.name, header.value);
}

/// Render a deny or failure decision into an `http.Response`. Security and
/// correlation headers are left to the caller, which owns those policies.
pub fn shapeResponse(allocator: std.mem.Allocator, response: *http.Response, decision: *const Decision, correlation_id: []const u8) !void {
    _ = response.setStatus(@enumFromInt(decision.status));
    if (decision.relaysAuthResponse()) {
        if (decision.body.len > 0) _ = response.setBodyOwned(try allocator.dupe(u8, decision.body));
        if (decision.content_type) |content_type| _ = response.setContentType(content_type);
        for (decision.client_headers) |header| try response.headers.append(header.name, header.value);
        // Auth decisions are per-request; never let a shared cache replay one.
        _ = response.setHeaderIfAbsent("Cache-Control", "no-store");
    } else {
        const payload = try gp.buildApiErrorJson(allocator, decision.errorCode(), decision.errorMessage(), correlation_id);
        _ = response.setBodyOwned(payload).setContentType("application/json");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Loopback HTTP/1.1 server that answers each connection with the next canned
/// raw response and records what it received. Shared with the H1/H3 dispatch
/// tests in `gateway_handlers.zig`.
pub const TestAuthServer = struct {
    allocator: std.mem.Allocator,
    listen_fd: std.posix.fd_t,
    listen_port: u16,
    thread: ?std.Thread = null,
    responses: []const []const u8,
    delay_ms: u32 = 0,
    mutex: compat.Mutex = .{},
    requests: std.ArrayList([]u8) = .empty,

    pub fn start(allocator: std.mem.Allocator, responses: []const []const u8) !TestAuthServer {
        const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
        try std.testing.expect(listen_fd >= 0);
        _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));
        var sin: std.c.sockaddr.in = .{
            .family = std.posix.AF.INET,
            .port = std.mem.nativeToBig(u16, 0),
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
            .zero = [_]u8{0} ** 8,
        };
        try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
        try std.testing.expect(std.c.listen(listen_fd, 8) == 0);
        var bound: std.c.sockaddr.in = undefined;
        var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        try std.testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
        return .{
            .allocator = allocator,
            .listen_fd = listen_fd,
            .listen_port = std.mem.bigToNative(u16, bound.port),
            .responses = responses,
        };
    }

    pub fn run(self: *TestAuthServer) !void {
        self.thread = try std.Thread.spawn(.{}, TestAuthServer.threadMain, .{self});
    }

    pub fn stop(self: *TestAuthServer) void {
        if (self.thread) |thread| {
            // Unblock a pending accept() for any response not consumed.
            var remaining = self.responses.len -| self.requestCount();
            while (remaining > 0) : (remaining -= 1) {
                if (compat.tcpConnectToHost(self.allocator, "127.0.0.1", self.listen_port)) |stream| {
                    stream.close();
                } else |_| break;
            }
            thread.join();
        }
        _ = std.c.close(self.listen_fd);
        for (self.requests.items) |raw| self.allocator.free(raw);
        self.requests.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn url(self: *const TestAuthServer, buf: []u8, path: []const u8) []const u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}{s}", .{ self.listen_port, path }) catch unreachable;
    }

    pub fn requestCount(self: *TestAuthServer) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.requests.items.len;
    }

    pub fn requestContains(self: *TestAuthServer, index: usize, needle: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (index >= self.requests.items.len) return false;
        return std.ascii.indexOfIgnoreCase(self.requests.items[index], needle) != null;
    }

    fn threadMain(self: *TestAuthServer) void {
        for (self.responses) |canned| {
            const fd = std.c.accept(self.listen_fd, null, null);
            if (fd < 0) return;
            defer _ = std.c.close(fd);
            var raw = std.ArrayList(u8).empty;
            defer raw.deinit(self.allocator);
            var buf: [4096]u8 = undefined;
            while (true) {
                const n = std.c.read(fd, &buf, buf.len);
                if (n <= 0) break;
                raw.appendSlice(self.allocator, buf[0..@intCast(n)]) catch return;
                const head_end = std.mem.indexOf(u8, raw.items, "\r\n\r\n") orelse continue;
                const content_length = testContentLength(raw.items[0..head_end]);
                if (raw.items.len >= head_end + 4 + content_length) break;
            }
            if (raw.items.len == 0) continue;
            const owned = self.allocator.dupe(u8, raw.items) catch return;
            self.mutex.lock();
            self.requests.append(self.allocator, owned) catch {
                self.mutex.unlock();
                self.allocator.free(owned);
                return;
            };
            self.mutex.unlock();
            if (self.delay_ms > 0) compat.sleepNs(@as(u64, self.delay_ms) * std.time.ns_per_ms);
            _ = std.c.write(fd, canned.ptr, canned.len);
        }
    }

    fn testContentLength(head: []const u8) usize {
        var lines = std.mem.splitSequence(u8, head, "\r\n");
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), "content-length")) continue;
            return std.fmt.parseInt(usize, std.mem.trim(u8, line[colon + 1 ..], " "), 10) catch 0;
        }
        return 0;
    }
};

fn testConfig() edge_config.EdgeConfig {
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.upstream_tls_ca_bundle = "";
    cfg.upstream_tls_client_cert = "";
    cfg.upstream_tls_client_key = "";
    return cfg;
}

fn testInput(headers: *const http.Headers, body: ?[]const u8) Input {
    return .{
        .method = if (body != null) "POST" else "GET",
        .uri = "/admin/panel?x=1",
        .host = "app.example.test",
        .proto = "https",
        .client_ip = "198.51.100.7",
        .correlation_id = "req-fa",
        .headers = headers,
        .body = body,
    };
}

test "authorize allows 2xx and returns only allowlisted auth headers" {
    const allocator = std.testing.allocator;
    var server = try TestAuthServer.start(allocator, &.{
        "HTTP/1.1 200 OK\r\nX-Auth-User: alice\r\nX-Auth-Groups: admins\r\nX-Internal: secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer server.stop();
    try server.run();
    var url_buf: [64]u8 = undefined;
    const fa = ForwardAuth{ .url = server.url(&url_buf, "/verify"), .upstream_headers = &.{ "X-Auth-User", "X-Auth-Groups" } };
    var headers = http.Headers.init(allocator);
    defer headers.deinit();
    try headers.append("Cookie", "session=abc");
    var cfg = testConfig();

    var decision = try authorize(allocator, &cfg, &fa, testInput(&headers, null));
    defer decision.deinit();

    try std.testing.expect(decision.allowed());
    try std.testing.expectEqual(@as(usize, 2), decision.upstream_headers.len);
    for (decision.upstream_headers) |header| try std.testing.expect(!std.ascii.eqlIgnoreCase(header.name, "x-internal"));
    try std.testing.expect(server.requestContains(0, "GET /verify HTTP/1.1"));
    try std.testing.expect(server.requestContains(0, "cookie: session=abc"));
    try std.testing.expect(server.requestContains(0, "X-Forwarded-Uri: /admin/panel?x=1"));
    try std.testing.expect(server.requestContains(0, "X-Forwarded-Method: GET"));
}

test "authorize relays redirect and challenge denials with only safe headers" {
    const allocator = std.testing.allocator;
    var server = try TestAuthServer.start(allocator, &.{
        "HTTP/1.1 302 Found\r\nLocation: https://sso.example.test/login?rd=%2Fadmin\r\nSet-Cookie: csrf=1\r\nX-Internal: secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nLocation: /ignored\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied",
    });
    defer server.stop();
    try server.run();
    var url_buf: [64]u8 = undefined;
    const fa = ForwardAuth{ .url = server.url(&url_buf, "/verify"), .client_headers = &.{"Set-Cookie"} };
    var headers = http.Headers.init(allocator);
    defer headers.deinit();
    var cfg = testConfig();

    var redirect = try authorize(allocator, &cfg, &fa, testInput(&headers, null));
    defer redirect.deinit();
    try std.testing.expectEqual(Outcome.denied, redirect.outcome);
    try std.testing.expectEqual(@as(u16, 302), redirect.status);
    try std.testing.expectEqual(@as(usize, 2), redirect.client_headers.len);

    var challenge = try authorize(allocator, &cfg, &fa, testInput(&headers, null));
    defer challenge.deinit();
    try std.testing.expectEqual(@as(u16, 401), challenge.status);
    try std.testing.expectEqualStrings("denied", challenge.body);
    try std.testing.expectEqualStrings("text/plain", challenge.content_type.?);
    try std.testing.expectEqual(@as(usize, 1), challenge.client_headers.len);
    try std.testing.expect(std.ascii.eqlIgnoreCase(challenge.client_headers[0].name, "www-authenticate"));

    var response = http.Response.init(allocator);
    defer response.deinit();
    try shapeResponse(allocator, &response, &challenge, "req-fa");
    try std.testing.expectEqual(@as(u16, 401), @intFromEnum(response.status));
    try std.testing.expectEqualStrings("Basic realm=\"admin\"", response.headers.get("www-authenticate").?);
    try std.testing.expect(response.headers.get("location") == null);
    try std.testing.expectEqualStrings("no-store", response.headers.get("cache-control").?);
}

test "authorize treats 5xx, malformed and slow auth responses as fail-closed failures" {
    const allocator = std.testing.allocator;
    var server = try TestAuthServer.start(allocator, &.{
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "NOT-HTTP garbage\r\n\r\n",
    });
    defer server.stop();
    try server.run();
    var url_buf: [64]u8 = undefined;
    const fa = ForwardAuth{ .url = server.url(&url_buf, "/verify") };
    var headers = http.Headers.init(allocator);
    defer headers.deinit();
    var cfg = testConfig();

    var server_error = try authorize(allocator, &cfg, &fa, testInput(&headers, null));
    defer server_error.deinit();
    try std.testing.expectEqual(Outcome.unavailable, server_error.outcome);
    try std.testing.expectEqual(ForwardAuth.DEFAULT_FAILURE_STATUS, server_error.status);

    var malformed = try authorize(allocator, &cfg, &fa, testInput(&headers, null));
    defer malformed.deinit();
    try std.testing.expect(!malformed.allowed());
    try std.testing.expect(!malformed.relaysAuthResponse());
    try std.testing.expectEqual(ForwardAuth.DEFAULT_FAILURE_STATUS, malformed.status);

    var slow_server = try TestAuthServer.start(allocator, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    slow_server.delay_ms = 1_000;
    defer slow_server.stop();
    try slow_server.run();
    var slow_url_buf: [64]u8 = undefined;
    const slow_fa = ForwardAuth{ .url = slow_server.url(&slow_url_buf, "/verify"), .timeout_ms = 100, .failure_status = 504 };
    var slow = try authorize(allocator, &cfg, &slow_fa, testInput(&headers, null));
    defer slow.deinit();
    try std.testing.expectEqual(Outcome.timeout, slow.outcome);
    try std.testing.expectEqual(@as(u16, 504), slow.status);
}

test "authorize sends the body only when forward_auth_body allows it" {
    const allocator = std.testing.allocator;
    const ok = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
    var server = try TestAuthServer.start(allocator, &.{ ok, ok });
    defer server.stop();
    try server.run();
    var url_buf: [64]u8 = undefined;
    var headers = http.Headers.init(allocator);
    defer headers.deinit();
    try headers.append("Content-Type", "application/json");
    var cfg = testConfig();

    const no_body = ForwardAuth{ .url = server.url(&url_buf, "/verify") };
    var first = try authorize(allocator, &cfg, &no_body, testInput(&headers, "{\"secret\":1}"));
    defer first.deinit();
    try std.testing.expect(first.allowed());
    try std.testing.expect(server.requestContains(0, "GET /verify"));
    try std.testing.expect(!server.requestContains(0, "secret"));
    try std.testing.expect(!server.requestContains(0, "content-type"));

    const with_body = ForwardAuth{ .url = no_body.url, .max_body_bytes = 64 };
    var second = try authorize(allocator, &cfg, &with_body, testInput(&headers, "{\"secret\":1}"));
    defer second.deinit();
    try std.testing.expect(second.allowed());
    try std.testing.expect(server.requestContains(1, "POST /verify"));
    try std.testing.expect(server.requestContains(1, "{\"secret\":1}"));
}

test "classifyTransportError separates timeouts from unreachable services" {
    try std.testing.expectEqual(Outcome.timeout, classifyTransportError(error.Timeout));
    try std.testing.expectEqual(Outcome.unavailable, classifyTransportError(error.ConnectionRefused));
    try std.testing.expectEqual(Outcome.unavailable, classifyTransportError(error.ConnectionFailed));
    try std.testing.expectEqual(Outcome.invalid_response, classifyTransportError(error.InvalidUpstreamResponse));
}

test "auth request forwards client credentials and asserts original request metadata" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    var request_headers = http.Headers.init(allocator);
    defer request_headers.deinit();
    try request_headers.append("Authorization", "Bearer abc");
    try request_headers.append("Cookie", "_oauth2_proxy=xyz");
    try request_headers.append("X-Forwarded-For", "6.6.6.6");
    try request_headers.append("X-Original-URI", "/forged");
    try request_headers.append("Content-Type", "application/json");
    try request_headers.append("X-Tardigrade-User-ID", "forged");
    try request_headers.append("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01");

    var headers = std.array_list.Managed(std.http.Header).init(arena_state.allocator());
    try appendAuthRequestHeaders(&headers, .{
        .method = "POST",
        .uri = "/admin/users?page=2",
        .host = "app.example.test",
        .proto = "https",
        .client_ip = "203.0.113.9",
        .correlation_id = "req-1",
        .headers = &request_headers,
        .body = null,
    }, false);

    const Lookup = struct {
        fn count(items: []const std.http.Header, name: []const u8) usize {
            var n: usize = 0;
            for (items) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, name)) n += 1;
            }
            return n;
        }
        fn value(items: []const std.http.Header, name: []const u8) ?[]const u8 {
            for (items) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
            }
            return null;
        }
    };
    try std.testing.expectEqualStrings("Bearer abc", Lookup.value(headers.items, "authorization").?);
    try std.testing.expectEqualStrings("_oauth2_proxy=xyz", Lookup.value(headers.items, "cookie").?);
    try std.testing.expectEqualStrings("POST", Lookup.value(headers.items, "X-Forwarded-Method").?);
    try std.testing.expectEqualStrings("/admin/users?page=2", Lookup.value(headers.items, "X-Forwarded-Uri").?);
    try std.testing.expectEqualStrings("/admin/users?page=2", Lookup.value(headers.items, "X-Original-URI").?);
    try std.testing.expectEqualStrings("app.example.test", Lookup.value(headers.items, "X-Forwarded-Host").?);
    try std.testing.expectEqualStrings("203.0.113.9", Lookup.value(headers.items, "X-Forwarded-For").?);
    try std.testing.expectEqual(@as(usize, 1), Lookup.count(headers.items, "X-Forwarded-For"));
    try std.testing.expectEqual(@as(usize, 1), Lookup.count(headers.items, "X-Original-URI"));
    try std.testing.expectEqual(@as(usize, 0), Lookup.count(headers.items, "content-type"));
    try std.testing.expectEqual(@as(usize, 0), Lookup.count(headers.items, "x-tardigrade-user-id"));
    const traceparent = Lookup.value(headers.items, "traceparent").?;
    try std.testing.expect(std.mem.startsWith(u8, traceparent, "00-0af7651916cd43dd8448eb211c80319c-"));
    try std.testing.expect(!std.mem.endsWith(u8, traceparent, "-b7ad6b7169203331-01"));
}

test "applyUpstreamHeaders strips client forgeries even when auth omits the header" {
    const allocator = std.testing.allocator;
    var headers = http.Headers.init(allocator);
    defer headers.deinit();
    try headers.append("X-Auth-User", "admin");
    try headers.append("X-Auth-Email", "forged@example.test");
    try headers.append("Accept", "*/*");
    const fa = ForwardAuth{ .url = "http://127.0.0.1:1/verify", .upstream_headers = &.{ "X-Auth-User", "X-Auth-Email" } };
    var decision = Decision{
        .arena = std.heap.ArenaAllocator.init(allocator),
        .outcome = .allowed,
        .upstream_headers = &.{.{ .name = "X-Auth-User", .value = "alice" }},
    };
    defer decision.deinit();

    try applyUpstreamHeaders(&headers, &fa, &decision);

    try std.testing.expectEqualStrings("alice", headers.get("x-auth-user").?);
    try std.testing.expectEqual(@as(usize, 1), headers.countByName("x-auth-user"));
    try std.testing.expect(headers.get("x-auth-email") == null);
    try std.testing.expectEqualStrings("*/*", headers.get("accept").?);
}

test "authorize fails closed with the configured status when the service is unreachable" {
    const allocator = std.testing.allocator;
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.upstream_tls_ca_bundle = "";
    cfg.upstream_tls_client_cert = "";
    cfg.upstream_tls_client_key = "";
    var request_headers = http.Headers.init(allocator);
    defer request_headers.deinit();
    // Port 1 on loopback is reserved and refuses connections.
    const fa = ForwardAuth{ .url = "http://127.0.0.1:1/verify", .timeout_ms = 500, .failure_status = 502 };
    var decision = try authorize(allocator, &cfg, &fa, .{
        .method = "GET",
        .uri = "/admin",
        .host = null,
        .proto = "http",
        .client_ip = "127.0.0.1",
        .correlation_id = "req-down",
        .headers = &request_headers,
        .body = null,
    });
    defer decision.deinit();
    try std.testing.expect(!decision.allowed());
    try std.testing.expect(!decision.relaysAuthResponse());
    try std.testing.expectEqual(Outcome.unavailable, decision.outcome);
    try std.testing.expectEqual(@as(u16, 502), decision.status);
}

test "authorize rejects bodies over the configured forward limit before any subrequest" {
    const allocator = std.testing.allocator;
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    var request_headers = http.Headers.init(allocator);
    defer request_headers.deinit();
    const fa = ForwardAuth{ .url = "http://127.0.0.1:1/verify", .max_body_bytes = 4 };
    var decision = try authorize(allocator, &cfg, &fa, .{
        .method = "POST",
        .uri = "/upload",
        .host = null,
        .proto = "http",
        .client_ip = "127.0.0.1",
        .correlation_id = "req-big",
        .headers = &request_headers,
        .body = "too large",
    });
    defer decision.deinit();
    try std.testing.expectEqual(Outcome.body_too_large, decision.outcome);
    try std.testing.expectEqual(@as(u16, 413), decision.status);
}
