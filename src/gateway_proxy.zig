//! Shared proxy primitives and bounded buffered HTTP/1 upstream transports.
//!
//! Functions whose names include `BoundedBuffered` materialize an upstream
//! response in memory only after enforcing an explicit size cap. They are kept
//! separate from the reverse-proxy data-plane orchestration in
//! `gateway_proxy_runtime.zig` so streaming/backpressure work can replace the
//! data-plane executor without depending on control-plane helper behavior.

const compat = @import("zig_compat.zig");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gs = @import("gateway_state.zig");
const gph = @import("gateway_proxy_headers.zig");
const gpres = @import("gateway_proxy_response.zig");
const gpt = @import("gateway_proxy_target.zig");
const gconn = @import("gateway_connection.zig");

// Re-export the header-boundary API so existing callers that import from this
// module continue to work without change.
pub const MaybeOwnedBytes = gph.MaybeOwnedBytes;
pub const buildForwardedFor = gph.buildForwardedFor;
pub const isTrustedUpstream = gph.isTrustedUpstream;
pub const appendTrustedUpstreamHeaders = gph.appendTrustedUpstreamHeaders;
pub const appendRequestIdHeaders = gph.appendRequestIdHeaders;
pub const writeRequestIdHeaders = gph.writeRequestIdHeaders;
pub const setRequestIdHeaders = gph.setRequestIdHeaders;
pub const applyResponseHeaders = gpres.applyResponseHeaders;
pub const writeStreamedUpstreamResponse = gpres.writeStreamedUpstreamResponse;
pub const writeStreamedUpstreamResponseHead = gpres.writeStreamedUpstreamResponseHead;
pub const writeStreamedUpstreamResponseHeadFromHeaders = gpres.writeStreamedUpstreamResponseHeadFromHeaders;
pub const writeBufferedUpstreamResponse = gpres.writeBufferedUpstreamResponse;
pub const writeBufferedUpstreamResponseHead = gpres.writeBufferedUpstreamResponseHead;
pub const computeHstsValue = gpres.computeHstsValue;
pub const writeSecurityHeaders = gpres.writeSecurityHeaders;
pub const writeSecurityHeadersFiltered = gpres.writeSecurityHeadersFiltered;
pub const writeChunk = gpres.writeChunk;
pub const buildApiErrorJson = gpres.buildApiErrorJson;
pub const sendApiError = gpres.sendApiError;
pub const upstreamReasonPhrase = gpres.upstreamReasonPhrase;
pub const ResolvedProxyTarget = gpt.ResolvedProxyTarget;
pub const isRedirectStatusCode = gpt.isRedirectStatusCode;
pub const resolveProxyTarget = gpt.resolveProxyTarget;
pub const appendProxyQueryString = gpt.appendProxyQueryString;
pub const resolveRedirectTargetUrl = gpt.resolveRedirectTargetUrl;
pub const unixSocketPathFromEndpoint = gpt.unixSocketPathFromEndpoint;
pub const combineProxyTarget = gpt.combineProxyTarget;
pub const parseUpstreamHost = gpt.parseUpstreamHost;
const maxBufferedUpstreamResponseBytes = gs.maxBufferedUpstreamResponseBytes;
const CancellationToken = http.cancellation.CancellationToken;

fn setSocketRecvTimeoutMs(fd: std.posix.fd_t, timeout_ms: u32) !void {
    const tv = std.posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
}

fn setSocketTimeoutMs(fd: std.posix.fd_t, recv_timeout_ms: u32, send_timeout_ms: u32) !void {
    const recv_tv = std.posix.timeval{
        .sec = @intCast(recv_timeout_ms / 1000),
        .usec = @intCast((recv_timeout_ms % 1000) * 1000),
    };
    const send_tv = std.posix.timeval{
        .sec = @intCast(send_timeout_ms / 1000),
        .usec = @intCast((send_timeout_ms % 1000) * 1000),
    };
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&recv_tv));
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&send_tv));
}

pub const UpstreamHeader = struct {
    name: []const u8,
    value: []const u8,
};

/// Fully materialized upstream response returned by bounded buffered helpers.
pub const BufferedUpstreamResponse = struct {
    metadata_arena: std.heap.ArenaAllocator,
    status_code: u16,
    reason: []const u8,
    headers: []UpstreamHeader,
    body: []u8,

    pub fn deinit(self: *BufferedUpstreamResponse, allocator: std.mem.Allocator) void {
        self.metadata_arena.deinit();
        allocator.free(self.body);
        self.* = undefined;
    }

    pub fn headerValue(self: *const BufferedUpstreamResponse, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        }
        return null;
    }
};

pub const StreamingRequestBody = struct {
    content_length: usize,
    initial_bytes: []const u8 = &.{},
};

pub const StreamingProxyResult = struct {
    status_code: u16,
    reason: []const u8,
    response_body_bytes: usize,
    upstream_ttfb_ms: u64,
    upstream_aborted: bool = false,
};

pub fn uriComponentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |value| value,
        .percent_encoded => |value| value,
    };
}

/// Parse an HTTP/1 response that has already been read under a caller-owned
/// bound. Do not call this on unbounded network input.
pub fn parseBufferedUpstreamResponse(allocator: std.mem.Allocator, raw: []const u8) !BufferedUpstreamResponse {
    var metadata_arena = std.heap.ArenaAllocator.init(allocator);
    errdefer metadata_arena.deinit();
    const metadata_allocator = metadata_arena.allocator();

    // If the upstream closed before sending a complete response head, treat it
    // as a protocol error (not an unsupported method — the name would be
    // misleading here).  Callers synthesise a 502 Bad Gateway for this case.
    const header_end = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.UpstreamProtocolError;
    const headers_raw = raw[0..header_end];
    const resp_body = raw[header_end + 4 ..];

    const first_line_end = std.mem.findScalar(u8, headers_raw, '\n') orelse return error.UpstreamProtocolError;
    const first_line = compat.trimRight(u8, headers_raw[0..first_line_end], "\r");
    var line_parts = std.mem.splitScalar(u8, first_line, ' ');
    _ = line_parts.next();
    const status_str = line_parts.next() orelse "200";
    const status_code = std.fmt.parseInt(u16, status_str, 10) catch 200;
    const reason = line_parts.rest();

    var resp_headers = std.array_list.Managed(UpstreamHeader).init(metadata_allocator);
    var hdr_lines = std.mem.splitSequence(u8, headers_raw[first_line_end + 1 ..], "\r\n");
    while (hdr_lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const hname = std.mem.trim(u8, line[0..colon], " \t");
        const hval = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (gph.shouldSkipUpstreamResponseHeader(hname)) continue;
        try resp_headers.append(.{
            .name = try metadata_allocator.dupe(u8, hname),
            .value = try metadata_allocator.dupe(u8, hval),
        });
    }

    return .{
        .metadata_arena = metadata_arena,
        .status_code = status_code,
        .reason = try metadata_allocator.dupe(u8, reason),
        .headers = try resp_headers.toOwnedSlice(),
        .body = try allocator.dupe(u8, resp_body),
    };
}

/// Execute a bounded buffered HTTP/1 request over a Unix socket. This is
/// appropriate for small control-plane/internal calls and compatibility paths
/// where the caller provides a strict response cap.
pub fn executeBoundedBufferedUnixSocketHttpRequest(
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    timeout_ms: u32,
    /// If > 0, overrides `SO_RCVTIMEO` after sending the request to enforce a
    /// separate deadline for waiting on the first response byte (distinct from
    /// the write-phase timeout above).
    response_timeout_ms: u32,
) !BufferedUpstreamResponse {
    const fd = try compat.connectBlockingUnix(socket_path);
    defer _ = std.c.close(fd);

    return exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(fd),
        fd,
        uri,
        method,
        extra_headers,
        body,
        content_type_override,
        max_buffered_response_bytes,
        timeout_ms,
        response_timeout_ms,
    );
}

/// Execute a bounded buffered HTTP/1 request over a TCP socket, with optional
/// TLS. This is the manual-transport replacement for the `std.http.Client`
/// data-plane and control-plane proxy paths: unlike `std.http.Client` it
/// exposes the underlying socket fd, so per-phase connect and response
/// timeouts (`SO_SNDTIMEO`/`SO_RCVTIMEO`) are enforced. The connection is not
/// pooled (`Connection: close`); upstream keepalive reuse on this path is
/// traded for timeout enforcement (see issue #196; richer pooling tracked in
/// issue #141).
pub fn executeBoundedBufferedTcpHttpRequest(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    /// When non-null, wrap the TCP stream in TLS before exchanging the request.
    tls_options: ?http.tls_termination.UpstreamTlsOptions,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    /// Bounds the connect/handshake and request-write phase. The blocking TCP
    /// connect itself is not interruptible by SO_*TIMEO; this bounds the
    /// handshake stall and the write phase that follow.
    connect_timeout_ms: u32,
    /// If > 0, overrides `SO_RCVTIMEO` after the request is sent to bound the
    /// wait for the first response byte separately from the write phase.
    response_timeout_ms: u32,
) !BufferedUpstreamResponse {
    const fd = try compat.connectBlockingTcp(host, port);
    defer _ = std.c.close(fd);

    if (connect_timeout_ms > 0) {
        try setSocketTimeoutMs(fd, connect_timeout_ms, connect_timeout_ms);
    }

    if (tls_options) |opts| {
        var tls_conn = try http.tls_termination.UpstreamTlsConn.connect(fd, host, opts);
        defer tls_conn.deinit();
        return exchangeBoundedBufferedHttpRequest(
            allocator,
            &tls_conn,
            fd,
            uri,
            method,
            extra_headers,
            body,
            content_type_override,
            max_buffered_response_bytes,
            connect_timeout_ms,
            response_timeout_ms,
        );
    }

    return exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(fd),
        fd,
        uri,
        method,
        extra_headers,
        body,
        content_type_override,
        max_buffered_response_bytes,
        connect_timeout_ms,
        response_timeout_ms,
    );
}

/// Send a bounded buffered HTTP/1 request over an already-connected transport
/// and parse the response. `transport` must provide `writeAll([]const u8)` and
/// `read([]u8) !usize` (satisfied by both `compat.NetStream` and
/// `*UpstreamTlsConn`). `fd` is the underlying socket used for per-phase
/// timeout control. The caller owns connecting and closing the transport.
fn exchangeBoundedBufferedHttpRequest(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    send_timeout_ms: u32,
    response_timeout_ms: u32,
) !BufferedUpstreamResponse {
    if (send_timeout_ms > 0) {
        try setSocketTimeoutMs(fd, send_timeout_ms, send_timeout_ms);
    }

    var req_aw: std.Io.Writer.Allocating = .init(allocator);
    defer req_aw.deinit();
    const req_writer = &req_aw.writer;
    var host_buf: [256]u8 = undefined;
    const host = if (uri.host) |value| try value.toRaw(&host_buf) else "localhost";

    try req_writer.print("{s} {s}", .{ method, uriComponentBytes(uri.path) });
    if (uri.query) |query| {
        try req_writer.print("?{s}", .{uriComponentBytes(query)});
    }
    try req_writer.writeAll(" HTTP/1.1\r\n");
    try req_writer.print("Host: {s}\r\n", .{host});
    try req_writer.writeAll("Connection: close\r\n");
    if (content_type_override) |content_type| {
        try req_writer.print("Content-Type: {s}\r\n", .{content_type});
    }
    for (extra_headers) |header| {
        try req_writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    if (body.len > 0) {
        try req_writer.print("Content-Length: {d}\r\n", .{body.len});
    }
    try req_writer.writeAll("\r\n");
    if (body.len > 0) {
        try req_writer.writeAll(body);
    }

    try transport.writeAll(req_aw.written());

    // Bound the wait for the response with poll() rather than SO_RCVTIMEO:
    // SO_RCVTIMEO is reliably honored on AF_UNIX sockets but is silently ignored
    // on the AF_INET upstream sockets used here, so a hung TCP origin would block
    // the worker forever. SO_RCVTIMEO is still set (best effort) so OpenSSL-driven
    // TLS reads remain bounded; poll() is the authoritative deadline. (issue #196)
    if (response_timeout_ms > 0) {
        setSocketRecvTimeoutMs(fd, response_timeout_ms) catch {};
    }
    const read_deadline_ms = if (response_timeout_ms > 0) response_timeout_ms else send_timeout_ms;

    var resp_raw = std.array_list.Managed(u8).init(allocator);
    defer resp_raw.deinit();
    var read_buf: [8192]u8 = undefined;
    while (true) {
        if (read_deadline_ms > 0 and !try pollFdReadable(fd, read_deadline_ms)) {
            return error.Timeout;
        }
        const n = try transport.read(&read_buf);
        if (n == 0) break;
        try resp_raw.appendSlice(read_buf[0..n]);
        if (resp_raw.items.len > max_buffered_response_bytes) return error.StreamTooLong;
    }

    return parseBufferedUpstreamResponse(allocator, resp_raw.items);
}

/// Wait up to `timeout_ms` for `fd` to become readable. Returns false on
/// timeout. EINTR is retried within the original deadline.
fn pollFdReadable(fd: std.posix.fd_t, timeout_ms: u32) !bool {
    var pfds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR,
        .revents = 0,
    }};
    const ready = std.posix.poll(&pfds, @intCast(@min(timeout_ms, std.math.maxInt(i32)))) catch |err| switch (err) {
        error.Unexpected => return error.Timeout,
        else => return err,
    };
    return ready != 0;
}

test "parseBufferedUpstreamResponse keeps metadata in an arena and preserves forwarded headers" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Cache-Control: no-store\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "ok",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), parsed.status_code);
    try std.testing.expectEqualStrings("OK", parsed.reason);
    try std.testing.expectEqualStrings("text/plain", parsed.headerValue("content-type").?);
    try std.testing.expect(bufferedUpstreamResponseHasNoStore(&parsed));
    try std.testing.expectEqualStrings("ok", parsed.body);
}

test "parseBufferedUpstreamResponse returns UpstreamProtocolError on partial upstream response" {
    // Simulates an upstream that closes the TCP connection before sending a
    // complete HTTP response head (the scenario reported in issue #94).
    // Before the fix this returned error.UnsupportedHttpMethod, a misleading
    // name that also prevented callers from distinguishing a real method
    // rejection from a dropped-connection scenario.
    const testing = std.testing;

    // Upstream closed immediately — empty body
    try testing.expectError(error.UpstreamProtocolError, parseBufferedUpstreamResponse(testing.allocator, ""));

    // Upstream sent a partial status line and closed
    try testing.expectError(error.UpstreamProtocolError, parseBufferedUpstreamResponse(testing.allocator, "HTTP/1.1"));

    // Upstream sent headers but no blank line (no \r\n\r\n terminator)
    try testing.expectError(error.UpstreamProtocolError, parseBufferedUpstreamResponse(testing.allocator, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"));
}

pub fn bufferedUpstreamResponseHasNoStore(response: *const BufferedUpstreamResponse) bool {
    for (response.headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cache-control")) continue;
        var tokens = std.mem.splitScalar(u8, header.value, ',');
        while (tokens.next()) |token_raw| {
            const token = std.mem.trim(u8, token_raw, " \t\r\n");
            if (std.ascii.eqlIgnoreCase(token, "no-store")) return true;
        }
    }
    return false;
}

fn markRequestConnectionClosing(req: *std.http.Client.Request) void {
    if (req.connection) |connection| {
        connection.closing = true;
    }
}

/// Execute the current bounded buffered HTTP/1 reverse-proxy transport.
/// `gateway_proxy_runtime.zig` owns data-plane retry/routing semantics and
/// should be the place future streaming/backpressure work swaps this out.
pub fn executeBoundedBufferedHttpProxyRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    url: []const u8,
    unix_socket_path: ?[]const u8,
    method: []const u8,
    request_headers: *const http.Headers,
    body: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    forwarded_proto: []const u8,
    incoming_host: ?[]const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    attempt_timeout_ms: u32,
    connect_timeout_ms: u32,
    /// If > 0, caps the time from finished request-send to first response byte.
    /// Enforced on all transports (Unix socket, TCP, TLS) via per-phase socket
    /// timeouts now that the path no longer routes through std.http.Client.
    response_timeout_ms: u32,
    cancel_token: ?*const CancellationToken,
) !BufferedUpstreamResponse {
    // Bail out before touching the network if the request is already stopped.
    if (cancel_token) |tok| {
        if (tok.isStopped()) return error.RequestCancelled;
    }
    const proxy_extra_header_slack = 10;
    const max_buffered_response_bytes = maxBufferedUpstreamResponseBytes(cfg);
    const uri = try std.Uri.parse(url);

    // HTTPS upstreams (plain or mTLS) use the OpenSSL transport, which exposes
    // the underlying socket fd for timeout control and supports custom
    // CA/SNI/client-cert config. It rebuilds proxy headers internally, so this
    // delegation must happen before the shared header build below.
    if (unix_socket_path == null and std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
        return executeBoundedBufferedHttpsMtlsRequest(
            allocator,
            url,
            method,
            request_headers,
            body,
            correlation_id,
            client_ip,
            forwarded_proto,
            incoming_host,
            auth_identity,
            auth_user_id,
            auth_device_id,
            auth_scopes,
            cfg,
        );
    }

    var extra_headers_stack = std.heap.stackFallback(2048, allocator);
    const extra_headers_allocator = extra_headers_stack.get();
    var forwarded_for = try gph.buildForwardedFor(allocator, request_headers.get("x-forwarded-for"), client_ip);
    defer forwarded_for.deinit(allocator);

    var extra_headers = std.array_list.Managed(std.http.Header).init(extra_headers_allocator);
    defer extra_headers.deinit();
    try extra_headers.ensureUnusedCapacity(request_headers.count() + proxy_extra_header_slack);
    try gph.appendProxyRequestHeaders(&extra_headers, request_headers);
    try gph.appendRequestIdHeaders(&extra_headers, correlation_id);
    try extra_headers.append(.{ .name = "X-Forwarded-For", .value = forwarded_for.value });
    try extra_headers.append(.{ .name = "X-Real-IP", .value = client_ip });
    try extra_headers.append(.{ .name = "X-Forwarded-Proto", .value = forwarded_proto });
    if (incoming_host) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) try extra_headers.append(.{ .name = "X-Forwarded-Host", .value = trimmed });
    }
    try gph.appendAssertedIdentityHeaders(&extra_headers, auth_identity, auth_user_id, auth_device_id, auth_scopes);
    // W3C Trace Context: propagate inbound traceparent or originate a new one.
    // A child span is created from an inbound context so the trace ID is preserved
    // but each hop gets its own span ID.
    var traceparent_buf: [55]u8 = undefined;
    if (request_headers.get("traceparent") == null) {
        const tc = http.trace_context.generate();
        const tp = tc.format(&traceparent_buf);
        if (tp.len > 0) try extra_headers.append(.{ .name = "traceparent", .value = tp });
    }

    if (unix_socket_path) |socket_path| {
        const base_timeout_ms = if (attempt_timeout_ms > 0) attempt_timeout_ms else connect_timeout_ms;
        const effective_timeout_ms = if (cancel_token) |tok|
            tok.effectiveTimeoutMs(base_timeout_ms)
        else
            base_timeout_ms;
        const effective_response_timeout_ms = if (cancel_token) |tok|
            tok.effectiveTimeoutMs(response_timeout_ms)
        else
            response_timeout_ms;
        return executeBoundedBufferedUnixSocketHttpRequest(
            allocator,
            socket_path,
            uri,
            method,
            extra_headers.items,
            body,
            null,
            max_buffered_response_bytes,
            effective_timeout_ms,
            effective_response_timeout_ms,
        );
    }

    // Plain HTTP/1 TCP upstream — manual bounded transport with per-phase
    // timeout enforcement (issue #196). Connection is not pooled.
    const host = if (uri.host) |h| uriComponentBytes(h) else return error.UpstreamProtocolError;
    const port: u16 = uri.port orelse 80;
    const base_timeout_ms = if (attempt_timeout_ms > 0) attempt_timeout_ms else connect_timeout_ms;
    const effective_send_timeout_ms = if (cancel_token) |tok|
        tok.effectiveTimeoutMs(base_timeout_ms)
    else
        base_timeout_ms;
    const effective_response_timeout_ms = if (cancel_token) |tok|
        tok.effectiveTimeoutMs(response_timeout_ms)
    else
        response_timeout_ms;
    return executeBoundedBufferedTcpHttpRequest(
        allocator,
        host,
        port,
        null,
        uri,
        method,
        extra_headers.items,
        body,
        null,
        max_buffered_response_bytes,
        effective_send_timeout_ms,
        effective_response_timeout_ms,
    );
}

/// Execute the bounded buffered HTTPS/mTLS compatibility transport using
/// OpenSSL directly, supporting custom CA bundles, SNI overrides, and mutual
/// TLS client certificates. Used when `TARDIGRADE_UPSTREAM_TLS_CLIENT_CERT`
/// is set; not a streaming data-plane implementation.
pub fn executeBoundedBufferedHttpsMtlsRequest(
    allocator: std.mem.Allocator,
    url: []const u8,
    method: []const u8,
    request_headers: *const http.Headers,
    body: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    forwarded_proto: []const u8,
    incoming_host: ?[]const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    cfg: *const edge_config.EdgeConfig,
) !BufferedUpstreamResponse {
    const max_buffered_response_bytes = maxBufferedUpstreamResponseBytes(cfg);
    const uri = try std.Uri.parse(url);
    const host = if (uri.host) |h| switch (h) {
        .raw => |r| r,
        .percent_encoded => |pe| pe,
    } else return error.UnsupportedHttpMethod;
    const port: u16 = if (uri.port) |p| p else 443;
    const tcp_stream = try compat.tcpConnectToHost(allocator, host, port);
    defer tcp_stream.close();

    // Apply upstream connect timeout to bound the TLS handshake. The TCP
    // connect itself is blocking, so this timeout bounds the handshake stall
    // rather than the TCP SYN. Falls back to upstream_timeout_ms when the
    // connect-specific timeout is not set.
    const effective_connect_timeout_ms = if (cfg.upstream_connect_timeout_ms > 0)
        cfg.upstream_connect_timeout_ms
    else
        cfg.upstream_timeout_ms;
    if (effective_connect_timeout_ms > 0) {
        gconn.setSocketTimeoutMs(tcp_stream.handle, effective_connect_timeout_ms, effective_connect_timeout_ms) catch {};
    }

    var tls_conn = try http.tls_termination.UpstreamTlsConn.connect(tcp_stream.handle, host, .{
        .skip_verify = !cfg.upstream_tls_verify,
        .ca_bundle_path = cfg.upstream_tls_ca_bundle,
        .sni_override = cfg.upstream_tls_server_name,
        .client_cert_path = cfg.upstream_tls_client_cert,
        .client_key_path = cfg.upstream_tls_client_key,
    });
    defer tls_conn.deinit();

    // Build and send HTTP/1.1 request.
    const path_raw = switch (uri.path) {
        .raw => |path| if (path.len > 0) path else "/",
        .percent_encoded => |path| if (path.len > 0) path else "/",
    };
    var forwarded_for = try gph.buildForwardedFor(allocator, request_headers.get("x-forwarded-for"), client_ip);
    defer forwarded_for.deinit(allocator);

    var req_aw: std.Io.Writer.Allocating = .init(allocator);
    defer req_aw.deinit();
    const req_writer = &req_aw.writer;
    try req_writer.print("{s} {s} HTTP/1.1\r\n", .{ method, path_raw });
    try req_writer.print("Host: {s}\r\n", .{host});
    try req_writer.print("Connection: close\r\n", .{});
    if (body.len > 0) try req_writer.print("Content-Length: {d}\r\n", .{body.len});
    try gph.writeRequestIdHeaders(req_writer, correlation_id);
    try req_writer.print("X-Forwarded-For: {s}\r\n", .{forwarded_for.value});
    try req_writer.print("X-Real-IP: {s}\r\n", .{client_ip});
    try req_writer.print("X-Forwarded-Proto: {s}\r\n", .{forwarded_proto});
    if (incoming_host) |h| {
        const trimmed = std.mem.trim(u8, h, " \t\r\n");
        if (trimmed.len > 0) try req_writer.print("X-Forwarded-Host: {s}\r\n", .{trimmed});
    }
    try gph.writeAssertedIdentityHeaders(req_writer, auth_identity, auth_user_id, auth_device_id, auth_scopes);
    const connection_header = request_headers.get("connection");
    for (request_headers.iterator()) |entry| {
        if (gph.shouldSkipUpstreamRequestHeader(entry.name, connection_header)) continue;
        try req_writer.print("{s}: {s}\r\n", .{ entry.name, entry.value });
    }
    // W3C Trace Context: originate when absent (inbound propagation happens via
    // the iterator loop above since traceparent is not in the skip list).
    if (request_headers.get("traceparent") == null) {
        var tp_buf: [55]u8 = undefined;
        const tc = http.trace_context.generate();
        const tp = tc.format(&tp_buf);
        if (tp.len > 0) try req_writer.print("traceparent: {s}\r\n", .{tp});
    }
    try req_writer.writeAll("\r\n");
    if (body.len > 0) try req_writer.writeAll(body);

    // After the TLS handshake, switch to the per-attempt read/write timeout for
    // request write and response read phases.
    if (cfg.upstream_timeout_ms > 0) {
        const resp_timeout_ms = if (cfg.upstream_response_timeout_ms > 0)
            cfg.upstream_response_timeout_ms
        else
            cfg.upstream_timeout_ms;
        gconn.setSocketTimeoutMs(tcp_stream.handle, resp_timeout_ms, cfg.upstream_timeout_ms) catch {};
    }

    try tls_conn.writeAll(req_aw.written());

    // Read the raw HTTP response.
    var resp_raw = std.array_list.Managed(u8).init(allocator);
    defer resp_raw.deinit();
    var read_buf: [8192]u8 = undefined;
    while (true) {
        const n = tls_conn.read(&read_buf) catch 0;
        if (n == 0) break;
        try resp_raw.appendSlice(read_buf[0..n]);
        if (resp_raw.items.len > max_buffered_response_bytes) return error.StreamTooLong;
    }
    return parseBufferedUpstreamResponse(allocator, resp_raw.items);
}

pub fn executeStreamingHttpProxyRequest(
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    cfg: *const edge_config.EdgeConfig,
    url: []const u8,
    method: []const u8,
    request_headers: *const http.Headers,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    downstream_conn: anytype,
    downstream_writer: anytype,
    correlation_id: []const u8,
    client_ip: []const u8,
    forwarded_proto: []const u8,
    incoming_host: ?[]const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    security: *const http.security_headers.SecurityHeaders,
    sticky_set_cookie: ?[]const u8,
    cancel_token: ?*const CancellationToken,
) !StreamingProxyResult {
    if (cancel_token) |tok| {
        if (tok.isStopped()) return error.RequestCancelled;
    }
    const proxy_extra_header_slack = 10;
    const method_enum = std.meta.stringToEnum(std.http.Method, method) orelse return error.UnsupportedHttpMethod;
    const uri = try std.Uri.parse(url);
    var forwarded_for = try buildForwardedFor(allocator, request_headers.get("x-forwarded-for"), client_ip);
    defer forwarded_for.deinit(allocator);
    var metadata_arena = std.heap.ArenaAllocator.init(allocator);
    defer metadata_arena.deinit();
    const metadata_allocator = metadata_arena.allocator();

    var extra_headers_stack = std.heap.stackFallback(2048, allocator);
    const extra_headers_allocator = extra_headers_stack.get();
    var extra_headers = std.array_list.Managed(std.http.Header).init(extra_headers_allocator);
    defer extra_headers.deinit();
    try extra_headers.ensureUnusedCapacity(request_headers.count() + proxy_extra_header_slack);
    try gph.appendProxyRequestHeaders(&extra_headers, request_headers);
    try gph.appendRequestIdHeaders(&extra_headers, correlation_id);
    try extra_headers.append(.{ .name = "X-Forwarded-For", .value = forwarded_for.value });
    try extra_headers.append(.{ .name = "X-Real-IP", .value = client_ip });
    try extra_headers.append(.{ .name = "X-Forwarded-Proto", .value = forwarded_proto });
    if (incoming_host) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) try extra_headers.append(.{ .name = "X-Forwarded-Host", .value = trimmed });
    }
    try gph.appendAssertedIdentityHeaders(&extra_headers, auth_identity, auth_user_id, auth_device_id, auth_scopes);
    var traceparent_buf: [55]u8 = undefined;
    if (request_headers.get("traceparent") == null) {
        const tc = http.trace_context.generate();
        const tp = tc.format(&traceparent_buf);
        if (tp.len > 0) try extra_headers.append(.{ .name = "traceparent", .value = tp });
    }

    var server_header_buffer: [16 * 1024]u8 = undefined;
    var req = try client.request(method_enum, uri, .{
        .headers = .{
            .connection = .omit,
            .user_agent = .omit,
            .accept_encoding = .omit,
        },
        .extra_headers = extra_headers.items,
        .keep_alive = true,
        .redirect_behavior = .unhandled,
    });
    defer req.deinit();

    const ttfb_start_ms = http.event_loop.monotonicMs();
    if (streaming_body) |stream_body| {
        req.transfer_encoding = .{ .content_length = stream_body.content_length };
        const body_writer_buffer = try allocator.alloc(u8, cfg.proxy_stream_buffer_size);
        defer allocator.free(body_writer_buffer);
        const relay_buffer = try allocator.alloc(u8, cfg.proxy_stream_buffer_size);
        defer allocator.free(relay_buffer);
        var body_writer = req.sendBodyUnflushed(body_writer_buffer) catch |err| {
            markRequestConnectionClosing(&req);
            return err;
        };

        var sent: usize = @min(stream_body.initial_bytes.len, stream_body.content_length);
        if (sent > 0) {
            body_writer.writer.writeAll(stream_body.initial_bytes[0..sent]) catch |err| {
                markRequestConnectionClosing(&req);
                return err;
            };
        }
        while (sent < stream_body.content_length) {
            if (cancel_token) |tok| {
                if (tok.isStopped()) {
                    markRequestConnectionClosing(&req);
                    return error.RequestCancelled;
                }
            }
            const want = @min(relay_buffer.len, stream_body.content_length - sent);
            const n = downstream_conn.read(relay_buffer[0..want]) catch {
                markRequestConnectionClosing(&req);
                return error.ClientAborted;
            };
            if (n == 0) {
                markRequestConnectionClosing(&req);
                return error.ClientAborted;
            }
            body_writer.writer.writeAll(relay_buffer[0..n]) catch |err| {
                markRequestConnectionClosing(&req);
                return err;
            };
            sent += n;
        }
        body_writer.end() catch |err| {
            markRequestConnectionClosing(&req);
            return err;
        };
    } else if (buffered_body.len > 0 or method_enum.requestHasBody()) {
        req.sendBodyComplete(@constCast(buffered_body)) catch |err| {
            markRequestConnectionClosing(&req);
            return err;
        };
    } else {
        req.sendBodiless() catch |err| {
            markRequestConnectionClosing(&req);
            return err;
        };
    }

    var resp = req.receiveHead(&server_header_buffer) catch |err| {
        markRequestConnectionClosing(&req);
        return err;
    };
    const ttfb_ms = http.event_loop.monotonicMs() - ttfb_start_ms;
    const status_code: u16 = @intFromEnum(resp.head.status);
    const reason = gpres.upstreamReasonPhrase(resp.head.status);

    var headers = std.array_list.Managed(UpstreamHeader).init(metadata_allocator);
    try headers.ensureUnusedCapacity(8);
    var header_it = resp.head.iterateHeaders();
    while (header_it.next()) |header| {
        if (gph.shouldSkipUpstreamResponseHeader(header.name)) continue;
        try headers.append(.{
            .name = try metadata_allocator.dupe(u8, header.name),
            .value = try metadata_allocator.dupe(u8, header.value),
        });
    }
    const upstream_headers = try headers.toOwnedSlice();
    const body_allowed = gpres.responseBodyAllowed(method, status_code);

    gpres.writeStreamedUpstreamResponseHeadFromHeaders(
        downstream_writer,
        status_code,
        reason,
        upstream_headers,
        body_allowed,
        correlation_id,
        security,
        sticky_set_cookie,
    ) catch {
        markRequestConnectionClosing(&req);
        return error.ClientAborted;
    };

    var streamed_body_bytes: usize = 0;
    if (body_allowed) {
        const expected_body_len = resp.head.content_length;
        const transfer_buffer = try allocator.alloc(u8, cfg.proxy_stream_buffer_size);
        defer allocator.free(transfer_buffer);
        const relay_buffer = try allocator.alloc(u8, cfg.proxy_stream_buffer_size);
        defer allocator.free(relay_buffer);
        var body_reader = resp.reader(transfer_buffer);
        while (true) {
            if (cancel_token) |tok| {
                if (tok.isStopped()) {
                    markRequestConnectionClosing(&req);
                    return error.RequestCancelled;
                }
            }
            const n = body_reader.readSliceShort(relay_buffer) catch |err| switch (err) {
                error.ReadFailed => {
                    markRequestConnectionClosing(&req);
                    return .{
                        .status_code = status_code,
                        .reason = reason,
                        .response_body_bytes = streamed_body_bytes,
                        .upstream_ttfb_ms = ttfb_ms,
                        .upstream_aborted = true,
                    };
                },
            };
            if (n == 0) break;
            gpres.writeChunk(downstream_writer, relay_buffer[0..n]) catch {
                markRequestConnectionClosing(&req);
                return error.ClientAborted;
            };
            streamed_body_bytes += n;
        }
        if (expected_body_len) |expected| {
            if (@as(u64, @intCast(streamed_body_bytes)) < expected) {
                markRequestConnectionClosing(&req);
                return .{
                    .status_code = status_code,
                    .reason = reason,
                    .response_body_bytes = streamed_body_bytes,
                    .upstream_ttfb_ms = ttfb_ms,
                    .upstream_aborted = true,
                };
            }
        }
        gpres.writeChunk(downstream_writer, "") catch {
            markRequestConnectionClosing(&req);
            return error.ClientAborted;
        };
    }

    return .{
        .status_code = status_code,
        .reason = reason,
        .response_body_bytes = streamed_body_bytes,
        .upstream_ttfb_ms = ttfb_ms,
        .upstream_aborted = false,
    };
}

pub fn upstreamResponseHasNoStore(response: std.http.Client.Response.Head) bool {
    var it = response.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cache-control")) continue;
        var tokens = std.mem.splitScalar(u8, header.value, ',');
        while (tokens.next()) |token_raw| {
            const token = std.mem.trim(u8, token_raw, " \t\r\n");
            if (std.ascii.eqlIgnoreCase(token, "no-store")) return true;
        }
    }
    return false;
}

pub const UpstreamMappedError = struct {
    status: u16,
    code: []const u8,
    message: []const u8,
};

pub const ProxyExecMappedError = struct {
    status: http.Status,
    code: []const u8,
    message: []const u8,
};

pub fn mapUpstreamError(status: u16) UpstreamMappedError {
    return switch (status) {
        401 => .{ .status = 401, .code = "unauthorized", .message = "Unauthorized" },
        429 => .{ .status = 429, .code = "rate_limited", .message = "Rate limited" },
        502, 503 => .{ .status = 503, .code = "tool_unavailable", .message = "Upstream unavailable" },
        504 => .{ .status = 504, .code = "upstream_timeout", .message = "Upstream timeout" },
        else => .{ .status = 500, .code = "internal_error", .message = "Internal error" },
    };
}

pub fn mapControlPlaneProxyExecutionError(err: anyerror) ProxyExecMappedError {
    return switch (err) {
        error.UpstreamUntrusted => .{
            .status = .service_unavailable,
            .code = "upstream_untrusted",
            .message = "Untrusted upstream response",
        },
        error.Timeout => .{
            .status = .gateway_timeout,
            .code = "upstream_timeout",
            .message = "Upstream timeout",
        },
        else => .{
            .status = .gateway_timeout,
            .code = "upstream_timeout",
            .message = "Upstream timeout",
        },
    };
}

test "mapUpstreamError returns stable codes" {
    const mapped = mapUpstreamError(502);
    try std.testing.expectEqual(@as(u16, 503), mapped.status);
    try std.testing.expectEqualStrings("tool_unavailable", mapped.code);
}

// --- Malformed upstream response handling tests ---

test "parseBufferedUpstreamResponse handles response with no body" {
    // The parser requires at least one header line so that headers_raw contains
    // a newline (from which the status-line boundary is found).
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 204 No Content\r\nX-Accel-Buffering: no\r\n\r\n",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 204), parsed.status_code);
    try std.testing.expectEqualStrings("No Content", parsed.reason);
    try std.testing.expectEqualStrings("", parsed.body);
    try std.testing.expectEqualStrings("no", parsed.headerValue("X-Accel-Buffering").?);
}

test "parseBufferedUpstreamResponse strips hop-by-hop headers from upstream 5xx responses" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 502 Bad Gateway\r\n" ++
            "Connection: close\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "Server: nginx/1.24.0\r\n" ++
            "X-Powered-By: PHP/8.1\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "\r\n" ++
            "error",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 502), parsed.status_code);
    try std.testing.expect(parsed.headerValue("connection") == null);
    try std.testing.expect(parsed.headerValue("transfer-encoding") == null);
    try std.testing.expect(parsed.headerValue("server") == null);
    try std.testing.expect(parsed.headerValue("x-powered-by") == null);
    try std.testing.expectEqualStrings("text/plain", parsed.headerValue("content-type").?);
}

test "parseBufferedUpstreamResponse strips Content-Length from upstream (Tardigrade recalculates)" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Length: 5\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "\r\n" ++
            "hello",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expect(parsed.headerValue("content-length") == null);
    try std.testing.expectEqualStrings("text/plain", parsed.headerValue("content-type").?);
    try std.testing.expectEqualStrings("hello", parsed.body);
}

test "parseBufferedUpstreamResponse handles upstream with missing reason phrase" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 200 \r\nContent-Type: text/plain\r\n\r\nbody",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 200), parsed.status_code);
    try std.testing.expectEqualStrings("body", parsed.body);
}

test "parseBufferedUpstreamResponse errors on empty response" {
    try std.testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(std.testing.allocator, ""),
    );
}

test "parseBufferedUpstreamResponse errors on truncated status line" {
    try std.testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(std.testing.allocator, "HTTP/1.1 200"),
    );
}

test "parseBufferedUpstreamResponse errors when header block is never terminated" {
    try std.testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(
            std.testing.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
        ),
    );
}

// ---------------------------------------------------------------------------
// Bounded transport exchange + timeout enforcement (issue #196)
// ---------------------------------------------------------------------------
//
// These tests drive exchangeBoundedBufferedHttpRequest over a blocking
// socketpair: deterministic, no event loop, no threads. They cover the two
// behaviors the std.http.Client path could not provide: a correct buffered
// request/response exchange, and a bounded response read that returns an error
// (rather than blocking forever) when the peer never replies.

fn makeBlockingSocketpair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) {
        return error.SocketPairFailed;
    }
    return fds;
}

test "exchangeBoundedBufferedHttpRequest parses a buffered response from a peer" {
    const allocator = std.testing.allocator;
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    // Pre-load the peer's response, then shut its write side so the client read
    // loop sees EOF once the response is drained.
    const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello";
    _ = std.c.write(peer_fd, response.ptr, response.len);
    _ = std.c.shutdown(peer_fd, std.posix.SHUT.WR);

    const uri = try std.Uri.parse("http://localhost/");
    var resp = try exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        1_000,
        1_000,
    );
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello", resp.body);
    try std.testing.expectEqualStrings("text/plain", resp.headerValue("content-type").?);

    // The serialized request is readable from the peer end, Connection: close
    // and a derived Host header included.
    var req_buf: [512]u8 = undefined;
    const n = std.c.read(peer_fd, &req_buf, req_buf.len);
    try std.testing.expect(n > 0);
    const req = req_buf[0..@intCast(n)];
    try std.testing.expect(std.mem.startsWith(u8, req, "GET / HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, req, "Connection: close\r\n") != null);
}

test "exchangeBoundedBufferedHttpRequest enforces the response read timeout when the peer never replies" {
    const allocator = std.testing.allocator;
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    // The peer accepts the request bytes but never writes a response and never
    // closes. Without per-phase timeouts the client read would block forever;
    // the 200ms response timeout must surface an error instead.
    const uri = try std.Uri.parse("http://localhost/");
    const start_ms = http.event_loop.monotonicMs();
    const result = exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        1_000, // send timeout: generous
        200, // response timeout: short — this must fire on the silent peer
    );
    const elapsed_ms = http.event_loop.monotonicMs() - start_ms;

    if (result) |resp_val| {
        var resp = resp_val;
        resp.deinit(allocator);
        return error.TestUnexpectedResult; // a silent peer must not yield a response
    } else |_| {}

    // Returned via the 200ms poll deadline, well before any test-suite watchdog.
    try std.testing.expect(elapsed_ms >= 150);
    try std.testing.expect(elapsed_ms < 2_000);
}

/// Raw blocking responder: accepts one connection, drains the request, writes a
/// fixed 200 response, and closes. Uses std.c directly so the test never touches
/// the std.Io event loop.
fn rawHttpResponder(listen_fd: std.posix.fd_t) void {
    const conn = std.c.accept(listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);
    var buf: [4096]u8 = undefined;
    _ = std.c.read(conn, &buf, buf.len);
    const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello";
    _ = std.c.write(conn, response.ptr, response.len);
}

test "connectBlockingTcp + exchange round-trips a real TCP origin" {
    const allocator = std.testing.allocator;

    // Raw blocking listener (no event loop).
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);
    _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));

    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 8) == 0);

    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try std.testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
    const port = std.mem.bigToNative(u16, bound.port);
    try std.testing.expect(port != 0);

    const responder = try std.Thread.spawn(.{}, rawHttpResponder, .{listen_fd});
    defer responder.join();

    const uri = try std.Uri.parse("http://127.0.0.1/");
    var resp = try executeBoundedBufferedTcpHttpRequest(
        allocator,
        "127.0.0.1",
        port,
        null,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        2_000,
        2_000,
    );
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello", resp.body);
    try std.testing.expectEqualStrings("text/plain", resp.headerValue("content-type").?);
}

test "connectBlockingUnix + exchange round-trips a Unix-socket origin" {
    const allocator = std.testing.allocator;

    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var rnd: [8]u8 = undefined;
    compat.randomBytes(&rnd);
    const full_path = try std.fmt.bufPrint(&full_path_buf, "/tmp/tardigrade-test-{x}.sock", .{std.mem.readInt(u64, &rnd, .little)});
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(path_z[0..full_path.len], full_path);
    path_z[full_path.len] = 0;
    _ = std.c.unlink(@ptrCast(&path_z)); // best-effort: clear any stale socket
    defer _ = std.c.unlink(@ptrCast(&path_z));

    const listen_fd = std.c.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);

    var un = std.mem.zeroes(std.c.sockaddr.un);
    un.family = std.posix.AF.UNIX;
    try std.testing.expect(full_path.len < un.path.len);
    @memcpy(un.path[0..full_path.len], full_path);
    const un_len: std.posix.socklen_t = @intCast(@offsetOf(std.c.sockaddr.un, "path") + full_path.len + 1);
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&un), un_len) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 8) == 0);

    const responder = try std.Thread.spawn(.{}, rawHttpResponder, .{listen_fd});
    defer responder.join();

    const uri = try std.Uri.parse("http://localhost/");
    var resp = try executeBoundedBufferedUnixSocketHttpRequest(
        allocator,
        full_path,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        2_000,
        2_000,
    );
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello", resp.body);
}
