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
    var stream = try compat.connectUnixSocket(socket_path);
    defer stream.close();

    if (timeout_ms > 0) {
        try setSocketTimeoutMs(stream.handle, timeout_ms, timeout_ms);
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

    try stream.writeAll(req_aw.written());

    // Switch the recv timeout to the response-specific limit after the request
    // is sent, bounding just the wait for the upstream to begin responding.
    if (response_timeout_ms > 0) {
        try setSocketRecvTimeoutMs(stream.handle, response_timeout_ms);
    }

    var resp_raw = std.array_list.Managed(u8).init(allocator);
    defer resp_raw.deinit();
    var read_buf: [8192]u8 = undefined;
    while (true) {
        const n = try stream.read(&read_buf);
        if (n == 0) break;
        try resp_raw.appendSlice(read_buf[0..n]);
        if (resp_raw.items.len > max_buffered_response_bytes) return error.StreamTooLong;
    }

    return parseBufferedUpstreamResponse(allocator, resp_raw.items);
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
    client: *std.http.Client,
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
    /// Only enforced on Unix socket upstreams; std.http.Client does not expose
    /// per-phase socket timeout control.
    response_timeout_ms: u32,
    cancel_token: ?*const CancellationToken,
) !BufferedUpstreamResponse {
    // Bail out before touching the network if the request is already stopped.
    if (cancel_token) |tok| {
        if (tok.isStopped()) return error.RequestCancelled;
    }
    const proxy_extra_header_slack = 10;
    const max_buffered_response_bytes = maxBufferedUpstreamResponseBytes(cfg);
    var extra_headers_stack = std.heap.stackFallback(2048, allocator);
    const extra_headers_allocator = extra_headers_stack.get();
    const method_enum = std.meta.stringToEnum(std.http.Method, method) orelse return error.UnsupportedHttpMethod;
    const uri = try std.Uri.parse(url);
    var forwarded_for = try gph.buildForwardedFor(allocator, request_headers.get("x-forwarded-for"), client_ip);
    defer forwarded_for.deinit(allocator);
    var metadata_arena = std.heap.ArenaAllocator.init(allocator);
    errdefer metadata_arena.deinit();
    const metadata_allocator = metadata_arena.allocator();

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

    if (body.len > 0 or method_enum.requestHasBody()) {
        req.sendBodyComplete(@constCast(body)) catch |err| {
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

    var body_buf: [8192]u8 = undefined;
    var body_reader = resp.reader(&body_buf);
    const body_data = if (resp.head.content_length) |content_length| blk: {
        if (content_length > max_buffered_response_bytes) return error.StreamTooLong;
        const exact_len: usize = @intCast(content_length);
        var body_list: std.ArrayList(u8) = .empty;
        defer body_list.deinit(allocator);
        try body_reader.appendExact(allocator, &body_list, exact_len);
        break :blk try body_list.toOwnedSlice(allocator);
    } else try body_reader.allocRemaining(allocator, .limited(max_buffered_response_bytes));
    errdefer allocator.free(body_data);

    return .{
        .metadata_arena = metadata_arena,
        .status_code = @intFromEnum(resp.head.status),
        .reason = try metadata_allocator.dupe(u8, gpres.upstreamReasonPhrase(resp.head.status)),
        .headers = try headers.toOwnedSlice(),
        .body = body_data,
    };
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
