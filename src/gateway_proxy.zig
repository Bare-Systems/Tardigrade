const compat = @import("zig_compat.zig");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gs = @import("gateway_state.zig");
const GatewayState = gs.GatewayState;
const maxBufferedUpstreamResponseBytes = gs.maxBufferedUpstreamResponseBytes;
const isAbsoluteHttpUrl = gs.isAbsoluteHttpUrl;
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

pub const RawUpstreamResponse = struct {
    metadata_arena: std.heap.ArenaAllocator,
    status_code: u16,
    reason: []const u8,
    headers: []UpstreamHeader,
    body: []u8,

    pub fn deinit(self: *RawUpstreamResponse, allocator: std.mem.Allocator) void {
        self.metadata_arena.deinit();
        allocator.free(self.body);
        self.* = undefined;
    }

    pub fn headerValue(self: *const RawUpstreamResponse, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        }
        return null;
    }
};

pub fn uriComponentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |value| value,
        .percent_encoded => |value| value,
    };
}

pub fn parseRawUpstreamResponse(allocator: std.mem.Allocator, raw: []const u8) !RawUpstreamResponse {
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
        if (shouldSkipUpstreamResponseHeader(hname)) continue;
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

pub fn executeUnixSocketHttpRequest(
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
) !RawUpstreamResponse {
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

    return parseRawUpstreamResponse(allocator, resp_raw.items);
}

test "parseRawUpstreamResponse keeps metadata in an arena and preserves forwarded headers" {
    var parsed = try parseRawUpstreamResponse(
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
    try std.testing.expect(rawUpstreamResponseHasNoStore(&parsed));
    try std.testing.expectEqualStrings("ok", parsed.body);
}

test "parseRawUpstreamResponse returns UpstreamProtocolError on partial upstream response" {
    // Simulates an upstream that closes the TCP connection before sending a
    // complete HTTP response head (the scenario reported in issue #94).
    // Before the fix this returned error.UnsupportedHttpMethod, a misleading
    // name that also prevented callers from distinguishing a real method
    // rejection from a dropped-connection scenario.
    const testing = std.testing;

    // Upstream closed immediately — empty body
    try testing.expectError(error.UpstreamProtocolError, parseRawUpstreamResponse(testing.allocator, ""));

    // Upstream sent a partial status line and closed
    try testing.expectError(error.UpstreamProtocolError, parseRawUpstreamResponse(testing.allocator, "HTTP/1.1"));

    // Upstream sent headers but no blank line (no \r\n\r\n terminator)
    try testing.expectError(error.UpstreamProtocolError, parseRawUpstreamResponse(testing.allocator, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"));
}

pub fn rawUpstreamResponseHasNoStore(response: *const RawUpstreamResponse) bool {
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

pub fn upstreamReasonPhrase(status: std.http.Status) []const u8 {
    return status.phrase() orelse "";
}

fn markRequestConnectionClosing(req: *std.http.Client.Request) void {
    if (req.connection) |connection| {
        connection.closing = true;
    }
}

pub fn executeRawHttpProxyRequest(
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
) !RawUpstreamResponse {
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
    var forwarded_for = try buildForwardedFor(allocator, request_headers.get("x-forwarded-for"), client_ip);
    defer forwarded_for.deinit(allocator);
    var metadata_arena = std.heap.ArenaAllocator.init(allocator);
    errdefer metadata_arena.deinit();
    const metadata_allocator = metadata_arena.allocator();

    var extra_headers = std.array_list.Managed(std.http.Header).init(extra_headers_allocator);
    defer extra_headers.deinit();
    try extra_headers.ensureUnusedCapacity(request_headers.count() + proxy_extra_header_slack);
    try appendProxyRequestHeaders(&extra_headers, request_headers);
    try appendRequestIdHeaders(&extra_headers, correlation_id);
    try extra_headers.append(.{ .name = "X-Forwarded-For", .value = forwarded_for.value });
    try extra_headers.append(.{ .name = "X-Real-IP", .value = client_ip });
    try extra_headers.append(.{ .name = "X-Forwarded-Proto", .value = forwarded_proto });
    if (incoming_host) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) try extra_headers.append(.{ .name = "X-Forwarded-Host", .value = trimmed });
    }
    try appendAssertedIdentityHeaders(&extra_headers, auth_identity, auth_user_id, auth_device_id, auth_scopes);
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
        return executeUnixSocketHttpRequest(
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
        if (shouldSkipUpstreamResponseHeader(header.name)) continue;
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
        .reason = try metadata_allocator.dupe(u8, upstreamReasonPhrase(resp.head.status)),
        .headers = try headers.toOwnedSlice(),
        .body = body_data,
    };
}

/// Execute an HTTPS upstream proxy request using OpenSSL directly, supporting
/// custom CA bundles, SNI overrides, and mutual TLS client certificates.
/// Used when `TARDIGRADE_UPSTREAM_TLS_CLIENT_CERT` is set.
pub fn executeUpstreamHttpsWithMtls(
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
) !RawUpstreamResponse {
    const max_buffered_response_bytes = maxBufferedUpstreamResponseBytes(cfg);
    const uri = try std.Uri.parse(url);
    const host = if (uri.host) |h| switch (h) {
        .raw => |r| r,
        .percent_encoded => |pe| pe,
    } else return error.UnsupportedHttpMethod;
    const port: u16 = if (uri.port) |p| p else 443;
    const tcp_stream = try compat.tcpConnectToHost(allocator, host, port);
    defer tcp_stream.close();

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
    var forwarded_for = try buildForwardedFor(allocator, request_headers.get("x-forwarded-for"), client_ip);
    defer forwarded_for.deinit(allocator);

    var req_aw: std.Io.Writer.Allocating = .init(allocator);
    defer req_aw.deinit();
    const req_writer = &req_aw.writer;
    try req_writer.print("{s} {s} HTTP/1.1\r\n", .{ method, path_raw });
    try req_writer.print("Host: {s}\r\n", .{host});
    try req_writer.print("Connection: close\r\n", .{});
    if (body.len > 0) try req_writer.print("Content-Length: {d}\r\n", .{body.len});
    try writeRequestIdHeaders(req_writer, correlation_id);
    try req_writer.print("X-Forwarded-For: {s}\r\n", .{forwarded_for.value});
    try req_writer.print("X-Real-IP: {s}\r\n", .{client_ip});
    try req_writer.print("X-Forwarded-Proto: {s}\r\n", .{forwarded_proto});
    if (incoming_host) |h| {
        const trimmed = std.mem.trim(u8, h, " \t\r\n");
        if (trimmed.len > 0) try req_writer.print("X-Forwarded-Host: {s}\r\n", .{trimmed});
    }
    try writeAssertedIdentityHeaders(req_writer, auth_identity, auth_user_id, auth_device_id, auth_scopes);
    const connection_header = request_headers.get("connection");
    for (request_headers.iterator()) |entry| {
        if (shouldSkipUpstreamRequestHeader(entry.name, connection_header)) continue;
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
    return parseRawUpstreamResponse(allocator, resp_raw.items);
}

pub fn applyResponseHeaders(state: *GatewayState, response: *http.Response) void {
    state.security_headers.apply(response);
    for (state.add_headers) |pair| {
        _ = response.setHeader(pair.name, pair.value);
    }
    if (state.http3_alt_svc) |value| {
        _ = response.setHeader("Alt-Svc", value);
    }
}

pub fn appendAssertedIdentityHeaders(
    headers: *std.array_list.Managed(std.http.Header),
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
) !void {
    if (auth_identity) |identity| {
        if (identity.len > 0) try headers.append(.{ .name = "X-Tardigrade-Auth-Identity", .value = identity });
    }
    if (auth_user_id) |user_id| {
        if (user_id.len > 0) try headers.append(.{ .name = "X-Tardigrade-User-ID", .value = user_id });
    }
    if (auth_device_id) |device_id| {
        if (device_id.len > 0) try headers.append(.{ .name = "X-Tardigrade-Device-ID", .value = device_id });
    }
    if (auth_scopes) |scopes| {
        if (scopes.len > 0) try headers.append(.{ .name = "X-Tardigrade-Scopes", .value = scopes });
    }
}

pub fn writeAssertedIdentityHeaders(
    writer: anytype,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
) !void {
    if (auth_identity) |identity| {
        if (identity.len > 0) try writer.print("X-Tardigrade-Auth-Identity: {s}\r\n", .{identity});
    }
    if (auth_user_id) |user_id| {
        if (user_id.len > 0) try writer.print("X-Tardigrade-User-ID: {s}\r\n", .{user_id});
    }
    if (auth_device_id) |device_id| {
        if (device_id.len > 0) try writer.print("X-Tardigrade-Device-ID: {s}\r\n", .{device_id});
    }
    if (auth_scopes) |scopes| {
        if (scopes.len > 0) try writer.print("X-Tardigrade-Scopes: {s}\r\n", .{scopes});
    }
}

pub fn writeStreamedUpstreamResponse(
    writer: anytype,
    status_code: u16,
    reason: []const u8,
    content_type: []const u8,
    content_disposition: ?[]const u8,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    sticky_set_cookie: ?[]const u8,
) !void {
    var header_buf: [4096]u8 = undefined;
    var header_stream = compat.fixedBufferStream(&header_buf);
    writeStreamedUpstreamResponseHead(
        header_stream.writer(),
        status_code,
        reason,
        content_type,
        content_disposition,
        correlation_id,
        security,
        sticky_set_cookie,
    ) catch {
        try writeStreamedUpstreamResponseHead(
            writer,
            status_code,
            reason,
            content_type,
            content_disposition,
            correlation_id,
            security,
            sticky_set_cookie,
        );
        return;
    };
    try writer.writeAll(header_stream.getWritten());
}

pub fn writeStreamedUpstreamResponseHead(
    writer: anytype,
    status_code: u16,
    reason: []const u8,
    content_type: []const u8,
    content_disposition: ?[]const u8,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    sticky_set_cookie: ?[]const u8,
) !void {
    const phrase = if (reason.len > 0)
        reason
    else
        (@as(std.http.Status, @enumFromInt(status_code)).phrase() orelse "");

    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ status_code, phrase });
    try writer.print("Server: {s}\r\n", .{http.SERVER_NAME});
    try writer.writeAll("Connection: close\r\n");
    try writer.writeAll("Transfer-Encoding: chunked\r\n");
    try writer.print("Content-Type: {s}\r\n", .{content_type});
    try writeRequestIdHeaders(writer, correlation_id);
    if (content_disposition) |cd| {
        try writer.print("Content-Disposition: {s}\r\n", .{cd});
    }
    if (sticky_set_cookie) |cookie| {
        try writer.print("Set-Cookie: {s}\r\n", .{cookie});
    }

    try writeSecurityHeaders(writer, security);
    try writer.writeAll("\r\n");
}

pub fn writeBufferedUpstreamResponse(
    writer: anytype,
    upstream_response: *const RawUpstreamResponse,
    keep_alive: bool,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    sticky_set_cookie: ?[]const u8,
) !void {
    var response_buf: [8192]u8 = undefined;
    var response_stream = compat.fixedBufferStream(&response_buf);
    writeBufferedUpstreamResponseHead(
        response_stream.writer(),
        upstream_response,
        keep_alive,
        correlation_id,
        security,
        sticky_set_cookie,
    ) catch {
        try writeBufferedUpstreamResponseHead(
            writer,
            upstream_response,
            keep_alive,
            correlation_id,
            security,
            sticky_set_cookie,
        );
        if (upstream_response.body.len > 0) try writer.writeAll(upstream_response.body);
        return;
    };
    const head_len = response_stream.getWritten().len;
    if (upstream_response.body.len > 0) {
        response_stream.writer().writeAll(upstream_response.body) catch {
            const written = response_stream.getWritten();
            const body_prefix_len = written.len - head_len;
            try writer.writeAll(written);
            try writer.writeAll(upstream_response.body[body_prefix_len..]);
            return;
        };
    }
    try writer.writeAll(response_stream.getWritten());
}

pub fn writeBufferedUpstreamResponseHead(
    writer: anytype,
    upstream_response: *const RawUpstreamResponse,
    keep_alive: bool,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
    sticky_set_cookie: ?[]const u8,
) !void {
    const phrase = if (upstream_response.reason.len > 0)
        upstream_response.reason
    else
        (@as(std.http.Status, @enumFromInt(upstream_response.status_code)).phrase() orelse "");

    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ upstream_response.status_code, phrase });
    try writer.print("Server: {s}\r\n", .{http.SERVER_NAME});
    try writer.print("Connection: {s}\r\n", .{if (keep_alive) "keep-alive" else "close"});
    try writer.print("Content-Length: {d}\r\n", .{upstream_response.body.len});
    try writeRequestIdHeaders(writer, correlation_id);
    for (upstream_response.headers) |header| {
        // Defense-in-depth: skip any upstream header that should not be
        // forwarded even if parse-time filtering missed it (e.g. headers
        // populated through a code path that bypasses shouldSkipUpstreamResponseHeader).
        if (shouldSkipUpstreamResponseHeader(header.name)) continue;
        try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    if (sticky_set_cookie) |cookie| {
        try writer.print("Set-Cookie: {s}\r\n", .{cookie});
    }
    // Only inject security headers that the upstream did not already supply,
    // preventing duplicate / conflicting headers (e.g. double CSP).
    try writeSecurityHeadersFiltered(writer, security, upstream_response.headers);
    try writer.writeAll("\r\n");
}

pub fn appendProxyRequestHeaders(
    extra_headers: *std.array_list.Managed(std.http.Header),
    request_headers: *const http.Headers,
) !void {
    const connection_header = request_headers.get("connection");
    for (request_headers.iterator()) |header| {
        if (shouldSkipUpstreamRequestHeader(header.name, connection_header)) continue;
        try extra_headers.append(.{ .name = header.name, .value = header.value });
    }
}

pub fn shouldSkipUpstreamRequestHeader(name: []const u8, connection_header: ?[]const u8) bool {
    // Strip inbound X-Tardigrade-* headers so clients cannot forge asserted
    // identity. Tardigrade re-adds the real values after auth resolves.
    const tardigrade_prefix = "x-tardigrade-";
    if (name.len >= tardigrade_prefix.len and
        std.ascii.eqlIgnoreCase(name[0..tardigrade_prefix.len], tardigrade_prefix))
        return true;

    if (connectionHeaderReferencesHeader(connection_header, name)) return true;

    return std.ascii.eqlIgnoreCase(name, "accept-encoding") or
        std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-authenticate") or
        std.ascii.eqlIgnoreCase(name, "proxy-authorization") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "te") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade") or
        std.ascii.eqlIgnoreCase(name, "x-forwarded-for") or
        std.ascii.eqlIgnoreCase(name, "x-forwarded-host") or
        std.ascii.eqlIgnoreCase(name, "x-forwarded-proto") or
        std.ascii.eqlIgnoreCase(name, "x-real-ip") or
        std.ascii.eqlIgnoreCase(name, http.correlation.REQUEST_HEADER_NAME) or
        std.ascii.eqlIgnoreCase(name, http.correlation.HEADER_NAME);
}

pub fn connectionHeaderReferencesHeader(connection_header: ?[]const u8, name: []const u8) bool {
    const raw = connection_header orelse return false;
    var tokens = std.mem.splitScalar(u8, raw, ',');
    while (tokens.next()) |token_raw| {
        const token = std.mem.trim(u8, token_raw, " \t");
        if (token.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(token, name)) return true;
    }
    return false;
}

pub fn shouldSkipUpstreamResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-encoding") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "te") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "upgrade") or
        // Strip upstream technology-disclosure headers. Tardigrade emits its
        // own Server header; leaking the upstream value exposes backend stack
        // details to external clients (WSTG-INFO-02, ASVS-14.3.3).
        std.ascii.eqlIgnoreCase(name, "server") or
        std.ascii.eqlIgnoreCase(name, "x-powered-by") or
        std.ascii.eqlIgnoreCase(name, http.correlation.REQUEST_HEADER_NAME) or
        std.ascii.eqlIgnoreCase(name, http.correlation.HEADER_NAME);
}

pub fn computeHstsValue(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig) ![]u8 {
    if (!cfg.hsts_enabled or cfg.tls_cert_path.len == 0) return allocator.dupe(u8, "");
    const subs = if (cfg.hsts_include_subdomains) "; includeSubDomains" else "";
    const preload = if (cfg.hsts_preload) "; preload" else "";
    return std.fmt.allocPrint(allocator, "max-age={d}{s}{s}", .{ cfg.hsts_max_age, subs, preload });
}

pub fn writeSecurityHeaders(writer: anytype, sec: *const http.security_headers.SecurityHeaders) !void {
    try writeSecurityHeadersFiltered(writer, sec, &[_]UpstreamHeader{});
}

/// Like writeSecurityHeaders but skips any header already present in
/// `upstream_headers`, preventing duplicate / conflicting headers when the
/// upstream (e.g. a Rails app) already supplies its own security policy.
pub fn writeSecurityHeadersFiltered(
    writer: anytype,
    sec: *const http.security_headers.SecurityHeaders,
    upstream_headers: []const UpstreamHeader,
) !void {
    const has = struct {
        fn header(headers: []const UpstreamHeader, name: []const u8) bool {
            for (headers) |h| {
                if (std.ascii.eqlIgnoreCase(h.name, name)) return true;
            }
            return false;
        }
    }.header;

    if (sec.x_frame_options.len > 0 and !has(upstream_headers, "X-Frame-Options"))
        try writer.print("X-Frame-Options: {s}\r\n", .{sec.x_frame_options});
    if (sec.x_content_type_options.len > 0 and !has(upstream_headers, "X-Content-Type-Options"))
        try writer.print("X-Content-Type-Options: {s}\r\n", .{sec.x_content_type_options});
    if (sec.content_security_policy.len > 0 and !has(upstream_headers, "Content-Security-Policy"))
        try writer.print("Content-Security-Policy: {s}\r\n", .{sec.content_security_policy});
    if (sec.strict_transport_security.len > 0 and !has(upstream_headers, "Strict-Transport-Security"))
        try writer.print("Strict-Transport-Security: {s}\r\n", .{sec.strict_transport_security});
    if (sec.referrer_policy.len > 0 and !has(upstream_headers, "Referrer-Policy"))
        try writer.print("Referrer-Policy: {s}\r\n", .{sec.referrer_policy});
    if (sec.permissions_policy.len > 0 and !has(upstream_headers, "Permissions-Policy"))
        try writer.print("Permissions-Policy: {s}\r\n", .{sec.permissions_policy});
    if (sec.x_xss_protection.len > 0 and !has(upstream_headers, "X-XSS-Protection"))
        try writer.print("X-XSS-Protection: {s}\r\n", .{sec.x_xss_protection});
    if (sec.cross_origin_opener_policy.len > 0 and !has(upstream_headers, "Cross-Origin-Opener-Policy"))
        try writer.print("Cross-Origin-Opener-Policy: {s}\r\n", .{sec.cross_origin_opener_policy});
    if (sec.cross_origin_resource_policy.len > 0 and !has(upstream_headers, "Cross-Origin-Resource-Policy"))
        try writer.print("Cross-Origin-Resource-Policy: {s}\r\n", .{sec.cross_origin_resource_policy});
}

test "writeBufferedUpstreamResponse preserves oversized body bytes exactly" {
    const allocator = std.testing.allocator;
    const prefix = "/*! tailwindcss v4.1.4 | MIT License | synthetic */\n";
    const extra_len = 16 * 1024;
    const body = try allocator.alloc(u8, prefix.len + extra_len);
    defer allocator.free(body);
    @memcpy(body[0..prefix.len], prefix);
    for (body[prefix.len..], 0..) |*byte, idx| {
        byte.* = @intCast('a' + @as(u8, @intCast(idx % 26)));
    }

    var upstream_headers = [_]UpstreamHeader{
        .{ .name = "Content-Type", .value = "text/css" },
    };
    var response = RawUpstreamResponse{
        .metadata_arena = std.heap.ArenaAllocator.init(allocator),
        .status_code = 200,
        .reason = "OK",
        .headers = upstream_headers[0..],
        .body = body,
    };
    defer response.metadata_arena.deinit();

    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try writeBufferedUpstreamResponse(
        &output.writer,
        &response,
        false,
        "req-large-body",
        &http.security_headers.SecurityHeaders.api,
        null,
    );

    const raw = output.written();
    const head_end = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.InvalidHttpResponse;
    try std.testing.expectEqualStrings(body, raw[head_end + 4 ..]);
}

pub fn writeChunk(writer: anytype, bytes: []const u8) !void {
    try writer.print("{x}\r\n", .{bytes.len});
    try writer.writeAll(bytes);
    try writer.writeAll("\r\n");
}

pub fn stripPort(authority: []const u8) []const u8 {
    if (authority.len == 0) return authority;
    if (authority[0] == '[') {
        const close_idx = std.mem.findScalar(u8, authority, ']') orelse return authority;
        return authority[0 .. close_idx + 1];
    }
    const colon_idx = std.mem.findScalarLast(u8, authority, ':') orelse return authority;
    return authority[0..colon_idx];
}

pub fn isTrustedUpstream(cfg: *const edge_config.EdgeConfig, upstream_host: []const u8) bool {
    if (!cfg.trust_require_upstream_identity and cfg.trusted_upstream_identities.len == 0) return true;
    if (upstream_host.len == 0) return false;
    const host = stripPort(upstream_host);

    for (cfg.trusted_upstream_identities) |trusted| {
        const trusted_host = stripPort(trusted);
        if (std.ascii.eqlIgnoreCase(trusted, upstream_host) or std.ascii.eqlIgnoreCase(trusted_host, host)) {
            return true;
        }
    }
    return false;
}

pub fn appendTrustedUpstreamHeaders(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    extra_headers: *std.array_list.Managed(std.http.Header),
    owned_header_values: *std.array_list.Managed([]u8),
    target_url: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    auth_identity: ?[]const u8,
    api_version: ?u32,
    payload: []const u8,
) !void {
    if (cfg.trust_shared_secret.len == 0) return;

    const ts = compat.unixTimestamp();
    const ts_value = try std.fmt.allocPrint(allocator, "{d}", .{ts});
    try owned_header_values.append(ts_value);
    try extra_headers.append(.{ .name = "X-Tardigrade-Gateway-Id", .value = cfg.trust_gateway_id });
    try extra_headers.append(.{ .name = "X-Tardigrade-Trust-Timestamp", .value = ts_value });

    var payload_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &payload_digest, .{});
    var payload_digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&payload_digest_hex, "{f}", .{compat.fmtSliceHexLower(&payload_digest)}) catch unreachable;

    const identity = auth_identity orelse "-";
    const api_version_value = if (api_version) |ver|
        try std.fmt.allocPrint(allocator, "{d}", .{ver})
    else
        try allocator.dupe(u8, "-");
    defer allocator.free(api_version_value);

    const material = try std.fmt.allocPrint(
        allocator,
        "POST\n{s}\n{s}\n{s}\n{s}\n{s}\n{s}\n{s}\n{s}",
        .{ target_url, correlation_id, client_ip, cfg.trust_gateway_id, ts_value, payload_digest_hex, identity, api_version_value },
    );
    defer allocator.free(material);

    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, material, cfg.trust_shared_secret);
    const signature_hex = try std.fmt.allocPrint(allocator, "{f}", .{compat.fmtSliceHexLower(&mac)});
    try owned_header_values.append(signature_hex);
    try extra_headers.append(.{ .name = "X-Tardigrade-Trust-Signature", .value = signature_hex });
}

pub fn buildForwardedFor(allocator: std.mem.Allocator, incoming: ?[]const u8, client_ip: []const u8) !MaybeOwnedBytes {
    if (incoming) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) {
            const owned = try std.fmt.allocPrint(allocator, "{s}, {s}", .{ trimmed, client_ip });
            return .{ .value = owned, .owned = owned };
        }
    }
    return .{ .value = client_ip };
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

pub const ResolvedProxyTarget = struct {
    url: []u8,
    upstream_host: []const u8,
    unix_socket_path: ?[]const u8 = null,
};

pub const MaybeOwnedBytes = struct {
    value: []const u8,
    owned: ?[]u8 = null,

    pub fn deinit(self: *MaybeOwnedBytes, allocator: std.mem.Allocator) void {
        if (self.owned) |buf| allocator.free(buf);
        self.* = undefined;
    }
};

pub fn isRedirectStatusCode(status_code: u16) bool {
    return switch (status_code) {
        301, 302, 303, 307, 308 => true,
        else => false,
    };
}

pub fn resolveProxyTarget(
    allocator: std.mem.Allocator,
    upstream_base_url: []const u8,
    proxy_pass_target: []const u8,
    suffix_path: ?[]const u8,
) !ResolvedProxyTarget {
    const target_trimmed = std.mem.trim(u8, proxy_pass_target, " \t\r\n");
    const target = if (target_trimmed.len == 0) "/" else target_trimmed;
    const combined_target = try combineProxyTarget(allocator, target, suffix_path);
    errdefer allocator.free(combined_target);

    if (isAbsoluteHttpUrl(target)) {
        return .{
            .url = combined_target,
            .upstream_host = parseUpstreamHost(combined_target) orelse "",
            .unix_socket_path = null,
        };
    }

    if (unixSocketPathFromEndpoint(upstream_base_url)) |socket_path| {
        var normalized: []const u8 = combined_target;
        if (!std.mem.startsWith(u8, normalized, "/")) {
            const with_slash = try std.fmt.allocPrint(allocator, "/{s}", .{normalized});
            allocator.free(combined_target);
            normalized = with_slash;
        }
        const full_url = try std.fmt.allocPrint(allocator, "http://localhost{s}", .{normalized});
        allocator.free(normalized);
        return .{
            .url = full_url,
            .upstream_host = socket_path,
            .unix_socket_path = socket_path,
        };
    }

    var normalized: []const u8 = combined_target;
    if (!std.mem.startsWith(u8, normalized, "/")) {
        const with_slash = try std.fmt.allocPrint(allocator, "/{s}", .{normalized});
        allocator.free(combined_target);
        normalized = with_slash;
    }
    errdefer if (normalized.ptr != combined_target.ptr) allocator.free(normalized);

    const full_url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ upstream_base_url, normalized });
    if (normalized.ptr != combined_target.ptr) allocator.free(normalized);
    allocator.free(combined_target);

    return .{
        .url = full_url,
        .upstream_host = parseUpstreamHost(upstream_base_url) orelse "",
        .unix_socket_path = null,
    };
}

pub fn appendProxyQueryString(
    allocator: std.mem.Allocator,
    url: []const u8,
    query: ?[]const u8,
) !MaybeOwnedBytes {
    const value = query orelse return .{ .value = url };
    if (value.len == 0) return .{ .value = url };
    if (std.mem.findScalar(u8, url, '?') != null) {
        const owned = try std.fmt.allocPrint(allocator, "{s}&{s}", .{ url, value });
        return .{ .value = owned, .owned = owned };
    }
    const owned = try std.fmt.allocPrint(allocator, "{s}?{s}", .{ url, value });
    return .{ .value = owned, .owned = owned };
}

pub fn resolveRedirectTargetUrl(allocator: std.mem.Allocator, current_url: []const u8, location: []const u8) ![]u8 {
    if (isAbsoluteHttpUrl(location)) return allocator.dupe(u8, location);
    if (!std.mem.startsWith(u8, location, "/")) return error.HttpRedirectLocationInvalid;

    const current_uri = try std.Uri.parse(current_url);
    const scheme = current_uri.scheme;
    const host = (current_uri.host orelse return error.HttpRedirectLocationInvalid).raw;
    if (current_uri.port) |port| {
        return std.fmt.allocPrint(allocator, "{s}://{s}:{d}{s}", .{ scheme, host, port, location });
    }
    return std.fmt.allocPrint(allocator, "{s}://{s}{s}", .{ scheme, host, location });
}

pub fn unixSocketPathFromEndpoint(endpoint: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, endpoint, "unix://")) {
        const path = endpoint["unix://".len..];
        if (path.len == 0) return null;
        return path;
    }
    if (std.mem.startsWith(u8, endpoint, "unix:")) {
        const path = endpoint["unix:".len..];
        if (path.len == 0) return null;
        return path;
    }
    return null;
}

pub fn combineProxyTarget(allocator: std.mem.Allocator, target: []const u8, suffix_path: ?[]const u8) ![]u8 {
    if (suffix_path == null) return allocator.dupe(u8, target);

    const suffix = suffix_path.?;
    const left_trimmed = compat.trimRight(u8, target, "/");
    const right_trimmed = std.mem.trimStart(u8, suffix, "/");

    if (left_trimmed.len == 0) {
        return std.fmt.allocPrint(allocator, "/{s}", .{right_trimmed});
    }

    if (right_trimmed.len == 0) {
        return allocator.dupe(u8, left_trimmed);
    }

    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ left_trimmed, right_trimmed });
}

pub fn parseUpstreamHost(base_url: []const u8) ?[]const u8 {
    const scheme_end = std.mem.find(u8, base_url, "://") orelse return null;
    const authority_start = scheme_end + 3;
    if (authority_start >= base_url.len) return null;

    const path_start = std.mem.findScalarPos(u8, base_url, authority_start, '/') orelse base_url.len;
    if (path_start <= authority_start) return null;
    return base_url[authority_start..path_start];
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

pub fn mapProxyExecutionError(err: anyerror) ProxyExecMappedError {
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

pub fn buildApiErrorJson(allocator: std.mem.Allocator, code: []const u8, message: []const u8, request_id: ?[]const u8) ![]u8 {
    if (request_id) |rid| {
        return std.fmt.allocPrint(allocator, "{{\"code\":\"{s}\",\"message\":\"{s}\",\"request_id\":\"{s}\"}}", .{ code, message, rid });
    }
    return std.fmt.allocPrint(allocator, "{{\"code\":\"{s}\",\"message\":\"{s}\",\"request_id\":null}}", .{ code, message });
}

pub fn setRequestIdHeaders(response: *http.Response, request_id: []const u8) void {
    _ = response.setHeader(http.correlation.REQUEST_HEADER_NAME, request_id);
    _ = response.setHeader(http.correlation.HEADER_NAME, request_id);
}

pub fn writeRequestIdHeaders(writer: anytype, request_id: []const u8) !void {
    try writer.print("{s}: {s}\r\n", .{ http.correlation.REQUEST_HEADER_NAME, request_id });
    try writer.print("{s}: {s}\r\n", .{ http.correlation.HEADER_NAME, request_id });
}

pub fn appendRequestIdHeaders(headers: *std.array_list.Managed(std.http.Header), request_id: []const u8) !void {
    try headers.append(.{ .name = http.correlation.REQUEST_HEADER_NAME, .value = request_id });
    try headers.append(.{ .name = http.correlation.HEADER_NAME, .value = request_id });
}

pub fn sendApiError(allocator: std.mem.Allocator, writer: anytype, status: http.Status, code: []const u8, message: []const u8, request_id: ?[]const u8, keep_alive: bool, state: *GatewayState) !void {
    const payload = try buildApiErrorJson(allocator, code, message, request_id);
    defer allocator.free(payload);

    var response = http.Response.json(allocator, payload);
    defer response.deinit();
    _ = response.setStatus(status).setConnection(keep_alive);
    if (request_id) |rid| {
        setRequestIdHeaders(&response, rid);
    }
    applyResponseHeaders(state, &response);
    try response.write(writer);
    state.metricsRecord(@intFromEnum(status));
    state.metricsRecordErrorCode(code);
}
