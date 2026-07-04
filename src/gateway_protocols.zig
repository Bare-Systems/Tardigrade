const compat = @import("zig_compat.zig");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gs = @import("gateway_state.zig");
const GatewayState = gs.GatewayState;
const gp = @import("gateway_proxy.zig");
const sendApiError = gp.sendApiError;
const applyResponseHeaders = gp.applyResponseHeaders;

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

fn stripHostPort(raw_host: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw_host, " \t\r\n");
    if (trimmed.len == 0) return trimmed;
    if (trimmed[0] == '[') {
        const end = std.mem.findScalar(u8, trimmed, ']') orelse return trimmed;
        return trimmed[1..end];
    }
    const colon = std.mem.findScalarLast(u8, trimmed, ':') orelse return trimmed;
    const head = trimmed[0..colon];
    if (std.mem.findScalar(u8, head, ':') != null) return trimmed;
    return head;
}

fn hostPort(raw_host: []const u8) ?u16 {
    const trimmed = std.mem.trim(u8, raw_host, " \t\r\n");
    if (trimmed.len == 0) return null;
    if (trimmed[0] == '[') {
        const end = std.mem.findScalar(u8, trimmed, ']') orelse return null;
        if (end + 1 >= trimmed.len or trimmed[end + 1] != ':') return null;
        return std.fmt.parseInt(u16, trimmed[end + 2 ..], 10) catch null;
    }
    const colon = std.mem.findScalarLast(u8, trimmed, ':') orelse return null;
    const head = trimmed[0..colon];
    if (std.mem.findScalar(u8, head, ':') != null) return null;
    return std.fmt.parseInt(u16, trimmed[colon + 1 ..], 10) catch null;
}

pub fn handleFastcgiRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    upstream: []const u8,
    request: *const http.Request,
    client_ip: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
) !u16 {
    const endpoint = std.mem.trim(u8, upstream, " \t\r\n");
    if (endpoint.len == 0) {
        try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "FastCGI upstream not configured", correlation_id, keep_alive, state);
        return 501;
    }

    const configured_doc_root = std.mem.trim(u8, cfg.doc_root, " \t\r\n");
    const document_root = request.headers.get("x-fastcgi-document-root") orelse configured_doc_root;
    const path_info = request.headers.get("x-fastcgi-path-info") orelse request.uri.path;
    const fastcgi_index = if (cfg.fastcgi_index.len > 0) cfg.fastcgi_index else "index.php";
    const default_script_path = defaultFastcgiScriptPath(allocator, document_root, path_info, fastcgi_index) catch null;
    defer if (default_script_path) |path| allocator.free(path);
    const script_filename = request.headers.get("x-fastcgi-script-filename") orelse (default_script_path orelse "/index.php");
    const default_script_name = if (std.mem.endsWith(u8, path_info, "/"))
        std.fmt.allocPrint(allocator, "{s}{s}", .{ path_info, fastcgi_index }) catch null
    else
        null;
    defer if (default_script_name) |path| allocator.free(path);
    const script_name = request.headers.get("x-fastcgi-script-name") orelse (default_script_name orelse path_info);
    const host = request.headers.get("host") orelse "";
    const server_name = stripHostPort(host);

    var port_buf: [16]u8 = undefined;
    const server_port = if (hostPort(host)) |port|
        std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch "80"
    else if (cfg.listen_port > 0)
        std.fmt.bufPrint(&port_buf, "{d}", .{cfg.listen_port}) catch "80"
    else
        "80";

    var remote_port_buf: [8]u8 = undefined;
    const remote_port = request.headers.get("x-forwarded-port") orelse request.headers.get("x-real-port") orelse
        (std.fmt.bufPrint(&remote_port_buf, "{d}", .{0}) catch "0");

    var request_uri = std.array_list.Managed(u8).init(allocator);
    defer request_uri.deinit();
    try request_uri.appendSlice(request.uri.path);
    if (request.uri.query) |query| {
        try request_uri.append('?');
        try request_uri.appendSlice(query);
    }

    var extra_env = std.array_list.Managed(http.fastcgi.EnvPair).init(allocator);
    defer extra_env.deinit();
    for (cfg.fastcgi_params) |pair| {
        try extra_env.append(.{ .name = pair.name, .value = pair.value });
    }
    try extra_env.append(.{ .name = "TARDIGRADE_CORRELATION_ID", .value = correlation_id });

    var leased = state.acquireFastcgiStream(endpoint) catch |err| {
        state.logger.warn(correlation_id, "fastcgi connect failed for {s}: {}", .{ endpoint, err });
        try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "FastCGI request failed", correlation_id, keep_alive, state);
        return 502;
    };
    errdefer state.releaseFastcgiStream(endpoint, leased.conn, false);
    // Bound the exchange (#171): without SO timeouts a hung php-fpm pins this
    // worker indefinitely — the exchange had no deadline at all. A timed-out
    // read surfaces as an exchange error -> 502, and the connection is not
    // returned to the pool.
    if (cfg.upstream_timeout_ms > 0) {
        compat.setSocketTimeoutsMs(leased.conn.stream.handle, cfg.upstream_timeout_ms, cfg.upstream_timeout_ms);
    }

    var fcgi = http.fastcgi.exchange(allocator, &leased.conn.stream, .{
        .request_id = state.nextFastcgiRequestId(endpoint),
        .keep_conn = true,
        .method = request.method.toString(),
        .script_filename = script_filename,
        .request_uri = request_uri.items,
        .query_string = request.uri.query orelse "",
        .path_info = path_info,
        .script_name = script_name,
        .document_root = document_root,
        .content_type = request.contentType(),
        .remote_addr = client_ip,
        .remote_port = remote_port,
        .server_name = if (server_name.len > 0) server_name else "localhost",
        .server_port = server_port,
        .server_protocol = request.version.toString(),
        .request_scheme = if (cfg.tls_cert_path.len > 0 and cfg.tls_key_path.len > 0) "https" else "http",
        .https = cfg.tls_cert_path.len > 0 and cfg.tls_key_path.len > 0,
        .headers = &request.headers,
        .extra_env = extra_env.items,
    }, request.body orelse "") catch |err| {
        state.logger.warn(correlation_id, "fastcgi request failed for {s}: {}", .{ endpoint, err });
        state.releaseFastcgiStream(endpoint, leased.conn, false);
        try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "FastCGI request failed", correlation_id, keep_alive, state);
        return 502;
    };
    defer fcgi.deinit();

    if (fcgi.stderr.len > 0) {
        state.logger.warn(correlation_id, "fastcgi stderr from {s}: {s}", .{ endpoint, fcgi.stderr });
    }

    if (fcgi.protocol_status != http.fastcgi.request_complete or fcgi.app_status != 0) {
        state.logger.warn(correlation_id, "fastcgi end_request failure from {s}: app_status={d} protocol_status={d}", .{ endpoint, fcgi.app_status, fcgi.protocol_status });
        state.releaseFastcgiStream(endpoint, leased.conn, false);
        try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "FastCGI upstream failed", correlation_id, keep_alive, state);
        return 502;
    }

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response.setStatus(@enumFromInt(fcgi.status))
        .setBody(fcgi.body)
        .setContentType(fcgi.contentType())
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);

    for (fcgi.headers.iterator()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "status") or
            std.ascii.eqlIgnoreCase(header.name, "content-type") or
            std.ascii.eqlIgnoreCase(header.name, "content-length") or
            std.ascii.eqlIgnoreCase(header.name, "connection"))
        {
            continue;
        }
        _ = response.setHeader(header.name, header.value);
    }

    applyResponseHeaders(state, &response);
    try response.write(writer);
    state.metricsRecord(fcgi.status);
    state.releaseFastcgiStream(endpoint, leased.conn, true);
    return fcgi.status;
}

pub fn defaultFastcgiScriptPath(
    allocator: std.mem.Allocator,
    document_root: []const u8,
    path_info: []const u8,
    fastcgi_index: []const u8,
) ![]u8 {
    if (document_root.len == 0) {
        return allocator.dupe(u8, if (std.mem.endsWith(u8, path_info, "/")) fastcgi_index else path_info);
    }
    if (std.mem.endsWith(u8, path_info, "/")) {
        return std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ document_root, path_info, fastcgi_index });
    }
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ document_root, path_info });
}

pub fn handleScgiRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    upstream: []const u8,
    request: *const http.Request,
    client_ip: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
) !u16 {
    const endpoint = std.mem.trim(u8, upstream, " \t\r\n");
    if (endpoint.len == 0) {
        try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "SCGI upstream not configured", correlation_id, keep_alive, state);
        return 501;
    }

    const path_info = request.headers.get("x-scgi-path-info") orelse request.uri.path;
    const script_name = request.headers.get("x-scgi-script-name") orelse path_info;
    const document_root = request.headers.get("x-scgi-document-root") orelse "";
    const host = request.headers.get("host") orelse "";
    const server_name = stripHostPort(host);
    var port_buf: [16]u8 = undefined;
    const server_port = if (hostPort(host)) |port|
        std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch "80"
    else if (cfg.listen_port > 0)
        std.fmt.bufPrint(&port_buf, "{d}", .{cfg.listen_port}) catch "80"
    else
        "80";

    var remote_port_buf: [8]u8 = undefined;
    const remote_port = request.headers.get("x-forwarded-port") orelse request.headers.get("x-real-port") orelse
        (std.fmt.bufPrint(&remote_port_buf, "{d}", .{0}) catch "0");

    var request_uri = std.array_list.Managed(u8).init(allocator);
    defer request_uri.deinit();
    try request_uri.appendSlice(request.uri.path);
    if (request.uri.query) |query| {
        try request_uri.append('?');
        try request_uri.appendSlice(query);
    }

    var scgi = http.scgi.execute(allocator, endpoint, .{
        .method = request.method.toString(),
        .request_uri = request_uri.items,
        .query_string = request.uri.query orelse "",
        .path_info = path_info,
        .script_name = script_name,
        .document_root = document_root,
        .content_type = request.contentType(),
        .remote_addr = client_ip,
        .remote_port = remote_port,
        .server_name = if (server_name.len > 0) server_name else "localhost",
        .server_port = server_port,
        .server_protocol = request.version.toString(),
        .request_scheme = if (cfg.tls_cert_path.len > 0 and cfg.tls_key_path.len > 0) "https" else "http",
        .https = cfg.tls_cert_path.len > 0 and cfg.tls_key_path.len > 0,
        .headers = &request.headers,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_CORRELATION_ID", .value = correlation_id },
        },
    }, request.body orelse "", cfg.upstream_timeout_ms) catch |err| {
        state.logger.warn(correlation_id, "scgi request failed for {s}: {}", .{ endpoint, err });
        try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "SCGI request failed", correlation_id, keep_alive, state);
        return 502;
    };
    defer scgi.deinit();

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response.setStatus(@enumFromInt(scgi.status))
        .setBody(scgi.body)
        .setContentType(scgi.contentType())
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    for (scgi.headers.iterator()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "status") or
            std.ascii.eqlIgnoreCase(header.name, "content-type") or
            std.ascii.eqlIgnoreCase(header.name, "content-length") or
            std.ascii.eqlIgnoreCase(header.name, "connection"))
        {
            continue;
        }
        _ = response.setHeader(header.name, header.value);
    }
    applyResponseHeaders(state, &response);
    try response.write(writer);
    state.metricsRecord(scgi.status);
    return scgi.status;
}

pub fn handleUwsgiRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    upstream: []const u8,
    request: *const http.Request,
    client_ip: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
) !u16 {
    const endpoint = std.mem.trim(u8, upstream, " \t\r\n");
    if (endpoint.len == 0) {
        try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "uWSGI upstream not configured", correlation_id, keep_alive, state);
        return 501;
    }

    const path_info = request.headers.get("x-uwsgi-path-info") orelse request.uri.path;
    const script_name = request.headers.get("x-uwsgi-script-name") orelse path_info;
    const document_root = request.headers.get("x-uwsgi-document-root") orelse "";
    const host = request.headers.get("host") orelse "";
    const server_name = stripHostPort(host);
    var port_buf: [16]u8 = undefined;
    const server_port = if (hostPort(host)) |port|
        std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch "80"
    else if (cfg.listen_port > 0)
        std.fmt.bufPrint(&port_buf, "{d}", .{cfg.listen_port}) catch "80"
    else
        "80";

    var remote_port_buf: [8]u8 = undefined;
    const remote_port = request.headers.get("x-forwarded-port") orelse request.headers.get("x-real-port") orelse
        (std.fmt.bufPrint(&remote_port_buf, "{d}", .{0}) catch "0");

    var request_uri = std.array_list.Managed(u8).init(allocator);
    defer request_uri.deinit();
    try request_uri.appendSlice(request.uri.path);
    if (request.uri.query) |query| {
        try request_uri.append('?');
        try request_uri.appendSlice(query);
    }

    var uwsgi = http.uwsgi.execute(allocator, endpoint, .{
        .method = request.method.toString(),
        .request_uri = request_uri.items,
        .query_string = request.uri.query orelse "",
        .path_info = path_info,
        .script_name = script_name,
        .document_root = document_root,
        .content_type = request.contentType(),
        .remote_addr = client_ip,
        .remote_port = remote_port,
        .server_name = if (server_name.len > 0) server_name else "localhost",
        .server_port = server_port,
        .server_protocol = request.version.toString(),
        .request_scheme = if (cfg.tls_cert_path.len > 0 and cfg.tls_key_path.len > 0) "https" else "http",
        .https = cfg.tls_cert_path.len > 0 and cfg.tls_key_path.len > 0,
        .headers = &request.headers,
        .extra_env = &.{
            .{ .name = "TARDIGRADE_CORRELATION_ID", .value = correlation_id },
        },
    }, request.body orelse "", cfg.upstream_timeout_ms) catch |err| {
        state.logger.warn(correlation_id, "uwsgi request failed for {s}: {}", .{ endpoint, err });
        try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "uWSGI request failed", correlation_id, keep_alive, state);
        return 502;
    };
    defer uwsgi.deinit();

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response.setStatus(@enumFromInt(uwsgi.status))
        .setBody(uwsgi.body)
        .setContentType(uwsgi.contentType())
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    for (uwsgi.headers.iterator()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "status") or
            std.ascii.eqlIgnoreCase(header.name, "content-type") or
            std.ascii.eqlIgnoreCase(header.name, "content-length") or
            std.ascii.eqlIgnoreCase(header.name, "connection") or
            std.ascii.eqlIgnoreCase(header.name, "transfer-encoding"))
        {
            continue;
        }
        _ = response.setHeader(header.name, header.value);
    }
    applyResponseHeaders(state, &response);
    try response.write(writer);
    state.metricsRecord(uwsgi.status);
    return uwsgi.status;
}

pub fn proxyGrpcExecute(
    allocator: std.mem.Allocator,
    upstream_url: []const u8,
    body: []const u8,
    correlation_id: []const u8,
    state: *GatewayState,
) ![]u8 {
    const uri = try std.Uri.parse(upstream_url);
    var header_buf: [16 * 1024]u8 = undefined;
    var headers = [_]std.http.Header{
        .{ .name = http.correlation.REQUEST_HEADER_NAME, .value = correlation_id },
        .{ .name = http.correlation.HEADER_NAME, .value = correlation_id },
        .{ .name = "TE", .value = "trailers" },
    };
    var req = try state.upstream_client.request(.POST, uri, .{
        .extra_headers = headers[0..],
        .headers = .{ .content_type = .{ .override = "application/grpc" } },
        .keep_alive = true,
    });
    defer req.deinit();
    try req.sendBodyComplete(@constCast(body));
    var resp = try req.receiveHead(&header_buf);
    var resp_buf: [8192]u8 = undefined;
    return try resp.reader(&resp_buf).allocRemaining(allocator, .limited(4 * 1024 * 1024));
}

pub fn handleMailProxyRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    upstream: []const u8,
    body: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
) !void {
    const endpoint = std.mem.trim(u8, upstream, " \t\r\n");
    if (endpoint.len == 0) {
        try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "Upstream not configured", correlation_id, keep_alive, state);
        return;
    }
    const resp = executeRawProtocolRequest(allocator, endpoint, body) catch |err| {
        std.log.warn("mail/stream proxy failed: {}", .{err});
        try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "Upstream request failed", correlation_id, keep_alive, state);
        return;
    };
    defer allocator.free(resp);
    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response.setStatus(.ok)
        .setBody(resp)
        .setContentType("application/octet-stream")
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    applyResponseHeaders(state, &response);
    try response.write(writer);
    state.metricsRecord(200);
}

pub fn handleImapProxyRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    upstream: []const u8,
    body: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
) !void {
    const endpoint = std.mem.trim(u8, upstream, " \t\r\n");
    if (endpoint.len == 0) {
        try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "Upstream not configured", correlation_id, keep_alive, state);
        return;
    }
    const resp = blk: {
        const maybe_mail_endpoint = parseMailProxyEndpoint(endpoint) catch |err| {
            std.log.warn("imap proxy endpoint invalid: {}", .{err});
            try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "Upstream request failed", correlation_id, keep_alive, state);
            return;
        };
        if (maybe_mail_endpoint) |mail_endpoint| {
            break :blk executeImapProtocolRequest(allocator, mail_endpoint, body) catch |err| {
                std.log.warn("imap proxy failed: {}", .{err});
                try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "Upstream request failed", correlation_id, keep_alive, state);
                return;
            };
        }
        break :blk executeRawProtocolRequest(allocator, endpoint, body) catch |err| {
            std.log.warn("imap proxy failed: {}", .{err});
            try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "Upstream request failed", correlation_id, keep_alive, state);
            return;
        };
    };
    defer allocator.free(resp);
    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response.setStatus(.ok)
        .setBody(resp)
        .setContentType("application/octet-stream")
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    applyResponseHeaders(state, &response);
    try response.write(writer);
    state.metricsRecord(200);
}

const MailProxyTransport = enum {
    starttls,
    tls,
};

const MailProxyEndpoint = struct {
    transport: MailProxyTransport,
    host: []const u8,
    port: u16,
};

pub fn handleSmtpProxyRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    upstream: []const u8,
    body: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
    auth_identity: ?[]const u8,
) !void {
    const endpoint = std.mem.trim(u8, upstream, " \t\r\n");
    if (endpoint.len == 0) {
        try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "Upstream not configured", correlation_id, keep_alive, state);
        return;
    }
    const upstream_payload = try injectSmtpAuthIdentity(allocator, body, auth_identity);
    defer if (upstream_payload.ptr != body.ptr) allocator.free(upstream_payload);
    const resp = blk: {
        const maybe_mail_endpoint = parseMailProxyEndpoint(endpoint) catch |err| {
            std.log.warn("smtp proxy endpoint invalid: {}", .{err});
            try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "Upstream request failed", correlation_id, keep_alive, state);
            return;
        };
        if (maybe_mail_endpoint) |mail_endpoint| {
            break :blk executeSmtpProtocolRequest(allocator, mail_endpoint, upstream_payload) catch |err| {
                std.log.warn("smtp proxy failed: {}", .{err});
                try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "Upstream request failed", correlation_id, keep_alive, state);
                return;
            };
        }
        break :blk executeRawProtocolRequest(allocator, endpoint, upstream_payload) catch |err| {
            std.log.warn("smtp proxy failed: {}", .{err});
            try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "Upstream request failed", correlation_id, keep_alive, state);
            return;
        };
    };
    defer allocator.free(resp);
    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response.setStatus(.ok)
        .setBody(resp)
        .setContentType("application/octet-stream")
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    applyResponseHeaders(state, &response);
    try response.write(writer);
    state.metricsRecord(200);
}

fn injectSmtpAuthIdentity(
    allocator: std.mem.Allocator,
    payload: []const u8,
    auth_identity: ?[]const u8,
) ![]const u8 {
    const identity = auth_identity orelse return payload;
    if (identity.len == 0) return payload;

    const data_start = findSmtpDataStart(payload) orelse return payload;
    if (std.mem.findPos(u8, payload, data_start, "X-Tardigrade-Auth-Identity:")) |_| return payload;

    const header_line = try std.fmt.allocPrint(allocator, "X-Tardigrade-Auth-Identity: {s}\r\n", .{identity});
    defer allocator.free(header_line);

    if (std.mem.findPos(u8, payload, data_start, "\r\n\r\n")) |_| {
        return std.fmt.allocPrint(
            allocator,
            "{s}{s}{s}",
            .{ payload[0..data_start], header_line, payload[data_start..] },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "{s}{s}\r\n{s}",
        .{ payload[0..data_start], header_line, payload[data_start..] },
    );
}

fn findSmtpDataStart(payload: []const u8) ?usize {
    if (std.mem.startsWith(u8, payload, "DATA\r\n")) return "DATA\r\n".len;
    if (std.mem.find(u8, payload, "\r\nDATA\r\n")) |idx| return idx + "\r\nDATA\r\n".len;
    return null;
}

fn executeRawProtocolRequest(allocator: std.mem.Allocator, endpoint: []const u8, payload: []const u8) ![]u8 {
    const ep = try http.memcached.parseEndpoint(endpoint);
    const stream = try compat.tcpConnectToHost(allocator, ep.host, ep.port);
    defer stream.close();
    try setSocketTimeoutMs(stream.handle, 2_000, 2_000);
    try stream.writer().writeAll(payload);
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    var buf: [16 * 1024]u8 = undefined;
    const n = try stream.read(&buf);
    if (n > 0) try out.appendSlice(buf[0..n]);
    return out.toOwnedSlice();
}

fn parseMailProxyEndpoint(raw: []const u8) !?MailProxyEndpoint {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    var transport: MailProxyTransport = undefined;
    var endpoint = trimmed;
    if (std.mem.startsWith(u8, endpoint, "starttls://")) {
        transport = .starttls;
        endpoint = endpoint["starttls://".len..];
    } else if (std.mem.startsWith(u8, endpoint, "smtp+starttls://")) {
        transport = .starttls;
        endpoint = endpoint["smtp+starttls://".len..];
    } else if (std.mem.startsWith(u8, endpoint, "tls://")) {
        transport = .tls;
        endpoint = endpoint["tls://".len..];
    } else if (std.mem.startsWith(u8, endpoint, "smtps://")) {
        transport = .tls;
        endpoint = endpoint["smtps://".len..];
    } else {
        return null;
    }
    const parsed = http.memcached.parseEndpoint(endpoint) catch |err| switch (err) {
        error.InvalidEndpoint => return error.InvalidConfigEndpoint,
        else => return err,
    };
    if (parsed.host.len == 0 or parsed.port == 0) return error.InvalidConfigEndpoint;
    return .{
        .transport = transport,
        .host = parsed.host,
        .port = parsed.port,
    };
}

fn executeSmtpProtocolRequest(allocator: std.mem.Allocator, endpoint: MailProxyEndpoint, payload: []const u8) ![]u8 {
    const stream = try compat.tcpConnectToHost(allocator, endpoint.host, endpoint.port);
    defer stream.close();
    try setSocketTimeoutMs(stream.handle, 10_000, 10_000);
    return switch (endpoint.transport) {
        .tls => executeSmtpTlsRequest(allocator, stream, endpoint.host, payload),
        .starttls => executeSmtpStartTlsRequest(allocator, stream, endpoint.host, payload),
    };
}

fn executeImapProtocolRequest(allocator: std.mem.Allocator, endpoint: MailProxyEndpoint, payload: []const u8) ![]u8 {
    const stream = try compat.tcpConnectToHost(allocator, endpoint.host, endpoint.port);
    defer stream.close();
    try setSocketTimeoutMs(stream.handle, 10_000, 10_000);
    return switch (endpoint.transport) {
        .tls => executeImapTlsRequest(allocator, stream, endpoint.host, payload),
        .starttls => executeImapStartTlsRequest(allocator, stream, endpoint.host, payload),
    };
}

fn executeSmtpTlsRequest(
    allocator: std.mem.Allocator,
    stream: compat.NetStream,
    host: []const u8,
    payload: []const u8,
) ![]u8 {
    _ = host;
    var tls_client = try std.crypto.tls.Client.init(stream, .{
        .host = .no_verification,
        .ca = .no_verification,
    });
    tls_client.allow_truncation_attacks = true;
    try tls_client.writeAll(stream, payload);
    return readSmtpReplyTls(allocator, &tls_client, stream);
}

fn executeSmtpStartTlsRequest(
    allocator: std.mem.Allocator,
    stream: compat.NetStream,
    host: []const u8,
    payload: []const u8,
) ![]u8 {
    _ = host;
    const greeting = try readSmtpReplyPlain(allocator, stream);
    defer allocator.free(greeting);
    if (!smtpReplyContainsCode(greeting, "220")) return error.ProtocolError;

    try stream.writer().writeAll("EHLO tardigrade.local\r\n");
    const ehlo_reply = try readSmtpReplyPlain(allocator, stream);
    defer allocator.free(ehlo_reply);
    if (!smtpReplyAdvertisesStartTls(ehlo_reply)) return error.ProtocolError;

    try stream.writer().writeAll("STARTTLS\r\n");
    const starttls_reply = try readSmtpReplyPlain(allocator, stream);
    defer allocator.free(starttls_reply);
    if (!smtpReplyContainsCode(starttls_reply, "220")) return error.ProtocolError;

    var tls_client = try std.crypto.tls.Client.init(stream, .{
        .host = .no_verification,
        .ca = .no_verification,
    });
    tls_client.allow_truncation_attacks = true;

    try tls_client.writeAll(stream, "EHLO tardigrade.local\r\n");
    const post_tls_ehlo = try readSmtpReplyTls(allocator, &tls_client, stream);
    defer allocator.free(post_tls_ehlo);
    if (!smtpReplyContainsCode(post_tls_ehlo, "250")) return error.ProtocolError;

    try tls_client.writeAll(stream, payload);
    return readSmtpReplyTls(allocator, &tls_client, stream);
}

fn executeImapTlsRequest(
    allocator: std.mem.Allocator,
    stream: compat.NetStream,
    host: []const u8,
    payload: []const u8,
) ![]u8 {
    _ = host;
    var tls_client = try std.crypto.tls.Client.init(stream, .{
        .host = .no_verification,
        .ca = .no_verification,
    });
    tls_client.allow_truncation_attacks = true;

    const greeting = try readImapReplyTls(allocator, &tls_client, stream, null);
    defer allocator.free(greeting);
    if (!imapReplyContainsOk(greeting)) return error.ProtocolError;

    try tls_client.writeAll(stream, payload);
    return readImapReplyTls(allocator, &tls_client, stream, imapPayloadTag(payload));
}

fn executeImapStartTlsRequest(
    allocator: std.mem.Allocator,
    stream: compat.NetStream,
    host: []const u8,
    payload: []const u8,
) ![]u8 {
    _ = host;
    const greeting = try readImapReplyPlain(allocator, stream, null);
    defer allocator.free(greeting);
    if (!imapReplyContainsOk(greeting)) return error.ProtocolError;

    try stream.writer().writeAll("a001 STARTTLS\r\n");
    const starttls_reply = try readImapReplyPlain(allocator, stream, "a001");
    defer allocator.free(starttls_reply);
    if (!imapTaggedReplyContainsOk(starttls_reply, "a001")) return error.ProtocolError;

    var tls_client = try std.crypto.tls.Client.init(stream, .{
        .host = .no_verification,
        .ca = .no_verification,
    });
    tls_client.allow_truncation_attacks = true;

    try tls_client.writeAll(stream, payload);
    return readImapReplyTls(allocator, &tls_client, stream, imapPayloadTag(payload));
}

fn readSmtpReplyPlain(allocator: std.mem.Allocator, stream: compat.NetStream) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    var buf: [2048]u8 = undefined;
    while (true) {
        const n = try stream.read(&buf);
        if (n == 0) break;
        try out.appendSlice(buf[0..n]);
        if (smtpReplyComplete(out.items)) break;
    }
    if (out.items.len == 0) return error.EndOfStream;
    return out.toOwnedSlice();
}

fn readSmtpReplyTls(allocator: std.mem.Allocator, tls_client: *std.crypto.tls.Client, stream: compat.NetStream) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    var buf: [2048]u8 = undefined;
    while (true) {
        const n = try tls_client.read(stream, &buf);
        if (n == 0) break;
        try out.appendSlice(buf[0..n]);
        if (smtpReplyComplete(out.items)) break;
    }
    if (out.items.len == 0) return error.EndOfStream;
    return out.toOwnedSlice();
}

fn readImapReplyPlain(allocator: std.mem.Allocator, stream: compat.NetStream, tag: ?[]const u8) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    var buf: [2048]u8 = undefined;
    while (true) {
        const n = try stream.read(&buf);
        if (n == 0) break;
        try out.appendSlice(buf[0..n]);
        if (imapReplyComplete(out.items, tag)) break;
    }
    if (out.items.len == 0) return error.EndOfStream;
    return out.toOwnedSlice();
}

fn readImapReplyTls(
    allocator: std.mem.Allocator,
    tls_client: *std.crypto.tls.Client,
    stream: compat.NetStream,
    tag: ?[]const u8,
) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    var buf: [2048]u8 = undefined;
    while (true) {
        const n = try tls_client.read(stream, &buf);
        if (n == 0) break;
        try out.appendSlice(buf[0..n]);
        if (imapReplyComplete(out.items, tag)) break;
    }
    if (out.items.len == 0) return error.EndOfStream;
    return out.toOwnedSlice();
}

fn imapPayloadTag(payload: []const u8) ?[]const u8 {
    const line_end = std.mem.find(u8, payload, "\r\n") orelse payload.len;
    const first_line = payload[0..line_end];
    var toks = std.mem.tokenizeAny(u8, first_line, " \t");
    return toks.next();
}

fn imapReplyComplete(reply: []const u8, tag: ?[]const u8) bool {
    if (!std.mem.endsWith(u8, reply, "\r\n")) return false;
    if (tag) |t| {
        var it = std.mem.splitSequence(u8, reply, "\r\n");
        while (it.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, t) and line.len > t.len and line[t.len] == ' ') return true;
        }
        return false;
    }
    return true;
}

fn imapReplyContainsOk(reply: []const u8) bool {
    return std.mem.find(u8, reply, " OK") != null or std.mem.startsWith(u8, std.mem.trim(u8, reply, " \t\r\n"), "* OK");
}

fn imapTaggedReplyContainsOk(reply: []const u8, tag: []const u8) bool {
    var it = std.mem.splitSequence(u8, reply, "\r\n");
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, tag) and line.len > tag.len and line[tag.len] == ' ') {
            return std.mem.find(u8, line, " OK") != null;
        }
    }
    return false;
}

fn smtpReplyComplete(reply: []const u8) bool {
    var idx: usize = 0;
    var multiline_code: ?[]const u8 = null;
    var saw_terminal = false;
    while (idx < reply.len) {
        const line_end = std.mem.findPos(u8, reply, idx, "\r\n") orelse return false;
        const line = reply[idx..line_end];
        if (line.len >= 4 and std.ascii.isDigit(line[0]) and std.ascii.isDigit(line[1]) and std.ascii.isDigit(line[2])) {
            if (line[3] == '-') {
                multiline_code = line[0..3];
            } else if (line[3] == ' ') {
                if (multiline_code) |code| {
                    if (std.mem.eql(u8, code, line[0..3])) {
                        saw_terminal = true;
                        multiline_code = null;
                    }
                } else {
                    saw_terminal = true;
                }
            }
        }
        idx = line_end + 2;
    }
    return saw_terminal and idx == reply.len;
}

fn smtpReplyContainsCode(reply: []const u8, code: []const u8) bool {
    var it = std.mem.splitSequence(u8, reply, "\r\n");
    while (it.next()) |line| {
        if (line.len >= 3 and std.mem.eql(u8, line[0..3], code)) return true;
    }
    return false;
}

fn smtpReplyAdvertisesStartTls(reply: []const u8) bool {
    var it = std.mem.splitSequence(u8, reply, "\r\n");
    while (it.next()) |line| {
        if (line.len < 4 or !std.mem.eql(u8, line[0..3], "250")) continue;
        const feature = std.mem.trim(u8, line[4..], " \t\r\n");
        if (std.ascii.eqlIgnoreCase(feature, "STARTTLS")) return true;
    }
    return false;
}

fn executeUdpDatagramRequest(allocator: std.mem.Allocator, endpoint: []const u8, payload: []const u8) ![]u8 {
    const ep = try http.memcached.parseEndpoint(endpoint);
    const address = try std.Io.net.IpAddress.resolve(compat.io(), ep.host, ep.port);
    var sin: std.c.sockaddr.in = undefined;
    const sock_family: c_uint = switch (address) {
        .ip4 => |ip4| blk: {
            sin = .{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, ip4.port),
                .addr = std.mem.readInt(u32, &ip4.bytes, .big),
                .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
            };
            break :blk std.posix.AF.INET;
        },
        .ip6 => return error.Ipv6NotSupportedForUdp,
    };
    const sock = std.c.socket(sock_family, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    if (sock < 0) return error.SocketFailed;
    defer _ = std.c.close(sock);
    const sent = std.c.sendto(sock, payload.ptr, payload.len, 0, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in));
    if (sent < 0) return error.SendFailed;
    var buf: [16 * 1024]u8 = undefined;
    const n = std.c.recv(sock, &buf, buf.len, 0);
    if (n < 0) return error.RecvFailed;
    return allocator.dupe(u8, buf[0..@intCast(n)]);
}

const MemcachedPayload = struct {
    op: []u8,
    key: []u8,
    value: ?[]u8 = null,
    ttl: u32 = 60,
};

fn parseMemcachedPayload(allocator: std.mem.Allocator, body: []const u8) !MemcachedPayload {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    const op_val = obj.get("op") orelse return error.InvalidPayload;
    const key_val = obj.get("key") orelse return error.InvalidPayload;
    if (op_val != .string or key_val != .string) return error.InvalidPayload;
    const val = if (obj.get("value")) |v| blk: {
        if (v != .string) break :blk null;
        break :blk try allocator.dupe(u8, v.string);
    } else null;
    const ttl = if (obj.get("ttl")) |t|
        if (t == .integer and t.integer >= 0) @as(u32, @intCast(t.integer)) else 60
    else
        60;
    return .{
        .op = try allocator.dupe(u8, op_val.string),
        .key = try allocator.dupe(u8, key_val.string),
        .value = val,
        .ttl = ttl,
    };
}
