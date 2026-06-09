//! Route dispatch, middleware, operational handlers, HTTP/3 request handling,
//! mirror/subrequest glue, and access logging for the edge gateway. Connection
//! setup remains in edge_gateway; endpoint behavior lives here.

const compat = @import("zig_compat.zig");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const ga = @import("gateway_auth.zig");
const gcp = @import("gateway_control_plane_proxy.zig");
const gp = @import("gateway_proxy.zig");
const gpr = @import("gateway_protocols.zig");
const gproxy_runtime = @import("gateway_proxy_runtime.zig");
const gs = @import("gateway_state.zig");
const gstatic = @import("gateway_static_runtime.zig");

const JSON_CONTENT_TYPE = "application/json";
const GatewayState = gs.GatewayState;
const ReloadableConfigStore = gs.ReloadableConfigStore;
const MAX_REQUEST_SIZE = gs.MAX_REQUEST_SIZE;
const authorizeRequest = ga.authorizeRequest;
const authorizeViaSubrequest = ga.authorizeViaSubrequest;
const hostMatchesPatterns = ga.hostMatchesPatterns;
const resolveRequestConfig = ga.resolveRequestConfig;
const isGeoBlocked = ga.isGeoBlocked;
const executeBoundedControlPlaneJsonProxy = gcp.executeBoundedControlPlaneJsonProxy;
const applyResponseHeaders = gp.applyResponseHeaders;
const appendProxyQueryString = gp.appendProxyQueryString;
const buildApiErrorJson = gp.buildApiErrorJson;
const resolveProxyTarget = gp.resolveProxyTarget;
const sendApiError = gp.sendApiError;
const setRequestIdHeaders = gp.setRequestIdHeaders;
const writeRequestIdHeaders = gp.writeRequestIdHeaders;
const writeSecurityHeaders = gp.writeSecurityHeaders;
const handleFastcgiRoute = gpr.handleFastcgiRoute;
const executeBufferedDataPlaneProxyRequest = gproxy_runtime.executeBufferedDataPlaneProxyRequest;
const handleLocationProxyPass = gproxy_runtime.handleLocationProxyPass;
const proxySuffixPathForLocation = gproxy_runtime.proxySuffixPathForLocation;
const handleStaticLocation = gstatic.handleStaticLocation;
const maybeResolveStaticErrorPage = gstatic.maybeResolveStaticErrorPage;
const serveTryFilesFallback = gstatic.serveTryFilesFallback;

pub fn routeRequest(
    conn: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *http.Request,
    correlation_id: []const u8,
    keep_alive: *bool,
    client_ip: []const u8,
    streaming_request_body: ?gproxy_runtime.StreamingRequestBody,
) !u16 {
    const writer = conn.writer();
    if (try handleTranscriptRoute(allocator, writer, state, request, correlation_id, keep_alive.*)) |status| {
        state.metricsRecord(status);
        return status;
    }

    if (std.mem.eql(u8, request.uri.path, "/tardigrade/reload/status")) {
        const status = try handleReloadStatusRoute(allocator, writer, state, correlation_id, keep_alive.*);
        state.metricsRecord(status);
        return status;
    }

    if (cfg.metrics_path.len > 0 and std.mem.eql(u8, request.uri.path, cfg.metrics_path)) {
        const status = try handleMetricsRoute(allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive.*);
        state.metricsRecord(status);
        return status;
    }

    if (http.location_router.matchLocation(request.uri.path, cfg.location_blocks)) |matched| {
        if (matched.block.auth == .required and !ctx.authenticated and ctx.identity == null) {
            var auth_res = try authorizeRequest(allocator, cfg, &request.headers);
            defer auth_res.deinit(allocator);
            if (auth_res.ok) {
                if (auth_res.identity) |identity| {
                    ctx.setAuthContext(identity, auth_res.user_id, auth_res.device_id, auth_res.scopes);
                    auth_res.identity = null;
                    auth_res.user_id = null;
                    auth_res.device_id = null;
                    auth_res.scopes = null;
                }
            } else if (http.session.fromHeaders(&request.headers)) |session_token| {
                if (state.validateSessionIdentity(allocator, session_token)) |identity| {
                    ctx.setIdentity(identity);
                } else {
                    try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive.*, state);
                    state.metricsRecord(401);
                    state.metricsRecordErrorCode("unauthorized");
                    return 401;
                }
            } else if (cfg.auth_request_url.len > 0 and authorizeViaSubrequest(allocator, cfg, request, correlation_id, client_ip)) {
                ctx.authenticated = true;
            } else {
                const auth_status: http.Status = if (auth_res.failure_reason == .invalid) .forbidden else .unauthorized;
                const auth_code = if (auth_res.failure_reason == .invalid) "forbidden" else "unauthorized";
                const auth_message = if (auth_res.failure_reason == .invalid) "Forbidden" else "Unauthorized";
                const auth_status_code: u16 = @intFromEnum(auth_status);
                try sendApiError(allocator, writer, auth_status, auth_code, auth_message, correlation_id, keep_alive.*, state);
                state.metricsRecord(auth_status_code);
                state.metricsRecordErrorCode(auth_code);
                return auth_status_code;
            }
        }
        switch (matched.block.action) {
            .proxy_pass => |target| {
                return try handleLocationProxyPass(
                    allocator,
                    conn,
                    writer,
                    cfg,
                    state,
                    ctx,
                    request,
                    target,
                    proxySuffixPathForLocation(request.uri.path, matched, cfg.location_blocks),
                    correlation_id,
                    keep_alive.*,
                    client_ip,
                    ctx.identity,
                    ctx.user_id,
                    ctx.device_id,
                    ctx.scopes,
                    request.headers.get("host"),
                    matched.block.pattern,
                    streaming_request_body,
                );
            },
            .fastcgi_pass => |upstream| {
                return try handleFastcgiRoute(allocator, writer, cfg, upstream, request, client_ip, correlation_id, keep_alive.*, state);
            },
            .return_response => |ret| {
                // Static-return directives (non-redirect) only make semantic sense
                // for GET and HEAD.  Accepting DELETE, PUT, or PATCH on a route like
                // `return 200 ok` would silently succeed and mislead the client into
                // believing a destructive operation completed (ASVS-14.5.1).
                // Redirect responses (3xx) are method-agnostic and pass through.
                const is_redirect = ret.status >= 300 and ret.status < 400;
                if (!is_redirect and !(request.method == .GET or request.method == .HEAD)) {
                    try sendApiError(allocator, writer, .method_not_allowed, "invalid_request", "Method Not Allowed", correlation_id, keep_alive.*, state);
                    state.metricsRecord(405);
                    return 405;
                }
                if (is_redirect and ret.body.len > 0) {
                    var response = http.Response.redirect(allocator, ret.body, @enumFromInt(ret.status));
                    defer response.deinit();
                    _ = response.setConnection(keep_alive.*);
                    setRequestIdHeaders(&response, correlation_id);
                    ctx.response_bytes = 0;
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                } else {
                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response.setStatus(@enumFromInt(ret.status))
                        .setBody(ret.body)
                        .setContentType("text/plain; charset=utf-8")
                        .setConnection(keep_alive.*);
                    setRequestIdHeaders(&response, correlation_id);
                    ctx.response_bytes = ret.body.len;
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                }
                state.metricsRecord(ret.status);
                return ret.status;
            },
            .rewrite => |rw| {
                request.uri.path = rw.replacement;
            },
            .static_root => |root_cfg| {
                if (try handleStaticLocation(allocator, conn, request, matched, root_cfg, correlation_id, keep_alive.*, state)) |status| return status;
            },
        }
    }

    if (serveTryFilesFallback(allocator, conn, cfg, request, correlation_id, keep_alive.*, state)) |status| {
        state.metricsRecord(status);
        return status;
    } else |_| {}

    try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive.*, state);
    state.metricsRecord(404);
    return 404;
}

pub fn primeRequestAuthContext(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    headers: *const http.Headers,
) !void {
    if (ctx.authenticated or ctx.identity != null) return;

    var auth_res = try authorizeRequest(allocator, cfg, headers);
    defer auth_res.deinit(allocator);
    if (auth_res.ok) {
        if (auth_res.identity) |identity| {
            ctx.setAuthContext(identity, auth_res.user_id, auth_res.device_id, auth_res.scopes);
            auth_res.identity = null;
            auth_res.user_id = null;
            auth_res.device_id = null;
            auth_res.scopes = null;
        } else {
            ctx.authenticated = true;
        }
        return;
    }

    if (http.session.fromHeaders(headers)) |session_token| {
        if (state.validateSessionIdentity(allocator, session_token)) |identity| {
            ctx.setIdentity(identity);
        }
    }
}

fn handleTranscriptRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *GatewayState,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
) !?u16 {
    const transcript_path = normalizeTranscriptRoutePath(request.uri.path) orelse return null;

    if (!(request.method == .GET or request.method == .HEAD)) {
        try sendApiError(allocator, writer, .method_not_allowed, "invalid_request", "Method Not Allowed", correlation_id, keep_alive, state);
        return 405;
    }

    if (state.transcript_store_path.len == 0) {
        try sendApiError(allocator, writer, .not_found, "invalid_request", "Transcript store not configured", correlation_id, keep_alive, state);
        return 404;
    }

    if (std.mem.eql(u8, transcript_path, "/transcripts")) {
        const limit = parseTranscriptLimit(request.uri.query);
        const transcripts = try http.transcript_store.listRecent(allocator, state.transcript_store_path, limit);
        defer {
            for (transcripts) |*summary| summary.deinit(allocator);
            allocator.free(transcripts);
        }
        const payload = try jsonifyTranscriptSummaries(allocator, transcripts);
        defer allocator.free(payload);
        try writeJsonPayload(writer, allocator, payload, correlation_id, keep_alive, state, request.method == .HEAD);
        return 200;
    }

    if (std.mem.startsWith(u8, transcript_path, "/transcripts/")) {
        const id_raw = std.mem.trim(u8, transcript_path["/transcripts/".len..], " \t\r\n");
        const id = std.fmt.parseInt(usize, id_raw, 10) catch {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Invalid transcript id", correlation_id, keep_alive, state);
            return 400;
        };
        var entry = (try http.transcript_store.getById(allocator, state.transcript_store_path, id)) orelse {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Transcript not found", correlation_id, keep_alive, state);
            return 404;
        };
        defer entry.deinit(allocator);
        const payload = try jsonifyTranscriptEntry(allocator, &entry);
        defer allocator.free(payload);
        try writeJsonPayload(writer, allocator, payload, correlation_id, keep_alive, state, request.method == .HEAD);
        return 200;
    }

    return null;
}

fn handleReloadStatusRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *GatewayState,
    correlation_id: []const u8,
    keep_alive: bool,
) !u16 {
    state.reload_mutex.lock();
    const ok = state.last_reload_ok;
    const at_ms = state.last_reload_at_ms;
    const err_slice = state.last_reload_error[0..state.last_reload_error_len];
    state.reload_mutex.unlock();

    const payload = if (at_ms == 0)
        try std.fmt.allocPrint(allocator, "{{\"ok\":null,\"at_ms\":null,\"error\":null}}", .{})
    else if (ok)
        try std.fmt.allocPrint(allocator, "{{\"ok\":true,\"at_ms\":{d},\"error\":null}}", .{at_ms})
    else
        try std.fmt.allocPrint(allocator, "{{\"ok\":false,\"at_ms\":{d},\"error\":\"{s}\"}}", .{ at_ms, err_slice });
    defer allocator.free(payload);

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response
        .setStatus(.ok)
        .setBody(payload)
        .setContentType("application/json")
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    applyResponseHeaders(state, &response);
    try response.write(writer);
    return 200;
}

fn handleMetricsRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
) !u16 {
    if (!(request.method == .GET or request.method == .HEAD)) {
        try sendApiError(allocator, writer, .method_not_allowed, "invalid_request", "Method Not Allowed", correlation_id, keep_alive, state);
        return 405;
    }

    if (cfg.metrics_require_auth and !ctx.authenticated and ctx.identity == null) {
        try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
        state.metricsRecordErrorCode("unauthorized");
        return 401;
    }

    const payload = try state.metricsToPrometheus(allocator);
    defer allocator.free(payload);

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response
        .setStatus(.ok)
        .setBody(if (request.method == .HEAD) "" else payload)
        .setContentType("text/plain; version=0.0.4; charset=utf-8")
        .setConnection(keep_alive);
    setRequestIdHeaders(&response, correlation_id);
    if (request.method == .HEAD) {
        _ = response.setContentLength(payload.len);
        ctx.response_bytes = 0;
        applyResponseHeaders(state, &response);
        try response.writeHead(writer);
    } else {
        ctx.response_bytes = payload.len;
        applyResponseHeaders(state, &response);
        try response.write(writer);
    }
    return 200;
}

fn normalizeTranscriptRoutePath(path: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, path, "/transcripts") or std.mem.startsWith(u8, path, "/transcripts/")) return path;
    if (std.mem.eql(u8, path, "/bearclaw/transcripts")) return "/transcripts";
    if (std.mem.startsWith(u8, path, "/bearclaw/transcripts/")) return path["/bearclaw".len..];
    return null;
}

fn parseTranscriptLimit(query: ?[]const u8) usize {
    const raw = parseQueryParam(query, "limit") orelse return 50;
    const parsed = std.fmt.parseInt(usize, raw, 10) catch return 50;
    return std.math.clamp(parsed, 1, 200);
}

fn jsonifyTranscriptSummaries(allocator: std.mem.Allocator, transcripts: []const http.transcript_store.Summary) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{ .transcripts = transcripts }, .{});
}

fn jsonifyTranscriptEntry(allocator: std.mem.Allocator, transcript: *const http.transcript_store.StoredEntry) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{ .transcript = transcript }, .{});
}

fn writeJsonPayload(
    writer: anytype,
    allocator: std.mem.Allocator,
    payload: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
    head_only: bool,
) !void {
    var response = http.Response.json(allocator, if (head_only) "" else payload);
    defer response.deinit();
    _ = response
        .setStatus(.ok)
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    applyResponseHeaders(state, &response);
    if (head_only) {
        try response.writeHead(writer);
    } else {
        try response.write(writer);
    }
}

fn rateLimitDescriptor(identity: ?[]const u8, client_ip: []const u8, buf: *[192]u8) []const u8 {
    if (identity) |id| {
        return std.fmt.bufPrint(buf, "identity:{s}", .{id}) catch blk: {
            const hash = std.hash.Wyhash.hash(0, id);
            break :blk std.fmt.bufPrint(buf, "identity-hash:{x}", .{hash}) catch "identity-hash";
        };
    }
    return std.fmt.bufPrint(buf, "ip:{s}", .{client_ip}) catch blk: {
        const hash = std.hash.Wyhash.hash(0, client_ip);
        break :blk std.fmt.bufPrint(buf, "ip-hash:{x}", .{hash}) catch "ip-hash";
    };
}

pub fn runMiddlewarePipeline(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
) !bool {
    const client_ip = ctx.client_ip;

    if (cfg.geo_blocked_countries.len > 0) {
        const country = request.headers.get(cfg.geo_country_header);
        if (isGeoBlocked(cfg.geo_blocked_countries, country)) {
            try sendApiError(allocator, writer, .forbidden, "forbidden", "Geo access denied", correlation_id, keep_alive, state);
            logAccess(state, ctx, request.method.toString(), request.uri.path, 403, request.headers.get("user-agent") orelse "");
            return true;
        }
    }

    const limits = cfg.request_limits;
    const uri_check = http.request_limits.validateUriLength(request.uri.path.len, limits);
    if (uri_check != .ok) {
        var msg_buf: [256]u8 = undefined;
        const msg = http.request_limits.rejectionMessage(uri_check, &msg_buf);
        try sendApiError(allocator, writer, .uri_too_long, "invalid_request", msg, correlation_id, keep_alive, state);
        state.logger.warn(correlation_id, "URI too long: {d} bytes", .{request.uri.path.len});
        logAccess(state, ctx, request.method.toString(), request.uri.path, 414, request.headers.get("user-agent") orelse "");
        return true;
    }
    const header_count_check = http.request_limits.validateHeaderCount(request.headers.count(), limits);
    if (header_count_check != .ok) {
        var msg_buf: [256]u8 = undefined;
        const msg = http.request_limits.rejectionMessage(header_count_check, &msg_buf);
        try sendApiError(allocator, writer, .request_header_fields_too_large, "invalid_request", msg, correlation_id, keep_alive, state);
        state.logger.warn(correlation_id, "Too many headers: {d}", .{request.headers.count()});
        logAccess(state, ctx, request.method.toString(), request.uri.path, 431, request.headers.get("user-agent") orelse "");
        return true;
    }
    for (request.headers.iterator()) |h| {
        const header_len = h.name.len + h.value.len + 2; // "name: value"
        const header_size_check = http.request_limits.validateHeaderSize(header_len, limits);
        if (header_size_check != .ok) {
            var msg_buf: [256]u8 = undefined;
            const msg = http.request_limits.rejectionMessage(header_size_check, &msg_buf);
            try sendApiError(allocator, writer, .request_header_fields_too_large, "invalid_request", msg, correlation_id, keep_alive, state);
            state.logger.warn(correlation_id, "Header too large: {d} bytes", .{header_len});
            logAccess(state, ctx, request.method.toString(), request.uri.path, 431, request.headers.get("user-agent") orelse "");
            return true;
        }
    }
    {
        var headers_total: usize = 0;
        for (request.headers.iterator()) |h| headers_total += h.name.len + h.value.len + 4; // ": \r\n"
        const total_check = http.request_limits.validateHeadersTotalSize(headers_total, limits);
        if (total_check != .ok) {
            var msg_buf: [256]u8 = undefined;
            const msg = http.request_limits.rejectionMessage(total_check, &msg_buf);
            try sendApiError(allocator, writer, .request_header_fields_too_large, "invalid_request", msg, correlation_id, keep_alive, state);
            state.logger.warn(correlation_id, "Headers total too large: {d} bytes", .{headers_total});
            logAccess(state, ctx, request.method.toString(), request.uri.path, 431, request.headers.get("user-agent") orelse "");
            return true;
        }
    }
    if (request.body) |body| {
        const body_check = http.request_limits.validateBodySize(body.len, limits);
        if (body_check != .ok) {
            try sendApiError(allocator, writer, .payload_too_large, "invalid_request", "Request body too large", correlation_id, keep_alive, state);
            state.logger.warn(correlation_id, "Body too large: {d} bytes", .{body.len});
            logAccess(state, ctx, request.method.toString(), request.uri.path, 413, request.headers.get("user-agent") orelse "");
            return true;
        }
    }

    if (state.access_control) |*acl| {
        if (acl.check(client_ip) == .denied) {
            try sendApiError(allocator, writer, .forbidden, "forbidden", "Access denied", correlation_id, keep_alive, state);
            logAccess(state, ctx, request.method.toString(), request.uri.path, 403, request.headers.get("user-agent") orelse "");
            return true;
        }
    }

    var rate_limit_buf: [192]u8 = undefined;
    const limit_key = rateLimitDescriptor(ctx.identity, client_ip, &rate_limit_buf);
    if (!state.rateLimitAllow(limit_key)) {
        const payload = try buildApiErrorJson(allocator, "rate_limited", "Rate limit exceeded", correlation_id);
        defer allocator.free(payload);
        var response = http.Response.json(allocator, payload);
        defer response.deinit();
        _ = response
            .setStatus(.too_many_requests)
            .setConnection(keep_alive)
            .setHeader("Retry-After", "1")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(429);
        state.metricsRecordErrorCode("rate_limited");
        logAccess(state, ctx, request.method.toString(), request.uri.path, 429, request.headers.get("user-agent") orelse "");
        return true;
    }

    return false;
}

fn streamSseTopic(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    topic: []const u8,
    last_event_id_start: u64,
    correlation_id: []const u8,
) !void {
    try writer.writeAll("HTTP/1.1 200 OK\r\n");
    try writer.print("Server: {s}\r\n", .{http.SERVER_NAME});
    try writer.writeAll("Connection: close\r\n");
    try writer.writeAll("Cache-Control: no-cache\r\n");
    try writer.writeAll("Content-Type: text/event-stream\r\n");
    try writer.writeAll("X-Accel-Buffering: no\r\n");
    try writeRequestIdHeaders(writer, correlation_id);
    try writeSecurityHeaders(writer, &state.security_headers);
    for (state.add_headers) |pair| {
        try writer.print("{s}: {s}\r\n", .{ pair.name, pair.value });
    }
    try writer.writeAll("\r\n");

    var last_event_id = last_event_id_start;
    var last_send_ms = http.event_loop.monotonicMs();
    var last_comment_ms = last_send_ms;
    const poll_ms = @max(cfg.sse_poll_interval_ms, 10);

    while (!http.shutdown.isShutdownRequested()) {
        if (cfg.sse_max_backlog > 0 and last_event_id > 0) {
            if (state.event_hub.oldestId(topic)) |oldest| {
                if (last_event_id + cfg.sse_max_backlog < oldest) {
                    try writeSseEvent(writer, oldest, "backlog_exceeded");
                    return;
                }
            }
        }

        const events = try state.event_hub.snapshotSince(allocator, topic, last_event_id);
        defer http.event_hub.deinitSnapshot(allocator, events);

        if (events.len > 0) {
            for (events) |event| {
                try writeSseEvent(writer, event.id, event.payload);
                last_event_id = event.id;
            }
            last_send_ms = http.event_loop.monotonicMs();
        } else {
            const now_ms = http.event_loop.monotonicMs();
            if (now_ms - last_comment_ms >= 15_000) {
                try writer.writeAll(": keepalive\n\n");
                last_comment_ms = now_ms;
            }
            if (cfg.sse_idle_timeout_ms > 0 and now_ms - last_send_ms >= cfg.sse_idle_timeout_ms) return;
        }

        std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(@as(i64, @intCast(poll_ms))), .awake) catch {}; // interrupt wakes are fine; SSE poll loop continues
    }
}

fn writeSseEvent(writer: anytype, id: u64, payload: []const u8) !void {
    try writer.print("id: {d}\n", .{id});
    var line_it = std.mem.splitScalar(u8, payload, '\n');
    while (line_it.next()) |line| {
        try writer.print("data: {s}\n", .{line});
    }
    try writer.writeAll("\n");
}

pub fn parseQueryParam(query: ?[]const u8, key: []const u8) ?[]const u8 {
    const raw = query orelse return null;
    var it = std.mem.splitScalar(u8, raw, '&');
    while (it.next()) |part| {
        const eq = std.mem.findScalar(u8, part, '=') orelse continue;
        const name = std.mem.trim(u8, part[0..eq], " \t\r\n");
        if (!std.mem.eql(u8, name, key)) continue;
        return std.mem.trim(u8, part[eq + 1 ..], " \t\r\n");
    }
    return null;
}

fn generateCommandId(allocator: std.mem.Allocator) ![]const u8 {
    var rnd: [16]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    return std.fmt.allocPrint(allocator, "cmd-{d}-{f}", .{
        compat.milliTimestamp(),
        compat.fmtSliceHexLower(&rnd),
    });
}

const AsyncCommandJob = struct {
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    command_id: []u8,
    command_name: []u8,
    upstream_path: []u8,
    envelope: []u8,
    correlation_id: []u8,
    client_ip: []u8,
    identity: ?[]u8,
    incoming_host: ?[]u8,
    incoming_x_forwarded_for: ?[]u8,
    api_version: ?u32,
};

fn spawnAsyncCommandExecution(
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    command_id: []const u8,
    command_name: []const u8,
    upstream_path: []const u8,
    envelope: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    identity: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
) void {
    const job = createAsyncCommandJob(
        state.allocator,
        cfg,
        state,
        command_id,
        command_name,
        upstream_path,
        envelope,
        correlation_id,
        client_ip,
        identity,
        api_version,
        incoming_host,
        incoming_x_forwarded_for,
    ) catch return;
    const t = std.Thread.spawn(.{}, runAsyncCommandJob, .{job}) catch {
        destroyAsyncCommandJob(job);
        state.commandLifecycleSetFailed(command_id, "async_spawn_failed");
        return;
    };
    t.detach();
}

fn createAsyncCommandJob(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    command_id: []const u8,
    command_name: []const u8,
    upstream_path: []const u8,
    envelope: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    identity: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
) !*AsyncCommandJob {
    const job = try allocator.create(AsyncCommandJob);
    errdefer allocator.destroy(job);
    job.* = .{
        .allocator = allocator,
        .cfg = cfg,
        .state = state,
        .command_id = dupeOrEmpty(allocator, command_id),
        .command_name = dupeOrEmpty(allocator, command_name),
        .upstream_path = dupeOrEmpty(allocator, upstream_path),
        .envelope = dupeOrEmpty(allocator, envelope),
        .correlation_id = dupeOrEmpty(allocator, correlation_id),
        .client_ip = dupeOrEmpty(allocator, client_ip),
        .identity = if (identity) |id| allocator.dupe(u8, id) catch null else null,
        .incoming_host = if (incoming_host) |h| allocator.dupe(u8, h) catch null else null,
        .incoming_x_forwarded_for = if (incoming_x_forwarded_for) |xff| allocator.dupe(u8, xff) catch null else null,
        .api_version = api_version,
    };
    return job;
}

fn dupeOrEmpty(allocator: std.mem.Allocator, src: []const u8) []u8 {
    return allocator.dupe(u8, src) catch allocator.alloc(u8, 0) catch unreachable;
}

fn destroyAsyncCommandJob(job: *AsyncCommandJob) void {
    const alloc = job.allocator;
    if (job.command_id.len > 0) alloc.free(job.command_id);
    if (job.command_name.len > 0) alloc.free(job.command_name);
    if (job.upstream_path.len > 0) alloc.free(job.upstream_path);
    if (job.envelope.len > 0) alloc.free(job.envelope);
    if (job.correlation_id.len > 0) alloc.free(job.correlation_id);
    if (job.client_ip.len > 0) alloc.free(job.client_ip);
    if (job.identity) |id| alloc.free(id);
    if (job.incoming_host) |h| alloc.free(h);
    if (job.incoming_x_forwarded_for) |xff| alloc.free(xff);
    alloc.destroy(job);
}

fn runAsyncCommandJob(job: *AsyncCommandJob) void {
    defer destroyAsyncCommandJob(job);

    job.state.commandLifecycleSetRunning(job.command_id);
    const exec = executeBoundedControlPlaneJsonProxy(
        job.allocator,
        job.cfg,
        .commands,
        job.cfg.proxy_pass_commands_prefix,
        job.upstream_path,
        job.envelope,
        job.correlation_id,
        job.client_ip,
        job.identity,
        null,
        null,
        null,
        job.api_version,
        job.incoming_host,
        job.incoming_x_forwarded_for,
        std.io.null_writer,
        job.state,
        false,
        null,
    ) catch |err| {
        job.state.commandLifecycleSetFailed(job.command_id, @errorName(err));
        return;
    };

    switch (exec) {
        .streamed_status => |streamed| {
            job.state.commandLifecycleSetCompleted(job.command_id, streamed.status, "", JSON_CONTENT_TYPE);
        },
        .buffered => |resp| {
            defer job.allocator.free(resp.body);
            defer job.allocator.free(resp.content_type);
            if (resp.content_disposition) |cd| job.allocator.free(cd);
            if (resp.location) |location| job.allocator.free(location);
            job.state.commandLifecycleSetCompleted(job.command_id, resp.status, resp.body, resp.content_type);
        },
    }
}

test "async command jobs copy request-owned inputs onto long-lived allocator" {
    var request_arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    const request_allocator = request_arena_state.allocator();

    const command_id = try request_allocator.dupe(u8, "cmd-request-owned");
    const command_name = try request_allocator.dupe(u8, "chat.send");
    const upstream_path = try request_allocator.dupe(u8, "/run");
    const envelope = try request_allocator.dupe(u8, "{\"ok\":true}");
    const correlation_id = try request_allocator.dupe(u8, "corr-123");
    const client_ip = try request_allocator.dupe(u8, "127.0.0.1");
    const identity = try request_allocator.dupe(u8, "identity-1");
    const incoming_host = try request_allocator.dupe(u8, "example.test");
    const incoming_xff = try request_allocator.dupe(u8, "10.0.0.1");

    var cfg: edge_config.EdgeConfig = undefined;
    var state: GatewayState = undefined;
    state.allocator = std.testing.allocator;

    const job = try createAsyncCommandJob(
        std.testing.allocator,
        &cfg,
        &state,
        command_id,
        command_name,
        upstream_path,
        envelope,
        correlation_id,
        client_ip,
        identity,
        1,
        incoming_host,
        incoming_xff,
    );
    defer destroyAsyncCommandJob(job);

    request_arena_state.deinit();

    try std.testing.expectEqualStrings("cmd-request-owned", job.command_id);
    try std.testing.expectEqualStrings("chat.send", job.command_name);
    try std.testing.expectEqualStrings("/run", job.upstream_path);
    try std.testing.expectEqualStrings("{\"ok\":true}", job.envelope);
    try std.testing.expectEqualStrings("corr-123", job.correlation_id);
    try std.testing.expectEqualStrings("127.0.0.1", job.client_ip);
    try std.testing.expectEqualStrings("identity-1", job.identity.?);
    try std.testing.expectEqualStrings("example.test", job.incoming_host.?);
    try std.testing.expectEqualStrings("10.0.0.1", job.incoming_x_forwarded_for.?);
}

pub fn parseLastEventId(raw: ?[]const u8) u64 {
    const value = raw orelse return 0;
    return std.fmt.parseInt(u64, std.mem.trim(u8, value, " \t\r\n"), 10) catch 0;
}

pub fn applyInternalRedirectRules(
    method: []const u8,
    path: []const u8,
    rules: []const edge_config.EdgeConfig.InternalRedirectRule,
    named_locations: []const edge_config.EdgeConfig.NamedLocation,
) []const u8 {
    var current = path;
    var hops: usize = 0;
    while (hops < 6) : (hops += 1) {
        var changed = false;
        for (rules) |rule| {
            if (!http.rewrite.methodMatches(rule.method, method)) continue;
            if (!http.rewrite.regexMatches(rule.pattern, current)) continue;
            if (rule.target.len > 1 and rule.target[0] == '@') {
                if (resolveNamedLocation(rule.target[1..], named_locations)) |named| {
                    current = named;
                    changed = true;
                    break;
                }
            } else {
                current = rule.target;
                changed = true;
                break;
            }
        }
        if (!changed) break;
    }
    return current;
}

pub fn evaluateConditionalRules(
    allocator: std.mem.Allocator,
    rules: []const edge_config.EdgeConfig.ConditionalRule,
    path: []const u8,
    request_uri: []const u8,
    host: []const u8,
    args: []const u8,
) !?http.rewrite.Outcome {
    for (rules) |rule| {
        const input = switch (rule.variable) {
            .request_uri => request_uri,
            .http_host => host,
            .args => args,
        };

        switch (rule.action) {
            .rewrite => |rw| {
                const replacement = try http.rewrite.substitutePattern(
                    allocator,
                    rule.pattern,
                    input,
                    request_uri,
                    rw.replacement,
                    rule.case_insensitive,
                ) orelse continue;
                switch (rw.flag) {
                    .redirect => return .{ .redirect = .{ .status = 302, .location = replacement } },
                    .permanent => return .{ .redirect = .{ .status = 301, .location = replacement } },
                    .@"break", .last => return .{ .pass = replacement },
                }
            },
            .returned => |ret| {
                const body = try http.rewrite.substitutePattern(
                    allocator,
                    rule.pattern,
                    input,
                    request_uri,
                    ret.body,
                    rule.case_insensitive,
                ) orelse continue;
                return .{ .returned = .{ .status = ret.status, .body = body } };
            },
        }
    }
    _ = path;
    return null;
}

fn resolveNamedLocation(name: []const u8, named_locations: []const edge_config.EdgeConfig.NamedLocation) ?[]const u8 {
    for (named_locations) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.path;
    }
    return null;
}

pub fn spawnMirrorRequests(
    allocator: std.mem.Allocator,
    rules: []const edge_config.EdgeConfig.MirrorRule,
    method: []const u8,
    path: []const u8,
    body: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    content_type: ?[]const u8,
) void {
    for (rules) |rule| {
        if (!http.rewrite.methodMatches(rule.method, method)) continue;
        if (!http.rewrite.regexMatches(rule.pattern, path)) continue;
        var client = std.http.Client{ .allocator = allocator, .io = compat.io() };
        defer client.deinit();
        const uri = std.Uri.parse(rule.target_url) catch continue;
        var header_buf: [1024]u8 = undefined;
        var headers = [_]std.http.Header{
            .{ .name = http.correlation.REQUEST_HEADER_NAME, .value = correlation_id },
            .{ .name = http.correlation.HEADER_NAME, .value = correlation_id },
            .{ .name = "X-Mirror-Client-IP", .value = client_ip },
            .{ .name = "Content-Type", .value = content_type orelse "application/octet-stream" },
        };
        var req = client.request(.POST, uri, .{
            .extra_headers = headers[0..],
            .headers = .{ .content_type = .{ .override = content_type orelse "application/octet-stream" } },
        }) catch continue;
        defer req.deinit();
        req.sendBodyComplete(@constCast(body)) catch continue;
        _ = req.receiveHead(&header_buf) catch {}; // subrequest response is intentionally ignored; fire-and-forget
    }
}

const SubrequestPayload = struct {
    method: std.http.Method = .GET,
    url: []u8,
    body: ?[]u8 = null,
};

const SubrequestResult = struct {
    status: u16,
    body: []u8,
    content_type: []const u8,
};

fn parseSubrequestPayload(allocator: std.mem.Allocator, body: []const u8) !SubrequestPayload {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    const url_val = obj.get("url") orelse return error.InvalidPayload;
    if (url_val != .string) return error.InvalidPayload;
    const method = if (obj.get("method")) |m| blk: {
        if (m != .string) break :blk std.http.Method.GET;
        break :blk if (std.ascii.eqlIgnoreCase(m.string, "POST")) std.http.Method.POST else std.http.Method.GET;
    } else std.http.Method.GET;
    const req_body = if (obj.get("body")) |b| blk: {
        if (b != .string) break :blk null;
        break :blk try allocator.dupe(u8, b.string);
    } else null;
    return .{
        .method = method,
        .url = try allocator.dupe(u8, url_val.string),
        .body = req_body,
    };
}

fn executeSubrequest(allocator: std.mem.Allocator, url: []const u8, method: std.http.Method, req_body: ?[]const u8) !SubrequestResult {
    var client = std.http.Client{ .allocator = allocator, .io = compat.io() };
    defer client.deinit();
    const uri = try std.Uri.parse(url);
    var header_buf: [16 * 1024]u8 = undefined;
    var req = try client.request(method, uri, .{});
    defer req.deinit();
    if (req_body) |b| {
        try req.sendBodyComplete(@constCast(b));
    } else {
        try req.sendBodiless();
    }
    var resp = try req.receiveHead(&header_buf);
    const resp_status = @intFromEnum(resp.head.status);
    const resp_content_type = resp.head.content_type orelse "application/octet-stream";
    var resp_buf: [8192]u8 = undefined;
    const body_data = try resp.reader(&resp_buf).allocRemaining(allocator, .limited(2 * 1024 * 1024));
    return .{
        .status = resp_status,
        .body = body_data,
        .content_type = resp_content_type,
    };
}

pub const Http3DispatchContext = struct {
    config_store: *ReloadableConfigStore,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
};

const Http3LocationOutcome = union(enum) {
    not_handled,
    handled,
    rewritten: struct {
        path: []const u8,
        query: ?[]const u8,
    },
};

fn finalizeHttp3Response(response: *http.Response) void {
    if (response.headers.get("x-request-id")) |request_id| {
        _ = response.setHeader(http.correlation.HEADER_NAME, request_id);
    } else if (response.headers.get("x-correlation-id")) |correlation_id| {
        _ = response.setHeader(http.correlation.REQUEST_HEADER_NAME, correlation_id);
    }
    _ = response
        .setHeader("server", http.SERVER_NAME)
        .setContentLength(if (response.body) |body| body.len else 0);
}

fn handleHttp3LocationProxyPass(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    ctx: *Http3DispatchContext,
    matched: http.location_router.MatchResult,
    request_path: []const u8,
    request_query: ?[]const u8,
    target: []const u8,
    correlation_id: []const u8,
) !void {
    const resolved = try resolveProxyTarget(allocator, ctx.cfg.upstream_base_url, target, proxySuffixPathForLocation(request_path, matched, ctx.cfg.location_blocks));
    defer allocator.free(resolved.url);
    var upstream_url = try appendProxyQueryString(allocator, resolved.url, request_query);
    defer upstream_url.deinit(allocator);

    var upstream_response = try executeBufferedDataPlaneProxyRequest(
        allocator,
        &ctx.state.upstream_client,
        ctx.cfg,
        upstream_url.value,
        resolved.unix_socket_path,
        request.method,
        &request.headers,
        request.body,
        correlation_id,
        request.headers.get("x-real-ip") orelse "unknown",
        if (edge_config.hasTlsFiles(ctx.cfg)) "https" else "http",
        request.headers.get(":authority") orelse request.headers.get("host"),
        null,
        null,
        null,
        null,
        ctx.cfg.upstream_timeout_ms,
        ctx.cfg.upstream_connect_timeout_ms,
        ctx.cfg.upstream_response_timeout_ms,
        null, // HTTP/3 path: no per-request lifecycle yet
    );
    defer upstream_response.deinit(allocator);
    const buffered_response = upstream_response.boundedBufferedForCompatibility();

    _ = response
        .setStatus(@enumFromInt(buffered_response.status_code))
        .setBodyOwned(try allocator.dupe(u8, buffered_response.body))
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    for (buffered_response.headers) |header| {
        _ = response.setHeader(header.name, header.value);
    }
    finalizeHttp3Response(response);
    applyResponseHeaders(ctx.state, response);
    ctx.state.metricsRecord(upstream_response.statusCode());
}

fn handleHttp3StaticLocation(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    matched: http.location_router.MatchResult,
    root_cfg: anytype,
    correlation_id: []const u8,
    ctx: *Http3DispatchContext,
    request_path: []const u8,
) !bool {
    if (!(std.mem.eql(u8, request.method, "GET") or std.mem.eql(u8, request.method, "HEAD"))) return false;

    var served = (try http.static_file.serve(allocator, .{
        .root = root_cfg.root,
        .request_path = request_path,
        .matched_pattern = matched.block.pattern,
        .alias = root_cfg.alias,
        .index = root_cfg.index,
        .try_files = root_cfg.try_files,
        .autoindex = root_cfg.autoindex,
        .headers = &request.headers,
        .max_bytes = MAX_REQUEST_SIZE,
    })) orelse blk: {
        var error_page = (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request_path, &request.headers, 404)) orelse return false;
        switch (error_page) {
            .redirect => |target| {
                defer allocator.free(target);
                _ = response
                    .setStatus(.found)
                    .setBody("")
                    .setContentType("text/plain; charset=utf-8")
                    .setHeader("Location", target)
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(302);
                return true;
            },
            .served => |*resolved| break :blk resolved.*,
        }
    };
    defer served.deinit(allocator);

    if (@intFromEnum(served.status_code) >= 400) {
        if (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request_path, &request.headers, @intFromEnum(served.status_code))) |error_page| {
            switch (error_page) {
                .redirect => |target| {
                    defer allocator.free(target);
                    _ = response
                        .setStatus(.found)
                        .setBody("")
                        .setContentType("text/plain; charset=utf-8")
                        .setHeader("Location", target)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    finalizeHttp3Response(response);
                    applyResponseHeaders(ctx.state, response);
                    ctx.state.metricsRecord(302);
                    return true;
                },
                .served => |replacement| {
                    served.deinit(allocator);
                    served = replacement;
                },
            }
        }
    }

    _ = response
        .setStatus(served.status_code)
        .setBodyOwned(if (std.mem.eql(u8, request.method, "HEAD")) try allocator.dupe(u8, "") else try allocator.dupe(u8, served.body orelse ""))
        .setContentType(served.content_type)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    if (served.etag_value) |etag_value| _ = response.setHeader("ETag", etag_value);
    if (served.last_modified_value) |last_modified| _ = response.setHeader("Last-Modified", last_modified);
    if (served.content_range_value) |content_range| _ = response.setHeader("Content-Range", content_range);
    if (served.accept_ranges) _ = response.setHeader("Accept-Ranges", "bytes");
    _ = response
        .setHeader("server", http.SERVER_NAME)
        .setContentLength(served.content_length);
    applyResponseHeaders(ctx.state, response);
    ctx.state.metricsRecord(@intFromEnum(served.status_code));
    return true;
}

fn routeHttp3Location(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    ctx: *Http3DispatchContext,
    request_path: []const u8,
    correlation_id: []const u8,
) !Http3LocationOutcome {
    const matched = http.location_router.matchLocation(request_path, ctx.cfg.location_blocks) orelse return .not_handled;
    const split = splitHttp3PathAndQuery(request.path);
    const request_query = split[1];
    switch (matched.block.action) {
        .proxy_pass => |target| {
            try handleHttp3LocationProxyPass(allocator, request, response, ctx, matched, request_path, request_query, target, correlation_id);
            return .handled;
        },
        .return_response => |ret| {
            _ = response
                .setStatus(@enumFromInt(ret.status))
                .setBody(ret.body)
                .setContentType(if (ret.status >= 300 and ret.status < 400) "text/plain; charset=utf-8" else "text/plain; charset=utf-8")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            if (ret.status >= 300 and ret.status < 400 and ret.body.len > 0) {
                _ = response.setHeader("location", ret.body);
            }
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(ret.status);
            return .handled;
        },
        .rewrite => |rw| {
            const rewritten_path, const rewritten_query = splitHttp3PathAndQuery(rw.replacement);
            return .{ .rewritten = .{ .path = rewritten_path, .query = rewritten_query } };
        },
        .static_root => |root_cfg| {
            if (try handleHttp3StaticLocation(allocator, request, response, matched, root_cfg, correlation_id, ctx, request_path)) {
                return .handled;
            }
            return .not_handled;
        },
        .fastcgi_pass => return .not_handled,
    }
}

fn handleHttp3Connection(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    ctx: *Http3DispatchContext,
) !void {
    const correlation_id = request.headers.get(http.correlation.REQUEST_HEADER_NAME) orelse request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
    var http3_path, _ = splitHttp3PathAndQuery(request.path);
    var rewrite_budget: usize = 0;
    while (rewrite_budget < 4) : (rewrite_budget += 1) {
        switch (try routeHttp3Location(allocator, request, response, ctx, http3_path, correlation_id)) {
            .handled => return,
            .not_handled => break,
            .rewritten => |rewrite_result| {
                http3_path = rewrite_result.path;
            },
        }
    }

    const payload = try buildApiErrorJson(allocator, "invalid_request", "Not Found", correlation_id);
    _ = response
        .setStatus(.not_found)
        .setBodyOwned(payload)
        .setContentType("application/json")
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    finalizeHttp3Response(response);
    applyResponseHeaders(ctx.state, response);
    ctx.state.metricsRecord(404);
}

fn splitHttp3PathAndQuery(path: []const u8) struct { []const u8, ?[]const u8 } {
    if (std.mem.findScalar(u8, path, '?')) |idx| {
        return .{ path[0..idx], path[idx + 1 ..] };
    }
    return .{ path, null };
}

pub fn handleHttp3Request(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    user_data: ?*anyopaque,
) !void {
    const ctx: *Http3DispatchContext = @ptrCast(@alignCast(user_data orelse return error.InvalidArgument));
    var cfg_lease = ctx.config_store.acquire();
    defer cfg_lease.release();
    const active_cfg = cfg_lease.cfg;
    const authority = request.headers.get(":authority") orelse request.headers.get("host");
    var effective_cfg_storage = active_cfg.*;
    const effective_cfg = resolveRequestConfig(active_cfg, authority, &effective_cfg_storage) orelse {
        const correlation_id = request.headers.get(http.correlation.REQUEST_HEADER_NAME) orelse request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
        const payload = try buildApiErrorJson(allocator, "invalid_request", "Not Found", correlation_id);
        _ = response
            .setStatus(.not_found)
            .setBodyOwned(payload)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(404);
        return;
    };
    if (!hostMatchesPatterns(effective_cfg.server_names, authority)) {
        const correlation_id = request.headers.get(http.correlation.REQUEST_HEADER_NAME) orelse request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
        const payload = try buildApiErrorJson(allocator, "invalid_request", "Not Found", correlation_id);
        _ = response
            .setStatus(.not_found)
            .setBodyOwned(payload)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(404);
        return;
    }

    var effective_ctx = ctx.*;
    effective_ctx.cfg = effective_cfg;
    try handleHttp3Connection(allocator, request, response, &effective_ctx);
}

pub fn logAccess(state: *GatewayState, ctx: *const http.request_context.RequestContext, method: []const u8, path: []const u8, status: u16, user_agent: []const u8) void {
    state.metricsRecordLatencyMs(ctx.elapsedMs());
    const cancel_reason: []const u8 = if (ctx.lifecycle) |lc|
        if (lc.token.reason) |reason| @tagName(reason) else ""
    else
        "";
    const entry = http.access_log.AccessLogEntry{
        .method = method,
        .path = path,
        .status = status,
        .latency_ms = ctx.elapsedMs(),
        .client_ip = ctx.client_ip,
        .correlation_id = ctx.request_id,
        .upstream_addr = ctx.upstream_addr orelse "",
        .upstream_status = ctx.upstream_status,
        .identity = ctx.identity orelse "-",
        .user_agent = user_agent,
        .bytes_sent = ctx.response_bytes,
        .response_bytes = ctx.response_bytes,
        .error_category = classifyErrorCategory(status),
        .cancel_reason = cancel_reason,
    };
    entry.log();
}

pub fn classifyErrorCategory(status: u16) []const u8 {
    return if (status < 400)
        "-"
    else if (status == 400 or status == 413 or status == 414)
        "invalid_request"
    else if (status == 401 or status == 403)
        "authz"
    else if (status == 408)
        "request_timeout"
    else if (status == 429)
        "rate_limited"
    else if (status == 503)
        "upstream_unavailable"
    else if (status == 504)
        "upstream_timeout"
    else if (status >= 500)
        "internal_error"
    else
        "client_error";
}

test "classifyErrorCategory maps statuses" {
    try std.testing.expectEqualStrings("-", classifyErrorCategory(200));
    try std.testing.expectEqualStrings("invalid_request", classifyErrorCategory(400));
    try std.testing.expectEqualStrings("authz", classifyErrorCategory(401));
    try std.testing.expectEqualStrings("rate_limited", classifyErrorCategory(429));
    try std.testing.expectEqualStrings("upstream_unavailable", classifyErrorCategory(503));
    try std.testing.expectEqualStrings("upstream_timeout", classifyErrorCategory(504));
    try std.testing.expectEqualStrings("internal_error", classifyErrorCategory(500));
}

test "parseQueryParam extracts topic" {
    const value = parseQueryParam("topic=alerts&foo=bar", "topic");
    try std.testing.expect(value != null);
    try std.testing.expectEqualStrings("alerts", value.?);
    try std.testing.expect(parseQueryParam("foo=bar", "topic") == null);
}

test "parseLastEventId handles invalid values" {
    try std.testing.expectEqual(@as(u64, 42), parseLastEventId("42"));
    try std.testing.expectEqual(@as(u64, 0), parseLastEventId("bad"));
    try std.testing.expectEqual(@as(u64, 0), parseLastEventId(null));
}
