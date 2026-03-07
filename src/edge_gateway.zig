const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");

const MAX_REQUEST_SIZE: usize = 256 * 1024;
const JSON_CONTENT_TYPE = "application/json";

/// Persistent gateway state shared across connections.
const GatewayState = struct {
    rate_limiter: ?http.rate_limiter.RateLimiter,
    idempotency_store: ?http.idempotency.IdempotencyStore,
    security_headers: http.security_headers.SecurityHeaders,
    session_store: ?http.session.SessionStore,
    access_control: ?http.access_control.AccessControl,
    logger: http.logger.Logger,
    metrics: http.metrics.Metrics,
    compression_config: http.compression.CompressionConfig,
    circuit_breaker: http.circuit_breaker.CircuitBreaker,
};

pub fn run(cfg: *const edge_config.EdgeConfig) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const state_allocator = gpa.allocator();

    var state = GatewayState{
        .rate_limiter = if (cfg.rate_limit_rps > 0)
            http.rate_limiter.RateLimiter.init(state_allocator, cfg.rate_limit_rps, cfg.rate_limit_burst)
        else
            null,
        .idempotency_store = if (cfg.idempotency_ttl_seconds > 0)
            http.idempotency.IdempotencyStore.init(state_allocator, cfg.idempotency_ttl_seconds)
        else
            null,
        .security_headers = if (cfg.security_headers_enabled)
            http.security_headers.SecurityHeaders.api
        else
            http.security_headers.SecurityHeaders{ .x_frame_options = "", .x_content_type_options = "", .content_security_policy = "", .strict_transport_security = "", .referrer_policy = "", .permissions_policy = "", .x_xss_protection = "" },
        .session_store = if (cfg.session_ttl_seconds > 0)
            http.session.SessionStore.init(state_allocator, cfg.session_ttl_seconds, cfg.session_max)
        else
            null,
        .access_control = if (cfg.access_control_rules.len > 0)
            http.access_control.AccessControl.fromConfig(state_allocator, cfg.access_control_rules, .allow) catch null
        else
            null,
        .logger = http.logger.Logger.init(cfg.log_level, "gateway"),
        .metrics = http.metrics.Metrics.init(),
        .compression_config = .{
            .enabled = cfg.compression_enabled,
            .min_size = cfg.compression_min_size,
        },
        .circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{
            .threshold = cfg.cb_threshold,
            .timeout_ms = cfg.cb_timeout_ms,
        }),
    };
    defer {
        if (state.rate_limiter) |*rl| rl.deinit();
        if (state.idempotency_store) |*is| is.deinit();
        if (state.session_store) |*ss| ss.deinit();
        if (state.access_control) |*acl| acl.deinit();
    }

    const address = try std.net.Address.parseIp(cfg.listen_host, cfg.listen_port);
    var server = try std.net.Address.listen(address, .{ .reuse_address = true });
    defer server.deinit();
    const listen_fd = server.stream.handle;

    try setNonBlocking(listen_fd, true);

    var event_loop = try http.event_loop.EventLoop.init();
    defer event_loop.deinit();
    try event_loop.addReadFd(listen_fd);
    var timer = http.event_loop.TimerManager.init(250);

    state.logger.info(null, "Tardigrade edge listening on {s}:{d}", .{ cfg.listen_host, cfg.listen_port });
    state.logger.info(null, "Event loop initialized with backend: {s}", .{event_loop.backendName()});
    if (!edge_config.hasTlsFiles(cfg)) {
        state.logger.warn(null, "TLS cert/key not set; serving HTTP only", .{});
    } else {
        state.logger.info(null, "TLS cert/key configured at {s} and {s}", .{ cfg.tls_cert_path, cfg.tls_key_path });
    }
    if (state.rate_limiter != null) {
        state.logger.info(null, "Rate limiting enabled: {d:.0} req/s, burst {d}", .{ cfg.rate_limit_rps, cfg.rate_limit_burst });
    }
    if (state.idempotency_store != null) {
        state.logger.info(null, "Idempotency cache enabled: TTL {d}s", .{cfg.idempotency_ttl_seconds});
    }
    if (state.session_store != null) {
        state.logger.info(null, "Session management enabled: TTL {d}s, max {d}", .{ cfg.session_ttl_seconds, cfg.session_max });
    }
    if (state.access_control != null) {
        state.logger.info(null, "IP access control enabled", .{});
    }
    if (cfg.basic_auth_hashes.len > 0) {
        state.logger.info(null, "HTTP Basic Auth enabled with {d} credential(s)", .{cfg.basic_auth_hashes.len});
    }
    {
        const limits = cfg.request_limits;
        if (limits.max_body_size > 0 or limits.max_uri_length > 0 or limits.max_header_count > 0) {
            state.logger.info(null, "Request limits configured", .{});
        }
    }
    if (cfg.compression_enabled) {
        state.logger.info(null, "Gzip compression enabled (min size: {d} bytes)", .{cfg.compression_min_size});
    }
    if (cfg.cb_threshold > 0) {
        state.logger.info(null, "Circuit breaker enabled: threshold={d} timeout={d}ms", .{ cfg.cb_threshold, cfg.cb_timeout_ms });
    }

    // Install signal handlers for graceful shutdown
    http.shutdown.installSignalHandlers();
    state.logger.info(null, "Signal handlers installed (SIGTERM/SIGINT for graceful shutdown)", .{});

    var ready_events: [64]http.event_loop.Event = undefined;
    while (!http.shutdown.isShutdownRequested()) {
        const now_ms = http.event_loop.monotonicMs();
        const timeout_ms = timer.msUntilNextTick(now_ms);
        const event_count = event_loop.wait(ready_events[0..], timeout_ms) catch |err| {
            state.logger.err(null, "event loop wait error: {}", .{err});
            continue;
        };

        var i: usize = 0;
        while (i < event_count) : (i += 1) {
            const ev = ready_events[i];
            if (!ev.readable or ev.fd != listen_fd) continue;
            acceptReadyConnections(listen_fd, cfg, &state);
        }

        if (timer.consumeTick(http.event_loop.monotonicMs())) {
            // Timer hook for periodic housekeeping (timeouts, cleanup) as async features expand.
        }
    }

    state.logger.info(null, "Graceful shutdown complete", .{});
}

fn acceptReadyConnections(listen_fd: std.posix.fd_t, cfg: *const edge_config.EdgeConfig, state: *GatewayState) void {
    while (!http.shutdown.isShutdownRequested()) {
        var accepted_addr: std.net.Address = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(std.net.Address);

        const client_fd = std.posix.accept(
            listen_fd,
            &accepted_addr.any,
            &addr_len,
            std.posix.SOCK.CLOEXEC | std.posix.SOCK.NONBLOCK,
        ) catch |err| switch (err) {
            error.WouldBlock => return,
            error.ConnectionAborted => continue,
            else => {
                state.logger.err(null, "accept error: {}", .{err});
                return;
            },
        };

        setNonBlocking(client_fd, false) catch |err| {
            state.logger.warn(null, "failed to switch client fd to blocking mode: {}", .{err});
            std.posix.close(client_fd);
            continue;
        };

        const stream = std.net.Stream{ .handle = client_fd };
        handleConnection(stream, cfg, state) catch |err| {
            state.logger.err(null, "edge connection error: {}", .{err});
        };
        stream.close();
    }
}

fn setNonBlocking(fd: std.posix.fd_t, enabled: bool) !void {
    var flags = try std.posix.fcntl(fd, std.posix.F.GETFL, 0);
    const nonblock_mask = @as(i32, 1 << @bitOffsetOf(std.posix.O, "NONBLOCK"));
    if (enabled) {
        flags |= nonblock_mask;
    } else {
        flags &= ~nonblock_mask;
    }
    _ = try std.posix.fcntl(fd, std.posix.F.SETFL, flags);
}

fn handleConnection(stream: std.net.Stream, cfg: *const edge_config.EdgeConfig, state: *GatewayState) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var req_buf: [MAX_REQUEST_SIZE]u8 = undefined;
    const total_read = try readHttpRequest(stream, req_buf[0..]);
    if (total_read == 0) return;

    const parse_result = http.Request.parse(allocator, req_buf[0..total_read], MAX_REQUEST_SIZE) catch |err| {
        try sendApiError(allocator, stream.writer(), .bad_request, "invalid_request", "Malformed request", null, false, state);
        state.logger.warn(null, "parse error: {}", .{err});
        return;
    };

    var request = parse_result.request;
    defer request.deinit();
    const writer = stream.writer();

    // --- Correlation ID ---
    const correlation_id = try http.correlation.fromHeadersOrGenerate(allocator, &request.headers);
    defer allocator.free(correlation_id);

    // --- Request Context ---
    const client_ip = http.request_context.extractClientIp(&request, "unknown");
    var ctx = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);

    // --- Request validation (body size, URI length, header count) ---
    const limits = cfg.request_limits;
    const uri_check = http.request_limits.validateUriLength(request.uri.path.len, limits);
    if (uri_check != .ok) {
        var msg_buf: [256]u8 = undefined;
        const msg = http.request_limits.rejectionMessage(uri_check, &msg_buf);
        try sendApiError(allocator, writer, .uri_too_long, "invalid_request", msg, correlation_id, false, state);
        state.logger.warn(correlation_id, "URI too long: {d} bytes", .{request.uri.path.len});
        logAccess(&ctx, request.method.toString(), request.uri.path, 414, request.headers.get("user-agent") orelse "");
        return;
    }
    const header_count_check = http.request_limits.validateHeaderCount(request.headers.count(), limits);
    if (header_count_check != .ok) {
        try sendApiError(allocator, writer, .bad_request, "invalid_request", "Too many headers", correlation_id, false, state);
        state.logger.warn(correlation_id, "Too many headers: {d}", .{request.headers.count()});
        logAccess(&ctx, request.method.toString(), request.uri.path, 400, request.headers.get("user-agent") orelse "");
        return;
    }
    if (request.body) |body| {
        const body_check = http.request_limits.validateBodySize(body.len, limits);
        if (body_check != .ok) {
            try sendApiError(allocator, writer, .payload_too_large, "invalid_request", "Request body too large", correlation_id, false, state);
            state.logger.warn(correlation_id, "Body too large: {d} bytes", .{body.len});
            logAccess(&ctx, request.method.toString(), request.uri.path, 413, request.headers.get("user-agent") orelse "");
            return;
        }
    }

    // --- Extract API version ---
    if (http.api_router.parseVersionedPath(request.uri.path)) |versioned| {
        ctx.setApiVersion(versioned.version);
    }

    // --- Extract idempotency key ---
    if (http.idempotency.fromHeaders(&request.headers)) |idem_key| {
        ctx.setIdempotencyKey(idem_key);
    }

    // --- IP Access Control ---
    if (state.access_control) |*acl| {
        if (acl.check(client_ip) == .denied) {
            try sendApiError(allocator, writer, .forbidden, "forbidden", "Access denied", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 403, request.headers.get("user-agent") orelse "");
            return;
        }
    }

    // --- Rate Limiting ---
    if (state.rate_limiter) |*rl| {
        if (rl.allow(client_ip)) |rl_result| {
            // Attach rate limit info — will be added to response headers below
            _ = rl_result;
        } else {
            try sendApiError(allocator, writer, .too_many_requests, "rate_limited", "Rate limit exceeded", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 429, request.headers.get("user-agent") orelse "");
            return;
        }
    }

    // --- Health endpoint ---
    if (request.method == .GET and std.mem.eql(u8, request.uri.path, "/health")) {
        var response = http.Response.json(allocator, "{\"status\":\"ok\",\"service\":\"tardigrade-edge\"}");
        defer response.deinit();
        _ = response.setConnection(false).setHeader(http.correlation.HEADER_NAME, correlation_id);
        state.security_headers.apply(&response);
        try response.write(writer);
        state.metrics.recordRequest(200);
        logAccess(&ctx, request.method.toString(), "/health", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Metrics endpoint ---
    if (request.method == .GET and std.mem.eql(u8, request.uri.path, "/metrics")) {
        const metrics_json = state.metrics.toJson(allocator) catch {
            try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to generate metrics", correlation_id, false, state);
            return;
        };
        defer allocator.free(metrics_json);

        var response = http.Response.json(allocator, metrics_json);
        defer response.deinit();
        _ = response.setConnection(false).setHeader(http.correlation.HEADER_NAME, correlation_id);
        state.security_headers.apply(&response);
        try response.write(writer);
        state.metrics.recordRequest(200);
        logAccess(&ctx, request.method.toString(), "/metrics", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Prometheus metrics endpoint ---
    if (request.method == .GET and std.mem.eql(u8, request.uri.path, "/metrics/prometheus")) {
        const prom_text = state.metrics.toPrometheus(allocator) catch {
            try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to generate metrics", correlation_id, false, state);
            return;
        };
        defer allocator.free(prom_text);

        var response = http.Response.init(allocator);
        defer response.deinit();
        _ = response.setBody(prom_text)
            .setContentType("text/plain; version=0.0.4; charset=utf-8")
            .setConnection(false)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        state.security_headers.apply(&response);
        try response.write(writer);
        state.metrics.recordRequest(200);
        logAccess(&ctx, request.method.toString(), "/metrics/prometheus", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Versioned API routing ---
    const versioned = http.api_router.parseVersionedPath(request.uri.path);
    if (versioned) |route| {
        if (!http.api_router.isSupportedVersion(route.version)) {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Unsupported API version", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 400, request.headers.get("user-agent") orelse "");
            return;
        }
    }

    // --- POST /v1/sessions (create session) ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/sessions")) {
        if (state.session_store == null) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Sessions not enabled", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 404, request.headers.get("user-agent") orelse "");
            return;
        }

        // Requires bearer auth to create a session
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (!auth_result.ok) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 401, request.headers.get("user-agent") orelse "");
            return;
        }
        const identity = auth_result.token_hash orelse "-";
        ctx.setIdentity(identity);

        // Optional device_id from JSON body
        var device_id: ?[]const u8 = null;
        if (request.body) |body| {
            if (isJsonContentType(request.contentType())) {
                device_id = parseDeviceId(allocator, body) catch null;
            }
        }
        defer if (device_id) |d| allocator.free(d);

        const session_token = state.session_store.?.create(identity, client_ip, device_id) catch |err| {
            const msg = switch (err) {
                error.TooManySessions => "Too many active sessions",
                else => "Session creation failed",
            };
            try sendApiError(allocator, writer, .too_many_requests, "rate_limited", msg, correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 429, request.headers.get("user-agent") orelse "");
            return;
        };

        const resp_body = try std.fmt.allocPrint(allocator, "{{\"session_token\":\"{s}\"}}", .{session_token});
        defer allocator.free(resp_body);

        var response = http.Response.json(allocator, resp_body);
        defer response.deinit();
        _ = response.setStatus(.created)
            .setConnection(false)
            .setHeader(http.correlation.HEADER_NAME, correlation_id)
            .setHeader(http.session.SESSION_HEADER, session_token);
        state.security_headers.apply(&response);
        try response.write(writer);
        state.metrics.recordRequest(201);
        logAccess(&ctx, request.method.toString(), "/v1/sessions", 201, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- DELETE /v1/sessions (revoke session) ---
    if (request.method == .DELETE and http.api_router.matchRoute(request.uri.path, 1, "/sessions")) {
        if (state.session_store == null) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Sessions not enabled", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 404, request.headers.get("user-agent") orelse "");
            return;
        }

        const session_token = http.session.fromHeaders(&request.headers) orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing or invalid X-Session-Token", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 400, request.headers.get("user-agent") orelse "");
            return;
        };

        const revoked = state.session_store.?.revoke(session_token);
        const resp_body = if (revoked)
            "{\"revoked\":true}"
        else
            "{\"revoked\":false}";

        var response = http.Response.json(allocator, resp_body);
        defer response.deinit();
        _ = response.setConnection(false)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        state.security_headers.apply(&response);
        try response.write(writer);
        state.metrics.recordRequest(200);
        logAccess(&ctx, request.method.toString(), "/v1/sessions", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- GET /v1/sessions (list sessions for identity) ---
    if (request.method == .GET and http.api_router.matchRoute(request.uri.path, 1, "/sessions")) {
        if (state.session_store == null) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Sessions not enabled", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 404, request.headers.get("user-agent") orelse "");
            return;
        }

        // Requires bearer auth
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (!auth_result.ok) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 401, request.headers.get("user-agent") orelse "");
            return;
        }
        const identity = auth_result.token_hash orelse "-";

        const sessions = state.session_store.?.listByIdentity(allocator, identity) catch {
            try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to list sessions", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 500, request.headers.get("user-agent") orelse "");
            return;
        };
        defer allocator.free(sessions);

        const resp_body = try std.fmt.allocPrint(allocator, "{{\"active_sessions\":{d}}}", .{sessions.len});
        defer allocator.free(resp_body);

        var response = http.Response.json(allocator, resp_body);
        defer response.deinit();
        _ = response.setConnection(false)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        state.security_headers.apply(&response);
        try response.write(writer);
        state.metrics.recordRequest(200);
        logAccess(&ctx, request.method.toString(), "/v1/sessions", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- POST /v1/commands (structured command routing) ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/commands")) {
        // --- Auth (bearer token or session token) ---
        var cmd_authenticated = false;
        const cmd_auth_result = authorizeRequest(cfg, &request.headers);
        if (cmd_auth_result.ok) {
            ctx.setIdentity(cmd_auth_result.token_hash orelse "-");
            cmd_authenticated = true;
        }
        if (!cmd_authenticated) {
            if (state.session_store) |*ss| {
                if (http.session.fromHeaders(&request.headers)) |session_token| {
                    if (ss.validate(session_token)) |session| {
                        ctx.setIdentity(session.identity);
                        cmd_authenticated = true;
                    }
                }
            }
        }
        if (!cmd_authenticated) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/commands", 401, request.headers.get("user-agent") orelse "");
            return;
        }

        // --- Content-Type validation ---
        if (!isJsonContentType(request.contentType())) {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Content-Type must be application/json", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/commands", 400, request.headers.get("user-agent") orelse "");
            return;
        }

        // --- Body parsing ---
        const cmd_body = request.body orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing request body", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/commands", 400, request.headers.get("user-agent") orelse "");
            return;
        };

        var cmd = http.command.parseCommand(allocator, cmd_body) catch |err| {
            const msg = switch (err) {
                http.command.ParseError.MissingCommand => "Missing 'command' field",
                http.command.ParseError.UnknownCommand => "Unknown command type",
                http.command.ParseError.InvalidParams => "Invalid or missing 'params' object",
                else => "Invalid command envelope",
            };
            try sendApiError(allocator, writer, .bad_request, "invalid_request", msg, correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/commands", 400, request.headers.get("user-agent") orelse "");
            return;
        };
        defer cmd.deinit(allocator);

        // --- Idempotency (inline key overrides header) ---
        const effective_idem_key = cmd.idempotency_key orelse ctx.idempotency_key;
        if (effective_idem_key) |idem_key| {
            if (state.idempotency_store) |*store| {
                if (store.get(idem_key)) |cached| {
                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response.setStatus(@enumFromInt(cached.status))
                        .setBody(cached.body)
                        .setContentType(cached.content_type)
                        .setConnection(false)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id)
                        .setHeader("X-Idempotent-Replayed", "true");
                    state.security_headers.apply(&response);
                    try response.write(writer);
                    state.metrics.recordRequest(cached.status);
                    logAccess(&ctx, request.method.toString(), "/v1/commands", cached.status, request.headers.get("user-agent") orelse "");
                    return;
                }
            }
        }

        // --- Build upstream envelope with context ---
        const envelope = http.command.buildUpstreamEnvelope(
            allocator,
            cmd.command_type,
            cmd.params_raw,
            correlation_id,
            ctx.identity orelse "-",
            client_ip,
            ctx.api_version,
        ) catch {
            try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to build upstream request", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/commands", 500, request.headers.get("user-agent") orelse "");
            return;
        };
        defer allocator.free(envelope);

        // --- Forward to upstream ---
        const upstream_path = cmd.command_type.upstreamPath();

        // --- Circuit breaker check ---
        if (!state.circuit_breaker.tryAcquire()) {
            state.logger.warn(null, "circuit breaker open, rejecting /v1/commands", .{});
            try sendApiError(allocator, writer, .service_unavailable, "upstream_unavailable", "Upstream unavailable", correlation_id, false, state);
            const cb_audit = http.command.CommandAudit{
                .command = cmd.command_type.toString(),
                .correlation_id = correlation_id,
                .identity = ctx.identity orelse "-",
                .status = 503,
                .latency_ms = ctx.elapsedMs(),
            };
            cb_audit.log();
            return;
        }

        const cmd_proxy_result = proxyCommand(allocator, cfg, upstream_path, envelope, correlation_id) catch {
            state.circuit_breaker.recordFailure();
            state.logger.warn(null, "circuit breaker: recorded failure, state={s}", .{state.circuit_breaker.stateName()});
            try sendApiError(allocator, writer, .gateway_timeout, "upstream_timeout", "Upstream timeout", correlation_id, false, state);
            // Audit
            const cmd_audit = http.command.CommandAudit{
                .command = cmd.command_type.toString(),
                .correlation_id = correlation_id,
                .identity = ctx.identity orelse "-",
                .status = 504,
                .latency_ms = ctx.elapsedMs(),
            };
            cmd_audit.log();
            return;
        };
        defer allocator.free(cmd_proxy_result.body);

        // Record circuit breaker outcome based on upstream status
        if (cmd_proxy_result.status >= 500) {
            state.circuit_breaker.recordFailure();
        } else {
            state.circuit_breaker.recordSuccess();
        }

        var cmd_final_status: u16 = cmd_proxy_result.status;
        var cmd_final_body: []const u8 = cmd_proxy_result.body;
        var cmd_error_body: ?[]const u8 = null;
        if (cmd_proxy_result.status != 200) {
            const mapped = mapUpstreamError(cmd_proxy_result.status);
            cmd_final_status = mapped.status;
            cmd_final_body = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
            cmd_error_body = cmd_final_body;
        }
        defer {
            if (cmd_error_body) |eb| allocator.free(eb);
        }

        // --- Compress and send ---
        const cmd_accept_encoding = request.headers.get("Accept-Encoding");
        const cmd_comp = http.compression.compressResponse(allocator, cmd_final_body, JSON_CONTENT_TYPE, cmd_accept_encoding, state.compression_config);
        defer if (cmd_comp.body) |cb| allocator.free(cb);
        const cmd_resp_body = if (cmd_comp.body) |cb| cb else cmd_final_body;
        var response = http.Response.json(allocator, cmd_resp_body);
        defer response.deinit();
        _ = response.setStatus(@enumFromInt(cmd_final_status))
            .setConnection(false)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        if (cmd_comp.compressed) _ = response.setHeader("Content-Encoding", "gzip");
        state.security_headers.apply(&response);
        try response.write(writer);
        state.metrics.recordRequest(cmd_final_status);

        // --- Store idempotency result ---
        if (effective_idem_key) |idem_key| {
            if (state.idempotency_store) |*store| {
                store.put(idem_key, cmd_final_status, cmd_final_body, JSON_CONTENT_TYPE) catch |err| {
                    std.log.warn("idempotency store error: {}", .{err});
                };
            }
        }

        // --- Structured command audit ---
        const audit = http.command.CommandAudit{
            .command = cmd.command_type.toString(),
            .correlation_id = correlation_id,
            .identity = ctx.identity orelse "-",
            .status = cmd_final_status,
            .latency_ms = ctx.elapsedMs(),
        };
        audit.log();
        return;
    }

    // --- POST /v1/chat ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/chat")) {
        // --- Idempotency check ---
        if (ctx.idempotency_key) |idem_key| {
            if (state.idempotency_store) |*store| {
                if (store.get(idem_key)) |cached| {
                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response.setStatus(@enumFromInt(cached.status))
                        .setBody(cached.body)
                        .setContentType(cached.content_type)
                        .setConnection(false)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id)
                        .setHeader("X-Idempotent-Replayed", "true");
                    state.security_headers.apply(&response);
                    try response.write(writer);
                    state.metrics.recordRequest(cached.status);
                    logAccess(&ctx, request.method.toString(), "/v1/chat", cached.status, request.headers.get("user-agent") orelse "");
                    return;
                }
            }
        }

        // --- Auth (bearer token or session token) ---
        var authenticated = false;
        // Try bearer token first
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (auth_result.ok) {
            ctx.setIdentity(auth_result.token_hash orelse "-");
            authenticated = true;
        }
        // Fall back to session token
        if (!authenticated) {
            if (state.session_store) |*ss| {
                if (http.session.fromHeaders(&request.headers)) |session_token| {
                    if (ss.validate(session_token)) |session| {
                        ctx.setIdentity(session.identity);
                        authenticated = true;
                    }
                }
            }
        }
        if (!authenticated) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", 401, request.headers.get("user-agent") orelse "");
            return;
        }

        // --- Content-Type validation ---
        if (!isJsonContentType(request.contentType())) {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Content-Type must be application/json", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", 400, request.headers.get("user-agent") orelse "");
            return;
        }

        // --- Body validation ---
        const body = request.body orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing request body", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", 400, request.headers.get("user-agent") orelse "");
            return;
        };

        const message = parseChatMessage(allocator, body, cfg.max_message_chars) catch |err| {
            const msg = switch (err) {
                error.EmptyMessage => "message must not be empty",
                error.MessageTooLarge => "message too long",
                else => "invalid chat payload",
            };
            try sendApiError(allocator, writer, .bad_request, "invalid_request", msg, correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", 400, request.headers.get("user-agent") orelse "");
            return;
        };

        // --- Circuit breaker check ---
        if (!state.circuit_breaker.tryAcquire()) {
            state.logger.warn(null, "circuit breaker open, rejecting /v1/chat", .{});
            try sendApiError(allocator, writer, .service_unavailable, "upstream_unavailable", "Upstream unavailable", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", 503, request.headers.get("user-agent") orelse "");
            return;
        }

        // --- Upstream proxy ---
        const proxy_result = proxyChat(allocator, cfg, message, correlation_id) catch {
            state.circuit_breaker.recordFailure();
            state.logger.warn(null, "circuit breaker: recorded failure, state={s}", .{state.circuit_breaker.stateName()});
            try sendApiError(allocator, writer, .gateway_timeout, "upstream_timeout", "Upstream timeout", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", 504, request.headers.get("user-agent") orelse "");
            return;
        };
        defer allocator.free(proxy_result.body);

        // Record circuit breaker outcome based on upstream status
        if (proxy_result.status >= 500) {
            state.circuit_breaker.recordFailure();
        } else {
            state.circuit_breaker.recordSuccess();
        }

        var final_status: u16 = proxy_result.status;
        var final_body: []const u8 = proxy_result.body;
        var error_body_to_free: ?[]const u8 = null;
        if (proxy_result.status != 200) {
            const mapped = mapUpstreamError(proxy_result.status);
            final_status = mapped.status;
            final_body = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
            error_body_to_free = final_body;
        }
        defer {
            if (error_body_to_free) |eb| allocator.free(eb);
        }

        // --- Compress and send ---
        const chat_accept_encoding = request.headers.get("Accept-Encoding");
        const chat_comp = http.compression.compressResponse(allocator, final_body, JSON_CONTENT_TYPE, chat_accept_encoding, state.compression_config);
        defer if (chat_comp.body) |cb| allocator.free(cb);
        const chat_resp_body = if (chat_comp.body) |cb| cb else final_body;
        var response = http.Response.json(allocator, chat_resp_body);
        defer response.deinit();
        _ = response.setStatus(@enumFromInt(final_status))
            .setConnection(false)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        if (chat_comp.compressed) _ = response.setHeader("Content-Encoding", "gzip");
        state.security_headers.apply(&response);
        try response.write(writer);
        state.metrics.recordRequest(final_status);

        // --- Store idempotency result ---
        if (ctx.idempotency_key) |idem_key| {
            if (state.idempotency_store) |*store| {
                store.put(idem_key, final_status, final_body, JSON_CONTENT_TYPE) catch |err| {
                    std.log.warn("idempotency store error: {}", .{err});
                };
            }
        }

        logAccess(&ctx, request.method.toString(), "/v1/chat", final_status, request.headers.get("user-agent") orelse "");
        return;
    }

    try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, false, state);
    logAccess(&ctx, request.method.toString(), request.uri.path, 404, request.headers.get("user-agent") orelse "");
}

const AuthResult = struct {
    ok: bool,
    token_hash: ?[]const u8,
};

fn authorizeRequest(cfg: *const edge_config.EdgeConfig, headers: *const http.Headers) AuthResult {
    // Try bearer token auth first
    if (cfg.auth_token_hashes.len > 0) {
        if (http.auth.authorize(headers, null)) |token| {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});

            var digest_hex: [64]u8 = undefined;
            _ = std.fmt.bufPrint(&digest_hex, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch return .{ .ok = false, .token_hash = null };

            for (cfg.auth_token_hashes) |allowed| {
                if (std.mem.eql(u8, allowed, digest_hex[0..])) return .{ .ok = true, .token_hash = allowed };
            }
        } else |_| {}
    }

    // Fall back to HTTP Basic Auth
    if (cfg.basic_auth_hashes.len > 0) {
        var cred_buf: [512]u8 = undefined;
        if (http.basic_auth.fromHeaders(headers, &cred_buf)) |creds| {
            if (http.basic_auth.verifyCredentials(creds, cfg.basic_auth_hashes)) {
                return .{ .ok = true, .token_hash = null };
            }
        } else |_| {}
    }

    return .{ .ok = false, .token_hash = null };
}

fn isJsonContentType(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    var lower_buf: [128]u8 = undefined;
    const lower = if (ct.len <= lower_buf.len)
        std.ascii.lowerString(lower_buf[0..ct.len], ct)
    else
        ct;
    return std.mem.indexOf(u8, lower, JSON_CONTENT_TYPE) != null;
}

fn parseDeviceId(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    const device_val = obj.get("device_id") orelse return error.NoDeviceId;
    if (device_val != .string) return error.InvalidDeviceId;

    const device_id = std.mem.trim(u8, device_val.string, " \t\r\n");
    if (device_id.len == 0) return error.EmptyDeviceId;
    if (device_id.len > 256) return error.DeviceIdTooLong;
    return try allocator.dupe(u8, device_id);
}

fn parseChatMessage(allocator: std.mem.Allocator, body: []const u8, max_len: usize) ![]const u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    const message_val = obj.get("message") orelse return error.InvalidRequest;
    if (message_val != .string) return error.InvalidRequest;

    const message = std.mem.trim(u8, message_val.string, " \t\r\n");
    if (message.len == 0) return error.EmptyMessage;
    if (message.len > max_len) return error.MessageTooLarge;
    return try allocator.dupe(u8, message);
}

const ProxyResult = struct {
    status: u16,
    body: []u8,
};

fn proxyChat(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig, message: []const u8, correlation_id: []const u8) !ProxyResult {
    defer allocator.free(message);

    const url = try std.fmt.allocPrint(allocator, "{s}/v1/chat", .{cfg.upstream_base_url});
    defer allocator.free(url);

    const request_body = try std.fmt.allocPrint(allocator, "{{\"message\":{s}}}", .{std.json.fmt(message, .{})});
    defer allocator.free(request_body);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var body = std.ArrayList(u8).init(allocator);
    errdefer body.deinit();

    const opts = std.http.Client.FetchOptions{
        .location = .{ .url = url },
        .method = .POST,
        .payload = request_body,
        .response_storage = .{ .dynamic = &body },
        .headers = .{ .content_type = .{ .override = "application/json" } },
        .extra_headers = &[_]std.http.Header{
            .{ .name = http.correlation.HEADER_NAME, .value = correlation_id },
        },
    };

    const result = try client.fetch(opts);
    return .{
        .status = @intFromEnum(result.status),
        .body = try body.toOwnedSlice(),
    };
}

fn proxyCommand(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig, upstream_path: []const u8, envelope: []const u8, correlation_id: []const u8) !ProxyResult {
    const url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ cfg.upstream_base_url, upstream_path });
    defer allocator.free(url);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var body = std.ArrayList(u8).init(allocator);
    errdefer body.deinit();

    const opts = std.http.Client.FetchOptions{
        .location = .{ .url = url },
        .method = .POST,
        .payload = envelope,
        .response_storage = .{ .dynamic = &body },
        .headers = .{ .content_type = .{ .override = "application/json" } },
        .extra_headers = &[_]std.http.Header{
            .{ .name = http.correlation.HEADER_NAME, .value = correlation_id },
        },
    };

    const result = try client.fetch(opts);
    return .{
        .status = @intFromEnum(result.status),
        .body = try body.toOwnedSlice(),
    };
}

const UpstreamMappedError = struct {
    status: u16,
    code: []const u8,
    message: []const u8,
};

fn mapUpstreamError(status: u16) UpstreamMappedError {
    return switch (status) {
        401 => .{ .status = 401, .code = "unauthorized", .message = "Unauthorized" },
        429 => .{ .status = 429, .code = "rate_limited", .message = "Rate limited" },
        502, 503 => .{ .status = 503, .code = "tool_unavailable", .message = "Upstream unavailable" },
        504 => .{ .status = 504, .code = "upstream_timeout", .message = "Upstream timeout" },
        else => .{ .status = 500, .code = "internal_error", .message = "Internal error" },
    };
}

fn buildApiErrorJson(allocator: std.mem.Allocator, code: []const u8, message: []const u8, request_id: ?[]const u8) ![]u8 {
    if (request_id) |rid| {
        return std.fmt.allocPrint(allocator, "{{\"code\":\"{s}\",\"message\":\"{s}\",\"request_id\":\"{s}\"}}", .{ code, message, rid });
    }
    return std.fmt.allocPrint(allocator, "{{\"code\":\"{s}\",\"message\":\"{s}\",\"request_id\":null}}", .{ code, message });
}

fn sendApiError(allocator: std.mem.Allocator, writer: anytype, status: http.Status, code: []const u8, message: []const u8, request_id: ?[]const u8, keep_alive: bool, state: *GatewayState) !void {
    const payload = try buildApiErrorJson(allocator, code, message, request_id);
    defer allocator.free(payload);

    var response = http.Response.json(allocator, payload);
    defer response.deinit();
    _ = response.setStatus(status).setConnection(keep_alive);
    if (request_id) |rid| {
        _ = response.setHeader(http.correlation.HEADER_NAME, rid);
    }
    state.security_headers.apply(&response);
    try response.write(writer);
    state.metrics.recordRequest(@intFromEnum(status));
}

/// Emit a structured JSON access log entry for a completed request.
///
/// Supplements the existing audit log with a dedicated "type":"access" JSON line
/// that is easy to parse by log shippers (Loki, Fluentd, etc.).
fn logAccess(ctx: *const http.request_context.RequestContext, method: []const u8, path: []const u8, status: u16, user_agent: []const u8) void {
    const entry = http.access_log.AccessLogEntry{
        .method = method,
        .path = path,
        .status = status,
        .latency_ms = ctx.elapsedMs(),
        .client_ip = ctx.client_ip,
        .correlation_id = ctx.request_id,
        .identity = ctx.identity orelse "-",
        .user_agent = user_agent,
        .bytes_sent = 0,
    };
    entry.log();
}

fn readHttpRequest(stream: std.net.Stream, buf: []u8) !usize {
    var total_read: usize = 0;
    var header_end: ?usize = null;

    while (total_read < buf.len) {
        const n = try stream.read(buf[total_read..]);
        if (n == 0) break;
        total_read += n;

        if (header_end == null) {
            if (std.mem.indexOf(u8, buf[0..total_read], "\r\n\r\n")) |pos| {
                header_end = pos + 4;
            }
        }

        if (header_end) |headers_len| {
            const content_length = parseContentLength(buf[0..headers_len]) orelse 0;
            if (total_read >= headers_len + content_length) break;
        }
    }

    return total_read;
}

fn parseContentLength(headers: []const u8) ?usize {
    var it = std.mem.tokenizeAny(u8, headers, "\r\n");
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "content-length")) continue;

        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        return std.fmt.parseInt(usize, value, 10) catch null;
    }
    return null;
}

test "authorizeRequest accepts valid hash" {
    const allocator = std.testing.allocator;
    const token = "secret-token";

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});
    const hash = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&digest)});
    defer allocator.free(hash);

    const hashes = try allocator.alloc([]const u8, 1);
    defer allocator.free(hashes);
    hashes[0] = hash;

    var cfg = edge_config.EdgeConfig{
        .listen_host = "0.0.0.0",
        .listen_port = 8069,
        .tls_cert_path = "",
        .tls_key_path = "",
        .upstream_base_url = "http://127.0.0.1:8080",
        .auth_token_hashes = hashes,
        .max_message_chars = 4000,
        .upstream_timeout_ms = 10000,
        .rate_limit_rps = 0,
        .rate_limit_burst = 0,
        .security_headers_enabled = false,
        .idempotency_ttl_seconds = 0,
        .session_ttl_seconds = 0,
        .session_max = 0,
        .access_control_rules = "",
        .request_limits = http.request_limits.RequestLimits.default,
        .basic_auth_hashes = &[_][]const u8{},
        .log_level = .info,
        .compression_enabled = false,
        .compression_min_size = 256,
        .cb_threshold = 0,
        .cb_timeout_ms = 30_000,
    };

    var headers = http.Headers.init(allocator);
    defer headers.deinit();
    try headers.append("Authorization", "Bearer secret-token");

    try std.testing.expect(authorizeRequest(&cfg, &headers).ok);
}

test "parseChatMessage validates payload" {
    const allocator = std.testing.allocator;
    const message = try parseChatMessage(allocator, "{\"message\":\"hello\"}", 10);
    defer allocator.free(message);
    try std.testing.expectEqualStrings("hello", message);

    try std.testing.expectError(error.MessageTooLarge, parseChatMessage(allocator, "{\"message\":\"hello\"}", 2));
}

test "mapUpstreamError returns stable codes" {
    const mapped = mapUpstreamError(502);
    try std.testing.expectEqual(@as(u16, 503), mapped.status);
    try std.testing.expectEqualStrings("tool_unavailable", mapped.code);
}
