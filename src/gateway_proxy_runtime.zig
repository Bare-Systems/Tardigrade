//! HTTP proxy runtime glue for the edge gateway. This module owns route-to-
//! upstream target resolution, retry budgeting, sticky affinity, and writing
//! proxied upstream responses back to clients. This is the data-plane home for
//! general `proxy_pass` traffic; control-plane JSON helpers live in
//! `gateway_control_plane_proxy.zig`.

const compat = @import("zig_compat.zig");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gp = @import("gateway_proxy.zig");
const gcp = @import("gateway_control_plane_proxy.zig");
const gs = @import("gateway_state.zig");

const GatewayState = gs.GatewayState;
const BufferedUpstreamResponse = gp.BufferedUpstreamResponse;
const UpstreamScope = gs.UpstreamScope;
const StickyUpstreamSelection = gs.StickyUpstreamSelection;
const upstreamPoolForScope = gs.upstreamPoolForScope;
const upstreamScopeName = gs.upstreamScopeName;
const proxyScopeForPath = gs.proxyScopeForPath;
const prepareStickyAffinityRequest = gs.prepareStickyAffinityRequest;
const buildStickySetCookieHeader = gs.buildStickySetCookieHeader;
const isAbsoluteHttpUrl = gs.isAbsoluteHttpUrl;
const executeBoundedControlPlaneJsonProxy = gcp.executeBoundedControlPlaneJsonProxy;
const resolveProxyTarget = gp.resolveProxyTarget;
const appendProxyQueryString = gp.appendProxyQueryString;
const executeBoundedBufferedHttpProxyRequest = gp.executeBoundedBufferedHttpProxyRequest;
const executeStreamingHttpProxyRequest = gp.executeStreamingHttpProxyRequest;
const mapControlPlaneProxyExecutionError = gp.mapControlPlaneProxyExecutionError;
const sendApiError = gp.sendApiError;
const setRequestIdHeaders = gp.setRequestIdHeaders;
const applyResponseHeaders = gp.applyResponseHeaders;
const writeBufferedUpstreamResponse = gp.writeBufferedUpstreamResponse;

pub const StreamingRequestBody = gp.StreamingRequestBody;

pub const DataPlaneProxyResponse = union(enum) {
    bounded_buffered: BufferedUpstreamResponse,

    pub fn deinit(self: *DataPlaneProxyResponse, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .bounded_buffered => |*response| response.deinit(allocator),
        }
        self.* = undefined;
    }

    pub fn statusCode(self: *const DataPlaneProxyResponse) u16 {
        return switch (self.*) {
            .bounded_buffered => |*response| response.status_code,
        };
    }

    pub fn bodyLen(self: *const DataPlaneProxyResponse) usize {
        return switch (self.*) {
            .bounded_buffered => |*response| response.body.len,
        };
    }

    pub fn transcriptBody(self: *const DataPlaneProxyResponse) []const u8 {
        return switch (self.*) {
            .bounded_buffered => |*response| response.body,
        };
    }

    pub fn contentTypeOr(self: *const DataPlaneProxyResponse, fallback: []const u8) []const u8 {
        return switch (self.*) {
            .bounded_buffered => |*response| response.headerValue("content-type") orelse fallback,
        };
    }

    pub fn boundedBufferedForCompatibility(self: *const DataPlaneProxyResponse) *const BufferedUpstreamResponse {
        return switch (self.*) {
            .bounded_buffered => |*response| response,
        };
    }

    pub fn writeHttp1(
        self: *const DataPlaneProxyResponse,
        writer: anytype,
        keep_alive: bool,
        correlation_id: []const u8,
        security: *const http.security_headers.SecurityHeaders,
        sticky_set_cookie: ?[]const u8,
    ) !void {
        switch (self.*) {
            .bounded_buffered => |*response| {
                try writeBufferedUpstreamResponse(writer, response, keep_alive, correlation_id, security, sticky_set_cookie);
            },
        }
    }
};

/// The current data-plane HTTP/1 executor is a bounded-buffer compatibility
/// path. It centralizes the call to the buffered transport helpers so #139 and
/// #140 can replace this function with streaming/backpressure behavior without
/// routing data-plane traffic through control-plane helper code.
pub fn executeBufferedDataPlaneProxyRequest(
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
    response_timeout_ms: u32,
    cancel_token: ?*const http.cancellation.CancellationToken,
    pool: ?*http.upstream_pool.UpstreamPool,
) !DataPlaneProxyResponse {
    // HTTPS (plain and mTLS) and Unix/TCP HTTP are all dispatched inside
    // executeBoundedBufferedHttpProxyRequest, which now owns transport
    // selection, per-phase timeout enforcement (issue #196), and keep-alive
    // pooling for plain HTTP (issue #141).
    return .{ .bounded_buffered = try executeBoundedBufferedHttpProxyRequest(
        allocator,
        cfg,
        url,
        unix_socket_path,
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
        attempt_timeout_ms,
        connect_timeout_ms,
        response_timeout_ms,
        cancel_token,
        pool,
    ) };
}

fn canStreamDataPlaneProxyRequest(
    cfg: *const edge_config.EdgeConfig,
    resolved: *const gp.ResolvedProxyTarget,
    url: []const u8,
    max_attempts: usize,
) bool {
    if (!cfg.proxy_streaming_mode.responseStreamingEnabled()) return false;
    if (max_attempts != 1) return false;
    if (resolved.unix_socket_path != null) return false;
    if (cfg.upstream_tls_client_cert.len > 0 and std.mem.startsWith(u8, url, "https://")) return false;
    return true;
}

pub fn dataPlaneBufferedCompatibilityResponseLimit(cfg: *const edge_config.EdgeConfig) usize {
    return gs.maxBufferedUpstreamResponseBytes(cfg);
}

pub fn proxySuffixPathForLocation(
    request_path: []const u8,
    matched: http.location_router.MatchResult,
    blocks: []const edge_config.EdgeConfig.LocationBlock,
) ?[]const u8 {
    if (mountStripPrefixForLocation(request_path, matched, blocks)) |strip_prefix| {
        if (std.mem.startsWith(u8, request_path, strip_prefix)) {
            const suffix = request_path[strip_prefix.len..];
            return if (suffix.len == 0) null else suffix;
        }
    }
    return matchedLocationSuffixPath(request_path, matched);
}

fn matchedLocationSuffixPath(
    request_path: []const u8,
    matched: http.location_router.MatchResult,
) ?[]const u8 {
    return switch (matched.block.match_type) {
        .exact => null,
        .prefix, .prefix_priority => blk: {
            if (std.mem.startsWith(u8, request_path, matched.block.pattern)) {
                const suffix = request_path[matched.block.pattern.len..];
                break :blk if (suffix.len == 0) null else suffix;
            }
            break :blk request_path;
        },
        .regex, .regex_case_insensitive => request_path,
    };
}

fn mountStripPrefixForLocation(
    request_path: []const u8,
    matched: http.location_router.MatchResult,
    blocks: []const edge_config.EdgeConfig.LocationBlock,
) ?[]const u8 {
    var best_pattern: ?[]const u8 = null;
    var best_priority: usize = std.math.maxInt(usize);

    for (blocks) |*candidate| {
        switch (candidate.match_type) {
            .prefix, .prefix_priority => {},
            else => continue,
        }
        if (candidate.pattern.len <= 1) continue;
        if (!std.mem.startsWith(u8, request_path, candidate.pattern)) continue;
        switch (candidate.action) {
            .proxy_pass => {},
            else => continue,
        }

        const should_consider = switch (matched.block.match_type) {
            .exact, .regex, .regex_case_insensitive => true,
            .prefix, .prefix_priority => blk: {
                if (candidate.pattern.len >= matched.block.pattern.len) break :blk false;
                break :blk proxyPassTargetsDiffer(matched.block, candidate);
            },
        };
        if (!should_consider) continue;

        if (best_pattern == null or
            candidate.pattern.len < best_pattern.?.len or
            (candidate.pattern.len == best_pattern.?.len and candidate.priority < best_priority))
        {
            best_pattern = candidate.pattern;
            best_priority = candidate.priority;
        }
    }

    return best_pattern;
}

fn proxyPassTargetsDiffer(
    matched_block: *const edge_config.EdgeConfig.LocationBlock,
    candidate_block: *const edge_config.EdgeConfig.LocationBlock,
) bool {
    const matched_target = switch (matched_block.action) {
        .proxy_pass => |target| std.mem.trim(u8, target, " \t\r\n"),
        else => return false,
    };
    const candidate_target = switch (candidate_block.action) {
        .proxy_pass => |target| std.mem.trim(u8, target, " \t\r\n"),
        else => return false,
    };
    return !std.mem.eql(u8, matched_target, candidate_target);
}

fn proxyRetryAttemptLimit(configured_attempts: u32, idempotent_only: bool, method: []const u8) usize {
    const attempts: usize = @intCast(@max(configured_attempts, @as(u32, 1)));
    if (attempts <= 1) return 1;
    if (idempotent_only and !isHttpMethodIdempotent(method)) return 1;
    return attempts;
}

pub fn handleVersionedApiProxyRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
    client_ip: []const u8,
) !?u16 {
    const versioned = http.api_router.parseVersionedPath(request.uri.path) orelse return null;
    const incoming_host = request.headers.get("host");
    const incoming_x_forwarded_for = request.headers.get("x-forwarded-for");
    const body = request.body orelse "";

    if (std.mem.eql(u8, versioned.path, "/chat") and cfg.proxy_pass_chat.len > 0) {
        return try executeVersionedApiProxyRoute(
            allocator,
            writer,
            cfg,
            state,
            ctx,
            &request.headers,
            .chat,
            cfg.proxy_pass_chat,
            null,
            body,
            correlation_id,
            keep_alive,
            client_ip,
            versioned.version,
            incoming_host,
            incoming_x_forwarded_for,
        );
    }

    if (std.mem.eql(u8, versioned.path, "/commands") and cfg.proxy_pass_commands_prefix.len > 0) {
        return try executeVersionedApiProxyRoute(
            allocator,
            writer,
            cfg,
            state,
            ctx,
            &request.headers,
            .commands,
            cfg.proxy_pass_commands_prefix,
            null,
            body,
            correlation_id,
            keep_alive,
            client_ip,
            versioned.version,
            incoming_host,
            incoming_x_forwarded_for,
        );
    }

    return null;
}

fn executeVersionedApiProxyRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request_headers: *const http.Headers,
    upstream_scope: UpstreamScope,
    proxy_pass_target: []const u8,
    suffix_path: ?[]const u8,
    payload: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    client_ip: []const u8,
    api_version: u16,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
) !u16 {
    const upstream_pool = upstreamPoolForScope(cfg, upstream_scope);
    const location_id = switch (upstream_scope) {
        .chat => "versioned:/chat",
        .commands => "versioned:/commands",
        .global => "versioned:/",
    };
    var sticky_affinity = try prepareStickyAffinityRequest(
        allocator,
        cfg,
        upstream_pool,
        request_headers,
        incoming_host,
        location_id,
        proxy_pass_target,
    );
    defer if (sticky_affinity) |*value| value.deinit(allocator);

    const exec = executeBoundedControlPlaneJsonProxy(
        allocator,
        cfg,
        upstream_scope,
        proxy_pass_target,
        suffix_path,
        payload,
        correlation_id,
        client_ip,
        ctx.identity,
        ctx.user_id,
        ctx.device_id,
        ctx.scopes,
        api_version,
        incoming_host,
        incoming_x_forwarded_for,
        writer,
        state,
        false,
        if (sticky_affinity) |*value| value else null,
    ) catch |err| {
        const mapped = mapControlPlaneProxyExecutionError(err);
        try sendApiError(allocator, writer, mapped.status, mapped.code, mapped.message, correlation_id, keep_alive, state);
        return @intFromEnum(mapped.status);
    };

    switch (exec) {
        .streamed_status => |streamed| {
            ctx.setUpstreamResult(streamed.upstream_addr, streamed.status, 0);
            return streamed.status;
        },
        .buffered => |resp| {
            defer allocator.free(resp.body);
            defer allocator.free(resp.content_type);
            if (resp.content_disposition) |cd| allocator.free(cd);
            if (resp.location) |location| allocator.free(location);
            if (resp.set_cookie) |cookie| allocator.free(cookie);

            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(@enumFromInt(resp.status))
                .setBody(resp.body)
                .setContentType(resp.content_type)
                .setConnection(keep_alive);
            setRequestIdHeaders(&response, correlation_id);
            if (resp.content_disposition) |cd| {
                _ = response.setHeader("Content-Disposition", cd);
            }
            if (resp.location) |location| {
                _ = response.setHeader("Location", location);
            }
            if (resp.set_cookie) |cookie| {
                _ = response.setHeader("Set-Cookie", cookie);
            }
            applyResponseHeaders(state, &response);
            try response.write(writer);
            ctx.setUpstreamResult(resp.upstream_addr, resp.status, resp.body.len);
            state.metricsRecord(resp.status);
            return resp.status;
        },
    }
}

pub fn handleLocationProxyPass(
    allocator: std.mem.Allocator,
    downstream_conn: anytype,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    target: []const u8,
    suffix_path: ?[]const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    client_ip: []const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    incoming_host: ?[]const u8,
    location_id: []const u8,
    streaming_request_body: ?StreamingRequestBody,
) !u16 {
    const upstream_scope = .global;
    const upstream_pool = upstreamPoolForScope(cfg, upstream_scope);
    var proxy_temp_arena = std.heap.ArenaAllocator.init(allocator);
    defer proxy_temp_arena.deinit();
    const temp_allocator = proxy_temp_arena.allocator();

    var sticky_affinity = try prepareStickyAffinityRequest(
        temp_allocator,
        cfg,
        upstream_pool,
        &request.headers,
        incoming_host,
        location_id,
        target,
    );

    const upstream_hash_key = if (suffix_path) |suffix| suffix else target;
    const selection: StickyUpstreamSelection = if (sticky_affinity) |*value|
        state.nextStickyUpstreamBaseUrl(cfg, upstream_pool, client_ip, upstream_hash_key, value.requested_upstream)
    else
        .{ .base_url = state.nextUpstreamBaseUrl(cfg, upstream_pool, client_ip, upstream_hash_key), .used_requested = false };
    const selected_base_url = if (isAbsoluteHttpUrl(std.mem.trim(u8, target, " \t\r\n")))
        cfg.upstream_base_url
    else
        selection.base_url;

    const resolved = try resolveProxyTarget(temp_allocator, selected_base_url, target, suffix_path);
    const body = request.body orelse "";
    const upstream_url = try appendProxyQueryString(temp_allocator, resolved.url, request.uri.query);
    const sticky_set_cookie = if (sticky_affinity) |*value|
        try buildStickySetCookieHeader(temp_allocator, cfg, value, selection.base_url)
    else
        null;
    const forwarded_proto = if (edge_config.hasTlsFiles(cfg)) "https" else "http";
    const method_str = request.method.toString();

    // Determine retry budget. Non-idempotent methods are not retried when the
    // idempotent-only guard is enabled (default on).
    const max_attempts = proxyRetryAttemptLimit(cfg.upstream_retry_attempts, cfg.upstream_retry_idempotent_only, method_str);
    const budget_start_ms = http.event_loop.monotonicMs();

    if (canStreamDataPlaneProxyRequest(cfg, &resolved, upstream_url.value, max_attempts)) {
        state.recordUpstreamAttemptStart(selection.base_url);
        const streamed = executeStreamingHttpProxyRequest(
            allocator,
            &state.upstream_client,
            cfg,
            upstream_url.value,
            method_str,
            &request.headers,
            body,
            streaming_request_body,
            downstream_conn,
            writer,
            correlation_id,
            client_ip,
            forwarded_proto,
            request.headers.get("host"),
            auth_identity,
            auth_user_id,
            auth_device_id,
            auth_scopes,
            &state.security_headers,
            sticky_set_cookie,
            if (ctx.lifecycle) |lc| &lc.token else null,
        ) catch |err| {
            state.recordUpstreamAttemptEnd(selection.base_url);
            if (err == error.ClientAborted) {
                state.metricsRecordProxyClientAbort();
                return err;
            }
            state.recordUpstreamFailure(cfg, selection.base_url);
            if (err == error.RequestCancelled) {
                if (ctx.lifecycle) |lc| lc.logTimeout("upstream_connect");
                try sendApiError(allocator, writer, .gateway_timeout, "upstream_timeout", "Upstream request timed out", correlation_id, false, state);
                ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.gateway_timeout), 0);
                return @intFromEnum(http.Status.gateway_timeout);
            }
            if (err == error.OutOfMemory) return error.OutOfMemory;
            const err_status: http.Status = switch (err) {
                error.Timeout, error.WouldBlock => .gateway_timeout,
                else => .bad_gateway,
            };
            const err_code = if (err_status == .gateway_timeout) "upstream_timeout" else "upstream_error";
            const err_msg = if (err_status == .gateway_timeout) "Upstream request timed out" else "Upstream connection failed";
            state.logger.warn(correlation_id, "streaming upstream request failed: {}", .{err});
            try sendApiError(allocator, writer, err_status, err_code, err_msg, correlation_id, false, state);
            ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(err_status), 0);
            return @intFromEnum(err_status);
        };
        state.recordUpstreamAttemptEnd(selection.base_url);

        const transcript_redactions: []const []const u8 = if (request.headers.get("authorization")) |raw_auth|
            if (http.auth.parseBearerToken(raw_auth)) |token| &.{token} else &.{}
        else
            &.{};
        state.appendTranscript(
            upstreamScopeName(proxyScopeForPath(request.uri.path)),
            request.uri.path,
            correlation_id,
            auth_identity,
            client_ip,
            upstream_url.value,
            if (streaming_request_body == null) body else "",
            streamed.status_code,
            "application/octet-stream",
            "",
            transcript_redactions,
        );
        if (!isAbsoluteHttpUrl(std.mem.trim(u8, target, " \t\r\n"))) {
            if (streamed.status_code >= 500 or streamed.upstream_aborted) {
                state.recordUpstreamFailure(cfg, selection.base_url);
            } else {
                state.recordUpstreamSuccess(cfg, selection.base_url);
            }
        }
        if (streamed.upstream_aborted) state.metricsRecordProxyUpstreamAbort();
        state.metricsRecordProxyStreamingRequest(streamed.upstream_ttfb_ms);
        ctx.setUpstreamResult(resolved.upstream_host, streamed.status_code, streamed.response_body_bytes);
        state.metricsRecord(streamed.status_code);
        return streamed.status_code;
    }

    if (streaming_request_body != null) {
        state.logger.warn(correlation_id, "streaming upload could not use streaming proxy path after routing", .{});
        try sendApiError(allocator, writer, .bad_gateway, "upstream_error", "Streaming upload could not be proxied", correlation_id, false, state);
        ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.bad_gateway), 0);
        return @intFromEnum(http.Status.bad_gateway);
    }

    // Extra retry budget reserved for stale pooled keep-alive connections (see
    // shouldRetryStaleUpstreamConnection). When an upstream closes an idle pooled
    // connection between selection and use, the response read returns zero bytes
    // (error.HttpConnectionClosing) and the request was never delivered, so it is
    // always safe to retry on a fresh connection. This budget is independent of
    // the operator-configured attempt count so the race is skipped transparently
    // even with the default of a single attempt.
    const max_stale_conn_retries: usize = 2;
    var stale_conn_retries: usize = 0;

    var attempt: usize = 0;
    var upstream_response: DataPlaneProxyResponse = while (attempt < max_attempts + stale_conn_retries) : (attempt += 1) {
        const per_attempt_timeout_ms: u32 = blk: {
            if (cfg.upstream_timeout_budget_ms == 0) break :blk cfg.upstream_timeout_ms;
            const elapsed_ms = http.event_loop.monotonicMs() - budget_start_ms;
            if (elapsed_ms >= cfg.upstream_timeout_budget_ms) return error.Timeout;
            const remaining = cfg.upstream_timeout_budget_ms - elapsed_ms;
            if (cfg.upstream_timeout_ms == 0) {
                break :blk @intCast(@min(remaining, @as(u64, std.math.maxInt(u32))));
            }
            break :blk @intCast(@min(@as(u64, cfg.upstream_timeout_ms), remaining));
        };
        state.recordUpstreamAttemptStart(selection.base_url);
        const upstream_start_ms = http.event_loop.monotonicMs();
        const resp = executeBufferedDataPlaneProxyRequest(
            allocator,
            cfg,
            upstream_url.value,
            resolved.unix_socket_path,
            method_str,
            &request.headers,
            body,
            correlation_id,
            client_ip,
            forwarded_proto,
            request.headers.get("host"),
            auth_identity,
            auth_user_id,
            auth_device_id,
            auth_scopes,
            per_attempt_timeout_ms,
            cfg.upstream_connect_timeout_ms,
            cfg.upstream_response_timeout_ms,
            if (ctx.lifecycle) |lc| &lc.token else null,
            &state.upstream_pool,
        );
        state.recordUpstreamAttemptEnd(selection.base_url);
        const result = resp catch |err| {
            // A pooled keep-alive connection the upstream closed before handling
            // our request surfaces as HttpConnectionClosing (zero response bytes
            // received). The request was never delivered, so this is a normal
            // keep-alive lifecycle event rather than an upstream health failure:
            // retry it on a fresh connection without counting it against upstream
            // health / circuit-breaker state. Non-idempotent methods are only
            // retried this way when the operator has disabled the idempotent-only
            // guard.
            if (shouldRetryStaleUpstreamConnection(
                err,
                method_str,
                stale_conn_retries,
                max_stale_conn_retries,
                cfg.upstream_retry_idempotent_only,
            )) {
                stale_conn_retries += 1;
                state.logger.warn(correlation_id, "proxy retrying on fresh connection after stale upstream keep-alive ({d}/{d})", .{ stale_conn_retries, max_stale_conn_retries });
                continue;
            }
            state.recordUpstreamFailure(cfg, selection.base_url);
            // If the request deadline elapsed, stop retrying immediately.
            if (err == error.RequestCancelled) {
                if (ctx.lifecycle) |lc| lc.logTimeout("upstream_connect");
                try sendApiError(allocator, writer, .gateway_timeout, "upstream_timeout", "Upstream request timed out", correlation_id, keep_alive, state);
                ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.gateway_timeout), 0);
                return @intFromEnum(http.Status.gateway_timeout);
            }
            if (attempt + 1 < max_attempts) {
                state.logger.warn(correlation_id, "proxy attempt {d}/{d} failed: {}", .{ attempt + 1, max_attempts, err });
                continue;
            }
            // All retry attempts are exhausted — synthesise a proper error
            // response so the client receives a complete HTTP message instead
            // of an abrupt TCP close (fixes #94).
            if (err == error.OutOfMemory) return error.OutOfMemory;
            const err_status: http.Status = switch (err) {
                error.Timeout, error.TimedOut, error.WouldBlock => .gateway_timeout,
                else => .bad_gateway,
            };
            const err_code = if (err_status == .gateway_timeout) "upstream_timeout" else "upstream_error";
            const err_msg = if (err_status == .gateway_timeout) "Upstream request timed out" else "Upstream connection failed";
            state.logger.warn(correlation_id, "upstream request failed after {d} attempt(s): {}", .{ attempt + 1, err });
            try sendApiError(allocator, writer, err_status, err_code, err_msg, correlation_id, keep_alive, state);
            ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(err_status), 0);
            return @intFromEnum(err_status);
        };
        const upstream_ttfb_ms = http.event_loop.monotonicMs() - upstream_start_ms;
        state.metricsRecordProxyBufferedRequest(result.bodyLen(), upstream_ttfb_ms);
        // Retry on 5xx only when attempts remain and the method allows it.
        if (result.statusCode() >= 500 and attempt + 1 < max_attempts) {
            state.recordUpstreamFailure(cfg, selection.base_url);
            state.logger.warn(correlation_id, "proxy attempt {d}/{d} got {d}, retrying", .{ attempt + 1, max_attempts, result.statusCode() });
            var r = result;
            state.metricsReleaseProxyBufferedBytes(r.bodyLen());
            r.deinit(allocator);
            continue;
        }
        break result;
    } else {
        // The retry loop ended because max_attempts was 0 or all budget was
        // consumed before even issuing a request.  Synthesise a 502 rather
        // than propagating the bare UpstreamUnavailable error (fixes #94).
        state.logger.warn(correlation_id, "no upstream attempts remaining for {s}", .{resolved.upstream_host});
        try sendApiError(allocator, writer, .bad_gateway, "upstream_unavailable", "No upstream available", correlation_id, keep_alive, state);
        ctx.setUpstreamResult(resolved.upstream_host, 502, 0);
        state.metricsRecord(502);
        return 502;
    };
    defer upstream_response.deinit(allocator);
    defer state.metricsReleaseProxyBufferedBytes(upstream_response.bodyLen());

    const transcript_redactions: []const []const u8 = if (request.headers.get("authorization")) |raw_auth|
        if (http.auth.parseBearerToken(raw_auth)) |token| &.{token} else &.{}
    else
        &.{};
    state.appendTranscript(
        upstreamScopeName(proxyScopeForPath(request.uri.path)),
        request.uri.path,
        correlation_id,
        auth_identity,
        client_ip,
        upstream_url.value,
        body,
        upstream_response.statusCode(),
        upstream_response.contentTypeOr("application/octet-stream"),
        upstream_response.transcriptBody(),
        transcript_redactions,
    );
    if (!isAbsoluteHttpUrl(std.mem.trim(u8, target, " \t\r\n"))) {
        if (upstream_response.statusCode() >= 500) {
            state.recordUpstreamFailure(cfg, selection.base_url);
        } else {
            state.recordUpstreamSuccess(cfg, selection.base_url);
        }
    }
    ctx.setUpstreamResult(resolved.upstream_host, upstream_response.statusCode(), upstream_response.bodyLen());
    try upstream_response.writeHttp1(writer, keep_alive, correlation_id, &state.security_headers, sticky_set_cookie);
    const status_code = upstream_response.statusCode();
    state.metricsRecord(status_code);
    return status_code;
}

/// Returns true for HTTP methods that are safe to retry on failure without
/// risk of double-applying a non-idempotent side effect (RFC 9110 §9.2).
/// GET, HEAD, PUT, DELETE, OPTIONS, and TRACE are idempotent.
/// POST and PATCH are not and must not be retried unless the operator
/// explicitly disables the idempotent-only guard.
pub fn isHttpMethodIdempotent(method: []const u8) bool {
    const upper = std.ascii.upperString;
    var buf: [16]u8 = undefined;
    if (method.len > buf.len) return false;
    const m = upper(buf[0..method.len], method);
    return std.mem.eql(u8, m, "GET") or
        std.mem.eql(u8, m, "HEAD") or
        std.mem.eql(u8, m, "PUT") or
        std.mem.eql(u8, m, "DELETE") or
        std.mem.eql(u8, m, "OPTIONS") or
        std.mem.eql(u8, m, "TRACE");
}

/// Decide whether a failed proxy attempt should be retried on a fresh upstream
/// connection because the error indicates the request was never delivered.
///
/// `error.HttpConnectionClosing` is raised when a pooled keep-alive connection
/// returns zero response bytes — i.e. the upstream closed an idle connection
/// before serving our request. Because nothing reached the upstream, retrying
/// cannot double-apply a side effect, so it is safe for idempotent methods and
/// for any method when the operator has disabled the idempotent-only guard.
/// The retry is bounded by `max_stale_conn_retries` so a persistently dead
/// upstream still fails fast.
fn shouldRetryStaleUpstreamConnection(
    err: anyerror,
    method: []const u8,
    stale_conn_retries: usize,
    max_stale_conn_retries: usize,
    idempotent_only: bool,
) bool {
    if (err != error.HttpConnectionClosing) return false;
    if (stale_conn_retries >= max_stale_conn_retries) return false;
    return isHttpMethodIdempotent(method) or !idempotent_only;
}

test "shouldRetryStaleUpstreamConnection retries idempotent methods on closed keep-alive" {
    try std.testing.expect(shouldRetryStaleUpstreamConnection(error.HttpConnectionClosing, "GET", 0, 2, true));
    try std.testing.expect(shouldRetryStaleUpstreamConnection(error.HttpConnectionClosing, "GET", 1, 2, true));
}

test "shouldRetryStaleUpstreamConnection respects the retry budget" {
    try std.testing.expect(!shouldRetryStaleUpstreamConnection(error.HttpConnectionClosing, "GET", 2, 2, true));
    try std.testing.expect(!shouldRetryStaleUpstreamConnection(error.HttpConnectionClosing, "GET", 3, 2, true));
}

test "shouldRetryStaleUpstreamConnection guards POST by idempotent-only setting" {
    try std.testing.expect(!shouldRetryStaleUpstreamConnection(error.HttpConnectionClosing, "POST", 0, 2, true));
    try std.testing.expect(shouldRetryStaleUpstreamConnection(error.HttpConnectionClosing, "POST", 0, 2, false));
}

test "shouldRetryStaleUpstreamConnection only triggers for pre-delivery closes" {
    try std.testing.expect(!shouldRetryStaleUpstreamConnection(error.ReadFailed, "GET", 0, 2, true));
    try std.testing.expect(!shouldRetryStaleUpstreamConnection(error.ConnectionResetByPeer, "GET", 0, 2, true));
    try std.testing.expect(!shouldRetryStaleUpstreamConnection(error.Timeout, "GET", 0, 2, true));
}

test "data-plane buffered compatibility response limit uses dedicated upstream cap" {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.max_buffered_upstream_response_bytes = 0;
    try std.testing.expectEqual(
        @as(usize, gs.MAX_REQUEST_SIZE),
        dataPlaneBufferedCompatibilityResponseLimit(&cfg),
    );

    cfg.max_buffered_upstream_response_bytes = 768 * 1024;
    try std.testing.expectEqual(@as(usize, 768 * 1024), dataPlaneBufferedCompatibilityResponseLimit(&cfg));
}

test "proxySuffixPathForLocation uses mount prefix for split upstream exact route" {
    const blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/ursa/health",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:18443" },
        },
        .{
            .match_type = .prefix,
            .pattern = "/ursa/",
            .priority = 1,
            .action = .{ .proxy_pass = "http://127.0.0.1:6707" },
        },
    };

    const matched = http.location_router.matchLocation("/ursa/health", &blocks).?;
    const suffix = proxySuffixPathForLocation("/ursa/health", matched, &blocks).?;
    try std.testing.expectEqualStrings("health", suffix);
}

test "proxySuffixPathForLocation keeps mount prefix for split upstream longer prefix route" {
    const blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .prefix_priority,
            .pattern = "/ursa/download/",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:18443" },
        },
        .{
            .match_type = .prefix,
            .pattern = "/ursa/",
            .priority = 1,
            .action = .{ .proxy_pass = "http://127.0.0.1:6707" },
        },
    };

    const matched = http.location_router.matchLocation("/ursa/download/file.bin", &blocks).?;
    const suffix = proxySuffixPathForLocation("/ursa/download/file.bin", matched, &blocks).?;
    try std.testing.expectEqualStrings("download/file.bin", suffix);
}

test "isHttpMethodIdempotent classifies idempotent methods" {
    try std.testing.expect(isHttpMethodIdempotent("GET"));
    try std.testing.expect(isHttpMethodIdempotent("HEAD"));
    try std.testing.expect(isHttpMethodIdempotent("PUT"));
    try std.testing.expect(isHttpMethodIdempotent("DELETE"));
    try std.testing.expect(isHttpMethodIdempotent("OPTIONS"));
    try std.testing.expect(isHttpMethodIdempotent("TRACE"));
    try std.testing.expect(isHttpMethodIdempotent("get"));
    try std.testing.expect(isHttpMethodIdempotent("Get"));
    try std.testing.expect(isHttpMethodIdempotent("delete"));
}

test "isHttpMethodIdempotent rejects non-idempotent methods" {
    try std.testing.expect(!isHttpMethodIdempotent("POST"));
    try std.testing.expect(!isHttpMethodIdempotent("PATCH"));
    try std.testing.expect(!isHttpMethodIdempotent("post"));
    try std.testing.expect(!isHttpMethodIdempotent(""));
    try std.testing.expect(!isHttpMethodIdempotent("VERYLONGMETHODNAME"));
}

test "upstream_retry_idempotent_only default true limits POST retries to 1" {
    try std.testing.expectEqual(@as(usize, 1), proxyRetryAttemptLimit(3, true, "POST"));
}

test "upstream_retry_idempotent_only allows GET retries" {
    try std.testing.expectEqual(@as(usize, 3), proxyRetryAttemptLimit(3, true, "GET"));
}

test "upstream_retry_idempotent_only=false allows POST retries" {
    try std.testing.expectEqual(@as(usize, 3), proxyRetryAttemptLimit(3, false, "POST"));
}

test "data-plane response wrapper exposes bounded buffered metadata" {
    const allocator = std.testing.allocator;
    const body = try allocator.dupe(u8, "payload");
    var upstream_headers = [_]gp.UpstreamHeader{
        .{ .name = "Content-Type", .value = "text/plain" },
    };

    var response = DataPlaneProxyResponse{ .bounded_buffered = .{
        .metadata_arena = std.heap.ArenaAllocator.init(allocator),
        .status_code = 202,
        .reason = "Accepted",
        .headers = upstream_headers[0..],
        .body = body,
    } };
    defer response.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 202), response.statusCode());
    try std.testing.expectEqual(@as(usize, body.len), response.bodyLen());
    try std.testing.expectEqualStrings("payload", response.transcriptBody());
    try std.testing.expectEqualStrings("text/plain", response.contentTypeOr("application/octet-stream"));
}
