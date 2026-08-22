//! HTTP proxy runtime glue for the edge gateway. This module owns route-to-
//! upstream target resolution, retry budgeting, sticky affinity, and writing
//! proxied upstream responses back to clients. This is the data-plane home for
//! general `proxy_pass` traffic; control-plane JSON helpers live in
//! `gateway_control_plane_proxy.zig`.

const compat = @import("zig_compat");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gp = @import("gateway_proxy.zig");
const gph = @import("gateway_proxy_headers.zig");
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
const writeBufferedUpstreamResponseWithMetrics = gp.writeBufferedUpstreamResponseWithMetrics;

pub const StreamingRequestBody = gp.StreamingRequestBody;

pub fn proxyAttemptErrorCountsAsUpstreamFailure(err: anyerror) bool {
    return switch (err) {
        error.OutOfMemory,
        error.ClientAborted,
        error.ProxyBufferCapacityUnavailable,
        error.RequestBufferLimitExceeded,
        error.InvalidChunkedUpload,
        error.ChunkedUploadTooLarge,
        error.UpstreamAtCapacity,
        error.ProxyBudgetExhausted,
        error.CircuitOpen,
        => false,
        else => true,
    };
}

fn recordStreamingProxyOutcome(
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    selection_base_url: []const u8,
    absolute_target: bool,
    circuit_permit: http.circuit_breaker.Permit,
    status_code: u16,
    upstream_aborted: bool,
    local_capacity_aborted: bool,
    correlation_id: []const u8,
) void {
    // Local capacity exhaustion can set `upstream_aborted` too because the
    // relay stops reading the origin after committing a response. Classify that
    // as local first so memory pressure cannot trip a healthy origin's circuit.
    if (local_capacity_aborted) {
        state.circuitReleasePermit(circuit_permit);
        state.logger.warn(correlation_id, "streaming relay truncated: local proxy buffer capacity exhausted", .{});
    } else if (status_code >= 500 or upstream_aborted) {
        if (absolute_target) {
            state.circuitRecordFailurePermit(circuit_permit);
        } else {
            state.recordProxyUpstreamFailure(cfg, selection_base_url, circuit_permit);
        }
    } else {
        if (absolute_target) {
            state.circuitRecordSuccessPermit(circuit_permit);
        } else {
            state.recordProxyUpstreamSuccess(cfg, selection_base_url, circuit_permit);
        }
    }
}

fn propagateStreamingDownstreamAbortAfterStatus(state: *GatewayState, streamed: *const gp.StreamingProxyResult) !void {
    if (!streamed.downstream_aborted_after_status) return;
    state.metricsRecordProxyClientAbort();
    return error.ClientAborted;
}

/// Why a request took the bounded buffered path instead of streaming (#139).
/// Every reason is recorded as a metric label and a debug log line so operators
/// can tell whether a given large transfer actually streamed.
///
/// The enum is owned by `http.metrics` so the counter mapping can switch over
/// it exhaustively; a reason cannot exist here without an observable counter.
pub const StreamingFallbackReason = http.metrics.ProxyStreamingFallbackReason;

const StreamingEligibility = union(enum) {
    stream,
    fallback: StreamingFallbackReason,
};

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
        alt_svc: ?[]const u8,
        sticky_set_cookie: ?[]const u8,
        metrics: *http.metrics.Metrics,
        metrics_mutex: *compat.Mutex,
    ) !void {
        switch (self.*) {
            .bounded_buffered => |*response| {
                try writeBufferedUpstreamResponseWithMetrics(writer, response, keep_alive, correlation_id, security, alt_svc, sticky_set_cookie, metrics, metrics_mutex);
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
    upstream_host_override: ?[]const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    forward_early_data: bool,
    attempt_timeout_ms: u32,
    connect_timeout_ms: u32,
    response_timeout_ms: u32,
    cancel_token: ?*const http.cancellation.CancellationToken,
    pool: ?*http.upstream_pool.UpstreamPool,
    h2_pool: ?*http.upstream_h2.H2ConnPool,
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
        upstream_host_override,
        auth_identity,
        auth_user_id,
        auth_device_id,
        auth_scopes,
        forward_early_data,
        attempt_timeout_ms,
        connect_timeout_ms,
        response_timeout_ms,
        cancel_token,
        pool,
        h2_pool,
    ) };
}

fn routeResponseStreamingEnabled(
    cfg: *const edge_config.EdgeConfig,
    block: *const edge_config.EdgeConfig.LocationBlock,
) bool {
    return block.proxy_streaming_policy.responseStreamingEnabled(cfg.proxy_streaming_mode.responseStreamingEnabled());
}

/// Unix-socket and upstream-mTLS targets are streamed like any other upstream
/// (#139): the streaming relay owns AF_UNIX connect/pooling and the same
/// `UpstreamTlsOptions` — including the client certificate — as the buffered
/// path, so neither is a reason to buffer.
fn streamingEligibilityForDataPlaneProxyRequest(
    cfg: *const edge_config.EdgeConfig,
    block: *const edge_config.EdgeConfig.LocationBlock,
    max_attempts: usize,
) StreamingEligibility {
    if (!routeResponseStreamingEnabled(cfg, block)) return .{ .fallback = .policy_disabled };
    if (max_attempts != 1) return .{ .fallback = .retries_configured };
    return .stream;
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
            return if (suffix.len == 0) "/" else suffix;
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
                break :blk if (suffix.len == 0) "/" else suffix;
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

pub fn proxyRetryAttemptLimit(configured_attempts: u32, idempotent_only: bool, method: []const u8) usize {
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
            try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
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
    matched_block: *const edge_config.EdgeConfig.LocationBlock,
    streaming_request_body: ?StreamingRequestBody,
) !u16 {
    if (ctx.early_data.replayExposed()) {
        ctx.early_data_action = .forwarded;
    }

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
    const absolute_proxy_target = isAbsoluteHttpUrl(std.mem.trim(u8, target, " \t\r\n"));

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
    const first_attempt_forward_early_data = ctx.early_data.inbound_marker or
        (ctx.early_data.transport_early and !ctx.early_data.downstreamHandshakeComplete());
    const needs_early_425_orchestration = ctx.early_data.replayExposed();

    const fallback_reason: StreamingFallbackReason = if (needs_early_425_orchestration)
        .early_data_retry_semantics
    else switch (streamingEligibilityForDataPlaneProxyRequest(cfg, matched_block, max_attempts)) {
        .stream => {
            const circuit_permit = state.circuitTryAcquirePermit() orelse {
                try sendApiError(allocator, writer, .service_unavailable, "upstream_circuit_open", "Upstream circuit breaker open", correlation_id, false, state);
                ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.service_unavailable), 0);
                return @intFromEnum(http.Status.service_unavailable);
            };
            state.recordUpstreamAttemptStart(selection.base_url);
            const proxy_buffer_observer = state.proxyBufferObserver();
            const streamed = executeStreamingHttpProxyRequest(
                allocator,
                cfg,
                upstream_url.value,
                resolved.unix_socket_path,
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
                state.http3_alt_svc,
                sticky_set_cookie,
                if (ctx.lifecycle) |lc| &lc.token else null,
                proxy_buffer_observer,
                state.proxyBufferGlobalAccount(),
                &state.upstream_pool,
                &state.h2_pool,
            ) catch |err| {
                state.recordUpstreamAttemptEnd(selection.base_url);
                if (err == error.ClientAborted) {
                    state.circuitReleasePermit(circuit_permit);
                    state.metricsRecordProxyClientAbort();
                    return err;
                }
                if (err == error.ProxyBufferCapacityUnavailable) {
                    // Local proxy buffer capacity, refused before any response
                    // byte was committed (#140). Like the active-connection cap
                    // above this is local saturation, not an origin fault, so
                    // it must not touch upstream health / circuit-breaker state.
                    state.circuitReleasePermit(circuit_permit);
                    try sendApiError(allocator, writer, .service_unavailable, "proxy_buffer_saturated", "Proxy buffer capacity exhausted", correlation_id, false, state);
                    ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.service_unavailable), 0);
                    return @intFromEnum(http.Status.service_unavailable);
                }
                if (err == error.UpstreamAtCapacity) {
                    // Fail-fast at the per-origin active cap (#239): a local
                    // saturation rejection, not an origin failure — do not count
                    // it against upstream health / circuit-breaker state.
                    state.circuitReleasePermit(circuit_permit);
                    try sendApiError(allocator, writer, .service_unavailable, "upstream_saturated", "Upstream connection limit reached", correlation_id, false, state);
                    ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.service_unavailable), 0);
                    return @intFromEnum(http.Status.service_unavailable);
                }
                // The upload's in-flight bytes outgrew the per-stream buffer
                // hard limit (#140). Unlike the aggregate refusal above this is
                // about *this* request rather than proxy-wide saturation, so it
                // is the client's 413 and not a 503 — and, being a client fault
                // raised before commitment, it is not charged to the origin.
                if (err == error.RequestBufferLimitExceeded) {
                    state.circuitReleasePermit(circuit_permit);
                    try sendApiError(allocator, writer, .payload_too_large, "payload_too_large", "Request body too large", correlation_id, false, state);
                    ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.payload_too_large), 0);
                    return @intFromEnum(http.Status.payload_too_large);
                }
                // The client's own chunked framing was bad or its upload
                // outgrew the request-body maximum (#139). Both are client
                // faults raised before any response byte is committed, so the
                // origin is not blamed for them.
                if (err == error.InvalidChunkedUpload or err == error.ChunkedUploadTooLarge) {
                    state.circuitReleasePermit(circuit_permit);
                    const upload_status: http.Status = if (err == error.ChunkedUploadTooLarge) .payload_too_large else .bad_request;
                    const upload_code = if (err == error.ChunkedUploadTooLarge) "payload_too_large" else "invalid_request";
                    const upload_msg = if (err == error.ChunkedUploadTooLarge) "Request body too large" else "Malformed chunked request body";
                    try sendApiError(allocator, writer, upload_status, upload_code, upload_msg, correlation_id, false, state);
                    ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(upload_status), 0);
                    return @intFromEnum(upload_status);
                }
                if (err == error.RequestCancelled) {
                    if (absolute_proxy_target) {
                        state.circuitRecordFailurePermit(circuit_permit);
                    } else {
                        state.recordProxyUpstreamFailure(cfg, selection.base_url, circuit_permit);
                    }
                    if (ctx.lifecycle) |lc| lc.logTimeout("upstream_connect");
                    try sendApiError(allocator, writer, .gateway_timeout, "upstream_timeout", "Upstream request timed out", correlation_id, false, state);
                    ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.gateway_timeout), 0);
                    return @intFromEnum(http.Status.gateway_timeout);
                }
                if (err == error.OutOfMemory) {
                    state.circuitReleasePermit(circuit_permit);
                    return error.OutOfMemory;
                }
                if (absolute_proxy_target) {
                    state.circuitRecordFailurePermit(circuit_permit);
                } else {
                    state.recordProxyUpstreamFailure(cfg, selection.base_url, circuit_permit);
                }
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
            recordStreamingProxyOutcome(
                state,
                cfg,
                selection.base_url,
                absolute_proxy_target,
                circuit_permit,
                streamed.status_code,
                streamed.upstream_aborted,
                streamed.local_capacity_aborted,
                correlation_id,
            );
            try propagateStreamingDownstreamAbortAfterStatus(state, &streamed);
            // `tardigrade_proxy_upstream_aborts_total` means "aborted by the
            // origin". A truncation this proxy caused by running out of buffer
            // capacity is not that, and counting it there would misattribute
            // local pressure to the origin in dashboards and alerts.
            if (streamed.local_capacity_aborted) {
                state.metricsRecordProxyLocalCapacityAbort();
            } else if (streamed.upstream_aborted) {
                state.metricsRecordProxyUpstreamAbort();
            }
            state.metricsRecordProxyStreamingRequest(streamed.upstream_ttfb_ms);
            ctx.setUpstreamResult(resolved.upstream_host, streamed.status_code, streamed.response_body_bytes);
            state.metricsRecord(streamed.status_code);
            return streamed.status_code;
        },
        .fallback => |reason| reason,
    };
    state.metricsRecordProxyStreamingFallback(fallback_reason);
    state.logger.debug(correlation_id, "proxy streaming fallback: {s}", .{fallback_reason.label()});

    if (streaming_request_body != null) {
        state.logger.warn(correlation_id, "streaming upload could not use streaming proxy path after routing: {s}", .{fallback_reason.label()});
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
    var attempt_executor = ProductionBufferedProxyAttemptExecutor{
        .allocator = allocator,
        .cfg = cfg,
        .state = state,
        .ctx = ctx,
        .request = request,
        .body = body,
        .upstream_url = upstream_url.value,
        .unix_socket_path = resolved.unix_socket_path,
        .correlation_id = correlation_id,
        .client_ip = client_ip,
        .forwarded_proto = forwarded_proto,
        .auth_identity = auth_identity,
        .auth_user_id = auth_user_id,
        .auth_device_id = auth_device_id,
        .auth_scopes = auth_scopes,
        .selection_base_url = selection.base_url,
        .absolute_target = absolute_proxy_target,
        .budget_start_ms = budget_start_ms,
    };
    var upstream_response: DataPlaneProxyResponse = switch (try runBufferedProxyAttempts(
        &ctx.early_data,
        first_attempt_forward_early_data,
        method_str,
        matched_block,
        max_attempts,
        max_stale_conn_retries,
        cfg.upstream_retry_idempotent_only,
        &attempt_executor,
    )) {
        .response => |response| response,
        .early_425_retry_parked => unreachable,
        .upstream_at_capacity => {
            // Fail-fast at the per-origin active cap (#239): a local
            // saturation rejection, not an origin failure — do not count
            // it against upstream health / circuit-breaker state, and do
            // not burn retry attempts re-hitting the cap.
            try sendApiError(allocator, writer, .service_unavailable, "upstream_saturated", "Upstream connection limit reached", correlation_id, keep_alive, state);
            ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.service_unavailable), 0);
            return @intFromEnum(http.Status.service_unavailable);
        },
        .circuit_open => {
            try sendApiError(allocator, writer, .service_unavailable, "upstream_circuit_open", "Upstream circuit breaker open", correlation_id, keep_alive, state);
            ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.service_unavailable), 0);
            return @intFromEnum(http.Status.service_unavailable);
        },
        .request_cancelled => {
            if (ctx.lifecycle) |lc| lc.logTimeout("upstream_connect");
            try sendApiError(allocator, writer, .gateway_timeout, "upstream_timeout", "Upstream request timed out", correlation_id, keep_alive, state);
            ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.gateway_timeout), 0);
            return @intFromEnum(http.Status.gateway_timeout);
        },
        .retry_budget_exhausted => return error.Timeout,
        .terminal_error => |err| {
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
            state.logger.warn(correlation_id, "upstream request failed after configured retries: {}", .{err});
            try sendApiError(allocator, writer, err_status, err_code, err_msg, correlation_id, keep_alive, state);
            ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(err_status), 0);
            return @intFromEnum(err_status);
        },
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
    if (absolute_proxy_target) {
        if (upstream_response.statusCode() >= 500) {
            attempt_executor.recordCircuitFailure();
        } else if (upstream_response.statusCode() != @intFromEnum(http.Status.too_early)) {
            attempt_executor.recordCircuitSuccess();
        } else {
            attempt_executor.releaseCircuitProbe();
        }
    } else {
        if (upstream_response.statusCode() >= 500) {
            attempt_executor.recordCircuitFailure();
        } else if (upstream_response.statusCode() != @intFromEnum(http.Status.too_early)) {
            attempt_executor.recordCircuitSuccess();
        } else {
            attempt_executor.releaseCircuitProbe();
        }
    }
    ctx.setUpstreamResult(resolved.upstream_host, upstream_response.statusCode(), upstream_response.bodyLen());
    try upstream_response.writeHttp1(writer, keep_alive, correlation_id, &state.security_headers, state.http3_alt_svc, sticky_set_cookie, &state.metrics, &state.metrics_mutex);
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
pub fn shouldRetryStaleUpstreamConnection(
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

fn shouldRetryEarlyUpstream425(
    early_ctx: http.request_context.EarlyDataContext,
    first_attempt_forwarded_early_data: bool,
    retry_used: bool,
    method: []const u8,
    matched_block: *const edge_config.EdgeConfig.LocationBlock,
) bool {
    if (!first_attempt_forwarded_early_data) return false;
    if (retry_used) return false;
    if (!early_ctx.mayRetryUpstream425()) return false;
    if (!http.early_data.methodSafe(method)) return false;
    if (matched_block.early_data != .replay_safe) return false;
    if (matched_block.proxy_early_data != .rfc8470) return false;
    return true;
}

const BufferedProxyRetryState = struct {
    early_425_retry_used: bool = false,
    early_425_retry_result_pending: bool = false,
    early_425_extra_attempts: usize = 0,
    retry_as_ordinary: bool = false,

    fn loopBound(self: BufferedProxyRetryState, max_attempts: usize, stale_conn_retries: usize) usize {
        return max_attempts + stale_conn_retries + self.early_425_extra_attempts;
    }

    fn transparentAttempts(self: BufferedProxyRetryState, stale_conn_retries: usize) usize {
        return self.early_425_extra_attempts + stale_conn_retries;
    }

    fn configuredAttemptIndex(self: BufferedProxyRetryState, attempt: usize, stale_conn_retries: usize) usize {
        const transparent = self.transparentAttempts(stale_conn_retries);
        return attempt - @min(attempt, transparent);
    }

    fn hasConfiguredRetryRemaining(self: BufferedProxyRetryState, attempt: usize, max_attempts: usize, stale_conn_retries: usize) bool {
        return self.configuredAttemptIndex(attempt, stale_conn_retries) + 1 < max_attempts;
    }

    fn forwardEarlyData(self: BufferedProxyRetryState, first_attempt_forward_early_data: bool) bool {
        return if (self.retry_as_ordinary) false else first_attempt_forward_early_data;
    }

    fn consumeEarly425Retry(self: *BufferedProxyRetryState) void {
        self.early_425_retry_used = true;
        self.early_425_retry_result_pending = true;
        self.early_425_extra_attempts = 1;
        self.retry_as_ordinary = true;
    }

    fn recordEarly425RetryResultOnce(
        self: *BufferedProxyRetryState,
        attempt_executor: anytype,
        result: http.metrics.EarlyDataRetryResult,
    ) void {
        if (!self.early_425_retry_result_pending) return;
        self.early_425_retry_result_pending = false;
        attempt_executor.recordEarlyRetryResult(result);
    }
};

pub const BufferedProxyAttemptsResult = union(enum) {
    response: DataPlaneProxyResponse,
    early_425_retry_parked,
    upstream_at_capacity,
    circuit_open,
    request_cancelled,
    retry_budget_exhausted,
    terminal_error: anyerror,
};

pub fn runBufferedProxyAttempts(
    early_ctx: *http.request_context.EarlyDataContext,
    first_attempt_forward_early_data: bool,
    method: []const u8,
    matched_block: *const edge_config.EdgeConfig.LocationBlock,
    max_attempts: usize,
    max_stale_conn_retries: usize,
    upstream_retry_idempotent_only: bool,
    attempt_executor: anytype,
) !BufferedProxyAttemptsResult {
    var stale_conn_retries: usize = 0;
    var retry_state = BufferedProxyRetryState{};

    var attempt: usize = 0;
    while (attempt < retry_state.loopBound(max_attempts, stale_conn_retries)) : (attempt += 1) {
        const resp = attempt_executor.execute(attempt, retry_state.forwardEarlyData(first_attempt_forward_early_data)) catch |err| {
            if (shouldRetryStaleUpstreamConnection(
                err,
                method,
                stale_conn_retries,
                max_stale_conn_retries,
                upstream_retry_idempotent_only,
            )) {
                stale_conn_retries += 1;
                try attempt_executor.onStaleConnectionRetry(stale_conn_retries, max_stale_conn_retries);
                continue;
            }
            retry_state.recordEarly425RetryResultOnce(attempt_executor, .failure);
            if (err == error.CircuitOpen) return .circuit_open;
            if (err == error.ProxyBudgetExhausted) {
                maybeReleaseCircuitProbe(attempt_executor);
                return .retry_budget_exhausted;
            }
            if (err == error.UpstreamAtCapacity) {
                maybeReleaseCircuitProbe(attempt_executor);
                return .upstream_at_capacity;
            }
            try attempt_executor.onTerminalAttemptError(err);
            if (err == error.RequestCancelled) return .request_cancelled;
            if (retry_state.hasConfiguredRetryRemaining(attempt, max_attempts, stale_conn_retries)) {
                try attempt_executor.onConfiguredErrorRetry(retry_state.configuredAttemptIndex(attempt, stale_conn_retries), max_attempts, err);
                continue;
            }
            return .{ .terminal_error = err };
        };

        var result = resp;
        try attempt_executor.onBufferedResponse(&result);
        if (result.statusCode() == @intFromEnum(http.Status.too_early) and shouldRetryEarlyUpstream425(
            early_ctx.*,
            first_attempt_forward_early_data,
            retry_state.early_425_retry_used,
            method,
            matched_block,
        )) {
            if (!early_ctx.downstreamHandshakeComplete()) {
                if (maybeParkEarly425Retry(attempt_executor, &result)) |parked| {
                    if (parked) return .early_425_retry_parked;
                } else |err| {
                    attempt_executor.recordEarlyRetryResult(.failure);
                    attempt_executor.recordEarlyUpstream425Action(.forwarded);
                    try attempt_executor.onEarly425HandshakeFailure(err);
                    return .{ .response = result };
                }
            }
            early_ctx.waitOrDriveDownstreamHandshake() catch |err| {
                attempt_executor.recordEarlyRetryResult(.failure);
                attempt_executor.recordEarlyUpstream425Action(.forwarded);
                try attempt_executor.onEarly425HandshakeFailure(err);
                return .{ .response = result };
            };
            if (!early_ctx.downstreamHandshakeComplete()) {
                if (maybeParkEarly425Retry(attempt_executor, &result)) |parked| {
                    if (parked) return .early_425_retry_parked;
                } else |err| {
                    attempt_executor.recordEarlyRetryResult(.failure);
                    attempt_executor.recordEarlyUpstream425Action(.forwarded);
                    try attempt_executor.onEarly425HandshakeFailure(err);
                    return .{ .response = result };
                }
                attempt_executor.recordEarlyRetryResult(.failure);
                attempt_executor.recordEarlyUpstream425Action(.forwarded);
                return .{ .response = result };
            }
            attempt_executor.recordEarlyUpstream425Action(.retried);
            retry_state.consumeEarly425Retry();
            try attempt_executor.onEarly425Retry(&result);
            continue;
        }
        if (result.statusCode() == @intFromEnum(http.Status.too_early)) {
            attempt_executor.recordEarlyUpstream425Action(.forwarded);
            retry_state.recordEarly425RetryResultOnce(attempt_executor, .too_early);
        } else {
            retry_state.recordEarly425RetryResultOnce(attempt_executor, .success);
        }
        if (result.statusCode() >= 500 and retry_state.hasConfiguredRetryRemaining(attempt, max_attempts, stale_conn_retries)) {
            try attempt_executor.onConfigured5xxRetry(retry_state.configuredAttemptIndex(attempt, stale_conn_retries), max_attempts, &result);
            continue;
        }
        return .{ .response = result };
    }
    return error.UpstreamUnavailable;
}

fn maybeParkEarly425Retry(attempt_executor: anytype, result: *DataPlaneProxyResponse) !bool {
    if (comptime @hasDecl(@TypeOf(attempt_executor.*), "parkEarly425Retry")) {
        try attempt_executor.parkEarly425Retry(result);
        return true;
    }
    return false;
}

fn maybeReleaseCircuitProbe(attempt_executor: anytype) void {
    if (comptime @hasDecl(@TypeOf(attempt_executor.*), "releaseCircuitProbe")) {
        attempt_executor.releaseCircuitProbe();
    }
}

const ProductionBufferedProxyAttemptExecutor = struct {
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    body: []const u8,
    upstream_url: []const u8,
    unix_socket_path: ?[]const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    forwarded_proto: []const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    selection_base_url: []const u8,
    absolute_target: bool,
    budget_start_ms: u64,
    last_attempt_start_ms: u64 = 0,
    circuit_permit: ?http.circuit_breaker.Permit = null,

    fn recordEarlyUpstream425Action(
        self: *ProductionBufferedProxyAttemptExecutor,
        action: http.metrics.EarlyDataUpstream425Action,
    ) void {
        self.state.metricsRecordEarlyDataUpstream425(action);
        if (action == .retried) {
            self.ctx.early_data_action = .retried;
        }
    }

    fn recordEarlyRetryResult(
        self: *ProductionBufferedProxyAttemptExecutor,
        result: http.metrics.EarlyDataRetryResult,
    ) void {
        self.state.metricsRecordEarlyDataRetry(result);
        self.ctx.early_data_retry_result = switch (result) {
            .success => .success,
            .too_early => .too_early,
            .failure => .failure,
        };
    }

    fn perAttemptTimeoutMs(self: *ProductionBufferedProxyAttemptExecutor) !u32 {
        if (self.cfg.upstream_timeout_budget_ms == 0) return self.cfg.upstream_timeout_ms;
        const elapsed_ms = http.event_loop.monotonicMs() - self.budget_start_ms;
        if (elapsed_ms >= self.cfg.upstream_timeout_budget_ms) return error.ProxyBudgetExhausted;
        const remaining = self.cfg.upstream_timeout_budget_ms - elapsed_ms;
        if (self.cfg.upstream_timeout_ms == 0) {
            return @intCast(@min(remaining, @as(u64, std.math.maxInt(u32))));
        }
        return @intCast(@min(@as(u64, self.cfg.upstream_timeout_ms), remaining));
    }

    fn execute(
        self: *ProductionBufferedProxyAttemptExecutor,
        attempt: usize,
        forward_early_data: bool,
    ) !DataPlaneProxyResponse {
        _ = attempt;
        if (self.circuit_permit == null) {
            self.circuit_permit = self.state.circuitTryAcquirePermit() orelse return error.CircuitOpen;
        }
        const per_attempt_timeout_ms = try self.perAttemptTimeoutMs();
        self.state.recordUpstreamAttemptStart(self.selection_base_url);
        self.last_attempt_start_ms = http.event_loop.monotonicMs();
        const resp = executeBufferedDataPlaneProxyRequest(
            self.allocator,
            self.cfg,
            self.upstream_url,
            self.unix_socket_path,
            self.request.method.toString(),
            &self.request.headers,
            self.body,
            self.correlation_id,
            self.client_ip,
            self.forwarded_proto,
            self.request.headers.get("host"),
            null,
            self.auth_identity,
            self.auth_user_id,
            self.auth_device_id,
            self.auth_scopes,
            forward_early_data,
            per_attempt_timeout_ms,
            self.cfg.upstream_connect_timeout_ms,
            self.cfg.upstream_response_timeout_ms,
            if (self.ctx.lifecycle) |lc| &lc.token else null,
            &self.state.upstream_pool,
            &self.state.h2_pool,
        );
        self.state.recordUpstreamAttemptEnd(self.selection_base_url);
        return resp;
    }

    fn onBufferedResponse(
        self: *ProductionBufferedProxyAttemptExecutor,
        result: *DataPlaneProxyResponse,
    ) !void {
        const upstream_ttfb_ms = http.event_loop.monotonicMs() - self.last_attempt_start_ms;
        self.state.metricsRecordProxyBufferedRequest(result.bodyLen(), upstream_ttfb_ms);
    }

    fn onStaleConnectionRetry(
        self: *ProductionBufferedProxyAttemptExecutor,
        stale_conn_retries: usize,
        max_stale_conn_retries: usize,
    ) !void {
        self.state.logger.warn(self.correlation_id, "proxy retrying on fresh connection after stale upstream keep-alive ({d}/{d})", .{ stale_conn_retries, max_stale_conn_retries });
    }

    fn releaseCircuitProbe(self: *ProductionBufferedProxyAttemptExecutor) void {
        const permit = self.circuit_permit orelse return;
        self.state.circuitReleasePermit(permit);
        self.circuit_permit = null;
    }

    fn recordCircuitFailure(self: *ProductionBufferedProxyAttemptExecutor) void {
        const permit = self.circuit_permit orelse return;
        if (self.absolute_target) {
            self.state.circuitRecordFailurePermit(permit);
        } else {
            self.state.recordProxyUpstreamFailure(self.cfg, self.selection_base_url, permit);
        }
        self.circuit_permit = null;
    }

    fn recordCircuitSuccess(self: *ProductionBufferedProxyAttemptExecutor) void {
        const permit = self.circuit_permit orelse return;
        if (self.absolute_target) {
            self.state.circuitRecordSuccessPermit(permit);
        } else {
            self.state.recordProxyUpstreamSuccess(self.cfg, self.selection_base_url, permit);
        }
        self.circuit_permit = null;
    }

    fn onTerminalAttemptError(
        self: *ProductionBufferedProxyAttemptExecutor,
        err: anyerror,
    ) !void {
        if (proxyAttemptErrorCountsAsUpstreamFailure(err)) {
            self.recordCircuitFailure();
        } else {
            self.releaseCircuitProbe();
        }
    }

    fn onConfiguredErrorRetry(
        self: *ProductionBufferedProxyAttemptExecutor,
        configured_attempt_index: usize,
        max_attempts: usize,
        err: anyerror,
    ) !void {
        self.state.logger.warn(self.correlation_id, "proxy attempt {d}/{d} failed: {}", .{ configured_attempt_index + 1, max_attempts, err });
    }

    fn onEarly425Retry(
        self: *ProductionBufferedProxyAttemptExecutor,
        result: *DataPlaneProxyResponse,
    ) !void {
        self.state.logger.debug(self.correlation_id, "retrying early-data upstream 425 once after downstream handshake completion", .{});
        self.state.metricsReleaseProxyBufferedBytes(result.bodyLen());
        result.deinit(self.allocator);
    }

    fn onEarly425HandshakeFailure(
        self: *ProductionBufferedProxyAttemptExecutor,
        err: anyerror,
    ) !void {
        self.state.logger.warn(self.correlation_id, "could not complete downstream handshake before early-data 425 retry: {}", .{err});
    }

    fn onConfigured5xxRetry(
        self: *ProductionBufferedProxyAttemptExecutor,
        configured_attempt_index: usize,
        max_attempts: usize,
        result: *DataPlaneProxyResponse,
    ) !void {
        self.recordCircuitFailure();
        self.state.logger.warn(self.correlation_id, "proxy attempt {d}/{d} got {d}, retrying", .{ configured_attempt_index + 1, max_attempts, result.statusCode() });
        self.state.metricsReleaseProxyBufferedBytes(result.bodyLen());
        result.deinit(self.allocator);
    }
};

test "ProductionBufferedProxyAttemptExecutor keeps absolute target failures out of passive health" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.upstream_mutex = .{};
    state.circuit_mutex = .{};
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 30_000 });
    state.upstream_health = std.StringHashMap(gs.UpstreamHealth).init(allocator);
    defer {
        var it = state.upstream_health.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        state.upstream_health.deinit();
    }

    const permit = state.circuitTryAcquirePermit() orelse return error.TestExpectedOrdinaryPermit;
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.upstream_max_fails = 1;
    cfg.upstream_fail_timeout_ms = 60_000;

    var attempt_executor = ProductionBufferedProxyAttemptExecutor{
        .allocator = allocator,
        .cfg = &cfg,
        .state = &state,
        .ctx = undefined,
        .request = undefined,
        .body = "",
        .upstream_url = "http://absolute.example/resource",
        .unix_socket_path = null,
        .correlation_id = "test",
        .client_ip = "127.0.0.1",
        .forwarded_proto = "http",
        .auth_identity = null,
        .auth_user_id = null,
        .auth_device_id = null,
        .auth_scopes = null,
        .selection_base_url = "http://configured.example",
        .absolute_target = true,
        .budget_start_ms = 0,
        .circuit_permit = permit,
    };

    attempt_executor.recordCircuitFailure();

    try std.testing.expectEqual(@as(usize, 0), state.upstreamUnhealthyCount());
    try std.testing.expect(state.circuitTryAcquirePermit() == null);
}

test "streaming absolute target local capacity abort releases circuit permit first" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.upstream_mutex = .{};
    state.circuit_mutex = .{};
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    state.logger = http.logger.Logger.init(.err, "test");
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 30_000 });
    state.upstream_health = std.StringHashMap(gs.UpstreamHealth).init(allocator);
    defer {
        var it = state.upstream_health.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        state.upstream_health.deinit();
    }

    const permit = state.circuitTryAcquirePermit() orelse return error.TestExpectedOrdinaryPermit;
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.upstream_max_fails = 1;
    cfg.upstream_fail_timeout_ms = 60_000;

    recordStreamingProxyOutcome(
        &state,
        &cfg,
        "http://configured.example",
        true,
        permit,
        200,
        true,
        true,
        "test-correlation",
    );

    try std.testing.expectEqual(@as(usize, 0), state.upstreamUnhealthyCount());
    try std.testing.expectEqualStrings("closed", state.circuitStateName());
    try std.testing.expect(state.circuitTryAcquirePermit() != null);
}

test "streaming downstream abort after known 500 records outcome then propagates client abort" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.upstream_mutex = .{};
    state.circuit_mutex = .{};
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    state.logger = http.logger.Logger.init(.err, "test");
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    state.upstream_health = std.StringHashMap(gs.UpstreamHealth).init(allocator);
    defer {
        var it = state.upstream_health.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        state.upstream_health.deinit();
    }

    var cfg: edge_config.EdgeConfig = undefined;
    cfg.upstream_max_fails = 1;
    cfg.upstream_fail_timeout_ms = 60_000;
    state.circuitRecordFailurePermit(state.circuitTryAcquirePermit().?);
    const permit = state.circuitTryAcquirePermit() orelse return error.TestExpectedHalfOpenPermit;

    const streamed = gp.StreamingProxyResult{
        .status_code = 500,
        .reason = "Internal Server Error",
        .response_body_bytes = 0,
        .upstream_ttfb_ms = 7,
        .downstream_aborted_after_status = true,
    };
    recordStreamingProxyOutcome(
        &state,
        &cfg,
        "http://configured.example",
        true,
        permit,
        streamed.status_code,
        streamed.upstream_aborted,
        streamed.local_capacity_aborted,
        "test-correlation",
    );
    try std.testing.expectError(error.ClientAborted, propagateStreamingDownstreamAbortAfterStatus(&state, &streamed));

    try std.testing.expectEqualStrings("open", state.circuitStateName());
    try std.testing.expect(state.circuitTryAcquirePermit() != null);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.proxy_client_aborts);
}

const Early425RetryHarnessResult = struct {
    downstream_status: u16,
    upstream_deliveries: usize,
    handshake_failures: usize = 0,
    early_425_forwarded: usize = 0,
    early_425_retried: usize = 0,
    early_retry_success: usize = 0,
    early_retry_too_early: usize = 0,
    early_retry_failure: usize = 0,
};

const ScriptedBufferedAttemptExecutor = struct {
    allocator: std.mem.Allocator,
    upstream_statuses: []const u16,
    early_data_header_counts: *std.array_list.Managed(usize),
    request_ctx: ?*http.request_context.RequestContext = null,
    fail_attempt_index: ?usize = null,
    fail_attempt_err: anyerror = error.TestRetryTransportFailed,
    deliveries: usize = 0,
    execute_failures: usize = 0,
    terminal_attempt_errors: usize = 0,
    handshake_failures: usize = 0,
    early_425_forwarded: usize = 0,
    early_425_retried: usize = 0,
    early_retry_success: usize = 0,
    early_retry_too_early: usize = 0,
    early_retry_failure: usize = 0,

    fn recordEarlyUpstream425Action(
        self: *ScriptedBufferedAttemptExecutor,
        action: http.metrics.EarlyDataUpstream425Action,
    ) void {
        switch (action) {
            .forwarded => self.early_425_forwarded += 1,
            .retried => self.early_425_retried += 1,
        }
        if (action == .retried) {
            if (self.request_ctx) |ctx| ctx.early_data_action = .retried;
        }
    }

    fn recordEarlyRetryResult(
        self: *ScriptedBufferedAttemptExecutor,
        result: http.metrics.EarlyDataRetryResult,
    ) void {
        switch (result) {
            .success => self.early_retry_success += 1,
            .too_early => self.early_retry_too_early += 1,
            .failure => self.early_retry_failure += 1,
        }
        if (self.request_ctx) |ctx| {
            ctx.early_data_retry_result = switch (result) {
                .success => .success,
                .too_early => .too_early,
                .failure => .failure,
            };
        }
    }

    fn execute(
        self: *ScriptedBufferedAttemptExecutor,
        attempt: usize,
        forward_early_data: bool,
    ) !DataPlaneProxyResponse {
        if (self.fail_attempt_index == attempt) {
            try recordCanonicalEarlyDataHeaderCount(self.allocator, self.early_data_header_counts, forward_early_data);
            self.execute_failures += 1;
            return self.fail_attempt_err;
        }
        if (attempt >= self.upstream_statuses.len) return error.TestHarnessMissingStatus;
        try recordCanonicalEarlyDataHeaderCount(self.allocator, self.early_data_header_counts, forward_early_data);
        self.deliveries += 1;
        const raw = try std.fmt.allocPrint(
            self.allocator,
            "HTTP/1.1 {d} test\r\nContent-Length: 0\r\n\r\n",
            .{self.upstream_statuses[attempt]},
        );
        defer self.allocator.free(raw);
        return .{ .bounded_buffered = try gp.parseBufferedUpstreamResponse(self.allocator, raw) };
    }

    fn onBufferedResponse(
        self: *ScriptedBufferedAttemptExecutor,
        result: *DataPlaneProxyResponse,
    ) !void {
        _ = self;
        _ = result;
    }

    fn onEarly425HandshakeFailure(
        self: *ScriptedBufferedAttemptExecutor,
        _: anyerror,
    ) !void {
        self.handshake_failures += 1;
    }

    fn onStaleConnectionRetry(
        self: *ScriptedBufferedAttemptExecutor,
        stale_conn_retries: usize,
        max_stale_conn_retries: usize,
    ) !void {
        _ = self;
        _ = stale_conn_retries;
        _ = max_stale_conn_retries;
    }

    fn onTerminalAttemptError(
        self: *ScriptedBufferedAttemptExecutor,
        _: anyerror,
    ) !void {
        self.terminal_attempt_errors += 1;
    }

    fn onConfiguredErrorRetry(
        self: *ScriptedBufferedAttemptExecutor,
        configured_attempt_index: usize,
        max_attempts: usize,
        _: anyerror,
    ) !void {
        _ = self;
        _ = configured_attempt_index;
        _ = max_attempts;
    }

    fn onEarly425Retry(
        self: *ScriptedBufferedAttemptExecutor,
        result: *DataPlaneProxyResponse,
    ) !void {
        result.deinit(self.allocator);
    }

    fn onConfigured5xxRetry(
        self: *ScriptedBufferedAttemptExecutor,
        configured_attempt_index: usize,
        max_attempts: usize,
        result: *DataPlaneProxyResponse,
    ) !void {
        _ = configured_attempt_index;
        _ = max_attempts;
        result.deinit(self.allocator);
    }
};

const ParkingBufferedAttemptExecutor = struct {
    inner: ScriptedBufferedAttemptExecutor,
    parked: usize = 0,
    fail_park: bool = false,

    fn recordEarlyUpstream425Action(
        self: *ParkingBufferedAttemptExecutor,
        action: http.metrics.EarlyDataUpstream425Action,
    ) void {
        self.inner.recordEarlyUpstream425Action(action);
    }

    fn recordEarlyRetryResult(
        self: *ParkingBufferedAttemptExecutor,
        result: http.metrics.EarlyDataRetryResult,
    ) void {
        self.inner.recordEarlyRetryResult(result);
    }

    fn execute(
        self: *ParkingBufferedAttemptExecutor,
        attempt: usize,
        forward_early_data: bool,
    ) !DataPlaneProxyResponse {
        return self.inner.execute(attempt, forward_early_data);
    }

    fn onBufferedResponse(
        self: *ParkingBufferedAttemptExecutor,
        result: *DataPlaneProxyResponse,
    ) !void {
        try self.inner.onBufferedResponse(result);
    }

    fn onEarly425HandshakeFailure(
        self: *ParkingBufferedAttemptExecutor,
        err: anyerror,
    ) !void {
        try self.inner.onEarly425HandshakeFailure(err);
    }

    fn onStaleConnectionRetry(
        self: *ParkingBufferedAttemptExecutor,
        stale_conn_retries: usize,
        max_stale_conn_retries: usize,
    ) !void {
        try self.inner.onStaleConnectionRetry(stale_conn_retries, max_stale_conn_retries);
    }

    fn onTerminalAttemptError(
        self: *ParkingBufferedAttemptExecutor,
        err: anyerror,
    ) !void {
        try self.inner.onTerminalAttemptError(err);
    }

    fn onConfiguredErrorRetry(
        self: *ParkingBufferedAttemptExecutor,
        configured_attempt_index: usize,
        max_attempts: usize,
        err: anyerror,
    ) !void {
        try self.inner.onConfiguredErrorRetry(configured_attempt_index, max_attempts, err);
    }

    fn onEarly425Retry(
        self: *ParkingBufferedAttemptExecutor,
        result: *DataPlaneProxyResponse,
    ) !void {
        try self.inner.onEarly425Retry(result);
    }

    fn parkEarly425Retry(
        self: *ParkingBufferedAttemptExecutor,
        result: *DataPlaneProxyResponse,
    ) !void {
        if (self.fail_park) return error.TestParkingFailed;
        self.parked += 1;
        result.deinit(self.inner.allocator);
    }

    fn onConfigured5xxRetry(
        self: *ParkingBufferedAttemptExecutor,
        configured_attempt_index: usize,
        max_attempts: usize,
        result: *DataPlaneProxyResponse,
    ) !void {
        try self.inner.onConfigured5xxRetry(configured_attempt_index, max_attempts, result);
    }
};

const ErrorBufferedAttemptExecutor = struct {
    err: anyerror,
    execute_calls: usize = 0,
    terminal_attempt_errors: usize = 0,
    configured_error_retries: usize = 0,

    fn recordEarlyUpstream425Action(
        self: *ErrorBufferedAttemptExecutor,
        action: http.metrics.EarlyDataUpstream425Action,
    ) void {
        _ = self;
        _ = action;
    }

    fn recordEarlyRetryResult(
        self: *ErrorBufferedAttemptExecutor,
        result: http.metrics.EarlyDataRetryResult,
    ) void {
        _ = self;
        _ = result;
    }

    fn execute(
        self: *ErrorBufferedAttemptExecutor,
        attempt: usize,
        forward_early_data: bool,
    ) !DataPlaneProxyResponse {
        _ = attempt;
        _ = forward_early_data;
        self.execute_calls += 1;
        return self.err;
    }

    fn onBufferedResponse(
        self: *ErrorBufferedAttemptExecutor,
        result: *DataPlaneProxyResponse,
    ) !void {
        _ = self;
        _ = result;
    }

    fn onStaleConnectionRetry(
        self: *ErrorBufferedAttemptExecutor,
        stale_conn_retries: usize,
        max_stale_conn_retries: usize,
    ) !void {
        _ = self;
        _ = stale_conn_retries;
        _ = max_stale_conn_retries;
    }

    fn onTerminalAttemptError(
        self: *ErrorBufferedAttemptExecutor,
        _: anyerror,
    ) !void {
        self.terminal_attempt_errors += 1;
    }

    fn onConfiguredErrorRetry(
        self: *ErrorBufferedAttemptExecutor,
        configured_attempt_index: usize,
        max_attempts: usize,
        _: anyerror,
    ) !void {
        _ = configured_attempt_index;
        _ = max_attempts;
        self.configured_error_retries += 1;
    }

    fn onEarly425Retry(
        self: *ErrorBufferedAttemptExecutor,
        result: *DataPlaneProxyResponse,
    ) !void {
        _ = self;
        _ = result;
    }

    fn onEarly425HandshakeFailure(
        self: *ErrorBufferedAttemptExecutor,
        _: anyerror,
    ) !void {
        _ = self;
    }

    fn onConfigured5xxRetry(
        self: *ErrorBufferedAttemptExecutor,
        configured_attempt_index: usize,
        max_attempts: usize,
        result: *DataPlaneProxyResponse,
    ) !void {
        _ = self;
        _ = configured_attempt_index;
        _ = max_attempts;
        _ = result;
    }
};

fn recordCanonicalEarlyDataHeaderCount(
    allocator: std.mem.Allocator,
    counts: *std.array_list.Managed(usize),
    forward_early_data: bool,
) !void {
    var headers = std.array_list.Managed(std.http.Header).init(allocator);
    defer headers.deinit();
    try gph.appendCanonicalEarlyDataHeader(&headers, forward_early_data);

    var count: usize = 0;
    for (headers.items) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "Early-Data") and
            std.mem.eql(u8, header.value, "1"))
        {
            count += 1;
        }
    }
    try counts.append(count);
}

fn runEarly425RetryHarness(
    allocator: std.mem.Allocator,
    early_ctx: *http.request_context.EarlyDataContext,
    method: []const u8,
    matched_block: *const edge_config.EdgeConfig.LocationBlock,
    max_attempts: usize,
    upstream_statuses: []const u16,
    early_data_header_counts: *std.array_list.Managed(usize),
) !Early425RetryHarnessResult {
    const first_attempt_forward_early_data = early_ctx.inbound_marker or
        (early_ctx.transport_early and !early_ctx.downstreamHandshakeComplete());
    var executor = ScriptedBufferedAttemptExecutor{
        .allocator = allocator,
        .upstream_statuses = upstream_statuses,
        .early_data_header_counts = early_data_header_counts,
    };
    return switch (try runBufferedProxyAttempts(
        early_ctx,
        first_attempt_forward_early_data,
        method,
        matched_block,
        max_attempts,
        0,
        true,
        &executor,
    )) {
        .response => |response| {
            var mutable_response = response;
            defer mutable_response.deinit(allocator);
            return .{
                .downstream_status = mutable_response.statusCode(),
                .upstream_deliveries = executor.deliveries,
                .handshake_failures = executor.handshake_failures,
                .early_425_forwarded = executor.early_425_forwarded,
                .early_425_retried = executor.early_425_retried,
                .early_retry_success = executor.early_retry_success,
                .early_retry_too_early = executor.early_retry_too_early,
                .early_retry_failure = executor.early_retry_failure,
            };
        },
        .early_425_retry_parked,
        .upstream_at_capacity,
        .circuit_open,
        .request_cancelled,
        .retry_budget_exhausted,
        .terminal_error,
        => error.TestUnexpectedTerminalProxyResult,
    };
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

test "shouldRetryEarlyUpstream425 permits exactly current-hop replay-safe RFC8470 retry" {
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };

    try std.testing.expect(shouldRetryEarlyUpstream425(
        .{ .transport_early = true },
        true,
        false,
        "GET",
        &block,
    ));
    try std.testing.expect(!shouldRetryEarlyUpstream425(
        .{ .transport_early = true, .inbound_marker = true },
        true,
        false,
        "GET",
        &block,
    ));
    try std.testing.expect(!shouldRetryEarlyUpstream425(
        .{ .transport_early = true },
        true,
        true,
        "GET",
        &block,
    ));
    try std.testing.expect(!shouldRetryEarlyUpstream425(
        .{ .transport_early = true },
        true,
        false,
        "POST",
        &block,
    ));
    var origin_unknown = block;
    origin_unknown.proxy_early_data = .off;
    try std.testing.expect(!shouldRetryEarlyUpstream425(
        .{ .transport_early = true },
        true,
        false,
        "GET",
        &origin_unknown,
    ));
}

const TestEarly425Barrier = struct {
    complete: bool = false,
    fail_wait: bool = false,
    waits: usize = 0,

    fn isComplete(ptr: *anyopaque) bool {
        const self: *TestEarly425Barrier = @ptrCast(@alignCast(ptr));
        return self.complete;
    }

    fn waitOrDrive(ptr: *anyopaque) anyerror!void {
        const self: *TestEarly425Barrier = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        if (self.fail_wait) return error.TestHandshakeDriveFailed;
        self.complete = true;
    }

    fn barrier(self: *TestEarly425Barrier) http.request_context.DownstreamHandshakeBarrier {
        return .{
            .ctx = self,
            .is_complete_fn = isComplete,
            .wait_or_drive_fn = waitOrDrive,
        };
    }
};

test "early upstream 425 retry sends marker once then retries ordinary to 200" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();

    const result = try runEarly425RetryHarness(allocator, &ctx, "GET", &block, 1, &.{ 425, 200 }, &header_counts);

    try std.testing.expectEqual(@as(u16, 200), result.downstream_status);
    try std.testing.expectEqual(@as(usize, 2), result.upstream_deliveries);
    try std.testing.expectEqual(@as(usize, 1), barrier.waits);
    try std.testing.expectEqual(@as(usize, 1), result.early_425_retried);
    try std.testing.expectEqual(@as(usize, 1), result.early_retry_success);
    try std.testing.expectEqualSlices(usize, &.{ 1, 0 }, header_counts.items);
}

test "early upstream 425 can park retry until event-loop handshake completion" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();
    var executor = ParkingBufferedAttemptExecutor{
        .inner = .{
            .allocator = allocator,
            .upstream_statuses = &.{ 425, 200 },
            .early_data_header_counts = &header_counts,
        },
    };

    const result = try runBufferedProxyAttempts(&ctx, true, "GET", &block, 1, 0, true, &executor);

    try std.testing.expectEqual(std.meta.Tag(BufferedProxyAttemptsResult).early_425_retry_parked, std.meta.activeTag(result));
    try std.testing.expectEqual(@as(usize, 1), executor.inner.deliveries);
    try std.testing.expectEqual(@as(usize, 0), barrier.waits);
    try std.testing.expectEqual(@as(usize, 1), executor.parked);
    try std.testing.expectEqual(@as(usize, 0), executor.inner.early_425_retried);
    try std.testing.expectEqualSlices(usize, &.{1}, header_counts.items);
}

test "early upstream 425 parking failure forwards original response" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();
    var executor = ParkingBufferedAttemptExecutor{
        .inner = .{
            .allocator = allocator,
            .upstream_statuses = &.{ 425, 200 },
            .early_data_header_counts = &header_counts,
        },
        .fail_park = true,
    };

    const result = try runBufferedProxyAttempts(&ctx, true, "GET", &block, 1, 0, true, &executor);

    switch (result) {
        .response => |response| {
            var mutable = response;
            defer mutable.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 425), mutable.statusCode());
        },
        else => return error.TestUnexpectedTerminalProxyResult,
    }
    try std.testing.expectEqual(@as(usize, 1), executor.inner.deliveries);
    try std.testing.expectEqual(@as(usize, 0), executor.parked);
    try std.testing.expectEqual(@as(usize, 1), executor.inner.early_retry_failure);
    try std.testing.expectEqual(@as(usize, 1), executor.inner.early_425_forwarded);
}

test "early upstream 425 retry forwards second 425 without third delivery" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();

    const result = try runEarly425RetryHarness(allocator, &ctx, "GET", &block, 1, &.{ 425, 425, 200 }, &header_counts);

    try std.testing.expectEqual(@as(u16, 425), result.downstream_status);
    try std.testing.expectEqual(@as(usize, 2), result.upstream_deliveries);
    try std.testing.expectEqual(@as(usize, 1), barrier.waits);
    try std.testing.expectEqual(@as(usize, 1), result.early_425_retried);
    try std.testing.expectEqual(@as(usize, 1), result.early_425_forwarded);
    try std.testing.expectEqual(@as(usize, 1), result.early_retry_too_early);
    try std.testing.expectEqualSlices(usize, &.{ 1, 0 }, header_counts.items);
}

test "early upstream 425 ordinary retry transport failure records failure once" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();
    var executor = ScriptedBufferedAttemptExecutor{
        .allocator = allocator,
        .upstream_statuses = &.{425},
        .early_data_header_counts = &header_counts,
        .fail_attempt_index = 1,
        .fail_attempt_err = error.TestRetryTransportFailed,
    };

    const result = try runBufferedProxyAttempts(&ctx, true, "GET", &block, 1, 0, true, &executor);

    switch (result) {
        .terminal_error => |err| try std.testing.expectEqual(error.TestRetryTransportFailed, err),
        else => return error.TestUnexpectedTerminalProxyResult,
    }
    try std.testing.expectEqual(@as(usize, 1), executor.deliveries);
    try std.testing.expectEqual(@as(usize, 1), executor.execute_failures);
    try std.testing.expectEqual(@as(usize, 1), executor.early_425_retried);
    try std.testing.expectEqual(@as(usize, 1), executor.early_retry_failure);
    try std.testing.expectEqual(@as(usize, 0), executor.early_retry_success);
    try std.testing.expectEqualSlices(usize, &.{ 1, 0 }, header_counts.items);
}

test "early upstream 425 retry blocked by circuit records failure once" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();
    var executor = ScriptedBufferedAttemptExecutor{
        .allocator = allocator,
        .upstream_statuses = &.{425},
        .early_data_header_counts = &header_counts,
        .fail_attempt_index = 1,
        .fail_attempt_err = error.CircuitOpen,
    };

    const result = try runBufferedProxyAttempts(&ctx, true, "GET", &block, 1, 0, true, &executor);

    try std.testing.expectEqual(std.meta.Tag(BufferedProxyAttemptsResult).circuit_open, std.meta.activeTag(result));
    try std.testing.expectEqual(@as(usize, 1), executor.deliveries);
    try std.testing.expectEqual(@as(usize, 1), executor.execute_failures);
    try std.testing.expectEqual(@as(usize, 1), executor.early_425_retried);
    try std.testing.expectEqual(@as(usize, 1), executor.early_retry_failure);
    try std.testing.expectEqual(@as(usize, 0), executor.early_retry_success);
    try std.testing.expectEqualSlices(usize, &.{ 1, 0 }, header_counts.items);
}

test "early upstream 425 retry success records retried action in request context" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var early_ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var request_ctx = http.request_context.RequestContext.init(allocator, "req-early-success", "127.0.0.1");
    request_ctx.early_data_action = .forwarded;
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();
    var executor = ScriptedBufferedAttemptExecutor{
        .allocator = allocator,
        .upstream_statuses = &.{ 425, 200 },
        .early_data_header_counts = &header_counts,
        .request_ctx = &request_ctx,
    };

    const result = try runBufferedProxyAttempts(&early_ctx, true, "GET", &block, 1, 0, true, &executor);
    switch (result) {
        .response => |response| {
            var mutable = response;
            defer mutable.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), mutable.statusCode());
        },
        else => return error.TestUnexpectedTerminalProxyResult,
    }
    try std.testing.expectEqual(http.request_context.EarlyDataAction.retried, request_ctx.early_data_action);
    try std.testing.expectEqual(http.request_context.EarlyDataRetryResult.success, request_ctx.early_data_retry_result);
}

test "early upstream 425 retry second 425 records retried action in request context" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var early_ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var request_ctx = http.request_context.RequestContext.init(allocator, "req-early-425", "127.0.0.1");
    request_ctx.early_data_action = .forwarded;
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();
    var executor = ScriptedBufferedAttemptExecutor{
        .allocator = allocator,
        .upstream_statuses = &.{ 425, 425 },
        .early_data_header_counts = &header_counts,
        .request_ctx = &request_ctx,
    };

    const result = try runBufferedProxyAttempts(&early_ctx, true, "GET", &block, 1, 0, true, &executor);
    switch (result) {
        .response => |response| {
            var mutable = response;
            defer mutable.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 425), mutable.statusCode());
        },
        else => return error.TestUnexpectedTerminalProxyResult,
    }
    try std.testing.expectEqual(http.request_context.EarlyDataAction.retried, request_ctx.early_data_action);
    try std.testing.expectEqual(http.request_context.EarlyDataRetryResult.too_early, request_ctx.early_data_retry_result);
}

test "early upstream 425 retry transport failure records retried action in request context" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var early_ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var request_ctx = http.request_context.RequestContext.init(allocator, "req-early-failure", "127.0.0.1");
    request_ctx.early_data_action = .forwarded;
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();
    var executor = ScriptedBufferedAttemptExecutor{
        .allocator = allocator,
        .upstream_statuses = &.{425},
        .early_data_header_counts = &header_counts,
        .request_ctx = &request_ctx,
        .fail_attempt_index = 1,
        .fail_attempt_err = error.TestRetryTransportFailed,
    };

    const result = try runBufferedProxyAttempts(&early_ctx, true, "GET", &block, 1, 0, true, &executor);
    switch (result) {
        .terminal_error => |err| try std.testing.expectEqual(error.TestRetryTransportFailed, err),
        else => return error.TestUnexpectedTerminalProxyResult,
    }
    try std.testing.expectEqual(http.request_context.EarlyDataAction.retried, request_ctx.early_data_action);
    try std.testing.expectEqual(http.request_context.EarlyDataRetryResult.failure, request_ctx.early_data_retry_result);
}

test "early upstream 425 handshake failure keeps forwarded action in request context" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{ .fail_wait = true };
    var early_ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var request_ctx = http.request_context.RequestContext.init(allocator, "req-early-handshake-failure", "127.0.0.1");
    request_ctx.early_data_action = .forwarded;
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();
    var executor = ScriptedBufferedAttemptExecutor{
        .allocator = allocator,
        .upstream_statuses = &.{425},
        .early_data_header_counts = &header_counts,
        .request_ctx = &request_ctx,
    };

    const result = try runBufferedProxyAttempts(&early_ctx, true, "GET", &block, 1, 0, true, &executor);
    switch (result) {
        .response => |response| {
            var mutable = response;
            defer mutable.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 425), mutable.statusCode());
        },
        else => return error.TestUnexpectedTerminalProxyResult,
    }
    try std.testing.expectEqual(http.request_context.EarlyDataAction.forwarded, request_ctx.early_data_action);
    try std.testing.expectEqual(http.request_context.EarlyDataRetryResult.failure, request_ctx.early_data_retry_result);
}

test "early upstream 425 stale ordinary retry recovers without failure metric" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();
    var executor = ScriptedBufferedAttemptExecutor{
        .allocator = allocator,
        .upstream_statuses = &.{ 425, 0, 200 },
        .early_data_header_counts = &header_counts,
        .fail_attempt_index = 1,
        .fail_attempt_err = error.HttpConnectionClosing,
    };

    const result = try runBufferedProxyAttempts(&ctx, true, "GET", &block, 1, 1, true, &executor);

    switch (result) {
        .response => |response| {
            var mutable = response;
            defer mutable.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), mutable.statusCode());
        },
        else => return error.TestUnexpectedTerminalProxyResult,
    }
    try std.testing.expectEqual(@as(usize, 2), executor.deliveries);
    try std.testing.expectEqual(@as(usize, 1), executor.execute_failures);
    try std.testing.expectEqual(@as(usize, 1), executor.early_425_retried);
    try std.testing.expectEqual(@as(usize, 1), executor.early_retry_success);
    try std.testing.expectEqual(@as(usize, 0), executor.early_retry_failure);
    try std.testing.expectEqualSlices(usize, &.{ 1, 0, 0 }, header_counts.items);
}

test "early upstream 425 stale retry does not consume configured retry budget" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();
    var executor = ScriptedBufferedAttemptExecutor{
        .allocator = allocator,
        .upstream_statuses = &.{ 425, 0, 500, 200 },
        .early_data_header_counts = &header_counts,
        .fail_attempt_index = 1,
        .fail_attempt_err = error.HttpConnectionClosing,
    };

    const result = try runBufferedProxyAttempts(&ctx, true, "GET", &block, 2, 1, true, &executor);

    switch (result) {
        .response => |response| {
            var mutable = response;
            defer mutable.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), mutable.statusCode());
        },
        else => return error.TestUnexpectedTerminalProxyResult,
    }
    try std.testing.expectEqual(@as(usize, 3), executor.deliveries);
    try std.testing.expectEqual(@as(usize, 1), executor.execute_failures);
    try std.testing.expectEqual(@as(usize, 1), executor.early_425_retried);
    try std.testing.expectEqual(@as(usize, 1), executor.early_retry_success);
    try std.testing.expectEqualSlices(usize, &.{ 1, 0, 0, 0 }, header_counts.items);
}

test "early upstream 425 handshake failure forwards original 425" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{ .fail_wait = true };
    var ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();

    const result = try runEarly425RetryHarness(allocator, &ctx, "GET", &block, 1, &.{ 425, 200 }, &header_counts);

    try std.testing.expectEqual(@as(u16, 425), result.downstream_status);
    try std.testing.expectEqual(@as(usize, 1), result.upstream_deliveries);
    try std.testing.expectEqual(@as(usize, 1), barrier.waits);
    try std.testing.expectEqual(@as(usize, 1), result.handshake_failures);
    try std.testing.expectEqual(@as(usize, 1), result.early_425_forwarded);
    try std.testing.expectEqual(@as(usize, 1), result.early_retry_failure);
    try std.testing.expectEqualSlices(usize, &.{1}, header_counts.items);
}

test "inbound early-data marker forwards upstream 425 without local retry" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var ctx = http.request_context.EarlyDataContext{ .inbound_marker = true, .downstream_handshake = barrier.barrier() };
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();

    const result = try runEarly425RetryHarness(allocator, &ctx, "GET", &block, 1, &.{ 425, 200 }, &header_counts);

    try std.testing.expectEqual(@as(u16, 425), result.downstream_status);
    try std.testing.expectEqual(@as(usize, 1), result.upstream_deliveries);
    try std.testing.expectEqual(@as(usize, 0), barrier.waits);
    try std.testing.expectEqualSlices(usize, &.{1}, header_counts.items);
}

test "semantic upstream 425 retry does not consume configured 5xx retry budget" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var barrier = TestEarly425Barrier{};
    var ctx = http.request_context.EarlyDataContext{ .transport_early = true, .downstream_handshake = barrier.barrier() };
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();

    const result = try runEarly425RetryHarness(allocator, &ctx, "GET", &block, 2, &.{ 425, 500, 200 }, &header_counts);

    try std.testing.expectEqual(@as(u16, 200), result.downstream_status);
    try std.testing.expectEqual(@as(usize, 3), result.upstream_deliveries);
    try std.testing.expectEqual(@as(usize, 1), barrier.waits);
    try std.testing.expectEqual(@as(usize, 1), result.early_425_retried);
    try std.testing.expectEqual(@as(usize, 1), result.early_retry_success);
    try std.testing.expectEqualSlices(usize, &.{ 1, 0, 0 }, header_counts.items);
}

test "stale retry remains transparent to configured retry budget without early data" {
    const allocator = std.testing.allocator;
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var ctx = http.request_context.EarlyDataContext{};
    var header_counts = std.array_list.Managed(usize).init(allocator);
    defer header_counts.deinit();
    var executor = ScriptedBufferedAttemptExecutor{
        .allocator = allocator,
        .upstream_statuses = &.{ 0, 500, 200 },
        .early_data_header_counts = &header_counts,
        .fail_attempt_index = 0,
        .fail_attempt_err = error.HttpConnectionClosing,
    };

    const result = try runBufferedProxyAttempts(&ctx, false, "GET", &block, 2, 1, true, &executor);

    switch (result) {
        .response => |response| {
            var mutable = response;
            defer mutable.deinit(allocator);
            try std.testing.expectEqual(@as(u16, 200), mutable.statusCode());
        },
        else => return error.TestUnexpectedTerminalProxyResult,
    }
    try std.testing.expectEqual(@as(usize, 2), executor.deliveries);
    try std.testing.expectEqual(@as(usize, 1), executor.execute_failures);
    try std.testing.expectEqual(@as(usize, 0), executor.early_425_retried);
    try std.testing.expectEqualSlices(usize, &.{ 0, 0, 0 }, header_counts.items);
}

test "buffered proxy attempts record RequestCancelled as upstream failure before terminating" {
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var ctx = http.request_context.EarlyDataContext{};
    var executor = ErrorBufferedAttemptExecutor{ .err = error.RequestCancelled };

    const result = try runBufferedProxyAttempts(&ctx, false, "GET", &block, 3, 0, true, &executor);

    try std.testing.expectEqual(std.meta.Tag(BufferedProxyAttemptsResult).request_cancelled, std.meta.activeTag(result));
    try std.testing.expectEqual(@as(usize, 1), executor.execute_calls);
    try std.testing.expectEqual(@as(usize, 1), executor.terminal_attempt_errors);
    try std.testing.expectEqual(@as(usize, 0), executor.configured_error_retries);
}

test "buffered proxy attempts stop on local retry budget exhaustion before upstream failure accounting" {
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var ctx = http.request_context.EarlyDataContext{};
    var executor = ErrorBufferedAttemptExecutor{ .err = error.ProxyBudgetExhausted };

    const result = try runBufferedProxyAttempts(&ctx, false, "GET", &block, 3, 0, true, &executor);

    try std.testing.expectEqual(std.meta.Tag(BufferedProxyAttemptsResult).retry_budget_exhausted, std.meta.activeTag(result));
    try std.testing.expectEqual(@as(usize, 1), executor.execute_calls);
    try std.testing.expectEqual(@as(usize, 0), executor.terminal_attempt_errors);
    try std.testing.expectEqual(@as(usize, 0), executor.configured_error_retries);
}

test "buffered proxy attempts fail fast when circuit breaker is open" {
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };
    var ctx = http.request_context.EarlyDataContext{};
    var executor = ErrorBufferedAttemptExecutor{ .err = error.CircuitOpen };

    const result = try runBufferedProxyAttempts(&ctx, false, "GET", &block, 3, 0, true, &executor);

    try std.testing.expectEqual(std.meta.Tag(BufferedProxyAttemptsResult).circuit_open, std.meta.activeTag(result));
    try std.testing.expectEqual(@as(usize, 1), executor.execute_calls);
    try std.testing.expectEqual(@as(usize, 0), executor.terminal_attempt_errors);
    try std.testing.expectEqual(@as(usize, 0), executor.configured_error_retries);
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

test "streaming eligibility returns typed fallback reasons" {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.proxy_streaming_mode = .response;
    cfg.upstream_tls_client_cert = "";

    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .proxy_streaming_policy = .inherit,
    };
    try std.testing.expectEqual(StreamingEligibility.stream, streamingEligibilityForDataPlaneProxyRequest(&cfg, &block, 1));
    try std.testing.expectEqualStrings("early_data_retry_semantics", StreamingFallbackReason.early_data_retry_semantics.label());

    var off_block = block;
    off_block.proxy_streaming_policy = .off;
    try std.testing.expectEqual(StreamingEligibility{ .fallback = .policy_disabled }, streamingEligibilityForDataPlaneProxyRequest(&cfg, &off_block, 1));
    try std.testing.expectEqual(StreamingEligibility{ .fallback = .retries_configured }, streamingEligibilityForDataPlaneProxyRequest(&cfg, &block, 2));

    // Unix-socket and upstream-mTLS targets stream like any other upstream
    // (#139) — neither forces the buffered path any more.
    cfg.upstream_tls_client_cert = "/cert.pem";
    try std.testing.expectEqual(StreamingEligibility.stream, streamingEligibilityForDataPlaneProxyRequest(&cfg, &block, 1));
}

test "route streaming policy can override global mode" {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.proxy_streaming_mode = .off;
    cfg.upstream_tls_client_cert = "";

    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/bulk/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
        .proxy_streaming_policy = .response,
    };

    try std.testing.expectEqual(StreamingEligibility.stream, streamingEligibilityForDataPlaneProxyRequest(&cfg, &block, 1));
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

    const matched = http.location_router.matchLocation(std.testing.allocator, "/ursa/health", &blocks).?;
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

    const matched = http.location_router.matchLocation(std.testing.allocator, "/ursa/download/file.bin", &blocks).?;
    const suffix = proxySuffixPathForLocation("/ursa/download/file.bin", matched, &blocks).?;
    try std.testing.expectEqualStrings("download/file.bin", suffix);
}

test "proxySuffixPathForLocation maps split upstream mount root to slash" {
    const blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/ursa/",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:6707" },
        },
    };

    const matched = http.location_router.matchLocation(std.testing.allocator, "/ursa/", &blocks).?;
    const suffix = proxySuffixPathForLocation("/ursa/", matched, &blocks).?;
    try std.testing.expectEqualStrings("/", suffix);
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
