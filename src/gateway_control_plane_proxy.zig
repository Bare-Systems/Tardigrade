//! Bounded control-plane/API upstream proxy helpers.
//!
//! This module owns the small JSON/control-plane proxy calls used by versioned
//! API routes and proxy-cache refreshes. Those calls may materialize upstream
//! responses in memory because every buffered read is capped by
//! `controlPlaneBufferedResponseLimit`. General location `proxy_pass` traffic
//! belongs in `gateway_proxy_runtime.zig`, where future streaming/backpressure
//! work can replace the current bounded-buffer compatibility executor.

const compat = @import("zig_compat");
const builtin = @import("builtin");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gs = @import("gateway_state.zig");
const GatewayState = gs.GatewayState;
const UpstreamScope = gs.UpstreamScope;
const StickyAffinityRequest = gs.StickyAffinityRequest;
const StickyUpstreamSelection = gs.StickyUpstreamSelection;
const upstreamPoolForScope = gs.upstreamPoolForScope;
const upstreamScopeName = gs.upstreamScopeName;
const buildStickySetCookieHeader = gs.buildStickySetCookieHeader;
const isAbsoluteHttpUrl = gs.isAbsoluteHttpUrl;
const gp = @import("gateway_proxy.zig");
const resolveProxyTarget = gp.resolveProxyTarget;
const buildForwardedFor = gp.buildForwardedFor;
const isTrustedUpstream = gp.isTrustedUpstream;
const appendRequestIdHeaders = gp.appendRequestIdHeaders;
const appendTrustedUpstreamHeaders = gp.appendTrustedUpstreamHeaders;
const executeBoundedBufferedUnixSocketHttpRequest = gp.executeBoundedBufferedUnixSocketHttpRequest;
const executeBoundedBufferedTcpHttpRequest = gp.executeBoundedBufferedTcpHttpRequest;
const uriComponentBytes = gp.uriComponentBytes;
const bufferedUpstreamResponseHasNoStore = gp.bufferedUpstreamResponseHasNoStore;
const writeStreamedUpstreamResponse = gp.writeStreamedUpstreamResponse;
const writeChunk = gp.writeChunk;

const JSON_CONTENT_TYPE = "application/json";
const DEFAULT_CONTROL_PLANE_BUFFERED_RESPONSE_LIMIT: usize = 2 * 1024 * 1024;

/// Buffered control-plane responses are intentionally small and bounded. This
/// cap is separate from the data-plane proxy response cap because these calls
/// are API/control-plane helpers, not the general reverse-proxy hot path.
pub fn controlPlaneBufferedResponseLimit(cfg: *const edge_config.EdgeConfig) usize {
    return if (cfg.max_connection_memory_bytes > 0)
        cfg.max_connection_memory_bytes
    else
        DEFAULT_CONTROL_PLANE_BUFFERED_RESPONSE_LIMIT;
}

fn controlPlaneAttemptErrorCountsAsUpstreamFailure(err: anyerror) bool {
    return switch (err) {
        error.ControlPlaneResponseMaterializationFailed,
        error.OutOfMemory,
        error.UpstreamUntrusted,
        error.UpstreamAtCapacity,
        error.CircuitOpen,
        error.DownstreamWriteFailed,
        error.InvalidUri,
        error.InvalidFormat,
        error.UnsupportedUriScheme,
        error.MissingUriHost,
        => false,
        else => true,
    };
}

fn recordControlPlaneProxyFailure(
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    upstream_base_url: []const u8,
    absolute_target: bool,
    permit: http.circuit_breaker.Permit,
) void {
    if (absolute_target) {
        state.circuitRecordFailurePermit(permit);
    } else {
        state.recordProxyUpstreamFailure(cfg, upstream_base_url, permit);
    }
}

fn recordControlPlaneProxyStatus(
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    upstream_base_url: []const u8,
    absolute_target: bool,
    permit: http.circuit_breaker.Permit,
    status: u16,
) void {
    if (status >= 500) {
        recordControlPlaneProxyFailure(state, cfg, upstream_base_url, absolute_target, permit);
    } else {
        recordControlPlaneProxySuccess(state, cfg, upstream_base_url, absolute_target, permit);
    }
}

fn recordControlPlaneProxySuccess(
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    upstream_base_url: []const u8,
    absolute_target: bool,
    permit: http.circuit_breaker.Permit,
) void {
    if (absolute_target) {
        state.circuitRecordSuccessPermit(permit);
    } else {
        state.recordProxyUpstreamSuccess(cfg, upstream_base_url, permit);
    }
}

pub fn buildProxyCacheKey(
    allocator: std.mem.Allocator,
    key_template: []const u8,
    method: []const u8,
    path: []const u8,
    payload: []const u8,
    identity: ?[]const u8,
    api_version: ?u32,
) ![]u8 {
    var payload_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &payload_digest, .{});
    var payload_digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&payload_digest_hex, "{f}", .{compat.fmtSliceHexLower(&payload_digest)}) catch unreachable;

    const identity_value = identity orelse "-";
    var api_version_buf: [20]u8 = undefined;
    const api_version_value = if (api_version) |ver|
        std.fmt.bufPrint(&api_version_buf, "{d}", .{ver}) catch "-"
    else
        "-";

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var token_it = std.mem.splitScalar(u8, key_template, ':');
    var wrote_any = false;
    while (token_it.next()) |part| {
        const token = std.mem.trim(u8, part, " \t\r\n");
        if (token.len == 0) continue;
        const value: []const u8 = if (std.mem.eql(u8, token, "method"))
            method
        else if (std.mem.eql(u8, token, "path"))
            path
        else if (std.mem.eql(u8, token, "payload_sha256"))
            payload_digest_hex[0..]
        else if (std.mem.eql(u8, token, "identity"))
            identity_value
        else if (std.mem.eql(u8, token, "api_version"))
            api_version_value
        else
            continue;
        if (wrote_any) try out.append(allocator, ':');
        try out.appendSlice(allocator, value);
        wrote_any = true;
    }

    if (!wrote_any) {
        try out.appendSlice(allocator, method);
        try out.append(allocator, ':');
        try out.appendSlice(allocator, path);
        try out.append(allocator, ':');
        try out.appendSlice(allocator, payload_digest_hex[0..]);
    }
    return out.toOwnedSlice(allocator);
}

pub const ControlPlaneProxyResult = struct {
    status: u16,
    body: []u8,
    content_type: []u8,
    content_disposition: ?[]u8,
    location: ?[]u8,
    set_cookie: ?[]u8,
    cacheable: bool,
    upstream_addr: []const u8,
    accounted: bool = false,
};

pub const ControlPlaneProxyExecution = union(enum) {
    streamed_status: struct {
        status: u16,
        upstream_addr: []const u8,
        accounted: bool = false,
    },
    buffered: ControlPlaneProxyResult,
};

const ProxyCacheRefreshTask = struct {
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    cache_key: []u8,
    upstream_scope: UpstreamScope,
    proxy_pass_target: []const u8,
    suffix_path: ?[]u8,
    payload: []u8,
    client_ip: []u8,
    identity: ?[]u8,
    api_version: ?u32,
};

fn proxyCacheRefreshThread(task: *ProxyCacheRefreshTask) void {
    defer {
        task.state.proxyCacheUnlock(task.cache_key);
        task.allocator.free(task.cache_key);
        if (task.suffix_path) |suffix| task.allocator.free(suffix);
        task.allocator.free(task.payload);
        task.allocator.free(task.client_ip);
        if (task.identity) |id| task.allocator.free(id);
        task.allocator.destroy(task);
    }

    const exec = executeBoundedControlPlaneJsonProxy(
        task.allocator,
        task.cfg,
        task.upstream_scope,
        task.proxy_pass_target,
        task.suffix_path,
        task.payload,
        "proxy-cache-refresh",
        task.client_ip,
        task.identity,
        task.api_version,
        null,
        null,
        std.io.null_writer,
        task.state,
        false,
        null,
    ) catch return;

    switch (exec) {
        .streamed_status => {},
        .buffered => |result| {
            defer task.allocator.free(result.body);
            defer task.allocator.free(result.content_type);
            if (result.content_disposition) |cd| task.allocator.free(cd);
            if (result.location) |location| task.allocator.free(location);
            if (result.set_cookie) |cookie| task.allocator.free(cookie);
            if (result.status == 200) {
                task.state.proxyCachePut(task.cache_key, result.status, result.body, result.content_type) catch {}; // cache write is best-effort; a miss on the next request is acceptable
            }
        },
    }
}

fn spawnProxyCacheRefresh(
    _: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    cache_key: []const u8,
    upstream_scope: UpstreamScope,
    proxy_pass_target: []const u8,
    suffix_path: ?[]const u8,
    payload: []const u8,
    client_ip: []const u8,
    identity: ?[]const u8,
    api_version: ?u32,
) void {
    const task_allocator = state.allocator;
    if (!(state.proxyCacheTryLock(cache_key) catch false)) return;

    const task = task_allocator.create(ProxyCacheRefreshTask) catch {
        state.proxyCacheUnlock(cache_key);
        return;
    };
    errdefer task_allocator.destroy(task);

    const owned_key = task_allocator.dupe(u8, cache_key) catch {
        state.proxyCacheUnlock(cache_key);
        return;
    };
    errdefer task_allocator.free(owned_key);
    const owned_payload = task_allocator.dupe(u8, payload) catch {
        state.proxyCacheUnlock(cache_key);
        return;
    };
    errdefer task_allocator.free(owned_payload);
    const owned_ip = task_allocator.dupe(u8, client_ip) catch {
        state.proxyCacheUnlock(cache_key);
        return;
    };
    errdefer task_allocator.free(owned_ip);
    const owned_suffix = if (suffix_path) |suffix|
        task_allocator.dupe(u8, suffix) catch {
            state.proxyCacheUnlock(cache_key);
            return;
        }
    else
        null;
    errdefer if (owned_suffix) |s| task_allocator.free(s);
    const owned_identity = if (identity) |id|
        task_allocator.dupe(u8, id) catch {
            state.proxyCacheUnlock(cache_key);
            return;
        }
    else
        null;
    errdefer if (owned_identity) |id| task_allocator.free(id);

    task.* = .{
        .allocator = task_allocator,
        .cfg = cfg,
        .state = state,
        .cache_key = owned_key,
        .upstream_scope = upstream_scope,
        .proxy_pass_target = proxy_pass_target,
        .suffix_path = owned_suffix,
        .payload = owned_payload,
        .client_ip = owned_ip,
        .identity = owned_identity,
        .api_version = api_version,
    };

    const thread = std.Thread.spawn(.{}, proxyCacheRefreshThread, .{task}) catch {
        state.proxyCacheUnlock(cache_key);
        task_allocator.free(owned_key);
        task_allocator.free(owned_payload);
        task_allocator.free(owned_ip);
        if (owned_suffix) |s| task_allocator.free(s);
        if (owned_identity) |id| task_allocator.free(id);
        task_allocator.destroy(task);
        return;
    };
    thread.detach();
}

pub fn executeBoundedControlPlaneJsonProxy(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    upstream_scope: UpstreamScope,
    proxy_pass_target: []const u8,
    suffix_path: ?[]const u8,
    payload: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
    downstream_writer: anytype,
    state: *GatewayState,
    enable_streaming_success: bool,
    sticky_affinity: ?*const StickyAffinityRequest,
) !ControlPlaneProxyExecution {
    const upstream_pool = upstreamPoolForScope(cfg, upstream_scope);
    // JSON proxy always POSTs; respect the idempotent-only guard.
    const configured_attempts: usize = @intCast(@max(cfg.upstream_retry_attempts, @as(u32, 1)));
    const max_attempts: usize = if (cfg.upstream_retry_idempotent_only) 1 else configured_attempts;
    const start_ms = http.event_loop.monotonicMs();
    const upstream_hash_key = if (payload.len > 0) payload else (suffix_path orelse proxy_pass_target);
    const absolute_proxy_target = isAbsoluteHttpUrl(std.mem.trim(u8, proxy_pass_target, " \t\r\n"));

    var attempt: usize = 0;
    var last_err: ?anyerror = null;
    while (attempt < max_attempts) : (attempt += 1) {
        const per_attempt_timeout_ms: u32 = blk: {
            if (cfg.upstream_timeout_budget_ms == 0) break :blk cfg.upstream_timeout_ms;
            const elapsed_ms = http.event_loop.monotonicMs() - start_ms;
            if (elapsed_ms >= cfg.upstream_timeout_budget_ms) return error.Timeout;
            const remaining = cfg.upstream_timeout_budget_ms - elapsed_ms;
            if (cfg.upstream_timeout_ms == 0) {
                break :blk @intCast(@min(remaining, @as(u64, std.math.maxInt(u32))));
            }
            break :blk @intCast(@min(@as(u64, cfg.upstream_timeout_ms), remaining));
        };

        const selection = if (sticky_affinity) |value|
            state.nextStickyUpstreamBaseUrl(cfg, upstream_pool, client_ip, upstream_hash_key, value.requested_upstream)
        else
            StickyUpstreamSelection{ .base_url = state.nextUpstreamBaseUrl(cfg, upstream_pool, client_ip, upstream_hash_key), .used_requested = false };
        const upstream_base_url = selection.base_url;
        const sticky_set_cookie = if (sticky_affinity) |value|
            try buildStickySetCookieHeader(allocator, cfg, value, upstream_base_url)
        else
            null;
        defer if (sticky_set_cookie) |cookie| allocator.free(cookie);
        const circuit_permit = state.circuitTryAcquirePermit() orelse return error.CircuitOpen;
        state.recordUpstreamAttemptStart(upstream_base_url);
        const exec = blk: {
            defer state.recordUpstreamAttemptEnd(upstream_base_url);
            break :blk executeBoundedControlPlaneJsonProxyAttempt(
                allocator,
                cfg,
                upstream_scope,
                per_attempt_timeout_ms,
                upstream_base_url,
                proxy_pass_target,
                suffix_path,
                payload,
                correlation_id,
                client_ip,
                auth_identity,
                auth_user_id,
                auth_device_id,
                auth_scopes,
                api_version,
                incoming_host,
                incoming_x_forwarded_for,
                downstream_writer,
                state,
                enable_streaming_success,
                sticky_set_cookie,
                absolute_proxy_target,
                circuit_permit,
            ) catch |err| {
                if (err == error.DownstreamWriteFailed or err == error.ControlPlaneResponseMaterializationFailed) return err;
                if (controlPlaneAttemptErrorCountsAsUpstreamFailure(err)) {
                    recordControlPlaneProxyFailure(state, cfg, upstream_base_url, absolute_proxy_target, circuit_permit);
                } else {
                    state.circuitReleasePermit(circuit_permit);
                }
                last_err = err;
                if (attempt + 1 < max_attempts) {
                    state.logger.warn(correlation_id, "upstream attempt {d}/{d} failed: {}", .{ attempt + 1, max_attempts, err });
                    continue;
                }
                return err;
            };
        };
        switch (exec) {
            .streamed_status => |streamed| {
                if (!streamed.accounted) {
                    if (streamed.status >= 500) {
                        recordControlPlaneProxyFailure(state, cfg, upstream_base_url, absolute_proxy_target, circuit_permit);
                    } else {
                        recordControlPlaneProxySuccess(state, cfg, upstream_base_url, absolute_proxy_target, circuit_permit);
                    }
                }
                return exec;
            },
            .buffered => |res| {
                if (!res.accounted) {
                    recordControlPlaneProxyStatus(state, cfg, upstream_base_url, absolute_proxy_target, circuit_permit, res.status);
                }
                if (res.status >= 500) {
                    if (attempt + 1 < max_attempts) {
                        allocator.free(res.body);
                        allocator.free(res.content_type);
                        if (res.content_disposition) |cd| allocator.free(cd);
                        if (res.location) |location| allocator.free(location);
                        if (res.set_cookie) |cookie| allocator.free(cookie);
                        continue;
                    }
                }
                return exec;
            },
        }
    }

    return last_err orelse error.UpstreamUnavailable;
}

fn executeBoundedControlPlaneJsonProxyAttempt(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    upstream_scope: UpstreamScope,
    attempt_timeout_ms: u32,
    upstream_base_url: []const u8,
    proxy_pass_target: []const u8,
    suffix_path: ?[]const u8,
    payload: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
    downstream_writer: anytype,
    state: *GatewayState,
    enable_streaming_success: bool,
    sticky_set_cookie: ?[]const u8,
    absolute_proxy_target: bool,
    circuit_permit: http.circuit_breaker.Permit,
) !ControlPlaneProxyExecution {
    const proxy_json_extra_header_slack = 12;
    const proxy_json_owned_header_value_slack = 3;
    var extra_headers_stack = std.heap.stackFallback(2048, allocator);
    const extra_headers_allocator = extra_headers_stack.get();
    var owned_header_values_stack = std.heap.stackFallback(256, allocator);
    const owned_header_values_allocator = owned_header_values_stack.get();
    const resolved_target = try resolveProxyTarget(allocator, upstream_base_url, proxy_pass_target, suffix_path);
    const current_url = resolved_target.url;
    defer allocator.free(current_url);
    const current_unix_socket_path = resolved_target.unix_socket_path;

    var forwarded_for = try buildForwardedFor(allocator, incoming_x_forwarded_for, client_ip);
    defer forwarded_for.deinit(allocator);

    const forwarded_host = incoming_host orelse "";
    const forwarded_proto = if (edge_config.hasTlsFiles(cfg)) "https" else "http";
    const upstream_host = resolved_target.upstream_host;
    if (cfg.trust_require_upstream_identity and cfg.trust_shared_secret.len == 0) return error.UpstreamUntrusted;
    if (!isTrustedUpstream(cfg, upstream_host)) return error.UpstreamUntrusted;

    var extra_headers = std.array_list.Managed(std.http.Header).init(extra_headers_allocator);
    defer extra_headers.deinit();
    var owned_header_values = std.array_list.Managed([]u8).init(owned_header_values_allocator);
    defer {
        for (owned_header_values.items) |value| allocator.free(value);
        owned_header_values.deinit();
    }
    try extra_headers.ensureUnusedCapacity(proxy_json_extra_header_slack);
    try owned_header_values.ensureUnusedCapacity(proxy_json_owned_header_value_slack);
    try appendRequestIdHeaders(&extra_headers, correlation_id);
    try extra_headers.append(.{ .name = "X-Forwarded-For", .value = forwarded_for.value });
    try extra_headers.append(.{ .name = "X-Real-IP", .value = client_ip });
    try extra_headers.append(.{ .name = "X-Forwarded-Proto", .value = forwarded_proto });
    if (cfg.upstream_gunzip_enabled) {
        try extra_headers.append(.{ .name = "Accept-Encoding", .value = "gzip, identity" });
    }
    if (forwarded_host.len > 0) try extra_headers.append(.{ .name = "X-Forwarded-Host", .value = forwarded_host });
    if (auth_identity) |identity| {
        if (identity.len > 0) try extra_headers.append(.{ .name = "X-Tardigrade-Auth-Identity", .value = identity });
    }
    if (auth_user_id) |user_id| {
        if (user_id.len > 0) try extra_headers.append(.{ .name = "X-Tardigrade-User-ID", .value = user_id });
    }
    if (auth_device_id) |device_id| {
        if (device_id.len > 0) try extra_headers.append(.{ .name = "X-Tardigrade-Device-ID", .value = device_id });
    }
    if (auth_scopes) |scopes| {
        if (scopes.len > 0) try extra_headers.append(.{ .name = "X-Tardigrade-Scopes", .value = scopes });
    }
    if (api_version) |ver| {
        const api_version_value = try std.fmt.allocPrint(allocator, "{d}", .{ver});
        try owned_header_values.append(api_version_value);
        try extra_headers.append(.{ .name = "X-Tardigrade-Api-Version", .value = api_version_value });
    }
    try appendTrustedUpstreamHeaders(
        allocator,
        cfg,
        &extra_headers,
        &owned_header_values,
        resolved_target.url,
        correlation_id,
        client_ip,
        auth_identity,
        api_version,
        payload,
    );

    const uri = try std.Uri.parse(current_url);
    {
        // Control-plane upstreams are reached over a bounded manual transport
        // (Unix, TCP, or TLS) so per-phase connect/response timeouts are
        // enforced. This previously routed TCP/HTTPS through a shared
        // std.http.Client that could not bound a hung upstream (issue #196).
        var buffered_resp = if (current_unix_socket_path) |socket_path|
            try executeBoundedBufferedUnixSocketHttpRequest(
                allocator,
                socket_path,
                uri,
                "POST",
                extra_headers.items,
                payload,
                "application/json",
                controlPlaneBufferedResponseLimit(cfg),
                attempt_timeout_ms,
                cfg.upstream_response_timeout_ms,
                &state.upstream_pool, // unix keep-alive pooling (#239)
            )
        else blk: {
            const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
            const upstream_host_name = if (uri.host) |h| uriComponentBytes(h) else return error.UpstreamProtocolError;
            const upstream_port: u16 = uri.port orelse (if (is_https) @as(u16, 443) else 80);
            const tls_options: ?http.upstream_tls.UpstreamTlsOptions = if (is_https) .{
                .skip_verify = !cfg.upstream_tls_verify,
                .ca_bundle_path = cfg.upstream_tls_ca_bundle,
                .sni_override = cfg.upstream_tls_server_name,
                .client_cert_path = cfg.upstream_tls_client_cert,
                .client_key_path = cfg.upstream_tls_client_key,
            } else null;
            break :blk try executeBoundedBufferedTcpHttpRequest(
                allocator,
                upstream_host_name,
                upstream_port,
                tls_options,
                uri,
                "POST",
                extra_headers.items,
                payload,
                "application/json",
                controlPlaneBufferedResponseLimit(cfg),
                attempt_timeout_ms,
                cfg.upstream_response_timeout_ms,
                &state.upstream_pool, // keep-alive pooling for control-plane upstreams (#141 Phase 1c)
                null, // control plane stays on HTTP/1.1 (no h2 offer)
                false, // ... and no prior-knowledge h2c either (#237)
            );
        };
        defer buffered_resp.deinit(allocator);

        const status_code = buffered_resp.status_code;
        const upstream_reason = buffered_resp.reason;
        const upstream_content_type = buffered_resp.headerValue("Content-Type") orelse JSON_CONTENT_TYPE;
        const upstream_content_disposition = buffered_resp.headerValue("Content-Disposition");
        recordControlPlaneProxyStatus(state, cfg, upstream_base_url, absolute_proxy_target, circuit_permit, status_code);
        try maybeFailControlPlaneMaterializationAfterStatus();
        const upstream_location = if (buffered_resp.headerValue("Location")) |location|
            allocator.dupe(u8, location) catch return error.ControlPlaneResponseMaterializationFailed
        else
            null;
        errdefer if (upstream_location) |location| allocator.free(location);
        const cacheable = !bufferedUpstreamResponseHasNoStore(&buffered_resp);
        const stream_status = enable_streaming_success and (status_code == 200 or cfg.proxy_stream_all_statuses);
        if (stream_status) {
            writeStreamedUpstreamResponse(
                downstream_writer,
                status_code,
                upstream_reason,
                upstream_content_type,
                upstream_content_disposition,
                false,
                correlation_id,
                &state.security_headers,
                state.http3_alt_svc,
                sticky_set_cookie,
            ) catch return error.DownstreamWriteFailed;
            if (buffered_resp.body.len > 0) {
                writeChunk(downstream_writer, buffered_resp.body) catch return error.DownstreamWriteFailed;
            }
            downstream_writer.writeAll("0\r\n\r\n") catch return error.DownstreamWriteFailed;
            return .{ .streamed_status = .{ .status = status_code, .upstream_addr = upstream_host, .accounted = true } };
        }

        if (status_code != 200) {
            const buffered_content_type = allocator.dupe(u8, upstream_content_type) catch return error.ControlPlaneResponseMaterializationFailed;
            errdefer allocator.free(buffered_content_type);
            const buffered_content_disposition = if (upstream_content_disposition) |cd|
                allocator.dupe(u8, cd) catch return error.ControlPlaneResponseMaterializationFailed
            else
                null;
            errdefer if (buffered_content_disposition) |cd| allocator.free(cd);
            const buffered_set_cookie = if (sticky_set_cookie) |cookie|
                allocator.dupe(u8, cookie) catch return error.ControlPlaneResponseMaterializationFailed
            else
                null;
            errdefer if (buffered_set_cookie) |cookie| allocator.free(cookie);

            state.appendTranscript(
                upstreamScopeName(upstream_scope),
                proxy_pass_target,
                correlation_id,
                auth_identity,
                client_ip,
                current_url,
                payload,
                status_code,
                upstream_content_type,
                "",
                &.{},
            );
            return .{
                .buffered = .{
                    .status = status_code,
                    .body = try allocator.alloc(u8, 0),
                    .content_type = buffered_content_type,
                    .content_disposition = buffered_content_disposition,
                    .location = upstream_location,
                    .set_cookie = buffered_set_cookie,
                    .cacheable = false,
                    .upstream_addr = upstream_host,
                    .accounted = true,
                },
            };
        }

        const body = allocator.dupe(u8, buffered_resp.body) catch return error.ControlPlaneResponseMaterializationFailed;
        errdefer allocator.free(body);
        const buffered_content_type = allocator.dupe(u8, upstream_content_type) catch return error.ControlPlaneResponseMaterializationFailed;
        errdefer allocator.free(buffered_content_type);
        const buffered_content_disposition = if (upstream_content_disposition) |cd|
            allocator.dupe(u8, cd) catch return error.ControlPlaneResponseMaterializationFailed
        else
            null;
        errdefer if (buffered_content_disposition) |cd| allocator.free(cd);
        const buffered_set_cookie = if (sticky_set_cookie) |cookie|
            allocator.dupe(u8, cookie) catch return error.ControlPlaneResponseMaterializationFailed
        else
            null;
        errdefer if (buffered_set_cookie) |cookie| allocator.free(cookie);
        state.appendTranscript(
            upstreamScopeName(upstream_scope),
            proxy_pass_target,
            correlation_id,
            auth_identity,
            client_ip,
            current_url,
            payload,
            status_code,
            buffered_content_type,
            body,
            &.{},
        );
        return .{
            .buffered = .{
                .status = status_code,
                .body = body,
                .content_type = buffered_content_type,
                .content_disposition = buffered_content_disposition,
                .location = upstream_location,
                .set_cookie = buffered_set_cookie,
                .cacheable = cacheable,
                .upstream_addr = upstream_host,
                .accounted = true,
            },
        };
    }
}

var test_fail_control_plane_materialization_after_status: bool = false;

fn maybeFailControlPlaneMaterializationAfterStatus() !void {
    if (builtin.is_test and test_fail_control_plane_materialization_after_status) return error.ControlPlaneResponseMaterializationFailed;
}

test "control-plane buffered response limit is explicit and bounded" {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.max_connection_memory_bytes = 0;
    try std.testing.expectEqual(
        @as(usize, DEFAULT_CONTROL_PLANE_BUFFERED_RESPONSE_LIMIT),
        controlPlaneBufferedResponseLimit(&cfg),
    );

    cfg.max_connection_memory_bytes = 512 * 1024;
    try std.testing.expectEqual(@as(usize, 512 * 1024), controlPlaneBufferedResponseLimit(&cfg));
}

const ControlPlaneTestOrigin = struct {
    listen_fd: std.posix.fd_t,
    listen_port: u16,
    statuses: []const u16,
    request_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    thread: ?std.Thread = null,

    fn start(allocator: std.mem.Allocator, statuses: []const u16) !ControlPlaneTestOrigin {
        _ = allocator;
        const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
        try std.testing.expect(listen_fd >= 0);
        _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));
        var sin = std.c.sockaddr.in{
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
            .listen_fd = listen_fd,
            .listen_port = std.mem.bigToNative(u16, bound.port),
            .statuses = statuses,
        };
    }

    fn run(self: *ControlPlaneTestOrigin) !void {
        self.thread = try std.Thread.spawn(.{}, ControlPlaneTestOrigin.serve, .{self});
    }

    fn stop(self: *ControlPlaneTestOrigin) void {
        _ = std.c.close(self.listen_fd);
        if (self.thread) |thread| thread.join();
        self.thread = null;
    }

    fn port(self: *const ControlPlaneTestOrigin) u16 {
        return self.listen_port;
    }

    fn requestCount(self: *const ControlPlaneTestOrigin) usize {
        return self.request_count.load(.monotonic);
    }

    fn serve(self: *ControlPlaneTestOrigin) void {
        while (self.request_count.load(.monotonic) < self.statuses.len) {
            const fd = std.c.accept(self.listen_fd, null, null);
            if (fd < 0) return;
            defer _ = std.c.close(fd);
            var req_buf: [2048]u8 = undefined;
            _ = std.c.read(fd, &req_buf, req_buf.len);
            const idx = self.request_count.fetchAdd(1, .monotonic);
            const status = self.statuses[@min(idx, self.statuses.len - 1)];
            const body = if (status == 200) "ok" else "fail";
            var response_buf: [256]u8 = undefined;
            const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 {d} test\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
                status,
                body.len,
                body,
            }) catch return;
            _ = std.c.write(fd, response.ptr, response.len);
        }
    }
};

const FailingControlPlaneDownstreamWriter = struct {
    pub fn writeAll(_: FailingControlPlaneDownstreamWriter, _: []const u8) !void {
        return error.TestDownstreamWriteFailed;
    }

    pub fn print(self: FailingControlPlaneDownstreamWriter, comptime _: []const u8, _: anytype) !void {
        return self.writeAll("");
    }
};

fn initControlPlaneProxyTestConfig(upstream_base_url: []const u8) edge_config.EdgeConfig {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.upstream_base_url = upstream_base_url;
    cfg.upstream_base_urls = &.{};
    cfg.upstream_base_url_weights = &.{};
    cfg.upstream_backup_base_urls = &.{};
    cfg.upstream_chat_base_urls = &.{};
    cfg.upstream_chat_base_url_weights = &.{};
    cfg.upstream_chat_backup_base_urls = &.{};
    cfg.upstream_commands_base_urls = &.{};
    cfg.upstream_commands_base_url_weights = &.{};
    cfg.upstream_commands_backup_base_urls = &.{};
    cfg.upstream_retry_attempts = 1;
    cfg.upstream_retry_idempotent_only = true;
    cfg.upstream_timeout_ms = 1000;
    cfg.upstream_connect_timeout_ms = 1000;
    cfg.upstream_response_timeout_ms = 1000;
    cfg.upstream_timeout_budget_ms = 0;
    cfg.upstream_gunzip_enabled = false;
    cfg.upstream_pool_enabled = false;
    cfg.upstream_pool_max_active_per_host = 0;
    cfg.upstream_pool_max_idle_per_host = 0;
    cfg.upstream_pool_idle_timeout_ms = 0;
    cfg.upstream_pool_max_lifetime_ms = 0;
    cfg.upstream_tls_verify = false;
    cfg.upstream_tls_ca_bundle = "";
    cfg.upstream_tls_server_name = "";
    cfg.upstream_tls_client_cert = "";
    cfg.upstream_tls_client_key = "";
    cfg.trust_require_upstream_identity = false;
    cfg.trust_shared_secret = "";
    cfg.trust_gateway_id = "";
    cfg.trusted_upstream_identities = &.{};
    cfg.trusted_proxy_cidrs = &.{};
    cfg.max_connection_memory_bytes = 0;
    cfg.upstream_max_fails = 1;
    cfg.upstream_fail_timeout_ms = 60_000;
    cfg.upstream_active_health_interval_ms = 0;
    cfg.upstream_slow_start_ms = 0;
    cfg.proxy_stream_all_statuses = false;
    cfg.tls_cert_path = "";
    cfg.tls_key_path = "";
    return cfg;
}

fn initControlPlaneProxyTestState(state: *GatewayState, allocator: std.mem.Allocator) void {
    state.allocator = allocator;
    state.upstream_mutex = .{};
    state.circuit_mutex = .{};
    state.metrics_mutex = .{};
    state.transcript_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    state.logger = http.logger.Logger.init(.err, "test");
    state.security_headers = .{};
    state.http3_alt_svc = null;
    state.transcript_store_path = "";
    state.upstream_rr_index = 0;
    state.upstream_backup_rr_index = 0;
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 30_000 });
    state.upstream_health = std.StringHashMap(gs.UpstreamHealth).init(allocator);
    state.upstream_active_requests = std.StringHashMap(usize).init(allocator);
    state.upstream_pool = http.upstream_pool.UpstreamPool.init(allocator, .{});
    state.h2_pool = http.upstream_h2.H2ConnPool.init(allocator, .{});
}

fn deinitControlPlaneProxyTestState(state: *GatewayState) void {
    var h_it = state.upstream_health.iterator();
    while (h_it.next()) |entry| state.allocator.free(entry.key_ptr.*);
    state.upstream_health.deinit();
    var a_it = state.upstream_active_requests.iterator();
    while (a_it.next()) |entry| state.allocator.free(entry.key_ptr.*);
    state.upstream_active_requests.deinit();
    state.upstream_pool.deinit();
    state.h2_pool.deinit();
}

test "control-plane downstream streaming write failure records known 200 and never retries" {
    const allocator = std.testing.allocator;
    var origin = try ControlPlaneTestOrigin.start(allocator, &.{200});
    defer origin.stop();
    try origin.run();

    var state: GatewayState = undefined;
    initControlPlaneProxyTestState(&state, allocator);
    defer deinitControlPlaneProxyTestState(&state);
    var cfg = initControlPlaneProxyTestConfig("http://configured.example");
    cfg.upstream_retry_idempotent_only = false;
    cfg.upstream_retry_attempts = 3;
    const target = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/api", .{origin.port()});
    defer allocator.free(target);
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    state.circuitRecordFailurePermit(state.circuitTryAcquirePermit().?);

    try std.testing.expectError(error.DownstreamWriteFailed, executeBoundedControlPlaneJsonProxy(
        allocator,
        &cfg,
        .global,
        target,
        null,
        "{}",
        "test-correlation",
        "127.0.0.1",
        null,
        null,
        null,
        null,
        null,
        "localhost",
        null,
        FailingControlPlaneDownstreamWriter{},
        &state,
        true,
        null,
    ));

    try std.testing.expectEqual(@as(usize, 1), origin.requestCount());
    try std.testing.expectEqual(@as(usize, 0), state.upstreamUnhealthyCount());
    try std.testing.expectEqualStrings("closed", state.circuitStateName());
}

test "control-plane downstream streaming write failure records known 500 and never retries" {
    const allocator = std.testing.allocator;
    var origin = try ControlPlaneTestOrigin.start(allocator, &.{500});
    defer origin.stop();
    try origin.run();

    var state: GatewayState = undefined;
    initControlPlaneProxyTestState(&state, allocator);
    defer deinitControlPlaneProxyTestState(&state);
    var cfg = initControlPlaneProxyTestConfig("http://configured.example");
    cfg.proxy_stream_all_statuses = true;
    cfg.upstream_retry_idempotent_only = false;
    cfg.upstream_retry_attempts = 3;
    const target = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/api", .{origin.port()});
    defer allocator.free(target);
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    state.circuitRecordFailurePermit(state.circuitTryAcquirePermit().?);

    try std.testing.expectError(error.DownstreamWriteFailed, executeBoundedControlPlaneJsonProxy(
        allocator,
        &cfg,
        .global,
        target,
        null,
        "{}",
        "test-correlation",
        "127.0.0.1",
        null,
        null,
        null,
        null,
        null,
        "localhost",
        null,
        FailingControlPlaneDownstreamWriter{},
        &state,
        true,
        null,
    ));

    try std.testing.expectEqual(@as(usize, 1), origin.requestCount());
    try std.testing.expectEqual(@as(usize, 0), state.upstreamUnhealthyCount());
    try std.testing.expectEqualStrings("open", state.circuitStateName());
    try std.testing.expect(state.circuitTryAcquirePermit() != null);
}

test "control-plane post-status materialization failure records known 200 and never retries" {
    const allocator = std.testing.allocator;
    var origin = try ControlPlaneTestOrigin.start(allocator, &.{200});
    defer origin.stop();
    try origin.run();

    var state: GatewayState = undefined;
    initControlPlaneProxyTestState(&state, allocator);
    defer deinitControlPlaneProxyTestState(&state);
    var cfg = initControlPlaneProxyTestConfig("http://configured.example");
    cfg.upstream_retry_idempotent_only = false;
    cfg.upstream_retry_attempts = 3;
    const target = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/api", .{origin.port()});
    defer allocator.free(target);
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    state.circuitRecordFailurePermit(state.circuitTryAcquirePermit().?);

    test_fail_control_plane_materialization_after_status = true;
    defer test_fail_control_plane_materialization_after_status = false;
    var body_buf: [1024]u8 = undefined;
    var body_writer = compat.fixedBufferStream(&body_buf);
    try std.testing.expectError(error.ControlPlaneResponseMaterializationFailed, executeBoundedControlPlaneJsonProxy(
        allocator,
        &cfg,
        .global,
        target,
        null,
        "{}",
        "test-correlation",
        "127.0.0.1",
        null,
        null,
        null,
        null,
        null,
        "localhost",
        null,
        body_writer.writer(),
        &state,
        false,
        null,
    ));

    try std.testing.expectEqual(@as(usize, 1), origin.requestCount());
    try std.testing.expectEqual(@as(usize, 0), state.upstreamUnhealthyCount());
    try std.testing.expectEqualStrings("closed", state.circuitStateName());
}

test "control-plane post-status materialization failure records known 500 and never retries" {
    const allocator = std.testing.allocator;
    var origin = try ControlPlaneTestOrigin.start(allocator, &.{500});
    defer origin.stop();
    try origin.run();

    var state: GatewayState = undefined;
    initControlPlaneProxyTestState(&state, allocator);
    defer deinitControlPlaneProxyTestState(&state);
    var cfg = initControlPlaneProxyTestConfig("http://configured.example");
    cfg.upstream_retry_idempotent_only = false;
    cfg.upstream_retry_attempts = 3;
    const target = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/api", .{origin.port()});
    defer allocator.free(target);
    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    state.circuitRecordFailurePermit(state.circuitTryAcquirePermit().?);

    test_fail_control_plane_materialization_after_status = true;
    defer test_fail_control_plane_materialization_after_status = false;
    var body_buf: [1024]u8 = undefined;
    var body_writer = compat.fixedBufferStream(&body_buf);
    try std.testing.expectError(error.ControlPlaneResponseMaterializationFailed, executeBoundedControlPlaneJsonProxy(
        allocator,
        &cfg,
        .global,
        target,
        null,
        "{}",
        "test-correlation",
        "127.0.0.1",
        null,
        null,
        null,
        null,
        null,
        "localhost",
        null,
        body_writer.writer(),
        &state,
        false,
        null,
    ));

    try std.testing.expectEqual(@as(usize, 1), origin.requestCount());
    try std.testing.expectEqual(@as(usize, 0), state.upstreamUnhealthyCount());
    try std.testing.expectEqualStrings("open", state.circuitStateName());
    try std.testing.expect(state.circuitTryAcquirePermit() != null);
}

test "control-plane absolute target outcomes do not mutate configured passive health" {
    const allocator = std.testing.allocator;
    var origin = try ControlPlaneTestOrigin.start(allocator, &.{ 500, 200 });
    defer origin.stop();
    try origin.run();

    var state: GatewayState = undefined;
    initControlPlaneProxyTestState(&state, allocator);
    defer deinitControlPlaneProxyTestState(&state);
    var cfg = initControlPlaneProxyTestConfig("http://configured.example");
    const target = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/api", .{origin.port()});
    defer allocator.free(target);

    var body_buf_1: [1024]u8 = undefined;
    var body_writer_1 = compat.fixedBufferStream(&body_buf_1);
    var exec_1 = try executeBoundedControlPlaneJsonProxy(
        allocator,
        &cfg,
        .global,
        target,
        null,
        "{}",
        "test-correlation",
        "127.0.0.1",
        null,
        null,
        null,
        null,
        null,
        "localhost",
        null,
        body_writer_1.writer(),
        &state,
        false,
        null,
    );
    defer switch (exec_1) {
        .buffered => |*res| {
            allocator.free(res.body);
            allocator.free(res.content_type);
            if (res.content_disposition) |cd| allocator.free(cd);
            if (res.location) |location| allocator.free(location);
            if (res.set_cookie) |cookie| allocator.free(cookie);
        },
        .streamed_status => {},
    };

    try std.testing.expectEqual(@as(usize, 0), state.upstreamUnhealthyCount());
    try std.testing.expect(state.circuitTryAcquirePermit() == null);

    state.circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{});
    state.recordUpstreamFailure(&cfg, cfg.upstream_base_url);
    try std.testing.expectEqual(@as(usize, 1), state.upstreamUnhealthyCount());

    var body_buf_2: [1024]u8 = undefined;
    var body_writer_2 = compat.fixedBufferStream(&body_buf_2);
    var exec_2 = try executeBoundedControlPlaneJsonProxy(
        allocator,
        &cfg,
        .global,
        target,
        null,
        "{}",
        "test-correlation",
        "127.0.0.1",
        null,
        null,
        null,
        null,
        null,
        "localhost",
        null,
        body_writer_2.writer(),
        &state,
        false,
        null,
    );
    defer switch (exec_2) {
        .buffered => |*res| {
            allocator.free(res.body);
            allocator.free(res.content_type);
            if (res.content_disposition) |cd| allocator.free(cd);
            if (res.location) |location| allocator.free(location);
            if (res.set_cookie) |cookie| allocator.free(cookie);
        },
        .streamed_status => {},
    };

    try std.testing.expectEqual(@as(usize, 1), state.upstreamUnhealthyCount());
    try std.testing.expectEqual(@as(usize, 2), origin.requestCount());
}

test "buildProxyCacheKey supports template tokens" {
    const allocator = std.testing.allocator;
    const key = try buildProxyCacheKey(
        allocator,
        "method:path:identity:api_version",
        "POST",
        "/api/messages",
        "{\"message\":\"hello\"}",
        "identity-1",
        2,
    );
    defer allocator.free(key);
    try std.testing.expectEqualStrings("POST:/api/messages:identity-1:2", key);
}

test "buildProxyCacheKey falls back for unknown template tokens" {
    const allocator = std.testing.allocator;
    const payload = "{\"command\":\"list_tools\"}";
    const key = try buildProxyCacheKey(
        allocator,
        "unknown:also_unknown",
        "POST",
        "/api/tasks",
        payload,
        null,
        null,
    );
    defer allocator.free(key);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    const expected = try std.fmt.allocPrint(allocator, "POST:/api/tasks:{f}", .{compat.fmtSliceHexLower(&digest)});
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, key);
}
