//! Bounded control-plane/API upstream proxy helpers.
//!
//! This module owns the small JSON/control-plane proxy calls used by versioned
//! API routes and proxy-cache refreshes. Those calls may materialize upstream
//! responses in memory because every buffered read is capped by
//! `controlPlaneBufferedResponseLimit`. General location `proxy_pass` traffic
//! belongs in `gateway_proxy_runtime.zig`, where future streaming/backpressure
//! work can replace the current bounded-buffer compatibility executor.

const compat = @import("zig_compat.zig");
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
const gp = @import("gateway_proxy.zig");
const resolveProxyTarget = gp.resolveProxyTarget;
const buildForwardedFor = gp.buildForwardedFor;
const isTrustedUpstream = gp.isTrustedUpstream;
const appendRequestIdHeaders = gp.appendRequestIdHeaders;
const appendTrustedUpstreamHeaders = gp.appendTrustedUpstreamHeaders;
const executeBoundedBufferedUnixSocketHttpRequest = gp.executeBoundedBufferedUnixSocketHttpRequest;
const bufferedUpstreamResponseHasNoStore = gp.bufferedUpstreamResponseHasNoStore;
const upstreamResponseHasNoStore = gp.upstreamResponseHasNoStore;
const upstreamReasonPhrase = gp.upstreamReasonPhrase;
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
};

pub const ControlPlaneProxyExecution = union(enum) {
    streamed_status: struct {
        status: u16,
        upstream_addr: []const u8,
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
            ) catch |err| {
                state.recordUpstreamFailure(cfg, upstream_base_url);
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
                if (streamed.status >= 500) {
                    state.recordUpstreamFailure(cfg, upstream_base_url);
                } else {
                    state.recordUpstreamSuccess(cfg, upstream_base_url);
                }
                return exec;
            },
            .buffered => |res| {
                if (res.status >= 500) {
                    state.recordUpstreamFailure(cfg, upstream_base_url);
                    if (attempt + 1 < max_attempts) {
                        allocator.free(res.body);
                        allocator.free(res.content_type);
                        if (res.content_disposition) |cd| allocator.free(cd);
                        if (res.location) |location| allocator.free(location);
                        if (res.set_cookie) |cookie| allocator.free(cookie);
                        continue;
                    }
                } else {
                    state.recordUpstreamSuccess(cfg, upstream_base_url);
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

    var server_header_buffer: [16 * 1024]u8 = undefined;
    const uri = try std.Uri.parse(current_url);
    if (current_unix_socket_path) |socket_path| {
        var buffered_resp = try executeBoundedBufferedUnixSocketHttpRequest(
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
        );
        defer buffered_resp.deinit(allocator);

        const status_code = buffered_resp.status_code;
        const upstream_reason = buffered_resp.reason;
        const upstream_content_type = buffered_resp.headerValue("Content-Type") orelse JSON_CONTENT_TYPE;
        const upstream_content_disposition = buffered_resp.headerValue("Content-Disposition");
        const upstream_location = if (buffered_resp.headerValue("Location")) |location|
            try allocator.dupe(u8, location)
        else
            null;
        errdefer if (upstream_location) |location| allocator.free(location);
        const cacheable = !bufferedUpstreamResponseHasNoStore(&buffered_resp);
        const stream_status = enable_streaming_success and (status_code == 200 or cfg.proxy_stream_all_statuses);
        if (stream_status) {
            try writeStreamedUpstreamResponse(
                downstream_writer,
                status_code,
                upstream_reason,
                upstream_content_type,
                upstream_content_disposition,
                correlation_id,
                &state.security_headers,
                sticky_set_cookie,
            );
            if (buffered_resp.body.len > 0) {
                try writeChunk(downstream_writer, buffered_resp.body);
            }
            try downstream_writer.writeAll("0\r\n\r\n");
            return .{ .streamed_status = .{ .status = status_code, .upstream_addr = upstream_host } };
        }

        if (status_code != 200) {
            const buffered_content_type = try allocator.dupe(u8, upstream_content_type);
            errdefer allocator.free(buffered_content_type);
            const buffered_content_disposition = if (upstream_content_disposition) |cd|
                try allocator.dupe(u8, cd)
            else
                null;
            errdefer if (buffered_content_disposition) |cd| allocator.free(cd);
            const buffered_set_cookie = if (sticky_set_cookie) |cookie|
                try allocator.dupe(u8, cookie)
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
                },
            };
        }

        const body = try allocator.dupe(u8, buffered_resp.body);
        errdefer allocator.free(body);
        const buffered_content_type = try allocator.dupe(u8, upstream_content_type);
        errdefer allocator.free(buffered_content_type);
        const buffered_content_disposition = if (upstream_content_disposition) |cd|
            try allocator.dupe(u8, cd)
        else
            null;
        errdefer if (buffered_content_disposition) |cd| allocator.free(cd);
        const buffered_set_cookie = if (sticky_set_cookie) |cookie|
            try allocator.dupe(u8, cookie)
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
            },
        };
    }

    var req = try state.upstream_client.request(.POST, uri, .{
        .headers = .{ .content_type = .{ .override = "application/json" } },
        .extra_headers = extra_headers.items,
        .keep_alive = false,
        .redirect_behavior = .unhandled,
    });
    defer req.deinit();

    try req.sendBodyComplete(@constCast(payload));
    var resp = try req.receiveHead(&server_header_buffer);

    const status_code: u16 = @intFromEnum(resp.head.status);
    const upstream_reason = upstreamReasonPhrase(resp.head.status);
    const upstream_content_type = resp.head.content_type orelse JSON_CONTENT_TYPE;
    const upstream_content_disposition = resp.head.content_disposition;
    const upstream_location = if (resp.head.location) |location|
        try allocator.dupe(u8, location)
    else
        null;
    errdefer if (upstream_location) |location| allocator.free(location);
    const cacheable = !upstreamResponseHasNoStore(resp.head);
    const stream_status = enable_streaming_success and (status_code == 200 or cfg.proxy_stream_all_statuses);
    var resp_read_buf: [8192]u8 = undefined;
    if (stream_status) {
        try writeStreamedUpstreamResponse(
            downstream_writer,
            status_code,
            upstream_reason,
            upstream_content_type,
            upstream_content_disposition,
            correlation_id,
            &state.security_headers,
            sticky_set_cookie,
        );

        const read_buf = try state.relay_buffer_pool.acquire();
        defer state.relay_buffer_pool.release(read_buf);
        const body_reader = resp.reader(&resp_read_buf);
        while (true) {
            const n = try body_reader.read(read_buf);
            if (n == 0) break;
            try writeChunk(downstream_writer, read_buf[0..n]);
        }
        try downstream_writer.writeAll("0\r\n\r\n");
        return .{ .streamed_status = .{ .status = status_code, .upstream_addr = upstream_host } };
    }

    if (status_code != 200) {
        const buffered_content_type = try allocator.dupe(u8, upstream_content_type);
        errdefer allocator.free(buffered_content_type);
        const buffered_content_disposition = if (upstream_content_disposition) |cd|
            try allocator.dupe(u8, cd)
        else
            null;
        errdefer if (buffered_content_disposition) |cd| allocator.free(cd);
        const buffered_set_cookie = if (sticky_set_cookie) |cookie|
            try allocator.dupe(u8, cookie)
        else
            null;
        errdefer if (buffered_set_cookie) |cookie| allocator.free(cookie);

        const drain_buf = try state.relay_buffer_pool.acquire();
        defer state.relay_buffer_pool.release(drain_buf);
        const body_reader = resp.reader(&resp_read_buf);
        while (true) {
            const n = try body_reader.read(drain_buf);
            if (n == 0) break;
        }
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
            },
        };
    }

    const max_buffered = controlPlaneBufferedResponseLimit(cfg);
    const body = try resp.reader(&resp_read_buf).allocRemaining(allocator, .limited(max_buffered));
    errdefer allocator.free(body);
    const buffered_content_type = try allocator.dupe(u8, upstream_content_type);
    errdefer allocator.free(buffered_content_type);
    const buffered_content_disposition = if (upstream_content_disposition) |cd|
        try allocator.dupe(u8, cd)
    else
        null;
    errdefer if (buffered_content_disposition) |cd| allocator.free(cd);
    const buffered_set_cookie = if (sticky_set_cookie) |cookie|
        try allocator.dupe(u8, cookie)
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
        },
    };
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
