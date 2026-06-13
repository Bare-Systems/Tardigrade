//! Hot reload, shutdown-adjacent maintenance, and background probe helpers for
//! the edge gateway runtime. The main gateway loop owns event dispatch; this
//! module owns reload state mutation and timer-triggered maintenance work.

const compat = @import("zig_compat.zig");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gp = @import("gateway_proxy.zig");
const gc = @import("gateway_connection.zig");
const gs = @import("gateway_state.zig");

const GatewayState = gs.GatewayState;
const WorkerContext = gs.WorkerContext;
const ReloadableConfigStore = gs.ReloadableConfigStore;
const MAX_REQUEST_SIZE = gs.MAX_REQUEST_SIZE;
const computeHstsValue = gp.computeHstsValue;
const unixSocketPathFromEndpoint = gp.unixSocketPathFromEndpoint;
const uriComponentBytes = gp.uriComponentBytes;
const setSocketTimeoutMs = gc.setSocketTimeoutMs;

pub fn hotReloadConfig(
    allocator: std.mem.Allocator,
    worker_ctx: *WorkerContext,
    state: *GatewayState,
    http3_dispatch_ctx: anytype,
) void {
    const now_ms = compat.milliTimestamp();
    state.metricsRecordReloadAttempt();
    state.logger.info(null, "configuration hot-reload starting", .{});
    const loaded = edge_config.loadFromEnv(allocator) catch |err| {
        const msg = std.fmt.bufPrint(&state.last_reload_error, "load failed: {}", .{err}) catch "load failed";
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        state.last_reload_error_len = msg.len;
        state.reload_mutex.unlock();
        state.metricsRecordReloadFailure();
        state.logger.warn(null, "config reload failed during load: {}", .{err});
        return;
    };
    edge_config.validate(&loaded) catch |err| {
        var rejected = loaded;
        rejected.deinit(allocator);
        const msg = std.fmt.bufPrint(&state.last_reload_error, "validation rejected: {}", .{err}) catch "validation rejected";
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        state.last_reload_error_len = msg.len;
        state.reload_mutex.unlock();
        state.metricsRecordReloadFailure();
        state.logger.warn(null, "config reload rejected by validation: {}", .{err});
        return;
    };
    edge_config.warnRiskyConfig(&loaded);
    const cfg_ptr = allocator.create(edge_config.EdgeConfig) catch {
        var rejected = loaded;
        rejected.deinit(allocator);
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        @memcpy(state.last_reload_error[0..19], "allocation failed  ");
        state.last_reload_error_len = 19;
        state.reload_mutex.unlock();
        state.metricsRecordReloadFailure();
        state.logger.warn(null, "config reload allocation failed", .{});
        return;
    };
    cfg_ptr.* = loaded;
    const prepared_version = worker_ctx.config_store.prepareOwned(cfg_ptr) catch {
        cfg_ptr.deinit(allocator);
        allocator.destroy(cfg_ptr);
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        @memcpy(state.last_reload_error[0..21], "bookkeeping failed   ");
        state.last_reload_error_len = 21;
        state.reload_mutex.unlock();
        state.metricsRecordReloadFailure();
        state.logger.warn(null, "config reload bookkeeping failed", .{});
        return;
    };

    applyReloadedRuntimeConfig(cfg_ptr, state);
    worker_ctx.config_store.installPrepared(prepared_version);
    http3_dispatch_ctx.cfg = cfg_ptr;
    http.access_log.deinit();
    http.access_log.init(allocator, .{
        .format = cfg_ptr.access_log_format,
        .custom_template = cfg_ptr.access_log_template,
        .min_status = cfg_ptr.access_log_min_status,
        .buffer_size_bytes = cfg_ptr.access_log_buffer_size,
        .syslog_udp_endpoint = cfg_ptr.access_log_syslog_udp,
        .redact_header_names = cfg_ptr.log_redact_headers,
    }) catch {}; // access log is best-effort; gateway continues without it
    state.reload_mutex.lock();
    state.last_reload_ok = true;
    state.last_reload_at_ms = now_ms;
    state.last_reload_error_len = 0;
    state.reload_mutex.unlock();
    state.metricsRecordReloadSuccess();
    state.logger.info(null, "configuration hot-reload applied", .{});
}

fn applyReloadedRuntimeConfig(cfg: *const edge_config.EdgeConfig, state: *GatewayState) void {
    // Warn when restart-only path/URL fields differ; they are NOT rebound here.
    if (!std.mem.eql(u8, state.session_store_path, cfg.session_store_path))
        state.logger.warn(null, "TARDIGRADE_SESSION_STORE_PATH changed on reload; restart required for new path to take effect (active: '{s}', new: '{s}')", .{ state.session_store_path, cfg.session_store_path });
    if (!std.mem.eql(u8, state.approval_store_path, cfg.approval_store_path))
        state.logger.warn(null, "TARDIGRADE_APPROVAL_STORE_PATH changed on reload; restart required for new path to take effect (active: '{s}', new: '{s}')", .{ state.approval_store_path, cfg.approval_store_path });
    if (!std.mem.eql(u8, state.approval_escalation_webhook, cfg.approval_escalation_webhook))
        state.logger.warn(null, "TARDIGRADE_APPROVAL_ESCALATION_WEBHOOK changed on reload; restart required for new URL to take effect (active: '{s}', new: '{s}')", .{ state.approval_escalation_webhook, cfg.approval_escalation_webhook });
    if (!std.mem.eql(u8, state.transcript_store_path, cfg.transcript_store_path))
        state.logger.warn(null, "TARDIGRADE_TRANSCRIPT_STORE_PATH changed on reload; restart required for new path to take effect (active: '{s}', new: '{s}')", .{ state.transcript_store_path, cfg.transcript_store_path });

    state.rate_limiter_mutex.lock();
    if (state.rate_limiter) |*rl| rl.deinit();
    state.rate_limiter = if (cfg.rate_limit_rps > 0)
        http.rate_limiter.RateLimiter.init(state.allocator, cfg.rate_limit_rps, cfg.rate_limit_burst)
    else
        null;
    state.rate_limiter_mutex.unlock();

    state.proxy_cache_mutex.lock();
    if (state.proxy_cache_store) |*pc| pc.deinit();
    state.proxy_cache_store = if (cfg.proxy_cache_ttl_seconds > 0)
        http.idempotency.IdempotencyStore.init(state.allocator, cfg.proxy_cache_ttl_seconds)
    else
        null;
    state.proxy_cache_path = cfg.proxy_cache_path;
    state.proxy_cache_ttl_seconds = cfg.proxy_cache_ttl_seconds;
    state.proxy_cache_mutex.unlock();

    state.runtime_mutex.lock();
    state.add_headers = cfg.add_headers;
    if (state.http3_alt_svc) |value| state.allocator.free(value);
    state.http3_alt_svc = if (cfg.http3_enabled) http.http3_handler.formatAltSvc(state.allocator, cfg.quic_port) catch null else null;
    if (state.hsts_value.len > 0) state.allocator.free(state.hsts_value);
    state.hsts_value = computeHstsValue(state.allocator, cfg) catch &.{};
    state.security_headers = blk: {
        var s = if (cfg.security_headers_enabled)
            http.security_headers.SecurityHeaders.api
        else
            http.security_headers.SecurityHeaders{ .x_frame_options = "", .x_content_type_options = "", .content_security_policy = "", .strict_transport_security = "", .referrer_policy = "", .permissions_policy = "", .x_xss_protection = "", .cross_origin_opener_policy = "", .cross_origin_resource_policy = "" };
        s.strict_transport_security = state.hsts_value;
        break :blk s;
    };
    state.max_connections_per_ip = cfg.max_connections_per_ip;
    state.max_active_connections = cfg.max_active_connections;
    state.max_in_flight_requests = cfg.max_in_flight_requests;
    state.max_total_connection_memory_bytes = cfg.max_total_connection_memory_bytes;
    state.connection_memory_estimate_bytes = if (cfg.max_connection_memory_bytes > 0) cfg.max_connection_memory_bytes else MAX_REQUEST_SIZE;
    state.compression_config = .{
        .enabled = cfg.compression_enabled,
        .min_size = cfg.compression_min_size,
        .brotli_enabled = cfg.compression_brotli_enabled,
        .brotli_quality = cfg.compression_brotli_quality,
    };
    state.logger.min_level = cfg.log_level;
    state.runtime_mutex.unlock();
}

pub fn reopenErrorLog(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.error_log_path.len == 0 or std.ascii.eqlIgnoreCase(cfg.error_log_path, "stderr")) return;
    var fc = try compat.cwd().createFile(cfg.error_log_path, .{ .truncate = false, .read = false });
    defer fc.close();
    _ = std.c.lseek(fc.file.handle, 0, std.c.SEEK.END);
    _ = std.c.dup2(fc.file.handle, std.Io.File.stderr().handle);
}

/// Refresh DNS-discovered upstreams when the refresh interval has elapsed.
/// Discovered addresses supplement the statically configured upstream pool
/// via GatewayState.dns_discovery; the selection functions read from both.
pub fn runDnsDiscoveryRefresh(_: *const edge_config.EdgeConfig, state: *GatewayState) void {
    const now_ms = http.event_loop.monotonicMs();
    if (state.dns_discovery.needsRefresh(now_ms)) {
        state.dns_discovery.refresh(now_ms);
    }
}

/// Context passed to the background health-probe thread.
const HealthProbeTask = struct {
    state: *GatewayState,
    config_store: *ReloadableConfigStore,
    allocator: std.mem.Allocator,
};

/// Background thread that runs all active health probes without blocking the
/// main event loop. Clears GatewayState.health_probe_running on completion.
fn activeHealthProbeThread(task: *HealthProbeTask) void {
    const allocator = task.allocator;
    const state = task.state;
    const config_store = task.config_store;
    allocator.destroy(task);

    defer state.health_probe_running.store(false, .release);

    var cfg_lease = config_store.acquire();
    defer cfg_lease.release();
    const cfg = cfg_lease.cfg;

    if (cfg.upstream_base_urls.len > 0) {
        for (cfg.upstream_base_urls) |base_url| {
            probeSingleUpstream(cfg, state, base_url);
        }
        for (cfg.upstream_backup_base_urls) |base_url| {
            probeSingleUpstream(cfg, state, base_url);
        }
    } else {
        probeSingleUpstream(cfg, state, cfg.upstream_base_url);
    }

    for (cfg.upstream_chat_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, base_url);
    }
    for (cfg.upstream_chat_backup_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, base_url);
    }
    for (cfg.upstream_commands_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, base_url);
    }
    for (cfg.upstream_commands_backup_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, base_url);
    }

    // Also probe DNS-discovered upstreams when active health checks are enabled.
    if (state.dns_discovery.config.host.len > 0) {
        state.dns_discovery.mutex.lock();
        // Snapshot URLs under the discovery lock, then probe without it to avoid
        // blocking the discovery refresh thread.
        var discovered_buf: [32][]u8 = undefined;
        const n = @min(state.dns_discovery.urls.items.len, discovered_buf.len);
        for (state.dns_discovery.urls.items[0..n], 0..) |url, i| discovered_buf[i] = url;
        state.dns_discovery.mutex.unlock();
        for (discovered_buf[0..n]) |url| {
            probeSingleUpstream(cfg, state, url);
        }
    }

    state.metrics_mutex.lock();
    state.metrics.recordHealthProbeRun();
    state.metrics_mutex.unlock();
}

/// Schedule a background health-probe batch if one is not already running.
/// Returns immediately; actual probing runs in a detached thread so the main
/// event loop is never blocked by upstream HTTP round-trips.
pub fn runActiveHealthChecks(cfg: *const edge_config.EdgeConfig, state: *GatewayState, config_store: *ReloadableConfigStore) void {
    if (cfg.upstream_active_health_interval_ms == 0) return;

    const now_ms = http.event_loop.monotonicMs();
    if (state.next_active_health_probe_ms != 0 and now_ms < state.next_active_health_probe_ms) return;
    state.next_active_health_probe_ms = now_ms + cfg.upstream_active_health_interval_ms;

    // Skip if a previous batch is still in flight.
    if (state.health_probe_running.load(.acquire)) return;
    state.health_probe_running.store(true, .release);

    const task = state.allocator.create(HealthProbeTask) catch {
        state.health_probe_running.store(false, .release);
        return;
    };
    task.* = .{
        .state = state,
        .config_store = config_store,
        .allocator = state.allocator,
    };

    const thread = std.Thread.spawn(.{}, activeHealthProbeThread, .{task}) catch {
        state.health_probe_running.store(false, .release);
        state.allocator.destroy(task);
        return;
    };
    thread.detach();
}

const activeHealthConfig = gs.activeHealthConfig;

pub fn runProxyCacheMaintenance(cfg: *const edge_config.EdgeConfig, state: *GatewayState) void {
    if (cfg.proxy_cache_ttl_seconds == 0) return;
    const interval = cfg.proxy_cache_manager_interval_ms;
    if (interval == 0) return;
    const now_ms = http.event_loop.monotonicMs();
    if (state.next_proxy_cache_maintenance_ms != 0 and now_ms < state.next_proxy_cache_maintenance_ms) return;
    state.next_proxy_cache_maintenance_ms = now_ms + interval;

    state.proxy_cache_mutex.lock();
    defer state.proxy_cache_mutex.unlock();
    if (state.proxy_cache_store) |*store| {
        _ = store.cleanupExpired();
    }
}

fn probeSingleUpstream(cfg: *const edge_config.EdgeConfig, state: *GatewayState, base_url: []const u8) void {
    const health_cfg = activeHealthConfig(cfg, base_url);
    const probe_base = if (unixSocketPathFromEndpoint(base_url) != null) "http://localhost" else base_url;
    const probe_url = http.health_checker.buildProbeUrl(state.allocator, probe_base, health_cfg.path) catch |err| {
        state.logger.warn(null, "active health probe url build failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };
    defer state.allocator.free(probe_url);

    const uri = std.Uri.parse(probe_url) catch |err| {
        state.logger.warn(null, "active health probe uri parse failed for {s}: {}", .{ probe_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };

    if (unixSocketPathFromEndpoint(base_url)) |socket_path| {
        const status_code = probeUnixSocketUpstream(socket_path, uri, cfg.upstream_active_health_timeout_ms) catch |err| {
            state.logger.warn(null, "active health probe unix request failed for {s}: {}", .{ base_url, err });
            state.recordActiveProbeResult(cfg, base_url, false);
            return;
        };
        state.recordActiveProbeResult(cfg, base_url, health_cfg.statusIsHealthy(status_code));
        return;
    }

    const status_code = probeTcpHttpUpstream(state.allocator, uri, cfg.upstream_active_health_timeout_ms) catch |err| {
        state.logger.warn(null, "active health probe tcp request failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };
    state.recordActiveProbeResult(cfg, base_url, health_cfg.statusIsHealthy(status_code));
}

fn probeUnixSocketUpstream(socket_path: []const u8, uri: std.Uri, timeout_ms: u32) !u16 {
    var stream = try compat.connectUnixSocket(socket_path);
    defer stream.close();

    if (timeout_ms > 0) {
        try setSocketTimeoutMs(stream.handle, timeout_ms, timeout_ms);
    }

    var request_target_buf = std.array_list.Managed(u8).init(std.heap.page_allocator);
    defer request_target_buf.deinit();
    const path_raw = switch (uri.path) {
        .raw => |path| if (path.len > 0) path else "/",
        .percent_encoded => |path| if (path.len > 0) path else "/",
    };
    try request_target_buf.appendSlice(path_raw);
    if (uri.query) |query| {
        try request_target_buf.appendSlice("?");
        try request_target_buf.appendSlice(uriComponentBytes(query));
    }

    try stream.print("GET {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", .{request_target_buf.items});

    var response_buf: [256]u8 = undefined;
    var used: usize = 0;
    while (used < response_buf.len) {
        const n = try stream.read(response_buf[used..]);
        if (n == 0) break;
        used += n;
        if (std.mem.find(u8, response_buf[0..used], "\r\n")) |line_end| {
            var parts = std.mem.splitScalar(u8, response_buf[0..line_end], ' ');
            _ = parts.next() orelse return error.InvalidHttpResponse;
            const status_str = parts.next() orelse return error.InvalidHttpResponse;
            return std.fmt.parseInt(u16, status_str, 10);
        }
    }

    return error.InvalidHttpResponse;
}

/// Probe a TCP/HTTP upstream with a bounded timeout, mirroring
/// probeUnixSocketUpstream but over a regular TCP connection. Uses a raw
/// socket so we can apply SO_RCVTIMEO and SO_SNDTIMEO before the HTTP
/// round-trip, preventing hung probes from blocking the health-check batch.
fn probeTcpHttpUpstream(allocator: std.mem.Allocator, uri: std.Uri, timeout_ms: u32) !u16 {
    const host = if (uri.host) |h| switch (h) {
        .raw => |r| r,
        .percent_encoded => |pe| pe,
    } else return error.InvalidHttpResponse;
    const port: u16 = if (uri.port) |p| p else 80;

    var stream = try compat.tcpConnectToHost(allocator, host, port);
    defer stream.close();

    if (timeout_ms > 0) {
        try setSocketTimeoutMs(stream.handle, timeout_ms, timeout_ms);
    }

    const path_raw = switch (uri.path) {
        .raw => |path| if (path.len > 0) path else "/",
        .percent_encoded => |path| if (path.len > 0) path else "/",
    };
    try stream.print("GET {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{ path_raw, host });

    var response_buf: [256]u8 = undefined;
    var used: usize = 0;
    while (used < response_buf.len) {
        const n = try stream.read(response_buf[used..]);
        if (n == 0) break;
        used += n;
        if (std.mem.find(u8, response_buf[0..used], "\r\n")) |line_end| {
            var parts = std.mem.splitScalar(u8, response_buf[0..line_end], ' ');
            _ = parts.next() orelse return error.InvalidHttpResponse;
            const status_str = parts.next() orelse return error.InvalidHttpResponse;
            return std.fmt.parseInt(u16, status_str, 10);
        }
    }

    return error.InvalidHttpResponse;
}
