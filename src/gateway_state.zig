const compat = @import("zig_compat.zig");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");

/// Shared inbound request buffer size limit, also used as a default proxy
/// response buffer ceiling when no explicit limit is configured.
pub const MAX_REQUEST_SIZE: usize = 256 * 1024;

pub const ProxyCacheLookup = struct {
    cached: http.idempotency.CachedResponse,
    is_stale: bool,
};

pub const UpstreamHealth = struct {
    fail_count: u32 = 0,
    unhealthy_until_ms: u64 = 0,
    probe: http.health_checker.State = .{},
    slow_start_until_ms: u64 = 0,
};

pub const ConnectionSlotResult = enum {
    accepted,
    over_ip_limit,
    over_global_limit,
    over_global_memory_limit,
};

pub const Http2PendingStream = struct {
    method: ?[]u8 = null,
    path: ?[]u8 = null,
    headers: http.Headers,
    body: std.ArrayList(u8),
    priority_weight: u8 = 16,

    pub fn init(allocator: std.mem.Allocator) Http2PendingStream {
        return .{
            .headers = http.Headers.init(allocator),
            .body = .empty,
        };
    }

    pub fn deinit(self: *Http2PendingStream, allocator: std.mem.Allocator) void {
        if (self.method) |m| allocator.free(m);
        if (self.path) |p| allocator.free(p);
        self.headers.deinit();
        self.body.deinit(allocator);
        self.* = undefined;
    }
};

pub const UpstreamScope = enum {
    global,
    chat,
    commands,
};

pub fn upstreamScopeName(scope: UpstreamScope) []const u8 {
    return switch (scope) {
        .global => "global",
        .chat => "chat",
        .commands => "commands",
    };
}

pub fn proxyScopeForPath(path: []const u8) UpstreamScope {
    if (http.api_router.matchRoute(path, 1, "/chat")) return .chat;
    if (http.api_router.matchRoute(path, 1, "/commands")) return .commands;
    return .global;
}

pub fn maxBufferedUpstreamResponseBytes(cfg: *const edge_config.EdgeConfig) usize {
    return if (cfg.max_buffered_upstream_response_bytes > 0)
        cfg.max_buffered_upstream_response_bytes
    else
        MAX_REQUEST_SIZE;
}

pub const UpstreamPoolView = struct {
    fallback_url: []const u8,
    primary_urls: []const []const u8,
    primary_weights: []const u32,
    backup_urls: []const []const u8,
};

pub const StickyAffinityRequest = struct {
    location_key: []u8,
    cookie_name: []u8,
    requested_upstream: ?[]u8,

    fn deinit(self: *StickyAffinityRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.location_key);
        allocator.free(self.cookie_name);
        if (self.requested_upstream) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const StickyUpstreamSelection = struct {
    base_url: []const u8,
    used_requested: bool,
};

pub const CommandLifecycleStatus = enum {
    pending,
    running,
    completed,
    failed,
};

pub const CommandLifecycleEntry = struct {
    status: CommandLifecycleStatus,
    command_type: []u8,
    correlation_id: []u8,
    identity: []u8,
    created_ms: i64,
    updated_ms: i64,
    response_status: u16,
    response_body: []u8,
    response_content_type: []u8,
    error_message: []u8,
};

pub const CommandLifecycleSnapshot = struct {
    status: CommandLifecycleStatus,
    response_status: u16,
    response_body: []u8,
    response_content_type: []u8,
    error_message: []u8,

    fn deinit(self: *CommandLifecycleSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.response_body);
        allocator.free(self.response_content_type);
        allocator.free(self.error_message);
        self.* = undefined;
    }
};

pub const ApprovalStatus = enum {
    pending,
    approved,
    denied,
    escalated,
};

pub const ApprovalDecision = enum {
    approve,
    deny,
};

pub const ApprovalValidation = enum {
    approved,
    pending,
    denied,
    escalated,
    invalid,
    missing,
};

pub const ApprovalEntry = struct {
    method: []u8,
    path: []u8,
    identity: []u8,
    command_id: []u8,
    status: ApprovalStatus,
    created_ms: i64,
    expires_ms: i64,
    decided_ms: i64,
    decided_by: []u8,
    /// True once the escalation webhook has been fired for this entry.
    escalation_fired: bool = false,

    fn deinit(self: *ApprovalEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.method);
        allocator.free(self.path);
        allocator.free(self.identity);
        allocator.free(self.command_id);
        allocator.free(self.decided_by);
        self.* = undefined;
    }
};

pub const ApprovalCreateResult = struct {
    token: []u8,
    expires_ms: i64,
};

pub const MuxChannelKind = enum {
    events,
    command,
};

pub const MuxChannel = struct {
    name: []u8,
    kind: MuxChannelKind,
    topic: ?[]u8 = null,
    last_event_id: u64 = 0,
    command_id: ?[]u8 = null,
    last_command_status: ?CommandLifecycleStatus = null,
};

pub const MuxPendingFrame = struct {
    payload: []u8,
};

pub const MuxResumeState = struct {
    channels: []MuxChannel,
    expires_ms: i64,
};

pub const MuxDeviceCount = struct {
    device_id: []u8,
    count: usize,
};

pub const MuxMetricsSnapshot = struct {
    device_counts: []MuxDeviceCount,
};

fn deinitMuxMetricsSnapshot(allocator: std.mem.Allocator, device_counts: []MuxDeviceCount) void {
    for (device_counts) |entry| allocator.free(entry.device_id);
    allocator.free(device_counts);
}

fn deinitMuxPendingFrames(allocator: std.mem.Allocator, pending: *std.ArrayList(MuxPendingFrame)) void {
    for (pending.items) |frame| allocator.free(frame.payload);
    pending.deinit(allocator);
}

fn deinitMuxChannel(allocator: std.mem.Allocator, ch: *MuxChannel) void {
    allocator.free(ch.name);
    if (ch.topic) |t| allocator.free(t);
    if (ch.command_id) |id| allocator.free(id);
    ch.* = undefined;
}

fn cloneMuxChannel(allocator: std.mem.Allocator, ch: *const MuxChannel) !MuxChannel {
    return .{
        .name = try allocator.dupe(u8, ch.name),
        .kind = ch.kind,
        .topic = if (ch.topic) |topic| try allocator.dupe(u8, topic) else null,
        .last_event_id = ch.last_event_id,
        .command_id = if (ch.command_id) |command_id| try allocator.dupe(u8, command_id) else null,
        .last_command_status = ch.last_command_status,
    };
}

fn cloneMuxChannels(allocator: std.mem.Allocator, channels: []const MuxChannel) ![]MuxChannel {
    var out = try allocator.alloc(MuxChannel, channels.len);
    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |*ch| deinitMuxChannel(allocator, ch);
        allocator.free(out);
    }
    for (channels, 0..) |ch, idx| {
        out[idx] = try cloneMuxChannel(allocator, &ch);
        initialized += 1;
    }
    return out;
}

fn deinitMuxResumeState(allocator: std.mem.Allocator, saved_state: *MuxResumeState) void {
    for (saved_state.channels) |*ch| deinitMuxChannel(allocator, ch);
    allocator.free(saved_state.channels);
    saved_state.* = undefined;
}

/// Persistent gateway state shared across connections.
pub const GatewayState = struct {
    allocator: std.mem.Allocator,
    connection_mutex: compat.Mutex = .{},
    rate_limiter_mutex: compat.Mutex = .{},
    idempotency_mutex: compat.Mutex = .{},
    proxy_cache_mutex: compat.Mutex = .{},
    session_mutex: compat.Mutex = .{},
    transcript_mutex: compat.Mutex = .{},
    command_mutex: compat.Mutex = .{},
    approval_mutex: compat.Mutex = .{},
    circuit_mutex: compat.Mutex = .{},
    metrics_mutex: compat.Mutex = .{},
    upstream_mutex: compat.Mutex = .{},
    runtime_mutex: compat.Mutex = .{},
    rate_limiter: ?http.rate_limiter.RateLimiter,
    idempotency_store: ?http.idempotency.IdempotencyStore,
    proxy_cache_store: ?http.idempotency.IdempotencyStore,
    proxy_cache_path: []const u8,
    proxy_cache_ttl_seconds: u32,
    security_headers: http.security_headers.SecurityHeaders,
    /// Owned HSTS header value. Empty when HSTS is disabled or TLS is not configured.
    hsts_value: []u8 = &.{},
    add_headers: []const edge_config.EdgeConfig.HeaderPair,
    http3_alt_svc: ?[]u8,
    http3_runtime: ?*http.http3_runtime.Runtime,
    session_store: ?http.session.SessionStore,
    session_store_path: []const u8,
    access_control: ?http.access_control.AccessControl,
    logger: http.logger.Logger,
    metrics: http.metrics.Metrics,
    compression_config: http.compression.CompressionConfig,
    circuit_breaker: http.circuit_breaker.CircuitBreaker,
    upstream_client: std.http.Client,
    /// ACME HTTP-01 challenge token store (null when ACME automation is disabled).
    acme_challenge_store: ?http.acme_client.ChallengeStore,
    event_hub: http.event_hub.EventHub,
    request_buffer_pool: http.buffer_pool.BufferPool,
    relay_buffer_pool: http.buffer_pool.BufferPool,
    max_connections_per_ip: u32,
    max_active_connections: u32,
    active_connections_total: usize,
    /// Atomic count of HTTP requests currently being executed.
    in_flight_requests: std.atomic.Value(u32),
    /// Maximum concurrent in-flight requests (0 = unlimited). Requests exceeding
    /// this limit are rejected with 503 before any work is done.
    max_in_flight_requests: u32,
    active_ws_streams: usize,
    active_sse_streams: usize,
    active_mux_connections: usize,
    active_mux_subscriptions: usize,
    connection_memory_estimate_bytes: usize,
    max_total_connection_memory_bytes: usize,
    upstream_rr_index: usize,
    upstream_backup_rr_index: usize,
    lb_random_state: u64,
    next_active_health_probe_ms: u64,
    next_proxy_cache_maintenance_ms: u64,
    /// Set to true while a background health-probe thread is running so the
    /// event loop does not dispatch a second batch before the first finishes.
    health_probe_running: std.atomic.Value(bool),
    upstream_health: std.StringHashMap(UpstreamHealth),
    upstream_active_requests: std.StringHashMap(usize),
    fastcgi_pool: std.StringHashMap(std.ArrayList(compat.NetStream)),
    fastcgi_next_request_id: std.StringHashMap(u16),
    proxy_cache_locks: std.StringHashMap(u32),
    active_connections_by_ip: std.StringHashMap(u32),
    active_fds: std.AutoHashMap(std.posix.fd_t, void),
    fd_to_ip: std.AutoHashMap(std.posix.fd_t, []u8),
    command_lifecycle: std.StringHashMap(CommandLifecycleEntry),
    approvals: std.StringHashMap(ApprovalEntry),
    mux_subscriptions_by_device: std.StringHashMap(usize),
    mux_resume_state: std.StringHashMap(MuxResumeState),
    /// Path to persistent approval store file (empty = in-memory only).
    approval_store_path: []const u8,
    /// Webhook URL for escalation notifications (empty = disabled).
    approval_escalation_webhook: []const u8,
    /// Approval TTL in milliseconds.
    approval_ttl_ms: i64,
    /// Max concurrent pending approval requests per identity (0 = unlimited).
    approval_max_pending_per_identity: u32,
    transcript_store_path: []const u8,
    /// DNS-based upstream discovery state. Active when
    /// cfg.upstream_dns_discovery_host is non-empty.
    dns_discovery: http.dns_discovery.DnsDiscovery,
    /// Reload state: set by hotReloadConfig on every attempt so operators can
    /// query the outcome without tailing logs.
    reload_mutex: compat.Mutex = .{},
    last_reload_ok: bool = false,
    last_reload_at_ms: i64 = 0,
    last_reload_error: [256]u8 = undefined,
    last_reload_error_len: usize = 0,

    pub fn deinit(self: *GatewayState) void {
        self.dns_discovery.deinit();
        if (self.rate_limiter) |*rl| rl.deinit();
        if (self.idempotency_store) |*is| is.deinit();
        if (self.proxy_cache_store) |*pc| pc.deinit();
        if (self.session_store) |*ss| ss.deinit();
        if (self.access_control) |*acl| acl.deinit();
        self.upstream_client.deinit();
        if (self.acme_challenge_store) |*store| store.deinit();
        self.event_hub.deinit();
        self.request_buffer_pool.deinit();
        self.relay_buffer_pool.deinit();
        if (self.hsts_value.len > 0) self.allocator.free(self.hsts_value);
        if (self.http3_alt_svc) |value| self.allocator.free(value);
        var upstream_it = self.upstream_health.iterator();
        while (upstream_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.upstream_health.deinit();
        var upstream_active_it = self.upstream_active_requests.iterator();
        while (upstream_active_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.upstream_active_requests.deinit();
        var fastcgi_it = self.fastcgi_pool.iterator();
        while (fastcgi_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            for (entry.value_ptr.items) |stream| {
                var owned = stream;
                owned.close();
            }
            entry.value_ptr.deinit(self.allocator);
        }
        self.fastcgi_pool.deinit();
        var fastcgi_id_it = self.fastcgi_next_request_id.iterator();
        while (fastcgi_id_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.fastcgi_next_request_id.deinit();
        var cache_lock_it = self.proxy_cache_locks.iterator();
        while (cache_lock_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.proxy_cache_locks.deinit();
        var ip_it = self.active_connections_by_ip.iterator();
        while (ip_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.active_connections_by_ip.deinit();
        self.active_fds.deinit();

        var fd_it = self.fd_to_ip.iterator();
        while (fd_it.next()) |entry| self.allocator.free(entry.value_ptr.*);
        self.fd_to_ip.deinit();
        var cmd_it = self.command_lifecycle.iterator();
        while (cmd_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.command_type);
            self.allocator.free(entry.value_ptr.correlation_id);
            self.allocator.free(entry.value_ptr.identity);
            self.allocator.free(entry.value_ptr.response_body);
            self.allocator.free(entry.value_ptr.response_content_type);
            self.allocator.free(entry.value_ptr.error_message);
        }
        self.command_lifecycle.deinit();
        var approval_it = self.approvals.iterator();
        while (approval_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.approvals.deinit();
        var mux_sub_it = self.mux_subscriptions_by_device.iterator();
        while (mux_sub_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.mux_subscriptions_by_device.deinit();
        var mux_resume_it = self.mux_resume_state.iterator();
        while (mux_resume_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            deinitMuxResumeState(self.allocator, entry.value_ptr);
        }
        self.mux_resume_state.deinit();
    }

    pub fn acquireFastcgiStream(self: *GatewayState, endpoint: []const u8) !struct { stream: compat.NetStream, reused: bool } {
        self.connection_mutex.lock();
        if (self.fastcgi_pool.getPtr(endpoint)) |pool| {
            if (pool.items.len > 0) {
                const stream = pool.pop().?;
                self.connection_mutex.unlock();
                return .{ .stream = stream, .reused = true };
            }
        }
        self.connection_mutex.unlock();
        return .{ .stream = try http.fastcgi.connect(self.allocator, endpoint), .reused = false };
    }

    pub fn releaseFastcgiStream(self: *GatewayState, endpoint: []const u8, stream: compat.NetStream, allow_reuse: bool) void {
        if (!allow_reuse) {
            var owned = stream;
            owned.close();
            return;
        }

        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();

        if (self.fastcgi_pool.getPtr(endpoint)) |pool| {
            if (pool.items.len >= 4) {
                var owned = stream;
                owned.close();
                return;
            }
            pool.append(self.allocator, stream) catch {
                var owned = stream;
                owned.close();
            };
            return;
        }

        const owned_key = self.allocator.dupe(u8, endpoint) catch {
            var owned = stream;
            owned.close();
            return;
        };
        var pool: std.ArrayList(compat.NetStream) = .empty;
        pool.append(self.allocator, stream) catch {
            self.allocator.free(owned_key);
            var owned = stream;
            owned.close();
            return;
        };
        self.fastcgi_pool.put(owned_key, pool) catch {
            for (pool.items) |item| {
                var owned = item;
                owned.close();
            }
            pool.deinit(self.allocator);
            self.allocator.free(owned_key);
        };
    }

    pub fn nextFastcgiRequestId(self: *GatewayState, endpoint: []const u8) u16 {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();

        if (self.fastcgi_next_request_id.getPtr(endpoint)) |value| {
            const next = value.*;
            value.* = if (next == std.math.maxInt(u16)) 1 else next + 1;
            return next;
        }

        const owned_key = self.allocator.dupe(u8, endpoint) catch return 1;
        self.fastcgi_next_request_id.put(owned_key, 2) catch {
            self.allocator.free(owned_key);
            return 1;
        };
        return 1;
    }

    pub fn tryAcquireConnectionSlot(self: *GatewayState, fd: std.posix.fd_t, ip_key: []const u8) !ConnectionSlotResult {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();

        if (self.max_active_connections > 0 and self.active_connections_total >= self.max_active_connections) {
            self.metrics_mutex.lock();
            self.metrics.recordConnectionRejection();
            self.metrics_mutex.unlock();
            return .over_global_limit;
        }
        if (self.max_total_connection_memory_bytes > 0 and self.connection_memory_estimate_bytes > 0) {
            const projected: u128 = (@as(u128, self.active_connections_total) + 1) * @as(u128, self.connection_memory_estimate_bytes);
            if (projected > self.max_total_connection_memory_bytes) {
                self.metrics_mutex.lock();
                self.metrics.recordConnectionRejection();
                self.metrics_mutex.unlock();
                return .over_global_memory_limit;
            }
        }

        var ip_slot_acquired = false;
        if (self.max_connections_per_ip > 0) {
            const current = self.active_connections_by_ip.get(ip_key) orelse 0;
            if (current >= self.max_connections_per_ip) {
                self.metrics_mutex.lock();
                self.metrics.recordConnectionRejection();
                self.metrics_mutex.unlock();
                return .over_ip_limit;
            }

            if (current == 0) {
                const owned_key = try self.allocator.dupe(u8, ip_key);
                errdefer self.allocator.free(owned_key);
                try self.active_connections_by_ip.put(owned_key, 1);
            } else {
                try self.active_connections_by_ip.put(ip_key, current + 1);
            }
            ip_slot_acquired = true;

            const owned_fd_ip = try self.allocator.dupe(u8, ip_key);
            errdefer self.allocator.free(owned_fd_ip);
            self.fd_to_ip.put(fd, owned_fd_ip) catch |err| {
                if (self.active_connections_by_ip.getPtr(ip_key)) |count| {
                    if (count.* > 1) {
                        count.* -= 1;
                    } else {
                        if (self.active_connections_by_ip.fetchRemove(ip_key)) |kv| {
                            self.allocator.free(kv.key);
                        }
                    }
                }
                return err;
            };
        }

        self.active_fds.put(fd, {}) catch |err| {
            if (ip_slot_acquired) {
                if (self.fd_to_ip.fetchRemove(fd)) |removed| self.allocator.free(removed.value);
                if (self.active_connections_by_ip.getPtr(ip_key)) |count| {
                    if (count.* > 1) {
                        count.* -= 1;
                    } else {
                        if (self.active_connections_by_ip.fetchRemove(ip_key)) |kv| {
                            self.allocator.free(kv.key);
                        }
                    }
                }
            }
            return err;
        };
        self.active_connections_total += 1;
        self.metrics_mutex.lock();
        self.metrics.setActiveConnections(self.active_connections_total);
        self.metrics_mutex.unlock();
        return .accepted;
    }

    pub fn releaseConnectionSlot(self: *GatewayState, fd: std.posix.fd_t) void {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();

        if (self.active_fds.fetchRemove(fd) != null and self.active_connections_total > 0) {
            self.active_connections_total -= 1;
            self.metrics_mutex.lock();
            self.metrics.setActiveConnections(self.active_connections_total);
            self.metrics_mutex.unlock();
        }
        if (self.max_connections_per_ip == 0) return;

        const removed = self.fd_to_ip.fetchRemove(fd) orelse return;
        defer self.allocator.free(removed.value);

        if (self.active_connections_by_ip.getPtr(removed.value)) |count| {
            if (count.* > 1) {
                count.* -= 1;
            } else {
                if (self.active_connections_by_ip.fetchRemove(removed.value)) |kv| {
                    self.allocator.free(kv.key);
                }
            }
        }
    }

    /// Attempt to reserve an in-flight request slot.
    ///
    /// Returns false (and the caller should respond 503) when
    /// `max_in_flight_requests > 0` and the limit is already reached.
    pub fn tryAcquireRequestSlot(self: *GatewayState) bool {
        if (self.max_in_flight_requests == 0) return true;
        const prev = self.in_flight_requests.fetchAdd(1, .acq_rel);
        if (prev >= self.max_in_flight_requests) {
            _ = self.in_flight_requests.fetchSub(1, .acq_rel);
            return false;
        }
        return true;
    }

    /// Release a previously-acquired in-flight request slot.
    pub fn releaseRequestSlot(self: *GatewayState) void {
        if (self.max_in_flight_requests == 0) return;
        _ = self.in_flight_requests.fetchSub(1, .acq_rel);
    }

    pub fn rateLimitAllow(self: *GatewayState, descriptor: []const u8) bool {
        self.rate_limiter_mutex.lock();
        defer self.rate_limiter_mutex.unlock();
        if (self.rate_limiter) |*rl| {
            return rl.allow(descriptor) != null;
        }
        return true;
    }

    pub fn idempotencyGetCopy(self: *GatewayState, allocator: std.mem.Allocator, key: []const u8) !?http.idempotency.CachedResponse {
        self.idempotency_mutex.lock();
        defer self.idempotency_mutex.unlock();
        if (self.idempotency_store) |*store| {
            if (store.get(key)) |cached| {
                const body = try allocator.dupe(u8, cached.body);
                errdefer allocator.free(body);
                const ct = try allocator.dupe(u8, cached.content_type);
                return .{
                    .status = cached.status,
                    .body = body,
                    .content_type = ct,
                    .created_ns = cached.created_ns,
                };
            }
        }
        return null;
    }

    pub fn idempotencyPut(self: *GatewayState, key: []const u8, status: u16, body: []const u8, content_type: []const u8) !void {
        self.idempotency_mutex.lock();
        defer self.idempotency_mutex.unlock();
        if (self.idempotency_store) |*store| {
            try store.put(key, status, body, content_type);
        }
    }

    pub fn proxyCacheGetCopyWithStale(self: *GatewayState, allocator: std.mem.Allocator, key: []const u8, stale_seconds: u32) !?ProxyCacheLookup {
        self.proxy_cache_mutex.lock();
        var locked = true;
        defer if (locked) self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_store) |*store| {
            if (store.getWithStale(key, stale_seconds)) |lookup| {
                const body = try allocator.dupe(u8, lookup.response.body);
                errdefer allocator.free(body);
                const ct = try allocator.dupe(u8, lookup.response.content_type);
                locked = false;
                self.proxy_cache_mutex.unlock();
                return .{
                    .cached = .{
                        .status = lookup.response.status,
                        .body = body,
                        .content_type = ct,
                        .created_ns = lookup.response.created_ns,
                    },
                    .is_stale = lookup.is_stale,
                };
            }
        }
        locked = false;
        self.proxy_cache_mutex.unlock();

        if (self.proxy_cache_path.len == 0) return null;
        const disk_lookup = try proxyCacheReadFromDisk(allocator, self.proxy_cache_path, key, self.proxy_cache_ttl_seconds, stale_seconds);
        if (disk_lookup) |found| {
            self.proxy_cache_mutex.lock();
            defer self.proxy_cache_mutex.unlock();
            if (self.proxy_cache_store) |*store| {
                store.put(key, found.cached.status, found.cached.body, found.cached.content_type) catch {}; // cache write is best-effort; a miss on the next request is acceptable
            }
        }
        return disk_lookup;
    }

    pub fn proxyCachePut(self: *GatewayState, key: []const u8, status: u16, body: []const u8, content_type: []const u8) !void {
        self.proxy_cache_mutex.lock();
        var locked = true;
        defer if (locked) self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_store) |*store| {
            try store.put(key, status, body, content_type);
        }
        locked = false;
        self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_path.len > 0) {
            try proxyCacheWriteToDisk(self.proxy_cache_path, key, status, body, content_type);
        }
    }

    pub fn proxyCacheDelete(self: *GatewayState, key: []const u8) bool {
        self.proxy_cache_mutex.lock();
        var removed = false;
        if (self.proxy_cache_store) |*store| {
            removed = store.delete(key);
        }
        self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_path.len > 0) {
            removed = proxyCacheDeleteFromDisk(self.proxy_cache_path, key) or removed;
        }
        return removed;
    }

    pub fn proxyCachePurgeAll(self: *GatewayState) usize {
        self.proxy_cache_mutex.lock();
        var removed: usize = 0;
        if (self.proxy_cache_store) |*store| {
            removed += store.clear();
        }
        self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_path.len > 0) {
            removed += proxyCachePurgeDisk(self.proxy_cache_path);
        }
        return removed;
    }

    pub fn proxyCacheTryLock(self: *GatewayState, key: []const u8) !bool {
        self.proxy_cache_mutex.lock();
        defer self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_locks.contains(key)) return false;
        const owned = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned);
        try self.proxy_cache_locks.put(owned, 1);
        return true;
    }

    pub fn proxyCacheUnlock(self: *GatewayState, key: []const u8) void {
        self.proxy_cache_mutex.lock();
        defer self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_locks.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
        }
    }

    pub fn proxyCacheWaitForUnlock(self: *GatewayState, key: []const u8, timeout_ms: u32) bool {
        const deadline = http.event_loop.monotonicMs() + timeout_ms;
        while (http.event_loop.monotonicMs() < deadline) {
            self.proxy_cache_mutex.lock();
            const locked = self.proxy_cache_locks.contains(key);
            self.proxy_cache_mutex.unlock();
            if (!locked) return true;
            std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(10), .awake) catch {}; // interrupt wakes are fine; loop continues immediately
        }
        return false;
    }

    pub fn createSession(self: *GatewayState, allocator: std.mem.Allocator, identity: []const u8, client_ip: []const u8, device_id: ?[]const u8) ![]const u8 {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const token = try self.session_store.?.create(identity, client_ip, device_id);
        self.persistSessionsLocked();
        return try allocator.dupe(u8, token);
    }

    pub fn validateSessionIdentity(self: *GatewayState, allocator: std.mem.Allocator, token: []const u8) ?[]const u8 {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store) |*ss| {
            if (ss.validate(token)) |session| {
                self.persistSessionsLocked();
                return allocator.dupe(u8, session.identity) catch null;
            }
        }
        return null;
    }

    pub fn revokeSession(self: *GatewayState, token: []const u8) bool {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store) |*ss| {
            const revoked = ss.revoke(token);
            if (revoked) self.persistSessionsLocked();
            return revoked;
        }
        return false;
    }

    pub fn countSessionsByIdentity(self: *GatewayState, allocator: std.mem.Allocator, identity: []const u8) !usize {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const sessions = try self.session_store.?.listByIdentity(allocator, identity);
        defer allocator.free(sessions);
        return sessions.len;
    }

    pub fn refreshSession(self: *GatewayState, allocator: std.mem.Allocator, token: []const u8, client_ip: []const u8) ![]const u8 {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const existing = self.session_store.?.validate(token) orelse return error.InvalidSession;
        const new_token = try self.session_store.?.create(existing.identity, client_ip, existing.device_id);
        _ = self.session_store.?.revoke(token);
        self.persistSessionsLocked();
        return try allocator.dupe(u8, new_token);
    }

    pub fn persistSessionsLocked(self: *GatewayState) void {
        if (self.session_store_path.len == 0) return;
        if (self.session_store) |*ss| {
            http.session_store_file.persist(self.allocator, self.session_store_path, ss) catch |err| {
                self.logger.warn(null, "session store persist failed: {}", .{err});
            };
        }
    }

    pub fn appendTranscript(
        self: *GatewayState,
        scope: []const u8,
        route: []const u8,
        correlation_id: []const u8,
        identity: ?[]const u8,
        client_ip: []const u8,
        upstream_url: []const u8,
        request_body: []const u8,
        response_status: u16,
        response_content_type: []const u8,
        response_body: []const u8,
        redacted_values: []const []const u8,
    ) void {
        if (self.transcript_store_path.len == 0) return;
        self.transcript_mutex.lock();
        defer self.transcript_mutex.unlock();
        http.transcript_store.append(self.allocator, self.transcript_store_path, .{
            .ts_ms = compat.milliTimestamp(),
            .scope = scope,
            .route = route,
            .correlation_id = correlation_id,
            .identity = identity orelse "",
            .client_ip = client_ip,
            .upstream_url = upstream_url,
            .request_body = request_body,
            .response_status = response_status,
            .response_content_type = response_content_type,
            .response_body = response_body,
        }, redacted_values) catch |err| {
            self.logger.warn(correlation_id, "transcript store append failed: {}", .{err});
        };
    }

    pub fn commandLifecycleCreate(self: *GatewayState, command_id: []const u8, command_type: []const u8, correlation_id: []const u8, identity: []const u8) !void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        const now = compat.milliTimestamp();
        const owned_id = try self.allocator.dupe(u8, command_id);
        errdefer self.allocator.free(owned_id);
        const owned_cmd = try self.allocator.dupe(u8, command_type);
        errdefer self.allocator.free(owned_cmd);
        const owned_corr = try self.allocator.dupe(u8, correlation_id);
        errdefer self.allocator.free(owned_corr);
        const owned_ident = try self.allocator.dupe(u8, identity);
        errdefer self.allocator.free(owned_ident);
        const entry = CommandLifecycleEntry{
            .status = .pending,
            .command_type = owned_cmd,
            .correlation_id = owned_corr,
            .identity = owned_ident,
            .created_ms = now,
            .updated_ms = now,
            .response_status = 0,
            .response_body = try self.allocator.dupe(u8, ""),
            .response_content_type = try self.allocator.dupe(u8, ""),
            .error_message = try self.allocator.dupe(u8, ""),
        };
        try self.command_lifecycle.put(owned_id, entry);
    }

    pub fn commandLifecycleSetRunning(self: *GatewayState, command_id: []const u8) void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        if (self.command_lifecycle.getPtr(command_id)) |entry| {
            entry.status = .running;
            entry.updated_ms = compat.milliTimestamp();
        }
    }

    pub fn commandLifecycleSetCompleted(self: *GatewayState, command_id: []const u8, status: u16, body: []const u8, content_type: []const u8) void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        if (self.command_lifecycle.getPtr(command_id)) |entry| {
            self.allocator.free(entry.response_body);
            self.allocator.free(entry.response_content_type);
            self.allocator.free(entry.error_message);
            entry.status = .completed;
            entry.updated_ms = compat.milliTimestamp();
            entry.response_status = status;
            entry.response_body = self.allocator.dupe(u8, body) catch self.allocator.dupe(u8, "") catch return;
            entry.response_content_type = self.allocator.dupe(u8, content_type) catch self.allocator.dupe(u8, "") catch return;
            entry.error_message = self.allocator.dupe(u8, "") catch self.allocator.dupe(u8, "") catch return;
        }
    }

    pub fn commandLifecycleSetFailed(self: *GatewayState, command_id: []const u8, message: []const u8) void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        if (self.command_lifecycle.getPtr(command_id)) |entry| {
            self.allocator.free(entry.error_message);
            entry.status = .failed;
            entry.updated_ms = compat.milliTimestamp();
            entry.error_message = self.allocator.dupe(u8, message) catch self.allocator.dupe(u8, "command_failed") catch return;
        }
    }

    pub fn commandLifecycleSnapshotJson(self: *GatewayState, allocator: std.mem.Allocator, command_id: []const u8) ?[]const u8 {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        const entry = self.command_lifecycle.get(command_id) orelse return null;
        const status_name = @tagName(entry.status);
        return std.fmt.allocPrint(allocator, "{{\"command_id\":\"{s}\",\"status\":\"{s}\",\"command\":\"{s}\",\"correlation_id\":\"{s}\",\"identity\":\"{s}\",\"created_ms\":{d},\"updated_ms\":{d},\"response_status\":{d},\"response_content_type\":\"{s}\",\"response_body\":{s},\"error\":\"{s}\"}}", .{
            command_id,
            status_name,
            entry.command_type,
            entry.correlation_id,
            entry.identity,
            entry.created_ms,
            entry.updated_ms,
            entry.response_status,
            entry.response_content_type,
            if (entry.response_body.len > 0 and (std.mem.startsWith(u8, entry.response_body, "{") or std.mem.startsWith(u8, entry.response_body, "["))) entry.response_body else "\"\"",
            entry.error_message,
        }) catch null;
    }

    pub fn commandLifecycleGet(self: *GatewayState, allocator: std.mem.Allocator, command_id: []const u8) ?CommandLifecycleSnapshot {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        const entry = self.command_lifecycle.get(command_id) orelse return null;
        const response_body = allocator.dupe(u8, entry.response_body) catch return null;
        errdefer allocator.free(response_body);
        const response_content_type = allocator.dupe(u8, entry.response_content_type) catch return null;
        errdefer allocator.free(response_content_type);
        const error_message = allocator.dupe(u8, entry.error_message) catch return null;
        return .{
            .status = entry.status,
            .response_status = entry.response_status,
            .response_body = response_body,
            .response_content_type = response_content_type,
            .error_message = error_message,
        };
    }

    pub fn approvalCreate(self: *GatewayState, allocator: std.mem.Allocator, method: []const u8, path: []const u8, identity: []const u8, command_id: ?[]const u8) !ApprovalCreateResult {
        const result = blk: {
            self.approval_mutex.lock();
            defer self.approval_mutex.unlock();

            // Rate-limit: cap pending approvals per identity.
            if (self.approval_max_pending_per_identity > 0) {
                if (self.approvalCountPendingForIdentityLocked(identity) >= self.approval_max_pending_per_identity) {
                    return error.TooManyPendingApprovals;
                }
            }

            var rnd: [16]u8 = undefined;
            std.crypto.random.bytes(&rnd);
            const token = try std.fmt.allocPrint(self.allocator, "apr-{d}-{f}", .{
                compat.milliTimestamp(),
                compat.fmtSliceHexLower(&rnd),
            });
            errdefer self.allocator.free(token);
            const now = compat.milliTimestamp();
            const expires_ms = now + self.approval_ttl_ms;
            const entry = ApprovalEntry{
                .method = try self.allocator.dupe(u8, method),
                .path = try self.allocator.dupe(u8, path),
                .identity = try self.allocator.dupe(u8, identity),
                .command_id = try self.allocator.dupe(u8, command_id orelse ""),
                .status = .pending,
                .created_ms = now,
                .expires_ms = expires_ms,
                .decided_ms = 0,
                .decided_by = try self.allocator.dupe(u8, ""),
            };
            try self.approvals.put(token, entry);
            break :blk ApprovalCreateResult{
                .token = try allocator.dupe(u8, token),
                .expires_ms = expires_ms,
            };
        };
        // Persist outside the mutex.
        self.persistApprovals();
        return result;
    }

    pub fn approvalRespond(self: *GatewayState, token: []const u8, decision: ApprovalDecision, actor: []const u8) bool {
        var webhook_payload: ?[]u8 = null;
        defer if (webhook_payload) |p| self.allocator.free(p);

        const success = blk: {
            self.approval_mutex.lock();
            defer self.approval_mutex.unlock();
            const entry = self.approvals.getPtr(token) orelse break :blk false;
            if (approvalEscalateIfExpiredLocked(entry) and !entry.escalation_fired) {
                entry.escalation_fired = true;
                webhook_payload = self.buildApprovalWebhookPayloadLocked(token, entry);
            }
            if (entry.status != .pending) break :blk false;
            entry.status = if (decision == .approve) .approved else .denied;
            entry.decided_ms = compat.milliTimestamp();
            self.allocator.free(entry.decided_by);
            entry.decided_by = self.allocator.dupe(u8, actor) catch self.allocator.dupe(u8, "") catch break :blk false;
            break :blk true;
        };

        if (webhook_payload) |p| {
            http.approval_store.fireWebhook(self.allocator, self.approval_escalation_webhook, p);
        }
        if (success) self.persistApprovals();
        return success;
    }

    pub fn approvalValidate(self: *GatewayState, token: []const u8, method: []const u8, path: []const u8, identity: ?[]const u8) ApprovalValidation {
        var webhook_payload: ?[]u8 = null;
        defer if (webhook_payload) |p| self.allocator.free(p);

        const result = blk: {
            self.approval_mutex.lock();
            defer self.approval_mutex.unlock();
            const entry = self.approvals.getPtr(token) orelse break :blk ApprovalValidation.missing;
            if (approvalEscalateIfExpiredLocked(entry) and !entry.escalation_fired) {
                entry.escalation_fired = true;
                webhook_payload = self.buildApprovalWebhookPayloadLocked(token, entry);
            }
            if (!http.rewrite.methodMatches(entry.method, method)) break :blk ApprovalValidation.invalid;
            if (!http.rewrite.regexMatches(entry.path, path)) break :blk ApprovalValidation.invalid;
            if (identity) |id| {
                if (entry.identity.len > 0 and !std.mem.eql(u8, entry.identity, id)) break :blk ApprovalValidation.invalid;
            }
            break :blk switch (entry.status) {
                .pending => ApprovalValidation.pending,
                .approved => ApprovalValidation.approved,
                .denied => ApprovalValidation.denied,
                .escalated => ApprovalValidation.escalated,
            };
        };

        if (webhook_payload) |p| {
            http.approval_store.fireWebhook(self.allocator, self.approval_escalation_webhook, p);
        }
        return result;
    }

    pub fn approvalSnapshotJson(self: *GatewayState, allocator: std.mem.Allocator, token: []const u8) ?[]const u8 {
        var webhook_payload: ?[]u8 = null;
        defer if (webhook_payload) |p| self.allocator.free(p);

        const json = blk: {
            self.approval_mutex.lock();
            defer self.approval_mutex.unlock();
            const entry = self.approvals.getPtr(token) orelse break :blk @as(?[]const u8, null);
            if (approvalEscalateIfExpiredLocked(entry) and !entry.escalation_fired) {
                entry.escalation_fired = true;
                webhook_payload = self.buildApprovalWebhookPayloadLocked(token, entry);
            }
            const command_id_json = if (entry.command_id.len > 0)
                std.fmt.allocPrint(allocator, "\"{s}\"", .{entry.command_id}) catch break :blk @as(?[]const u8, null)
            else
                allocator.dupe(u8, "null") catch break :blk @as(?[]const u8, null);
            defer allocator.free(command_id_json);
            const decided_by_json = if (entry.decided_by.len > 0)
                std.fmt.allocPrint(allocator, "\"{s}\"", .{entry.decided_by}) catch break :blk @as(?[]const u8, null)
            else
                allocator.dupe(u8, "null") catch break :blk @as(?[]const u8, null);
            defer allocator.free(decided_by_json);
            break :blk std.fmt.allocPrint(allocator, "{{\"approval_token\":\"{s}\",\"status\":\"{s}\",\"method\":\"{s}\",\"path\":\"{s}\",\"identity\":\"{s}\",\"command_id\":{s},\"created_ms\":{d},\"expires_ms\":{d},\"decided_ms\":{d},\"decided_by\":{s}}}", .{
                token,
                @tagName(entry.status),
                entry.method,
                entry.path,
                entry.identity,
                command_id_json,
                entry.created_ms,
                entry.expires_ms,
                entry.decided_ms,
                decided_by_json,
            }) catch null;
        };

        if (webhook_payload) |p| {
            http.approval_store.fireWebhook(self.allocator, self.approval_escalation_webhook, p);
        }
        return json;
    }

    /// Returns true if the entry was JUST escalated (status transitioned from pending).
    /// Must be called with approval_mutex held.
    pub fn approvalEscalateIfExpiredLocked(entry: *ApprovalEntry) bool {
        if (entry.status != .pending) return false;
        const now = compat.milliTimestamp();
        if (now >= entry.expires_ms) {
            entry.status = .escalated;
            entry.decided_ms = now;
            return true;
        }
        return false;
    }

    /// Count pending approvals for a given identity. Must be called with approval_mutex held.
    pub fn approvalCountPendingForIdentityLocked(self: *GatewayState, identity: []const u8) u32 {
        var count: u32 = 0;
        var it = self.approvals.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            if (e.status == .pending and std.mem.eql(u8, e.identity, identity)) {
                count += 1;
            }
        }
        return count;
    }

    /// Build a JSON payload for the escalation webhook. Must be called with approval_mutex held.
    /// Returns an allocator-owned slice or null on OOM.
    pub fn buildApprovalWebhookPayloadLocked(self: *GatewayState, token: []const u8, entry: *const ApprovalEntry) ?[]u8 {
        const command_id_part = if (entry.command_id.len > 0)
            std.fmt.allocPrint(self.allocator, "\"{s}\"", .{entry.command_id}) catch return null
        else
            self.allocator.dupe(u8, "null") catch return null;
        defer self.allocator.free(command_id_part);
        return std.fmt.allocPrint(
            self.allocator,
            "{{\"event\":\"escalated\",\"approval_token\":\"{s}\",\"method\":\"{s}\",\"path\":\"{s}\",\"identity\":\"{s}\",\"command_id\":{s},\"created_ms\":{d},\"expires_ms\":{d}}}",
            .{ token, entry.method, entry.path, entry.identity, command_id_part, entry.created_ms, entry.expires_ms },
        ) catch null;
    }

    /// Snapshot all approval entries into a slice suitable for persistence.
    /// Must be called with approval_mutex held. Caller frees via http.approval_store.freeLoaded.
    pub fn approvalSnapshotEntriesLocked(self: *GatewayState, allocator: std.mem.Allocator) ![]http.approval_store.StoredApproval {
        var out = try allocator.alloc(http.approval_store.StoredApproval, self.approvals.count());
        var i: usize = 0;
        errdefer {
            for (out[0..i]) |e| {
                allocator.free(e.token);
                allocator.free(e.method);
                allocator.free(e.path);
                allocator.free(e.identity);
                allocator.free(e.command_id);
                allocator.free(e.status);
                allocator.free(e.decided_by);
            }
            allocator.free(out);
        }
        var it = self.approvals.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            out[i] = .{
                .token = try allocator.dupe(u8, kv.key_ptr.*),
                .method = try allocator.dupe(u8, e.method),
                .path = try allocator.dupe(u8, e.path),
                .identity = try allocator.dupe(u8, e.identity),
                .command_id = try allocator.dupe(u8, e.command_id),
                .status = try allocator.dupe(u8, @tagName(e.status)),
                .created_ms = e.created_ms,
                .expires_ms = e.expires_ms,
                .decided_ms = e.decided_ms,
                .decided_by = try allocator.dupe(u8, e.decided_by),
                .escalation_fired = e.escalation_fired,
            };
            i += 1;
        }
        return out[0..i];
    }

    /// Persist all approvals to disk (no-op when store path is unconfigured).
    pub fn persistApprovals(self: *GatewayState) void {
        if (self.approval_store_path.len == 0) return;
        const snapshot = blk: {
            self.approval_mutex.lock();
            defer self.approval_mutex.unlock();
            break :blk self.approvalSnapshotEntriesLocked(self.allocator) catch return;
        };
        defer http.approval_store.freeLoaded(self.allocator, snapshot);
        http.approval_store.persist(self.allocator, self.approval_store_path, snapshot) catch |err| {
            self.logger.warn(null, "approval store persist failed: {}", .{err});
        };
    }

    pub fn circuitTryAcquire(self: *GatewayState) bool {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        return self.circuit_breaker.tryAcquire();
    }

    pub fn circuitRecordFailure(self: *GatewayState) void {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        self.circuit_breaker.recordFailure();
    }

    pub fn circuitRecordSuccess(self: *GatewayState) void {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        self.circuit_breaker.recordSuccess();
    }

    pub fn circuitStateName(self: *GatewayState) []const u8 {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        return self.circuit_breaker.stateName();
    }

    pub fn metricsRecord(self: *GatewayState, status: u16) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordRequest(status);
    }

    pub fn metricsRecordLatencyMs(self: *GatewayState, latency_ms: i64) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordLatencyMs(latency_ms);
    }

    pub fn metricsRecordQueueRejection(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordQueueRejection();
    }

    pub fn metricsRecordMuxFrameError(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordMuxFrameError();
    }

    pub fn metricsRecordErrorCode(self: *GatewayState, code: []const u8) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordErrorCode(code);
    }

    pub fn metricsRecordProxyStreamingRequest(self: *GatewayState, ttfb_ms: u64) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyStreamingRequest(ttfb_ms);
    }

    pub fn metricsRecordProxyBufferedRequest(self: *GatewayState, buffered_bytes: usize, ttfb_ms: u64) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyBufferedRequest(buffered_bytes, ttfb_ms);
    }

    pub fn metricsReleaseProxyBufferedBytes(self: *GatewayState, buffered_bytes: usize) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.releaseProxyBufferedBytes(buffered_bytes);
    }

    pub fn metricsRecordProxyClientAbort(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyClientAbort();
    }

    pub fn metricsRecordProxyUpstreamAbort(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordProxyUpstreamAbort();
    }

    pub fn metricsSetWorkerPoolStats(self: *GatewayState, active_jobs: usize, queued_jobs: usize, worker_threads: usize, queue_capacity: usize) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.setWorkerPoolStats(active_jobs, queued_jobs, worker_threads, queue_capacity);
    }

    pub fn metricsToJson(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        const mux_snapshot = try self.muxMetricsSnapshot(allocator);
        defer deinitMuxMetricsSnapshot(allocator, mux_snapshot.device_counts);

        self.metrics_mutex.lock();
        const metrics_snapshot = self.metrics;
        self.metrics_mutex.unlock();

        var device_json = std.ArrayList(u8).empty;
        errdefer device_json.deinit(allocator);
        try device_json.append(allocator, '{');
        for (mux_snapshot.device_counts, 0..) |entry, idx| {
            if (idx > 0) try device_json.append(allocator, ',');
            try device_json.print(allocator, "{s}:{d}", .{ std.json.fmt(entry.device_id, .{}), entry.count });
        }
        try device_json.append(allocator, '}');
        const device_json_owned = try device_json.toOwnedSlice(allocator);
        defer allocator.free(device_json_owned);

        var out = std.array_list.Managed(u8).init(allocator);
        errdefer out.deinit();
        try out.print(
            \\{{"total_requests":{d},"status_2xx":{d},"status_3xx":{d},"status_4xx":{d},"status_5xx":{d},"uptime_seconds":{d},"active_connections":{d},"mux_connections":{d},"mux_subscriptions":{d},"mux_subscriptions_by_device":{s},"connection_rejections":{d},"queue_rejections":{d},"upstream_unhealthy_backends":{d},"proxy_streaming_requests_total":{d},"proxy_buffered_requests_total":{d},"proxy_buffered_bytes_current":{d},"proxy_buffered_bytes_total":{d},"proxy_client_aborts_total":{d},"proxy_upstream_aborts_total":{d},"proxy_ttfb_ms_count":{d},"proxy_ttfb_ms_sum":{d}
        , .{
            metrics_snapshot.total_requests,
            metrics_snapshot.status_2xx,
            metrics_snapshot.status_3xx,
            metrics_snapshot.status_4xx,
            metrics_snapshot.status_5xx,
            metrics_snapshot.uptimeSeconds(),
            metrics_snapshot.active_connections,
            metrics_snapshot.mux_connections,
            metrics_snapshot.mux_subscriptions,
            device_json_owned,
            metrics_snapshot.connection_rejections,
            metrics_snapshot.queue_rejections,
            metrics_snapshot.upstream_unhealthy_backends,
            metrics_snapshot.proxy_streaming_requests,
            metrics_snapshot.proxy_buffered_requests,
            metrics_snapshot.proxy_buffered_bytes_current,
            metrics_snapshot.proxy_buffered_bytes_total,
            metrics_snapshot.proxy_client_aborts,
            metrics_snapshot.proxy_upstream_aborts,
            metrics_snapshot.proxy_ttfb_ms_count,
            metrics_snapshot.proxy_ttfb_ms_sum,
        });
        try out.print(
            \\,"request_latency_ms_count":{d},"request_latency_ms_sum":{d},"worker_active_jobs":{d},"worker_queued_jobs":{d},"worker_threads":{d},"worker_queue_capacity":{d},"error_invalid_request":{d},"error_unauthorized":{d},"error_rate_limited":{d},"error_upstream_timeout":{d},"error_upstream_unavailable":{d},"error_internal_error":{d},"error_overload":{d},"mux_frame_errors":{d}}}
        , .{
            metrics_snapshot.latency_count,
            metrics_snapshot.latency_sum_ms,
            metrics_snapshot.worker_active_jobs,
            metrics_snapshot.worker_queued_jobs,
            metrics_snapshot.worker_threads,
            metrics_snapshot.worker_queue_capacity,
            metrics_snapshot.err_invalid_request,
            metrics_snapshot.err_unauthorized,
            metrics_snapshot.err_rate_limited,
            metrics_snapshot.err_upstream_timeout,
            metrics_snapshot.err_upstream_unavailable,
            metrics_snapshot.err_internal_error,
            metrics_snapshot.err_overload,
            metrics_snapshot.mux_frame_errors,
        });
        return out.toOwnedSlice();
    }

    pub fn metricsToPrometheus(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        const mux_snapshot = try self.muxMetricsSnapshot(allocator);
        defer deinitMuxMetricsSnapshot(allocator, mux_snapshot.device_counts);

        self.metrics_mutex.lock();
        const metrics_snapshot = self.metrics;
        self.metrics_mutex.unlock();

        const base = try metrics_snapshot.toPrometheus(allocator);
        defer allocator.free(base);

        var combined = std.ArrayList(u8).empty;
        errdefer combined.deinit(allocator);
        try combined.appendSlice(allocator, base);
        if (mux_snapshot.device_counts.len > 0) {
            try combined.appendSlice(allocator,
                \\# HELP tardigrade_mux_device_channels Current active mux channels by device
                \\# TYPE tardigrade_mux_device_channels gauge
                \\
            );
            for (mux_snapshot.device_counts) |entry| {
                const line = try std.fmt.allocPrint(allocator, "tardigrade_mux_device_channels{{device_id=\"{s}\"}} {d}\n", .{ entry.device_id, entry.count });
                defer allocator.free(line);
                try combined.appendSlice(allocator, line);
            }
        }
        return combined.toOwnedSlice(allocator);
    }

    pub fn nextUpstreamBaseUrl(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, client_ip: []const u8, hash_key: []const u8) []const u8 {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        const now_ms = http.event_loop.monotonicMs();
        // When the pool has no static primaries, check DNS-discovered upstreams first.
        if (pool.primary_urls.len == 0) {
            if (self.selectDiscoveredUpstreamLocked(now_ms)) |discovered| return discovered;
        }
        return self.nextUpstreamBaseUrlLocked(cfg, pool, client_ip, hash_key, now_ms);
    }

    /// Select a URL from the DNS-discovered upstream set in round-robin order.
    /// Must be called while holding upstream_mutex. Returns null when discovery
    /// is inactive or the discovered set is empty.
    pub fn selectDiscoveredUpstreamLocked(self: *GatewayState, now_ms: u64) ?[]const u8 {
        _ = now_ms;
        // We need to read dns_discovery.urls. Since dns_discovery has its own mutex
        // and we already hold upstream_mutex, we must not block — tryLock instead.
        if (!self.dns_discovery.mutex.tryLock()) return null;
        defer self.dns_discovery.mutex.unlock();
        const urls = self.dns_discovery.urls.items;
        if (urls.len == 0) return null;
        const idx = self.upstream_rr_index % urls.len;
        self.upstream_rr_index = (idx + 1) % urls.len;
        return urls[idx];
    }

    pub fn nextStickyUpstreamBaseUrl(
        self: *GatewayState,
        cfg: *const edge_config.EdgeConfig,
        pool: UpstreamPoolView,
        client_ip: []const u8,
        hash_key: []const u8,
        requested_upstream: ?[]const u8,
    ) StickyUpstreamSelection {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        const now_ms = http.event_loop.monotonicMs();

        if (requested_upstream) |candidate| {
            if (self.isStickyUpstreamHealthyLocked(cfg, pool, candidate, now_ms)) {
                return .{ .base_url = candidate, .used_requested = true };
            }
        }

        return .{
            .base_url = self.nextUpstreamBaseUrlLocked(cfg, pool, client_ip, hash_key, now_ms),
            .used_requested = false,
        };
    }

    pub fn nextUpstreamBaseUrlLocked(
        self: *GatewayState,
        cfg: *const edge_config.EdgeConfig,
        pool: UpstreamPoolView,
        client_ip: []const u8,
        hash_key: []const u8,
        now_ms: u64,
    ) []const u8 {
        if (pool.primary_urls.len == 0) {
            return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
        }

        switch (cfg.upstream_lb_algorithm) {
            .least_connections => {
                if (self.selectLeastConnectionsUpstreamLocked(cfg, pool, now_ms)) |selected| {
                    return selected;
                }
                return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
            },
            .ip_hash => {
                if (self.selectIpHashUpstreamLocked(cfg, pool, client_ip, now_ms)) |selected| {
                    return selected;
                }
                return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
            },
            .generic_hash => {
                if (self.selectGenericHashUpstreamLocked(cfg, pool, hash_key, now_ms)) |selected| {
                    return selected;
                }
                return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
            },
            .random_two_choices => {
                if (self.selectRandomTwoChoicesUpstreamLocked(cfg, pool, now_ms)) |selected| {
                    return selected;
                }
                return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
            },
            .round_robin => {},
        }
        const primary_slots = primaryWeightedSlotCount(pool.primary_urls, pool.primary_weights);
        const start = self.upstream_rr_index % primary_slots;

        var offset: usize = 0;
        while (offset < primary_slots) : (offset += 1) {
            const ticket = (start + offset) % primary_slots;
            const idx = weightedTicketToIndex(pool.primary_urls, pool.primary_weights, ticket);
            const candidate = pool.primary_urls[idx];
            if (self.isUpstreamHealthyLocked(cfg, candidate, now_ms) and self.slowStartAllowsTrafficLocked(cfg, candidate, now_ms, @intCast(idx))) {
                self.upstream_rr_index = (ticket + 1) % primary_slots;
                return candidate;
            }
        }

        // Fallback pass: choose any healthy backend even if still in slow-start.
        offset = 0;
        while (offset < primary_slots) : (offset += 1) {
            const ticket = (start + offset) % primary_slots;
            const idx = weightedTicketToIndex(pool.primary_urls, pool.primary_weights, ticket);
            const candidate = pool.primary_urls[idx];
            if (self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) {
                self.upstream_rr_index = (ticket + 1) % primary_slots;
                return candidate;
            }
        }

        return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, now_ms);
    }

    pub fn isStickyUpstreamHealthyLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, candidate: []const u8, now_ms: u64) bool {
        for (pool.primary_urls, 0..) |upstream, idx| {
            if (!std.mem.eql(u8, upstream, candidate)) continue;
            if (!self.isUpstreamHealthyLocked(cfg, upstream, now_ms)) return false;
            if (self.slowStartAllowsTrafficLocked(cfg, upstream, now_ms, @intCast(idx))) return true;
        }
        for (pool.primary_urls) |upstream| {
            if (std.mem.eql(u8, upstream, candidate)) {
                return self.isUpstreamHealthyLocked(cfg, upstream, now_ms);
            }
        }
        for (pool.backup_urls, 0..) |upstream, idx| {
            if (!std.mem.eql(u8, upstream, candidate)) continue;
            if (!self.isUpstreamHealthyLocked(cfg, upstream, now_ms)) return false;
            if (self.slowStartAllowsTrafficLocked(cfg, upstream, now_ms, @intCast(idx))) return true;
        }
        for (pool.backup_urls) |upstream| {
            if (std.mem.eql(u8, upstream, candidate)) {
                return self.isUpstreamHealthyLocked(cfg, upstream, now_ms);
            }
        }
        if (std.mem.eql(u8, pool.fallback_url, candidate)) {
            return self.isUpstreamHealthyLocked(cfg, candidate, now_ms);
        }
        return false;
    }

    pub fn selectLeastConnectionsUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) ?[]const u8 {
        var best_idx: ?usize = null;
        var best_load: usize = std.math.maxInt(usize);
        for (pool.primary_urls, 0..) |candidate, idx| {
            if (!self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) continue;
            if (!self.slowStartAllowsTrafficLocked(cfg, candidate, now_ms, @intCast(idx))) continue;

            const load = self.upstream_active_requests.get(candidate) orelse 0;
            if (best_idx == null or load < best_load) {
                best_idx = idx;
                best_load = load;
            }
        }
        if (best_idx) |idx| {
            self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
            return pool.primary_urls[idx];
        }
        return null;
    }

    pub fn selectIpHashUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, client_ip: []const u8, now_ms: u64) ?[]const u8 {
        if (pool.primary_urls.len == 0) return null;
        const start = ipHashIndex(client_ip, pool.primary_urls.len);

        var offset: usize = 0;
        while (offset < pool.primary_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.primary_urls.len;
            const candidate = pool.primary_urls[idx];
            if (!self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) continue;
            if (!self.slowStartAllowsTrafficLocked(cfg, candidate, now_ms, @intCast(idx))) continue;
            self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
            return candidate;
        }

        offset = 0;
        while (offset < pool.primary_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.primary_urls.len;
            const candidate = pool.primary_urls[idx];
            if (self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) {
                self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
                return candidate;
            }
        }
        return null;
    }

    pub fn selectGenericHashUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, hash_key: []const u8, now_ms: u64) ?[]const u8 {
        if (pool.primary_urls.len == 0) return null;
        const start = ipHashIndex(hash_key, pool.primary_urls.len);

        var offset: usize = 0;
        while (offset < pool.primary_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.primary_urls.len;
            const candidate = pool.primary_urls[idx];
            if (!self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) continue;
            if (!self.slowStartAllowsTrafficLocked(cfg, candidate, now_ms, @intCast(idx))) continue;
            self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
            return candidate;
        }

        offset = 0;
        while (offset < pool.primary_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.primary_urls.len;
            const candidate = pool.primary_urls[idx];
            if (self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) {
                self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
                return candidate;
            }
        }
        return null;
    }

    pub fn nextLbRandomLocked(self: *GatewayState) u64 {
        self.lb_random_state = lcrngNext(self.lb_random_state);
        return self.lb_random_state;
    }

    pub fn nextRandomIndexLocked(self: *GatewayState, len: usize) usize {
        if (len == 0) return 0;
        return @intCast(self.nextLbRandomLocked() % len);
    }

    pub fn selectRandomTwoChoicesUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) ?[]const u8 {
        if (pool.primary_urls.len == 0) return null;

        const first_idx = self.nextRandomIndexLocked(pool.primary_urls.len);
        var second_idx = first_idx;
        if (pool.primary_urls.len > 1) {
            second_idx = self.nextRandomIndexLocked(pool.primary_urls.len - 1);
            if (second_idx >= first_idx) second_idx += 1;
        }

        const first = pool.primary_urls[first_idx];
        const second = pool.primary_urls[second_idx];
        const first_healthy = self.isUpstreamHealthyLocked(cfg, first, now_ms);
        const second_healthy = self.isUpstreamHealthyLocked(cfg, second, now_ms);
        const first_strict = first_healthy and self.slowStartAllowsTrafficLocked(cfg, first, now_ms, @intCast(first_idx));
        const second_strict = second_healthy and self.slowStartAllowsTrafficLocked(cfg, second, now_ms, @intCast(second_idx));

        const chosen_idx: ?usize = blk: {
            if (first_strict and second_strict) {
                const first_load = self.upstream_active_requests.get(first) orelse 0;
                const second_load = self.upstream_active_requests.get(second) orelse 0;
                break :blk if (second_load < first_load) second_idx else first_idx;
            }
            if (first_strict) break :blk first_idx;
            if (second_strict) break :blk second_idx;
            if (first_healthy and second_healthy) {
                const first_load = self.upstream_active_requests.get(first) orelse 0;
                const second_load = self.upstream_active_requests.get(second) orelse 0;
                break :blk if (second_load < first_load) second_idx else first_idx;
            }
            if (first_healthy) break :blk first_idx;
            if (second_healthy) break :blk second_idx;
            break :blk null;
        };

        if (chosen_idx) |idx| {
            self.upstream_rr_index = (idx + 1) % pool.primary_urls.len;
            return pool.primary_urls[idx];
        }
        return null;
    }

    pub fn selectPrimaryFallbackWithBackupsLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) []const u8 {
        if (self.selectBackupUpstreamLocked(cfg, pool, now_ms)) |backup| {
            return backup;
        }
        // If all primary backends are currently unhealthy, still probe primaries in round-robin order.
        return selectUpstreamBaseUrlWeighted(pool.primary_urls, pool.primary_weights, pool.fallback_url, &self.upstream_rr_index);
    }

    pub fn selectBackupUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) ?[]const u8 {
        if (pool.backup_urls.len == 0) return null;

        const start = self.upstream_backup_rr_index % pool.backup_urls.len;
        var offset: usize = 0;
        while (offset < pool.backup_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.backup_urls.len;
            const candidate = pool.backup_urls[idx];
            if (!self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) continue;
            if (!self.slowStartAllowsTrafficLocked(cfg, candidate, now_ms, @intCast(idx))) continue;
            self.upstream_backup_rr_index = (idx + 1) % pool.backup_urls.len;
            return candidate;
        }

        offset = 0;
        while (offset < pool.backup_urls.len) : (offset += 1) {
            const idx = (start + offset) % pool.backup_urls.len;
            const candidate = pool.backup_urls[idx];
            if (self.isUpstreamHealthyLocked(cfg, candidate, now_ms)) {
                self.upstream_backup_rr_index = (idx + 1) % pool.backup_urls.len;
                return candidate;
            }
        }
        return null;
    }

    pub fn recordUpstreamFailure(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8) void {
        if (cfg.upstream_max_fails == 0) return;

        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();

        if (self.upstream_health.getPtr(upstream_base_url)) |health| {
            health.fail_count +|= 1;
            if (health.fail_count >= cfg.upstream_max_fails) {
                health.fail_count = 0;
                health.unhealthy_until_ms = http.event_loop.monotonicMs() + cfg.upstream_fail_timeout_ms;
            }
            self.updateUpstreamHealthMetricLocked();
            return;
        }

        const owned = self.allocator.dupe(u8, upstream_base_url) catch return;
        self.upstream_health.put(owned, .{}) catch {
            self.allocator.free(owned);
            return;
        };
        if (self.upstream_health.getPtr(owned)) |health| {
            health.fail_count = 1;
            if (health.fail_count >= cfg.upstream_max_fails) {
                health.fail_count = 0;
                health.unhealthy_until_ms = http.event_loop.monotonicMs() + cfg.upstream_fail_timeout_ms;
            }
        }
        self.updateUpstreamHealthMetricLocked();
    }

    pub fn recordUpstreamSuccess(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8) void {
        if (cfg.upstream_max_fails == 0) return;

        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        if (self.upstream_health.getPtr(upstream_base_url)) |health| {
            health.fail_count = 0;
            health.unhealthy_until_ms = 0;
            health.slow_start_until_ms = 0;
        }
        self.updateUpstreamHealthMetricLocked();
    }

    pub fn recordActiveProbeResult(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, healthy: bool) void {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();

        const health = if (self.upstream_health.getPtr(upstream_base_url)) |existing|
            existing
        else blk: {
            const owned = self.allocator.dupe(u8, upstream_base_url) catch return;
            self.upstream_health.put(owned, .{}) catch {
                self.allocator.free(owned);
                return;
            };
            break :blk self.upstream_health.getPtr(owned).?;
        };

        const health_cfg = activeHealthConfig(cfg, upstream_base_url);
        const transition = if (healthy)
            health.probe.recordSuccess(health_cfg)
        else
            health.probe.recordFailure(health_cfg);

        switch (transition) {
            .marked_up => {
                health.unhealthy_until_ms = 0;
                health.fail_count = 0;
                self.beginSlowStartLocked(cfg, health, http.event_loop.monotonicMs());
            },
            .marked_down => {
                health.unhealthy_until_ms = http.event_loop.monotonicMs() + cfg.upstream_fail_timeout_ms;
                health.slow_start_until_ms = 0;
            },
            else => {},
        }
        self.updateUpstreamHealthMetricLocked();
    }

    pub fn isUpstreamHealthyLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, now_ms: u64) bool {
        if (self.upstream_health.getPtr(upstream_base_url)) |health| {
            if (health.unhealthy_until_ms != 0 and now_ms >= health.unhealthy_until_ms) {
                health.unhealthy_until_ms = 0;
                health.fail_count = 0;
                self.beginSlowStartLocked(cfg, health, now_ms);
                self.updateUpstreamHealthMetricLocked();
            }
            if (health.unhealthy_until_ms != 0 and now_ms < health.unhealthy_until_ms) return false;
            if (cfg.upstream_active_health_interval_ms > 0 and !health.probe.isRoutable()) return false;
            return true;
        }
        return true;
    }

    pub fn slowStartAllowsTrafficLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, now_ms: u64, ticket: u64) bool {
        if (cfg.upstream_slow_start_ms == 0) return true;
        const health = self.upstream_health.getPtr(upstream_base_url) orelse return true;
        if (health.slow_start_until_ms == 0) return true;
        if (now_ms >= health.slow_start_until_ms) {
            health.slow_start_until_ms = 0;
            return true;
        }

        const remaining = health.slow_start_until_ms - now_ms;
        if (remaining >= cfg.upstream_slow_start_ms) return false;
        const elapsed = cfg.upstream_slow_start_ms - remaining;
        const allowed_percent: u64 = @max(1, (elapsed * 100) / cfg.upstream_slow_start_ms);
        return (ticket % 100) < allowed_percent;
    }

    pub fn beginSlowStartLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, health: *UpstreamHealth, now_ms: u64) void {
        _ = self;
        if (cfg.upstream_slow_start_ms == 0) {
            health.slow_start_until_ms = 0;
            return;
        }
        health.slow_start_until_ms = now_ms + cfg.upstream_slow_start_ms;
    }

    pub fn updateUpstreamHealthMetricLocked(self: *GatewayState) void {
        const now_ms = http.event_loop.monotonicMs();
        var unhealthy: usize = 0;
        var it = self.upstream_health.iterator();
        while (it.next()) |entry| {
            const health = entry.value_ptr.*;
            if (health.unhealthy_until_ms > now_ms or !health.probe.isRoutable()) unhealthy += 1;
        }
        self.metrics_mutex.lock();
        self.metrics.setUpstreamUnhealthyBackends(unhealthy);
        self.metrics_mutex.unlock();
    }

    pub fn upstreamUnhealthyCount(self: *GatewayState) usize {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        const now_ms = http.event_loop.monotonicMs();
        var unhealthy: usize = 0;
        var it = self.upstream_health.iterator();
        while (it.next()) |entry| {
            const health = entry.value_ptr.*;
            if (health.unhealthy_until_ms > now_ms or !health.probe.isRoutable()) unhealthy += 1;
        }
        return unhealthy;
    }

    pub fn recordUpstreamAttemptStart(self: *GatewayState, upstream_base_url: []const u8) void {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();

        if (self.upstream_active_requests.getPtr(upstream_base_url)) |count| {
            count.* += 1;
            return;
        }
        const owned = self.allocator.dupe(u8, upstream_base_url) catch return;
        self.upstream_active_requests.put(owned, 1) catch {
            self.allocator.free(owned);
        };
    }

    pub fn recordUpstreamAttemptEnd(self: *GatewayState, upstream_base_url: []const u8) void {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        if (self.upstream_active_requests.getPtr(upstream_base_url)) |count| {
            if (count.* > 1) {
                count.* -= 1;
            } else {
                if (self.upstream_active_requests.fetchRemove(upstream_base_url)) |kv| {
                    self.allocator.free(kv.key);
                }
            }
        }
    }

    pub fn streamCountAdjust(self: *GatewayState, ws_delta: i32, sse_delta: i32) void {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();
        if (ws_delta < 0) {
            const dec: usize = @intCast(-ws_delta);
            self.active_ws_streams = if (self.active_ws_streams > dec) self.active_ws_streams - dec else 0;
        } else if (ws_delta > 0) {
            self.active_ws_streams += @intCast(ws_delta);
        }
        if (sse_delta < 0) {
            const dec: usize = @intCast(-sse_delta);
            self.active_sse_streams = if (self.active_sse_streams > dec) self.active_sse_streams - dec else 0;
        } else if (sse_delta > 0) {
            self.active_sse_streams += @intCast(sse_delta);
        }
    }

    pub fn streamCounts(self: *GatewayState) struct { ws: usize, sse: usize } {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();
        return .{ .ws = self.active_ws_streams, .sse = self.active_sse_streams };
    }

    pub fn muxConnectionAdjust(self: *GatewayState, delta: i32) void {
        self.connection_mutex.lock();
        if (delta < 0) {
            const dec: usize = @intCast(-delta);
            self.active_mux_connections = if (self.active_mux_connections > dec) self.active_mux_connections - dec else 0;
        } else if (delta > 0) {
            self.active_mux_connections += @intCast(delta);
        }
        const active = self.active_mux_connections;
        self.connection_mutex.unlock();

        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.setMuxConnections(active);
    }

    pub fn muxSubscriptionCount(self: *GatewayState, device_id: []const u8) usize {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();
        return self.mux_subscriptions_by_device.get(device_id) orelse 0;
    }

    pub fn muxSubscriptionAdjust(self: *GatewayState, device_id: []const u8, delta: i32) void {
        self.connection_mutex.lock();
        if (delta < 0) {
            const dec: usize = @intCast(-delta);
            self.active_mux_subscriptions = if (self.active_mux_subscriptions > dec) self.active_mux_subscriptions - dec else 0;
            if (self.mux_subscriptions_by_device.getPtr(device_id)) |count_ptr| {
                count_ptr.* = if (count_ptr.* > dec) count_ptr.* - dec else 0;
                if (count_ptr.* == 0) {
                    if (self.mux_subscriptions_by_device.fetchRemove(device_id)) |removed| {
                        self.allocator.free(removed.key);
                    }
                }
            }
        } else if (delta > 0) {
            const inc: usize = @intCast(delta);
            self.active_mux_subscriptions += inc;
            if (self.mux_subscriptions_by_device.getPtr(device_id)) |count_ptr| {
                count_ptr.* += inc;
            } else {
                const owned = self.allocator.dupe(u8, device_id) catch {
                    self.connection_mutex.unlock();
                    return;
                };
                self.mux_subscriptions_by_device.put(owned, inc) catch {
                    self.allocator.free(owned);
                    self.connection_mutex.unlock();
                    return;
                };
            }
        }
        const active = self.active_mux_subscriptions;
        self.connection_mutex.unlock();

        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.setMuxSubscriptions(active);
    }

    pub fn muxMetricsSnapshot(self: *GatewayState, allocator: std.mem.Allocator) !MuxMetricsSnapshot {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();

        var device_counts = std.ArrayList(MuxDeviceCount).empty;
        errdefer {
            for (device_counts.items) |entry| allocator.free(entry.device_id);
            device_counts.deinit(allocator);
        }
        var it = self.mux_subscriptions_by_device.iterator();
        while (it.next()) |entry| {
            try device_counts.append(allocator, .{
                .device_id = try allocator.dupe(u8, entry.key_ptr.*),
                .count = entry.value_ptr.*,
            });
        }
        return .{ .device_counts = try device_counts.toOwnedSlice(allocator) };
    }

    pub fn saveMuxResumeState(self: *GatewayState, device_id: []const u8, channels: []const MuxChannel, grace_ms: u32) void {
        self.runtime_mutex.lock();
        defer self.runtime_mutex.unlock();

        if (self.mux_resume_state.fetchRemove(device_id)) |removed| {
            self.allocator.free(removed.key);
            var value = removed.value;
            deinitMuxResumeState(self.allocator, &value);
        }
        if (grace_ms == 0 or channels.len == 0) return;

        const owned_key = self.allocator.dupe(u8, device_id) catch return;
        const owned_channels = cloneMuxChannels(self.allocator, channels) catch {
            self.allocator.free(owned_key);
            return;
        };
        self.mux_resume_state.put(owned_key, .{
            .channels = owned_channels,
            .expires_ms = compat.milliTimestamp() + @as(i64, grace_ms),
        }) catch {
            var saved_state = MuxResumeState{ .channels = owned_channels, .expires_ms = 0 };
            deinitMuxResumeState(self.allocator, &saved_state);
            self.allocator.free(owned_key);
        };
    }

    pub fn takeMuxResumeState(self: *GatewayState, allocator: std.mem.Allocator, device_id: []const u8) ?[]MuxChannel {
        self.runtime_mutex.lock();
        defer self.runtime_mutex.unlock();

        const removed = self.mux_resume_state.fetchRemove(device_id) orelse return null;
        defer self.allocator.free(removed.key);
        var saved = removed.value;
        defer deinitMuxResumeState(self.allocator, &saved);
        if (saved.expires_ms < compat.milliTimestamp()) return null;
        return cloneMuxChannels(allocator, saved.channels) catch null;
    }

    pub fn connectionCounts(self: *GatewayState) struct { active: usize, per_ip: usize } {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();
        return .{ .active = self.active_connections_total, .per_ip = self.active_connections_by_ip.count() };
    }

    pub fn upstreamHealthJson(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, "{\"upstreams\":[");
        var first = true;
        const now_ms = http.event_loop.monotonicMs();
        var it = self.upstream_health.iterator();
        while (it.next()) |entry| {
            if (!first) try out.appendSlice(allocator, ",");
            first = false;
            const url = entry.key_ptr.*;
            const h = entry.value_ptr.*;
            const healthy = (h.unhealthy_until_ms == 0 or h.unhealthy_until_ms <= now_ms) and h.probe.isRoutable();
            try out.print(
                allocator,
                "{{\"url\":\"{s}\",\"healthy\":{},\"unhealthy_until_ms\":{d},\"active_status\":\"{s}\"}}",
                .{ url, healthy, h.unhealthy_until_ms, h.probe.status.asString() },
            );
        }
        try out.appendSlice(allocator, "]}");
        return out.toOwnedSlice(allocator);
    }
};

/// Linear congruential PRNG step used for load-balancing randomness.
/// Always called while holding GatewayState.upstream_mutex; exposed as a
/// standalone pure function so it can be unit-tested independently.
pub fn lcrngNext(state: u64) u64 {
    return state *% 6364136223846793005 +% 1442695040888963407;
}

pub fn upstreamPoolForScope(cfg: *const edge_config.EdgeConfig, scope: UpstreamScope) UpstreamPoolView {
    return switch (scope) {
        .chat => if (cfg.upstream_chat_base_urls.len > 0 or cfg.upstream_chat_backup_base_urls.len > 0)
            .{
                .fallback_url = cfg.upstream_base_url,
                .primary_urls = cfg.upstream_chat_base_urls,
                .primary_weights = cfg.upstream_chat_base_url_weights,
                .backup_urls = cfg.upstream_chat_backup_base_urls,
            }
        else
            upstreamPoolForScope(cfg, .global),
        .commands => if (cfg.upstream_commands_base_urls.len > 0 or cfg.upstream_commands_backup_base_urls.len > 0)
            .{
                .fallback_url = cfg.upstream_base_url,
                .primary_urls = cfg.upstream_commands_base_urls,
                .primary_weights = cfg.upstream_commands_base_url_weights,
                .backup_urls = cfg.upstream_commands_backup_base_urls,
            }
        else
            upstreamPoolForScope(cfg, .global),
        .global => .{
            .fallback_url = cfg.upstream_base_url,
            .primary_urls = cfg.upstream_base_urls,
            .primary_weights = cfg.upstream_base_url_weights,
            .backup_urls = cfg.upstream_backup_base_urls,
        },
    };
}

fn stickyCookieSecret(cfg: *const edge_config.EdgeConfig) []const u8 {
    if (cfg.trust_shared_secret.len > 0) return cfg.trust_shared_secret;
    if (cfg.jwt_secret.len > 0) return cfg.jwt_secret;
    return "";
}

fn stickyAffinityEligible(cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, proxy_pass_target: []const u8) bool {
    if (stickyCookieSecret(cfg).len == 0) return false;
    if (isAbsoluteHttpUrl(std.mem.trim(u8, proxy_pass_target, " \t\r\n"))) return false;

    var upstreams: usize = pool.primary_urls.len + pool.backup_urls.len;
    if (upstreams == 0 and pool.fallback_url.len > 0) upstreams = 1;
    return upstreams > 1;
}

pub fn prepareStickyAffinityRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    pool: UpstreamPoolView,
    headers: *const http.Headers,
    incoming_host: ?[]const u8,
    location_id: []const u8,
    proxy_pass_target: []const u8,
) !?StickyAffinityRequest {
    if (!stickyAffinityEligible(cfg, pool, proxy_pass_target)) return null;

    const host = if (incoming_host) |value|
        std.mem.trim(u8, value, " \t\r\n")
    else
        "";
    const normalized_host = if (host.len > 0) host else "-";
    const location_key = try std.fmt.allocPrint(allocator, "{s}|{s}", .{ normalized_host, location_id });
    errdefer allocator.free(location_key);
    const cookie_name = try affinityCookieName(allocator, location_key);
    errdefer allocator.free(cookie_name);
    const requested_upstream = try parseStickyCookieUpstream(allocator, cfg, headers, location_key, cookie_name);

    return .{
        .location_key = location_key,
        .cookie_name = cookie_name,
        .requested_upstream = requested_upstream,
    };
}

fn affinityCookieName(allocator: std.mem.Allocator, location_key: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "__Host-tg-aff-{x}", .{std.hash.Wyhash.hash(0, location_key)});
}

pub fn buildStickySetCookieHeader(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    affinity: *const StickyAffinityRequest,
    selected_upstream: []const u8,
) !?[]u8 {
    if (affinity.requested_upstream) |requested| {
        if (std.mem.eql(u8, requested, selected_upstream)) return null;
    }

    const value = try stickyCookieValue(allocator, stickyCookieSecret(cfg), affinity.location_key, selected_upstream);
    defer allocator.free(value);
    return try std.fmt.allocPrint(
        allocator,
        "{s}={s}; Path=/; HttpOnly; Secure; SameSite=Lax",
        .{ affinity.cookie_name, value },
    );
}

fn stickyCookieValue(
    allocator: std.mem.Allocator,
    secret: []const u8,
    location_key: []const u8,
    upstream_base_url: []const u8,
) ![]u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const upstream_b64 = try allocator.alloc(u8, enc.calcSize(upstream_base_url.len));
    defer allocator.free(upstream_b64);
    _ = enc.encode(upstream_b64, upstream_base_url);

    const signature_hex = try stickyCookieSignatureHex(allocator, secret, location_key, upstream_base_url);
    defer allocator.free(signature_hex);
    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ upstream_b64, signature_hex });
}

fn stickyCookieSignatureHex(
    allocator: std.mem.Allocator,
    secret: []const u8,
    location_key: []const u8,
    upstream_base_url: []const u8,
) ![]u8 {
    const material = try std.fmt.allocPrint(allocator, "{s}\n{s}", .{ location_key, upstream_base_url });
    defer allocator.free(material);

    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, material, secret);
    return std.fmt.allocPrint(allocator, "{f}", .{compat.fmtSliceHexLower(&mac)});
}

fn parseStickyCookieUpstream(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    headers: *const http.Headers,
    location_key: []const u8,
    cookie_name: []const u8,
) !?[]u8 {
    const raw_cookie = findCookieValue(headers, cookie_name) orelse return null;
    const dot = std.mem.findScalarLast(u8, raw_cookie, '.') orelse return null;
    const encoded_upstream = raw_cookie[0..dot];
    const provided_sig = raw_cookie[dot + 1 ..];
    if (encoded_upstream.len == 0 or provided_sig.len == 0) return null;

    const dec = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = dec.calcSizeForSlice(encoded_upstream) catch return null;
    const upstream = try allocator.alloc(u8, decoded_len);
    dec.decode(upstream, encoded_upstream) catch {
        allocator.free(upstream);
        return null;
    };

    const expected_sig = try stickyCookieSignatureHex(allocator, stickyCookieSecret(cfg), location_key, upstream);
    defer allocator.free(expected_sig);
    if (!std.mem.eql(u8, expected_sig, provided_sig)) {
        allocator.free(upstream);
        return null;
    }

    return upstream;
}

fn findCookieValue(headers: *const http.Headers, cookie_name: []const u8) ?[]const u8 {
    for (headers.iterator()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cookie")) continue;
        if (findCookieValueInHeader(header.value, cookie_name)) |value| return value;
    }
    return null;
}

fn findCookieValueInHeader(cookie_header: []const u8, cookie_name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, cookie_header, ';');
    while (it.next()) |segment_raw| {
        const segment = std.mem.trim(u8, segment_raw, " \t\r\n");
        if (segment.len <= cookie_name.len or segment[cookie_name.len] != '=') continue;
        if (!std.mem.eql(u8, segment[0..cookie_name.len], cookie_name)) continue;
        return std.mem.trim(u8, segment[cookie_name.len + 1 ..], " \t\r\n");
    }
    return null;
}

fn selectUpstreamBaseUrl(base_urls: []const []const u8, fallback: []const u8, rr_index: *usize) []const u8 {
    if (base_urls.len == 0) return fallback;
    const idx = rr_index.* % base_urls.len;
    rr_index.* = (idx + 1) % base_urls.len;
    return base_urls[idx];
}

fn primaryWeightedSlotCount(base_urls: []const []const u8, weights: []const u32) usize {
    if (base_urls.len == 0) return 0;
    if (weights.len != base_urls.len or weights.len == 0) return base_urls.len;

    var total: usize = 0;
    for (weights) |w| total +|= w;
    return if (total == 0) base_urls.len else total;
}

fn weightedTicketToIndex(base_urls: []const []const u8, weights: []const u32, ticket: usize) usize {
    if (base_urls.len == 0) return 0;
    if (weights.len != base_urls.len or weights.len == 0) return ticket % base_urls.len;

    const total = primaryWeightedSlotCount(base_urls, weights);
    var remaining = ticket % total;
    for (weights, 0..) |w, idx| {
        if (remaining < w) return idx;
        remaining -= w;
    }
    return base_urls.len - 1;
}

fn selectUpstreamBaseUrlWeighted(base_urls: []const []const u8, weights: []const u32, fallback: []const u8, rr_index: *usize) []const u8 {
    if (base_urls.len == 0) return fallback;
    const slots = primaryWeightedSlotCount(base_urls, weights);
    const ticket = rr_index.* % slots;
    const idx = weightedTicketToIndex(base_urls, weights, ticket);
    rr_index.* = (ticket + 1) % slots;
    return base_urls[idx];
}

fn ipHashIndex(client_ip: []const u8, len: usize) usize {
    if (len == 0) return 0;
    const hash = std.hash.Wyhash.hash(0, client_ip);
    return @intCast(hash % len);
}

pub const WorkerContext = struct {
    config_store: *ReloadableConfigStore,
    state: *GatewayState,
    tls: ?*http.tls_termination.TlsTerminator,
    session_pool: *ConnectionSessionPool,
    /// Event loop used to (un)watch idle keepalive connections (#138). A worker
    /// re-arms a parked fd here; the loop thread dispatches it back on readiness.
    event_loop: *http.event_loop.EventLoop,
    /// Registry of idle keepalive connections parked off the worker pool (#138).
    parked: *http.keepalive_park.ParkedRegistry,

    pub fn acquireConfig(self: *WorkerContext) ConfigLease {
        return self.config_store.acquire();
    }
};

pub const ManagedConfigVersion = struct {
    cfg: *const edge_config.EdgeConfig,
    owned_cfg: ?*edge_config.EdgeConfig,
    ref_count: usize,
};

pub const ConfigLease = struct {
    store: *ReloadableConfigStore,
    version: *ManagedConfigVersion,
    cfg: *const edge_config.EdgeConfig,

    pub fn release(self: *ConfigLease) void {
        self.store.release(self.version);
        self.* = undefined;
    }
};

pub const ReloadableConfigStore = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    current: *ManagedConfigVersion,
    retired: std.ArrayList(*ManagedConfigVersion),

    pub fn initBorrowed(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig) !ReloadableConfigStore {
        return .{
            .allocator = allocator,
            .current = try createBorrowedVersion(allocator, cfg),
            .retired = .empty,
        };
    }

    pub fn deinit(self: *ReloadableConfigStore) void {
        for (self.retired.items) |version| {
            self.destroyVersion(version);
        }
        self.retired.deinit(self.allocator);
        self.destroyVersion(self.current);
        self.* = undefined;
    }

    pub fn acquire(self: *ReloadableConfigStore) ConfigLease {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.current.ref_count += 1;
        return .{
            .store = self,
            .version = self.current,
            .cfg = self.current.cfg,
        };
    }

    pub fn prepareOwned(self: *ReloadableConfigStore, cfg_ptr: *edge_config.EdgeConfig) !*ManagedConfigVersion {
        const version = try createOwnedVersion(self.allocator, cfg_ptr);
        self.mutex.lock();
        defer self.mutex.unlock();
        self.retired.ensureUnusedCapacity(self.allocator, 1) catch |err| {
            self.destroyVersion(version);
            return err;
        };
        return version;
    }

    pub fn installPrepared(self: *ReloadableConfigStore, new_version: *ManagedConfigVersion) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const old_version = self.current;
        self.current = new_version;
        self.retired.appendAssumeCapacity(old_version);
        std.debug.assert(old_version.ref_count > 0);
        old_version.ref_count -= 1;
        self.collectRetiredLocked();
    }

    pub fn release(self: *ReloadableConfigStore, version: *ManagedConfigVersion) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        std.debug.assert(version.ref_count > 0);
        version.ref_count -= 1;
        self.collectRetiredLocked();
    }

    pub fn collectRetiredLocked(self: *ReloadableConfigStore) void {
        var idx: usize = 0;
        while (idx < self.retired.items.len) {
            const version = self.retired.items[idx];
            if (version.ref_count == 0) {
                self.destroyVersion(version);
                _ = self.retired.swapRemove(idx);
                continue;
            }
            idx += 1;
        }
    }

    pub fn destroyVersion(self: *ReloadableConfigStore, version: *ManagedConfigVersion) void {
        if (version.owned_cfg) |owned_cfg| {
            owned_cfg.deinit(self.allocator);
            self.allocator.destroy(owned_cfg);
        }
        self.allocator.destroy(version);
    }

    pub fn createBorrowedVersion(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig) !*ManagedConfigVersion {
        const version = try allocator.create(ManagedConfigVersion);
        version.* = .{
            .cfg = cfg,
            .owned_cfg = null,
            .ref_count = 1,
        };
        return version;
    }

    pub fn createOwnedVersion(allocator: std.mem.Allocator, cfg_ptr: *edge_config.EdgeConfig) !*ManagedConfigVersion {
        const version = try allocator.create(ManagedConfigVersion);
        version.* = .{
            .cfg = cfg_ptr,
            .owned_cfg = cfg_ptr,
            .ref_count = 1,
        };
        return version;
    }
};

pub const ConnectionSession = struct {
    pending_buf: ?[]u8 = null,
    pending_len: usize = 0,
    proxy_protocol_checked: bool = false,
    proxy_client_ip_len: usize = 0,
    proxy_client_ip_buf: [64]u8 = undefined,
};

pub const ConnectionSessionPool = struct {
    allocator: std.mem.Allocator,
    buffer_pool: *http.buffer_pool.BufferPool,
    mutex: compat.Mutex = .{},
    free_list: std.ArrayList(*ConnectionSession),
    max_cached: usize,

    pub fn init(allocator: std.mem.Allocator, buffer_pool: *http.buffer_pool.BufferPool, max_cached: usize) ConnectionSessionPool {
        return .{
            .allocator = allocator,
            .buffer_pool = buffer_pool,
            .free_list = .empty,
            .max_cached = max_cached,
        };
    }

    pub fn deinit(self: *ConnectionSessionPool) void {
        for (self.free_list.items) |session| {
            if (session.pending_buf) |buf| self.buffer_pool.release(buf);
            self.allocator.destroy(session);
        }
        self.free_list.deinit(self.allocator);
    }

    pub fn acquire(self: *ConnectionSessionPool) !*ConnectionSession {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.free_list.items.len > 0) {
            const session = self.free_list.pop().?;
            session.* = .{};
            return session;
        }
        const session = try self.allocator.create(ConnectionSession);
        session.* = .{};
        return session;
    }

    pub fn release(self: *ConnectionSessionPool, session: *ConnectionSession) void {
        if (session.pending_buf) |buf| self.buffer_pool.release(buf);
        session.pending_len = 0;
        session.pending_buf = null;
        session.proxy_protocol_checked = false;
        session.proxy_client_ip_len = 0;

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.free_list.items.len >= self.max_cached) {
            self.allocator.destroy(session);
            return;
        }
        self.free_list.append(self.allocator, session) catch {
            self.allocator.destroy(session);
        };
    }
};

/// Load persisted approvals from disk into state at startup.
/// Prunes entries older than 1 hour that are no longer pending.
pub fn loadApprovalStore(state: *GatewayState) !void {
    const stored = try http.approval_store.load(state.allocator, state.approval_store_path);
    defer http.approval_store.freeLoaded(state.allocator, stored);

    const now = compat.milliTimestamp();
    const retention_ms: i64 = 3_600_000; // 1 hour retention for decided entries

    for (stored) |s| {
        const status = std.meta.stringToEnum(ApprovalStatus, s.status) orelse .escalated;
        // Prune old decided entries; always keep pending ones.
        if (status != .pending and s.decided_ms > 0 and (now - s.decided_ms) > retention_ms) {
            continue;
        }
        const token_key = state.allocator.dupe(u8, s.token) catch continue;
        const entry = ApprovalEntry{
            .method = state.allocator.dupe(u8, s.method) catch {
                state.allocator.free(token_key);
                continue;
            },
            .path = state.allocator.dupe(u8, s.path) catch {
                state.allocator.free(token_key);
                continue;
            },
            .identity = state.allocator.dupe(u8, s.identity) catch {
                state.allocator.free(token_key);
                continue;
            },
            .command_id = state.allocator.dupe(u8, s.command_id) catch {
                state.allocator.free(token_key);
                continue;
            },
            .status = status,
            .created_ms = s.created_ms,
            .expires_ms = s.expires_ms,
            .decided_ms = s.decided_ms,
            .decided_by = state.allocator.dupe(u8, s.decided_by) catch {
                state.allocator.free(token_key);
                continue;
            },
            .escalation_fired = s.escalation_fired,
        };
        state.approvals.put(token_key, entry) catch {
            state.allocator.free(token_key);
        };
    }
}

pub fn loadSessionStore(state: *GatewayState) !void {
    if (state.session_store == null or state.session_store_path.len == 0) return;
    const stored = try http.session_store_file.load(state.allocator, state.session_store_path);
    defer http.session_store_file.freeLoaded(state.allocator, stored);
    if (state.session_store) |*store| {
        try http.session_store_file.restore(state.allocator, store, stored);
    }
}

// Helper functions used by GatewayState methods (must live here to avoid
// cross-module calls from within the struct).

pub fn isAbsoluteHttpUrl(value: []const u8) bool {
    return std.mem.startsWith(u8, value, "http://") or std.mem.startsWith(u8, value, "https://");
}

pub fn activeHealthConfig(cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8) http.health_checker.Config {
    var success_status = cfg.upstream_active_health_success_status;
    for (cfg.upstream_active_health_success_status_overrides) |entry| {
        if (std.mem.eql(u8, upstream_base_url, entry.upstream_base_url)) {
            success_status = entry.range;
            break;
        }
    }
    return .{
        .path = cfg.upstream_active_health_path,
        .interval_ms = cfg.upstream_active_health_interval_ms,
        .timeout_ms = cfg.upstream_active_health_timeout_ms,
        .fail_threshold = cfg.upstream_active_health_fail_threshold,
        .success_threshold = cfg.upstream_active_health_success_threshold,
        .success_status_min = success_status.min,
        .success_status_max = success_status.max,
    };
}

fn proxyCacheFilePath(allocator: std.mem.Allocator, cache_path: []const u8, key: []const u8) ![]u8 {
    var key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key, &key_digest, .{});
    var key_digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&key_digest_hex, "{f}", .{compat.fmtSliceHexLower(&key_digest)}) catch unreachable;
    return std.fmt.allocPrint(allocator, "{s}/{s}.cache", .{ cache_path, key_digest_hex[0..] });
}

fn proxyCacheWriteToDisk(cache_path: []const u8, key: []const u8, status: u16, body: []const u8, content_type: []const u8) !void {
    if (cache_path.len == 0) return;
    compat.cwd().makePath(cache_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const allocator = std.heap.page_allocator;
    const file_path = try proxyCacheFilePath(allocator, cache_path, key);
    defer allocator.free(file_path);

    var fc = try compat.cwd().createFile(file_path, .{ .truncate = true, .read = false });
    defer fc.close();
    const header = try std.fmt.allocPrint(allocator, "{d}\n{d}\n{s}\n\n", .{ status, compat.nanoTimestamp(), content_type });
    defer allocator.free(header);
    try fc.writeAll(header);
    try fc.writeAll(body);
}

fn proxyCacheReadFromDisk(
    allocator: std.mem.Allocator,
    cache_path: []const u8,
    key: []const u8,
    ttl_seconds: u32,
    stale_seconds: u32,
) !?ProxyCacheLookup {
    if (cache_path.len == 0) return null;
    const file_path = try proxyCacheFilePath(allocator, cache_path, key);
    defer allocator.free(file_path);

    const raw = compat.cwd().readFileAlloc(allocator, file_path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(raw);

    const l1 = std.mem.findScalar(u8, raw, '\n') orelse return null;
    const l2 = std.mem.findScalarPos(u8, raw, l1 + 1, '\n') orelse return null;
    const l3 = std.mem.findScalarPos(u8, raw, l2 + 1, '\n') orelse return null;
    if (l3 + 1 >= raw.len or raw[l3 + 1] != '\n') return null;
    const body_start = l3 + 2;

    const status = std.fmt.parseInt(u16, std.mem.trim(u8, raw[0..l1], " \t\r\n"), 10) catch return null;
    const created_ns = std.fmt.parseInt(i128, std.mem.trim(u8, raw[l1 + 1 .. l2], " \t\r\n"), 10) catch return null;
    const ct_slice = std.mem.trim(u8, raw[l2 + 1 .. l3], " \t\r\n");
    const now_ns = compat.nanoTimestamp();
    const age_ns = now_ns - created_ns;
    const ttl_ns: i128 = @as(i128, ttl_seconds) * std.time.ns_per_s;
    const stale_ns: i128 = @as(i128, stale_seconds) * std.time.ns_per_s;
    if (age_ns > ttl_ns + stale_ns) {
        _ = proxyCacheDeleteFromDisk(cache_path, key);
        return null;
    }

    const body = try allocator.dupe(u8, raw[body_start..]);
    errdefer allocator.free(body);
    const ct = try allocator.dupe(u8, ct_slice);
    return .{
        .cached = .{
            .status = status,
            .body = body,
            .content_type = ct,
            .created_ns = created_ns,
        },
        .is_stale = age_ns > ttl_ns,
    };
}

fn proxyCacheDeleteFromDisk(cache_path: []const u8, key: []const u8) bool {
    if (cache_path.len == 0) return false;
    const allocator = std.heap.page_allocator;
    const file_path = proxyCacheFilePath(allocator, cache_path, key) catch return false;
    defer allocator.free(file_path);
    compat.cwd().deleteFile(file_path) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return false,
    };
    return true;
}

fn proxyCachePurgeDisk(cache_path: []const u8) usize {
    if (cache_path.len == 0) return 0;
    var dir = compat.cwd().openDir(cache_path, .{ .iterate = true }) catch return 0;
    defer dir.close();

    var removed: usize = 0;
    var it = dir.iterate();
    while (it.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        dir.deleteFile(entry.name) catch continue;
        removed += 1;
    }
    return removed;
}

// Tests for types and functions defined in this module.
test "lcrngNext produces distinct successive values" {
    // Verify the LCG advances state on each step.
    const seed: u64 = 1;
    const v1 = lcrngNext(seed);
    const v2 = lcrngNext(v1);
    const v3 = lcrngNext(v2);
    try std.testing.expect(v1 != seed);
    try std.testing.expect(v2 != v1);
    try std.testing.expect(v3 != v2);
}

test "lcrngNext is deterministic" {
    // Same seed always produces the same sequence — important for reproducible
    // load-balancing behaviour in tests.
    const seed: u64 = 0xDEADBEEFCAFEBABE;
    try std.testing.expectEqual(lcrngNext(seed), lcrngNext(seed));
    try std.testing.expectEqual(lcrngNext(lcrngNext(seed)), lcrngNext(lcrngNext(seed)));
}

test "lcrngNext never returns zero from non-zero seed" {
    // LCG multiplier is odd and addend is odd, so the period is 2^64.
    // Verify a run of 1024 steps from a non-zero seed never wraps to zero
    // (statistical sanity check, not a proof of full period).
    var state: u64 = 42;
    var i: usize = 0;
    while (i < 1024) : (i += 1) {
        state = lcrngNext(state);
        try std.testing.expect(state != 0);
    }
}

test "selectUpstreamBaseUrl round-robins across configured bases" {
    var idx: usize = 0;
    const base_urls = [_][]const u8{
        "http://upstream-a:8080",
        "http://upstream-b:8080",
        "http://upstream-c:8080",
    };

    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrl(base_urls[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-b:8080", selectUpstreamBaseUrl(base_urls[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-c:8080", selectUpstreamBaseUrl(base_urls[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrl(base_urls[0..], "http://fallback:8080", &idx));
}

test "selectUpstreamBaseUrlWeighted honors configured weights" {
    var idx: usize = 0;
    const base_urls = [_][]const u8{
        "http://upstream-a:8080",
        "http://upstream-b:8080",
        "http://upstream-c:8080",
    };
    const weights = [_]u32{ 3, 1, 2 };

    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-b:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-c:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-c:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
    try std.testing.expectEqualStrings("http://upstream-a:8080", selectUpstreamBaseUrlWeighted(base_urls[0..], weights[0..], "http://fallback:8080", &idx));
}

test "connection session pool reuses released sessions" {
    var buffer_pool = http.buffer_pool.BufferPool.init(std.testing.allocator, 1024, 4);
    defer buffer_pool.deinit();
    var pool = ConnectionSessionPool.init(std.testing.allocator, &buffer_pool, 4);
    defer pool.deinit();

    const first = try pool.acquire();
    first.pending_len = 42;
    pool.release(first);

    const second = try pool.acquire();
    defer pool.release(second);

    try std.testing.expect(first == second);
    try std.testing.expectEqual(@as(usize, 0), second.pending_len);
}

test "reloadable config store retires old config after last lease" {
    var first_cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    var second_cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{});

    var store = try ReloadableConfigStore.initBorrowed(std.testing.allocator, &first_cfg);
    defer store.deinit();

    var lease = store.acquire();
    try store.retired.ensureUnusedCapacity(std.testing.allocator, 1);
    const new_version = try ReloadableConfigStore.createBorrowedVersion(std.testing.allocator, &second_cfg);
    store.installPrepared(new_version);

    try std.testing.expectEqual(@as(usize, 1), store.retired.items.len);
    lease.release();
    try std.testing.expectEqual(@as(usize, 0), store.retired.items.len);
}
