const std = @import("std");
const builtin = @import("builtin");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");

const MAX_REQUEST_SIZE: usize = 256 * 1024;
const STREAM_RELAY_BUFFER_SIZE: usize = 16 * 1024;
const JSON_CONTENT_TYPE = "application/json";
const ADMIN_ROUTES_JSON =
    "{\"routes\":[" ++
    "\"/health\",\"/metrics\",\"/metrics/json\",\"/metrics/prometheus\"," ++
    "\"/admin/routes\",\"/admin/connections\",\"/admin/streams\",\"/admin/upstreams\",\"/admin/certs\",\"/admin/auth-registry\"," ++
    "\"/v1/chat\",\"/v1/commands\",\"/v1/commands/status\",\"/v1/approvals/request\",\"/v1/approvals/respond\",\"/v1/approvals/status\",\"/v1/sessions\",\"/v1/cache/purge\"," ++
    "\"/v1/ws/chat\",\"/v1/ws/commands\",\"/v1/ws/mux\",\"/v1/events/stream\",\"/v1/events/publish\"," ++
    "\"/v1/subrequest\",\"/v1/backend/fastcgi\",\"/v1/backend/uwsgi\",\"/v1/backend/scgi\",\"/v1/backend/grpc\",\"/v1/backend/memcached\"," ++
    "\"/v1/mail/smtp\",\"/v1/mail/imap\",\"/v1/mail/pop3\",\"/v1/stream/tcp\",\"/v1/stream/udp\"" ++
    "]}";
const HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP2_MAX_FRAME_SIZE: usize = 16 * 1024;
const WS_MUX_MAX_CHANNELS: usize = 32;
/// Fallback approval TTL when no config value is provided (5 minutes).
const APPROVAL_TIMEOUT_MS_DEFAULT: i64 = 300_000;
const ProxyCacheLookup = struct {
    cached: http.idempotency.CachedResponse,
    is_stale: bool,
};

const UpstreamHealth = struct {
    fail_count: u32 = 0,
    unhealthy_until_ms: u64 = 0,
    probe: http.health_checker.State = .{},
    slow_start_until_ms: u64 = 0,
};

const ConnectionSlotResult = enum {
    accepted,
    over_ip_limit,
    over_global_limit,
    over_global_memory_limit,
};

const Http2PendingStream = struct {
    method: ?[]u8 = null,
    path: ?[]u8 = null,
    headers: http.Headers,
    body: std.ArrayList(u8),
    priority_weight: u8 = 16,

    fn init(allocator: std.mem.Allocator) Http2PendingStream {
        return .{
            .headers = http.Headers.init(allocator),
            .body = std.ArrayList(u8).init(allocator),
        };
    }

    fn deinit(self: *Http2PendingStream, allocator: std.mem.Allocator) void {
        if (self.method) |m| allocator.free(m);
        if (self.path) |p| allocator.free(p);
        self.headers.deinit();
        self.body.deinit();
        self.* = undefined;
    }
};

const UpstreamScope = enum {
    global,
    chat,
    commands,
};

const UpstreamPoolView = struct {
    fallback_url: []const u8,
    primary_urls: []const []const u8,
    primary_weights: []const u32,
    backup_urls: []const []const u8,
};

const CommandLifecycleStatus = enum {
    pending,
    running,
    completed,
    failed,
};

const CommandLifecycleEntry = struct {
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

const CommandLifecycleSnapshot = struct {
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

const ApprovalStatus = enum {
    pending,
    approved,
    denied,
    escalated,
};

const ApprovalDecision = enum {
    approve,
    deny,
};

const ApprovalValidation = enum {
    approved,
    pending,
    denied,
    escalated,
    invalid,
    missing,
};

const ApprovalEntry = struct {
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

const ApprovalCreateResult = struct {
    token: []u8,
    expires_ms: i64,
};

const MuxChannelKind = enum {
    events,
    command,
};

const MuxChannel = struct {
    name: []u8,
    kind: MuxChannelKind,
    topic: ?[]u8 = null,
    last_event_id: u64 = 0,
    command_id: ?[]u8 = null,
    last_command_status: ?CommandLifecycleStatus = null,
};

/// Persistent gateway state shared across connections.
const GatewayState = struct {
    allocator: std.mem.Allocator,
    connection_mutex: std.Thread.Mutex = .{},
    rate_limiter_mutex: std.Thread.Mutex = .{},
    idempotency_mutex: std.Thread.Mutex = .{},
    proxy_cache_mutex: std.Thread.Mutex = .{},
    session_mutex: std.Thread.Mutex = .{},
    command_mutex: std.Thread.Mutex = .{},
    approval_mutex: std.Thread.Mutex = .{},
    circuit_mutex: std.Thread.Mutex = .{},
    metrics_mutex: std.Thread.Mutex = .{},
    upstream_mutex: std.Thread.Mutex = .{},
    runtime_mutex: std.Thread.Mutex = .{},
    rate_limiter: ?http.rate_limiter.RateLimiter,
    idempotency_store: ?http.idempotency.IdempotencyStore,
    proxy_cache_store: ?http.idempotency.IdempotencyStore,
    proxy_cache_path: []const u8,
    proxy_cache_ttl_seconds: u32,
    security_headers: http.security_headers.SecurityHeaders,
    add_headers: []const edge_config.EdgeConfig.HeaderPair,
    http3_alt_svc: ?[]u8,
    http3_runtime: ?*http.http3_runtime.Runtime,
    session_store: ?http.session.SessionStore,
    access_control: ?http.access_control.AccessControl,
    logger: http.logger.Logger,
    metrics: http.metrics.Metrics,
    compression_config: http.compression.CompressionConfig,
    circuit_breaker: http.circuit_breaker.CircuitBreaker,
    upstream_client: std.http.Client,
    event_hub: http.event_hub.EventHub,
    request_buffer_pool: http.buffer_pool.BufferPool,
    relay_buffer_pool: http.buffer_pool.BufferPool,
    max_connections_per_ip: u32,
    max_active_connections: u32,
    active_connections_total: usize,
    active_ws_streams: usize,
    active_sse_streams: usize,
    connection_memory_estimate_bytes: usize,
    max_total_connection_memory_bytes: usize,
    upstream_rr_index: usize,
    upstream_backup_rr_index: usize,
    lb_random_state: u64,
    next_active_health_probe_ms: u64,
    next_proxy_cache_maintenance_ms: u64,
    upstream_health: std.StringHashMap(UpstreamHealth),
    upstream_active_requests: std.StringHashMap(usize),
    fastcgi_pool: std.StringHashMap(std.ArrayList(std.net.Stream)),
    fastcgi_next_request_id: std.StringHashMap(u16),
    proxy_cache_locks: std.StringHashMap(u32),
    active_connections_by_ip: std.StringHashMap(u32),
    active_fds: std.AutoHashMap(std.posix.fd_t, void),
    fd_to_ip: std.AutoHashMap(std.posix.fd_t, []u8),
    command_lifecycle: std.StringHashMap(CommandLifecycleEntry),
    approvals: std.StringHashMap(ApprovalEntry),
    /// Path to persistent approval store file (empty = in-memory only).
    approval_store_path: []const u8,
    /// Webhook URL for escalation notifications (empty = disabled).
    approval_escalation_webhook: []const u8,
    /// Approval TTL in milliseconds.
    approval_ttl_ms: i64,
    /// Max concurrent pending approval requests per identity (0 = unlimited).
    approval_max_pending_per_identity: u32,

    fn deinit(self: *GatewayState) void {
        if (self.rate_limiter) |*rl| rl.deinit();
        if (self.idempotency_store) |*is| is.deinit();
        if (self.proxy_cache_store) |*pc| pc.deinit();
        if (self.session_store) |*ss| ss.deinit();
        if (self.access_control) |*acl| acl.deinit();
        self.upstream_client.deinit();
        self.event_hub.deinit();
        self.request_buffer_pool.deinit();
        self.relay_buffer_pool.deinit();
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
            entry.value_ptr.deinit();
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
    }

    fn acquireFastcgiStream(self: *GatewayState, endpoint: []const u8) !struct { stream: std.net.Stream, reused: bool } {
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

    fn releaseFastcgiStream(self: *GatewayState, endpoint: []const u8, stream: std.net.Stream, allow_reuse: bool) void {
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
            pool.append(stream) catch {
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
        var pool = std.ArrayList(std.net.Stream).init(self.allocator);
        pool.append(stream) catch {
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
            pool.deinit();
            self.allocator.free(owned_key);
        };
    }

    fn nextFastcgiRequestId(self: *GatewayState, endpoint: []const u8) u16 {
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

    fn tryAcquireConnectionSlot(self: *GatewayState, fd: std.posix.fd_t, ip_key: []const u8) !ConnectionSlotResult {
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

    fn releaseConnectionSlot(self: *GatewayState, fd: std.posix.fd_t) void {
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

    fn rateLimitAllow(self: *GatewayState, client_ip: []const u8) bool {
        self.rate_limiter_mutex.lock();
        defer self.rate_limiter_mutex.unlock();
        if (self.rate_limiter) |*rl| {
            return rl.allow(client_ip) != null;
        }
        return true;
    }

    fn idempotencyGetCopy(self: *GatewayState, allocator: std.mem.Allocator, key: []const u8) !?http.idempotency.CachedResponse {
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

    fn idempotencyPut(self: *GatewayState, key: []const u8, status: u16, body: []const u8, content_type: []const u8) !void {
        self.idempotency_mutex.lock();
        defer self.idempotency_mutex.unlock();
        if (self.idempotency_store) |*store| {
            try store.put(key, status, body, content_type);
        }
    }

    fn proxyCacheGetCopyWithStale(self: *GatewayState, allocator: std.mem.Allocator, key: []const u8, stale_seconds: u32) !?ProxyCacheLookup {
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
                store.put(key, found.cached.status, found.cached.body, found.cached.content_type) catch {};
            }
        }
        return disk_lookup;
    }

    fn proxyCachePut(self: *GatewayState, key: []const u8, status: u16, body: []const u8, content_type: []const u8) !void {
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

    fn proxyCacheDelete(self: *GatewayState, key: []const u8) bool {
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

    fn proxyCachePurgeAll(self: *GatewayState) usize {
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

    fn proxyCacheTryLock(self: *GatewayState, key: []const u8) !bool {
        self.proxy_cache_mutex.lock();
        defer self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_locks.contains(key)) return false;
        const owned = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned);
        try self.proxy_cache_locks.put(owned, 1);
        return true;
    }

    fn proxyCacheUnlock(self: *GatewayState, key: []const u8) void {
        self.proxy_cache_mutex.lock();
        defer self.proxy_cache_mutex.unlock();
        if (self.proxy_cache_locks.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
        }
    }

    fn proxyCacheWaitForUnlock(self: *GatewayState, key: []const u8, timeout_ms: u32) bool {
        const deadline = http.event_loop.monotonicMs() + timeout_ms;
        while (http.event_loop.monotonicMs() < deadline) {
            self.proxy_cache_mutex.lock();
            const locked = self.proxy_cache_locks.contains(key);
            self.proxy_cache_mutex.unlock();
            if (!locked) return true;
            std.time.sleep(10 * std.time.ns_per_ms);
        }
        return false;
    }

    fn createSession(self: *GatewayState, allocator: std.mem.Allocator, identity: []const u8, client_ip: []const u8, device_id: ?[]const u8) ![]const u8 {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const token = try self.session_store.?.create(identity, client_ip, device_id);
        return try allocator.dupe(u8, token);
    }

    fn validateSessionIdentity(self: *GatewayState, allocator: std.mem.Allocator, token: []const u8) ?[]const u8 {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store) |*ss| {
            if (ss.validate(token)) |session| {
                return allocator.dupe(u8, session.identity) catch null;
            }
        }
        return null;
    }

    fn revokeSession(self: *GatewayState, token: []const u8) bool {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store) |*ss| return ss.revoke(token);
        return false;
    }

    fn countSessionsByIdentity(self: *GatewayState, allocator: std.mem.Allocator, identity: []const u8) !usize {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const sessions = try self.session_store.?.listByIdentity(allocator, identity);
        defer allocator.free(sessions);
        return sessions.len;
    }

    fn refreshSession(self: *GatewayState, allocator: std.mem.Allocator, token: []const u8, client_ip: []const u8) ![]const u8 {
        self.session_mutex.lock();
        defer self.session_mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const existing = self.session_store.?.validate(token) orelse return error.InvalidSession;
        const new_token = try self.session_store.?.create(existing.identity, client_ip, existing.device_id);
        _ = self.session_store.?.revoke(token);
        return try allocator.dupe(u8, new_token);
    }

    fn commandLifecycleCreate(self: *GatewayState, command_id: []const u8, command_type: []const u8, correlation_id: []const u8, identity: []const u8) !void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        const now = std.time.milliTimestamp();
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

    fn commandLifecycleSetRunning(self: *GatewayState, command_id: []const u8) void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        if (self.command_lifecycle.getPtr(command_id)) |entry| {
            entry.status = .running;
            entry.updated_ms = std.time.milliTimestamp();
        }
    }

    fn commandLifecycleSetCompleted(self: *GatewayState, command_id: []const u8, status: u16, body: []const u8, content_type: []const u8) void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        if (self.command_lifecycle.getPtr(command_id)) |entry| {
            self.allocator.free(entry.response_body);
            self.allocator.free(entry.response_content_type);
            self.allocator.free(entry.error_message);
            entry.status = .completed;
            entry.updated_ms = std.time.milliTimestamp();
            entry.response_status = status;
            entry.response_body = self.allocator.dupe(u8, body) catch self.allocator.dupe(u8, "") catch return;
            entry.response_content_type = self.allocator.dupe(u8, content_type) catch self.allocator.dupe(u8, "") catch return;
            entry.error_message = self.allocator.dupe(u8, "") catch self.allocator.dupe(u8, "") catch return;
        }
    }

    fn commandLifecycleSetFailed(self: *GatewayState, command_id: []const u8, message: []const u8) void {
        self.command_mutex.lock();
        defer self.command_mutex.unlock();
        if (self.command_lifecycle.getPtr(command_id)) |entry| {
            self.allocator.free(entry.error_message);
            entry.status = .failed;
            entry.updated_ms = std.time.milliTimestamp();
            entry.error_message = self.allocator.dupe(u8, message) catch self.allocator.dupe(u8, "command_failed") catch return;
        }
    }

    fn commandLifecycleSnapshotJson(self: *GatewayState, allocator: std.mem.Allocator, command_id: []const u8) ?[]const u8 {
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

    fn commandLifecycleGet(self: *GatewayState, allocator: std.mem.Allocator, command_id: []const u8) ?CommandLifecycleSnapshot {
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

    fn approvalCreate(self: *GatewayState, allocator: std.mem.Allocator, method: []const u8, path: []const u8, identity: []const u8, command_id: ?[]const u8) !ApprovalCreateResult {
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
            const token = try std.fmt.allocPrint(self.allocator, "apr-{d}-{s}", .{
                std.time.milliTimestamp(),
                std.fmt.fmtSliceHexLower(&rnd),
            });
            errdefer self.allocator.free(token);
            const now = std.time.milliTimestamp();
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

    fn approvalRespond(self: *GatewayState, token: []const u8, decision: ApprovalDecision, actor: []const u8) bool {
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
            entry.decided_ms = std.time.milliTimestamp();
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

    fn approvalValidate(self: *GatewayState, token: []const u8, method: []const u8, path: []const u8, identity: ?[]const u8) ApprovalValidation {
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

    fn approvalSnapshotJson(self: *GatewayState, allocator: std.mem.Allocator, token: []const u8) ?[]const u8 {
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
    fn approvalEscalateIfExpiredLocked(entry: *ApprovalEntry) bool {
        if (entry.status != .pending) return false;
        const now = std.time.milliTimestamp();
        if (now >= entry.expires_ms) {
            entry.status = .escalated;
            entry.decided_ms = now;
            return true;
        }
        return false;
    }

    /// Count pending approvals for a given identity. Must be called with approval_mutex held.
    fn approvalCountPendingForIdentityLocked(self: *GatewayState, identity: []const u8) u32 {
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
    fn buildApprovalWebhookPayloadLocked(self: *GatewayState, token: []const u8, entry: *const ApprovalEntry) ?[]u8 {
        const command_id_part = if (entry.command_id.len > 0)
            std.fmt.allocPrint(self.allocator, "\"{s}\"", .{entry.command_id}) catch return null
        else
            self.allocator.dupe(u8, "null") catch return null;
        defer self.allocator.free(command_id_part);
        return std.fmt.allocPrint(self.allocator,
            "{{\"event\":\"escalated\",\"approval_token\":\"{s}\",\"method\":\"{s}\",\"path\":\"{s}\",\"identity\":\"{s}\",\"command_id\":{s},\"created_ms\":{d},\"expires_ms\":{d}}}",
            .{ token, entry.method, entry.path, entry.identity, command_id_part, entry.created_ms, entry.expires_ms },
        ) catch null;
    }

    /// Snapshot all approval entries into a slice suitable for persistence.
    /// Must be called with approval_mutex held. Caller frees via http.approval_store.freeLoaded.
    fn approvalSnapshotEntriesLocked(self: *GatewayState, allocator: std.mem.Allocator) ![]http.approval_store.StoredApproval {
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
    fn persistApprovals(self: *GatewayState) void {
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

    fn circuitTryAcquire(self: *GatewayState) bool {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        return self.circuit_breaker.tryAcquire();
    }

    fn circuitRecordFailure(self: *GatewayState) void {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        self.circuit_breaker.recordFailure();
    }

    fn circuitRecordSuccess(self: *GatewayState) void {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        self.circuit_breaker.recordSuccess();
    }

    fn circuitStateName(self: *GatewayState) []const u8 {
        self.circuit_mutex.lock();
        defer self.circuit_mutex.unlock();
        return self.circuit_breaker.stateName();
    }

    fn metricsRecord(self: *GatewayState, status: u16) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordRequest(status);
    }

    fn metricsRecordQueueRejection(self: *GatewayState) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordQueueRejection();
    }

    fn metricsRecordErrorCode(self: *GatewayState, code: []const u8) void {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        self.metrics.recordErrorCode(code);
    }

    fn metricsToJson(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        return self.metrics.toJson(allocator);
    }

    fn metricsToPrometheus(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        self.metrics_mutex.lock();
        defer self.metrics_mutex.unlock();
        return self.metrics.toPrometheus(allocator);
    }

    fn nextUpstreamBaseUrl(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, client_ip: []const u8, hash_key: []const u8) []const u8 {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        if (pool.primary_urls.len == 0) {
            return self.selectPrimaryFallbackWithBackupsLocked(cfg, pool, http.event_loop.monotonicMs());
        }
        const now_ms = http.event_loop.monotonicMs();

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

    fn selectLeastConnectionsUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) ?[]const u8 {
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

    fn selectIpHashUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, client_ip: []const u8, now_ms: u64) ?[]const u8 {
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

    fn selectGenericHashUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, hash_key: []const u8, now_ms: u64) ?[]const u8 {
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

    fn nextLbRandomLocked(self: *GatewayState) u64 {
        self.lb_random_state = self.lb_random_state *% 6364136223846793005 +% 1442695040888963407;
        return self.lb_random_state;
    }

    fn nextRandomIndexLocked(self: *GatewayState, len: usize) usize {
        if (len == 0) return 0;
        return @intCast(self.nextLbRandomLocked() % len);
    }

    fn selectRandomTwoChoicesUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) ?[]const u8 {
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

    fn selectPrimaryFallbackWithBackupsLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) []const u8 {
        if (self.selectBackupUpstreamLocked(cfg, pool, now_ms)) |backup| {
            return backup;
        }
        // If all primary backends are currently unhealthy, still probe primaries in round-robin order.
        return selectUpstreamBaseUrlWeighted(pool.primary_urls, pool.primary_weights, pool.fallback_url, &self.upstream_rr_index);
    }

    fn selectBackupUpstreamLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, now_ms: u64) ?[]const u8 {
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

    fn recordUpstreamFailure(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8) void {
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

    fn recordUpstreamSuccess(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8) void {
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

    fn recordActiveProbeResult(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, healthy: bool) void {
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

    fn isUpstreamHealthyLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, now_ms: u64) bool {
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

    fn slowStartAllowsTrafficLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, now_ms: u64, ticket: u64) bool {
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

    fn beginSlowStartLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, health: *UpstreamHealth, now_ms: u64) void {
        _ = self;
        if (cfg.upstream_slow_start_ms == 0) {
            health.slow_start_until_ms = 0;
            return;
        }
        health.slow_start_until_ms = now_ms + cfg.upstream_slow_start_ms;
    }

    fn updateUpstreamHealthMetricLocked(self: *GatewayState) void {
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

    fn upstreamUnhealthyCount(self: *GatewayState) usize {
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

    fn recordUpstreamAttemptStart(self: *GatewayState, upstream_base_url: []const u8) void {
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

    fn recordUpstreamAttemptEnd(self: *GatewayState, upstream_base_url: []const u8) void {
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

    fn streamCountAdjust(self: *GatewayState, ws_delta: i32, sse_delta: i32) void {
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

    fn streamCounts(self: *GatewayState) struct { ws: usize, sse: usize } {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();
        return .{ .ws = self.active_ws_streams, .sse = self.active_sse_streams };
    }

    fn connectionCounts(self: *GatewayState) struct { active: usize, per_ip: usize } {
        self.connection_mutex.lock();
        defer self.connection_mutex.unlock();
        return .{ .active = self.active_connections_total, .per_ip = self.active_connections_by_ip.count() };
    }

    fn upstreamHealthJson(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        self.upstream_mutex.lock();
        defer self.upstream_mutex.unlock();
        var out = std.ArrayList(u8).init(allocator);
        errdefer out.deinit();
        try out.appendSlice("{\"upstreams\":[");
        var first = true;
        const now_ms = http.event_loop.monotonicMs();
        var it = self.upstream_health.iterator();
        while (it.next()) |entry| {
            if (!first) try out.appendSlice(",");
            first = false;
            const url = entry.key_ptr.*;
            const h = entry.value_ptr.*;
            const healthy = (h.unhealthy_until_ms == 0 or h.unhealthy_until_ms <= now_ms) and h.probe.isRoutable();
            try out.writer().print(
                "{{\"url\":\"{s}\",\"healthy\":{},\"unhealthy_until_ms\":{d},\"active_status\":\"{s}\"}}",
                .{ url, healthy, h.unhealthy_until_ms, h.probe.status.asString() },
            );
        }
        try out.appendSlice("]}");
        return out.toOwnedSlice();
    }
};

fn upstreamPoolForScope(cfg: *const edge_config.EdgeConfig, scope: UpstreamScope) UpstreamPoolView {
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

const WorkerContext = struct {
    cfg_ptr: std.atomic.Value(usize),
    state: *GatewayState,
    tls: ?*http.tls_termination.TlsTerminator,
    session_pool: *ConnectionSessionPool,

    fn currentCfg(self: *const WorkerContext) *const edge_config.EdgeConfig {
        const ptr: *const edge_config.EdgeConfig = @ptrFromInt(self.cfg_ptr.load(.seq_cst));
        return ptr;
    }
};

const ConnectionSession = struct {
    pending_buf: ?[]u8 = null,
    pending_len: usize = 0,
    proxy_protocol_checked: bool = false,
    proxy_client_ip_len: usize = 0,
    proxy_client_ip_buf: [64]u8 = undefined,
};

const ConnectionSessionPool = struct {
    allocator: std.mem.Allocator,
    buffer_pool: *http.buffer_pool.BufferPool,
    mutex: std.Thread.Mutex = .{},
    free_list: std.ArrayList(*ConnectionSession),
    max_cached: usize,

    fn init(allocator: std.mem.Allocator, buffer_pool: *http.buffer_pool.BufferPool, max_cached: usize) ConnectionSessionPool {
        return .{
            .allocator = allocator,
            .buffer_pool = buffer_pool,
            .free_list = std.ArrayList(*ConnectionSession).init(allocator),
            .max_cached = max_cached,
        };
    }

    fn deinit(self: *ConnectionSessionPool) void {
        for (self.free_list.items) |session| {
            if (session.pending_buf) |buf| self.buffer_pool.release(buf);
            self.allocator.destroy(session);
        }
        self.free_list.deinit();
    }

    fn acquire(self: *ConnectionSessionPool) !*ConnectionSession {
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

    fn release(self: *ConnectionSessionPool, session: *ConnectionSession) void {
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
        self.free_list.append(session) catch {
            self.allocator.destroy(session);
        };
    }
};

/// Load persisted approvals from disk into state at startup.
/// Prunes entries older than 1 hour that are no longer pending.
fn loadApprovalStore(state: *GatewayState) !void {
    const stored = try http.approval_store.load(state.allocator, state.approval_store_path);
    defer http.approval_store.freeLoaded(state.allocator, stored);

    const now = std.time.milliTimestamp();
    const retention_ms: i64 = 3_600_000; // 1 hour retention for decided entries

    for (stored) |s| {
        const status = std.meta.stringToEnum(ApprovalStatus, s.status) orelse .escalated;
        // Prune old decided entries; always keep pending ones.
        if (status != .pending and s.decided_ms > 0 and (now - s.decided_ms) > retention_ms) {
            continue;
        }
        const token_key = state.allocator.dupe(u8, s.token) catch continue;
        const entry = ApprovalEntry{
            .method = state.allocator.dupe(u8, s.method) catch { state.allocator.free(token_key); continue; },
            .path = state.allocator.dupe(u8, s.path) catch { state.allocator.free(token_key); continue; },
            .identity = state.allocator.dupe(u8, s.identity) catch { state.allocator.free(token_key); continue; },
            .command_id = state.allocator.dupe(u8, s.command_id) catch { state.allocator.free(token_key); continue; },
            .status = status,
            .created_ms = s.created_ms,
            .expires_ms = s.expires_ms,
            .decided_ms = s.decided_ms,
            .decided_by = state.allocator.dupe(u8, s.decided_by) catch { state.allocator.free(token_key); continue; },
            .escalation_fired = s.escalation_fired,
        };
        state.approvals.put(token_key, entry) catch { state.allocator.free(token_key); };
    }
}

pub fn run(cfg: *const edge_config.EdgeConfig) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const state_allocator = gpa.allocator();

    var state = GatewayState{
        .allocator = state_allocator,
        .rate_limiter = if (cfg.rate_limit_rps > 0)
            http.rate_limiter.RateLimiter.init(state_allocator, cfg.rate_limit_rps, cfg.rate_limit_burst)
        else
            null,
        .idempotency_store = if (cfg.idempotency_ttl_seconds > 0)
            http.idempotency.IdempotencyStore.init(state_allocator, cfg.idempotency_ttl_seconds)
        else
            null,
        .proxy_cache_store = if (cfg.proxy_cache_ttl_seconds > 0)
            http.idempotency.IdempotencyStore.init(state_allocator, cfg.proxy_cache_ttl_seconds)
        else
            null,
        .proxy_cache_path = cfg.proxy_cache_path,
        .proxy_cache_ttl_seconds = cfg.proxy_cache_ttl_seconds,
        .security_headers = if (cfg.security_headers_enabled)
            http.security_headers.SecurityHeaders.api
        else
            http.security_headers.SecurityHeaders{ .x_frame_options = "", .x_content_type_options = "", .content_security_policy = "", .strict_transport_security = "", .referrer_policy = "", .permissions_policy = "", .x_xss_protection = "" },
        .add_headers = cfg.add_headers,
        .http3_alt_svc = if (cfg.http3_enabled) http.http3_handler.formatAltSvc(state_allocator, cfg.quic_port) catch null else null,
        .http3_runtime = null,
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
            .brotli_enabled = cfg.compression_brotli_enabled,
            .brotli_quality = cfg.compression_brotli_quality,
        },
        .circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{
            .threshold = cfg.cb_threshold,
            .timeout_ms = cfg.cb_timeout_ms,
        }),
        .upstream_client = .{ .allocator = state_allocator },
        .event_hub = http.event_hub.EventHub.init(state_allocator, cfg.sse_max_events_per_topic),
        .request_buffer_pool = http.buffer_pool.BufferPool.init(state_allocator, MAX_REQUEST_SIZE, cfg.connection_pool_size),
        .relay_buffer_pool = http.buffer_pool.BufferPool.init(state_allocator, STREAM_RELAY_BUFFER_SIZE, cfg.connection_pool_size),
        .max_connections_per_ip = cfg.max_connections_per_ip,
        .max_active_connections = cfg.max_active_connections,
        .active_connections_total = 0,
        .active_ws_streams = 0,
        .active_sse_streams = 0,
        .connection_memory_estimate_bytes = if (cfg.max_connection_memory_bytes > 0) cfg.max_connection_memory_bytes else MAX_REQUEST_SIZE,
        .max_total_connection_memory_bytes = cfg.max_total_connection_memory_bytes,
        .upstream_rr_index = 0,
        .upstream_backup_rr_index = 0,
        .lb_random_state = 0x9e3779b97f4a7c15 ^ @as(u64, @intCast(http.event_loop.monotonicMs())),
        .next_active_health_probe_ms = 0,
        .next_proxy_cache_maintenance_ms = 0,
        .upstream_health = std.StringHashMap(UpstreamHealth).init(state_allocator),
        .upstream_active_requests = std.StringHashMap(usize).init(state_allocator),
        .fastcgi_pool = std.StringHashMap(std.ArrayList(std.net.Stream)).init(state_allocator),
        .fastcgi_next_request_id = std.StringHashMap(u16).init(state_allocator),
        .proxy_cache_locks = std.StringHashMap(u32).init(state_allocator),
        .active_connections_by_ip = std.StringHashMap(u32).init(state_allocator),
        .active_fds = std.AutoHashMap(std.posix.fd_t, void).init(state_allocator),
        .fd_to_ip = std.AutoHashMap(std.posix.fd_t, []u8).init(state_allocator),
        .command_lifecycle = std.StringHashMap(CommandLifecycleEntry).init(state_allocator),
        .approvals = std.StringHashMap(ApprovalEntry).init(state_allocator),
        .approval_store_path = cfg.approval_store_path,
        .approval_escalation_webhook = cfg.approval_escalation_webhook,
        .approval_ttl_ms = if (cfg.approval_ttl_ms > 0) cfg.approval_ttl_ms else APPROVAL_TIMEOUT_MS_DEFAULT,
        .approval_max_pending_per_identity = cfg.approval_max_pending_per_identity,
    };
    defer state.deinit();

    // Load approval state from persistent store (if configured).
    if (cfg.approval_store_path.len > 0) {
        loadApprovalStore(&state) catch |err| {
            state.logger.warn(null, "failed to load approval store '{s}': {}", .{ cfg.approval_store_path, err });
        };
    }

    http.access_log.init(state_allocator, .{
        .format = cfg.access_log_format,
        .custom_template = cfg.access_log_template,
        .min_status = cfg.access_log_min_status,
        .buffer_size_bytes = cfg.access_log_buffer_size,
        .syslog_udp_endpoint = cfg.access_log_syslog_udp,
    }) catch {};
    defer http.access_log.deinit();

    const address = try std.net.Address.parseIp(cfg.listen_host, cfg.listen_port);
    var server = try std.net.Address.listen(address, .{ .reuse_address = true });
    defer server.deinit();
    const listen_fd = server.stream.handle;

    try setNonBlocking(listen_fd, true);
    applyRuntimeIdentity(cfg, &state.logger) catch |err| {
        state.logger.warn(null, "privilege drop configuration failed: {}", .{err});
    };

    var event_loop = try http.event_loop.EventLoop.init();
    defer event_loop.deinit();
    try event_loop.addReadFd(listen_fd);
    var timer = http.event_loop.TimerManager.init(250);
    var http3_runtime: ?http.http3_runtime.Runtime = null;
    var tls_terminator: ?http.tls_termination.TlsTerminator = null;
    var http3_dispatch_ctx = Http3DispatchContext{ .cfg = cfg, .state = &state };
    if (edge_config.hasTlsFiles(cfg)) {
        var sni_specs = try state_allocator.alloc(http.tls_termination.SniCertSpec, cfg.tls_sni_certs.len);
        defer state_allocator.free(sni_specs);
        for (cfg.tls_sni_certs, 0..) |sc, i| {
            sni_specs[i] = .{ .server_name = sc.server_name, .cert_path = sc.cert_path, .key_path = sc.key_path };
        }
        tls_terminator = try http.tls_termination.TlsTerminator.init(state_allocator, .{
            .cert_path = cfg.tls_cert_path,
            .key_path = cfg.tls_key_path,
            .min_version = cfg.tls_min_version,
            .max_version = cfg.tls_max_version,
            .cipher_list = cfg.tls_cipher_list,
            .cipher_suites = cfg.tls_cipher_suites,
            .sni_certs = sni_specs,
            .session_cache_enabled = cfg.tls_session_cache_enabled,
            .session_cache_size = cfg.tls_session_cache_size,
            .session_timeout_seconds = cfg.tls_session_timeout_seconds,
            .session_tickets_enabled = cfg.tls_session_tickets_enabled,
            .ocsp_stapling_enabled = cfg.tls_ocsp_stapling_enabled,
            .ocsp_response_path = cfg.tls_ocsp_response_path,
            .client_ca_path = cfg.tls_client_ca_path,
            .client_verify = cfg.tls_client_verify,
            .client_verify_depth = cfg.tls_client_verify_depth,
            .crl_path = cfg.tls_crl_path,
            .crl_check = cfg.tls_crl_check,
            .dynamic_reload_interval_ms = cfg.tls_dynamic_reload_interval_ms,
            .acme_enabled = cfg.tls_acme_enabled,
            .acme_cert_dir = cfg.tls_acme_cert_dir,
            .http2_enabled = cfg.http2_enabled,
        });
    }
    defer if (tls_terminator) |*tls| tls.deinit();
    if (cfg.http3_enabled) {
        if (!edge_config.hasTlsFiles(cfg)) {
            state.logger.warn(null, "HTTP/3 requested without TLS cert/key; QUIC bootstrap will remain incomplete", .{});
        }
        http3_runtime = http.http3_runtime.Runtime.init(state_allocator, &state.logger, .{
            .listen_host = cfg.listen_host,
            .quic_port = cfg.quic_port,
            .tls_cert_path = cfg.tls_cert_path,
            .tls_key_path = cfg.tls_key_path,
            .tls_min_version = "1.3",
            .tls_max_version = "1.3",
            .enable_0rtt = cfg.http3_enable_0rtt,
            .connection_migration = cfg.http3_connection_migration,
            .max_datagram_size = cfg.http3_max_datagram_size,
            .request_handler = handleHttp3Request,
            .request_handler_ctx = &http3_dispatch_ctx,
        }) catch |err| switch (err) {
            error.DependencyUnavailable => blk: {
                state.logger.warn(null, "HTTP/3 requested but ngtcp2/nghttp3 integration is not enabled in this build", .{});
                break :blk null;
            },
            else => return err,
        };
        if (http3_runtime) |*runtime| runtime.start();
    }
    state.http3_runtime = if (http3_runtime) |*runtime| runtime else null;
    defer if (http3_runtime) |*runtime| runtime.deinit();
    const worker_count: usize = blk: {
        const configured = if (cfg.worker_threads == 0)
            (std.Thread.getCpuCount() catch 1)
        else
            cfg.worker_threads;
        break :blk @intCast(@max(configured, @as(u32, 1)));
    };
    var worker_ctx = WorkerContext{
        .cfg_ptr = std.atomic.Value(usize).init(@intFromPtr(cfg)),
        .state = &state,
        .tls = if (tls_terminator) |*tls| tls else null,
        .session_pool = undefined,
    };
    var session_pool = ConnectionSessionPool.init(state_allocator, &state.request_buffer_pool, cfg.connection_pool_size);
    defer session_pool.deinit();
    worker_ctx.session_pool = &session_pool;
    var reloaded_cfgs = std.ArrayList(*edge_config.EdgeConfig).init(state_allocator);
    defer {
        for (reloaded_cfgs.items) |rcfg| {
            rcfg.deinit(state_allocator);
            state_allocator.destroy(rcfg);
        }
        reloaded_cfgs.deinit();
    }

    var worker_pool: http.worker_pool.WorkerPool = undefined;
    try worker_pool.init(
        state_allocator,
        worker_count,
        cfg.worker_queue_size,
        handleAcceptedClient,
        &worker_ctx,
    );
    defer worker_pool.deinit();

    state.logger.info(null, "Tardigrade edge listening on {s}:{d}", .{ cfg.listen_host, cfg.listen_port });
    state.logger.info(null, "Event loop initialized with backend: {s}", .{event_loop.backendName()});
    if (!edge_config.hasTlsFiles(cfg)) {
        state.logger.warn(null, "TLS cert/key not set; serving HTTP only", .{});
    } else {
        state.logger.info(null, "TLS termination enabled with cert/key at {s} and {s}", .{ cfg.tls_cert_path, cfg.tls_key_path });
    }
    if (state.rate_limiter != null) {
        state.logger.info(null, "Rate limiting enabled: {d:.0} req/s, burst {d}", .{ cfg.rate_limit_rps, cfg.rate_limit_burst });
    }
    if (state.idempotency_store != null) {
        state.logger.info(null, "Idempotency cache enabled: TTL {d}s", .{cfg.idempotency_ttl_seconds});
    }
    if (state.proxy_cache_store != null) {
        state.logger.info(null, "Proxy cache enabled: TTL {d}s key_template={s}", .{ cfg.proxy_cache_ttl_seconds, cfg.proxy_cache_key_template });
        if (cfg.proxy_cache_path.len > 0) {
            std.fs.cwd().makePath(cfg.proxy_cache_path) catch |err| {
                state.logger.warn(null, "failed to create proxy cache path {s}: {}", .{ cfg.proxy_cache_path, err });
            };
            state.logger.info(null, "Proxy cache disk path enabled: {s}", .{cfg.proxy_cache_path});
        }
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
    state.logger.info(null, "Access log configured: format={s} min_status={d} buffer={d} syslog={s}", .{
        @tagName(cfg.access_log_format),
        cfg.access_log_min_status,
        cfg.access_log_buffer_size,
        if (cfg.access_log_syslog_udp.len > 0) cfg.access_log_syslog_udp else "off",
    });
    if (cfg.proxy_protocol_mode != .off) {
        state.logger.info(null, "Proxy protocol enabled: {s}", .{@tagName(cfg.proxy_protocol_mode)});
        if (edge_config.hasTlsFiles(cfg)) {
            state.logger.warn(null, "proxy protocol parsing currently applies only to plaintext listeners", .{});
        }
    }
    if (cfg.http3_enabled) {
        state.logger.info(null, "HTTP/3 foundation enabled: quic_port={d} 0rtt={} migration={} max_datagram={d}", .{
            cfg.quic_port,
            cfg.http3_enable_0rtt,
            cfg.http3_connection_migration,
            cfg.http3_max_datagram_size,
        });
    }
    if (cfg.trust_shared_secret.len > 0) {
        state.logger.info(null, "Trusted upstream signing enabled (gateway_id={s})", .{cfg.trust_gateway_id});
    }
    if (cfg.trusted_upstream_identities.len > 0) {
        state.logger.info(null, "Trusted upstream identities configured: {d}", .{cfg.trusted_upstream_identities.len});
    }
    if (cfg.trust_require_upstream_identity) {
        state.logger.info(null, "Strict upstream trust verification enabled", .{});
    }
    if (cfg.websocket_enabled) {
        state.logger.info(null, "WebSocket routes enabled: idle_timeout={d}ms max_frame={d} ping_interval={d}ms", .{
            cfg.websocket_idle_timeout_ms,
            cfg.websocket_max_frame_size,
            cfg.websocket_ping_interval_ms,
        });
    }
    if (cfg.sse_enabled) {
        state.logger.info(null, "SSE routes enabled: events/topic={d} poll={d}ms backlog={d} idle_timeout={d}ms", .{
            cfg.sse_max_events_per_topic,
            cfg.sse_poll_interval_ms,
            cfg.sse_max_backlog,
            cfg.sse_idle_timeout_ms,
        });
    }
    if (cfg.rewrite_rules.len > 0) {
        state.logger.info(null, "Rewrite rules enabled: {d}", .{cfg.rewrite_rules.len});
    }
    if (cfg.return_rules.len > 0) {
        state.logger.info(null, "Return rules enabled: {d}", .{cfg.return_rules.len});
    }
    if (cfg.internal_redirect_rules.len > 0) {
        state.logger.info(null, "Internal redirect rules enabled: {d}", .{cfg.internal_redirect_rules.len});
    }
    if (cfg.mirror_rules.len > 0) {
        state.logger.info(null, "Mirror rules enabled: {d}", .{cfg.mirror_rules.len});
    }
    if (cfg.fastcgi_upstream.len > 0 or cfg.uwsgi_upstream.len > 0 or cfg.scgi_upstream.len > 0 or cfg.grpc_upstream.len > 0 or cfg.memcached_upstream.len > 0) {
        state.logger.info(null, "Backend protocol bridges enabled (fastcgi/uwsgi/scgi/grpc/memcached)", .{});
    }
    if (cfg.smtp_upstream.len > 0 or cfg.imap_upstream.len > 0 or cfg.pop3_upstream.len > 0) {
        state.logger.info(null, "Mail protocol proxy routes enabled (smtp/imap/pop3)", .{});
    }
    if (cfg.tcp_proxy_upstream.len > 0 or cfg.udp_proxy_upstream.len > 0) {
        state.logger.info(null, "Stream proxy routes enabled (tcp/udp), ssl_termination={}", .{cfg.stream_ssl_termination});
    }
    {
        const limits = cfg.request_limits;
        if (limits.max_body_size > 0 or limits.max_uri_length > 0 or limits.max_header_count > 0) {
            state.logger.info(null, "Request limits configured", .{});
        }
    }
    if (cfg.compression_enabled) {
        state.logger.info(null, "Response compression enabled (min size: {d} bytes, brotli={}, br_quality={d})", .{
            cfg.compression_min_size,
            cfg.compression_brotli_enabled,
            cfg.compression_brotli_quality,
        });
    }
    if (cfg.upstream_gunzip_enabled) {
        state.logger.info(null, "Upstream gunzip enabled (proxy requests advertise Accept-Encoding: gzip)", .{});
    }
    if (cfg.cb_threshold > 0) {
        state.logger.info(null, "Circuit breaker enabled: threshold={d} timeout={d}ms", .{ cfg.cb_threshold, cfg.cb_timeout_ms });
    }
    state.logger.info(null, "Worker pool enabled: workers={d} queue={d}", .{ worker_count, cfg.worker_queue_size });
    if (cfg.fd_soft_limit > 0) {
        const applied = applyFdSoftLimit(cfg.fd_soft_limit) catch |err| blk: {
            state.logger.warn(null, "failed to apply fd soft limit: {}", .{err});
            break :blk null;
        };
        if (applied) |limit| {
            state.logger.info(null, "FD soft limit configured: {d}", .{limit});
        }
    }
    state.logger.info(null, "Keep-alive configured: timeout={d}ms max_requests={d}", .{ cfg.keep_alive_timeout_ms, cfg.max_requests_per_connection });
    state.logger.info(null, "Connection session pool configured: max_cached={d}", .{cfg.connection_pool_size});
    if (cfg.max_connection_memory_bytes > 0) {
        state.logger.info(null, "Per-connection memory limit configured: {d} bytes", .{cfg.max_connection_memory_bytes});
    }
    if (cfg.proxy_stream_all_statuses) {
        state.logger.info(null, "Proxy streaming for all upstream statuses enabled", .{});
    }
    if (cfg.upstream_base_urls.len > 0) {
        state.logger.info(null, "Upstream round-robin enabled with {d} base URLs", .{cfg.upstream_base_urls.len});
        if (cfg.upstream_base_url_weights.len > 0) {
            state.logger.info(null, "Upstream server weights enabled with {d} entries", .{cfg.upstream_base_url_weights.len});
        }
        if (cfg.upstream_backup_base_urls.len > 0) {
            state.logger.info(null, "Upstream backup servers enabled with {d} base URLs", .{cfg.upstream_backup_base_urls.len});
        }
        switch (cfg.upstream_lb_algorithm) {
            .least_connections => state.logger.info(null, "Upstream load balancing algorithm: least_connections", .{}),
            .ip_hash => state.logger.info(null, "Upstream load balancing algorithm: ip_hash", .{}),
            .generic_hash => state.logger.info(null, "Upstream load balancing algorithm: generic_hash", .{}),
            .random_two_choices => state.logger.info(null, "Upstream load balancing algorithm: random_two_choices", .{}),
            .round_robin => {},
        }
    }
    if (cfg.upstream_chat_base_urls.len > 0 or cfg.upstream_chat_backup_base_urls.len > 0) {
        state.logger.info(null, "Upstream block 'chat' enabled with {d} base URLs", .{cfg.upstream_chat_base_urls.len});
        if (cfg.upstream_chat_base_url_weights.len > 0) {
            state.logger.info(null, "Upstream block 'chat' weights enabled with {d} entries", .{cfg.upstream_chat_base_url_weights.len});
        }
        if (cfg.upstream_chat_backup_base_urls.len > 0) {
            state.logger.info(null, "Upstream block 'chat' backups enabled with {d} base URLs", .{cfg.upstream_chat_backup_base_urls.len});
        }
    }
    if (cfg.upstream_commands_base_urls.len > 0 or cfg.upstream_commands_backup_base_urls.len > 0) {
        state.logger.info(null, "Upstream block 'commands' enabled with {d} base URLs", .{cfg.upstream_commands_base_urls.len});
        if (cfg.upstream_commands_base_url_weights.len > 0) {
            state.logger.info(null, "Upstream block 'commands' weights enabled with {d} entries", .{cfg.upstream_commands_base_url_weights.len});
        }
        if (cfg.upstream_commands_backup_base_urls.len > 0) {
            state.logger.info(null, "Upstream block 'commands' backups enabled with {d} base URLs", .{cfg.upstream_commands_backup_base_urls.len});
        }
    }
    if (cfg.upstream_retry_attempts > 1) {
        state.logger.info(null, "Upstream retry attempts configured: {d}", .{cfg.upstream_retry_attempts});
    }
    if (cfg.upstream_timeout_budget_ms > 0) {
        state.logger.info(null, "Upstream timeout budget configured: {d}ms", .{cfg.upstream_timeout_budget_ms});
    }
    if (cfg.upstream_max_fails > 0) {
        state.logger.info(null, "Passive upstream health enabled: max_fails={d} fail_timeout={d}ms", .{ cfg.upstream_max_fails, cfg.upstream_fail_timeout_ms });
    }
    if (cfg.upstream_active_health_interval_ms > 0) {
        state.logger.info(null, "Active upstream health checks enabled: interval={d}ms path={s} timeout={d}ms fail_threshold={d} success_threshold={d}", .{
            cfg.upstream_active_health_interval_ms,
            cfg.upstream_active_health_path,
            cfg.upstream_active_health_timeout_ms,
            cfg.upstream_active_health_fail_threshold,
            cfg.upstream_active_health_success_threshold,
        });
    }
    if (cfg.upstream_slow_start_ms > 0) {
        state.logger.info(null, "Upstream slow-start enabled: {d}ms", .{cfg.upstream_slow_start_ms});
    }
    if (cfg.max_connections_per_ip > 0) {
        state.logger.info(null, "Per-IP connection limit enabled: {d}", .{cfg.max_connections_per_ip});
    }
    if (cfg.max_active_connections > 0) {
        state.logger.info(null, "Global active connection limit enabled: {d}", .{cfg.max_active_connections});
    }
    if (cfg.max_total_connection_memory_bytes > 0) {
        state.logger.info(null, "Global connection memory estimate limit enabled: {d} bytes", .{cfg.max_total_connection_memory_bytes});
    }

    // Install signal handlers for graceful shutdown
    http.shutdown.installSignalHandlers();
    state.logger.info(null, "Signal handlers installed (SIGTERM/SIGINT shutdown, SIGHUP reload, SIGUSR1 reopen logs, SIGUSR2 upgrade)", .{});

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
            acceptReadyConnections(listen_fd, &worker_pool, &state);
        }

        if (timer.consumeTick(http.event_loop.monotonicMs())) {
            if (http.shutdown.consumeUpgradeRequested()) {
                state.logger.info(null, "Upgrade signal received; entering graceful shutdown", .{});
                http.shutdown.requestShutdown();
            }
            if (http.shutdown.consumeReopenLogsRequested()) {
                const current_cfg = worker_ctx.currentCfg();
                http.access_log.flush();
                reopenErrorLog(current_cfg) catch |err| {
                    state.logger.warn(null, "log reopen failed: {}", .{err});
                };
            }
            if (http.shutdown.consumeReloadRequested()) {
                hotReloadConfig(state_allocator, &worker_ctx, &state, &reloaded_cfgs);
            }
            const current_cfg = worker_ctx.currentCfg();
            runActiveHealthChecks(current_cfg, &state);
            runProxyCacheMaintenance(current_cfg, &state);
            if (tls_terminator) |*tls| tls.runMaintenance(http.event_loop.monotonicMs());
        }
    }

    state.logger.info(null, "Shutdown requested; draining active connection work", .{});
    worker_pool.shutdownAndJoin(true);
    state.logger.info(null, "Graceful shutdown complete", .{});
}

fn acceptReadyConnections(listen_fd: std.posix.fd_t, worker_pool: *http.worker_pool.WorkerPool, state: *GatewayState) void {
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

        const owned_ip_key = clientIpKeyFromAddress(state.allocator, accepted_addr) catch null;
        defer if (owned_ip_key) |key| state.allocator.free(key);
        const ip_key = owned_ip_key orelse "unknown";

        const slot_result = state.tryAcquireConnectionSlot(client_fd, ip_key) catch |err| {
            state.logger.warn(null, "connection slot tracking error: {}", .{err});
            std.posix.close(client_fd);
            continue;
        };
        switch (slot_result) {
            .accepted => {},
            .over_ip_limit => {
                state.logger.warn(null, "per-IP connection limit reached for {s}", .{ip_key});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
            .over_global_limit => {
                state.logger.warn(null, "global active connection limit reached", .{});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
            .over_global_memory_limit => {
                state.logger.warn(null, "global connection memory estimate limit reached", .{});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
        }

        worker_pool.submit(client_fd) catch |err| {
            state.logger.warn(null, "worker queue submit failed: {}", .{err});
            state.metricsRecordQueueRejection();
            state.metricsRecordErrorCode("overload");
            state.releaseConnectionSlot(client_fd);
            rejectOverloadedClient(client_fd);
            continue;
        };
    }
}

fn hotReloadConfig(
    allocator: std.mem.Allocator,
    worker_ctx: *WorkerContext,
    state: *GatewayState,
    reloaded_cfgs: *std.ArrayList(*edge_config.EdgeConfig),
) void {
    const loaded = edge_config.loadFromEnv(allocator) catch |err| {
        state.logger.warn(null, "config reload failed during validation: {}", .{err});
        return;
    };
    edge_config.validate(&loaded) catch |err| {
        var rejected = loaded;
        rejected.deinit(allocator);
        state.logger.warn(null, "config reload rejected by validation: {}", .{err});
        return;
    };
    const cfg_ptr = allocator.create(edge_config.EdgeConfig) catch {
        var rejected = loaded;
        rejected.deinit(allocator);
        state.logger.warn(null, "config reload allocation failed", .{});
        return;
    };
    cfg_ptr.* = loaded;
    reloaded_cfgs.append(cfg_ptr) catch {
        cfg_ptr.deinit(allocator);
        allocator.destroy(cfg_ptr);
        state.logger.warn(null, "config reload bookkeeping failed", .{});
        return;
    };

    applyReloadedRuntimeConfig(cfg_ptr, state);
    worker_ctx.cfg_ptr.store(@intFromPtr(cfg_ptr), .seq_cst);
    http.access_log.deinit();
    http.access_log.init(allocator, .{
        .format = cfg_ptr.access_log_format,
        .custom_template = cfg_ptr.access_log_template,
        .min_status = cfg_ptr.access_log_min_status,
        .buffer_size_bytes = cfg_ptr.access_log_buffer_size,
        .syslog_udp_endpoint = cfg_ptr.access_log_syslog_udp,
    }) catch {};
    state.logger.info(null, "configuration hot-reload applied", .{});
}

fn applyReloadedRuntimeConfig(cfg: *const edge_config.EdgeConfig, state: *GatewayState) void {
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
    state.security_headers = if (cfg.security_headers_enabled)
        http.security_headers.SecurityHeaders.api
    else
        http.security_headers.SecurityHeaders{ .x_frame_options = "", .x_content_type_options = "", .content_security_policy = "", .strict_transport_security = "", .referrer_policy = "", .permissions_policy = "", .x_xss_protection = "" };
    state.max_connections_per_ip = cfg.max_connections_per_ip;
    state.max_active_connections = cfg.max_active_connections;
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

fn reopenErrorLog(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.error_log_path.len == 0 or std.ascii.eqlIgnoreCase(cfg.error_log_path, "stderr")) return;
    var file = try std.fs.cwd().createFile(cfg.error_log_path, .{ .truncate = false, .read = false });
    defer file.close();
    try file.seekFromEnd(0);
    try std.posix.dup2(file.handle, std.io.getStdErr().handle);
}

fn rejectOverloadedClient(client_fd: std.posix.fd_t) void {
    setNonBlocking(client_fd, false) catch {};
    const stream = std.net.Stream{ .handle = client_fd };
    stream.writer().writeAll(
        "HTTP/1.1 503 Service Unavailable\r\n" ++
            "Connection: close\r\n" ++
            "Content-Length: 0\r\n" ++
            "Retry-After: 1\r\n" ++
            "\r\n",
    ) catch {};
    stream.close();
}

fn runActiveHealthChecks(cfg: *const edge_config.EdgeConfig, state: *GatewayState) void {
    if (cfg.upstream_active_health_interval_ms == 0) return;

    const now_ms = http.event_loop.monotonicMs();
    if (state.next_active_health_probe_ms != 0 and now_ms < state.next_active_health_probe_ms) return;
    state.next_active_health_probe_ms = now_ms + cfg.upstream_active_health_interval_ms;

    var probe_client = std.http.Client{ .allocator = state.allocator };
    defer probe_client.deinit();

    if (cfg.upstream_base_urls.len > 0) {
        for (cfg.upstream_base_urls) |base_url| {
            probeSingleUpstream(cfg, state, &probe_client, base_url);
        }
        for (cfg.upstream_backup_base_urls) |base_url| {
            probeSingleUpstream(cfg, state, &probe_client, base_url);
        }
    } else {
        probeSingleUpstream(cfg, state, &probe_client, cfg.upstream_base_url);
    }

    for (cfg.upstream_chat_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, &probe_client, base_url);
    }
    for (cfg.upstream_chat_backup_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, &probe_client, base_url);
    }
    for (cfg.upstream_commands_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, &probe_client, base_url);
    }
    for (cfg.upstream_commands_backup_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, &probe_client, base_url);
    }
}

fn activeHealthConfig(cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8) http.health_checker.Config {
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

fn runProxyCacheMaintenance(cfg: *const edge_config.EdgeConfig, state: *GatewayState) void {
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

fn probeSingleUpstream(cfg: *const edge_config.EdgeConfig, state: *GatewayState, probe_client: *std.http.Client, base_url: []const u8) void {
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

    var header_buf: [4 * 1024]u8 = undefined;
    const unix_conn: ?*std.http.Client.Connection = if (unixSocketPathFromEndpoint(base_url)) |socket_path|
        probe_client.connectUnix(socket_path) catch |err| {
            state.logger.warn(null, "active health probe unix connect failed for {s}: {}", .{ base_url, err });
            state.recordActiveProbeResult(cfg, base_url, false);
            return;
        }
    else
        null;
    var req = probe_client.open(.GET, uri, .{
        .server_header_buffer = &header_buf,
        .connection = unix_conn,
        .keep_alive = false,
    }) catch |err| {
        state.logger.warn(null, "active health probe open failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };
    defer req.deinit();

    if (cfg.upstream_active_health_timeout_ms > 0) {
        if (req.connection) |conn| {
            setSocketTimeoutMs(conn.stream.handle, cfg.upstream_active_health_timeout_ms, cfg.upstream_active_health_timeout_ms) catch {};
        }
    }

    req.send() catch |err| {
        state.logger.warn(null, "active health probe send failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };
    req.finish() catch |err| {
        state.logger.warn(null, "active health probe finish failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };
    req.wait() catch |err| {
        state.logger.warn(null, "active health probe wait failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };

    const status_code: u16 = @intFromEnum(req.response.status);
    if (health_cfg.statusIsHealthy(status_code)) {
        state.recordActiveProbeResult(cfg, base_url, true);
    } else {
        state.recordActiveProbeResult(cfg, base_url, false);
    }
}

fn applyFdSoftLimit(desired: u64) !?u64 {
    if (desired == 0) return null;
    switch (builtin.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .solaris, .illumos, .ios, .tvos, .watchos, .visionos => {},
        else => return null,
    }

    var limits = try std.posix.getrlimit(std.posix.rlimit_resource.NOFILE);
    const current_soft: u64 = @intCast(limits.cur);
    const hard: u64 = @intCast(limits.max);
    const target: u64 = @min(desired, hard);
    if (target == current_soft) return target;

    limits.cur = @intCast(target);
    try std.posix.setrlimit(std.posix.rlimit_resource.NOFILE, limits);
    return target;
}

fn applyRuntimeIdentity(cfg: *const edge_config.EdgeConfig, logger: *const http.logger.Logger) !void {
    const c = @cImport({
        @cInclude("unistd.h");
    });
    if (cfg.chroot_dir.len > 0) {
        try std.posix.chdir(cfg.chroot_dir);
        if (c.chroot(".") != 0) return error.ChrootFailed;
        try std.posix.chdir("/");
        logger.info(null, "Applied chroot jail: {s}", .{cfg.chroot_dir});
    }

    if (cfg.run_group.len > 0) {
        const gid = std.fmt.parseInt(u32, cfg.run_group, 10) catch {
            logger.warn(null, "run_group expects numeric gid; got '{s}'", .{cfg.run_group});
            return error.InvalidRunGroup;
        };
        try std.posix.setgid(gid);
        logger.info(null, "Applied runtime group: gid={d}", .{gid});
    }
    if (cfg.run_user.len > 0) {
        const uid = std.fmt.parseInt(u32, cfg.run_user, 10) catch {
            logger.warn(null, "run_user expects numeric uid; got '{s}'", .{cfg.run_user});
            return error.InvalidRunUser;
        };
        try std.posix.setuid(uid);
        logger.info(null, "Applied runtime user: uid={d}", .{uid});
    }

    if (cfg.require_unprivileged_user and c.getuid() == 0) {
        return error.RunningAsRoot;
    }
}

fn handleAcceptedClient(raw_ctx: *anyopaque, client_fd: std.posix.fd_t) void {
    const ctx: *WorkerContext = @ptrCast(@alignCast(raw_ctx));
    defer ctx.state.releaseConnectionSlot(client_fd);
    const session = ctx.session_pool.acquire() catch |err| {
        ctx.state.logger.warn(null, "failed to acquire pooled connection session: {}", .{err});
        std.posix.close(client_fd);
        return;
    };
    defer {
        if (session.pending_buf) |buf| {
            ctx.state.request_buffer_pool.release(buf);
            session.pending_buf = null;
            session.pending_len = 0;
        }
    }
    defer ctx.session_pool.release(session);

    const cfg = ctx.currentCfg();
    const idle_timeout_ms = if (cfg.keep_alive_timeout_ms > 0)
        cfg.keep_alive_timeout_ms
    else
        cfg.request_limits.header_timeout_ms;
    if (idle_timeout_ms > 0) {
        setSocketTimeoutMs(client_fd, idle_timeout_ms, idle_timeout_ms) catch |err| {
            ctx.state.logger.warn(null, "failed to set client socket timeout: {}", .{err});
        };
    }

    setNonBlocking(client_fd, false) catch |err| {
        ctx.state.logger.warn(null, "failed to switch client fd to blocking mode: {}", .{err});
        std.posix.close(client_fd);
        return;
    };

    if (ctx.tls) |tls| {
        var tls_conn = tls.accept(client_fd) catch |err| {
            ctx.state.logger.warn(null, "tls handshake error: {}", .{err});
            std.posix.close(client_fd);
            return;
        };
        defer tls_conn.deinit();
        defer std.posix.close(client_fd);

        if (tls_conn.negotiatedProtocol() == .http2 and cfg.http2_enabled) {
            handleHttp2Connection(&tls_conn, session, cfg, ctx.state) catch |err| {
                ctx.state.logger.err(null, "http2 connection error: {}", .{err});
            };
            return;
        }

        var served: u32 = 0;
        while (true) {
            const live_cfg = ctx.currentCfg();
            var keep_alive = false;
            handleConnection(&tls_conn, session, live_cfg, ctx.state, &keep_alive, false) catch |err| {
                ctx.state.logger.err(null, "edge connection error: {}", .{err});
                break;
            };
            served += 1;
            if (http.shutdown.isShutdownRequested()) break;
            if (!keep_alive) break;
            if (live_cfg.max_requests_per_connection > 0 and served >= live_cfg.max_requests_per_connection) break;
        }
        if (served == cfg.max_requests_per_connection and cfg.max_requests_per_connection > 0) {
            ctx.state.logger.debug(null, "closing connection after max requests per connection reached ({d})", .{cfg.max_requests_per_connection});
        }
    } else {
        const stream = std.net.Stream{ .handle = client_fd };
        defer stream.close();

        var served: u32 = 0;
        while (true) {
            const live_cfg = ctx.currentCfg();
            var keep_alive = false;
            handleConnection(stream, session, live_cfg, ctx.state, &keep_alive, true) catch |err| {
                ctx.state.logger.err(null, "edge connection error: {}", .{err});
                break;
            };
            served += 1;
            if (http.shutdown.isShutdownRequested()) break;
            if (!keep_alive) break;
            if (live_cfg.max_requests_per_connection > 0 and served >= live_cfg.max_requests_per_connection) break;
        }
        if (served == cfg.max_requests_per_connection and cfg.max_requests_per_connection > 0) {
            ctx.state.logger.debug(null, "closing connection after max requests per connection reached ({d})", .{cfg.max_requests_per_connection});
        }
    }
}

fn clientIpKeyFromAddress(allocator: std.mem.Allocator, address: std.net.Address) ![]const u8 {
    return switch (address.any.family) {
        std.posix.AF.INET => blk: {
            const b = @as(*const [4]u8, @ptrCast(&address.in.sa.addr));
            break :blk std.fmt.allocPrint(allocator, "v4:{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
        },
        std.posix.AF.INET6 => std.fmt.allocPrint(allocator, "v6:{s}", .{std.fmt.fmtSliceHexLower(address.in6.sa.addr[0..])}),
        else => error.UnsupportedAddressFamily,
    };
}

fn setNonBlocking(fd: std.posix.fd_t, enabled: bool) !void {
    var flags = try std.posix.fcntl(fd, std.posix.F.GETFL, 0);
    const nonblock_mask = @as(usize, 1) << @bitOffsetOf(std.posix.O, "NONBLOCK");
    if (enabled) {
        flags |= nonblock_mask;
    } else {
        flags &= ~nonblock_mask;
    }
    _ = try std.posix.fcntl(fd, std.posix.F.SETFL, flags);
}

const ProxyHeaderOutcome = union(enum) {
    no_header,
    need_more,
    invalid,
    parsed: struct {
        consumed: usize,
        client_ip_len: usize,
    },
};

const proxy_v2_signature = "\r\n\r\n\x00\r\nQUIT\n";

fn maybeConsumeProxyProtocolPreface(conn: anytype, mode: edge_config.ProxyProtocolMode, pending_buf: []u8, pending_len: *usize, client_ip_buf: *[64]u8, client_ip_len: *usize) !void {
    if (mode == .off) return;

    while (true) {
        const outcome = parseProxyHeader(pending_buf[0..pending_len.*], mode, client_ip_buf);
        switch (outcome) {
            .no_header => return,
            .invalid => return error.InvalidProxyProtocolHeader,
            .parsed => |parsed| {
                client_ip_len.* = parsed.client_ip_len;
                if (parsed.consumed < pending_len.*) {
                    const remaining = pending_len.* - parsed.consumed;
                    std.mem.copyForwards(u8, pending_buf[0..remaining], pending_buf[parsed.consumed..pending_len.*]);
                    pending_len.* = remaining;
                } else {
                    pending_len.* = 0;
                }
                return;
            },
            .need_more => {
                if (pending_len.* == pending_buf.len) return error.ProxyProtocolHeaderTooLarge;
                const n = try conn.read(pending_buf[pending_len.*..]);
                if (n == 0) return error.ConnectionClosed;
                pending_len.* += n;
            },
        }
    }
}

fn parseProxyHeader(buf: []const u8, mode: edge_config.ProxyProtocolMode, client_ip_buf: *[64]u8) ProxyHeaderOutcome {
    return switch (mode) {
        .off => .no_header,
        .v1 => parseProxyHeaderV1(buf, true, client_ip_buf),
        .v2 => parseProxyHeaderV2(buf, true, client_ip_buf),
        .auto => blk: {
            if (buf.len == 0) break :blk .need_more;
            if (buf[0] == 'P') break :blk parseProxyHeaderV1(buf, false, client_ip_buf);
            if (buf[0] == '\r') break :blk parseProxyHeaderV2(buf, false, client_ip_buf);
            break :blk .no_header;
        },
    };
}

fn parseProxyHeaderV1(buf: []const u8, strict: bool, client_ip_buf: *[64]u8) ProxyHeaderOutcome {
    const prefix = "PROXY ";
    if (buf.len < prefix.len) {
        if (std.mem.eql(u8, buf, prefix[0..buf.len])) return .need_more;
        return if (strict) .invalid else .no_header;
    }
    if (!std.mem.eql(u8, buf[0..prefix.len], prefix)) return if (strict) .invalid else .no_header;

    const line_end = std.mem.indexOf(u8, buf, "\r\n") orelse {
        if (buf.len >= 108) return .invalid;
        return .need_more;
    };
    const line = buf[0..line_end];

    var tok_it = std.mem.tokenizeScalar(u8, line, ' ');
    const sig = tok_it.next() orelse return .invalid;
    if (!std.mem.eql(u8, sig, "PROXY")) return .invalid;
    const proto = tok_it.next() orelse return .invalid;
    if (std.mem.eql(u8, proto, "UNKNOWN")) {
        return .{ .parsed = .{ .consumed = line_end + 2, .client_ip_len = 0 } };
    }

    if (!std.mem.eql(u8, proto, "TCP4") and !std.mem.eql(u8, proto, "TCP6")) return .invalid;
    const src_ip = tok_it.next() orelse return .invalid;
    _ = tok_it.next() orelse return .invalid;
    _ = tok_it.next() orelse return .invalid;
    _ = tok_it.next() orelse return .invalid;
    if (src_ip.len == 0 or src_ip.len > client_ip_buf.len) return .invalid;
    @memcpy(client_ip_buf[0..src_ip.len], src_ip);
    return .{ .parsed = .{ .consumed = line_end + 2, .client_ip_len = src_ip.len } };
}

fn parseProxyHeaderV2(buf: []const u8, strict: bool, client_ip_buf: *[64]u8) ProxyHeaderOutcome {
    if (buf.len < proxy_v2_signature.len) {
        if (std.mem.eql(u8, buf, proxy_v2_signature[0..buf.len])) return .need_more;
        return if (strict) .invalid else .no_header;
    }
    if (!std.mem.eql(u8, buf[0..proxy_v2_signature.len], proxy_v2_signature)) return if (strict) .invalid else .no_header;
    if (buf.len < 16) return .need_more;

    const ver_cmd = buf[12];
    if ((ver_cmd >> 4) != 0x2) return .invalid;
    const cmd = ver_cmd & 0x0f;
    const fam = buf[13] >> 4;
    const addr_len = std.mem.readInt(u16, buf[14..16], .big);
    const total_len: usize = 16 + addr_len;
    if (total_len > 1024) return .invalid;
    if (buf.len < total_len) return .need_more;

    if (cmd != 0x1) {
        return .{ .parsed = .{ .consumed = total_len, .client_ip_len = 0 } };
    }

    switch (fam) {
        0x1 => {
            if (addr_len < 12) return .invalid;
            const src = buf[16..20];
            const printed = std.fmt.bufPrint(client_ip_buf, "{d}.{d}.{d}.{d}", .{ src[0], src[1], src[2], src[3] }) catch return .invalid;
            return .{ .parsed = .{ .consumed = total_len, .client_ip_len = printed.len } };
        },
        0x2 => {
            if (addr_len < 36) return .invalid;
            const src = buf[16..32];
            const g0 = std.mem.readInt(u16, src[0..2], .big);
            const g1 = std.mem.readInt(u16, src[2..4], .big);
            const g2 = std.mem.readInt(u16, src[4..6], .big);
            const g3 = std.mem.readInt(u16, src[6..8], .big);
            const g4 = std.mem.readInt(u16, src[8..10], .big);
            const g5 = std.mem.readInt(u16, src[10..12], .big);
            const g6 = std.mem.readInt(u16, src[12..14], .big);
            const g7 = std.mem.readInt(u16, src[14..16], .big);
            const printed = std.fmt.bufPrint(client_ip_buf, "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", .{ g0, g1, g2, g3, g4, g5, g6, g7 }) catch return .invalid;
            return .{ .parsed = .{ .consumed = total_len, .client_ip_len = printed.len } };
        },
        else => return .{ .parsed = .{ .consumed = total_len, .client_ip_len = 0 } },
    }
}

fn handleHttp2Connection(conn: anytype, session: *ConnectionSession, cfg: *const edge_config.EdgeConfig, state: *GatewayState) !void {
    _ = session;
    var preface: [HTTP2_PREFACE.len]u8 = undefined;
    try readExactConn(conn, preface[0..]);
    if (!std.mem.eql(u8, preface[0..], HTTP2_PREFACE)) return error.InvalidHttp2Preface;

    try http.http2_frame.writeSettings(conn.writer(), &[_][2]u32{
        .{ 0x3, 100 }, // max concurrent streams
        .{ 0x4, 1024 * 1024 }, // initial window size
    });

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    var stream_windows = std.AutoHashMap(u31, i32).init(allocator);
    defer stream_windows.deinit();
    var stream_priorities = std.AutoHashMap(u31, u8).init(allocator);
    defer stream_priorities.deinit();
    var ready_streams = std.ArrayList(u31).init(allocator);
    defer ready_streams.deinit();
    var next_server_stream_id: u31 = 2;
    var conn_send_window: i32 = 65_535;
    defer {
        var it = pending.iterator();
        while (it.next()) |entry| {
            var ps = entry.value_ptr.*;
            ps.deinit(allocator);
        }
        pending.deinit();
    }

    while (!http.shutdown.isShutdownRequested()) {
        var frame = http.http2_frame.readFrame(conn, allocator, HTTP2_MAX_FRAME_SIZE) catch |err| switch (err) {
            error.ConnectionClosed => return,
            else => return err,
        };
        defer http.http2_frame.deinitFrame(allocator, &frame);

        switch (frame.typ) {
            .settings => {
                if ((frame.flags & http.http2_frame.Flags.ACK) == 0) try http.http2_frame.writeSettingsAck(conn.writer());
            },
            .ping => {
                if ((frame.flags & http.http2_frame.Flags.ACK) == 0) try http.http2_frame.writePingAck(conn.writer(), frame.payload);
            },
            .headers => {
                if (frame.stream_id == 0) return error.InvalidHttp2StreamId;
                var payload_offset: usize = 0;
                if ((frame.flags & http.http2_frame.Flags.PRIORITY) != 0) {
                    const pr = try http.http2_frame.parsePriority(frame.payload);
                    try stream_priorities.put(frame.stream_id, pr.weight);
                    payload_offset = 5;
                }
                var decoded = try http.hpack.decode(allocator, frame.payload[payload_offset..]);
                defer http.hpack.deinitDecoded(allocator, &decoded);

                var ps = pending.get(frame.stream_id) orelse Http2PendingStream.init(allocator);
                ps.priority_weight = stream_priorities.get(frame.stream_id) orelse ps.priority_weight;
                for (decoded.headers) |h| {
                    if (std.mem.eql(u8, h.name, ":method")) {
                        if (ps.method) |m| allocator.free(m);
                        ps.method = try allocator.dupe(u8, h.value);
                    } else if (std.mem.eql(u8, h.name, ":path")) {
                        if (ps.path) |p| allocator.free(p);
                        ps.path = try allocator.dupe(u8, h.value);
                    } else if (h.name.len > 0 and h.name[0] != ':') {
                        try ps.headers.append(h.name, h.value);
                    }
                }
                try pending.put(frame.stream_id, ps);
                _ = try stream_windows.getOrPutValue(frame.stream_id, 65_535);

                if ((frame.flags & http.http2_frame.Flags.END_STREAM) != 0) {
                    try ready_streams.append(frame.stream_id);
                }
            },
            .data => {
                if (frame.stream_id == 0) return error.InvalidHttp2StreamId;
                if (stream_windows.getPtr(frame.stream_id)) |sw| sw.* -= @intCast(frame.payload.len);
                conn_send_window -= @intCast(frame.payload.len);
                if (pending.getPtr(frame.stream_id)) |ps| {
                    try ps.body.appendSlice(frame.payload);
                    try http.http2_frame.writeWindowUpdate(conn.writer(), frame.stream_id, @intCast(frame.payload.len));
                    try http.http2_frame.writeWindowUpdate(conn.writer(), 0, @intCast(frame.payload.len));
                    if (stream_windows.getPtr(frame.stream_id)) |sw| sw.* += @intCast(frame.payload.len);
                    conn_send_window += @intCast(frame.payload.len);
                    if ((frame.flags & http.http2_frame.Flags.END_STREAM) != 0) {
                        try ready_streams.append(frame.stream_id);
                    }
                } else {
                    try http.http2_frame.writeGoaway(conn.writer(), frame.stream_id, 1);
                    return;
                }
            },
            .priority => {
                const pr = try http.http2_frame.parsePriority(frame.payload);
                try stream_priorities.put(frame.stream_id, pr.weight);
                if (pending.getPtr(frame.stream_id)) |ps| ps.priority_weight = pr.weight;
            },
            .window_update => {
                const inc = try http.http2_frame.parseWindowUpdateIncrement(frame.payload);
                if (frame.stream_id == 0) {
                    conn_send_window += @intCast(inc);
                } else {
                    const gop = try stream_windows.getOrPutValue(frame.stream_id, 65_535);
                    gop.value_ptr.* += @intCast(inc);
                }
            },
            .rst_stream => {
                if (pending.fetchRemove(frame.stream_id)) |removed| {
                    var tmp = removed.value;
                    tmp.deinit(allocator);
                }
                _ = stream_windows.remove(frame.stream_id);
                _ = stream_priorities.remove(frame.stream_id);
            },
            .continuation, .push_promise, .goaway => {},
        }

        while (ready_streams.items.len > 0) {
            var best_idx: usize = 0;
            var best_weight: u8 = 0;
            for (ready_streams.items, 0..) |sid, idx| {
                const w = stream_priorities.get(sid) orelse 16;
                if (w >= best_weight) {
                    best_weight = w;
                    best_idx = idx;
                }
            }
            const sid = ready_streams.swapRemove(best_idx);
            if (pending.getPtr(sid)) |ps| {
                try respondHttp2Stream(conn.writer(), allocator, state, cfg, sid, ps, &next_server_stream_id);
            }
            if (pending.fetchRemove(sid)) |removed| {
                var tmp = removed.value;
                tmp.deinit(allocator);
            }
            _ = stream_windows.remove(sid);
            _ = stream_priorities.remove(sid);
        }
    }
}

fn respondHttp2Stream(
    writer: anytype,
    allocator: std.mem.Allocator,
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    stream_id: u31,
    ps: *const Http2PendingStream,
    next_server_stream_id: *u31,
) !void {
    const method = ps.method orelse return error.InvalidHttp2Request;
    const path = ps.path orelse return error.InvalidHttp2Request;
    const correlation_id = try http.correlation.generate(allocator);
    defer allocator.free(correlation_id);

    var status_code: u16 = 404;
    var body: []const u8 = "{\"error\":\"Not Found\"}";
    var body_alloc: ?[]u8 = null;
    defer if (body_alloc) |b| allocator.free(b);
    var content_type: []const u8 = JSON_CONTENT_TYPE;

    if (std.mem.eql(u8, method, "POST") and http.api_router.matchRoute(path, 1, "/chat")) {
        const auth_result = authorizeRequest(cfg, &ps.headers);
        if (!auth_result.ok) {
            status_code = 401;
            body = "{\"error\":\"Unauthorized\"}";
        } else {
            const message = parseChatMessage(allocator, ps.body.items, cfg.max_message_chars) catch null;
            if (message) |msg| {
                defer allocator.free(msg);
                const chat_request_body = try std.fmt.allocPrint(allocator, "{{\"message\":{s}}}", .{std.json.fmt(msg, .{})});
                defer allocator.free(chat_request_body);
                const exec = proxyJsonExecute(
                    allocator,
                    cfg,
                    .chat,
                    cfg.proxy_pass_chat,
                    null,
                    chat_request_body,
                    correlation_id,
                    "h2",
                    auth_result.token_hash,
                    null,
                    null,
                    null,
                    writer,
                    state,
                    false,
                ) catch null;
                if (exec) |res| switch (res) {
                    .buffered => |proxy_result| {
                        defer allocator.free(proxy_result.body);
                        status_code = proxy_result.status;
                        body_alloc = try allocator.dupe(u8, proxy_result.body);
                        body = body_alloc.?;
                        content_type = proxy_result.content_type;
                        if (proxy_result.content_disposition) |cd| allocator.free(cd);
                        allocator.free(proxy_result.content_type);
                    },
                    .streamed_status => |st| {
                        status_code = st;
                        body = "";
                    },
                } else {
                    status_code = 503;
                    body = "{\"error\":\"Upstream unavailable\"}";
                }
            } else {
                status_code = 400;
                body = "{\"error\":\"invalid chat payload\"}";
            }
        }
    } else if (std.mem.eql(u8, method, "POST") and http.api_router.matchRoute(path, 1, "/commands")) {
        const auth_result = authorizeRequest(cfg, &ps.headers);
        if (!auth_result.ok) {
            status_code = 401;
            body = "{\"error\":\"Unauthorized\"}";
        } else {
            var cmd = http.command.parseCommand(allocator, ps.body.items) catch null;
            if (cmd) |*command| {
                defer command.deinit(allocator);
                const upstream_path = command.command_type.upstreamPath();
                const envelope = http.command.buildUpstreamEnvelope(
                    allocator,
                    command.command_type,
                    command.params_raw,
                    correlation_id,
                    correlation_id,
                    auth_result.token_hash orelse "-",
                    "h2",
                    null,
                ) catch null;
                if (envelope) |env| {
                    defer allocator.free(env);
                    const exec = proxyJsonExecute(
                        allocator,
                        cfg,
                        .commands,
                        cfg.proxy_pass_commands_prefix,
                        upstream_path,
                        env,
                        correlation_id,
                        "h2",
                        auth_result.token_hash,
                        null,
                        null,
                        null,
                        writer,
                        state,
                        false,
                    ) catch null;
                    if (exec) |res| switch (res) {
                        .buffered => |proxy_result| {
                            defer allocator.free(proxy_result.body);
                            status_code = proxy_result.status;
                            body_alloc = try allocator.dupe(u8, proxy_result.body);
                            body = body_alloc.?;
                            content_type = proxy_result.content_type;
                            if (proxy_result.content_disposition) |cd| allocator.free(cd);
                            allocator.free(proxy_result.content_type);
                        },
                        .streamed_status => |st| {
                            status_code = st;
                            body = "";
                        },
                    } else {
                        status_code = 503;
                        body = "{\"error\":\"Upstream unavailable\"}";
                    }
                } else {
                    status_code = 500;
                    body = "{\"error\":\"failed to build command envelope\"}";
                }
            } else {
                status_code = 400;
                body = "{\"error\":\"invalid command envelope\"}";
            }
        }
    }

    if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/health")) {
        status_code = 200;
        body = "{\"status\":\"ok\",\"service\":\"tardigrade-edge\"}";
    } else if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/metrics")) {
        body_alloc = state.metricsToPrometheus(allocator) catch null;
        if (body_alloc) |b| {
            status_code = 200;
            body = b;
            content_type = "text/plain; version=0.0.4; charset=utf-8";
        } else {
            status_code = 500;
            body = "{\"error\":\"internal_error\"}";
        }
    } else if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/metrics/json")) {
        body_alloc = state.metricsToJson(allocator) catch null;
        if (body_alloc) |b| {
            status_code = 200;
            body = b;
        } else {
            status_code = 500;
            body = "{\"error\":\"internal_error\"}";
        }
    } else if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/metrics/prometheus")) {
        body_alloc = state.metricsToPrometheus(allocator) catch null;
        if (body_alloc) |b| {
            status_code = 200;
            body = b;
            content_type = "text/plain; version=0.0.4; charset=utf-8";
        } else {
            status_code = 500;
            body = "{\"error\":\"internal_error\"}";
        }
    }

    const status_str = try std.fmt.allocPrint(allocator, "{d}", .{status_code});
    defer allocator.free(status_str);
    const len_str = try std.fmt.allocPrint(allocator, "{d}", .{body.len});
    defer allocator.free(len_str);

    var response_headers = std.ArrayList(http.hpack.HeaderField).init(allocator);
    defer response_headers.deinit();
    try response_headers.append(.{ .name = ":status", .value = status_str });
    try response_headers.append(.{ .name = "content-type", .value = content_type });
    try response_headers.append(.{ .name = "content-length", .value = len_str });
    try response_headers.append(.{ .name = http.correlation.HEADER_NAME, .value = correlation_id });
    for (state.add_headers) |h| {
        try response_headers.append(.{ .name = h.name, .value = h.value });
    }

    const header_block = try http.hpack.encodeLiteralHeaderBlock(allocator, response_headers.items);
    defer allocator.free(header_block);

    try http.http2_frame.writeFrame(
        writer,
        .headers,
        http.http2_frame.Flags.END_HEADERS,
        stream_id,
        header_block,
    );
    if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/health")) {
        const promised_stream_id = next_server_stream_id.*;
        next_server_stream_id.* += 2;
        try pushHttp2Resource(writer, allocator, stream_id, promised_stream_id, "/metrics/json", "application/json", "{\"pushed\":true}");
    }
    try http.http2_frame.writeFrame(
        writer,
        .data,
        http.http2_frame.Flags.END_STREAM,
        stream_id,
        body,
    );

    state.metricsRecord(status_code);
}

fn pushHttp2Resource(
    writer: anytype,
    allocator: std.mem.Allocator,
    parent_stream_id: u31,
    promised_stream_id: u31,
    path: []const u8,
    content_type: []const u8,
    body: []const u8,
) !void {
    const req_headers = [_]http.hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    const req_block = try http.hpack.encodeLiteralHeaderBlock(allocator, req_headers[0..]);
    defer allocator.free(req_block);
    try http.http2_frame.writePushPromise(writer, parent_stream_id, promised_stream_id, req_block, true);

    const status_headers = [_]http.hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = content_type },
    };
    const status_block = try http.hpack.encodeLiteralHeaderBlock(allocator, status_headers[0..]);
    defer allocator.free(status_block);
    try http.http2_frame.writeFrame(writer, .headers, http.http2_frame.Flags.END_HEADERS, promised_stream_id, status_block);
    try http.http2_frame.writeFrame(writer, .data, http.http2_frame.Flags.END_STREAM, promised_stream_id, body);
}

fn readExactConn(conn: anytype, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = try conn.read(out[off..]);
        if (n == 0) return error.ConnectionClosed;
        off += n;
    }
}

fn handleConnection(conn: anytype, session: *ConnectionSession, cfg: *const edge_config.EdgeConfig, state: *GatewayState, keep_alive_out: *bool, enable_proxy_protocol: bool) !void {
    var keep_alive = false;
    keep_alive_out.* = false;
    defer keep_alive_out.* = keep_alive;

    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    if (session.pending_buf == null) {
        session.pending_buf = try state.request_buffer_pool.acquire();
    }
    const pending_buf = session.pending_buf.?;
    if (cfg.max_connection_memory_bytes > 0 and pending_buf.len > cfg.max_connection_memory_bytes) {
        try sendApiError(allocator, conn.writer(), .payload_too_large, "invalid_request", "Connection memory limit exceeded", null, false, state);
        return;
    }

    if (enable_proxy_protocol and !session.proxy_protocol_checked) {
        maybeConsumeProxyProtocolPreface(
            conn,
            cfg.proxy_protocol_mode,
            pending_buf,
            &session.pending_len,
            &session.proxy_client_ip_buf,
            &session.proxy_client_ip_len,
        ) catch |err| {
            state.logger.warn(null, "proxy protocol parse failed: {}", .{err});
            try sendApiError(allocator, conn.writer(), .bad_request, "invalid_request", "Invalid proxy protocol header", null, false, state);
            return;
        };
        session.proxy_protocol_checked = true;
    } else if (!session.proxy_protocol_checked) {
        session.proxy_protocol_checked = true;
    }

    const total_read = try readHttpRequest(conn, pending_buf, &session.pending_len);
    if (total_read == 0) return;
    if (cfg.max_connection_memory_bytes > 0 and total_read > cfg.max_connection_memory_bytes) {
        session.pending_len = 0;
        try sendApiError(allocator, conn.writer(), .payload_too_large, "invalid_request", "Connection memory limit exceeded", null, false, state);
        return;
    }

    const parse_result = http.Request.parse(allocator, pending_buf[0..total_read], MAX_REQUEST_SIZE) catch |err| {
        try sendApiError(allocator, conn.writer(), .bad_request, "invalid_request", "Malformed request", null, keep_alive, state);
        state.logger.warn(null, "parse error: {}", .{err});
        return;
    };
    const bytes_consumed = parse_result.bytes_consumed;
    if (bytes_consumed < total_read) {
        const remaining = total_read - bytes_consumed;
        std.mem.copyForwards(u8, pending_buf[0..remaining], pending_buf[bytes_consumed..total_read]);
        session.pending_len = remaining;
    } else {
        session.pending_len = 0;
    }

    var request = parse_result.request;
    defer request.deinit();
    const writer = conn.writer();
    keep_alive = request.keepAlive();
    if (http.shutdown.isShutdownRequested()) keep_alive = false;

    // --- Correlation ID ---
    const correlation_id = try http.correlation.fromHeadersOrGenerate(allocator, &request.headers);
    defer allocator.free(correlation_id);

    // --- Request Context ---
    const connection_ip = if (session.proxy_client_ip_len > 0)
        session.proxy_client_ip_buf[0..session.proxy_client_ip_len]
    else
        "unknown";
    const client_ip = http.request_context.extractClientIp(&request, connection_ip);
    var effective_cfg_storage = cfg.*;
    const effective_cfg = resolveRequestConfig(cfg, request.headers.get("host"), &effective_cfg_storage) orelse {
        try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive, state);
        var ctx_404 = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);
        logAccess(&ctx_404, request.method.toString(), request.uri.path, 404, request.headers.get("user-agent") orelse "");
        return;
    };
    var ctx = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);
    if (!hostMatchesServerNames(effective_cfg, &request)) {
        try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive, state);
        logAccess(&ctx, request.method.toString(), request.uri.path, 404, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Rewrite / return directives ---
    var request_uri_buf = std.ArrayList(u8).init(allocator);
    defer request_uri_buf.deinit();
    try request_uri_buf.appendSlice(request.uri.path);
    if (request.uri.query) |query| {
        try request_uri_buf.append('?');
        try request_uri_buf.appendSlice(query);
    }

    var conditional_outcome = try evaluateConditionalRules(
        allocator,
        effective_cfg.conditional_rules,
        request.uri.path,
        request_uri_buf.items,
        request.headers.get("host") orelse "",
        request.uri.query orelse "",
    );
    defer if (conditional_outcome) |*outcome| outcome.deinit(allocator);
    if (conditional_outcome) |outcome| {
        switch (outcome) {
            .pass => |rewritten_path| {
                request.uri.path = rewritten_path;
            },
            .redirect => |r| {
                var response = http.Response.redirect(allocator, r.location, @enumFromInt(r.status));
                defer response.deinit();
                _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
                applyResponseHeaders(state, &response);
                try response.write(writer);
                state.metricsRecord(r.status);
                logAccess(&ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
                return;
            },
            .returned => |r| {
                if (r.status >= 300 and r.status < 400 and r.body.len > 0) {
                    var response = http.Response.redirect(allocator, r.body, @enumFromInt(r.status));
                    defer response.deinit();
                    _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                    state.metricsRecord(r.status);
                    logAccess(&ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
                    return;
                }
                var response = http.Response.init(allocator);
                defer response.deinit();
                _ = response.setStatus(@enumFromInt(r.status))
                    .setBody(r.body)
                    .setContentType("text/plain; charset=utf-8")
                    .setConnection(keep_alive)
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                applyResponseHeaders(state, &response);
                try response.write(writer);
                state.metricsRecord(r.status);
                logAccess(&ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
                return;
            },
        }
    }

    var rewrite_outcome = try http.rewrite.evaluate(
        allocator,
        request.method.toString(),
        request.uri.path,
        request_uri_buf.items,
        cfg.rewrite_rules,
        cfg.return_rules,
    );
    defer rewrite_outcome.deinit(allocator);
    switch (rewrite_outcome) {
        .pass => |rewritten_path| {
            request.uri.path = rewritten_path;
        },
        .redirect => |r| {
            var response = http.Response.redirect(allocator, r.location, @enumFromInt(r.status));
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(r.status);
            logAccess(&ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
            return;
        },
        .returned => |r| {
            if (r.status >= 300 and r.status < 400 and r.body.len > 0) {
                var response = http.Response.redirect(allocator, r.body, @enumFromInt(r.status));
                defer response.deinit();
                _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
                applyResponseHeaders(state, &response);
                try response.write(writer);
                state.metricsRecord(r.status);
                logAccess(&ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
                return;
            }
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(@enumFromInt(r.status))
                .setBody(r.body)
                .setContentType("text/plain; charset=utf-8")
                .setConnection(keep_alive)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(r.status);
            logAccess(&ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
            return;
        },
    }

    // --- Internal redirects / named locations ---
    request.uri.path = applyInternalRedirectRules(
        request.method.toString(),
        request.uri.path,
        effective_cfg.internal_redirect_rules,
        effective_cfg.named_locations,
    );

    // --- Mirror requests (best-effort async) ---
    if (effective_cfg.mirror_rules.len > 0) {
        spawnMirrorRequests(
            allocator,
            effective_cfg.mirror_rules,
            request.method.toString(),
            request.uri.path,
            request.body orelse "",
            correlation_id,
            client_ip,
            request.headers.get("content-type"),
        );
    }

    if (try runMiddlewarePipeline(allocator, writer, effective_cfg, state, &ctx, &request, correlation_id, keep_alive)) {
        return;
    }

    const route_status = try routeRequest(conn, allocator, effective_cfg, state, &ctx, &request, correlation_id, &keep_alive, client_ip);
    logAccess(&ctx, request.method.toString(), request.uri.path, route_status, request.headers.get("user-agent") orelse "");
    return;
}

fn routeRequest(
    conn: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *http.Request,
    correlation_id: []const u8,
    keep_alive: *bool,
    client_ip: []const u8,
) !u16 {
    const writer = conn.writer();
    if (http.location_router.matchLocation(request.uri.path, cfg.location_blocks)) |matched| {
        switch (matched.block.action) {
            .builtin_route => |route| {
                if (try dispatchBuiltinRouteHttp1(allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive.*, client_ip, route)) |status| return status;
            },
            .proxy_pass => |target| {
                return try handleLocationProxyPass(allocator, writer, cfg, state, request, target, correlation_id, keep_alive.*, client_ip, ctx.identity);
            },
            .fastcgi_pass => |upstream| {
                return try handleFastcgiRoute(allocator, writer, cfg, upstream, request, client_ip, correlation_id, keep_alive.*, state);
            },
            .return_response => |ret| {
                if (ret.status >= 300 and ret.status < 400 and ret.body.len > 0) {
                    var response = http.Response.redirect(allocator, ret.body, @enumFromInt(ret.status));
                    defer response.deinit();
                    _ = response.setConnection(keep_alive.*).setHeader(http.correlation.HEADER_NAME, correlation_id);
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                } else {
                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response.setStatus(@enumFromInt(ret.status))
                        .setBody(ret.body)
                        .setContentType("text/plain; charset=utf-8")
                        .setConnection(keep_alive.*)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
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
                if (try handleStaticLocation(allocator, writer, request, matched, root_cfg, correlation_id, keep_alive.*, state)) |status| return status;
            },
        }
    }

    const builtin_blocks = buildBuiltinLocationBlocks(cfg);
    if (http.location_router.matchLocation(request.uri.path, builtin_blocks[0..])) |matched| {
        switch (matched.block.action) {
            .builtin_route => |route| {
                return (try dispatchBuiltinRouteHttp1(allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive.*, client_ip, route)) orelse {
                    try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive.*, state);
                    state.metricsRecord(404);
                    return 404;
                };
            },
            .proxy_pass => |target| {
                return try handleLocationProxyPass(allocator, writer, cfg, state, request, target, correlation_id, keep_alive.*, client_ip, ctx.identity);
            },
            .fastcgi_pass => |upstream| {
                return try handleFastcgiRoute(allocator, writer, cfg, upstream, request, client_ip, correlation_id, keep_alive.*, state);
            },
            .return_response => |ret| {
                if (ret.status >= 300 and ret.status < 400 and ret.body.len > 0) {
                    var response = http.Response.redirect(allocator, ret.body, @enumFromInt(ret.status));
                    defer response.deinit();
                    _ = response.setConnection(keep_alive.*).setHeader(http.correlation.HEADER_NAME, correlation_id);
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                } else {
                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response.setStatus(@enumFromInt(ret.status))
                        .setBody(ret.body)
                        .setContentType("text/plain; charset=utf-8")
                        .setConnection(keep_alive.*)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
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
                if (try handleStaticLocation(allocator, writer, request, matched, root_cfg, correlation_id, keep_alive.*, state)) |status| return status;
            },
        }
    } else {
        if (request.method == .GET and std.mem.startsWith(u8, request.uri.path, "/admin/")) {
            const auth_result = authorizeRequest(cfg, &request.headers);
            if (!auth_result.ok) {
                try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive.*, state);
                state.metricsRecord(401);
                return 401;
            }
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Unknown admin route", correlation_id, keep_alive.*, state);
            state.metricsRecord(404);
            return 404;
        }

        if (http.api_router.parseVersionedPath(request.uri.path)) |versioned| {
            if (!http.api_router.isSupportedVersion(versioned.version)) {
                try sendApiError(allocator, writer, .bad_request, "invalid_request", "Unsupported API version", correlation_id, keep_alive.*, state);
                state.metricsRecord(400);
                return 400;
            }
            if (cfg.auth_request_url.len > 0 and isProtectedAuthRequestRoute(request.uri.path)) {
                if (!authorizeViaSubrequest(allocator, cfg, request, correlation_id, client_ip)) {
                    try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive.*, state);
                    state.metricsRecord(401);
                    return 401;
                }
            }
        }

        if (try handleBackendProtocolTail(conn, allocator, cfg, state, ctx, request, correlation_id, client_ip, keep_alive.*)) |status| {
            return status;
        }
        if (try handleWebSocketUpgrade(conn, allocator, cfg, state, ctx, request, correlation_id, client_ip, keep_alive)) |status| {
            return status;
        }
        if (try handleSseStream(writer, allocator, cfg, state, ctx, request, correlation_id, keep_alive)) |status| {
            return status;
        }
        if (try handleSsePublish(writer, allocator, cfg, state, ctx, request, correlation_id, keep_alive.*)) |status| {
            return status;
        }
        if (try handleBuiltinApiTailHttp1(allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive.*, client_ip)) |status| {
            return status;
        }
        if (try handlePrimaryApiTailHttp1(allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive.*, client_ip)) |status| {
            return status;
        }
    }

    if (serveTryFilesFallback(allocator, cfg, request.method.toString(), request.uri.path, correlation_id, keep_alive.*, writer, state)) |status| {
        state.metricsRecord(status);
        return status;
    } else |_| {}

    try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive.*, state);
    state.metricsRecord(404);
    return 404;
}

fn matchEffectiveLocation(cfg: *const edge_config.EdgeConfig, path: []const u8) ?http.location_router.MatchResult {
    var builtin_blocks = buildBuiltinLocationBlocks(cfg);
    return http.location_router.matchLocation(path, cfg.location_blocks) orelse
        http.location_router.matchLocation(path, builtin_blocks[0..]);
}

fn buildBuiltinLocationBlocks(cfg: *const edge_config.EdgeConfig) [20]http.location_router.LocationBlock {
    return .{
        .{ .match_type = .exact, .pattern = "/health", .priority = 0, .action = .{ .builtin_route = .health } },
        .{ .match_type = .exact, .pattern = "/metrics", .priority = 1, .action = .{ .builtin_route = .metrics } },
        .{ .match_type = .exact, .pattern = "/metrics/json", .priority = 2, .action = .{ .builtin_route = .metrics_json } },
        .{ .match_type = .exact, .pattern = "/metrics/prometheus", .priority = 3, .action = .{ .builtin_route = .metrics_prometheus } },
        .{ .match_type = .exact, .pattern = "/admin/routes", .priority = 4, .action = .{ .builtin_route = .admin_routes } },
        .{ .match_type = .exact, .pattern = "/admin/connections", .priority = 5, .action = .{ .builtin_route = .admin_connections } },
        .{ .match_type = .exact, .pattern = "/admin/streams", .priority = 6, .action = .{ .builtin_route = .admin_streams } },
        .{ .match_type = .exact, .pattern = "/admin/upstreams", .priority = 7, .action = .{ .builtin_route = .admin_upstreams } },
        .{ .match_type = .exact, .pattern = "/admin/certs", .priority = 8, .action = .{ .builtin_route = .admin_certs } },
        .{ .match_type = .exact, .pattern = "/admin/auth-registry", .priority = 9, .action = .{ .builtin_route = .admin_auth_registry } },
        .{ .match_type = .exact, .pattern = cfg.proxy_pass_chat, .priority = 10, .action = .{ .builtin_route = .v1_chat } },
        .{ .match_type = .exact, .pattern = "/v1/commands", .priority = 11, .action = .{ .builtin_route = .v1_commands } },
        .{ .match_type = .exact, .pattern = "/v1/commands/status", .priority = 12, .action = .{ .builtin_route = .v1_commands_status } },
        .{ .match_type = .exact, .pattern = "/v1/approvals/request", .priority = 13, .action = .{ .builtin_route = .v1_approvals_request } },
        .{ .match_type = .exact, .pattern = "/v1/approvals/respond", .priority = 14, .action = .{ .builtin_route = .v1_approvals_respond } },
        .{ .match_type = .exact, .pattern = "/v1/approvals/status", .priority = 15, .action = .{ .builtin_route = .v1_approvals_status } },
        .{ .match_type = .exact, .pattern = "/v1/devices/register", .priority = 16, .action = .{ .builtin_route = .v1_devices_register } },
        .{ .match_type = .exact, .pattern = "/v1/sessions/refresh", .priority = 17, .action = .{ .builtin_route = .v1_sessions_refresh } },
        .{ .match_type = .exact, .pattern = "/v1/sessions", .priority = 18, .action = .{ .builtin_route = .v1_sessions } },
        .{ .match_type = .exact, .pattern = "/v1/cache/purge", .priority = 19, .action = .{ .builtin_route = .v1_cache_purge } },
    };
}

const BuiltinJsonReply = struct {
    status: http.Status,
    body: ?[]const u8,
    session_header: ?[]const u8 = null,
    identity: ?[]const u8 = null,

    fn deinit(self: *BuiltinJsonReply, allocator: std.mem.Allocator) void {
        if (self.body) |body| allocator.free(body);
        if (self.session_header) |header| allocator.free(header);
        self.* = undefined;
    }

    fn takeBody(self: *BuiltinJsonReply) []const u8 {
        const body = self.body.?;
        self.body = null;
        return body;
    }
};

const ResolvedIdentity = struct {
    value: []const u8,
    owned: bool = false,

    fn deinit(self: *ResolvedIdentity, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.value);
        self.* = undefined;
    }
};

const ChatRequestPrep = struct {
    identity: ResolvedIdentity,
    message: []const u8,
    upstream_body: []u8,

    fn deinit(self: *ChatRequestPrep, allocator: std.mem.Allocator) void {
        self.identity.deinit(allocator);
        allocator.free(self.message);
        allocator.free(self.upstream_body);
        self.* = undefined;
    }
};

const CommandRequestPrep = struct {
    identity: ResolvedIdentity,
    command: http.command.Command,
    command_id: []const u8,
    upstream_body: []u8,
    upstream_path: []const u8,
    effective_idempotency_key: ?[]const u8,

    fn deinit(self: *CommandRequestPrep, allocator: std.mem.Allocator) void {
        self.identity.deinit(allocator);
        self.command.deinit(allocator);
        allocator.free(self.command_id);
        allocator.free(self.upstream_body);
        self.* = undefined;
    }
};

const RequestPrepError = struct {
    status: http.Status,
    code: []const u8,
    message: []const u8,
};

const NormalizedProxyReply = struct {
    status: u16,
    body: []u8,
    content_type: []const u8,
    content_disposition: ?[]const u8 = null,
    cacheable: bool = false,

    fn deinit(self: *NormalizedProxyReply, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        if (self.content_disposition) |cd| allocator.free(cd);
        self.* = undefined;
    }
};

const ProxyRequestSpec = struct {
    scope: UpstreamScope,
    proxy_target: []const u8,
    upstream_path: ?[]const u8,
    upstream_body: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    identity: ?[]const u8,
    api_version: ?u32,
    host: ?[]const u8,
    x_forwarded_for: ?[]const u8,
    allow_streaming: bool,
};

const ProxyRequestResult = union(enum) {
    streamed_status: u16,
    buffered: NormalizedProxyReply,

    fn deinit(self: *ProxyRequestResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .streamed_status => {},
            .buffered => |*reply| reply.deinit(allocator),
        }
        self.* = undefined;
    }
};

fn handleProxyRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    writer: anytype,
    spec: ProxyRequestSpec,
) (error{CircuitOpen} || anyerror)!ProxyRequestResult {
    if (!state.circuitTryAcquire()) return error.CircuitOpen;

    const exec = try proxyJsonExecute(
        allocator,
        cfg,
        spec.scope,
        spec.proxy_target,
        spec.upstream_path,
        spec.upstream_body,
        spec.correlation_id,
        spec.client_ip,
        spec.identity,
        spec.api_version,
        spec.host,
        spec.x_forwarded_for,
        writer,
        state,
        spec.allow_streaming,
    );

    return switch (exec) {
        .streamed_status => |status| blk: {
            if (status >= 500) state.circuitRecordFailure() else state.circuitRecordSuccess();
            break :blk .{ .streamed_status = status };
        },
        .buffered => |proxy_result| blk: {
            if (proxy_result.status >= 500) state.circuitRecordFailure() else state.circuitRecordSuccess();
            break :blk .{ .buffered = try normalizeBufferedProxyResult(allocator, spec.correlation_id, proxy_result) };
        },
    };
}

fn handleDeviceRegisterBuiltin(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    headers: *const http.Headers,
    body: []const u8,
    correlation_id: []const u8,
) !BuiltinJsonReply {
    _ = state;
    if (cfg.device_registry_path.len == 0) {
        return .{
            .status = .not_implemented,
            .body = try buildApiErrorJson(allocator, "tool_unavailable", "Device registry not configured", correlation_id),
        };
    }
    const auth_result = authorizeRequest(cfg, headers);
    if (!auth_result.ok) {
        return .{
            .status = .unauthorized,
            .body = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id),
        };
    }
    const reg = parseDeviceRegistration(allocator, body) catch {
        return .{
            .status = .bad_request,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Invalid device registration payload", correlation_id),
        };
    };
    defer {
        allocator.free(reg.device_id);
        allocator.free(reg.public_key);
    }
    registerDeviceIdentity(cfg.device_registry_path, reg.device_id, reg.public_key) catch {
        return .{
            .status = .internal_server_error,
            .body = try buildApiErrorJson(allocator, "internal_error", "Failed to persist device identity", correlation_id),
        };
    };
    return .{
        .status = .created,
        .body = try allocator.dupe(u8, "{\"registered\":true}"),
        .identity = auth_result.token_hash,
    };
}

fn handleSessionsBuiltin(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    method: []const u8,
    headers: *const http.Headers,
    body: []const u8,
    client_label: []const u8,
    correlation_id: []const u8,
) !BuiltinJsonReply {
    if (state.session_store == null) {
        return .{
            .status = .not_found,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Sessions not enabled", correlation_id),
        };
    }

    if (std.mem.eql(u8, method, "POST")) {
        const auth_result = authorizeRequest(cfg, headers);
        if (!auth_result.ok) {
            return .{
                .status = .unauthorized,
                .body = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id),
            };
        }

        var device_id: ?[]const u8 = null;
        if (body.len > 0 and isJsonContentType(headers.get("content-type"))) {
            device_id = parseDeviceId(allocator, body) catch null;
        }
        defer if (device_id) |value| allocator.free(value);

        const session_token = state.createSession(allocator, auth_result.token_hash orelse "-", client_label, device_id) catch |err| {
            const msg = switch (err) {
                error.TooManySessions => "Too many active sessions",
                else => "Session creation failed",
            };
            return .{
                .status = .too_many_requests,
                .body = try buildApiErrorJson(allocator, "rate_limited", msg, correlation_id),
                .identity = auth_result.token_hash,
            };
        };
        errdefer allocator.free(session_token);

        return .{
            .status = .created,
            .body = try std.fmt.allocPrint(allocator, "{{\"session_token\":\"{s}\"}}", .{session_token}),
            .session_header = session_token,
            .identity = auth_result.token_hash,
        };
    }

    if (std.mem.eql(u8, method, "DELETE")) {
        const session_token = http.session.fromHeaders(headers) orelse {
            return .{
                .status = .bad_request,
                .body = try buildApiErrorJson(allocator, "invalid_request", "Missing or invalid X-Session-Token", correlation_id),
            };
        };
        const revoked = state.revokeSession(session_token);
        return .{
            .status = .ok,
            .body = try allocator.dupe(u8, if (revoked) "{\"revoked\":true}" else "{\"revoked\":false}"),
        };
    }

    if (std.mem.eql(u8, method, "GET")) {
        const auth_result = authorizeRequest(cfg, headers);
        if (!auth_result.ok) {
            return .{
                .status = .unauthorized,
                .body = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id),
            };
        }
        const active_sessions = state.countSessionsByIdentity(allocator, auth_result.token_hash orelse "-") catch {
            return .{
                .status = .internal_server_error,
                .body = try buildApiErrorJson(allocator, "internal_error", "Failed to list sessions", correlation_id),
                .identity = auth_result.token_hash,
            };
        };
        return .{
            .status = .ok,
            .body = try std.fmt.allocPrint(allocator, "{{\"active_sessions\":{d}}}", .{active_sessions}),
            .identity = auth_result.token_hash,
        };
    }

    return .{
        .status = .not_found,
        .body = try buildApiErrorJson(allocator, "invalid_request", "Not Found", correlation_id),
    };
}

fn handleSessionRefreshBuiltin(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    headers: *const http.Headers,
    client_label: []const u8,
    correlation_id: []const u8,
) !BuiltinJsonReply {
    if (state.session_store == null) {
        return .{
            .status = .not_found,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Sessions not enabled", correlation_id),
        };
    }
    const session_token = http.session.fromHeaders(headers) orelse {
        return .{
            .status = .bad_request,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Missing or invalid X-Session-Token", correlation_id),
        };
    };
    const refreshed = state.refreshSession(allocator, session_token, client_label) catch {
        return .{
            .status = .unauthorized,
            .body = try buildApiErrorJson(allocator, "unauthorized", "Invalid session token", correlation_id),
        };
    };
    errdefer allocator.free(refreshed);
    return .{
        .status = .ok,
        .body = try std.fmt.allocPrint(allocator, "{{\"session_token\":\"{s}\",\"access_ttl_seconds\":{d},\"refresh_ttl_seconds\":{d}}}", .{
            refreshed,
            cfg.access_token_ttl_seconds,
            cfg.refresh_token_ttl_seconds,
        }),
        .session_header = refreshed,
    };
}

fn handleCachePurgeBuiltin(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    headers: *const http.Headers,
    body: []const u8,
    correlation_id: []const u8,
) !BuiltinJsonReply {
    if (state.proxy_cache_store == null) {
        return .{
            .status = .not_found,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Proxy cache not enabled", correlation_id),
        };
    }
    const auth_result = authorizeRequest(cfg, headers);
    if (!auth_result.ok) {
        return .{
            .status = .unauthorized,
            .body = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id),
        };
    }

    var purged: usize = 0;
    if (body.len > 0) {
        if (isJsonContentType(headers.get("content-type"))) {
            if (parseCachePurgeKey(allocator, body)) |key| {
                defer allocator.free(key);
                purged = if (state.proxyCacheDelete(key)) 1 else 0;
            } else |_| {
                purged = state.proxyCachePurgeAll();
            }
        } else {
            purged = state.proxyCachePurgeAll();
        }
    } else {
        purged = state.proxyCachePurgeAll();
    }

    return .{
        .status = .ok,
        .body = try std.fmt.allocPrint(allocator, "{{\"purged\":{d}}}", .{purged}),
        .identity = auth_result.token_hash,
    };
}

fn resolveApprovalIdentity(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    headers: *const http.Headers,
) !?[]const u8 {
    const auth_result = authorizeRequest(cfg, headers);
    if (auth_result.ok) return auth_result.token_hash orelse "-";
    if (http.session.fromHeaders(headers)) |session_token| {
        if (state.validateSessionIdentity(allocator, session_token)) |identity| {
            defer allocator.free(identity);
            return try allocator.dupe(u8, identity);
        }
    }
    return null;
}

fn resolveRequestIdentity(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    headers: *const http.Headers,
) ?ResolvedIdentity {
    const auth_result = authorizeRequest(cfg, headers);
    if (auth_result.ok) {
        return .{ .value = auth_result.token_hash orelse "-" };
    }
    if (http.session.fromHeaders(headers)) |session_token| {
        if (state.validateSessionIdentity(allocator, session_token)) |identity| {
            return .{ .value = identity, .owned = true };
        }
    }
    return null;
}

fn describeChatPrepError(err: anyerror) RequestPrepError {
    return .{
        .status = if (err == error.Unauthorized) .unauthorized else .bad_request,
        .code = if (err == error.Unauthorized) "unauthorized" else "invalid_request",
        .message = switch (err) {
            error.Unauthorized => "Unauthorized",
            error.InvalidContentType => "Content-Type must be application/json",
            error.MissingBody => "Missing request body",
            error.EmptyMessage => "message must not be empty",
            error.MessageTooLarge => "message too long",
            else => "invalid chat payload",
        },
    };
}

fn describeCommandPrepError(err: anyerror) RequestPrepError {
    return .{
        .status = switch (err) {
            error.Unauthorized => .unauthorized,
            error.BuildUpstreamFailed => .internal_server_error,
            else => .bad_request,
        },
        .code = switch (err) {
            error.Unauthorized => "unauthorized",
            error.BuildUpstreamFailed => "internal_error",
            else => "invalid_request",
        },
        .message = switch (err) {
            error.Unauthorized => "Unauthorized",
            error.InvalidContentType => "Content-Type must be application/json",
            error.MissingBody => "Missing request body",
            error.MissingCommand => "Missing 'command' field",
            error.UnknownCommand => "Unknown command type",
            error.InvalidParams => "Invalid or missing 'params' object",
            error.BuildUpstreamFailed => "Failed to build upstream request",
            else => "Invalid command envelope",
        },
    };
}

fn prepareChatRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    headers: *const http.Headers,
    body: ?[]const u8,
) !ChatRequestPrep {
    var identity = resolveRequestIdentity(allocator, cfg, state, headers) orelse {
        return error.Unauthorized;
    };
    errdefer identity.deinit(allocator);

    if (!isJsonContentType(headers.get("content-type"))) {
        return error.InvalidContentType;
    }

    const raw_body = body orelse return error.MissingBody;
    const message = parseChatMessage(allocator, raw_body, cfg.max_message_chars) catch |err| switch (err) {
        error.EmptyMessage => return error.EmptyMessage,
        error.MessageTooLarge => return error.MessageTooLarge,
        else => return error.InvalidPayload,
    };
    errdefer allocator.free(message);

    const upstream_body = try std.fmt.allocPrint(allocator, "{{\"message\":{s}}}", .{std.json.fmt(message, .{})});
    return .{
        .identity = identity,
        .message = message,
        .upstream_body = upstream_body,
    };
}

fn prepareCommandRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    headers: *const http.Headers,
    body: ?[]const u8,
    correlation_id: []const u8,
    client_label: []const u8,
    api_version: ?u16,
    request_idempotency_key: ?[]const u8,
) !CommandRequestPrep {
    var identity = resolveRequestIdentity(allocator, cfg, state, headers) orelse {
        return error.Unauthorized;
    };
    errdefer identity.deinit(allocator);

    if (!isJsonContentType(headers.get("content-type"))) {
        return error.InvalidContentType;
    }

    const raw_body = body orelse return error.MissingBody;
    var command = http.command.parseCommand(allocator, raw_body) catch |err| switch (err) {
        http.command.ParseError.MissingCommand => return error.MissingCommand,
        http.command.ParseError.UnknownCommand => return error.UnknownCommand,
        http.command.ParseError.InvalidParams => return error.InvalidParams,
        else => return error.InvalidPayload,
    };
    errdefer command.deinit(allocator);

    const command_id = if (command.command_id) |cid|
        try allocator.dupe(u8, cid)
    else
        try generateCommandId(allocator);
    errdefer allocator.free(command_id);

    const upstream_body = http.command.buildUpstreamEnvelope(
        allocator,
        command.command_type,
        command.params_raw,
        command_id,
        correlation_id,
        identity.value,
        client_label,
        api_version,
    ) catch return error.BuildUpstreamFailed;

    return .{
        .identity = identity,
        .command = command,
        .command_id = command_id,
        .upstream_body = upstream_body,
        .upstream_path = command.command_type.upstreamPath(),
        .effective_idempotency_key = command.idempotency_key orelse request_idempotency_key,
    };
}

fn normalizeBufferedProxyResult(
    allocator: std.mem.Allocator,
    correlation_id: []const u8,
    proxy_result: ProxyResult,
) !NormalizedProxyReply {
    if (proxy_result.status == 200) {
        return .{
            .status = proxy_result.status,
            .body = proxy_result.body,
            .content_type = proxy_result.content_type,
            .content_disposition = proxy_result.content_disposition,
            .cacheable = proxy_result.cacheable,
        };
    }

    allocator.free(proxy_result.content_type);
    if (proxy_result.content_disposition) |cd| allocator.free(cd);
    allocator.free(proxy_result.body);

    const mapped = mapUpstreamError(proxy_result.status);
    return .{
        .status = mapped.status,
        .body = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id),
        .content_type = JSON_CONTENT_TYPE,
    };
}

fn handleCommandStatusBuiltin(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    headers: *const http.Headers,
    query: ?[]const u8,
    correlation_id: []const u8,
) !BuiltinJsonReply {
    var authenticated = false;
    const auth_result = authorizeRequest(cfg, headers);
    if (auth_result.ok) authenticated = true;
    if (!authenticated) {
        if (http.session.fromHeaders(headers)) |session_token| {
            if (state.validateSessionIdentity(allocator, session_token) != null) authenticated = true;
        }
    }
    if (!authenticated) {
        return .{
            .status = .unauthorized,
            .body = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id),
        };
    }
    const command_id = parseQueryParam(query orelse "", "command_id") orelse {
        return .{
            .status = .bad_request,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Missing command_id", correlation_id),
        };
    };
    const snapshot = state.commandLifecycleSnapshotJson(allocator, command_id) orelse {
        return .{
            .status = .not_found,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Unknown command_id", correlation_id),
        };
    };
    return .{
        .status = .ok,
        .body = @constCast(snapshot),
    };
}

fn handleApprovalsRequestBuiltin(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    headers: *const http.Headers,
    body: []const u8,
    correlation_id: []const u8,
) !BuiltinJsonReply {
    const identity = (try resolveApprovalIdentity(allocator, cfg, state, headers)) orelse {
        return .{
            .status = .unauthorized,
            .body = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id),
        };
    };
    defer if (!authorizeRequest(cfg, headers).ok) allocator.free(identity);
    if (!isJsonContentType(headers.get("content-type"))) {
        return .{
            .status = .bad_request,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Content-Type must be application/json", correlation_id),
        };
    }
    if (body.len == 0) {
        return .{
            .status = .bad_request,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Missing request body", correlation_id),
            .identity = identity,
        };
    }
    var approval_req = parseApprovalRequestBody(allocator, body) catch {
        return .{
            .status = .bad_request,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Invalid approval request payload", correlation_id),
            .identity = identity,
        };
    };
    defer approval_req.deinit(allocator);
    if (!routeNeedsApproval(approval_req.method, approval_req.path, cfg.policy_approval_routes_raw) and
        !routeRequiresApprovalRule(approval_req.method, approval_req.path, cfg.policy_rules_raw))
    {
        return .{
            .status = .bad_request,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Route does not require approval", correlation_id),
            .identity = identity,
        };
    }
    const created = state.approvalCreate(allocator, approval_req.method, approval_req.path, identity, approval_req.command_id) catch |err| switch (err) {
        error.TooManyPendingApprovals => return .{
            .status = .too_many_requests,
            .body = try buildApiErrorJson(allocator, "too_many_requests", "Too many pending approvals for this identity", correlation_id),
            .identity = identity,
        },
        else => return .{
            .status = .internal_server_error,
            .body = try buildApiErrorJson(allocator, "internal_error", "Failed to create approval request", correlation_id),
            .identity = identity,
        },
    };
    defer allocator.free(created.token);
    _ = state.event_hub.publish("approvals.requests", body, http.event_loop.monotonicMs()) catch 0;
    return .{
        .status = .accepted,
        .body = try std.fmt.allocPrint(allocator, "{{\"approval_token\":\"{s}\",\"status\":\"pending\",\"expires_ms\":{d},\"status_url\":\"/v1/approvals/status?approval_token={s}\"}}", .{
            created.token,
            created.expires_ms,
            created.token,
        }),
        .identity = identity,
    };
}

fn handleApprovalsRespondBuiltin(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    headers: *const http.Headers,
    body: []const u8,
    correlation_id: []const u8,
) !BuiltinJsonReply {
    const auth_result = authorizeRequest(cfg, headers);
    if (!auth_result.ok) {
        return .{
            .status = .unauthorized,
            .body = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id),
        };
    }
    if (!isJsonContentType(headers.get("content-type"))) {
        return .{
            .status = .bad_request,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Content-Type must be application/json", correlation_id),
            .identity = auth_result.token_hash,
        };
    }
    if (body.len == 0) {
        return .{
            .status = .bad_request,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Missing request body", correlation_id),
            .identity = auth_result.token_hash,
        };
    }
    var approval_resp = parseApprovalResponseBody(allocator, body) catch {
        return .{
            .status = .bad_request,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Invalid approval response payload", correlation_id),
            .identity = auth_result.token_hash,
        };
    };
    defer approval_resp.deinit(allocator);
    if (!state.approvalRespond(approval_resp.token, approval_resp.decision, auth_result.token_hash orelse "-")) {
        return .{
            .status = .conflict,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Approval token not pending or not found", correlation_id),
            .identity = auth_result.token_hash,
        };
    }
    _ = state.event_hub.publish("approvals.responses", body, http.event_loop.monotonicMs()) catch 0;
    return .{
        .status = .ok,
        .body = try std.fmt.allocPrint(allocator, "{{\"approval_token\":\"{s}\",\"status\":\"{s}\"}}", .{
            approval_resp.token,
            if (approval_resp.decision == .approve) "approved" else "denied",
        }),
        .identity = auth_result.token_hash,
    };
}

fn handleApprovalsStatusBuiltin(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    headers: *const http.Headers,
    query: ?[]const u8,
    correlation_id: []const u8,
) !BuiltinJsonReply {
    const identity = (try resolveApprovalIdentity(allocator, cfg, state, headers)) orelse {
        return .{
            .status = .unauthorized,
            .body = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id),
        };
    };
    defer if (!authorizeRequest(cfg, headers).ok) allocator.free(identity);
    const approval_token = parseQueryParam(query orelse "", "approval_token") orelse {
        return .{
            .status = .bad_request,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Missing approval_token", correlation_id),
            .identity = identity,
        };
    };
    const snapshot = state.approvalSnapshotJson(allocator, approval_token) orelse {
        return .{
            .status = .not_found,
            .body = try buildApiErrorJson(allocator, "invalid_request", "Unknown approval_token", correlation_id),
            .identity = identity,
        };
    };
    return .{
        .status = .ok,
        .body = @constCast(snapshot),
        .identity = identity,
    };
}

fn dispatchBuiltinRouteHttp1(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
    client_ip: []const u8,
    route: http.location_router.BuiltinRoute,
) !?u16 {
    switch (route) {
        .health => {
            if (request.method != .GET) return null;
            var response = http.Response.init(allocator);
            defer response.deinit();
            try populateHealthResponse(allocator, &response, keep_alive, correlation_id, state, cfg, false);
            try response.write(writer);
            state.metricsRecord(200);
            return 200;
        },
        .metrics, .metrics_prometheus => {
            if (request.method != .GET) return null;
            const prom_text = state.metricsToPrometheus(allocator) catch {
                try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to generate metrics", correlation_id, keep_alive, state);
                return 500;
            };
            defer allocator.free(prom_text);
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setBody(prom_text)
                .setContentType("text/plain; version=0.0.4; charset=utf-8")
                .setConnection(keep_alive)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            return 200;
        },
        .metrics_json => {
            if (request.method != .GET) return null;
            const metrics_json = state.metricsToJson(allocator) catch {
                try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to generate metrics", correlation_id, keep_alive, state);
                return 500;
            };
            defer allocator.free(metrics_json);
            var response = http.Response.json(allocator, metrics_json);
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            return 200;
        },
        .admin_routes,
        .admin_connections,
        .admin_streams,
        .admin_upstreams,
        .admin_certs,
        .admin_auth_registry,
        => {
            if (request.method != .GET) return null;
            const auth_result = authorizeRequest(cfg, &request.headers);
            if (!auth_result.ok) {
                try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
                return 401;
            }
            var response = http.Response.init(allocator);
            defer response.deinit();
            switch (route) {
                .admin_routes => {
                    _ = response.setStatus(.ok)
                        .setBody(ADMIN_ROUTES_JSON)
                        .setContentType("application/json");
                },
                .admin_connections => {
                    const counts = state.connectionCounts();
                    const body = try std.fmt.allocPrint(allocator, "{{\"active\":{d},\"tracked_ip_buckets\":{d}}}", .{ counts.active, counts.per_ip });
                    _ = response.setStatus(.ok)
                        .setBodyOwned(body)
                        .setContentType("application/json");
                },
                .admin_streams => {
                    const counts = state.streamCounts();
                    const body = try std.fmt.allocPrint(allocator, "{{\"websocket_active\":{d},\"sse_active\":{d}}}", .{ counts.ws, counts.sse });
                    _ = response.setStatus(.ok)
                        .setBodyOwned(body)
                        .setContentType("application/json");
                },
                .admin_upstreams => {
                    const body = state.upstreamHealthJson(allocator) catch try allocator.dupe(u8, "{\"upstreams\":[]}");
                    _ = response.setStatus(.ok)
                        .setBodyOwned(body)
                        .setContentType("application/json");
                },
                .admin_certs => {
                    const body = try std.fmt.allocPrint(allocator, "{{\"default_cert\":\"{s}\",\"default_key\":\"{s}\",\"sni_count\":{d}}}", .{ cfg.tls_cert_path, cfg.tls_key_path, cfg.tls_sni_certs.len });
                    _ = response.setStatus(.ok)
                        .setBodyOwned(body)
                        .setContentType("application/json");
                },
                .admin_auth_registry => {
                    const body = try std.fmt.allocPrint(allocator, "{{\"bearer_hashes\":{d},\"basic_auth_hashes\":{d},\"sessions_enabled\":{}}}", .{
                        cfg.auth_token_hashes.len,
                        cfg.basic_auth_hashes.len,
                        state.session_store != null,
                    });
                    _ = response.setStatus(.ok)
                        .setBodyOwned(body)
                        .setContentType("application/json");
                },
                else => unreachable,
            }
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            return 200;
        },
        .v1_chat => {
            if (request.method != .POST) return null;

            if (ctx.idempotency_key) |idem_key| {
                if (try state.idempotencyGetCopy(allocator, idem_key)) |cached| {
                    defer allocator.free(cached.body);
                    defer allocator.free(cached.content_type);

                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response.setStatus(@enumFromInt(cached.status))
                        .setBody(cached.body)
                        .setContentType(cached.content_type)
                        .setConnection(keep_alive)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id)
                        .setHeader("X-Idempotent-Replayed", "true");
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                    state.metricsRecord(cached.status);
                    return cached.status;
                }
            }

            var prep = prepareChatRequest(allocator, cfg, state, &request.headers, request.body) catch |err| {
                const desc = describeChatPrepError(err);
                try sendApiError(allocator, writer, desc.status, desc.code, desc.message, correlation_id, keep_alive, state);
                return @intFromEnum(desc.status);
            };
            defer prep.deinit(allocator);
            ctx.setIdentity(prep.identity.value);

            const proxy_cache_bypass = shouldBypassProxyCache(&request.headers) or ctx.idempotency_key != null;
            const proxy_cache_key = if (cfg.proxy_cache_ttl_seconds > 0 and !proxy_cache_bypass)
                try buildProxyCacheKey(allocator, cfg.proxy_cache_key_template, request.method.toString(), "/v1/chat", prep.message, ctx.identity, if (ctx.api_version) |version| @as(u32, version) else null)
            else
                null;
            defer if (proxy_cache_key) |k| allocator.free(k);
            var proxy_cache_locked = false;
            defer if (proxy_cache_locked) {
                if (proxy_cache_key) |cache_key| state.proxyCacheUnlock(cache_key);
            };
            if (proxy_cache_key) |cache_key| {
                if (try state.proxyCacheGetCopyWithStale(allocator, cache_key, cfg.proxy_cache_stale_while_revalidate_seconds)) |lookup| {
                    defer allocator.free(lookup.cached.body);
                    defer allocator.free(lookup.cached.content_type);

                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response.setStatus(@enumFromInt(lookup.cached.status))
                        .setBody(lookup.cached.body)
                        .setContentType(lookup.cached.content_type)
                        .setConnection(keep_alive)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id)
                        .setHeader("X-Proxy-Cache", if (lookup.is_stale) "STALE" else "HIT");
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                    state.metricsRecord(lookup.cached.status);
                    if (lookup.is_stale) {
                        spawnProxyCacheRefresh(
                            allocator,
                            cfg,
                            state,
                            cache_key,
                            .chat,
                            cfg.proxy_pass_chat,
                            null,
                            prep.message,
                            client_ip,
                            ctx.identity,
                            if (ctx.api_version) |version| @as(u32, version) else null,
                        );
                    }
                    return lookup.cached.status;
                }

                proxy_cache_locked = try state.proxyCacheTryLock(cache_key);
                if (!proxy_cache_locked) {
                    _ = state.proxyCacheWaitForUnlock(cache_key, cfg.proxy_cache_lock_timeout_ms);
                    if (try state.proxyCacheGetCopyWithStale(allocator, cache_key, 0)) |post_wait_lookup| {
                        defer allocator.free(post_wait_lookup.cached.body);
                        defer allocator.free(post_wait_lookup.cached.content_type);
                        var response = http.Response.init(allocator);
                        defer response.deinit();
                        _ = response.setStatus(@enumFromInt(post_wait_lookup.cached.status))
                            .setBody(post_wait_lookup.cached.body)
                            .setContentType(post_wait_lookup.cached.content_type)
                            .setConnection(keep_alive)
                            .setHeader(http.correlation.HEADER_NAME, correlation_id)
                            .setHeader("X-Proxy-Cache", "HIT");
                        applyResponseHeaders(state, &response);
                        try response.write(writer);
                        state.metricsRecord(post_wait_lookup.cached.status);
                        return post_wait_lookup.cached.status;
                    }
                }
            }

            var proxy_result = handleProxyRequest(allocator, cfg, state, writer, .{
                .scope = .chat,
                .proxy_target = cfg.proxy_pass_chat,
                .upstream_path = null,
                .upstream_body = prep.upstream_body,
                .correlation_id = correlation_id,
                .client_ip = client_ip,
                .identity = ctx.identity,
                .api_version = if (ctx.api_version) |version| @as(u32, version) else null,
                .host = request.headers.get("host"),
                .x_forwarded_for = request.headers.get("x-forwarded-for"),
                .allow_streaming = ctx.idempotency_key == null and proxy_cache_key == null,
            }) catch |err| switch (err) {
                error.CircuitOpen => {
                    state.logger.warn(null, "circuit breaker open, rejecting /v1/chat", .{});
                    try sendApiError(allocator, writer, .service_unavailable, "upstream_unavailable", "Upstream unavailable", correlation_id, keep_alive, state);
                    return 503;
                },
                else => {
                    state.circuitRecordFailure();
                    state.logger.warn(null, "circuit breaker: recorded failure, state={s}", .{state.circuitStateName()});
                    const mapped = mapProxyExecutionError(err);
                    try sendApiError(allocator, writer, mapped.status, mapped.code, mapped.message, correlation_id, keep_alive, state);
                    return @intFromEnum(mapped.status);
                },
            };
            defer proxy_result.deinit(allocator);

            switch (proxy_result) {
                .streamed_status => |status| {
                    state.metricsRecord(status);
                    return status;
                },
                .buffered => |normalized| {
                    const comp = http.compression.compressResponse(allocator, normalized.body, normalized.content_type, request.headers.get("Accept-Encoding"), state.compression_config);
                    defer if (comp.body) |cb| allocator.free(cb);
                    const response_body = if (comp.body) |cb| cb else normalized.body;

                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response
                        .setStatus(@enumFromInt(normalized.status))
                        .setBody(response_body)
                        .setContentType(normalized.content_type)
                        .setConnection(keep_alive)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    if (normalized.content_disposition) |cd| {
                        _ = response.setHeader("Content-Disposition", cd);
                    }
                    if (comp.compressed and comp.encoding != null) {
                        _ = response.setHeader("Content-Encoding", comp.encoding.?.headerValue());
                    }
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                    state.metricsRecord(normalized.status);

                    if (proxy_cache_key) |cache_key| {
                        if (normalized.status == 200 and normalized.cacheable) {
                            state.proxyCachePut(cache_key, normalized.status, normalized.body, normalized.content_type) catch |err| {
                                std.log.warn("proxy cache store error: {}", .{err});
                            };
                        }
                    }
                    if (ctx.idempotency_key) |idem_key| {
                        state.idempotencyPut(idem_key, normalized.status, normalized.body, JSON_CONTENT_TYPE) catch |err| {
                            std.log.warn("idempotency store error: {}", .{err});
                        };
                    }
                    return normalized.status;
                },
            }
        },
        .v1_commands => {
            if (request.method != .POST) return null;

            var prep = prepareCommandRequest(
                allocator,
                cfg,
                state,
                &request.headers,
                request.body,
                correlation_id,
                client_ip,
                ctx.api_version,
                ctx.idempotency_key,
            ) catch |err| {
                const desc = describeCommandPrepError(err);
                try sendApiError(allocator, writer, desc.status, desc.code, desc.message, correlation_id, keep_alive, state);
                return @intFromEnum(desc.status);
            };
            defer prep.deinit(allocator);
            ctx.setIdentity(prep.identity.value);

            const effective_idem_key = prep.effective_idempotency_key;
            if (effective_idem_key) |idem_key| {
                if (try state.idempotencyGetCopy(allocator, idem_key)) |cached| {
                    defer allocator.free(cached.body);
                    defer allocator.free(cached.content_type);

                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response.setStatus(@enumFromInt(cached.status))
                        .setBody(cached.body)
                        .setContentType(cached.content_type)
                        .setConnection(keep_alive)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id)
                        .setHeader("X-Idempotent-Replayed", "true");
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                    state.metricsRecord(cached.status);
                    return cached.status;
                }
            }

            if (prep.command.async_execute) {
                state.commandLifecycleCreate(prep.command_id, prep.command.command_type.toString(), correlation_id, ctx.identity orelse "-") catch {
                    try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to initialize command lifecycle", correlation_id, keep_alive, state);
                    return 500;
                };
                spawnAsyncCommandExecution(
                    cfg,
                    state,
                    prep.command_id,
                    prep.command.command_type.toString(),
                    prep.upstream_path,
                    prep.upstream_body,
                    correlation_id,
                    client_ip,
                    ctx.identity,
                    if (ctx.api_version) |version| @as(u32, version) else null,
                    request.headers.get("host"),
                    request.headers.get("x-forwarded-for"),
                );
                const accepted_body = try std.fmt.allocPrint(allocator, "{{\"command_id\":\"{s}\",\"status\":\"pending\",\"status_url\":\"/v1/commands/status?command_id={s}\"}}", .{ prep.command_id, prep.command_id });
                defer allocator.free(accepted_body);
                var accepted = http.Response.json(allocator, accepted_body);
                defer accepted.deinit();
                _ = accepted.setStatus(.accepted).setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
                applyResponseHeaders(state, &accepted);
                try accepted.write(writer);
                state.metricsRecord(202);
                return 202;
            }

            state.commandLifecycleCreate(prep.command_id, prep.command.command_type.toString(), correlation_id, ctx.identity orelse "-") catch {};
            state.commandLifecycleSetRunning(prep.command_id);

            const proxy_cache_bypass = shouldBypassProxyCache(&request.headers) or effective_idem_key != null;
            const proxy_cache_key = if (cfg.proxy_cache_ttl_seconds > 0 and !proxy_cache_bypass)
                try buildProxyCacheKey(allocator, cfg.proxy_cache_key_template, request.method.toString(), "/v1/commands", prep.upstream_body, ctx.identity, if (ctx.api_version) |version| @as(u32, version) else null)
            else
                null;
            defer if (proxy_cache_key) |k| allocator.free(k);
            var proxy_cache_locked = false;
            defer if (proxy_cache_locked) {
                if (proxy_cache_key) |cache_key| state.proxyCacheUnlock(cache_key);
            };
            if (proxy_cache_key) |cache_key| {
                if (try state.proxyCacheGetCopyWithStale(allocator, cache_key, cfg.proxy_cache_stale_while_revalidate_seconds)) |lookup| {
                    defer allocator.free(lookup.cached.body);
                    defer allocator.free(lookup.cached.content_type);

                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response.setStatus(@enumFromInt(lookup.cached.status))
                        .setBody(lookup.cached.body)
                        .setContentType(lookup.cached.content_type)
                        .setConnection(keep_alive)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id)
                        .setHeader("X-Proxy-Cache", if (lookup.is_stale) "STALE" else "HIT");
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                    state.metricsRecord(lookup.cached.status);
                    if (lookup.is_stale) {
                        spawnProxyCacheRefresh(
                            allocator,
                            cfg,
                            state,
                            cache_key,
                            .commands,
                            cfg.proxy_pass_commands_prefix,
                            prep.upstream_path,
                            prep.upstream_body,
                            client_ip,
                            ctx.identity,
                            if (ctx.api_version) |version| @as(u32, version) else null,
                        );
                    }
                    return lookup.cached.status;
                }

                proxy_cache_locked = try state.proxyCacheTryLock(cache_key);
                if (!proxy_cache_locked) {
                    _ = state.proxyCacheWaitForUnlock(cache_key, cfg.proxy_cache_lock_timeout_ms);
                    if (try state.proxyCacheGetCopyWithStale(allocator, cache_key, 0)) |post_wait_lookup| {
                        defer allocator.free(post_wait_lookup.cached.body);
                        defer allocator.free(post_wait_lookup.cached.content_type);
                        var response = http.Response.init(allocator);
                        defer response.deinit();
                        _ = response.setStatus(@enumFromInt(post_wait_lookup.cached.status))
                            .setBody(post_wait_lookup.cached.body)
                            .setContentType(post_wait_lookup.cached.content_type)
                            .setConnection(keep_alive)
                            .setHeader(http.correlation.HEADER_NAME, correlation_id)
                            .setHeader("X-Proxy-Cache", "HIT");
                        applyResponseHeaders(state, &response);
                        try response.write(writer);
                        state.metricsRecord(post_wait_lookup.cached.status);
                        return post_wait_lookup.cached.status;
                    }
                }
            }

            var proxy_result = handleProxyRequest(allocator, cfg, state, writer, .{
                .scope = .commands,
                .proxy_target = cfg.proxy_pass_commands_prefix,
                .upstream_path = prep.upstream_path,
                .upstream_body = prep.upstream_body,
                .correlation_id = correlation_id,
                .client_ip = client_ip,
                .identity = ctx.identity,
                .api_version = if (ctx.api_version) |version| @as(u32, version) else null,
                .host = request.headers.get("host"),
                .x_forwarded_for = request.headers.get("x-forwarded-for"),
                .allow_streaming = effective_idem_key == null and proxy_cache_key == null,
            }) catch |err| switch (err) {
                error.CircuitOpen => {
                    state.logger.warn(null, "circuit breaker open, rejecting /v1/commands", .{});
                    try sendApiError(allocator, writer, .service_unavailable, "upstream_unavailable", "Upstream unavailable", correlation_id, keep_alive, state);
                    state.commandLifecycleSetFailed(prep.command_id, "upstream_unavailable");
                    const cb_audit = http.command.CommandAudit{
                        .command = prep.command.command_type.toString(),
                        .correlation_id = correlation_id,
                        .identity = ctx.identity orelse "-",
                        .status = 503,
                        .latency_ms = ctx.elapsedMs(),
                    };
                    cb_audit.log();
                    return 503;
                },
                else => {
                    state.circuitRecordFailure();
                    state.commandLifecycleSetFailed(prep.command_id, @errorName(err));
                    state.logger.warn(null, "circuit breaker: recorded failure, state={s}", .{state.circuitStateName()});
                    const mapped = mapProxyExecutionError(err);
                    try sendApiError(allocator, writer, mapped.status, mapped.code, mapped.message, correlation_id, keep_alive, state);
                    const cmd_audit = http.command.CommandAudit{
                        .command = prep.command.command_type.toString(),
                        .correlation_id = correlation_id,
                        .identity = ctx.identity orelse "-",
                        .status = @intFromEnum(mapped.status),
                        .latency_ms = ctx.elapsedMs(),
                    };
                    cmd_audit.log();
                    return @intFromEnum(mapped.status);
                },
            };
            defer proxy_result.deinit(allocator);

            switch (proxy_result) {
                .streamed_status => |status| {
                    state.commandLifecycleSetCompleted(prep.command_id, status, "", JSON_CONTENT_TYPE);
                    state.metricsRecord(status);
                    const streamed_audit = http.command.CommandAudit{
                        .command = prep.command.command_type.toString(),
                        .correlation_id = correlation_id,
                        .identity = ctx.identity orelse "-",
                        .status = status,
                        .latency_ms = ctx.elapsedMs(),
                    };
                    streamed_audit.log();
                    return status;
                },
                .buffered => |normalized| {
                    const comp = http.compression.compressResponse(allocator, normalized.body, normalized.content_type, request.headers.get("Accept-Encoding"), state.compression_config);
                    defer if (comp.body) |cb| allocator.free(cb);
                    const response_body = if (comp.body) |cb| cb else normalized.body;

                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response
                        .setStatus(@enumFromInt(normalized.status))
                        .setBody(response_body)
                        .setContentType(normalized.content_type)
                        .setConnection(keep_alive)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    if (normalized.content_disposition) |cd| {
                        _ = response.setHeader("Content-Disposition", cd);
                    }
                    if (comp.compressed and comp.encoding != null) {
                        _ = response.setHeader("Content-Encoding", comp.encoding.?.headerValue());
                    }
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                    state.metricsRecord(normalized.status);
                    state.commandLifecycleSetCompleted(prep.command_id, normalized.status, normalized.body, normalized.content_type);

                    if (proxy_cache_key) |cache_key| {
                        if (normalized.status == 200 and normalized.cacheable) {
                            state.proxyCachePut(cache_key, normalized.status, normalized.body, normalized.content_type) catch |err| {
                                std.log.warn("proxy cache store error: {}", .{err});
                            };
                        }
                    }
                    if (effective_idem_key) |idem_key| {
                        state.idempotencyPut(idem_key, normalized.status, normalized.body, JSON_CONTENT_TYPE) catch |err| {
                            std.log.warn("idempotency store error: {}", .{err});
                        };
                    }

                    const audit = http.command.CommandAudit{
                        .command = prep.command.command_type.toString(),
                        .correlation_id = correlation_id,
                        .identity = ctx.identity orelse "-",
                        .status = normalized.status,
                        .latency_ms = ctx.elapsedMs(),
                    };
                    audit.log();
                    return normalized.status;
                },
            }
        },
        .v1_commands_status => {
            if (request.method != .GET) return null;
            var reply = try handleCommandStatusBuiltin(allocator, cfg, state, &request.headers, request.uri.query, correlation_id);
            defer reply.deinit(allocator);
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(reply.status)
                .setBody(reply.body.?)
                .setContentType(JSON_CONTENT_TYPE)
                .setConnection(keep_alive)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            const status_code = @intFromEnum(reply.status);
            state.metricsRecord(status_code);
            return status_code;
        },
        .v1_approvals_request => {
            if (request.method != .POST) return null;
            var reply = try handleApprovalsRequestBuiltin(allocator, cfg, state, &request.headers, request.body orelse "", correlation_id);
            defer reply.deinit(allocator);
            if (reply.identity) |identity| ctx.setIdentity(identity);
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(reply.status)
                .setBody(reply.body.?)
                .setContentType(JSON_CONTENT_TYPE)
                .setConnection(keep_alive)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            const status_code = @intFromEnum(reply.status);
            state.metricsRecord(status_code);
            return status_code;
        },
        .v1_approvals_respond => {
            if (request.method != .POST) return null;
            var reply = try handleApprovalsRespondBuiltin(allocator, cfg, state, &request.headers, request.body orelse "", correlation_id);
            defer reply.deinit(allocator);
            if (reply.identity) |identity| ctx.setIdentity(identity);
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(reply.status)
                .setBody(reply.body.?)
                .setContentType(JSON_CONTENT_TYPE)
                .setConnection(keep_alive)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            const status_code = @intFromEnum(reply.status);
            state.metricsRecord(status_code);
            return status_code;
        },
        .v1_approvals_status => {
            if (request.method != .GET) return null;
            var reply = try handleApprovalsStatusBuiltin(allocator, cfg, state, &request.headers, request.uri.query, correlation_id);
            defer reply.deinit(allocator);
            if (reply.identity) |identity| ctx.setIdentity(identity);
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(reply.status)
                .setBody(reply.body.?)
                .setContentType(JSON_CONTENT_TYPE)
                .setConnection(keep_alive)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            const status_code = @intFromEnum(reply.status);
            state.metricsRecord(status_code);
            return status_code;
        },
        .v1_devices_register => {
            if (request.method != .POST) return null;
            var reply = try handleDeviceRegisterBuiltin(allocator, cfg, state, &request.headers, request.body orelse "", correlation_id);
            defer reply.deinit(allocator);
            if (reply.identity) |identity| ctx.setIdentity(identity);
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(reply.status)
                .setBody(reply.body.?)
                .setContentType(JSON_CONTENT_TYPE)
                .setConnection(keep_alive)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            if (reply.session_header) |session_header| {
                _ = response.setHeader(http.session.SESSION_HEADER, session_header);
            }
            applyResponseHeaders(state, &response);
            try response.write(writer);
            const status_code = @intFromEnum(reply.status);
            state.metricsRecord(status_code);
            return status_code;
        },
        .v1_sessions_refresh => {
            if (request.method != .POST) return null;
            var reply = try handleSessionRefreshBuiltin(allocator, cfg, state, &request.headers, client_ip, correlation_id);
            defer reply.deinit(allocator);
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(reply.status)
                .setBody(reply.body.?)
                .setContentType(JSON_CONTENT_TYPE)
                .setConnection(keep_alive)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            if (reply.session_header) |session_header| {
                _ = response.setHeader(http.session.SESSION_HEADER, session_header);
            }
            applyResponseHeaders(state, &response);
            try response.write(writer);
            const status_code = @intFromEnum(reply.status);
            state.metricsRecord(status_code);
            return status_code;
        },
        .v1_sessions => {
            var reply = try handleSessionsBuiltin(allocator, cfg, state, request.method.toString(), &request.headers, request.body orelse "", client_ip, correlation_id);
            defer reply.deinit(allocator);
            if (reply.identity) |identity| ctx.setIdentity(identity);
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(reply.status)
                .setBody(reply.body.?)
                .setContentType(JSON_CONTENT_TYPE)
                .setConnection(keep_alive)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            if (reply.session_header) |session_header| {
                _ = response.setHeader(http.session.SESSION_HEADER, session_header);
            }
            applyResponseHeaders(state, &response);
            try response.write(writer);
            const status_code = @intFromEnum(reply.status);
            state.metricsRecord(status_code);
            return status_code;
        },
        .v1_cache_purge => {
            if (request.method != .POST) return null;
            var reply = try handleCachePurgeBuiltin(allocator, cfg, state, &request.headers, request.body orelse "", correlation_id);
            defer reply.deinit(allocator);
            if (reply.identity) |identity| ctx.setIdentity(identity);
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(reply.status)
                .setBody(reply.body.?)
                .setContentType(JSON_CONTENT_TYPE)
                .setConnection(keep_alive)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            const status_code = @intFromEnum(reply.status);
            state.metricsRecord(status_code);
            return status_code;
        },
    }
}

fn handleLocationProxyPass(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    request: *const http.Request,
    target: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    _: []const u8,
    _: ?[]const u8,
) !u16 {
    const resolved = try resolveProxyTarget(allocator, cfg.upstream_base_url, target, request.uri.path);
    defer allocator.free(resolved.url);
    const body = request.body orelse "";
    var upstream_response = try executeRawHttpProxyRequest(allocator, resolved.url, request.method.toString(), request.contentType(), body, correlation_id);
    defer upstream_response.deinit(allocator);

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response.setStatus(@enumFromInt(upstream_response.status_code))
        .setBody(upstream_response.body)
        .setContentType(upstream_response.content_type)
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    applyResponseHeaders(state, &response);
    try response.write(writer);
    const status_code = upstream_response.status_code;
    state.metricsRecord(status_code);
    return status_code;
}

const RawUpstreamResponse = struct {
    status_code: u16,
    content_type: []u8,
    body: []u8,

    fn deinit(self: *RawUpstreamResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.content_type);
        allocator.free(self.body);
        self.* = undefined;
    }
};

fn executeRawHttpProxyRequest(
    allocator: std.mem.Allocator,
    url: []const u8,
    method: []const u8,
    content_type: ?[]const u8,
    body: []const u8,
    correlation_id: []const u8,
) !RawUpstreamResponse {
    const parsed = try parseAbsoluteHttpUrl(url);
    const stream = try std.net.tcpConnectToHost(allocator, parsed.host, parsed.port);
    defer stream.close();

    const ct = content_type orelse "application/octet-stream";
    try stream.writer().print(
        "{s} {s} HTTP/1.1\r\nHost: {s}\r\nContent-Length: {d}\r\nContent-Type: {s}\r\n{s}: {s}\r\nConnection: close\r\n\r\n",
        .{ method, parsed.path, parsed.authority, body.len, ct, http.correlation.HEADER_NAME, correlation_id },
    );
    if (body.len > 0) try stream.writer().writeAll(body);

    var raw = std.ArrayList(u8).init(allocator);
    defer raw.deinit();
    try readAllHttpMessage(allocator, stream, &raw, MAX_REQUEST_SIZE);

    const response = raw.items;
    const header_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return error.InvalidHttpResponse;
    const status_end = std.mem.indexOf(u8, response, "\r\n") orelse return error.InvalidHttpResponse;
    const status_line = response[0..status_end];
    const status_code = parseStatusCode(status_line) orelse return error.InvalidHttpResponse;
    const header_blob = response[status_end + 2 .. header_end];
    const body_slice = response[header_end + 4 ..];

    return .{
        .status_code = status_code,
        .content_type = try allocator.dupe(u8, headerValue(header_blob, "Content-Type") orelse "application/octet-stream"),
        .body = try allocator.dupe(u8, body_slice),
    };
}

const ParsedAbsoluteUrl = struct {
    authority: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,
};

fn parseAbsoluteHttpUrl(url: []const u8) !ParsedAbsoluteUrl {
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return error.InvalidUrl;
    const scheme = url[0..scheme_end];
    const authority_start = scheme_end + 3;
    const path_start = std.mem.indexOfScalarPos(u8, url, authority_start, '/') orelse url.len;
    const authority = url[authority_start..path_start];
    if (authority.len == 0) return error.InvalidUrl;
    return .{
        .authority = authority,
        .host = stripHostPort(authority),
        .port = hostPort(authority) orelse if (std.ascii.eqlIgnoreCase(scheme, "https")) 443 else 80,
        .path = if (path_start < url.len) url[path_start..] else "/",
    };
}

fn readAllHttpMessage(
    _: std.mem.Allocator,
    stream: std.net.Stream,
    out: *std.ArrayList(u8),
    max_bytes: usize,
) !void {
    var buf: [4096]u8 = undefined;
    var header_end: ?usize = null;
    var content_length: usize = 0;

    while (true) {
        const n = try stream.read(&buf);
        if (n == 0) break;
        try out.appendSlice(buf[0..n]);
        if (out.items.len > max_bytes) return error.MessageTooLarge;
        if (header_end == null) {
            if (std.mem.indexOf(u8, out.items, "\r\n\r\n")) |idx| {
                header_end = idx + 4;
                content_length = parseContentLength(out.items[0..idx]) orelse 0;
            }
        }
        if (header_end) |headers_len| {
            if (out.items.len >= headers_len + content_length) return;
        }
    }
}

fn parseStatusCode(status_line: []const u8) ?u16 {
    var parts = std.mem.tokenizeAny(u8, status_line, " ");
    _ = parts.next() orelse return null;
    const code = parts.next() orelse return null;
    return std.fmt.parseInt(u16, code, 10) catch null;
}

fn headerValue(headers_raw: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.tokenizeAny(u8, headers_raw, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const header_name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(header_name, name)) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}

const StaticErrorPageResult = union(enum) {
    served: http.static_file.Result,
    redirect: []u8,

    fn deinit(self: *StaticErrorPageResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .served => |*served| served.deinit(allocator),
            .redirect => |target| allocator.free(target),
        }
        self.* = undefined;
    }
};

fn wantsHtmlErrorPage(request_path: []const u8, headers: *const http.Headers) bool {
    if (std.mem.startsWith(u8, request_path, "/v1/")) return false;
    const accept = headers.get("accept") orelse return false;
    if (std.mem.indexOf(u8, accept, "text/html") != null) return true;
    if (std.mem.indexOf(u8, accept, "*/*") != null) return true;
    if (std.mem.indexOf(u8, accept, "application/json") != null) return false;
    return false;
}

fn findErrorPageTarget(block: *const http.location_router.LocationBlock, status_code: u16) ?[]const u8 {
    for (block.error_pages) |rule| {
        for (rule.status_codes) |candidate| {
            if (candidate == status_code) return rule.target;
        }
    }
    return null;
}

fn maybeResolveStaticErrorPage(
    allocator: std.mem.Allocator,
    matched: http.location_router.MatchResult,
    root_cfg: anytype,
    request_path: []const u8,
    headers: *const http.Headers,
    status_code: u16,
) !?StaticErrorPageResult {
    if (!wantsHtmlErrorPage(request_path, headers)) return null;
    const target = findErrorPageTarget(matched.block, status_code) orelse return null;
    if (std.mem.startsWith(u8, target, "http://") or std.mem.startsWith(u8, target, "https://")) {
        return .{ .redirect = try allocator.dupe(u8, target) };
    }
    var served = (try http.static_file.serve(allocator, .{
        .root = root_cfg.root,
        .request_path = target,
        .matched_pattern = "/",
        .alias = false,
        .index = root_cfg.index,
        .try_files = "",
        .autoindex = false,
        .headers = headers,
        .max_bytes = MAX_REQUEST_SIZE,
    })) orelse return null;
    served.status_code = @enumFromInt(status_code);
    return .{ .served = served };
}

fn runMiddlewarePipeline(
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
            logAccess(ctx, request.method.toString(), request.uri.path, 403, request.headers.get("user-agent") orelse "");
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
        logAccess(ctx, request.method.toString(), request.uri.path, 414, request.headers.get("user-agent") orelse "");
        return true;
    }
    const header_count_check = http.request_limits.validateHeaderCount(request.headers.count(), limits);
    if (header_count_check != .ok) {
        try sendApiError(allocator, writer, .bad_request, "invalid_request", "Too many headers", correlation_id, keep_alive, state);
        state.logger.warn(correlation_id, "Too many headers: {d}", .{request.headers.count()});
        logAccess(ctx, request.method.toString(), request.uri.path, 400, request.headers.get("user-agent") orelse "");
        return true;
    }
    if (request.body) |body| {
        const body_check = http.request_limits.validateBodySize(body.len, limits);
        if (body_check != .ok) {
            try sendApiError(allocator, writer, .payload_too_large, "invalid_request", "Request body too large", correlation_id, keep_alive, state);
            state.logger.warn(correlation_id, "Body too large: {d} bytes", .{body.len});
            logAccess(ctx, request.method.toString(), request.uri.path, 413, request.headers.get("user-agent") orelse "");
            return true;
        }
    }

    if (http.api_router.parseVersionedPath(request.uri.path)) |versioned| {
        ctx.setApiVersion(versioned.version);
    }

    if (ctx.api_version != null and isProtectedAuthRequestRoute(request.uri.path)) {
        if (cfg.device_auth_required and !validateDeviceRequest(cfg, request.method.toString(), request.uri.path, &request.headers, request.body orelse "")) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Device authentication failed", correlation_id, keep_alive, state);
            logAccess(ctx, request.method.toString(), request.uri.path, 401, request.headers.get("user-agent") orelse "");
            return true;
        }

        const identity = try extractIdentityForPolicy(allocator, cfg, state, request);
        defer if (identity) |id| allocator.free(id);
        if (evaluatePolicy(state, cfg, request.method.toString(), request.uri.path, identity, request.headers.get("x-device-id"), &request.headers)) |reason| {
            try sendApiError(allocator, writer, .forbidden, "forbidden", reason, correlation_id, keep_alive, state);
            logAccess(ctx, request.method.toString(), request.uri.path, 403, request.headers.get("user-agent") orelse "");
            return true;
        }
    }

    if (http.idempotency.fromHeaders(&request.headers)) |idem_key| {
        ctx.setIdempotencyKey(idem_key);
    }

    if (state.access_control) |*acl| {
        if (acl.check(client_ip) == .denied) {
            try sendApiError(allocator, writer, .forbidden, "forbidden", "Access denied", correlation_id, keep_alive, state);
            logAccess(ctx, request.method.toString(), request.uri.path, 403, request.headers.get("user-agent") orelse "");
            return true;
        }
    }

    if (!state.rateLimitAllow(client_ip)) {
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
        logAccess(ctx, request.method.toString(), request.uri.path, 429, request.headers.get("user-agent") orelse "");
        return true;
    }

    return false;
}

fn handleStaticLocation(
    allocator: std.mem.Allocator,
    writer: anytype,
    request: *const http.Request,
    matched: http.location_router.MatchResult,
    root_cfg: anytype,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
) !?u16 {
    if (!(request.method == .GET or request.method == .HEAD)) return null;
    var served = (try http.static_file.serve(allocator, .{
        .root = root_cfg.root,
        .request_path = request.uri.path,
        .matched_pattern = matched.block.pattern,
        .alias = root_cfg.alias,
        .index = root_cfg.index,
        .try_files = root_cfg.try_files,
        .autoindex = root_cfg.autoindex,
        .headers = &request.headers,
        .max_bytes = MAX_REQUEST_SIZE,
    })) orelse blk: {
        var error_page = (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request.uri.path, &request.headers, 404)) orelse return null;
        switch (error_page) {
            .redirect => |target| {
                defer allocator.free(target);
                var response = http.Response.init(allocator);
                defer response.deinit();
                _ = response
                    .setStatus(.found)
                    .setBody("")
                    .setContentType("text/plain; charset=utf-8")
                    .setConnection(keep_alive)
                    .setHeader("Location", target)
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                applyResponseHeaders(state, &response);
                if (request.method == .HEAD) {
                    try response.writeHead(writer);
                } else {
                    try response.write(writer);
                }
                state.metricsRecord(302);
                return 302;
            },
            .served => |*resolved| break :blk resolved.*,
        }
    };
    defer served.deinit(allocator);

    if (@intFromEnum(served.status_code) >= 400) {
        if (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request.uri.path, &request.headers, @intFromEnum(served.status_code))) |error_page| {
            switch (error_page) {
                .redirect => |target| {
                    defer allocator.free(target);
                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response
                        .setStatus(.found)
                        .setBody("")
                        .setContentType("text/plain; charset=utf-8")
                        .setConnection(keep_alive)
                        .setHeader("Location", target)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    applyResponseHeaders(state, &response);
                    if (request.method == .HEAD) {
                        try response.writeHead(writer);
                    } else {
                        try response.write(writer);
                    }
                    state.metricsRecord(302);
                    return 302;
                },
                .served => |replacement| {
                    served.deinit(allocator);
                    served = replacement;
                },
            }
        }
    }

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response
        .setStatus(served.status_code)
        .setBody(served.body)
        .setContentType(served.content_type)
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    if (served.etag_value) |etag_value| _ = response.setHeader("ETag", etag_value);
    if (served.last_modified_value) |last_modified| _ = response.setHeader("Last-Modified", last_modified);
    if (served.content_range_value) |content_range| _ = response.setHeader("Content-Range", content_range);
    if (served.accept_ranges) _ = response.setHeader("Accept-Ranges", "bytes");
    applyResponseHeaders(state, &response);
    if (request.method == .HEAD) {
        try response.writeHead(writer);
    } else {
        try response.write(writer);
    }
    const status_code = @intFromEnum(served.status_code);
    state.metricsRecord(status_code);
    return status_code;
}

fn authenticateRealtimeRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    headers: *const http.Headers,
) !bool {
    const auth_result = authorizeRequest(cfg, headers);
    if (auth_result.ok) {
        ctx.setIdentity(auth_result.token_hash orelse "-");
        return true;
    }
    if (http.session.fromHeaders(headers)) |session_token| {
        if (state.validateSessionIdentity(allocator, session_token)) |identity| {
            defer allocator.free(identity);
            ctx.setIdentity(identity);
            return true;
        }
    }
    return false;
}

fn handleWebSocketUpgrade(
    conn: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    client_ip: []const u8,
    keep_alive: *bool,
) !?u16 {
    if (request.method != .GET) return null;
    const writer = conn.writer();

    if (http.api_router.matchRoute(request.uri.path, 1, "/ws/mux")) {
        if (!cfg.websocket_enabled or !cfg.sse_enabled) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, false, state);
            state.metricsRecord(404);
            return 404;
        }
        if (!http.websocket.isUpgradeRequest(&request.headers)) {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Expected websocket upgrade request", correlation_id, false, state);
            state.metricsRecord(400);
            return 400;
        }
        if (!try authenticateRealtimeRequest(allocator, cfg, state, ctx, &request.headers)) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, false, state);
            state.metricsRecord(401);
            return 401;
        }
        const device_id = request.headers.get("x-device-id") orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing X-Device-ID for multiplex stream", correlation_id, false, state);
            state.metricsRecord(400);
            return 400;
        };
        if (!isValidDeviceTopicSegment(device_id)) {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Invalid device id", correlation_id, false, state);
            state.metricsRecord(400);
            return 400;
        }
        const ws_key = request.headers.get("sec-websocket-key") orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing Sec-WebSocket-Key", correlation_id, false, state);
            state.metricsRecord(400);
            return 400;
        };
        const accept_key = try http.websocket.acceptKey(allocator, ws_key);
        defer allocator.free(accept_key);
        try http.websocket.writeServerHandshake(writer, accept_key, request.headers.get("sec-websocket-protocol"));

        state.streamCountAdjust(1, 1);
        defer state.streamCountAdjust(-1, -1);
        handleWebSocketMultiplexLoop(
            conn,
            allocator,
            cfg,
            state,
            correlation_id,
            client_ip,
            ctx.identity,
            if (ctx.api_version) |version| @as(u32, version) else null,
            request.headers.get("host"),
            request.headers.get("x-forwarded-for"),
            device_id,
        ) catch |err| {
            state.logger.warn(correlation_id, "websocket multiplex loop ended: {}", .{err});
        };
        state.metricsRecord(101);
        keep_alive.* = false;
        return 101;
    }

    if (http.api_router.matchRoute(request.uri.path, 1, "/ws/chat") or http.api_router.matchRoute(request.uri.path, 1, "/ws/commands")) {
        if (!cfg.websocket_enabled) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, false, state);
            state.metricsRecord(404);
            return 404;
        }
        if (!http.websocket.isUpgradeRequest(&request.headers)) {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Expected websocket upgrade request", correlation_id, false, state);
            state.metricsRecord(400);
            return 400;
        }
        if (!try authenticateRealtimeRequest(allocator, cfg, state, ctx, &request.headers)) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, false, state);
            state.metricsRecord(401);
            return 401;
        }
        const ws_key = request.headers.get("sec-websocket-key") orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing Sec-WebSocket-Key", correlation_id, false, state);
            state.metricsRecord(400);
            return 400;
        };
        const accept_key = try http.websocket.acceptKey(allocator, ws_key);
        defer allocator.free(accept_key);
        try http.websocket.writeServerHandshake(writer, accept_key, request.headers.get("sec-websocket-protocol"));

        const ws_scope: UpstreamScope = if (http.api_router.matchRoute(request.uri.path, 1, "/ws/chat")) .chat else .commands;
        const ws_proxy_target = if (ws_scope == .chat) cfg.proxy_pass_chat else cfg.proxy_pass_commands_prefix;
        state.streamCountAdjust(1, 0);
        defer state.streamCountAdjust(-1, 0);
        handleWebSocketProxyLoop(
            conn,
            allocator,
            cfg,
            state,
            correlation_id,
            client_ip,
            ctx.identity,
            if (ctx.api_version) |version| @as(u32, version) else null,
            request.headers.get("host"),
            request.headers.get("x-forwarded-for"),
            ws_scope,
            ws_proxy_target,
        ) catch |err| {
            state.logger.warn(correlation_id, "websocket loop ended: {}", .{err});
        };
        state.metricsRecord(101);
        keep_alive.* = false;
        return 101;
    }

    return null;
}

fn handleSseStream(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: *bool,
) !?u16 {
    if (request.method != .GET) return null;
    if (!http.api_router.matchRoute(request.uri.path, 1, "/events/stream")) return null;

    if (!cfg.sse_enabled) {
        try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, false, state);
        state.metricsRecord(404);
        return 404;
    }
    if (!try authenticateRealtimeRequest(allocator, cfg, state, ctx, &request.headers)) {
        try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, false, state);
        state.metricsRecord(401);
        return 401;
    }

    const topic = parseQueryParam(request.uri.query, "topic") orelse "default";
    const last_event_id = parseLastEventId(request.headers.get("last-event-id"));
    state.streamCountAdjust(0, 1);
    defer state.streamCountAdjust(0, -1);
    try streamSseTopic(writer, allocator, cfg, state, topic, last_event_id, correlation_id);
    state.metricsRecord(200);
    keep_alive.* = false;
    return 200;
}

fn handleSsePublish(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
) !?u16 {
    if (request.method != .POST) return null;
    if (!http.api_router.matchRoute(request.uri.path, 1, "/events/publish")) return null;

    if (!cfg.sse_enabled) {
        try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive, state);
        state.metricsRecord(404);
        return 404;
    }
    const auth_result = authorizeRequest(cfg, &request.headers);
    if (!auth_result.ok) {
        try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
        state.metricsRecord(401);
        return 401;
    }
    ctx.setIdentity(auth_result.token_hash orelse "-");

    const topic = parseQueryParam(request.uri.query, "topic") orelse "default";
    const payload = request.body orelse "";
    const event_id = try state.event_hub.publish(topic, payload, http.event_loop.monotonicMs());
    const body = try std.fmt.allocPrint(allocator, "{{\"topic\":\"{s}\",\"id\":{d}}}", .{ topic, event_id });
    defer allocator.free(body);
    var response = http.Response.json(allocator, body);
    defer response.deinit();
    _ = response.setStatus(.accepted)
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    applyResponseHeaders(state, &response);
    try response.write(writer);
    state.metricsRecord(202);
    return 202;
}

fn handleBuiltinApiTailHttp1(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
    client_ip: []const u8,
) !?u16 {
    const matched_route: ?http.location_router.BuiltinRoute =
        if (http.api_router.matchRoute(request.uri.path, 1, "/devices/register"))
            .v1_devices_register
        else if (http.api_router.matchRoute(request.uri.path, 1, "/sessions/refresh"))
            .v1_sessions_refresh
        else if (http.api_router.matchRoute(request.uri.path, 1, "/sessions"))
            .v1_sessions
        else if (http.api_router.matchRoute(request.uri.path, 1, "/cache/purge"))
            .v1_cache_purge
        else if (http.api_router.matchRoute(request.uri.path, 1, "/commands/status"))
            .v1_commands_status
        else if (http.api_router.matchRoute(request.uri.path, 1, "/approvals/request"))
            .v1_approvals_request
        else if (http.api_router.matchRoute(request.uri.path, 1, "/approvals/respond"))
            .v1_approvals_respond
        else if (http.api_router.matchRoute(request.uri.path, 1, "/approvals/status"))
            .v1_approvals_status
        else
            null;

    if (matched_route) |route| {
        return try dispatchBuiltinRouteHttp1(allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive, client_ip, route);
    }
    return null;
}

fn handleBackendProtocolTail(
    conn: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    client_ip: []const u8,
    keep_alive: bool,
) !?u16 {
    const writer = conn.writer();

    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/subrequest")) {
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (!auth_result.ok) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
            return 401;
        }
        ctx.setIdentity(auth_result.token_hash orelse "-");
        const body = request.body orelse "";
        const sub = parseSubrequestPayload(allocator, body) catch {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Invalid subrequest payload", correlation_id, keep_alive, state);
            return 400;
        };
        defer {
            allocator.free(sub.url);
            if (sub.body) |b| allocator.free(b);
        }
        const out = executeSubrequest(allocator, sub.url, sub.method, sub.body) catch |err| {
            state.logger.warn(correlation_id, "subrequest failed: {}", .{err});
            try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "Subrequest failed", correlation_id, keep_alive, state);
            return 502;
        };
        defer allocator.free(out.body);
        var response = http.Response.init(allocator);
        defer response.deinit();
        _ = response.setStatus(@enumFromInt(out.status))
            .setBody(out.body)
            .setContentType(out.content_type)
            .setConnection(keep_alive)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(out.status);
        return out.status;
    }

    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/backend/fastcgi")) {
        return try handleFastcgiRoute(allocator, writer, cfg, cfg.fastcgi_upstream, request, client_ip, correlation_id, keep_alive, state);
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/backend/uwsgi")) {
        return try handleUwsgiRoute(allocator, writer, cfg, cfg.uwsgi_upstream, request, client_ip, correlation_id, keep_alive, state);
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/backend/scgi")) {
        return try handleScgiRoute(allocator, writer, cfg, cfg.scgi_upstream, request, client_ip, correlation_id, keep_alive, state);
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/backend/grpc")) {
        const upstream = std.mem.trim(u8, cfg.grpc_upstream, " \t\r\n");
        if (upstream.len == 0) {
            try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "gRPC upstream not configured", correlation_id, keep_alive, state);
            return 501;
        }
        const body = request.body orelse "";
        const grpc_resp = proxyGrpcExecute(allocator, upstream, body, correlation_id, state) catch |err| {
            state.logger.warn(correlation_id, "grpc proxy failed: {}", .{err});
            try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "gRPC proxy failed", correlation_id, keep_alive, state);
            return 502;
        };
        defer allocator.free(grpc_resp);
        var response = http.Response.init(allocator);
        defer response.deinit();
        _ = response.setStatus(.ok)
            .setBody(grpc_resp)
            .setContentType("application/grpc")
            .setConnection(keep_alive)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(200);
        return 200;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/backend/memcached")) {
        const ep = std.mem.trim(u8, cfg.memcached_upstream, " \t\r\n");
        if (ep.len == 0) {
            try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "Memcached upstream not configured", correlation_id, keep_alive, state);
            return 501;
        }
        const payload = request.body orelse "";
        const parsed = parseMemcachedPayload(allocator, payload) catch {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Invalid memcached payload", correlation_id, keep_alive, state);
            return 400;
        };
        defer {
            allocator.free(parsed.op);
            allocator.free(parsed.key);
            if (parsed.value) |v| allocator.free(v);
        }
        if (std.ascii.eqlIgnoreCase(parsed.op, "get")) {
            const body = blk: {
                const value = http.memcached.get(allocator, ep, parsed.key) catch null;
                defer if (value) |v| allocator.free(v);
                break :blk if (value) |v|
                    try std.fmt.allocPrint(allocator, "{{\"value\":{s}}}", .{std.json.fmt(v, .{})})
                else
                    try allocator.dupe(u8, "{\"value\":null}");
            };
            defer allocator.free(body);
            var response = http.Response.json(allocator, body);
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            return 200;
        }
        if (std.ascii.eqlIgnoreCase(parsed.op, "set")) {
            const stored = http.memcached.set(allocator, ep, parsed.key, parsed.value orelse "", parsed.ttl) catch false;
            var response = http.Response.json(allocator, if (stored) "{\"stored\":true}" else "{\"stored\":false}");
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            return 200;
        }
        try sendApiError(allocator, writer, .bad_request, "invalid_request", "Unsupported memcached operation", correlation_id, keep_alive, state);
        return 400;
    }

    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/mail/smtp")) {
        var identity = resolveRequestIdentity(allocator, cfg, state, &request.headers);
        defer if (identity) |*owned_identity| owned_identity.deinit(allocator);
        try handleSmtpProxyRoute(
            allocator,
            writer,
            cfg.smtp_upstream,
            request.body orelse "",
            correlation_id,
            keep_alive,
            state,
            if (identity) |resolved| resolved.value else null,
        );
        return 200;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/mail/imap")) {
        try handleImapProxyRoute(allocator, writer, cfg.imap_upstream, request.body orelse "", correlation_id, keep_alive, state);
        return 200;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/mail/pop3")) {
        try handleMailProxyRoute(allocator, writer, cfg.pop3_upstream, request.body orelse "", correlation_id, keep_alive, state);
        return 200;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/stream/tcp")) {
        try handleMailProxyRoute(allocator, writer, cfg.tcp_proxy_upstream, request.body orelse "", correlation_id, keep_alive, state);
        return 200;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/stream/udp")) {
        const upstream = std.mem.trim(u8, cfg.udp_proxy_upstream, " \t\r\n");
        if (upstream.len == 0) {
            try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "UDP upstream not configured", correlation_id, keep_alive, state);
            return 501;
        }
        const udp_resp = executeUdpDatagramRequest(allocator, upstream, request.body orelse "") catch |err| {
            state.logger.warn(correlation_id, "udp stream proxy failed: {}", .{err});
            try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "UDP proxy failed", correlation_id, keep_alive, state);
            return 502;
        };
        defer allocator.free(udp_resp);
        var response = http.Response.init(allocator);
        defer response.deinit();
        _ = response.setStatus(.ok)
            .setBody(udp_resp)
            .setContentType("application/octet-stream")
            .setConnection(keep_alive)
            .setHeader(http.correlation.HEADER_NAME, correlation_id)
            .setHeader("X-Stream-SSL-Termination", if (cfg.stream_ssl_termination) "enabled" else "disabled");
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(200);
        return 200;
    }

    return null;
}

fn handlePrimaryApiTailHttp1(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
    client_ip: []const u8,
) !?u16 {
    const matched_route: ?http.location_router.BuiltinRoute =
        if (http.api_router.matchRoute(request.uri.path, 1, "/commands"))
            .v1_commands
        else if (http.api_router.matchRoute(request.uri.path, 1, "/chat"))
            .v1_chat
        else
            null;

    if (matched_route) |route| {
        return try dispatchBuiltinRouteHttp1(allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive, client_ip, route);
    }
    return null;
}

fn handleWebSocketProxyLoop(
    conn: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    correlation_id: []const u8,
    client_ip: []const u8,
    identity: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
    scope: UpstreamScope,
    proxy_target: []const u8,
) !void {
    const writer = conn.writer();
    var last_activity_ms = http.event_loop.monotonicMs();

    while (!http.shutdown.isShutdownRequested()) {
        var frame = http.websocket.readFrame(conn, allocator, cfg.websocket_max_frame_size) catch |err| switch (err) {
            error.ConnectionClosed => return,
            else => return err,
        };
        defer http.websocket.deinitFrame(allocator, &frame);
        last_activity_ms = http.event_loop.monotonicMs();

        switch (frame.opcode) {
            .close => {
                try http.websocket.writeFrame(writer, .close, "", true);
                return;
            },
            .ping => {
                try http.websocket.writeFrame(writer, .pong, frame.payload, true);
                continue;
            },
            .pong => continue,
            .binary => continue,
            .continuation => continue,
            .text => {},
        }

        const payload = std.mem.trim(u8, frame.payload, " \t\r\n");
        if (payload.len == 0) {
            try http.websocket.writeFrame(writer, .text, "{\"code\":\"invalid_request\",\"message\":\"empty websocket message\"}", true);
            continue;
        }

        const upstream_payload = if (scope == .chat)
            try std.fmt.allocPrint(allocator, "{{\"message\":{s}}}", .{std.json.fmt(payload, .{})})
        else
            try allocator.dupe(u8, payload);
        defer allocator.free(upstream_payload);

        const exec = proxyJsonExecute(
            allocator,
            cfg,
            scope,
            proxy_target,
            null,
            upstream_payload,
            correlation_id,
            client_ip,
            identity,
            api_version,
            incoming_host,
            incoming_x_forwarded_for,
            std.io.null_writer,
            state,
            false,
        ) catch |err| {
            const mapped = mapProxyExecutionError(err);
            const err_json = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
            defer allocator.free(err_json);
            try http.websocket.writeFrame(writer, .text, err_json, true);
            continue;
        };

        switch (exec) {
            .streamed_status => |status| {
                const mapped = mapUpstreamError(status);
                const err_json = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
                defer allocator.free(err_json);
                try http.websocket.writeFrame(writer, .text, err_json, true);
            },
            .buffered => |result| {
                defer allocator.free(result.body);
                defer allocator.free(result.content_type);
                if (result.content_disposition) |cd| allocator.free(cd);

                if (result.status == 200) {
                    if (scope == .chat) {
                        _ = try state.event_hub.publish("ws.chat.responses", result.body, http.event_loop.monotonicMs());
                    } else {
                        _ = try state.event_hub.publish("ws.commands.responses", result.body, http.event_loop.monotonicMs());
                    }
                    try http.websocket.writeFrame(writer, .text, result.body, true);
                } else {
                    const mapped = mapUpstreamError(result.status);
                    const err_json = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
                    defer allocator.free(err_json);
                    try http.websocket.writeFrame(writer, .text, err_json, true);
                }
            },
        }
    }
}

fn handleWebSocketMultiplexLoop(
    conn: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    correlation_id: []const u8,
    client_ip: []const u8,
    identity: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
    device_id: []const u8,
) !void {
    const writer = conn.writer();
    var channels = std.ArrayList(MuxChannel).init(allocator);
    defer {
        for (channels.items) |*ch| deinitMuxChannel(allocator, ch);
        channels.deinit();
    }

    var last_activity_ms = http.event_loop.monotonicMs();
    while (!http.shutdown.isShutdownRequested()) {
        var frame = http.websocket.readFrame(conn, allocator, cfg.websocket_max_frame_size) catch |err| switch (err) {
            error.ConnectionClosed => return,
            else => return err,
        };
        defer http.websocket.deinitFrame(allocator, &frame);
        last_activity_ms = http.event_loop.monotonicMs();

        switch (frame.opcode) {
            .close => {
                try http.websocket.writeFrame(writer, .close, "", true);
                return;
            },
            .ping => {
                try http.websocket.writeFrame(writer, .pong, frame.payload, true);
                continue;
            },
            .pong, .binary, .continuation => continue,
            .text => {},
        }

        const payload = std.mem.trim(u8, frame.payload, " \t\r\n");
        if (payload.len == 0) continue;
        var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{ .ignore_unknown_fields = true }) catch {
            try http.websocket.writeFrame(writer, .text, "{\"type\":\"error\",\"message\":\"invalid json\"}", true);
            continue;
        };
        defer parsed.deinit();
        if (parsed.value != .object) {
            try http.websocket.writeFrame(writer, .text, "{\"type\":\"error\",\"message\":\"invalid envelope\"}", true);
            continue;
        }
        const obj = parsed.value.object;
        const msg_type = parseMuxObjectFieldString(obj, "type") orelse {
            try http.websocket.writeFrame(writer, .text, "{\"type\":\"error\",\"message\":\"missing type\"}", true);
            continue;
        };
        const channel_name = parseMuxObjectFieldString(obj, "channel") orelse "default";

        if (std.ascii.eqlIgnoreCase(msg_type, "subscribe")) {
            const topic = parseMuxObjectFieldString(obj, "topic") orelse {
                try http.websocket.writeFrame(writer, .text, "{\"type\":\"error\",\"message\":\"missing topic\"}", true);
                continue;
            };
            if (!isValidDeviceTopicSegment(topic) or channels.items.len >= WS_MUX_MAX_CHANNELS) {
                try http.websocket.writeFrame(writer, .text, "{\"type\":\"error\",\"message\":\"invalid or too many channels\"}", true);
                continue;
            }
            const namespaced_topic = try std.fmt.allocPrint(allocator, "device/{s}/{s}", .{ device_id, topic });
            defer allocator.free(namespaced_topic);
            upsertMuxEventChannel(allocator, &channels, channel_name, namespaced_topic);
            const ack = try std.fmt.allocPrint(allocator, "{{\"channel\":\"{s}\",\"type\":\"subscribed\",\"topic\":\"{s}\"}}", .{ channel_name, topic });
            defer allocator.free(ack);
            try http.websocket.writeFrame(writer, .text, ack, true);
            continue;
        }
        if (std.ascii.eqlIgnoreCase(msg_type, "unsubscribe")) {
            removeMuxChannel(allocator, &channels, channel_name);
            const ack = try std.fmt.allocPrint(allocator, "{{\"channel\":\"{s}\",\"type\":\"unsubscribed\"}}", .{channel_name});
            defer allocator.free(ack);
            try http.websocket.writeFrame(writer, .text, ack, true);
            continue;
        }
        if (std.ascii.eqlIgnoreCase(msg_type, "publish")) {
            const topic = parseMuxObjectFieldString(obj, "topic") orelse {
                try http.websocket.writeFrame(writer, .text, "{\"type\":\"error\",\"message\":\"missing topic\"}", true);
                continue;
            };
            var payload_owned: ?[]u8 = null;
            defer if (payload_owned) |owned| allocator.free(owned);
            const msg = if (obj.get("payload")) |payload_value|
                switch (payload_value) {
                    .string => payload_value.string,
                    else => blk: {
                        const encoded = std.json.stringifyAlloc(allocator, payload_value, .{}) catch {
                            try http.websocket.writeFrame(writer, .text, "{\"type\":\"error\",\"message\":\"invalid payload\"}", true);
                            continue;
                        };
                        payload_owned = encoded;
                        break :blk encoded;
                    },
                }
            else
                "";
            if (!isValidDeviceTopicSegment(topic)) {
                try http.websocket.writeFrame(writer, .text, "{\"type\":\"error\",\"message\":\"invalid topic\"}", true);
                continue;
            }
            const namespaced_topic = try std.fmt.allocPrint(allocator, "device/{s}/{s}", .{ device_id, topic });
            defer allocator.free(namespaced_topic);
            const event_id = try state.event_hub.publish(namespaced_topic, msg, http.event_loop.monotonicMs());
            const ack = try std.fmt.allocPrint(allocator, "{{\"channel\":\"{s}\",\"type\":\"published\",\"topic\":\"{s}\",\"id\":{d}}}", .{ channel_name, topic, event_id });
            defer allocator.free(ack);
            try http.websocket.writeFrame(writer, .text, ack, true);
            continue;
        }
        if (std.ascii.eqlIgnoreCase(msg_type, "command")) {
            var cmd = http.command.parseCommand(allocator, payload) catch {
                try http.websocket.writeFrame(writer, .text, "{\"type\":\"error\",\"message\":\"invalid command envelope\"}", true);
                continue;
            };
            defer cmd.deinit(allocator);
            const command_id = if (cmd.command_id) |cid| try allocator.dupe(u8, cid) else try generateCommandId(allocator);
            defer allocator.free(command_id);
            const envelope = try http.command.buildUpstreamEnvelope(
                allocator,
                cmd.command_type,
                cmd.params_raw,
                command_id,
                correlation_id,
                identity orelse "-",
                client_ip,
                if (api_version) |version| @as(u16, @intCast(version)) else null,
            );
            defer allocator.free(envelope);

            if (cmd.async_execute) {
                state.commandLifecycleCreate(command_id, cmd.command_type.toString(), correlation_id, identity orelse "-") catch {};
                spawnAsyncCommandExecution(
                    cfg,
                    state,
                    command_id,
                    cmd.command_type.toString(),
                    cmd.command_type.upstreamPath(),
                    envelope,
                    correlation_id,
                    client_ip,
                    identity,
                    api_version,
                    incoming_host,
                    incoming_x_forwarded_for,
                );
                upsertMuxCommandChannel(allocator, &channels, channel_name, command_id, .pending);
                const ack = try std.fmt.allocPrint(allocator, "{{\"channel\":\"{s}\",\"type\":\"command.accepted\",\"command_id\":\"{s}\"}}", .{ channel_name, command_id });
                defer allocator.free(ack);
                try http.websocket.writeFrame(writer, .text, ack, true);
                continue;
            }

            const exec = proxyJsonExecute(
                allocator,
                cfg,
                .commands,
                cfg.proxy_pass_commands_prefix,
                cmd.command_type.upstreamPath(),
                envelope,
                correlation_id,
                client_ip,
                identity,
                api_version,
                incoming_host,
                incoming_x_forwarded_for,
                std.io.null_writer,
                state,
                false,
            ) catch |err| {
                const err_msg = try std.fmt.allocPrint(allocator, "{{\"channel\":\"{s}\",\"type\":\"command.error\",\"command_id\":\"{s}\",\"error\":\"{s}\"}}", .{ channel_name, command_id, @errorName(err) });
                defer allocator.free(err_msg);
                try http.websocket.writeFrame(writer, .text, err_msg, true);
                continue;
            };
            switch (exec) {
                .streamed_status => |status| {
                    const msg = try std.fmt.allocPrint(allocator, "{{\"channel\":\"{s}\",\"type\":\"command.result\",\"command_id\":\"{s}\",\"status\":{d}}}", .{ channel_name, command_id, status });
                    defer allocator.free(msg);
                    try http.websocket.writeFrame(writer, .text, msg, true);
                },
                .buffered => |result| {
                    defer allocator.free(result.body);
                    defer allocator.free(result.content_type);
                    if (result.content_disposition) |cd| allocator.free(cd);
                    const body_is_json = std.mem.startsWith(u8, std.mem.trim(u8, result.body, " \t\r\n"), "{") or std.mem.startsWith(u8, std.mem.trim(u8, result.body, " \t\r\n"), "[");
                    const msg = if (body_is_json)
                        try std.fmt.allocPrint(allocator, "{{\"channel\":\"{s}\",\"type\":\"command.result\",\"command_id\":\"{s}\",\"status\":{d},\"body\":{s}}}", .{ channel_name, command_id, result.status, result.body })
                    else
                        try std.fmt.allocPrint(allocator, "{{\"channel\":\"{s}\",\"type\":\"command.result\",\"command_id\":\"{s}\",\"status\":{d},\"body\":{s}}}", .{ channel_name, command_id, result.status, std.json.fmt(result.body, .{}) });
                    defer allocator.free(msg);
                    try http.websocket.writeFrame(writer, .text, msg, true);
                },
            }
            continue;
        }

        try http.websocket.writeFrame(writer, .text, "{\"type\":\"error\",\"message\":\"unknown type\"}", true);
    }
}

fn deinitMuxChannel(allocator: std.mem.Allocator, ch: *MuxChannel) void {
    allocator.free(ch.name);
    if (ch.topic) |t| allocator.free(t);
    if (ch.command_id) |id| allocator.free(id);
    ch.* = undefined;
}

fn upsertMuxEventChannel(allocator: std.mem.Allocator, channels: *std.ArrayList(MuxChannel), channel_name: []const u8, topic: []const u8) void {
    for (channels.items) |*ch| {
        if (std.mem.eql(u8, ch.name, channel_name)) {
            if (ch.topic) |old| allocator.free(old);
            if (ch.command_id) |id| {
                allocator.free(id);
                ch.command_id = null;
            }
            ch.kind = .events;
            ch.topic = allocator.dupe(u8, topic) catch null;
            ch.last_event_id = 0;
            ch.last_command_status = null;
            return;
        }
    }
    channels.append(.{
        .name = allocator.dupe(u8, channel_name) catch return,
        .kind = .events,
        .topic = allocator.dupe(u8, topic) catch null,
        .last_event_id = 0,
        .command_id = null,
        .last_command_status = null,
    }) catch {};
}

fn upsertMuxCommandChannel(allocator: std.mem.Allocator, channels: *std.ArrayList(MuxChannel), channel_name: []const u8, command_id: []const u8, status: CommandLifecycleStatus) void {
    for (channels.items) |*ch| {
        if (std.mem.eql(u8, ch.name, channel_name)) {
            if (ch.command_id) |old| allocator.free(old);
            if (ch.topic) |old_topic| {
                allocator.free(old_topic);
                ch.topic = null;
            }
            ch.kind = .command;
            ch.command_id = allocator.dupe(u8, command_id) catch null;
            ch.last_command_status = status;
            return;
        }
    }
    channels.append(.{
        .name = allocator.dupe(u8, channel_name) catch return,
        .kind = .command,
        .topic = null,
        .last_event_id = 0,
        .command_id = allocator.dupe(u8, command_id) catch null,
        .last_command_status = status,
    }) catch {};
}

fn removeMuxChannel(allocator: std.mem.Allocator, channels: *std.ArrayList(MuxChannel), channel_name: []const u8) void {
    var i: usize = 0;
    while (i < channels.items.len) : (i += 1) {
        if (!std.mem.eql(u8, channels.items[i].name, channel_name)) continue;
        var ch = channels.swapRemove(i);
        deinitMuxChannel(allocator, &ch);
        return;
    }
}

fn pollMuxChannels(writer: anytype, allocator: std.mem.Allocator, state: *GatewayState, channels: *std.ArrayList(MuxChannel)) !void {
    for (channels.items) |*ch| {
        switch (ch.kind) {
            .events => {
                const topic = ch.topic orelse continue;
                const events = state.event_hub.snapshotSince(allocator, topic, ch.last_event_id) catch continue;
                defer http.event_hub.deinitSnapshot(allocator, events);
                for (events) |event| {
                    const msg = try std.fmt.allocPrint(allocator, "{{\"channel\":\"{s}\",\"type\":\"event\",\"topic\":{s},\"id\":{d},\"payload\":{s}}}", .{
                        ch.name,
                        std.json.fmt(topic, .{}),
                        event.id,
                        std.json.fmt(event.payload, .{}),
                    });
                    defer allocator.free(msg);
                    try http.websocket.writeFrame(writer, .text, msg, true);
                    ch.last_event_id = event.id;
                }
            },
            .command => {
                const command_id = ch.command_id orelse continue;
                var snap = state.commandLifecycleGet(allocator, command_id) orelse continue;
                defer snap.deinit(allocator);
                if (ch.last_command_status != null and ch.last_command_status.? == snap.status) continue;
                ch.last_command_status = snap.status;
                const body_json = if (snap.response_body.len > 0 and (std.mem.startsWith(u8, std.mem.trim(u8, snap.response_body, " \t\r\n"), "{") or std.mem.startsWith(u8, std.mem.trim(u8, snap.response_body, " \t\r\n"), "[")))
                    snap.response_body
                else
                    "\"\"";
                const msg = try std.fmt.allocPrint(allocator, "{{\"channel\":\"{s}\",\"type\":\"command.update\",\"command_id\":\"{s}\",\"status\":\"{s}\",\"response_status\":{d},\"body\":{s},\"error\":{s}}}", .{
                    ch.name,
                    command_id,
                    @tagName(snap.status),
                    snap.response_status,
                    body_json,
                    std.json.fmt(snap.error_message, .{}),
                });
                defer allocator.free(msg);
                try http.websocket.writeFrame(writer, .text, msg, true);
            },
        }
    }
}

fn parseMuxObjectFieldString(obj: std.json.ObjectMap, field_name: []const u8) ?[]const u8 {
    const v = obj.get(field_name) orelse return null;
    if (v != .string) return null;
    const trimmed = std.mem.trim(u8, v.string, " \t\r\n");
    if (trimmed.len == 0) return null;
    return trimmed;
}

fn isValidDeviceTopicSegment(raw: []const u8) bool {
    const s = std.mem.trim(u8, raw, " \t\r\n");
    if (s.len == 0 or s.len > 128) return false;
    for (s) |ch| {
        if (!(std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.')) return false;
    }
    return true;
}

fn serveTryFilesFallback(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    method: []const u8,
    request_path: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    writer: anytype,
    state: *GatewayState,
) !u16 {
    if (!(std.ascii.eqlIgnoreCase(method, "GET") or std.ascii.eqlIgnoreCase(method, "HEAD"))) return error.NoTryFiles;
    if (cfg.doc_root.len == 0 or cfg.try_files.len == 0) return error.NoTryFiles;

    var candidates = std.mem.splitScalar(u8, cfg.try_files, ',');
    while (candidates.next()) |cand_raw| {
        const cand = std.mem.trim(u8, cand_raw, " \t\r\n");
        if (cand.len == 0) continue;
        const rel = if (std.mem.eql(u8, cand, "$uri")) request_path else cand;
        const safe_rel = std.mem.trimLeft(u8, rel, "/");
        const full_path = try std.fs.path.join(allocator, &[_][]const u8{ cfg.doc_root, safe_rel });
        defer allocator.free(full_path);
        const file_data = std.fs.cwd().readFileAlloc(allocator, full_path, MAX_REQUEST_SIZE) catch continue;
        defer allocator.free(file_data);

        var response = http.Response.ok(allocator, if (std.ascii.eqlIgnoreCase(method, "HEAD")) "" else file_data, "application/octet-stream");
        defer response.deinit();
        _ = response
            .setConnection(keep_alive)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        return 200;
    }
    return error.NoTryFiles;
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
    try writer.print("Server: {s}/{s}\r\n", .{ http.SERVER_NAME, http.SERVER_VERSION });
    try writer.writeAll("Connection: close\r\n");
    try writer.writeAll("Cache-Control: no-cache\r\n");
    try writer.writeAll("Content-Type: text/event-stream\r\n");
    try writer.writeAll("X-Accel-Buffering: no\r\n");
    try writer.print("{s}: {s}\r\n", .{ http.correlation.HEADER_NAME, correlation_id });
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

        std.time.sleep(@as(u64, poll_ms) * std.time.ns_per_ms);
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

fn parseQueryParam(query: ?[]const u8, key: []const u8) ?[]const u8 {
    const raw = query orelse return null;
    var it = std.mem.splitScalar(u8, raw, '&');
    while (it.next()) |part| {
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse continue;
        const name = std.mem.trim(u8, part[0..eq], " \t\r\n");
        if (!std.mem.eql(u8, name, key)) continue;
        return std.mem.trim(u8, part[eq + 1 ..], " \t\r\n");
    }
    return null;
}

fn generateCommandId(allocator: std.mem.Allocator) ![]const u8 {
    var rnd: [16]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    return std.fmt.allocPrint(allocator, "cmd-{d}-{s}", .{
        std.time.milliTimestamp(),
        std.fmt.fmtSliceHexLower(&rnd),
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
    const exec = proxyJsonExecute(
        job.allocator,
        job.cfg,
        .commands,
        job.cfg.proxy_pass_commands_prefix,
        job.upstream_path,
        job.envelope,
        job.correlation_id,
        job.client_ip,
        job.identity,
        job.api_version,
        job.incoming_host,
        job.incoming_x_forwarded_for,
        std.io.null_writer,
        job.state,
        false,
    ) catch |err| {
        job.state.commandLifecycleSetFailed(job.command_id, @errorName(err));
        return;
    };

    switch (exec) {
        .streamed_status => |status| {
            job.state.commandLifecycleSetCompleted(job.command_id, status, "", JSON_CONTENT_TYPE);
        },
        .buffered => |resp| {
            defer job.allocator.free(resp.body);
            defer job.allocator.free(resp.content_type);
            if (resp.content_disposition) |cd| job.allocator.free(cd);
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

fn parseLastEventId(raw: ?[]const u8) u64 {
    const value = raw orelse return 0;
    return std.fmt.parseInt(u64, std.mem.trim(u8, value, " \t\r\n"), 10) catch 0;
}

fn applyInternalRedirectRules(
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

fn evaluateConditionalRules(
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

fn spawnMirrorRequests(
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
        var client = std.http.Client{ .allocator = allocator };
        defer client.deinit();
        const uri = std.Uri.parse(rule.target_url) catch continue;
        var header_buf: [8 * 1024]u8 = undefined;
        var headers = [_]std.http.Header{
            .{ .name = http.correlation.HEADER_NAME, .value = correlation_id },
            .{ .name = "X-Mirror-Client-IP", .value = client_ip },
            .{ .name = "Content-Type", .value = content_type orelse "application/octet-stream" },
        };
        var req = client.open(.POST, uri, .{
            .server_header_buffer = &header_buf,
            .extra_headers = headers[0..],
            .headers = .{ .content_type = .{ .override = content_type orelse "application/octet-stream" } },
        }) catch continue;
        defer req.deinit();
        req.send() catch continue;
        req.writeAll(body) catch continue;
        req.finish() catch continue;
        req.wait() catch continue;
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
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    const uri = try std.Uri.parse(url);
    var header_buf: [16 * 1024]u8 = undefined;
    var req = try client.open(method, uri, .{ .server_header_buffer = &header_buf });
    defer req.deinit();
    if (req_body) |b| {
        req.transfer_encoding = .{ .content_length = b.len };
    }
    try req.send();
    if (req_body) |b| {
        try req.writeAll(b);
    }
    try req.finish();
    try req.wait();
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try req.reader().readAllArrayList(&out, 2 * 1024 * 1024);
    return .{
        .status = @intFromEnum(req.response.status),
        .body = try out.toOwnedSlice(),
        .content_type = req.response.content_type orelse "application/octet-stream",
    };
}

fn handleFastcgiRoute(
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

    var request_uri = std.ArrayList(u8).init(allocator);
    defer request_uri.deinit();
    try request_uri.appendSlice(request.uri.path);
    if (request.uri.query) |query| {
        try request_uri.append('?');
        try request_uri.appendSlice(query);
    }

    var extra_env = std.ArrayList(http.fastcgi.EnvPair).init(allocator);
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
    errdefer {
        var owned = leased.stream;
        owned.close();
    }

    var fcgi = http.fastcgi.exchange(allocator, &leased.stream, .{
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
        var owned = leased.stream;
        owned.close();
        try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "FastCGI request failed", correlation_id, keep_alive, state);
        return 502;
    };
    defer fcgi.deinit();

    if (fcgi.stderr.len > 0) {
        state.logger.warn(correlation_id, "fastcgi stderr from {s}: {s}", .{ endpoint, fcgi.stderr });
    }

    if (fcgi.protocol_status != http.fastcgi.request_complete or fcgi.app_status != 0) {
        state.logger.warn(correlation_id, "fastcgi end_request failure from {s}: app_status={d} protocol_status={d}", .{ endpoint, fcgi.app_status, fcgi.protocol_status });
        var owned = leased.stream;
        owned.close();
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
    state.releaseFastcgiStream(endpoint, leased.stream, true);
    return fcgi.status;
}

fn defaultFastcgiScriptPath(
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

fn handleScgiRoute(
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

    var request_uri = std.ArrayList(u8).init(allocator);
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
    }, request.body orelse "") catch |err| {
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

fn handleUwsgiRoute(
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

    var request_uri = std.ArrayList(u8).init(allocator);
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
    }, request.body orelse "") catch |err| {
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

fn proxyGrpcExecute(
    allocator: std.mem.Allocator,
    upstream_url: []const u8,
    body: []const u8,
    correlation_id: []const u8,
    state: *GatewayState,
) ![]u8 {
    const uri = try std.Uri.parse(upstream_url);
    var header_buf: [16 * 1024]u8 = undefined;
    var headers = [_]std.http.Header{
        .{ .name = http.correlation.HEADER_NAME, .value = correlation_id },
        .{ .name = "TE", .value = "trailers" },
    };
    var req = try state.upstream_client.open(.POST, uri, .{
        .server_header_buffer = &header_buf,
        .extra_headers = headers[0..],
        .headers = .{ .content_type = .{ .override = "application/grpc" } },
        .keep_alive = true,
    });
    defer req.deinit();
    req.transfer_encoding = .{ .content_length = body.len };
    try req.send();
    try req.writeAll(body);
    try req.finish();
    try req.wait();
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try req.reader().readAllArrayList(&out, 4 * 1024 * 1024);
    return out.toOwnedSlice();
}

fn handleMailProxyRoute(
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

fn handleImapProxyRoute(
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

fn handleSmtpProxyRoute(
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
    if (std.mem.indexOfPos(u8, payload, data_start, "X-Tardigrade-Auth-Identity:")) |_| return payload;

    const header_line = try std.fmt.allocPrint(allocator, "X-Tardigrade-Auth-Identity: {s}\r\n", .{identity});
    defer allocator.free(header_line);

    if (std.mem.indexOfPos(u8, payload, data_start, "\r\n\r\n")) |_| {
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
    if (std.mem.indexOf(u8, payload, "\r\nDATA\r\n")) |idx| return idx + "\r\nDATA\r\n".len;
    return null;
}

fn executeRawProtocolRequest(allocator: std.mem.Allocator, endpoint: []const u8, payload: []const u8) ![]u8 {
    const ep = try http.memcached.parseEndpoint(endpoint);
    const stream = try std.net.tcpConnectToHost(allocator, ep.host, ep.port);
    defer stream.close();
    try setSocketTimeoutMs(stream.handle, 2_000, 2_000);
    try stream.writer().writeAll(payload);
    var out = std.ArrayList(u8).init(allocator);
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
    const stream = try std.net.tcpConnectToHost(allocator, endpoint.host, endpoint.port);
    defer stream.close();
    try setSocketTimeoutMs(stream.handle, 10_000, 10_000);
    return switch (endpoint.transport) {
        .tls => executeSmtpTlsRequest(allocator, stream, endpoint.host, payload),
        .starttls => executeSmtpStartTlsRequest(allocator, stream, endpoint.host, payload),
    };
}

fn executeImapProtocolRequest(allocator: std.mem.Allocator, endpoint: MailProxyEndpoint, payload: []const u8) ![]u8 {
    const stream = try std.net.tcpConnectToHost(allocator, endpoint.host, endpoint.port);
    defer stream.close();
    try setSocketTimeoutMs(stream.handle, 10_000, 10_000);
    return switch (endpoint.transport) {
        .tls => executeImapTlsRequest(allocator, stream, endpoint.host, payload),
        .starttls => executeImapStartTlsRequest(allocator, stream, endpoint.host, payload),
    };
}

fn executeSmtpTlsRequest(
    allocator: std.mem.Allocator,
    stream: std.net.Stream,
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
    stream: std.net.Stream,
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
    stream: std.net.Stream,
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
    stream: std.net.Stream,
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

fn readSmtpReplyPlain(allocator: std.mem.Allocator, stream: std.net.Stream) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
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

fn readSmtpReplyTls(allocator: std.mem.Allocator, tls_client: *std.crypto.tls.Client, stream: std.net.Stream) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
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

fn readImapReplyPlain(allocator: std.mem.Allocator, stream: std.net.Stream, tag: ?[]const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
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
    stream: std.net.Stream,
    tag: ?[]const u8,
) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
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
    const line_end = std.mem.indexOf(u8, payload, "\r\n") orelse payload.len;
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
    return std.mem.indexOf(u8, reply, " OK") != null or std.mem.startsWith(u8, std.mem.trim(u8, reply, " \t\r\n"), "* OK");
}

fn imapTaggedReplyContainsOk(reply: []const u8, tag: []const u8) bool {
    var it = std.mem.splitSequence(u8, reply, "\r\n");
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, tag) and line.len > tag.len and line[tag.len] == ' ') {
            return std.mem.indexOf(u8, line, " OK") != null;
        }
    }
    return false;
}

fn smtpReplyComplete(reply: []const u8) bool {
    var idx: usize = 0;
    var multiline_code: ?[]const u8 = null;
    var saw_terminal = false;
    while (idx < reply.len) {
        const line_end = std.mem.indexOfPos(u8, reply, idx, "\r\n") orelse return false;
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
    const addr = try std.net.Address.resolveIp(ep.host, ep.port);
    const sock = try std.posix.socket(addr.any.family, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    defer std.posix.close(sock);
    _ = try std.posix.sendto(sock, payload, 0, &addr.any, addr.getOsSockLen());
    var buf: [16 * 1024]u8 = undefined;
    const n = try std.posix.recv(sock, &buf, 0);
    return allocator.dupe(u8, buf[0..n]);
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

const AuthResult = struct {
    ok: bool,
    token_hash: ?[]const u8,
};

fn applyResponseHeaders(state: *GatewayState, response: *http.Response) void {
    state.security_headers.apply(response);
    for (state.add_headers) |pair| {
        _ = response.setHeader(pair.name, pair.value);
    }
    if (state.http3_alt_svc) |value| {
        _ = response.setHeader("Alt-Svc", value);
    }
}

const Http3HealthSnapshot = struct {
    handshake_state: []const u8,
    snapshot: http.http3_runtime.Snapshot,
};

const Http3DispatchContext = struct {
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

fn http3HandshakeState(state: *const GatewayState, cfg: *const edge_config.EdgeConfig, snapshot: http.http3_runtime.Snapshot) []const u8 {
    if (!cfg.http3_enabled) return "disabled";
    if (!edge_config.hasTlsFiles(cfg)) return "config_incomplete";
    if (state.http3_runtime == null) return "unavailable";
    return snapshot.handshakeState();
}

fn http3HealthSnapshot(state: *const GatewayState, cfg: *const edge_config.EdgeConfig) Http3HealthSnapshot {
    const snapshot = if (state.http3_runtime) |runtime| runtime.snapshot() else http.http3_runtime.Snapshot{ .quic_port = if (cfg.http3_enabled) cfg.quic_port else 0 };
    return .{
        .handshake_state = http3HandshakeState(state, cfg, snapshot),
        .snapshot = snapshot,
    };
}

fn populateHealthResponse(
    allocator: std.mem.Allocator,
    response: *http.Response,
    keep_alive: ?bool,
    correlation_id: []const u8,
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    http3_mode: bool,
) !void {
    const unhealthy_backends = state.upstreamUnhealthyCount();
    const http3_status = http.http3_handler.configurationStatus(cfg.http3_enabled, edge_config.hasTlsFiles(cfg));
    const http3_health = http3HealthSnapshot(state, cfg);
    const http3_last_error_name = http.ngtcp2_binding.errorName(http3_health.snapshot.last_error_code) orelse "-";
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"status\":\"ok\",\"service\":\"tardigrade-edge\",\"upstream_status\":\"{s}\",\"upstream_unhealthy_backends\":{d},\"http3_status\":\"{s}\",\"http3_quic_port\":{d},\"http3_handshake_state\":\"{s}\",\"http3_datagrams_seen\":{d},\"http3_zero_rtt_packets_seen\":{d},\"http3_tracked_connections\":{d},\"http3_native_connections\":{d},\"http3_native_reads_attempted\":{d},\"http3_native_read_calls\":{d},\"http3_handshakes_completed\":{d},\"http3_stream_bytes_received\":{d},\"http3_stream_chunks_received\":{d},\"http3_requests_completed\":{d},\"http3_packets_emitted\":{d},\"http3_bytes_emitted\":{d},\"http3_migration_events\":{d},\"http3_last_error_code\":{d},\"http3_last_error_name\":\"{s}\"}}",
        .{
            if (unhealthy_backends > 0) "degraded" else "healthy",
            unhealthy_backends,
            http3_status,
            if (cfg.http3_enabled) cfg.quic_port else 0,
            http3_health.handshake_state,
            http3_health.snapshot.datagrams_seen,
            http3_health.snapshot.zero_rtt_packets_seen,
            http3_health.snapshot.tracked_connections,
            http3_health.snapshot.native_connections,
            http3_health.snapshot.native_reads_attempted,
            http3_health.snapshot.native_read_calls,
            http3_health.snapshot.handshakes_completed,
            http3_health.snapshot.stream_bytes_received,
            http3_health.snapshot.stream_chunks_received,
            http3_health.snapshot.requests_completed,
            http3_health.snapshot.packets_emitted,
            http3_health.snapshot.bytes_emitted,
            http3_health.snapshot.migration_events,
            http3_health.snapshot.last_error_code,
            http3_last_error_name,
        },
    );
    _ = response
        .setStatus(.ok)
        .setBodyOwned(body)
        .setContentType("application/json")
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    if (keep_alive) |value| _ = response.setConnection(value);
    if (http3_mode) {
        _ = response
            .setHeader("server", http.SERVER_NAME ++ "/" ++ http.SERVER_VERSION)
            .setContentLength(body.len);
    }
    applyResponseHeaders(state, response);
}

fn finalizeHttp3Response(response: *http.Response) void {
    _ = response
        .setHeader("server", http.SERVER_NAME ++ "/" ++ http.SERVER_VERSION)
        .setContentLength(if (response.body) |body| body.len else 0);
}

fn dispatchBuiltinRouteHttp3(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    ctx: *Http3DispatchContext,
    correlation_id: []const u8,
    route: http.location_router.BuiltinRoute,
) !bool {
    switch (route) {
        .health => {
            if (!std.mem.eql(u8, request.method, "GET")) return false;
            try populateHealthResponse(allocator, response, null, correlation_id, ctx.state, ctx.cfg, true);
            ctx.state.metricsRecord(200);
            return true;
        },
        .metrics, .metrics_prometheus => {
            if (!std.mem.eql(u8, request.method, "GET")) return false;
            const prom_text = try ctx.state.metricsToPrometheus(allocator);
            _ = response
                .setStatus(.ok)
                .setBodyOwned(prom_text)
                .setContentType("text/plain; version=0.0.4; charset=utf-8")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(200);
            return true;
        },
        .metrics_json => {
            if (!std.mem.eql(u8, request.method, "GET")) return false;
            const metrics_json = try ctx.state.metricsToJson(allocator);
            _ = response
                .setStatus(.ok)
                .setBodyOwned(metrics_json)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(200);
            return true;
        },
        .admin_routes,
        .admin_connections,
        .admin_streams,
        .admin_upstreams,
        .admin_certs,
        .admin_auth_registry,
        => {
            if (!std.mem.eql(u8, request.method, "GET")) return false;
            const auth_result = authorizeRequest(ctx.cfg, &request.headers);
            if (!auth_result.ok) {
                const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
                _ = response
                    .setStatus(.unauthorized)
                    .setBodyOwned(payload)
                    .setContentType("application/json")
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(401);
                return true;
            }
            switch (route) {
                .admin_routes => {
                    _ = response
                        .setStatus(.ok)
                        .setBody(ADMIN_ROUTES_JSON)
                        .setContentType("application/json")
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                },
                .admin_connections => {
                    const counts = ctx.state.connectionCounts();
                    const body = try std.fmt.allocPrint(allocator, "{{\"active\":{d},\"tracked_ip_buckets\":{d}}}", .{ counts.active, counts.per_ip });
                    _ = response
                        .setStatus(.ok)
                        .setBodyOwned(body)
                        .setContentType("application/json")
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                },
                .admin_streams => {
                    const counts = ctx.state.streamCounts();
                    const body = try std.fmt.allocPrint(allocator, "{{\"websocket_active\":{d},\"sse_active\":{d}}}", .{ counts.ws, counts.sse });
                    _ = response
                        .setStatus(.ok)
                        .setBodyOwned(body)
                        .setContentType("application/json")
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                },
                .admin_upstreams => {
                    const body = ctx.state.upstreamHealthJson(allocator) catch try allocator.dupe(u8, "{\"upstreams\":[]}");
                    _ = response
                        .setStatus(.ok)
                        .setBodyOwned(body)
                        .setContentType("application/json")
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                },
                .admin_certs => {
                    const body = try std.fmt.allocPrint(allocator, "{{\"default_cert\":\"{s}\",\"default_key\":\"{s}\",\"sni_count\":{d}}}", .{ ctx.cfg.tls_cert_path, ctx.cfg.tls_key_path, ctx.cfg.tls_sni_certs.len });
                    _ = response
                        .setStatus(.ok)
                        .setBodyOwned(body)
                        .setContentType("application/json")
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                },
                .admin_auth_registry => {
                    const body = try std.fmt.allocPrint(allocator, "{{\"bearer_hashes\":{d},\"basic_auth_hashes\":{d},\"sessions_enabled\":{}}}", .{
                        ctx.cfg.auth_token_hashes.len,
                        ctx.cfg.basic_auth_hashes.len,
                        ctx.state.session_store != null,
                    });
                    _ = response
                        .setStatus(.ok)
                        .setBodyOwned(body)
                        .setContentType("application/json")
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                },
                else => unreachable,
            }
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(200);
            return true;
        },
        .v1_chat => {
            if (!std.mem.eql(u8, request.method, "POST")) return false;
            var prep = prepareChatRequest(allocator, ctx.cfg, ctx.state, &request.headers, request.body) catch |err| {
                const desc = describeChatPrepError(err);
                const payload = try buildApiErrorJson(allocator, desc.code, desc.message, correlation_id);
                _ = response
                    .setStatus(desc.status)
                    .setBodyOwned(payload)
                    .setContentType("application/json")
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(@intFromEnum(desc.status));
                return true;
            };
            defer prep.deinit(allocator);

            const exec = proxyJsonExecute(
                allocator,
                ctx.cfg,
                .chat,
                ctx.cfg.proxy_pass_chat,
                null,
                prep.upstream_body,
                correlation_id,
                "h3",
                prep.identity.value,
                null,
                request.headers.get("host"),
                request.headers.get("x-forwarded-for"),
                std.io.null_writer,
                ctx.state,
                false,
            ) catch |err| {
                const mapped = mapProxyExecutionError(err);
                const payload = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
                _ = response
                    .setStatus(mapped.status)
                    .setBodyOwned(payload)
                    .setContentType("application/json")
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(@intFromEnum(mapped.status));
                return true;
            };

            switch (exec) {
                .streamed_status => |status| {
                    _ = response
                        .setStatus(@enumFromInt(status))
                        .setBody("")
                        .setContentType("application/json")
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    finalizeHttp3Response(response);
                    applyResponseHeaders(ctx.state, response);
                    ctx.state.metricsRecord(status);
                    return true;
                },
                .buffered => |proxy_result| {
                    var normalized = try normalizeBufferedProxyResult(allocator, correlation_id, proxy_result);
                    defer normalized.deinit(allocator);
                    _ = response
                        .setStatus(@enumFromInt(normalized.status))
                        .setBodyOwned(try allocator.dupe(u8, normalized.body))
                        .setContentType(normalized.content_type)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    if (normalized.content_disposition) |cd| {
                        _ = response.setHeader("Content-Disposition", cd);
                    }
                    finalizeHttp3Response(response);
                    applyResponseHeaders(ctx.state, response);
                    ctx.state.metricsRecord(normalized.status);
                    return true;
                },
            }
        },
        .v1_commands => {
            if (!std.mem.eql(u8, request.method, "POST")) return false;
            var prep = prepareCommandRequest(allocator, ctx.cfg, ctx.state, &request.headers, request.body, correlation_id, "h3", null, null) catch |err| {
                const desc = describeCommandPrepError(err);
                const payload = try buildApiErrorJson(allocator, desc.code, desc.message, correlation_id);
                _ = response
                    .setStatus(desc.status)
                    .setBodyOwned(payload)
                    .setContentType("application/json")
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(@intFromEnum(desc.status));
                return true;
            };
            defer prep.deinit(allocator);

            ctx.state.commandLifecycleCreate(prep.command_id, prep.command.command_type.toString(), correlation_id, prep.identity.value) catch {};
            ctx.state.commandLifecycleSetRunning(prep.command_id);

            const exec = proxyJsonExecute(
                allocator,
                ctx.cfg,
                .commands,
                ctx.cfg.proxy_pass_commands_prefix,
                prep.upstream_path,
                prep.upstream_body,
                correlation_id,
                "h3",
                prep.identity.value,
                null,
                request.headers.get("host"),
                request.headers.get("x-forwarded-for"),
                std.io.null_writer,
                ctx.state,
                false,
            ) catch |err| {
                ctx.state.commandLifecycleSetFailed(prep.command_id, @errorName(err));
                const mapped = mapProxyExecutionError(err);
                const payload = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
                _ = response
                    .setStatus(mapped.status)
                    .setBodyOwned(payload)
                    .setContentType("application/json")
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(@intFromEnum(mapped.status));
                return true;
            };

            switch (exec) {
                .streamed_status => |status| {
                    ctx.state.commandLifecycleSetCompleted(prep.command_id, status, "", JSON_CONTENT_TYPE);
                    _ = response
                        .setStatus(@enumFromInt(status))
                        .setBody("")
                        .setContentType("application/json")
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    finalizeHttp3Response(response);
                    applyResponseHeaders(ctx.state, response);
                    ctx.state.metricsRecord(status);
                    return true;
                },
                .buffered => |proxy_result| {
                    var normalized = try normalizeBufferedProxyResult(allocator, correlation_id, proxy_result);
                    defer normalized.deinit(allocator);
                    ctx.state.commandLifecycleSetCompleted(prep.command_id, normalized.status, normalized.body, normalized.content_type);
                    _ = response
                        .setStatus(@enumFromInt(normalized.status))
                        .setBodyOwned(try allocator.dupe(u8, normalized.body))
                        .setContentType(normalized.content_type)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    if (normalized.content_disposition) |cd| {
                        _ = response.setHeader("Content-Disposition", cd);
                    }
                    finalizeHttp3Response(response);
                    applyResponseHeaders(ctx.state, response);
                    ctx.state.metricsRecord(normalized.status);
                    return true;
                },
            }
        },
        .v1_commands_status => {
            if (!std.mem.eql(u8, request.method, "GET")) return false;
            var reply = try handleCommandStatusBuiltin(allocator, ctx.cfg, ctx.state, &request.headers, splitHttp3PathAndQuery(request.path)[1], correlation_id);
            defer reply.deinit(allocator);
            _ = response
                .setStatus(reply.status)
                .setBodyOwned(reply.takeBody())
                .setContentType(JSON_CONTENT_TYPE)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(reply.status));
            return true;
        },
        .v1_approvals_request => {
            if (!std.mem.eql(u8, request.method, "POST")) return false;
            var reply = try handleApprovalsRequestBuiltin(allocator, ctx.cfg, ctx.state, &request.headers, request.body, correlation_id);
            defer reply.deinit(allocator);
            _ = response
                .setStatus(reply.status)
                .setBodyOwned(reply.takeBody())
                .setContentType(JSON_CONTENT_TYPE)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(reply.status));
            return true;
        },
        .v1_approvals_respond => {
            if (!std.mem.eql(u8, request.method, "POST")) return false;
            var reply = try handleApprovalsRespondBuiltin(allocator, ctx.cfg, ctx.state, &request.headers, request.body, correlation_id);
            defer reply.deinit(allocator);
            _ = response
                .setStatus(reply.status)
                .setBodyOwned(reply.takeBody())
                .setContentType(JSON_CONTENT_TYPE)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(reply.status));
            return true;
        },
        .v1_approvals_status => {
            if (!std.mem.eql(u8, request.method, "GET")) return false;
            var reply = try handleApprovalsStatusBuiltin(allocator, ctx.cfg, ctx.state, &request.headers, splitHttp3PathAndQuery(request.path)[1], correlation_id);
            defer reply.deinit(allocator);
            _ = response
                .setStatus(reply.status)
                .setBodyOwned(reply.takeBody())
                .setContentType(JSON_CONTENT_TYPE)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(reply.status));
            return true;
        },
        .v1_devices_register => {
            if (!std.mem.eql(u8, request.method, "POST")) return false;
            var reply = try handleDeviceRegisterBuiltin(allocator, ctx.cfg, ctx.state, &request.headers, request.body, correlation_id);
            defer reply.deinit(allocator);
            _ = response
                .setStatus(reply.status)
                .setBodyOwned(reply.takeBody())
                .setContentType(JSON_CONTENT_TYPE)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(reply.status));
            return true;
        },
        .v1_sessions_refresh => {
            if (!std.mem.eql(u8, request.method, "POST")) return false;
            var reply = try handleSessionRefreshBuiltin(allocator, ctx.cfg, ctx.state, &request.headers, "h3", correlation_id);
            defer reply.deinit(allocator);
            _ = response
                .setStatus(reply.status)
                .setBodyOwned(reply.takeBody())
                .setContentType(JSON_CONTENT_TYPE)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            if (reply.session_header) |session_header| {
                _ = response.setHeader(http.session.SESSION_HEADER, session_header);
            }
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(reply.status));
            return true;
        },
        .v1_sessions => {
            var reply = try handleSessionsBuiltin(allocator, ctx.cfg, ctx.state, request.method, &request.headers, request.body, "h3", correlation_id);
            defer reply.deinit(allocator);
            _ = response
                .setStatus(reply.status)
                .setBodyOwned(reply.takeBody())
                .setContentType(JSON_CONTENT_TYPE)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            if (reply.session_header) |session_header| {
                _ = response.setHeader(http.session.SESSION_HEADER, session_header);
            }
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(reply.status));
            return true;
        },
        .v1_cache_purge => {
            if (!std.mem.eql(u8, request.method, "POST")) return false;
            var reply = try handleCachePurgeBuiltin(allocator, ctx.cfg, ctx.state, &request.headers, request.body, correlation_id);
            defer reply.deinit(allocator);
            _ = response
                .setStatus(reply.status)
                .setBodyOwned(reply.takeBody())
                .setContentType(JSON_CONTENT_TYPE)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(reply.status));
            return true;
        },
    }
}

fn handleHttp3LocationProxyPass(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    ctx: *Http3DispatchContext,
    request_path: []const u8,
    target: []const u8,
    correlation_id: []const u8,
) !void {
    const resolved = try resolveProxyTarget(allocator, ctx.cfg.upstream_base_url, target, request_path);
    defer allocator.free(resolved.url);

    var upstream_response = try executeRawHttpProxyRequest(
        allocator,
        resolved.url,
        request.method,
        request.headers.get("content-type"),
        request.body,
        correlation_id,
    );
    defer upstream_response.deinit(allocator);

    _ = response
        .setStatus(@enumFromInt(upstream_response.status_code))
        .setBodyOwned(try allocator.dupe(u8, upstream_response.body))
        .setContentType(upstream_response.content_type)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    finalizeHttp3Response(response);
    applyResponseHeaders(ctx.state, response);
    ctx.state.metricsRecord(upstream_response.status_code);
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
        .setBodyOwned(if (std.mem.eql(u8, request.method, "HEAD")) try allocator.dupe(u8, "") else try allocator.dupe(u8, served.body))
        .setContentType(served.content_type)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    if (served.etag_value) |etag_value| _ = response.setHeader("ETag", etag_value);
    if (served.last_modified_value) |last_modified| _ = response.setHeader("Last-Modified", last_modified);
    if (served.content_range_value) |content_range| _ = response.setHeader("Content-Range", content_range);
    if (served.accept_ranges) _ = response.setHeader("Accept-Ranges", "bytes");
    _ = response
        .setHeader("server", http.SERVER_NAME ++ "/" ++ http.SERVER_VERSION)
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
    const matched = matchEffectiveLocation(ctx.cfg, request_path) orelse return .not_handled;
    switch (matched.block.action) {
        .builtin_route => |route| {
            if (try dispatchBuiltinRouteHttp3(allocator, request, response, ctx, correlation_id, route)) {
                return .handled;
            }
            return .not_handled;
        },
        .proxy_pass => |target| {
            try handleHttp3LocationProxyPass(allocator, request, response, ctx, request_path, target, correlation_id);
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
    const correlation_id = request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
    var http3_path, var http3_query = splitHttp3PathAndQuery(request.path);
    var rewrite_budget: usize = 0;
    while (rewrite_budget < 4) : (rewrite_budget += 1) {
        switch (try routeHttp3Location(allocator, request, response, ctx, http3_path, correlation_id)) {
            .handled => return,
            .not_handled => break,
            .rewritten => |rewrite_result| {
                http3_path = rewrite_result.path;
                http3_query = rewrite_result.query;
            },
        }
    }

    if (std.mem.eql(u8, request.method, "GET") and std.mem.eql(u8, http3_path, "/health")) {
        try populateHealthResponse(allocator, response, null, correlation_id, ctx.state, ctx.cfg, true);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "GET") and std.mem.eql(u8, http3_path, "/metrics")) {
        const prom_text = try ctx.state.metricsToPrometheus(allocator);
        _ = response
            .setStatus(.ok)
            .setBodyOwned(prom_text)
            .setContentType("text/plain; version=0.0.4; charset=utf-8")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "GET") and std.mem.eql(u8, http3_path, "/metrics/json")) {
        const metrics_json = try ctx.state.metricsToJson(allocator);
        _ = response
            .setStatus(.ok)
            .setBodyOwned(metrics_json)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "GET") and std.mem.eql(u8, http3_path, "/metrics/prometheus")) {
        const prom_text = try ctx.state.metricsToPrometheus(allocator);
        _ = response
            .setStatus(.ok)
            .setBodyOwned(prom_text)
            .setContentType("text/plain; version=0.0.4; charset=utf-8")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "GET") and std.mem.eql(u8, http3_path, "/admin/routes")) {
        const auth_result = authorizeRequest(ctx.cfg, &request.headers);
        if (!auth_result.ok) {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        }

        _ = response
            .setStatus(.ok)
            .setBody(ADMIN_ROUTES_JSON)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "GET") and std.mem.eql(u8, http3_path, "/admin/connections")) {
        const auth_result = authorizeRequest(ctx.cfg, &request.headers);
        if (!auth_result.ok) {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        }

        const counts = ctx.state.connectionCounts();
        const body = try std.fmt.allocPrint(allocator, "{{\"active\":{d},\"tracked_ip_buckets\":{d}}}", .{ counts.active, counts.per_ip });
        _ = response
            .setStatus(.ok)
            .setBodyOwned(body)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "GET") and std.mem.eql(u8, http3_path, "/admin/upstreams")) {
        const auth_result = authorizeRequest(ctx.cfg, &request.headers);
        if (!auth_result.ok) {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        }

        const body = ctx.state.upstreamHealthJson(allocator) catch try allocator.dupe(u8, "{\"upstreams\":[]}");
        _ = response
            .setStatus(.ok)
            .setBodyOwned(body)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "POST") and http.api_router.matchRoute(http3_path, 1, "/chat")) {
        var prep = prepareChatRequest(allocator, ctx.cfg, ctx.state, &request.headers, request.body) catch |err| {
            const payload = try buildApiErrorJson(
                allocator,
                switch (err) {
                    error.Unauthorized => "unauthorized",
                    else => "invalid_request",
                },
                switch (err) {
                    error.Unauthorized => "Unauthorized",
                    error.InvalidContentType => "Content-Type must be application/json",
                    error.MissingBody => "Missing request body",
                    error.EmptyMessage => "message must not be empty",
                    error.MessageTooLarge => "message too long",
                    else => "invalid chat payload",
                },
                correlation_id,
            );
            const status: http.Status = switch (err) {
                error.Unauthorized => .unauthorized,
                else => .bad_request,
            };
            _ = response
                .setStatus(status)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(status));
            return;
        };
        defer prep.deinit(allocator);

        const exec = proxyJsonExecute(
            allocator,
            ctx.cfg,
            .chat,
            ctx.cfg.proxy_pass_chat,
            null,
            prep.upstream_body,
            correlation_id,
            "h3",
            prep.identity.value,
            null,
            request.headers.get("host"),
            request.headers.get("x-forwarded-for"),
            std.io.null_writer,
            ctx.state,
            false,
        ) catch |err| {
            const mapped = mapProxyExecutionError(err);
            const payload = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
            _ = response
                .setStatus(mapped.status)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(mapped.status));
            return;
        };

        switch (exec) {
            .streamed_status => |status| {
                _ = response
                    .setStatus(@enumFromInt(status))
                    .setBody("")
                    .setContentType("application/json")
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(status);
                return;
            },
            .buffered => |proxy_result| {
                defer allocator.free(proxy_result.body);
                defer allocator.free(proxy_result.content_type);
                if (proxy_result.content_disposition) |cd| allocator.free(cd);

                if (proxy_result.status != 200) {
                    const mapped = mapUpstreamError(proxy_result.status);
                    const payload = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
                    _ = response
                        .setStatus(@enumFromInt(mapped.status))
                        .setBodyOwned(payload)
                        .setContentType("application/json")
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    finalizeHttp3Response(response);
                    applyResponseHeaders(ctx.state, response);
                    ctx.state.metricsRecord(mapped.status);
                    return;
                }

                const body_owned = try allocator.dupe(u8, proxy_result.body);
                _ = response
                    .setStatus(.ok)
                    .setBodyOwned(body_owned)
                    .setContentType(proxy_result.content_type)
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(200);
                return;
            },
        }
    }

    if (std.mem.eql(u8, request.method, "POST") and http.api_router.matchRoute(http3_path, 1, "/commands")) {
        var prep = prepareCommandRequest(allocator, ctx.cfg, ctx.state, &request.headers, request.body, correlation_id, "h3", null, null) catch |err| {
            const payload = try buildApiErrorJson(
                allocator,
                switch (err) {
                    error.Unauthorized => "unauthorized",
                    error.BuildUpstreamFailed => "internal_error",
                    else => "invalid_request",
                },
                switch (err) {
                    error.Unauthorized => "Unauthorized",
                    error.InvalidContentType => "Content-Type must be application/json",
                    error.MissingBody => "Missing request body",
                    error.MissingCommand => "Missing 'command' field",
                    error.UnknownCommand => "Unknown command type",
                    error.InvalidParams => "Invalid or missing 'params' object",
                    error.BuildUpstreamFailed => "Failed to build upstream request",
                    else => "Invalid command envelope",
                },
                correlation_id,
            );
            const status: http.Status = switch (err) {
                error.Unauthorized => .unauthorized,
                error.BuildUpstreamFailed => .internal_server_error,
                else => .bad_request,
            };
            _ = response
                .setStatus(status)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(status));
            return;
        };
        defer prep.deinit(allocator);

        ctx.state.commandLifecycleCreate(prep.command_id, prep.command.command_type.toString(), correlation_id, prep.identity.value) catch {};
        ctx.state.commandLifecycleSetRunning(prep.command_id);

        const exec = proxyJsonExecute(
            allocator,
            ctx.cfg,
            .commands,
            ctx.cfg.proxy_pass_commands_prefix,
            prep.upstream_path,
            prep.upstream_body,
            correlation_id,
            "h3",
            prep.identity.value,
            null,
            request.headers.get("host"),
            request.headers.get("x-forwarded-for"),
            std.io.null_writer,
            ctx.state,
            false,
        ) catch |err| {
            ctx.state.commandLifecycleSetFailed(prep.command_id, @errorName(err));
            const mapped = mapProxyExecutionError(err);
            const payload = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
            _ = response
                .setStatus(mapped.status)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(@intFromEnum(mapped.status));
            return;
        };

        switch (exec) {
            .streamed_status => |status| {
                ctx.state.commandLifecycleSetCompleted(prep.command_id, status, "", JSON_CONTENT_TYPE);
                _ = response
                    .setStatus(@enumFromInt(status))
                    .setBody("")
                    .setContentType("application/json")
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(status);
                return;
            },
            .buffered => |proxy_result| {
                defer allocator.free(proxy_result.body);
                defer allocator.free(proxy_result.content_type);
                if (proxy_result.content_disposition) |cd| allocator.free(cd);

                if (proxy_result.status != 200) {
                    const mapped = mapUpstreamError(proxy_result.status);
                    ctx.state.commandLifecycleSetCompleted(prep.command_id, mapped.status, "", JSON_CONTENT_TYPE);
                    const payload = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
                    _ = response
                        .setStatus(@enumFromInt(mapped.status))
                        .setBodyOwned(payload)
                        .setContentType("application/json")
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    finalizeHttp3Response(response);
                    applyResponseHeaders(ctx.state, response);
                    ctx.state.metricsRecord(mapped.status);
                    return;
                }

                const body_owned = try allocator.dupe(u8, proxy_result.body);
                ctx.state.commandLifecycleSetCompleted(prep.command_id, 200, proxy_result.body, proxy_result.content_type);
                _ = response
                    .setStatus(.ok)
                    .setBodyOwned(body_owned)
                    .setContentType(proxy_result.content_type)
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(200);
                return;
            },
        }
    }

    if (std.mem.eql(u8, request.method, "GET") and http.api_router.matchRoute(http3_path, 1, "/commands/status")) {
        var authenticated = false;
        const auth_result = authorizeRequest(ctx.cfg, &request.headers);
        if (auth_result.ok) authenticated = true;
        if (!authenticated) {
            if (http.session.fromHeaders(&request.headers)) |session_token| {
                if (ctx.state.validateSessionIdentity(allocator, session_token) != null) authenticated = true;
            }
        }
        if (!authenticated) {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        }

        const command_id = parseQueryParam(http3_query orelse "", "command_id") orelse {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Missing command_id", correlation_id);
            _ = response
                .setStatus(.bad_request)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(400);
            return;
        };
        const snapshot = ctx.state.commandLifecycleSnapshotJson(allocator, command_id) orelse {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Unknown command_id", correlation_id);
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

        _ = response
            .setStatus(.ok)
            .setBodyOwned(snapshot)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "POST") and http.api_router.matchRoute(http3_path, 1, "/approvals/request")) {
        var authenticated = false;
        const auth_result = authorizeRequest(ctx.cfg, &request.headers);
        if (auth_result.ok) authenticated = true;
        if (!authenticated) {
            if (http.session.fromHeaders(&request.headers)) |session_token| {
                if (ctx.state.validateSessionIdentity(allocator, session_token) != null) authenticated = true;
            }
        }
        if (!authenticated) {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        }
        if (!isJsonContentType(request.headers.get("content-type"))) {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Content-Type must be application/json", correlation_id);
            _ = response
                .setStatus(.bad_request)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(400);
            return;
        }
        var approval_req = parseApprovalRequestBody(allocator, request.body) catch {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Invalid approval request payload", correlation_id);
            _ = response
                .setStatus(.bad_request)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(400);
            return;
        };
        defer approval_req.deinit(allocator);
        if (!routeNeedsApproval(approval_req.method, approval_req.path, ctx.cfg.policy_approval_routes_raw) and
            !routeRequiresApprovalRule(approval_req.method, approval_req.path, ctx.cfg.policy_rules_raw))
        {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Route does not require approval", correlation_id);
            _ = response
                .setStatus(.bad_request)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(400);
            return;
        }
        const created = ctx.state.approvalCreate(allocator, approval_req.method, approval_req.path, auth_result.token_hash orelse "-", approval_req.command_id) catch |err| {
            const is_rate_limit = (err == error.TooManyPendingApprovals);
            const payload = if (is_rate_limit)
                try buildApiErrorJson(allocator, "too_many_requests", "Too many pending approvals for this identity", correlation_id)
            else
                try buildApiErrorJson(allocator, "internal_error", "Failed to create approval request", correlation_id);
            const status_code: http.Status = if (is_rate_limit) .too_many_requests else .internal_server_error;
            _ = response
                .setStatus(status_code)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(if (is_rate_limit) 429 else 500);
            return;
        };
        defer allocator.free(created.token);
        _ = ctx.state.event_hub.publish("approvals.requests", request.body, http.event_loop.monotonicMs()) catch 0;
        const body = try std.fmt.allocPrint(allocator, "{{\"approval_token\":\"{s}\",\"status\":\"pending\",\"expires_ms\":{d},\"status_url\":\"/v1/approvals/status?approval_token={s}\"}}", .{
            created.token,
            created.expires_ms,
            created.token,
        });
        _ = response
            .setStatus(.accepted)
            .setBodyOwned(body)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(202);
        return;
    }

    if (std.mem.eql(u8, request.method, "POST") and http.api_router.matchRoute(http3_path, 1, "/approvals/respond")) {
        const auth_result = authorizeRequest(ctx.cfg, &request.headers);
        if (!auth_result.ok) {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        }
        if (!isJsonContentType(request.headers.get("content-type"))) {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Content-Type must be application/json", correlation_id);
            _ = response
                .setStatus(.bad_request)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(400);
            return;
        }
        var approval_resp = parseApprovalResponseBody(allocator, request.body) catch {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Invalid approval response payload", correlation_id);
            _ = response
                .setStatus(.bad_request)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(400);
            return;
        };
        defer approval_resp.deinit(allocator);
        if (!ctx.state.approvalRespond(approval_resp.token, approval_resp.decision, auth_result.token_hash orelse "-")) {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Approval token not pending or not found", correlation_id);
            _ = response
                .setStatus(.conflict)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(409);
            return;
        }
        _ = ctx.state.event_hub.publish("approvals.responses", request.body, http.event_loop.monotonicMs()) catch 0;
        const body = try std.fmt.allocPrint(allocator, "{{\"approval_token\":\"{s}\",\"status\":\"{s}\"}}", .{
            approval_resp.token,
            if (approval_resp.decision == .approve) "approved" else "denied",
        });
        _ = response
            .setStatus(.ok)
            .setBodyOwned(body)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "GET") and http.api_router.matchRoute(http3_path, 1, "/approvals/status")) {
        var authenticated = false;
        const auth_result = authorizeRequest(ctx.cfg, &request.headers);
        if (auth_result.ok) authenticated = true;
        if (!authenticated) {
            if (http.session.fromHeaders(&request.headers)) |session_token| {
                if (ctx.state.validateSessionIdentity(allocator, session_token) != null) authenticated = true;
            }
        }
        if (!authenticated) {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        }
        const approval_token = parseQueryParam(http3_query orelse "", "approval_token") orelse {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Missing approval_token", correlation_id);
            _ = response
                .setStatus(.bad_request)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(400);
            return;
        };
        const snapshot = ctx.state.approvalSnapshotJson(allocator, approval_token) orelse {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Unknown approval_token", correlation_id);
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
        _ = response
            .setStatus(.ok)
            .setBodyOwned(snapshot)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "POST") and http.api_router.matchRoute(http3_path, 1, "/devices/register")) {
        if (ctx.cfg.device_registry_path.len == 0) {
            const payload = try buildApiErrorJson(allocator, "tool_unavailable", "Device registry not configured", correlation_id);
            _ = response
                .setStatus(.not_implemented)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(501);
            return;
        }

        const auth_result = authorizeRequest(ctx.cfg, &request.headers);
        if (!auth_result.ok) {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        }

        const reg = parseDeviceRegistration(allocator, request.body) catch {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Invalid device registration payload", correlation_id);
            _ = response
                .setStatus(.bad_request)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(400);
            return;
        };
        defer {
            allocator.free(reg.device_id);
            allocator.free(reg.public_key);
        }

        registerDeviceIdentity(ctx.cfg.device_registry_path, reg.device_id, reg.public_key) catch {
            const payload = try buildApiErrorJson(allocator, "internal_error", "Failed to persist device identity", correlation_id);
            _ = response
                .setStatus(.internal_server_error)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(500);
            return;
        };

        const body = try allocator.dupe(u8, "{\"registered\":true}");
        _ = response
            .setStatus(.created)
            .setBodyOwned(body)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(201);
        return;
    }

    if (std.mem.eql(u8, request.method, "POST") and http.api_router.matchRoute(http3_path, 1, "/sessions/refresh")) {
        if (ctx.state.session_store == null) {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Sessions not enabled", correlation_id);
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

        const session_token = http.session.fromHeaders(&request.headers) orelse {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Missing or invalid X-Session-Token", correlation_id);
            _ = response
                .setStatus(.bad_request)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(400);
            return;
        };

        const refreshed = ctx.state.refreshSession(allocator, session_token, "h3") catch {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Invalid session token", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        };
        defer allocator.free(refreshed);

        const body = try std.fmt.allocPrint(allocator, "{{\"session_token\":\"{s}\",\"access_ttl_seconds\":{d},\"refresh_ttl_seconds\":{d}}}", .{
            refreshed,
            ctx.cfg.access_token_ttl_seconds,
            ctx.cfg.refresh_token_ttl_seconds,
        });
        _ = response
            .setStatus(.ok)
            .setBodyOwned(body)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id)
            .setHeader(http.session.SESSION_HEADER, refreshed);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "POST") and http.api_router.matchRoute(http3_path, 1, "/sessions")) {
        if (ctx.state.session_store == null) {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Sessions not enabled", correlation_id);
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

        const auth_result = authorizeRequest(ctx.cfg, &request.headers);
        if (!auth_result.ok) {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        }

        const identity = auth_result.token_hash orelse "-";
        var device_id: ?[]const u8 = null;
        if (request.body.len > 0 and isJsonContentType(request.headers.get("content-type"))) {
            device_id = parseDeviceId(allocator, request.body) catch null;
        }
        defer if (device_id) |value| allocator.free(value);

        const session_token = ctx.state.createSession(allocator, identity, "h3", device_id) catch |err| {
            const msg = switch (err) {
                error.TooManySessions => "Too many active sessions",
                else => "Session creation failed",
            };
            const payload = try buildApiErrorJson(allocator, "rate_limited", msg, correlation_id);
            _ = response
                .setStatus(.too_many_requests)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(429);
            return;
        };
        defer allocator.free(session_token);

        const body = try std.fmt.allocPrint(allocator, "{{\"session_token\":\"{s}\"}}", .{session_token});
        _ = response
            .setStatus(.created)
            .setBodyOwned(body)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id)
            .setHeader(http.session.SESSION_HEADER, session_token);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(201);
        return;
    }

    if (std.mem.eql(u8, request.method, "DELETE") and http.api_router.matchRoute(http3_path, 1, "/sessions")) {
        if (ctx.state.session_store == null) {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Sessions not enabled", correlation_id);
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

        const session_token = http.session.fromHeaders(&request.headers) orelse {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Missing or invalid X-Session-Token", correlation_id);
            _ = response
                .setStatus(.bad_request)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(400);
            return;
        };

        const revoked = ctx.state.revokeSession(session_token);
        const body = if (revoked)
            try allocator.dupe(u8, "{\"revoked\":true}")
        else
            try allocator.dupe(u8, "{\"revoked\":false}");
        _ = response
            .setStatus(.ok)
            .setBodyOwned(body)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "GET") and http.api_router.matchRoute(http3_path, 1, "/sessions")) {
        if (ctx.state.session_store == null) {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Sessions not enabled", correlation_id);
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

        const auth_result = authorizeRequest(ctx.cfg, &request.headers);
        if (!auth_result.ok) {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        }

        const identity = auth_result.token_hash orelse "-";
        const active_sessions = ctx.state.countSessionsByIdentity(allocator, identity) catch {
            const payload = try buildApiErrorJson(allocator, "internal_error", "Failed to list sessions", correlation_id);
            _ = response
                .setStatus(.internal_server_error)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(500);
            return;
        };

        const body = try std.fmt.allocPrint(allocator, "{{\"active_sessions\":{d}}}", .{active_sessions});
        _ = response
            .setStatus(.ok)
            .setBodyOwned(body)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
    }

    if (std.mem.eql(u8, request.method, "POST") and http.api_router.matchRoute(http3_path, 1, "/cache/purge")) {
        if (ctx.state.proxy_cache_store == null) {
            const payload = try buildApiErrorJson(allocator, "invalid_request", "Proxy cache not enabled", correlation_id);
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

        const auth_result = authorizeRequest(ctx.cfg, &request.headers);
        if (!auth_result.ok) {
            const payload = try buildApiErrorJson(allocator, "unauthorized", "Unauthorized", correlation_id);
            _ = response
                .setStatus(.unauthorized)
                .setBodyOwned(payload)
                .setContentType("application/json")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(401);
            return;
        }

        var purged: usize = 0;
        if (request.body.len > 0) {
            if (isJsonContentType(request.headers.get("content-type"))) {
                if (parseCachePurgeKey(allocator, request.body)) |key| {
                    defer allocator.free(key);
                    purged = if (ctx.state.proxyCacheDelete(key)) 1 else 0;
                } else |_| {
                    purged = ctx.state.proxyCachePurgeAll();
                }
            } else {
                purged = ctx.state.proxyCachePurgeAll();
            }
        } else {
            purged = ctx.state.proxyCachePurgeAll();
        }

        const body = try std.fmt.allocPrint(allocator, "{{\"purged\":{d}}}", .{purged});
        _ = response
            .setStatus(.ok)
            .setBodyOwned(body)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(200);
        return;
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
    if (std.mem.indexOfScalar(u8, path, '?')) |idx| {
        return .{ path[0..idx], path[idx + 1 ..] };
    }
    return .{ path, null };
}

fn handleHttp3Request(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    user_data: ?*anyopaque,
) !void {
    const ctx: *Http3DispatchContext = @ptrCast(@alignCast(user_data orelse return error.InvalidArgument));
    const authority = request.headers.get(":authority") orelse request.headers.get("host");
    var effective_cfg_storage = ctx.cfg.*;
    const effective_cfg = resolveRequestConfig(ctx.cfg, authority, &effective_cfg_storage) orelse {
        const correlation_id = request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
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
        const correlation_id = request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
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

fn authorizeRequest(cfg: *const edge_config.EdgeConfig, headers: *const http.Headers) AuthResult {
    if (cfg.jwt_secret.len > 0) {
        if (http.auth.authorize(headers, null)) |token| {
            const claims = http.jwt.validateHs256(std.heap.page_allocator, token, .{
                .secret = cfg.jwt_secret,
                .required_issuer = if (cfg.jwt_issuer.len > 0) cfg.jwt_issuer else null,
                .required_audience = if (cfg.jwt_audience.len > 0) cfg.jwt_audience else null,
            }) catch null;
            if (claims != null) {
                return .{ .ok = true, .token_hash = "jwt" };
            }
        } else |_| {}
    }

    // Try bearer token auth first
    if (cfg.auth_token_hashes.len > 0) {
        if (http.auth.authorize(headers, null)) |token| {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});

            var digest_hex: [64]u8 = undefined;
            _ = std.fmt.bufPrint(&digest_hex, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch return .{ .ok = false, .token_hash = null };

            for (cfg.auth_token_hashes) |allowed| {
                if (allowed.len == 64 and std.crypto.utils.timingSafeEql([64]u8, allowed[0..64].*, digest_hex)) return .{ .ok = true, .token_hash = allowed };
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

fn shouldBypassProxyCache(headers: *const http.Headers) bool {
    if (headers.get("x-proxy-cache-bypass")) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(trimmed, "1") or std.ascii.eqlIgnoreCase(trimmed, "true") or std.ascii.eqlIgnoreCase(trimmed, "yes")) {
            return true;
        }
    }

    if (headers.get("pragma")) |pragma| {
        if (std.ascii.indexOfIgnoreCase(pragma, "no-cache") != null) return true;
    }

    if (headers.get("cache-control")) |cache_control| {
        var it = std.mem.splitScalar(u8, cache_control, ',');
        while (it.next()) |part| {
            const token = std.mem.trim(u8, part, " \t\r\n");
            if (std.ascii.eqlIgnoreCase(token, "no-cache") or std.ascii.eqlIgnoreCase(token, "no-store")) return true;
            if (std.ascii.startsWithIgnoreCase(token, "max-age=")) {
                const val = std.mem.trim(u8, token["max-age=".len..], " \t\r\n");
                if (std.mem.eql(u8, val, "0")) return true;
            }
        }
    }
    return false;
}

fn isGeoBlocked(blocked: []const []const u8, country: ?[]const u8) bool {
    const code = country orelse return false;
    const trimmed = std.mem.trim(u8, code, " \t\r\n");
    if (trimmed.len == 0) return false;
    for (blocked) |entry| {
        if (std.ascii.eqlIgnoreCase(entry, trimmed)) return true;
    }
    return false;
}

fn isProtectedAuthRequestRoute(path: []const u8) bool {
    return http.api_router.matchRoute(path, 1, "/chat") or
        http.api_router.matchRoute(path, 1, "/commands") or
        http.api_router.matchRoute(path, 1, "/approvals/request") or
        http.api_router.matchRoute(path, 1, "/approvals/respond") or
        http.api_router.matchRoute(path, 1, "/approvals/status") or
        http.api_router.matchRoute(path, 1, "/sessions") or
        http.api_router.matchRoute(path, 1, "/cache/purge") or
        http.api_router.matchRoute(path, 1, "/events/stream") or
        http.api_router.matchRoute(path, 1, "/events/publish") or
        http.api_router.matchRoute(path, 1, "/ws/chat") or
        http.api_router.matchRoute(path, 1, "/ws/commands") or
        http.api_router.matchRoute(path, 1, "/subrequest") or
        http.api_router.matchRoute(path, 1, "/backend/fastcgi") or
        http.api_router.matchRoute(path, 1, "/backend/uwsgi") or
        http.api_router.matchRoute(path, 1, "/backend/scgi") or
        http.api_router.matchRoute(path, 1, "/backend/grpc") or
        http.api_router.matchRoute(path, 1, "/backend/memcached") or
        http.api_router.matchRoute(path, 1, "/mail/smtp") or
        http.api_router.matchRoute(path, 1, "/mail/imap") or
        http.api_router.matchRoute(path, 1, "/mail/pop3") or
        http.api_router.matchRoute(path, 1, "/stream/tcp") or
        http.api_router.matchRoute(path, 1, "/stream/udp") or
        std.mem.startsWith(u8, path, "/admin/");
}

fn resolveRequestConfig(base_cfg: *const edge_config.EdgeConfig, raw_host: ?[]const u8, out: *edge_config.EdgeConfig) ?*const edge_config.EdgeConfig {
    out.* = base_cfg.*;
    if (base_cfg.server_blocks.len > 0) {
        const block = selectServerBlock(base_cfg, raw_host) orelse return null;
        if (block.server_names.len > 0 and !hostMatchesPatterns(block.server_names, raw_host)) return null;
        out.server_names = block.server_names;
        if (block.doc_root.len > 0) out.doc_root = block.doc_root;
        if (block.try_files.len > 0) out.try_files = block.try_files;
        if (block.location_blocks.len > 0) out.location_blocks = block.location_blocks;
        if (block.tls_cert_path.len > 0) out.tls_cert_path = block.tls_cert_path;
        if (block.tls_key_path.len > 0) out.tls_key_path = block.tls_key_path;
        if (block.upstream_base_url.len > 0) out.upstream_base_url = block.upstream_base_url;
        if (block.proxy_pass_chat.len > 0) out.proxy_pass_chat = block.proxy_pass_chat;
        if (block.proxy_pass_commands_prefix.len > 0) out.proxy_pass_commands_prefix = block.proxy_pass_commands_prefix;
        return out;
    }
    if (!hostMatchesPatterns(base_cfg.server_names, raw_host)) return null;
    return out;
}

fn selectServerBlock(cfg: *const edge_config.EdgeConfig, raw_host: ?[]const u8) ?*const edge_config.EdgeConfig.ServerBlock {
    var default_block: ?*const edge_config.EdgeConfig.ServerBlock = null;
    for (cfg.server_blocks) |*block| {
        if (block.server_names.len == 0 and default_block == null) default_block = block;
        if (hostMatchesPatterns(block.server_names, raw_host)) return block;
    }
    return default_block orelse if (cfg.server_blocks.len > 0) &cfg.server_blocks[0] else null;
}

fn hostMatchesServerNames(cfg: *const edge_config.EdgeConfig, request: *const http.Request) bool {
    return hostMatchesPatterns(cfg.server_names, request.headers.get("host"));
}

fn hostMatchesPatterns(patterns: []const []const u8, raw_host: ?[]const u8) bool {
    if (patterns.len == 0) return true;
    const host = stripHostPort(raw_host orelse return false);
    for (patterns) |pattern| {
        if (matchHostPattern(pattern, host)) return true;
    }
    return false;
}

fn stripHostPort(raw_host: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw_host, " \t\r\n");
    if (trimmed.len == 0) return trimmed;
    if (trimmed[0] == '[') {
        const end = std.mem.indexOfScalar(u8, trimmed, ']') orelse return trimmed;
        return trimmed[1..end];
    }
    const colon = std.mem.lastIndexOfScalar(u8, trimmed, ':') orelse return trimmed;
    const head = trimmed[0..colon];
    if (std.mem.indexOfScalar(u8, head, ':') != null) return trimmed;
    return head;
}

fn hostPort(raw_host: []const u8) ?u16 {
    const trimmed = std.mem.trim(u8, raw_host, " \t\r\n");
    if (trimmed.len == 0) return null;
    if (trimmed[0] == '[') {
        const end = std.mem.indexOfScalar(u8, trimmed, ']') orelse return null;
        if (end + 1 >= trimmed.len or trimmed[end + 1] != ':') return null;
        return std.fmt.parseInt(u16, trimmed[end + 2 ..], 10) catch null;
    }
    const colon = std.mem.lastIndexOfScalar(u8, trimmed, ':') orelse return null;
    const head = trimmed[0..colon];
    if (std.mem.indexOfScalar(u8, head, ':') != null) return null;
    return std.fmt.parseInt(u16, trimmed[colon + 1 ..], 10) catch null;
}

fn matchHostPattern(pattern_raw: []const u8, host: []const u8) bool {
    const pattern = std.mem.trim(u8, pattern_raw, " \t");
    if (pattern.len == 0) return false;
    if (pattern[0] == '~') {
        return http.rewrite.regexMatches(pattern[1..], host);
    }
    if (std.mem.startsWith(u8, pattern, "*.")) {
        const suffix = pattern[1..];
        return std.mem.endsWith(u8, host, suffix);
    }
    return std.ascii.eqlIgnoreCase(pattern, host);
}

const ApprovalRequestBody = struct {
    method: []u8,
    path: []u8,
    command_id: ?[]u8,

    fn deinit(self: *ApprovalRequestBody, allocator: std.mem.Allocator) void {
        allocator.free(self.method);
        allocator.free(self.path);
        if (self.command_id) |cid| allocator.free(cid);
        self.* = undefined;
    }
};

const ApprovalResponsePayload = struct {
    token: []u8,
    decision: ApprovalDecision,

    fn deinit(self: *ApprovalResponsePayload, allocator: std.mem.Allocator) void {
        allocator.free(self.token);
        self.* = undefined;
    }
};

const DeviceRegistration = struct {
    device_id: []const u8,
    public_key: []const u8,
};

fn parseApprovalRequestBody(allocator: std.mem.Allocator, body: []const u8) !ApprovalRequestBody {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidApprovalRequest;
    const obj = parsed.value.object;
    const method_val = obj.get("method") orelse return error.InvalidApprovalRequest;
    const path_val = obj.get("path") orelse return error.InvalidApprovalRequest;
    if (method_val != .string or path_val != .string) return error.InvalidApprovalRequest;
    const method = std.mem.trim(u8, method_val.string, " \t\r\n");
    const path = std.mem.trim(u8, path_val.string, " \t\r\n");
    if (method.len == 0 or path.len == 0) return error.InvalidApprovalRequest;
    var command_id: ?[]u8 = null;
    if (obj.get("command_id")) |cid_val| {
        if (cid_val == .string) {
            const cid = std.mem.trim(u8, cid_val.string, " \t\r\n");
            if (cid.len > 0) command_id = try allocator.dupe(u8, cid);
        }
    }
    return .{
        .method = try allocator.dupe(u8, method),
        .path = try allocator.dupe(u8, path),
        .command_id = command_id,
    };
}

fn parseApprovalResponseBody(allocator: std.mem.Allocator, body: []const u8) !ApprovalResponsePayload {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidApprovalResponse;
    const obj = parsed.value.object;
    const token_val = obj.get("approval_token") orelse return error.InvalidApprovalResponse;
    const decision_val = obj.get("decision") orelse return error.InvalidApprovalResponse;
    if (token_val != .string or decision_val != .string) return error.InvalidApprovalResponse;
    const token = std.mem.trim(u8, token_val.string, " \t\r\n");
    const decision_raw = std.mem.trim(u8, decision_val.string, " \t\r\n");
    if (token.len == 0 or decision_raw.len == 0) return error.InvalidApprovalResponse;
    const decision = if (std.ascii.eqlIgnoreCase(decision_raw, "approve"))
        ApprovalDecision.approve
    else if (std.ascii.eqlIgnoreCase(decision_raw, "deny"))
        ApprovalDecision.deny
    else
        return error.InvalidApprovalResponse;
    return .{
        .token = try allocator.dupe(u8, token),
        .decision = decision,
    };
}

fn parseDeviceRegistration(allocator: std.mem.Allocator, body: []const u8) !DeviceRegistration {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return error.InvalidDeviceRegistration;
    const obj = root.object;
    const did_val = obj.get("device_id") orelse return error.InvalidDeviceRegistration;
    const pk_val = obj.get("public_key") orelse return error.InvalidDeviceRegistration;
    if (did_val != .string or pk_val != .string) return error.InvalidDeviceRegistration;
    const device_id = std.mem.trim(u8, did_val.string, " \t\r\n");
    const public_key = std.mem.trim(u8, pk_val.string, " \t\r\n");
    if (device_id.len == 0 or public_key.len == 0) return error.InvalidDeviceRegistration;
    return .{
        .device_id = try allocator.dupe(u8, device_id),
        .public_key = try allocator.dupe(u8, public_key),
    };
}

fn registerDeviceIdentity(path: []const u8, device_id: []const u8, public_key: []const u8) !void {
    var file = std.fs.cwd().openFile(path, .{ .mode = .read_write }) catch try std.fs.cwd().createFile(path, .{ .truncate = false, .read = true });
    defer file.close();
    try file.seekFromEnd(0);
    try file.writer().print("{s}|{s}\n", .{ device_id, public_key });
}

fn loadRegisteredDeviceKey(allocator: std.mem.Allocator, registry_path: []const u8, device_id: []const u8) ?[]const u8 {
    const raw = std.fs.cwd().readFileAlloc(allocator, registry_path, 2 * 1024 * 1024) catch return null;
    defer allocator.free(raw);
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r\n");
        if (line.len == 0) continue;
        const sep = std.mem.indexOfScalar(u8, line, '|') orelse continue;
        const did = std.mem.trim(u8, line[0..sep], " \t");
        const key = std.mem.trim(u8, line[sep + 1 ..], " \t");
        if (std.mem.eql(u8, did, device_id)) return allocator.dupe(u8, key) catch null;
    }
    return null;
}

fn validateDeviceRequest(
    cfg: *const edge_config.EdgeConfig,
    method: []const u8,
    path: []const u8,
    headers: *const http.Headers,
    body: []const u8,
) bool {
    if (cfg.device_registry_path.len == 0) return false;
    const device_id = headers.get("x-device-id") orelse return false;
    const ts_str = headers.get("x-device-timestamp") orelse return false;
    const provided_sig = headers.get("x-device-signature") orelse return false;
    const ts = std.fmt.parseInt(i64, ts_str, 10) catch return false;
    const now = std.time.timestamp();
    const delta = if (now > ts) now - ts else ts - now;
    if (delta > 300) return false;

    const allocator = std.heap.page_allocator;
    const key = loadRegisteredDeviceKey(allocator, cfg.device_registry_path, device_id) orelse return false;
    defer allocator.free(key);
    const signed = std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n{s}\n{s}", .{ key, method, path, ts_str, body }) catch return false;
    defer allocator.free(signed);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(signed, &digest, .{});
    var digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&digest_hex, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch return false;
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, provided_sig, " \t\r\n"), digest_hex[0..]);
}

fn extractIdentityForPolicy(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    request: *const http.Request,
) !?[]const u8 {
    const auth_res = authorizeRequest(cfg, &request.headers);
    if (auth_res.ok and auth_res.token_hash != null) {
        const identity = try allocator.dupe(u8, auth_res.token_hash.?);
        return identity;
    }
    if (http.session.fromHeaders(&request.headers)) |session_token| {
        if (state.validateSessionIdentity(allocator, session_token)) |identity| return identity;
    }
    return null;
}

fn approvalPolicyError(state: *GatewayState, method: []const u8, path: []const u8, identity: ?[]const u8, headers: *const http.Headers) ?[]const u8 {
    const approval = headers.get("x-approval-token") orelse return "Approval required";
    const token = std.mem.trim(u8, approval, " \t\r\n");
    if (token.len == 0) return "Approval required";
    return switch (state.approvalValidate(token, method, path, identity)) {
        .approved => null,
        .pending => "Approval pending",
        .denied => "Approval denied",
        .escalated => "Approval timed out and escalated",
        .invalid => "Invalid approval token",
        .missing => "Approval required",
    };
}

fn evaluatePolicy(
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    method: []const u8,
    path: []const u8,
    identity: ?[]const u8,
    device_id: ?[]const u8,
    headers: *const http.Headers,
) ?[]const u8 {
    if (http.api_router.matchRoute(path, 1, "/approvals/request") or
        http.api_router.matchRoute(path, 1, "/approvals/respond") or
        http.api_router.matchRoute(path, 1, "/approvals/status"))
    {
        return null;
    }
    if (cfg.policy_approval_routes_raw.len > 0 and routeNeedsApproval(method, path, cfg.policy_approval_routes_raw)) {
        if (approvalPolicyError(state, method, path, identity, headers)) |reason| return reason;
    }
    if (cfg.policy_rules_raw.len == 0) return null;
    var rules = std.mem.splitScalar(u8, cfg.policy_rules_raw, ';');
    while (rules.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        var parts = std.mem.splitScalar(u8, entry, '|');
        const rule_method = std.mem.trim(u8, parts.next() orelse "", " \t");
        const rule_pattern = std.mem.trim(u8, parts.next() orelse "", " \t");
        const req_scope = std.mem.trim(u8, parts.next() orelse "", " \t");
        const req_approval = std.mem.trim(u8, parts.next() orelse "false", " \t");
        const allowed_hours = std.mem.trim(u8, parts.next() orelse "", " \t");
        const device_pattern = std.mem.trim(u8, parts.next() orelse "", " \t");
        if (rule_method.len == 0 or rule_pattern.len == 0) continue;
        if (!http.rewrite.methodMatches(rule_method, method)) continue;
        if (!http.rewrite.regexMatches(rule_pattern, path)) continue;

        if (req_scope.len > 0 and !identityHasScope(cfg.policy_user_scopes_raw, identity, req_scope)) return "Missing required scope";
        if (std.ascii.eqlIgnoreCase(req_approval, "true")) {
            if (approvalPolicyError(state, method, path, identity, headers)) |reason| return reason;
        }
        if (allowed_hours.len > 0 and !timeWindowAllows(allowed_hours)) return "Route not allowed at this time";
        if (device_pattern.len > 0) {
            const did = device_id orelse return "Device restriction denied";
            if (!http.rewrite.regexMatches(device_pattern, did)) return "Device restriction denied";
        }
    }
    return null;
}

fn routeRequiresApprovalRule(method: []const u8, path: []const u8, policy_rules_raw: []const u8) bool {
    if (policy_rules_raw.len == 0) return false;
    var rules = std.mem.splitScalar(u8, policy_rules_raw, ';');
    while (rules.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        var parts = std.mem.splitScalar(u8, entry, '|');
        const rule_method = std.mem.trim(u8, parts.next() orelse "", " \t");
        const rule_pattern = std.mem.trim(u8, parts.next() orelse "", " \t");
        _ = parts.next(); // scope
        const req_approval = std.mem.trim(u8, parts.next() orelse "false", " \t");
        if (rule_method.len == 0 or rule_pattern.len == 0) continue;
        if (!http.rewrite.methodMatches(rule_method, method)) continue;
        if (!http.rewrite.regexMatches(rule_pattern, path)) continue;
        if (std.ascii.eqlIgnoreCase(req_approval, "true")) return true;
    }
    return false;
}

fn routeNeedsApproval(method: []const u8, path: []const u8, raw: []const u8) bool {
    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        var parts = std.mem.splitScalar(u8, entry, '|');
        const rm = std.mem.trim(u8, parts.next() orelse "", " \t");
        const rp = std.mem.trim(u8, parts.next() orelse "", " \t");
        if (rm.len == 0 or rp.len == 0) continue;
        if (http.rewrite.methodMatches(rm, method) and http.rewrite.regexMatches(rp, path)) return true;
    }
    return false;
}

fn identityHasScope(scopes_raw: []const u8, identity: ?[]const u8, required: []const u8) bool {
    if (identity == null) return false;
    var it = std.mem.splitScalar(u8, scopes_raw, ';');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, entry, ':') orelse continue;
        const id = std.mem.trim(u8, entry[0..colon], " \t");
        if (!std.mem.eql(u8, id, identity.?)) continue;
        var s_it = std.mem.splitScalar(u8, entry[colon + 1 ..], ',');
        while (s_it.next()) |scope| {
            if (std.mem.eql(u8, std.mem.trim(u8, scope, " \t"), required)) return true;
        }
    }
    return false;
}

fn timeWindowAllows(raw: []const u8) bool {
    const dash = std.mem.indexOfScalar(u8, raw, '-') orelse return true;
    const start = std.fmt.parseInt(u8, std.mem.trim(u8, raw[0..dash], " \t"), 10) catch return true;
    const stop = std.fmt.parseInt(u8, std.mem.trim(u8, raw[dash + 1 ..], " \t"), 10) catch return true;
    const now = std.time.timestamp();
    const hour = @as(u8, @intCast(@mod(@divFloor(now, 3600), 24)));
    if (start <= stop) return hour >= start and hour < stop;
    return hour >= start or hour < stop;
}

fn authorizeViaSubrequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    request: *const http.Request,
    correlation_id: []const u8,
    client_ip: []const u8,
) bool {
    if (cfg.auth_request_url.len == 0) return true;
    const uri = std.Uri.parse(cfg.auth_request_url) catch return false;
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var header_buf: [4 * 1024]u8 = undefined;
    var headers_buf: [8]std.http.Header = undefined;
    var header_count: usize = 0;
    headers_buf[header_count] = .{ .name = "X-Original-Method", .value = request.method.toString() };
    header_count += 1;
    headers_buf[header_count] = .{ .name = "X-Original-URI", .value = request.uri.path };
    header_count += 1;
    headers_buf[header_count] = .{ .name = "X-Client-IP", .value = client_ip };
    header_count += 1;
    headers_buf[header_count] = .{ .name = http.correlation.HEADER_NAME, .value = correlation_id };
    header_count += 1;
    if (request.headers.get("authorization")) |authz| {
        headers_buf[header_count] = .{ .name = "Authorization", .value = authz };
        header_count += 1;
    }
    if (request.headers.get(http.session.SESSION_HEADER)) |session_token| {
        headers_buf[header_count] = .{ .name = http.session.SESSION_HEADER, .value = session_token };
        header_count += 1;
    }

    var req = client.open(.GET, uri, .{
        .server_header_buffer = &header_buf,
        .extra_headers = headers_buf[0..header_count],
    }) catch return false;
    defer req.deinit();
    req.send() catch return false;
    req.finish() catch return false;
    req.wait() catch return false;
    const status = @intFromEnum(req.response.status);
    return status >= 200 and status < 300;
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

fn parseCachePurgeKey(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    const key_val = obj.get("key") orelse return error.NoPurgeKey;
    if (key_val != .string) return error.NoPurgeKey;
    const key = std.mem.trim(u8, key_val.string, " \t\r\n");
    if (key.len == 0) return error.NoPurgeKey;
    return try allocator.dupe(u8, key);
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

fn buildProxyCacheKey(
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
    _ = std.fmt.bufPrint(&payload_digest_hex, "{s}", .{std.fmt.fmtSliceHexLower(&payload_digest)}) catch unreachable;

    const identity_value = identity orelse "-";
    var api_version_buf: [20]u8 = undefined;
    const api_version_value = if (api_version) |ver|
        std.fmt.bufPrint(&api_version_buf, "{d}", .{ver}) catch "-"
    else
        "-";

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
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
        if (wrote_any) try out.append(':');
        try out.appendSlice(value);
        wrote_any = true;
    }

    if (!wrote_any) {
        try out.appendSlice(method);
        try out.append(':');
        try out.appendSlice(path);
        try out.append(':');
        try out.appendSlice(payload_digest_hex[0..]);
    }
    return out.toOwnedSlice();
}

fn proxyCacheFilePath(allocator: std.mem.Allocator, cache_path: []const u8, key: []const u8) ![]u8 {
    var key_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key, &key_digest, .{});
    var key_digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&key_digest_hex, "{s}", .{std.fmt.fmtSliceHexLower(&key_digest)}) catch unreachable;
    return std.fmt.allocPrint(allocator, "{s}/{s}.cache", .{ cache_path, key_digest_hex[0..] });
}

fn proxyCacheWriteToDisk(cache_path: []const u8, key: []const u8, status: u16, body: []const u8, content_type: []const u8) !void {
    if (cache_path.len == 0) return;
    std.fs.cwd().makePath(cache_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const allocator = std.heap.page_allocator;
    const file_path = try proxyCacheFilePath(allocator, cache_path, key);
    defer allocator.free(file_path);

    const file = try std.fs.cwd().createFile(file_path, .{ .truncate = true, .read = true });
    defer file.close();
    var writer = file.writer();
    try writer.print("{d}\n{d}\n{s}\n\n", .{ status, std.time.nanoTimestamp(), content_type });
    try writer.writeAll(body);
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

    const raw = std.fs.cwd().readFileAlloc(allocator, file_path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(raw);

    const l1 = std.mem.indexOfScalar(u8, raw, '\n') orelse return null;
    const l2 = std.mem.indexOfScalarPos(u8, raw, l1 + 1, '\n') orelse return null;
    const l3 = std.mem.indexOfScalarPos(u8, raw, l2 + 1, '\n') orelse return null;
    if (l3 + 1 >= raw.len or raw[l3 + 1] != '\n') return null;
    const body_start = l3 + 2;

    const status = std.fmt.parseInt(u16, std.mem.trim(u8, raw[0..l1], " \t\r\n"), 10) catch return null;
    const created_ns = std.fmt.parseInt(i128, std.mem.trim(u8, raw[l1 + 1 .. l2], " \t\r\n"), 10) catch return null;
    const ct_slice = std.mem.trim(u8, raw[l2 + 1 .. l3], " \t\r\n");
    const now_ns = std.time.nanoTimestamp();
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
    std.fs.cwd().deleteFile(file_path) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return false,
    };
    return true;
}

fn proxyCachePurgeDisk(cache_path: []const u8) usize {
    if (cache_path.len == 0) return 0;
    var dir = std.fs.cwd().openDir(cache_path, .{ .iterate = true }) catch return 0;
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

const ProxyResult = struct {
    status: u16,
    body: []u8,
    content_type: []u8,
    content_disposition: ?[]u8,
    cacheable: bool,
};

const ProxyExecution = union(enum) {
    streamed_status: u16,
    buffered: ProxyResult,
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

    const exec = proxyJsonExecute(
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
    ) catch return;

    switch (exec) {
        .streamed_status => |_| {},
        .buffered => |result| {
            defer task.allocator.free(result.body);
            defer task.allocator.free(result.content_type);
            if (result.content_disposition) |cd| task.allocator.free(cd);
            if (result.status == 200) {
                task.state.proxyCachePut(task.cache_key, result.status, result.body, result.content_type) catch {};
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

fn proxyJsonExecute(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    upstream_scope: UpstreamScope,
    proxy_pass_target: []const u8,
    suffix_path: ?[]const u8,
    payload: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    auth_identity: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
    downstream_writer: anytype,
    state: *GatewayState,
    enable_streaming_success: bool,
) !ProxyExecution {
    const upstream_pool = upstreamPoolForScope(cfg, upstream_scope);
    const configured_attempts: usize = @intCast(@max(cfg.upstream_retry_attempts, @as(u32, 1)));
    const max_attempts = configured_attempts;
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

        const upstream_base_url = state.nextUpstreamBaseUrl(cfg, upstream_pool, client_ip, upstream_hash_key);
        state.recordUpstreamAttemptStart(upstream_base_url);
        const exec = blk: {
            defer state.recordUpstreamAttemptEnd(upstream_base_url);
            break :blk proxyJsonExecuteSingleAttempt(
                allocator,
                cfg,
                per_attempt_timeout_ms,
                upstream_base_url,
                proxy_pass_target,
                suffix_path,
                payload,
                correlation_id,
                client_ip,
                auth_identity,
                api_version,
                incoming_host,
                incoming_x_forwarded_for,
                downstream_writer,
                state,
                enable_streaming_success,
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
            .streamed_status => |status| {
                if (status >= 500) {
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

fn proxyJsonExecuteSingleAttempt(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    attempt_timeout_ms: u32,
    upstream_base_url: []const u8,
    proxy_pass_target: []const u8,
    suffix_path: ?[]const u8,
    payload: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    auth_identity: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
    downstream_writer: anytype,
    state: *GatewayState,
    enable_streaming_success: bool,
) !ProxyExecution {
    const resolved_target = try resolveProxyTarget(allocator, upstream_base_url, proxy_pass_target, suffix_path);
    var current_url = resolved_target.url;
    defer allocator.free(current_url);
    var current_unix_socket_path = resolved_target.unix_socket_path;
    var redirects_followed: u8 = 0;

    const forwarded_for = try buildForwardedFor(allocator, incoming_x_forwarded_for, client_ip);
    defer allocator.free(forwarded_for);

    const forwarded_host = incoming_host orelse "";
    const forwarded_proto = if (edge_config.hasTlsFiles(cfg)) "https" else "http";
    const upstream_host = resolved_target.upstream_host;
    if (cfg.trust_require_upstream_identity and cfg.trust_shared_secret.len == 0) return error.UpstreamUntrusted;
    if (!isTrustedUpstream(cfg, upstream_host)) return error.UpstreamUntrusted;

    var extra_headers = std.ArrayList(std.http.Header).init(allocator);
    defer extra_headers.deinit();
    var owned_header_values = std.ArrayList([]u8).init(allocator);
    defer {
        for (owned_header_values.items) |value| allocator.free(value);
        owned_header_values.deinit();
    }
    try extra_headers.append(.{ .name = http.correlation.HEADER_NAME, .value = correlation_id });
    try extra_headers.append(.{ .name = "X-Forwarded-For", .value = forwarded_for });
    try extra_headers.append(.{ .name = "X-Real-IP", .value = client_ip });
    try extra_headers.append(.{ .name = "X-Forwarded-Proto", .value = forwarded_proto });
    if (cfg.upstream_gunzip_enabled) {
        try extra_headers.append(.{ .name = "Accept-Encoding", .value = "gzip, identity" });
    }
    if (forwarded_host.len > 0) try extra_headers.append(.{ .name = "X-Forwarded-Host", .value = forwarded_host });
    if (upstream_host.len > 0) try extra_headers.append(.{ .name = "Host", .value = upstream_host });
    if (auth_identity) |identity| {
        if (identity.len > 0) try extra_headers.append(.{ .name = "X-Tardigrade-Auth-Identity", .value = identity });
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

    while (true) {
        var server_header_buffer: [16 * 1024]u8 = undefined;
        const uri = try std.Uri.parse(current_url);
        const unix_conn: ?*std.http.Client.Connection = if (current_unix_socket_path) |socket_path|
            try state.upstream_client.connectUnix(socket_path)
        else
            null;
        var req = try state.upstream_client.open(.POST, uri, .{
            .server_header_buffer = &server_header_buffer,
            .connection = unix_conn,
            .headers = .{ .content_type = .{ .override = "application/json" } },
            .extra_headers = extra_headers.items,
            .keep_alive = true,
            .redirect_behavior = .unhandled,
        });
        defer req.deinit();

        if (attempt_timeout_ms > 0) {
            if (req.connection) |conn| {
                setSocketTimeoutMs(conn.stream.handle, attempt_timeout_ms, attempt_timeout_ms) catch |err| {
                    state.logger.warn(null, "failed to set upstream socket timeout: {}", .{err});
                };
            }
        }

        req.transfer_encoding = .{ .content_length = payload.len };
        try req.send();
        try req.writeAll(payload);
        try req.finish();
        try req.wait();

        const status_code: u16 = @intFromEnum(req.response.status);
        if (redirects_followed == 0 and isRedirectStatusCode(status_code)) {
            if (req.response.location) |location| {
                const drain_buf = try state.relay_buffer_pool.acquire();
                defer state.relay_buffer_pool.release(drain_buf);
                while (true) {
                    const n = try req.reader().read(drain_buf);
                    if (n == 0) break;
                }
                const next_url = try resolveRedirectTargetUrl(allocator, current_url, location);
                allocator.free(current_url);
                current_url = next_url;
                current_unix_socket_path = null;
                redirects_followed += 1;
                continue;
            }
        }

        const upstream_content_type = req.response.content_type orelse JSON_CONTENT_TYPE;
        const upstream_content_disposition = req.response.content_disposition;
        const cacheable = !upstreamResponseHasNoStore(req.response);
        const stream_status = enable_streaming_success and (status_code == 200 or cfg.proxy_stream_all_statuses);
        if (stream_status) {
            try writeStreamedUpstreamResponse(
                downstream_writer,
                status_code,
                req.response.reason,
                upstream_content_type,
                upstream_content_disposition,
                correlation_id,
                &state.security_headers,
            );

            const read_buf = try state.relay_buffer_pool.acquire();
            defer state.relay_buffer_pool.release(read_buf);
            while (true) {
                const n = try req.reader().read(read_buf);
                if (n == 0) break;
                try writeChunk(downstream_writer, read_buf[0..n]);
            }
            try downstream_writer.writeAll("0\r\n\r\n");
            return .{ .streamed_status = status_code };
        }

        if (status_code != 200) {
            const buffered_content_type = try allocator.dupe(u8, upstream_content_type);
            errdefer allocator.free(buffered_content_type);
            const buffered_content_disposition = if (upstream_content_disposition) |cd|
                try allocator.dupe(u8, cd)
            else
                null;
            errdefer if (buffered_content_disposition) |cd| allocator.free(cd);

            const drain_buf = try state.relay_buffer_pool.acquire();
            defer state.relay_buffer_pool.release(drain_buf);
            while (true) {
                const n = try req.reader().read(drain_buf);
                if (n == 0) break;
            }
            return .{
                .buffered = .{
                    .status = status_code,
                    .body = try allocator.alloc(u8, 0),
                    .content_type = buffered_content_type,
                    .content_disposition = buffered_content_disposition,
                    .cacheable = false,
                },
            };
        }

        const max_buffered = if (cfg.max_connection_memory_bytes > 0)
            cfg.max_connection_memory_bytes
        else
            2 * 1024 * 1024;
        var body = std.ArrayList(u8).init(allocator);
        errdefer body.deinit();
        try req.reader().readAllArrayList(&body, max_buffered);
        const buffered_content_type = try allocator.dupe(u8, upstream_content_type);
        errdefer allocator.free(buffered_content_type);
        const buffered_content_disposition = if (upstream_content_disposition) |cd|
            try allocator.dupe(u8, cd)
        else
            null;
        errdefer if (buffered_content_disposition) |cd| allocator.free(cd);
        return .{
            .buffered = .{
                .status = status_code,
                .body = try body.toOwnedSlice(),
                .content_type = buffered_content_type,
                .content_disposition = buffered_content_disposition,
                .cacheable = cacheable,
            },
        };
    }
}

fn writeStreamedUpstreamResponse(
    writer: anytype,
    status_code: u16,
    reason: []const u8,
    content_type: []const u8,
    content_disposition: ?[]const u8,
    correlation_id: []const u8,
    security: *const http.security_headers.SecurityHeaders,
) !void {
    const phrase = if (reason.len > 0)
        reason
    else
        (@as(std.http.Status, @enumFromInt(status_code)).phrase() orelse "");

    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ status_code, phrase });
    try writer.print("Server: {s}/{s}\r\n", .{ http.SERVER_NAME, http.SERVER_VERSION });
    try writer.writeAll("Connection: close\r\n");
    try writer.writeAll("Transfer-Encoding: chunked\r\n");
    try writer.print("Content-Type: {s}\r\n", .{content_type});
    try writer.print("{s}: {s}\r\n", .{ http.correlation.HEADER_NAME, correlation_id });
    if (content_disposition) |cd| {
        try writer.print("Content-Disposition: {s}\r\n", .{cd});
    }

    try writeSecurityHeaders(writer, security);
    try writer.writeAll("\r\n");
}

fn writeSecurityHeaders(writer: anytype, sec: *const http.security_headers.SecurityHeaders) !void {
    if (sec.x_frame_options.len > 0) try writer.print("X-Frame-Options: {s}\r\n", .{sec.x_frame_options});
    if (sec.x_content_type_options.len > 0) try writer.print("X-Content-Type-Options: {s}\r\n", .{sec.x_content_type_options});
    if (sec.content_security_policy.len > 0) try writer.print("Content-Security-Policy: {s}\r\n", .{sec.content_security_policy});
    if (sec.strict_transport_security.len > 0) try writer.print("Strict-Transport-Security: {s}\r\n", .{sec.strict_transport_security});
    if (sec.referrer_policy.len > 0) try writer.print("Referrer-Policy: {s}\r\n", .{sec.referrer_policy});
    if (sec.permissions_policy.len > 0) try writer.print("Permissions-Policy: {s}\r\n", .{sec.permissions_policy});
    if (sec.x_xss_protection.len > 0) try writer.print("X-XSS-Protection: {s}\r\n", .{sec.x_xss_protection});
}

fn writeChunk(writer: anytype, bytes: []const u8) !void {
    try writer.print("{x}\r\n", .{bytes.len});
    try writer.writeAll(bytes);
    try writer.writeAll("\r\n");
}

fn stripPort(authority: []const u8) []const u8 {
    if (authority.len == 0) return authority;
    if (authority[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, authority, ']') orelse return authority;
        return authority[0 .. close_idx + 1];
    }
    const colon_idx = std.mem.lastIndexOfScalar(u8, authority, ':') orelse return authority;
    return authority[0..colon_idx];
}

fn isTrustedUpstream(cfg: *const edge_config.EdgeConfig, upstream_host: []const u8) bool {
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

fn appendTrustedUpstreamHeaders(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    extra_headers: *std.ArrayList(std.http.Header),
    owned_header_values: *std.ArrayList([]u8),
    target_url: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    auth_identity: ?[]const u8,
    api_version: ?u32,
    payload: []const u8,
) !void {
    if (cfg.trust_shared_secret.len == 0) return;

    const ts = std.time.timestamp();
    const ts_value = try std.fmt.allocPrint(allocator, "{d}", .{ts});
    try owned_header_values.append(ts_value);
    try extra_headers.append(.{ .name = "X-Tardigrade-Gateway-Id", .value = cfg.trust_gateway_id });
    try extra_headers.append(.{ .name = "X-Tardigrade-Trust-Timestamp", .value = ts_value });

    var payload_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &payload_digest, .{});
    var payload_digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&payload_digest_hex, "{s}", .{std.fmt.fmtSliceHexLower(&payload_digest)}) catch unreachable;

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
    const signature_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&mac)});
    try owned_header_values.append(signature_hex);
    try extra_headers.append(.{ .name = "X-Tardigrade-Trust-Signature", .value = signature_hex });
}

fn buildForwardedFor(allocator: std.mem.Allocator, incoming: ?[]const u8, client_ip: []const u8) ![]const u8 {
    if (incoming) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) {
            return std.fmt.allocPrint(allocator, "{s}, {s}", .{ trimmed, client_ip });
        }
    }
    return allocator.dupe(u8, client_ip);
}

fn upstreamResponseHasNoStore(response: std.http.Client.Response) bool {
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

const ResolvedProxyTarget = struct {
    url: []u8,
    upstream_host: []const u8,
    unix_socket_path: ?[]const u8 = null,
};

fn isRedirectStatusCode(status_code: u16) bool {
    return switch (status_code) {
        301, 302, 303, 307, 308 => true,
        else => false,
    };
}

fn resolveProxyTarget(
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

fn resolveRedirectTargetUrl(allocator: std.mem.Allocator, current_url: []const u8, location: []const u8) ![]u8 {
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

fn unixSocketPathFromEndpoint(endpoint: []const u8) ?[]const u8 {
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

fn combineProxyTarget(allocator: std.mem.Allocator, target: []const u8, suffix_path: ?[]const u8) ![]u8 {
    if (suffix_path == null) return allocator.dupe(u8, target);

    const suffix = suffix_path.?;
    const left_trimmed = std.mem.trimRight(u8, target, "/");
    const right_trimmed = std.mem.trimLeft(u8, suffix, "/");

    if (left_trimmed.len == 0) {
        return std.fmt.allocPrint(allocator, "/{s}", .{right_trimmed});
    }

    if (right_trimmed.len == 0) {
        return allocator.dupe(u8, left_trimmed);
    }

    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ left_trimmed, right_trimmed });
}

fn isAbsoluteHttpUrl(value: []const u8) bool {
    return std.mem.startsWith(u8, value, "http://") or std.mem.startsWith(u8, value, "https://");
}

fn parseUpstreamHost(base_url: []const u8) ?[]const u8 {
    const scheme_end = std.mem.indexOf(u8, base_url, "://") orelse return null;
    const authority_start = scheme_end + 3;
    if (authority_start >= base_url.len) return null;

    const path_start = std.mem.indexOfScalarPos(u8, base_url, authority_start, '/') orelse base_url.len;
    if (path_start <= authority_start) return null;
    return base_url[authority_start..path_start];
}

const UpstreamMappedError = struct {
    status: u16,
    code: []const u8,
    message: []const u8,
};

const ProxyExecMappedError = struct {
    status: http.Status,
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

fn mapProxyExecutionError(err: anyerror) ProxyExecMappedError {
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
    applyResponseHeaders(state, &response);
    try response.write(writer);
    state.metricsRecord(@intFromEnum(status));
    state.metricsRecordErrorCode(code);
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
        .error_category = classifyErrorCategory(status),
    };
    entry.log();
}

fn classifyErrorCategory(status: u16) []const u8 {
    return if (status < 400)
        "-"
    else if (status == 400 or status == 413 or status == 414)
        "invalid_request"
    else if (status == 401 or status == 403)
        "authz"
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

fn readHttpRequest(conn: anytype, buf: []u8, pending_len: *usize) !usize {
    var total_read = pending_len.*;

    while (total_read <= buf.len) {
        if (firstRequestCompleteLen(buf[0..total_read])) |request_len| {
            pending_len.* = total_read;
            return @min(total_read, request_len);
        }
        if (total_read == buf.len) break;

        const n = conn.read(buf[total_read..]) catch |err| return err;
        if (n == 0) break;
        total_read += n;
    }

    pending_len.* = total_read;
    return total_read;
}

fn firstRequestCompleteLen(data: []const u8) ?usize {
    const header_pos = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return null;
    const headers_len = header_pos + 4;
    const content_length = parseContentLength(data[0..headers_len]) orelse 0;
    const full_len = headers_len + content_length;
    if (data.len >= full_len) return full_len;
    return null;
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

test "buildForwardedFor appends client ip" {
    const allocator = std.testing.allocator;
    const value = try buildForwardedFor(allocator, "10.0.0.1, 10.0.0.2", "127.0.0.1");
    defer allocator.free(value);
    try std.testing.expectEqualStrings("10.0.0.1, 10.0.0.2, 127.0.0.1", value);
}

test "parseUpstreamHost extracts authority" {
    try std.testing.expectEqualStrings("127.0.0.1:8080", parseUpstreamHost("http://127.0.0.1:8080") orelse "");
    try std.testing.expectEqualStrings("api.example.com", parseUpstreamHost("https://api.example.com/v1") orelse "");
    try std.testing.expect(parseUpstreamHost("invalid-url") == null);
}

test "buildHealthProbeUrl joins base and probe path" {
    const allocator = std.testing.allocator;
    const url = try http.health_checker.buildProbeUrl(allocator, "http://127.0.0.1:8080/", "/health");
    defer allocator.free(url);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/health", url);
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

test "parse proxy protocol v1 header extracts source ip" {
    var ip_buf: [64]u8 = undefined;
    const header = "PROXY TCP4 203.0.113.9 10.0.0.5 443 8080\r\nGET / HTTP/1.1\r\n\r\n";
    const parsed = parseProxyHeader(header, .v1, &ip_buf);
    switch (parsed) {
        .parsed => |result| {
            try std.testing.expectEqual(@as(usize, 42), result.consumed);
            try std.testing.expectEqualStrings("203.0.113.9", ip_buf[0..result.client_ip_len]);
        },
        else => return error.UnexpectedTestResult,
    }
}

test "parse proxy protocol auto mode ignores non-proxy preface" {
    var ip_buf: [64]u8 = undefined;
    const header = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";
    const parsed = parseProxyHeader(header, .auto, &ip_buf);
    try std.testing.expect(parsed == .no_header);
}

test "parse proxy protocol v2 header extracts source ip" {
    var ip_buf: [64]u8 = undefined;
    const header = [_]u8{
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
        0x21, 0x11, 0x00, 0x0c, 203,  0,    113,  44,   10,   0,    0,    2,
        0x01, 0xbb, 0x1f, 0x90,
    };
    const parsed = parseProxyHeader(header[0..], .v2, &ip_buf);
    switch (parsed) {
        .parsed => |result| {
            try std.testing.expectEqual(@as(usize, 28), result.consumed);
            try std.testing.expectEqualStrings("203.0.113.44", ip_buf[0..result.client_ip_len]);
        },
        else => return error.UnexpectedTestResult,
    }
}

test "firstRequestCompleteLen detects pipelined boundary" {
    const pipelined =
        "GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n" ++
        "GET /two HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const first_len = firstRequestCompleteLen(pipelined).?;
    try std.testing.expectEqual(@as(usize, 38), first_len);
}

test "firstRequestCompleteLen waits for complete body" {
    const partial = "POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhel";
    try std.testing.expect(firstRequestCompleteLen(partial) == null);

    const complete = "POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(@as(usize, complete.len), firstRequestCompleteLen(complete).?);
}

test "firstRequestCompleteLen handles keep-alive pipelined requests" {
    const reqs =
        "GET /a HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n" ++
        "GET /b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const first_len = firstRequestCompleteLen(reqs).?;
    const first = reqs[0..first_len];
    try std.testing.expect(std.mem.indexOf(u8, first, "GET /a") != null);
    try std.testing.expect(std.mem.indexOf(u8, first, "keep-alive") != null);
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

test "combineProxyTarget joins prefix and suffix" {
    const allocator = std.testing.allocator;
    const joined = try combineProxyTarget(allocator, "/api", "/v1/chat");
    defer allocator.free(joined);
    try std.testing.expectEqualStrings("/api/v1/chat", joined);
}

test "resolveProxyTarget handles absolute and relative proxy_pass" {
    const allocator = std.testing.allocator;
    const cfg = edge_config.EdgeConfig{
        .listen_host = "0.0.0.0",
        .listen_port = 8069,
        .tls_cert_path = "",
        .tls_key_path = "",
        .tls_min_version = "1.2",
        .tls_max_version = "1.3",
        .tls_cipher_list = "",
        .tls_cipher_suites = "",
        .tls_sni_certs = &[_]edge_config.EdgeConfig.TlsSniCert{},
        .tls_session_cache_enabled = true,
        .tls_session_cache_size = 20_480,
        .tls_session_timeout_seconds = 300,
        .tls_session_tickets_enabled = true,
        .tls_ocsp_stapling_enabled = false,
        .tls_ocsp_response_path = "",
        .tls_client_ca_path = "",
        .tls_client_verify = false,
        .tls_client_verify_depth = 3,
        .tls_crl_path = "",
        .tls_crl_check = false,
        .tls_dynamic_reload_interval_ms = 5000,
        .tls_acme_enabled = false,
        .tls_acme_cert_dir = "",
        .http2_enabled = true,
        .http3_enabled = false,
        .quic_port = 443,
        .http3_enable_0rtt = false,
        .http3_connection_migration = false,
        .http3_max_datagram_size = 1350,
        .proxy_protocol_mode = .off,
        .trust_gateway_id = "tardigrade-edge",
        .trust_shared_secret = "",
        .trusted_upstream_identities = &[_][]const u8{},
        .trust_require_upstream_identity = false,
        .upstream_base_url = "http://127.0.0.1:8080",
        .upstream_base_urls = &[_][]const u8{},
        .upstream_base_url_weights = &[_]u32{},
        .upstream_backup_base_urls = &[_][]const u8{},
        .upstream_chat_base_urls = &[_][]const u8{},
        .upstream_chat_base_url_weights = &[_]u32{},
        .upstream_chat_backup_base_urls = &[_][]const u8{},
        .upstream_commands_base_urls = &[_][]const u8{},
        .upstream_commands_base_url_weights = &[_]u32{},
        .upstream_commands_backup_base_urls = &[_][]const u8{},
        .upstream_lb_algorithm = .round_robin,
        .proxy_pass_chat = "/v1/chat",
        .proxy_pass_commands_prefix = "",
        .auth_token_hashes = &[_][]const u8{},
        .max_message_chars = 4000,
        .upstream_timeout_ms = 10000,
        .rate_limit_rps = 0,
        .rate_limit_burst = 0,
        .security_headers_enabled = false,
        .idempotency_ttl_seconds = 0,
        .proxy_cache_ttl_seconds = 0,
        .proxy_cache_path = "",
        .proxy_cache_key_template = "method:path:payload_sha256",
        .proxy_cache_stale_while_revalidate_seconds = 0,
        .proxy_cache_lock_timeout_ms = 250,
        .proxy_cache_manager_interval_ms = 30_000,
        .geo_blocked_countries = &[_][]const u8{},
        .geo_country_header = "CF-IPCountry",
        .auth_request_url = "",
        .auth_request_timeout_ms = 2000,
        .jwt_secret = "",
        .jwt_issuer = "",
        .jwt_audience = "",
        .add_headers = &[_]edge_config.EdgeConfig.HeaderPair{},
        .policy_rules_raw = "",
        .policy_user_scopes_raw = "",
        .policy_approval_routes_raw = "",
        .session_ttl_seconds = 0,
        .session_max = 0,
        .device_registry_path = "",
        .device_auth_required = false,
        .access_token_ttl_seconds = 900,
        .refresh_token_ttl_seconds = 86_400,
        .access_control_rules = "",
        .request_limits = http.request_limits.RequestLimits.default,
        .basic_auth_hashes = &[_][]const u8{},
        .log_level = .info,
        .error_log_path = "",
        .pid_file = "",
        .run_user = "",
        .run_group = "",
        .chroot_dir = "",
        .require_unprivileged_user = false,
        .server_names = &[_][]const u8{},
        .doc_root = "",
        .try_files = "",
        .access_log_format = .json,
        .access_log_template = "",
        .access_log_min_status = 0,
        .access_log_buffer_size = 0,
        .access_log_syslog_udp = "",
        .compression_enabled = false,
        .compression_min_size = 256,
        .compression_brotli_enabled = true,
        .compression_brotli_quality = 5,
        .upstream_gunzip_enabled = true,
        .cb_threshold = 0,
        .cb_timeout_ms = 30_000,
        .worker_threads = 0,
        .master_process_enabled = false,
        .worker_processes = 1,
        .binary_upgrade_enabled = true,
        .worker_recycle_seconds = 0,
        .worker_cpu_affinity = "",
        .worker_queue_size = 1024,
        .fd_soft_limit = 0,
        .max_connections_per_ip = 0,
        .max_active_connections = 0,
        .keep_alive_timeout_ms = 5000,
        .max_requests_per_connection = 100,
        .connection_pool_size = 256,
        .max_connection_memory_bytes = 2 * 1024 * 1024,
        .max_total_connection_memory_bytes = 0,
        .proxy_stream_all_statuses = false,
        .upstream_retry_attempts = 1,
        .upstream_timeout_budget_ms = 0,
        .upstream_max_fails = 0,
        .upstream_fail_timeout_ms = 10_000,
        .upstream_active_health_interval_ms = 0,
        .upstream_active_health_path = "/health",
        .upstream_active_health_timeout_ms = 2000,
        .upstream_active_health_fail_threshold = 1,
        .upstream_active_health_success_threshold = 1,
        .upstream_active_health_success_status = .{ .min = 200, .max = 299 },
        .upstream_active_health_success_status_overrides = &[_]edge_config.EdgeConfig.UpstreamHealthSuccessStatusOverride{},
        .upstream_slow_start_ms = 0,
        .websocket_enabled = true,
        .websocket_idle_timeout_ms = 60_000,
        .websocket_max_frame_size = 1024 * 1024,
        .websocket_ping_interval_ms = 15_000,
        .sse_enabled = true,
        .sse_max_events_per_topic = 1024,
        .sse_poll_interval_ms = 250,
        .sse_max_backlog = 1024,
        .sse_idle_timeout_ms = 60_000,
        .rewrite_rules = &[_]edge_config.EdgeConfig.RewriteRule{},
        .return_rules = &[_]edge_config.EdgeConfig.ReturnRule{},
        .conditional_rules = &[_]edge_config.EdgeConfig.ConditionalRule{},
        .location_blocks = &[_]edge_config.EdgeConfig.LocationBlock{},
        .internal_redirect_rules = &[_]edge_config.EdgeConfig.InternalRedirectRule{},
        .named_locations = &[_]edge_config.EdgeConfig.NamedLocation{},
        .mirror_rules = &[_]edge_config.EdgeConfig.MirrorRule{},
        .fastcgi_upstream = "",
        .fastcgi_params = &[_]edge_config.EdgeConfig.HeaderPair{},
        .fastcgi_index = "index.php",
        .uwsgi_upstream = "",
        .scgi_upstream = "",
        .grpc_upstream = "",
        .memcached_upstream = "",
        .smtp_upstream = "",
        .imap_upstream = "",
        .pop3_upstream = "",
        .tcp_proxy_upstream = "",
        .udp_proxy_upstream = "",
        .stream_ssl_termination = false,
        .approval_store_path = "",
        .approval_ttl_ms = 300_000,
        .approval_escalation_webhook = "",
        .approval_max_pending_per_identity = 10,
    };

    const abs = try resolveProxyTarget(allocator, cfg.upstream_base_url, "https://api.example.com/base", "/v1/chat");
    defer allocator.free(abs.url);
    try std.testing.expectEqualStrings("https://api.example.com/base/v1/chat", abs.url);
    try std.testing.expectEqualStrings("api.example.com", abs.upstream_host);

    const rel = try resolveProxyTarget(allocator, cfg.upstream_base_url, "/gateway", "/v1/tools");
    defer allocator.free(rel.url);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/gateway/v1/tools", rel.url);
    try std.testing.expectEqualStrings("127.0.0.1:8080", rel.upstream_host);
}

test "builtin location blocks cover core routes" {
    const blocks = buildBuiltinLocationBlocks(&edge_config.EdgeConfig{
        .listen_host = "0.0.0.0",
        .listen_port = 8069,
        .tls_cert_path = "",
        .tls_key_path = "",
        .tls_min_version = "1.2",
        .tls_max_version = "1.3",
        .tls_cipher_list = "",
        .tls_cipher_suites = "",
        .tls_sni_certs = &[_]edge_config.EdgeConfig.TlsSniCert{},
        .tls_session_cache_enabled = true,
        .tls_session_cache_size = 20_480,
        .tls_session_timeout_seconds = 300,
        .tls_session_tickets_enabled = true,
        .tls_ocsp_stapling_enabled = false,
        .tls_ocsp_response_path = "",
        .tls_client_ca_path = "",
        .tls_client_verify = false,
        .tls_client_verify_depth = 3,
        .tls_crl_path = "",
        .tls_crl_check = false,
        .tls_dynamic_reload_interval_ms = 5000,
        .tls_acme_enabled = false,
        .tls_acme_cert_dir = "",
        .http2_enabled = true,
        .http3_enabled = false,
        .quic_port = 443,
        .http3_enable_0rtt = false,
        .http3_connection_migration = false,
        .http3_max_datagram_size = 1350,
        .proxy_protocol_mode = .off,
        .trust_gateway_id = "tardigrade-edge",
        .trust_shared_secret = "",
        .trusted_upstream_identities = &[_][]const u8{},
        .trust_require_upstream_identity = false,
        .upstream_base_url = "http://127.0.0.1:8080",
        .upstream_base_urls = &[_][]const u8{},
        .upstream_base_url_weights = &[_]u32{},
        .upstream_backup_base_urls = &[_][]const u8{},
        .upstream_chat_base_urls = &[_][]const u8{},
        .upstream_chat_base_url_weights = &[_]u32{},
        .upstream_chat_backup_base_urls = &[_][]const u8{},
        .upstream_commands_base_urls = &[_][]const u8{},
        .upstream_commands_base_url_weights = &[_]u32{},
        .upstream_commands_backup_base_urls = &[_][]const u8{},
        .upstream_lb_algorithm = .round_robin,
        .proxy_pass_chat = "/v1/chat",
        .proxy_pass_commands_prefix = "",
        .auth_token_hashes = &[_][]const u8{},
        .max_message_chars = 4000,
        .upstream_timeout_ms = 10000,
        .rate_limit_rps = 0,
        .rate_limit_burst = 0,
        .security_headers_enabled = false,
        .idempotency_ttl_seconds = 0,
        .proxy_cache_ttl_seconds = 0,
        .proxy_cache_path = "",
        .proxy_cache_key_template = "method:path:payload_sha256",
        .proxy_cache_stale_while_revalidate_seconds = 0,
        .proxy_cache_lock_timeout_ms = 250,
        .proxy_cache_manager_interval_ms = 30_000,
        .geo_blocked_countries = &[_][]const u8{},
        .geo_country_header = "CF-IPCountry",
        .auth_request_url = "",
        .auth_request_timeout_ms = 2000,
        .jwt_secret = "",
        .jwt_issuer = "",
        .jwt_audience = "",
        .add_headers = &[_]edge_config.EdgeConfig.HeaderPair{},
        .policy_rules_raw = "",
        .policy_user_scopes_raw = "",
        .policy_approval_routes_raw = "",
        .session_ttl_seconds = 0,
        .session_max = 0,
        .device_registry_path = "",
        .device_auth_required = false,
        .access_token_ttl_seconds = 900,
        .refresh_token_ttl_seconds = 86_400,
        .access_control_rules = "",
        .request_limits = http.request_limits.RequestLimits.default,
        .basic_auth_hashes = &[_][]const u8{},
        .log_level = .info,
        .error_log_path = "",
        .pid_file = "",
        .run_user = "",
        .run_group = "",
        .chroot_dir = "",
        .require_unprivileged_user = false,
        .server_names = &[_][]const u8{},
        .doc_root = "",
        .try_files = "",
        .access_log_format = .json,
        .access_log_template = "",
        .access_log_min_status = 0,
        .access_log_buffer_size = 0,
        .access_log_syslog_udp = "",
        .compression_enabled = false,
        .compression_min_size = 256,
        .compression_brotli_enabled = true,
        .compression_brotli_quality = 5,
        .upstream_gunzip_enabled = true,
        .cb_threshold = 0,
        .cb_timeout_ms = 30_000,
        .worker_threads = 0,
        .master_process_enabled = false,
        .worker_processes = 1,
        .binary_upgrade_enabled = true,
        .worker_recycle_seconds = 0,
        .worker_cpu_affinity = "",
        .worker_queue_size = 1024,
        .fd_soft_limit = 0,
        .max_connections_per_ip = 0,
        .max_active_connections = 0,
        .keep_alive_timeout_ms = 5000,
        .max_requests_per_connection = 100,
        .connection_pool_size = 256,
        .max_connection_memory_bytes = 2 * 1024 * 1024,
        .max_total_connection_memory_bytes = 0,
        .proxy_stream_all_statuses = false,
        .upstream_retry_attempts = 1,
        .upstream_timeout_budget_ms = 0,
        .upstream_max_fails = 0,
        .upstream_fail_timeout_ms = 10_000,
        .upstream_active_health_interval_ms = 0,
        .upstream_active_health_path = "/health",
        .upstream_active_health_timeout_ms = 2000,
        .upstream_active_health_fail_threshold = 1,
        .upstream_active_health_success_threshold = 1,
        .upstream_active_health_success_status = .{ .min = 200, .max = 299 },
        .upstream_active_health_success_status_overrides = &[_]edge_config.EdgeConfig.UpstreamHealthSuccessStatusOverride{},
        .upstream_slow_start_ms = 0,
        .websocket_enabled = true,
        .websocket_idle_timeout_ms = 60_000,
        .websocket_max_frame_size = 1024 * 1024,
        .websocket_ping_interval_ms = 15_000,
        .sse_enabled = true,
        .sse_max_events_per_topic = 1024,
        .sse_poll_interval_ms = 250,
        .sse_max_backlog = 1024,
        .sse_idle_timeout_ms = 60_000,
        .rewrite_rules = &[_]edge_config.EdgeConfig.RewriteRule{},
        .return_rules = &[_]edge_config.EdgeConfig.ReturnRule{},
        .conditional_rules = &[_]edge_config.EdgeConfig.ConditionalRule{},
        .location_blocks = &[_]edge_config.EdgeConfig.LocationBlock{},
        .internal_redirect_rules = &[_]edge_config.EdgeConfig.InternalRedirectRule{},
        .named_locations = &[_]edge_config.EdgeConfig.NamedLocation{},
        .mirror_rules = &[_]edge_config.EdgeConfig.MirrorRule{},
        .fastcgi_upstream = "",
        .fastcgi_params = &[_]edge_config.EdgeConfig.HeaderPair{},
        .fastcgi_index = "index.php",
        .uwsgi_upstream = "",
        .scgi_upstream = "",
        .grpc_upstream = "",
        .memcached_upstream = "",
        .smtp_upstream = "",
        .imap_upstream = "",
        .pop3_upstream = "",
        .tcp_proxy_upstream = "",
        .udp_proxy_upstream = "",
        .stream_ssl_termination = false,
        .approval_store_path = "",
        .approval_ttl_ms = 300_000,
        .approval_escalation_webhook = "",
        .approval_max_pending_per_identity = 10,
    });

    const health = http.location_router.matchLocation("/health", blocks[0..]).?;
    const chat = http.location_router.matchLocation("/v1/chat", blocks[0..]).?;
    switch (health.block.action) {
        .builtin_route => |route| try std.testing.expectEqual(http.location_router.BuiltinRoute.health, route),
        else => return error.UnexpectedTestResult,
    }
    switch (chat.block.action) {
        .builtin_route => |route| try std.testing.expectEqual(http.location_router.BuiltinRoute.v1_chat, route),
        else => return error.UnexpectedTestResult,
    }
}

test "resolveProxyTarget supports unix socket upstream base" {
    const allocator = std.testing.allocator;
    const resolved = try resolveProxyTarget(allocator, "unix:/tmp/tardigrade.sock", "/gateway", "/v1/chat");
    defer allocator.free(resolved.url);
    try std.testing.expectEqualStrings("http://localhost/gateway/v1/chat", resolved.url);
    try std.testing.expectEqualStrings("/tmp/tardigrade.sock", resolved.upstream_host);
    try std.testing.expect(resolved.unix_socket_path != null);
    try std.testing.expectEqualStrings("/tmp/tardigrade.sock", resolved.unix_socket_path.?);
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
        .tls_min_version = "1.2",
        .tls_max_version = "1.3",
        .tls_cipher_list = "",
        .tls_cipher_suites = "",
        .tls_sni_certs = &[_]edge_config.EdgeConfig.TlsSniCert{},
        .tls_session_cache_enabled = true,
        .tls_session_cache_size = 20_480,
        .tls_session_timeout_seconds = 300,
        .tls_session_tickets_enabled = true,
        .tls_ocsp_stapling_enabled = false,
        .tls_ocsp_response_path = "",
        .tls_client_ca_path = "",
        .tls_client_verify = false,
        .tls_client_verify_depth = 3,
        .tls_crl_path = "",
        .tls_crl_check = false,
        .tls_dynamic_reload_interval_ms = 5000,
        .tls_acme_enabled = false,
        .tls_acme_cert_dir = "",
        .http2_enabled = true,
        .http3_enabled = false,
        .quic_port = 443,
        .http3_enable_0rtt = false,
        .http3_connection_migration = false,
        .http3_max_datagram_size = 1350,
        .proxy_protocol_mode = .off,
        .trust_gateway_id = "tardigrade-edge",
        .trust_shared_secret = "",
        .trusted_upstream_identities = &[_][]const u8{},
        .trust_require_upstream_identity = false,
        .upstream_base_url = "http://127.0.0.1:8080",
        .upstream_base_urls = &[_][]const u8{},
        .upstream_base_url_weights = &[_]u32{},
        .upstream_backup_base_urls = &[_][]const u8{},
        .upstream_chat_base_urls = &[_][]const u8{},
        .upstream_chat_base_url_weights = &[_]u32{},
        .upstream_chat_backup_base_urls = &[_][]const u8{},
        .upstream_commands_base_urls = &[_][]const u8{},
        .upstream_commands_base_url_weights = &[_]u32{},
        .upstream_commands_backup_base_urls = &[_][]const u8{},
        .upstream_lb_algorithm = .round_robin,
        .proxy_pass_chat = "/v1/chat",
        .proxy_pass_commands_prefix = "",
        .auth_token_hashes = hashes,
        .max_message_chars = 4000,
        .upstream_timeout_ms = 10000,
        .rate_limit_rps = 0,
        .rate_limit_burst = 0,
        .security_headers_enabled = false,
        .idempotency_ttl_seconds = 0,
        .proxy_cache_ttl_seconds = 0,
        .proxy_cache_path = "",
        .proxy_cache_key_template = "method:path:payload_sha256",
        .proxy_cache_stale_while_revalidate_seconds = 0,
        .proxy_cache_lock_timeout_ms = 250,
        .proxy_cache_manager_interval_ms = 30_000,
        .geo_blocked_countries = &[_][]const u8{},
        .geo_country_header = "CF-IPCountry",
        .auth_request_url = "",
        .auth_request_timeout_ms = 2000,
        .jwt_secret = "",
        .jwt_issuer = "",
        .jwt_audience = "",
        .add_headers = &[_]edge_config.EdgeConfig.HeaderPair{},
        .policy_rules_raw = "",
        .policy_user_scopes_raw = "",
        .policy_approval_routes_raw = "",
        .session_ttl_seconds = 0,
        .session_max = 0,
        .device_registry_path = "",
        .device_auth_required = false,
        .access_token_ttl_seconds = 900,
        .refresh_token_ttl_seconds = 86_400,
        .access_control_rules = "",
        .request_limits = http.request_limits.RequestLimits.default,
        .basic_auth_hashes = &[_][]const u8{},
        .log_level = .info,
        .error_log_path = "",
        .pid_file = "",
        .run_user = "",
        .run_group = "",
        .chroot_dir = "",
        .require_unprivileged_user = false,
        .server_names = &[_][]const u8{},
        .doc_root = "",
        .try_files = "",
        .access_log_format = .json,
        .access_log_template = "",
        .access_log_min_status = 0,
        .access_log_buffer_size = 0,
        .access_log_syslog_udp = "",
        .compression_enabled = false,
        .compression_min_size = 256,
        .compression_brotli_enabled = true,
        .compression_brotli_quality = 5,
        .upstream_gunzip_enabled = true,
        .cb_threshold = 0,
        .cb_timeout_ms = 30_000,
        .worker_threads = 0,
        .master_process_enabled = false,
        .worker_processes = 1,
        .binary_upgrade_enabled = true,
        .worker_recycle_seconds = 0,
        .worker_cpu_affinity = "",
        .worker_queue_size = 1024,
        .fd_soft_limit = 0,
        .max_connections_per_ip = 0,
        .max_active_connections = 0,
        .keep_alive_timeout_ms = 5000,
        .max_requests_per_connection = 100,
        .connection_pool_size = 256,
        .max_connection_memory_bytes = 2 * 1024 * 1024,
        .max_total_connection_memory_bytes = 0,
        .proxy_stream_all_statuses = false,
        .upstream_retry_attempts = 1,
        .upstream_timeout_budget_ms = 0,
        .upstream_max_fails = 0,
        .upstream_fail_timeout_ms = 10_000,
        .upstream_active_health_interval_ms = 0,
        .upstream_active_health_path = "/health",
        .upstream_active_health_timeout_ms = 2000,
        .upstream_active_health_fail_threshold = 1,
        .upstream_active_health_success_threshold = 1,
        .upstream_active_health_success_status = .{ .min = 200, .max = 299 },
        .upstream_active_health_success_status_overrides = &[_]edge_config.EdgeConfig.UpstreamHealthSuccessStatusOverride{},
        .upstream_slow_start_ms = 0,
        .websocket_enabled = true,
        .websocket_idle_timeout_ms = 60_000,
        .websocket_max_frame_size = 1024 * 1024,
        .websocket_ping_interval_ms = 15_000,
        .sse_enabled = true,
        .sse_max_events_per_topic = 1024,
        .sse_poll_interval_ms = 250,
        .sse_max_backlog = 1024,
        .sse_idle_timeout_ms = 60_000,
        .rewrite_rules = &[_]edge_config.EdgeConfig.RewriteRule{},
        .return_rules = &[_]edge_config.EdgeConfig.ReturnRule{},
        .conditional_rules = &[_]edge_config.EdgeConfig.ConditionalRule{},
        .location_blocks = &[_]edge_config.EdgeConfig.LocationBlock{},
        .internal_redirect_rules = &[_]edge_config.EdgeConfig.InternalRedirectRule{},
        .named_locations = &[_]edge_config.EdgeConfig.NamedLocation{},
        .mirror_rules = &[_]edge_config.EdgeConfig.MirrorRule{},
        .fastcgi_upstream = "",
        .fastcgi_params = &[_]edge_config.EdgeConfig.HeaderPair{},
        .fastcgi_index = "index.php",
        .uwsgi_upstream = "",
        .scgi_upstream = "",
        .grpc_upstream = "",
        .memcached_upstream = "",
        .smtp_upstream = "",
        .imap_upstream = "",
        .pop3_upstream = "",
        .tcp_proxy_upstream = "",
        .udp_proxy_upstream = "",
        .stream_ssl_termination = false,
        .approval_store_path = "",
        .approval_ttl_ms = 300_000,
        .approval_escalation_webhook = "",
        .approval_max_pending_per_identity = 10,
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

test "buildProxyCacheKey supports template tokens" {
    const allocator = std.testing.allocator;
    const key = try buildProxyCacheKey(
        allocator,
        "method:path:identity:api_version",
        "POST",
        "/v1/chat",
        "{\"message\":\"hello\"}",
        "identity-1",
        2,
    );
    defer allocator.free(key);
    try std.testing.expectEqualStrings("POST:/v1/chat:identity-1:2", key);
}

test "buildProxyCacheKey falls back for unknown template tokens" {
    const allocator = std.testing.allocator;
    const payload = "{\"command\":\"list_tools\"}";
    const key = try buildProxyCacheKey(
        allocator,
        "unknown:also_unknown",
        "POST",
        "/v1/commands",
        payload,
        null,
        null,
    );
    defer allocator.free(key);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    const expected = try std.fmt.allocPrint(allocator, "POST:/v1/commands:{s}", .{std.fmt.fmtSliceHexLower(&digest)});
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, key);
}

test "mapUpstreamError returns stable codes" {
    const mapped = mapUpstreamError(502);
    try std.testing.expectEqual(@as(u16, 503), mapped.status);
    try std.testing.expectEqualStrings("tool_unavailable", mapped.code);
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

test "isValidDeviceTopicSegment accepts safe values" {
    try std.testing.expect(isValidDeviceTopicSegment("device-1"));
    try std.testing.expect(isValidDeviceTopicSegment("topic.alpha_2"));
    try std.testing.expect(isValidDeviceTopicSegment("  status.update  "));
}

test "isValidDeviceTopicSegment rejects invalid values" {
    try std.testing.expect(!isValidDeviceTopicSegment(""));
    try std.testing.expect(!isValidDeviceTopicSegment("bad/topic"));
    try std.testing.expect(!isValidDeviceTopicSegment("bad topic"));
    try std.testing.expect(!isValidDeviceTopicSegment("..*"));
}

test "routeRequiresApprovalRule detects approval requirement" {
    try std.testing.expect(routeRequiresApprovalRule("POST", "/v1/commands", "POST|/v1/commands|ops|true||"));
    try std.testing.expect(!routeRequiresApprovalRule("POST", "/v1/chat", "POST|/v1/commands|ops|true||"));
}

test "parseApprovalResponseBody parses approve and deny" {
    const allocator = std.testing.allocator;
    var approve = try parseApprovalResponseBody(allocator, "{\"approval_token\":\"tok-1\",\"decision\":\"approve\"}");
    defer approve.deinit(allocator);
    try std.testing.expectEqualStrings("tok-1", approve.token);
    try std.testing.expectEqual(ApprovalDecision.approve, approve.decision);

    var deny = try parseApprovalResponseBody(allocator, "{\"approval_token\":\"tok-2\",\"decision\":\"deny\"}");
    defer deny.deinit(allocator);
    try std.testing.expectEqualStrings("tok-2", deny.token);
    try std.testing.expectEqual(ApprovalDecision.deny, deny.decision);
}

test "parseApprovalRequestBody parses command scoped request" {
    const allocator = std.testing.allocator;
    var req = try parseApprovalRequestBody(allocator, "{\"method\":\"POST\",\"path\":\"/v1/commands\",\"command_id\":\"cmd-123\"}");
    defer req.deinit(allocator);
    try std.testing.expectEqualStrings("POST", req.method);
    try std.testing.expectEqualStrings("/v1/commands", req.path);
    try std.testing.expect(req.command_id != null);
    try std.testing.expectEqualStrings("cmd-123", req.command_id.?);
}
