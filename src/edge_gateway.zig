const std = @import("std");
const builtin = @import("builtin");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");

const MAX_REQUEST_SIZE: usize = 256 * 1024;
const STREAM_RELAY_BUFFER_SIZE: usize = 16 * 1024;
const JSON_CONTENT_TYPE = "application/json";
const ADMIN_ROUTES_JSON =
    "{\"routes\":[" ++
    "\"/health\",\"/metrics\",\"/metrics/prometheus\"," ++
    "\"/admin/routes\",\"/admin/connections\",\"/admin/streams\",\"/admin/upstreams\",\"/admin/certs\",\"/admin/auth-registry\"," ++
    "\"/v1/chat\",\"/v1/commands\",\"/v1/sessions\",\"/v1/cache/purge\"," ++
    "\"/v1/ws/chat\",\"/v1/ws/commands\",\"/v1/events/stream\",\"/v1/events/publish\"," ++
    "\"/v1/subrequest\",\"/v1/backend/fastcgi\",\"/v1/backend/uwsgi\",\"/v1/backend/scgi\",\"/v1/backend/grpc\",\"/v1/backend/memcached\"," ++
    "\"/v1/mail/smtp\",\"/v1/mail/imap\",\"/v1/mail/pop3\",\"/v1/stream/tcp\",\"/v1/stream/udp\"" ++
    "]}";
const HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP2_MAX_FRAME_SIZE: usize = 16 * 1024;
const ProxyCacheLookup = struct {
    cached: http.idempotency.CachedResponse,
    is_stale: bool,
};

const UpstreamHealth = struct {
    fail_count: u32 = 0,
    unhealthy_until_ms: u64 = 0,
    probe_fail_streak: u32 = 0,
    probe_success_streak: u32 = 0,
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

/// Persistent gateway state shared across connections.
const GatewayState = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    rate_limiter: ?http.rate_limiter.RateLimiter,
    idempotency_store: ?http.idempotency.IdempotencyStore,
    proxy_cache_store: ?http.idempotency.IdempotencyStore,
    proxy_cache_path: []const u8,
    proxy_cache_ttl_seconds: u32,
    security_headers: http.security_headers.SecurityHeaders,
    add_headers: []const edge_config.EdgeConfig.HeaderPair,
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
    proxy_cache_locks: std.StringHashMap(u32),
    active_connections_by_ip: std.StringHashMap(u32),
    active_fds: std.AutoHashMap(std.posix.fd_t, void),
    fd_to_ip: std.AutoHashMap(std.posix.fd_t, []u8),

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
        var upstream_it = self.upstream_health.iterator();
        while (upstream_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.upstream_health.deinit();
        var upstream_active_it = self.upstream_active_requests.iterator();
        while (upstream_active_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.upstream_active_requests.deinit();
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
    }

    fn tryAcquireConnectionSlot(self: *GatewayState, fd: std.posix.fd_t, ip_key: []const u8) !ConnectionSlotResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.max_active_connections > 0 and self.active_connections_total >= self.max_active_connections) {
            self.metrics.recordConnectionRejection();
            return .over_global_limit;
        }
        if (self.max_total_connection_memory_bytes > 0 and self.connection_memory_estimate_bytes > 0) {
            const projected: u128 = (@as(u128, self.active_connections_total) + 1) * @as(u128, self.connection_memory_estimate_bytes);
            if (projected > self.max_total_connection_memory_bytes) {
                self.metrics.recordConnectionRejection();
                return .over_global_memory_limit;
            }
        }

        var ip_slot_acquired = false;
        if (self.max_connections_per_ip > 0) {
            const current = self.active_connections_by_ip.get(ip_key) orelse 0;
            if (current >= self.max_connections_per_ip) {
                self.metrics.recordConnectionRejection();
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
        self.metrics.setActiveConnections(self.active_connections_total);
        return .accepted;
    }

    fn releaseConnectionSlot(self: *GatewayState, fd: std.posix.fd_t) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.active_fds.fetchRemove(fd) != null and self.active_connections_total > 0) {
            self.active_connections_total -= 1;
            self.metrics.setActiveConnections(self.active_connections_total);
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
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.rate_limiter) |*rl| {
            return rl.allow(client_ip) != null;
        }
        return true;
    }

    fn idempotencyGetCopy(self: *GatewayState, allocator: std.mem.Allocator, key: []const u8) !?http.idempotency.CachedResponse {
        self.mutex.lock();
        defer self.mutex.unlock();
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
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.idempotency_store) |*store| {
            try store.put(key, status, body, content_type);
        }
    }

    fn proxyCacheGetCopyWithStale(self: *GatewayState, allocator: std.mem.Allocator, key: []const u8, stale_seconds: u32) !?ProxyCacheLookup {
        self.mutex.lock();
        var locked = true;
        defer if (locked) self.mutex.unlock();
        if (self.proxy_cache_store) |*store| {
            if (store.getWithStale(key, stale_seconds)) |lookup| {
                const body = try allocator.dupe(u8, lookup.response.body);
                errdefer allocator.free(body);
                const ct = try allocator.dupe(u8, lookup.response.content_type);
                locked = false;
                self.mutex.unlock();
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
        self.mutex.unlock();

        if (self.proxy_cache_path.len == 0) return null;
        const disk_lookup = try proxyCacheReadFromDisk(allocator, self.proxy_cache_path, key, self.proxy_cache_ttl_seconds, stale_seconds);
        if (disk_lookup) |found| {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.proxy_cache_store) |*store| {
                store.put(key, found.cached.status, found.cached.body, found.cached.content_type) catch {};
            }
        }
        return disk_lookup;
    }

    fn proxyCachePut(self: *GatewayState, key: []const u8, status: u16, body: []const u8, content_type: []const u8) !void {
        self.mutex.lock();
        var locked = true;
        defer if (locked) self.mutex.unlock();
        if (self.proxy_cache_store) |*store| {
            try store.put(key, status, body, content_type);
        }
        locked = false;
        self.mutex.unlock();
        if (self.proxy_cache_path.len > 0) {
            try proxyCacheWriteToDisk(self.proxy_cache_path, key, status, body, content_type);
        }
    }

    fn proxyCacheDelete(self: *GatewayState, key: []const u8) bool {
        self.mutex.lock();
        var removed = false;
        if (self.proxy_cache_store) |*store| {
            removed = store.delete(key);
        }
        self.mutex.unlock();
        if (self.proxy_cache_path.len > 0) {
            removed = proxyCacheDeleteFromDisk(self.proxy_cache_path, key) or removed;
        }
        return removed;
    }

    fn proxyCachePurgeAll(self: *GatewayState) usize {
        self.mutex.lock();
        var removed: usize = 0;
        if (self.proxy_cache_store) |*store| {
            removed += store.clear();
        }
        self.mutex.unlock();
        if (self.proxy_cache_path.len > 0) {
            removed += proxyCachePurgeDisk(self.proxy_cache_path);
        }
        return removed;
    }

    fn proxyCacheTryLock(self: *GatewayState, key: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.proxy_cache_locks.contains(key)) return false;
        const owned = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned);
        try self.proxy_cache_locks.put(owned, 1);
        return true;
    }

    fn proxyCacheUnlock(self: *GatewayState, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.proxy_cache_locks.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
        }
    }

    fn proxyCacheWaitForUnlock(self: *GatewayState, key: []const u8, timeout_ms: u32) bool {
        const deadline = http.event_loop.monotonicMs() + timeout_ms;
        while (http.event_loop.monotonicMs() < deadline) {
            self.mutex.lock();
            const locked = self.proxy_cache_locks.contains(key);
            self.mutex.unlock();
            if (!locked) return true;
            std.time.sleep(10 * std.time.ns_per_ms);
        }
        return false;
    }

    fn createSession(self: *GatewayState, allocator: std.mem.Allocator, identity: []const u8, client_ip: []const u8, device_id: ?[]const u8) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const token = try self.session_store.?.create(identity, client_ip, device_id);
        return try allocator.dupe(u8, token);
    }

    fn validateSessionIdentity(self: *GatewayState, allocator: std.mem.Allocator, token: []const u8) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.session_store) |*ss| {
            if (ss.validate(token)) |session| {
                return allocator.dupe(u8, session.identity) catch null;
            }
        }
        return null;
    }

    fn revokeSession(self: *GatewayState, token: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.session_store) |*ss| return ss.revoke(token);
        return false;
    }

    fn countSessionsByIdentity(self: *GatewayState, allocator: std.mem.Allocator, identity: []const u8) !usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const sessions = try self.session_store.?.listByIdentity(allocator, identity);
        defer allocator.free(sessions);
        return sessions.len;
    }

    fn refreshSession(self: *GatewayState, allocator: std.mem.Allocator, token: []const u8, client_ip: []const u8) ![]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.session_store == null) return error.SessionsDisabled;
        const existing = self.session_store.?.validate(token) orelse return error.InvalidSession;
        const new_token = try self.session_store.?.create(existing.identity, client_ip, existing.device_id);
        _ = self.session_store.?.revoke(token);
        return try allocator.dupe(u8, new_token);
    }

    fn circuitTryAcquire(self: *GatewayState) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.circuit_breaker.tryAcquire();
    }

    fn circuitRecordFailure(self: *GatewayState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.circuit_breaker.recordFailure();
    }

    fn circuitRecordSuccess(self: *GatewayState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.circuit_breaker.recordSuccess();
    }

    fn circuitStateName(self: *GatewayState) []const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.circuit_breaker.stateName();
    }

    fn metricsRecord(self: *GatewayState, status: u16) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.metrics.recordRequest(status);
    }

    fn metricsRecordQueueRejection(self: *GatewayState) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.metrics.recordQueueRejection();
    }

    fn metricsRecordErrorCode(self: *GatewayState, code: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.metrics.recordErrorCode(code);
    }

    fn metricsToJson(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.metrics.toJson(allocator);
    }

    fn metricsToPrometheus(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.metrics.toPrometheus(allocator);
    }

    fn nextUpstreamBaseUrl(self: *GatewayState, cfg: *const edge_config.EdgeConfig, pool: UpstreamPoolView, client_ip: []const u8, hash_key: []const u8) []const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
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

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.upstream_health.getPtr(upstream_base_url)) |health| {
            health.fail_count +|= 1;
            health.probe_success_streak = 0;
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
            health.probe_success_streak = 0;
            if (health.fail_count >= cfg.upstream_max_fails) {
                health.fail_count = 0;
                health.unhealthy_until_ms = http.event_loop.monotonicMs() + cfg.upstream_fail_timeout_ms;
            }
        }
        self.updateUpstreamHealthMetricLocked();
    }

    fn recordUpstreamSuccess(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8) void {
        if (cfg.upstream_max_fails == 0) return;

        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.upstream_health.getPtr(upstream_base_url)) |health| {
            health.fail_count = 0;
            health.unhealthy_until_ms = 0;
            health.probe_fail_streak = 0;
            health.probe_success_streak = 0;
            health.slow_start_until_ms = 0;
        }
        self.updateUpstreamHealthMetricLocked();
    }

    fn recordActiveProbeResult(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, healthy: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();

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

        if (healthy) {
            health.probe_fail_streak = 0;
            health.probe_success_streak +|= 1;
            if (health.probe_success_streak >= cfg.upstream_active_health_success_threshold) {
                health.unhealthy_until_ms = 0;
                health.fail_count = 0;
                health.probe_success_streak = 0;
                self.beginSlowStartLocked(cfg, health, http.event_loop.monotonicMs());
            }
        } else {
            health.probe_success_streak = 0;
            health.probe_fail_streak +|= 1;
            if (health.probe_fail_streak >= cfg.upstream_active_health_fail_threshold) {
                health.probe_fail_streak = 0;
                health.unhealthy_until_ms = http.event_loop.monotonicMs() + cfg.upstream_fail_timeout_ms;
                health.slow_start_until_ms = 0;
            }
        }
        self.updateUpstreamHealthMetricLocked();
    }

    fn isUpstreamHealthyLocked(self: *GatewayState, cfg: *const edge_config.EdgeConfig, upstream_base_url: []const u8, now_ms: u64) bool {
        if (self.upstream_health.getPtr(upstream_base_url)) |health| {
            if (health.unhealthy_until_ms == 0) return true;
            if (now_ms >= health.unhealthy_until_ms) {
                health.unhealthy_until_ms = 0;
                health.fail_count = 0;
                self.beginSlowStartLocked(cfg, health, now_ms);
                self.updateUpstreamHealthMetricLocked();
                return true;
            }
            return false;
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
            if (health.unhealthy_until_ms > now_ms) unhealthy += 1;
        }
        self.metrics.setUpstreamUnhealthyBackends(unhealthy);
    }

    fn recordUpstreamAttemptStart(self: *GatewayState, upstream_base_url: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

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
        self.mutex.lock();
        defer self.mutex.unlock();
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
        self.mutex.lock();
        defer self.mutex.unlock();
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
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{ .ws = self.active_ws_streams, .sse = self.active_sse_streams };
    }

    fn connectionCounts(self: *GatewayState) struct { active: usize, per_ip: usize } {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{ .active = self.active_connections_total, .per_ip = self.active_connections_by_ip.count() };
    }

    fn upstreamHealthJson(self: *GatewayState, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
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
            const healthy = h.unhealthy_until_ms == 0 or h.unhealthy_until_ms <= now_ms;
            try out.writer().print("{{\"url\":\"{s}\",\"healthy\":{},\"unhealthy_until_ms\":{d}}}", .{ url, healthy, h.unhealthy_until_ms });
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
    mutex: std.Thread.Mutex = .{},
    free_list: std.ArrayList(*ConnectionSession),
    max_cached: usize,

    fn init(allocator: std.mem.Allocator, max_cached: usize) ConnectionSessionPool {
        return .{
            .allocator = allocator,
            .free_list = std.ArrayList(*ConnectionSession).init(allocator),
            .max_cached = max_cached,
        };
    }

    fn deinit(self: *ConnectionSessionPool) void {
        for (self.free_list.items) |session| {
            self.allocator.destroy(session);
        }
        self.free_list.deinit();
    }

    fn acquire(self: *ConnectionSessionPool) !*ConnectionSession {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.free_list.items.len > 0) {
            return self.free_list.pop().?;
        }
        return try self.allocator.create(ConnectionSession);
    }

    fn release(self: *ConnectionSessionPool, session: *ConnectionSession) void {
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
        .proxy_cache_locks = std.StringHashMap(u32).init(state_allocator),
        .active_connections_by_ip = std.StringHashMap(u32).init(state_allocator),
        .active_fds = std.AutoHashMap(std.posix.fd_t, void).init(state_allocator),
        .fd_to_ip = std.AutoHashMap(std.posix.fd_t, []u8).init(state_allocator),
    };
    defer state.deinit();
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
    var tls_terminator: ?http.tls_termination.TlsTerminator = null;
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
    var session_pool = ConnectionSessionPool.init(state_allocator, cfg.connection_pool_size);
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
        state.logger.info(null, "HTTP/3 foundation enabled: 0rtt={} migration={} max_datagram={d}", .{
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
    state.logger.info(null, "Signal handlers installed (SIGTERM/SIGINT shutdown, SIGHUP reload)", .{});

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
    const cfg_ptr = allocator.create(edge_config.EdgeConfig) catch {
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
    state.mutex.lock();
    defer state.mutex.unlock();
    state.add_headers = cfg.add_headers;
    state.security_headers = if (cfg.security_headers_enabled)
        http.security_headers.SecurityHeaders.api
    else
        http.security_headers.SecurityHeaders{ .x_frame_options = "", .x_content_type_options = "", .content_security_policy = "", .strict_transport_security = "", .referrer_policy = "", .permissions_policy = "", .x_xss_protection = "" };
    state.max_connections_per_ip = cfg.max_connections_per_ip;
    state.max_active_connections = cfg.max_active_connections;
    state.max_total_connection_memory_bytes = cfg.max_total_connection_memory_bytes;
    state.connection_memory_estimate_bytes = if (cfg.max_connection_memory_bytes > 0) cfg.max_connection_memory_bytes else MAX_REQUEST_SIZE;
    state.proxy_cache_path = cfg.proxy_cache_path;
    state.proxy_cache_ttl_seconds = cfg.proxy_cache_ttl_seconds;
    state.compression_config = .{
        .enabled = cfg.compression_enabled,
        .min_size = cfg.compression_min_size,
        .brotli_enabled = cfg.compression_brotli_enabled,
        .brotli_quality = cfg.compression_brotli_quality,
    };
    state.logger.min_level = cfg.log_level;
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

fn runProxyCacheMaintenance(cfg: *const edge_config.EdgeConfig, state: *GatewayState) void {
    if (cfg.proxy_cache_ttl_seconds == 0) return;
    const interval = cfg.proxy_cache_manager_interval_ms;
    if (interval == 0) return;
    const now_ms = http.event_loop.monotonicMs();
    if (state.next_proxy_cache_maintenance_ms != 0 and now_ms < state.next_proxy_cache_maintenance_ms) return;
    state.next_proxy_cache_maintenance_ms = now_ms + interval;

    state.mutex.lock();
    defer state.mutex.unlock();
    if (state.proxy_cache_store) |*store| {
        _ = store.cleanupExpired();
    }
}

fn probeSingleUpstream(cfg: *const edge_config.EdgeConfig, state: *GatewayState, probe_client: *std.http.Client, base_url: []const u8) void {
    const probe_base = if (unixSocketPathFromEndpoint(base_url) != null) "http://localhost" else base_url;
    const probe_url = buildHealthProbeUrl(state.allocator, probe_base, cfg.upstream_active_health_path) catch |err| {
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
    if (status_code >= 200 and status_code < 400) {
        state.recordActiveProbeResult(cfg, base_url, true);
    } else {
        state.recordActiveProbeResult(cfg, base_url, false);
    }
}

fn buildHealthProbeUrl(allocator: std.mem.Allocator, base_url: []const u8, probe_path: []const u8) ![]u8 {
    const base_trimmed = std.mem.trimRight(u8, base_url, "/");
    const path_trimmed = std.mem.trimLeft(u8, probe_path, "/");
    if (path_trimmed.len == 0) return std.fmt.allocPrint(allocator, "{s}/", .{base_trimmed});
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ base_trimmed, path_trimmed });
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
    const nonblock_mask = @as(i32, 1 << @bitOffsetOf(std.posix.O, "NONBLOCK"));
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
        try pushHttp2Resource(writer, allocator, stream_id, promised_stream_id, "/metrics", "application/json", "{\"pushed\":true}");
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
    var ctx = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);
    if (!hostMatchesServerNames(cfg, &request)) {
        try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive, state);
        logAccess(&ctx, request.method.toString(), request.uri.path, 404, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Rewrite / return directives ---
    const rewrite_outcome = http.rewrite.evaluate(
        request.method.toString(),
        request.uri.path,
        cfg.rewrite_rules,
        cfg.return_rules,
    );
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
        cfg.internal_redirect_rules,
        cfg.named_locations,
    );

    // --- Mirror requests (best-effort async) ---
    if (cfg.mirror_rules.len > 0) {
        spawnMirrorRequests(
            allocator,
            cfg.mirror_rules,
            request.method.toString(),
            request.uri.path,
            request.body orelse "",
            correlation_id,
            client_ip,
            request.headers.get("content-type"),
        );
    }

    // --- Geo-based blocking (external country header) ---
    if (cfg.geo_blocked_countries.len > 0) {
        const country = request.headers.get(cfg.geo_country_header);
        if (isGeoBlocked(cfg.geo_blocked_countries, country)) {
            try sendApiError(allocator, writer, .forbidden, "forbidden", "Geo access denied", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 403, request.headers.get("user-agent") orelse "");
            return;
        }
    }

    // --- Request validation (body size, URI length, header count) ---
    const limits = cfg.request_limits;
    const uri_check = http.request_limits.validateUriLength(request.uri.path.len, limits);
    if (uri_check != .ok) {
        var msg_buf: [256]u8 = undefined;
        const msg = http.request_limits.rejectionMessage(uri_check, &msg_buf);
        try sendApiError(allocator, writer, .uri_too_long, "invalid_request", msg, correlation_id, keep_alive, state);
        state.logger.warn(correlation_id, "URI too long: {d} bytes", .{request.uri.path.len});
        logAccess(&ctx, request.method.toString(), request.uri.path, 414, request.headers.get("user-agent") orelse "");
        return;
    }
    const header_count_check = http.request_limits.validateHeaderCount(request.headers.count(), limits);
    if (header_count_check != .ok) {
        try sendApiError(allocator, writer, .bad_request, "invalid_request", "Too many headers", correlation_id, keep_alive, state);
        state.logger.warn(correlation_id, "Too many headers: {d}", .{request.headers.count()});
        logAccess(&ctx, request.method.toString(), request.uri.path, 400, request.headers.get("user-agent") orelse "");
        return;
    }
    if (request.body) |body| {
        const body_check = http.request_limits.validateBodySize(body.len, limits);
        if (body_check != .ok) {
            try sendApiError(allocator, writer, .payload_too_large, "invalid_request", "Request body too large", correlation_id, keep_alive, state);
            state.logger.warn(correlation_id, "Body too large: {d} bytes", .{body.len});
            logAccess(&ctx, request.method.toString(), request.uri.path, 413, request.headers.get("user-agent") orelse "");
            return;
        }
    }

    // --- Extract API version ---
    if (http.api_router.parseVersionedPath(request.uri.path)) |versioned| {
        ctx.setApiVersion(versioned.version);
    }

    if (ctx.api_version != null and isProtectedAuthRequestRoute(request.uri.path)) {
        if (cfg.device_auth_required and !validateDeviceRequest(cfg, request.method.toString(), request.uri.path, &request.headers, request.body orelse "")) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Device authentication failed", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 401, request.headers.get("user-agent") orelse "");
            return;
        }

        const identity = try extractIdentityForPolicy(allocator, cfg, state, &request);
        defer if (identity) |id| allocator.free(id);
        if (evaluatePolicy(cfg, request.method.toString(), request.uri.path, identity, request.headers.get("x-device-id"), &request.headers)) |reason| {
            try sendApiError(allocator, writer, .forbidden, "forbidden", reason, correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 403, request.headers.get("user-agent") orelse "");
            return;
        }
    }

    // --- Extract idempotency key ---
    if (http.idempotency.fromHeaders(&request.headers)) |idem_key| {
        ctx.setIdempotencyKey(idem_key);
    }

    // --- IP Access Control ---
    if (state.access_control) |*acl| {
        if (acl.check(client_ip) == .denied) {
            try sendApiError(allocator, writer, .forbidden, "forbidden", "Access denied", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 403, request.headers.get("user-agent") orelse "");
            return;
        }
    }

    // --- Rate Limiting ---
    if (!state.rateLimitAllow(client_ip)) {
        try sendApiError(allocator, writer, .too_many_requests, "rate_limited", "Rate limit exceeded", correlation_id, keep_alive, state);
        logAccess(&ctx, request.method.toString(), request.uri.path, 429, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Health endpoint ---
    if (request.method == .GET and std.mem.eql(u8, request.uri.path, "/health")) {
        var response = http.Response.json(allocator, "{\"status\":\"ok\",\"service\":\"tardigrade-edge\"}");
        defer response.deinit();
        _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(200);
        logAccess(&ctx, request.method.toString(), "/health", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Metrics endpoint ---
    if (request.method == .GET and std.mem.eql(u8, request.uri.path, "/metrics")) {
        const metrics_json = state.metricsToJson(allocator) catch {
            try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to generate metrics", correlation_id, keep_alive, state);
            return;
        };
        defer allocator.free(metrics_json);

        var response = http.Response.json(allocator, metrics_json);
        defer response.deinit();
        _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(200);
        logAccess(&ctx, request.method.toString(), "/metrics", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Prometheus metrics endpoint ---
    if (request.method == .GET and std.mem.eql(u8, request.uri.path, "/metrics/prometheus")) {
        const prom_text = state.metricsToPrometheus(allocator) catch {
            try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to generate metrics", correlation_id, keep_alive, state);
            return;
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
        logAccess(&ctx, request.method.toString(), "/metrics/prometheus", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Admin API ---
    if (request.method == .GET and std.mem.startsWith(u8, request.uri.path, "/admin/")) {
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (!auth_result.ok) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 401, request.headers.get("user-agent") orelse "");
            return;
        }
        if (std.mem.eql(u8, request.uri.path, "/admin/routes")) {
            var response = http.Response.json(allocator, ADMIN_ROUTES_JSON);
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            logAccess(&ctx, request.method.toString(), request.uri.path, 200, request.headers.get("user-agent") orelse "");
            return;
        }
        if (std.mem.eql(u8, request.uri.path, "/admin/connections")) {
            const counts = state.connectionCounts();
            const body = try std.fmt.allocPrint(allocator, "{{\"active\":{d},\"tracked_ip_buckets\":{d}}}", .{ counts.active, counts.per_ip });
            defer allocator.free(body);
            var response = http.Response.json(allocator, body);
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            logAccess(&ctx, request.method.toString(), request.uri.path, 200, request.headers.get("user-agent") orelse "");
            return;
        }
        if (std.mem.eql(u8, request.uri.path, "/admin/streams")) {
            const counts = state.streamCounts();
            const body = try std.fmt.allocPrint(allocator, "{{\"websocket_active\":{d},\"sse_active\":{d}}}", .{ counts.ws, counts.sse });
            defer allocator.free(body);
            var response = http.Response.json(allocator, body);
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            logAccess(&ctx, request.method.toString(), request.uri.path, 200, request.headers.get("user-agent") orelse "");
            return;
        }
        if (std.mem.eql(u8, request.uri.path, "/admin/upstreams")) {
            const body = state.upstreamHealthJson(allocator) catch try allocator.dupe(u8, "{\"upstreams\":[]}");
            defer allocator.free(body);
            var response = http.Response.json(allocator, body);
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            logAccess(&ctx, request.method.toString(), request.uri.path, 200, request.headers.get("user-agent") orelse "");
            return;
        }
        if (std.mem.eql(u8, request.uri.path, "/admin/certs")) {
            const body = try std.fmt.allocPrint(allocator, "{{\"default_cert\":\"{s}\",\"default_key\":\"{s}\",\"sni_count\":{d}}}", .{ cfg.tls_cert_path, cfg.tls_key_path, cfg.tls_sni_certs.len });
            defer allocator.free(body);
            var response = http.Response.json(allocator, body);
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            logAccess(&ctx, request.method.toString(), request.uri.path, 200, request.headers.get("user-agent") orelse "");
            return;
        }
        if (std.mem.eql(u8, request.uri.path, "/admin/auth-registry")) {
            const body = try std.fmt.allocPrint(allocator, "{{\"bearer_hashes\":{d},\"basic_auth_hashes\":{d},\"sessions_enabled\":{}}}", .{
                cfg.auth_token_hashes.len,
                cfg.basic_auth_hashes.len,
                state.session_store != null,
            });
            defer allocator.free(body);
            var response = http.Response.json(allocator, body);
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            logAccess(&ctx, request.method.toString(), request.uri.path, 200, request.headers.get("user-agent") orelse "");
            return;
        }

        try sendApiError(allocator, writer, .not_found, "invalid_request", "Unknown admin route", correlation_id, keep_alive, state);
        logAccess(&ctx, request.method.toString(), request.uri.path, 404, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Versioned API routing ---
    const versioned = http.api_router.parseVersionedPath(request.uri.path);
    if (versioned) |route| {
        if (!http.api_router.isSupportedVersion(route.version)) {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Unsupported API version", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 400, request.headers.get("user-agent") orelse "");
            return;
        }
        if (cfg.auth_request_url.len > 0 and isProtectedAuthRequestRoute(request.uri.path)) {
            if (!authorizeViaSubrequest(allocator, cfg, &request, correlation_id, client_ip)) {
                try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
                logAccess(&ctx, request.method.toString(), request.uri.path, 401, request.headers.get("user-agent") orelse "");
                return;
            }
        }
    }

    // --- POST /v1/subrequest ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/subrequest")) {
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (!auth_result.ok) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/subrequest", 401, request.headers.get("user-agent") orelse "");
            return;
        }
        ctx.setIdentity(auth_result.token_hash orelse "-");
        const body = request.body orelse "";
        const sub = parseSubrequestPayload(allocator, body) catch {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Invalid subrequest payload", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/subrequest", 400, request.headers.get("user-agent") orelse "");
            return;
        };
        defer {
            allocator.free(sub.url);
            if (sub.body) |b| allocator.free(b);
        }
        const out = executeSubrequest(allocator, sub.url, sub.method, sub.body) catch |err| {
            state.logger.warn(correlation_id, "subrequest failed: {}", .{err});
            try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "Subrequest failed", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/subrequest", 502, request.headers.get("user-agent") orelse "");
            return;
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
        logAccess(&ctx, request.method.toString(), "/v1/subrequest", out.status, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Backend protocol bridges (Phase 11.3) ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/backend/fastcgi")) {
        try handleBackendProtocolRoute(
            allocator,
            writer,
            cfg.fastcgi_upstream,
            request.method.toString(),
            request.uri.path,
            request.body orelse "",
            correlation_id,
            keep_alive,
            state,
            .fastcgi,
        );
        logAccess(&ctx, request.method.toString(), "/v1/backend/fastcgi", 200, request.headers.get("user-agent") orelse "");
        return;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/backend/uwsgi")) {
        try handleBackendProtocolRoute(
            allocator,
            writer,
            cfg.uwsgi_upstream,
            request.method.toString(),
            request.uri.path,
            request.body orelse "",
            correlation_id,
            keep_alive,
            state,
            .uwsgi,
        );
        logAccess(&ctx, request.method.toString(), "/v1/backend/uwsgi", 200, request.headers.get("user-agent") orelse "");
        return;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/backend/scgi")) {
        try handleBackendProtocolRoute(
            allocator,
            writer,
            cfg.scgi_upstream,
            request.method.toString(),
            request.uri.path,
            request.body orelse "",
            correlation_id,
            keep_alive,
            state,
            .scgi,
        );
        logAccess(&ctx, request.method.toString(), "/v1/backend/scgi", 200, request.headers.get("user-agent") orelse "");
        return;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/backend/grpc")) {
        const upstream = std.mem.trim(u8, cfg.grpc_upstream, " \t\r\n");
        if (upstream.len == 0) {
            try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "gRPC upstream not configured", correlation_id, keep_alive, state);
            return;
        }
        const body = request.body orelse "";
        const grpc_resp = proxyGrpcExecute(
            allocator,
            upstream,
            body,
            correlation_id,
            state,
        ) catch |err| {
            state.logger.warn(correlation_id, "grpc proxy failed: {}", .{err});
            try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "gRPC proxy failed", correlation_id, keep_alive, state);
            return;
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
        logAccess(&ctx, request.method.toString(), "/v1/backend/grpc", 200, request.headers.get("user-agent") orelse "");
        return;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/backend/memcached")) {
        const ep = std.mem.trim(u8, cfg.memcached_upstream, " \t\r\n");
        if (ep.len == 0) {
            try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "Memcached upstream not configured", correlation_id, keep_alive, state);
            return;
        }
        const payload = request.body orelse "";
        const parsed = parseMemcachedPayload(allocator, payload) catch {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Invalid memcached payload", correlation_id, keep_alive, state);
            return;
        };
        defer {
            allocator.free(parsed.op);
            allocator.free(parsed.key);
            if (parsed.value) |v| allocator.free(v);
        }
        if (std.ascii.eqlIgnoreCase(parsed.op, "get")) {
            const value = http.memcached.get(allocator, ep, parsed.key) catch null;
            defer if (value) |v| allocator.free(v);
            const body = if (value) |v|
                try std.fmt.allocPrint(allocator, "{{\"value\":{s}}}", .{std.json.fmt(v, .{})})
            else
                try allocator.dupe(u8, "{\"value\":null}");
            defer allocator.free(body);
            var response = http.Response.json(allocator, body);
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            logAccess(&ctx, request.method.toString(), "/v1/backend/memcached", 200, request.headers.get("user-agent") orelse "");
            return;
        }
        if (std.ascii.eqlIgnoreCase(parsed.op, "set")) {
            const stored = http.memcached.set(allocator, ep, parsed.key, parsed.value orelse "", parsed.ttl) catch false;
            const body = if (stored) "{\"stored\":true}" else "{\"stored\":false}";
            var response = http.Response.json(allocator, body);
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(200);
            logAccess(&ctx, request.method.toString(), "/v1/backend/memcached", 200, request.headers.get("user-agent") orelse "");
            return;
        }
        try sendApiError(allocator, writer, .bad_request, "invalid_request", "Unsupported memcached operation", correlation_id, keep_alive, state);
        return;
    }

    // --- Mail proxy routes (Phase 11.4 optional) ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/mail/smtp")) {
        try handleMailProxyRoute(allocator, writer, cfg.smtp_upstream, request.body orelse "", correlation_id, keep_alive, state);
        logAccess(&ctx, request.method.toString(), "/v1/mail/smtp", 200, request.headers.get("user-agent") orelse "");
        return;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/mail/imap")) {
        try handleMailProxyRoute(allocator, writer, cfg.imap_upstream, request.body orelse "", correlation_id, keep_alive, state);
        logAccess(&ctx, request.method.toString(), "/v1/mail/imap", 200, request.headers.get("user-agent") orelse "");
        return;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/mail/pop3")) {
        try handleMailProxyRoute(allocator, writer, cfg.pop3_upstream, request.body orelse "", correlation_id, keep_alive, state);
        logAccess(&ctx, request.method.toString(), "/v1/mail/pop3", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Stream module routes (Phase 11.5) ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/stream/tcp")) {
        try handleMailProxyRoute(allocator, writer, cfg.tcp_proxy_upstream, request.body orelse "", correlation_id, keep_alive, state);
        logAccess(&ctx, request.method.toString(), "/v1/stream/tcp", 200, request.headers.get("user-agent") orelse "");
        return;
    }
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/stream/udp")) {
        const upstream = std.mem.trim(u8, cfg.udp_proxy_upstream, " \t\r\n");
        if (upstream.len == 0) {
            try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "UDP upstream not configured", correlation_id, keep_alive, state);
            return;
        }
        const udp_resp = executeUdpDatagramRequest(allocator, upstream, request.body orelse "") catch |err| {
            state.logger.warn(correlation_id, "udp stream proxy failed: {}", .{err});
            try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "UDP proxy failed", correlation_id, keep_alive, state);
            return;
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
        logAccess(&ctx, request.method.toString(), "/v1/stream/udp", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- WebSocket proxy routes ---
    if (request.method == .GET and (http.api_router.matchRoute(request.uri.path, 1, "/ws/chat") or http.api_router.matchRoute(request.uri.path, 1, "/ws/commands"))) {
        if (!cfg.websocket_enabled) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 404, request.headers.get("user-agent") orelse "");
            return;
        }
        if (!http.websocket.isUpgradeRequest(&request.headers)) {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Expected websocket upgrade request", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 400, request.headers.get("user-agent") orelse "");
            return;
        }

        var authenticated = false;
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (auth_result.ok) {
            ctx.setIdentity(auth_result.token_hash orelse "-");
            authenticated = true;
        }
        if (!authenticated) {
            if (http.session.fromHeaders(&request.headers)) |session_token| {
                if (state.validateSessionIdentity(allocator, session_token)) |identity| {
                    defer allocator.free(identity);
                    ctx.setIdentity(identity);
                    authenticated = true;
                }
            }
        }
        if (!authenticated) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 401, request.headers.get("user-agent") orelse "");
            return;
        }

        const ws_key = request.headers.get("sec-websocket-key") orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing Sec-WebSocket-Key", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 400, request.headers.get("user-agent") orelse "");
            return;
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
            ctx.api_version,
            request.headers.get("host"),
            request.headers.get("x-forwarded-for"),
            ws_scope,
            ws_proxy_target,
        ) catch |err| {
            state.logger.warn(correlation_id, "websocket loop ended: {}", .{err});
        };
        state.metricsRecord(101);
        logAccess(&ctx, request.method.toString(), request.uri.path, 101, request.headers.get("user-agent") orelse "");
        keep_alive = false;
        return;
    }

    // --- SSE stream route ---
    if (request.method == .GET and http.api_router.matchRoute(request.uri.path, 1, "/events/stream")) {
        if (!cfg.sse_enabled) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 404, request.headers.get("user-agent") orelse "");
            return;
        }

        var authenticated = false;
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (auth_result.ok) {
            ctx.setIdentity(auth_result.token_hash orelse "-");
            authenticated = true;
        }
        if (!authenticated) {
            if (http.session.fromHeaders(&request.headers)) |session_token| {
                if (state.validateSessionIdentity(allocator, session_token)) |identity| {
                    defer allocator.free(identity);
                    ctx.setIdentity(identity);
                    authenticated = true;
                }
            }
        }
        if (!authenticated) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, false, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 401, request.headers.get("user-agent") orelse "");
            return;
        }

        const topic = parseQueryParam(request.uri.query, "topic") orelse "default";
        const last_event_id = parseLastEventId(request.headers.get("last-event-id"));
        state.streamCountAdjust(0, 1);
        defer state.streamCountAdjust(0, -1);
        try streamSseTopic(writer, allocator, cfg, state, topic, last_event_id, correlation_id);
        state.metricsRecord(200);
        logAccess(&ctx, request.method.toString(), request.uri.path, 200, request.headers.get("user-agent") orelse "");
        keep_alive = false;
        return;
    }

    // --- SSE publish route ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/events/publish")) {
        if (!cfg.sse_enabled) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 404, request.headers.get("user-agent") orelse "");
            return;
        }
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (!auth_result.ok) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), request.uri.path, 401, request.headers.get("user-agent") orelse "");
            return;
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
        logAccess(&ctx, request.method.toString(), request.uri.path, 202, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- POST /v1/devices/register (device identity registration) ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/devices/register")) {
        if (cfg.device_registry_path.len == 0) {
            try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "Device registry not configured", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/devices/register", 501, request.headers.get("user-agent") orelse "");
            return;
        }
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (!auth_result.ok) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/devices/register", 401, request.headers.get("user-agent") orelse "");
            return;
        }
        const body = request.body orelse "";
        const reg = parseDeviceRegistration(allocator, body) catch {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Invalid device registration payload", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/devices/register", 400, request.headers.get("user-agent") orelse "");
            return;
        };
        defer {
            allocator.free(reg.device_id);
            allocator.free(reg.public_key);
        }
        registerDeviceIdentity(cfg.device_registry_path, reg.device_id, reg.public_key) catch {
            try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to persist device identity", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/devices/register", 500, request.headers.get("user-agent") orelse "");
            return;
        };
        var response = http.Response.created(allocator, "{\"registered\":true}", null);
        defer response.deinit();
        _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(201);
        logAccess(&ctx, request.method.toString(), "/v1/devices/register", 201, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- POST /v1/sessions/refresh ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/sessions/refresh")) {
        if (state.session_store == null) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Sessions not enabled", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions/refresh", 404, request.headers.get("user-agent") orelse "");
            return;
        }
        const session_token = http.session.fromHeaders(&request.headers) orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing or invalid X-Session-Token", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions/refresh", 400, request.headers.get("user-agent") orelse "");
            return;
        };
        const refreshed = state.refreshSession(allocator, session_token, client_ip) catch {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Invalid session token", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions/refresh", 401, request.headers.get("user-agent") orelse "");
            return;
        };
        defer allocator.free(refreshed);
        const resp_body = try std.fmt.allocPrint(allocator, "{{\"session_token\":\"{s}\",\"access_ttl_seconds\":{d},\"refresh_ttl_seconds\":{d}}}", .{
            refreshed,
            cfg.access_token_ttl_seconds,
            cfg.refresh_token_ttl_seconds,
        });
        defer allocator.free(resp_body);
        var response = http.Response.ok(allocator, resp_body)
            .setContentType(JSON_CONTENT_TYPE)
            .setConnection(keep_alive)
            .setHeader(http.correlation.HEADER_NAME, correlation_id)
            .setHeader(http.session.SESSION_HEADER, refreshed);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(200);
        logAccess(&ctx, request.method.toString(), "/v1/sessions/refresh", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- POST /v1/sessions (create session) ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/sessions")) {
        if (state.session_store == null) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Sessions not enabled", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 404, request.headers.get("user-agent") orelse "");
            return;
        }

        // Requires bearer auth to create a session
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (!auth_result.ok) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
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

        const session_token = state.createSession(allocator, identity, client_ip, device_id) catch |err| {
            const msg = switch (err) {
                error.TooManySessions => "Too many active sessions",
                else => "Session creation failed",
            };
            try sendApiError(allocator, writer, .too_many_requests, "rate_limited", msg, correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 429, request.headers.get("user-agent") orelse "");
            return;
        };
        defer allocator.free(session_token);

        const resp_body = try std.fmt.allocPrint(allocator, "{{\"session_token\":\"{s}\"}}", .{session_token});
        defer allocator.free(resp_body);

        var response = http.Response.json(allocator, resp_body);
        defer response.deinit();
        _ = response.setStatus(.created)
            .setConnection(keep_alive)
            .setHeader(http.correlation.HEADER_NAME, correlation_id)
            .setHeader(http.session.SESSION_HEADER, session_token);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(201);
        logAccess(&ctx, request.method.toString(), "/v1/sessions", 201, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- DELETE /v1/sessions (revoke session) ---
    if (request.method == .DELETE and http.api_router.matchRoute(request.uri.path, 1, "/sessions")) {
        if (state.session_store == null) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Sessions not enabled", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 404, request.headers.get("user-agent") orelse "");
            return;
        }

        const session_token = http.session.fromHeaders(&request.headers) orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing or invalid X-Session-Token", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 400, request.headers.get("user-agent") orelse "");
            return;
        };

        const revoked = state.revokeSession(session_token);
        const resp_body = if (revoked)
            "{\"revoked\":true}"
        else
            "{\"revoked\":false}";

        var response = http.Response.json(allocator, resp_body);
        defer response.deinit();
        _ = response.setConnection(keep_alive)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(200);
        logAccess(&ctx, request.method.toString(), "/v1/sessions", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- GET /v1/sessions (list sessions for identity) ---
    if (request.method == .GET and http.api_router.matchRoute(request.uri.path, 1, "/sessions")) {
        if (state.session_store == null) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Sessions not enabled", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 404, request.headers.get("user-agent") orelse "");
            return;
        }

        // Requires bearer auth
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (!auth_result.ok) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 401, request.headers.get("user-agent") orelse "");
            return;
        }
        const identity = auth_result.token_hash orelse "-";

        const active_sessions = state.countSessionsByIdentity(allocator, identity) catch {
            try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to list sessions", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/sessions", 500, request.headers.get("user-agent") orelse "");
            return;
        };

        const resp_body = try std.fmt.allocPrint(allocator, "{{\"active_sessions\":{d}}}", .{active_sessions});
        defer allocator.free(resp_body);

        var response = http.Response.json(allocator, resp_body);
        defer response.deinit();
        _ = response.setConnection(keep_alive)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(200);
        logAccess(&ctx, request.method.toString(), "/v1/sessions", 200, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- POST /v1/cache/purge ---
    if (request.method == .POST and http.api_router.matchRoute(request.uri.path, 1, "/cache/purge")) {
        if (state.proxy_cache_store == null) {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Proxy cache not enabled", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/cache/purge", 404, request.headers.get("user-agent") orelse "");
            return;
        }

        const auth_result = authorizeRequest(cfg, &request.headers);
        if (!auth_result.ok) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/cache/purge", 401, request.headers.get("user-agent") orelse "");
            return;
        }
        ctx.setIdentity(auth_result.token_hash orelse "-");

        var purged: usize = 0;
        if (request.body) |body| {
            if (isJsonContentType(request.contentType())) {
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

        const resp_body = try std.fmt.allocPrint(allocator, "{{\"purged\":{d}}}", .{purged});
        defer allocator.free(resp_body);
        var response = http.Response.json(allocator, resp_body);
        defer response.deinit();
        _ = response.setConnection(keep_alive)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(200);
        logAccess(&ctx, request.method.toString(), "/v1/cache/purge", 200, request.headers.get("user-agent") orelse "");
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
            if (http.session.fromHeaders(&request.headers)) |session_token| {
                if (state.validateSessionIdentity(allocator, session_token)) |identity| {
                    defer allocator.free(identity);
                    ctx.setIdentity(identity);
                    cmd_authenticated = true;
                }
            }
        }
        if (!cmd_authenticated) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/commands", 401, request.headers.get("user-agent") orelse "");
            return;
        }

        // --- Content-Type validation ---
        if (!isJsonContentType(request.contentType())) {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Content-Type must be application/json", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/commands", 400, request.headers.get("user-agent") orelse "");
            return;
        }

        // --- Body parsing ---
        const cmd_body = request.body orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing request body", correlation_id, keep_alive, state);
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
            try sendApiError(allocator, writer, .bad_request, "invalid_request", msg, correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/commands", 400, request.headers.get("user-agent") orelse "");
            return;
        };
        defer cmd.deinit(allocator);

        // --- Idempotency (inline key overrides header) ---
        const effective_idem_key = cmd.idempotency_key orelse ctx.idempotency_key;
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
                logAccess(&ctx, request.method.toString(), "/v1/commands", cached.status, request.headers.get("user-agent") orelse "");
                return;
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
            try sendApiError(allocator, writer, .internal_server_error, "internal_error", "Failed to build upstream request", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/commands", 500, request.headers.get("user-agent") orelse "");
            return;
        };
        defer allocator.free(envelope);
        const upstream_path = cmd.command_type.upstreamPath();

        const proxy_cache_bypass = shouldBypassProxyCache(&request.headers) or effective_idem_key != null;
        const proxy_cache_key = if (cfg.proxy_cache_ttl_seconds > 0 and !proxy_cache_bypass)
            try buildProxyCacheKey(allocator, cfg.proxy_cache_key_template, request.method.toString(), "/v1/commands", envelope, ctx.identity, ctx.api_version)
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
                logAccess(&ctx, request.method.toString(), "/v1/commands", lookup.cached.status, request.headers.get("user-agent") orelse "");
                if (lookup.is_stale) {
                    spawnProxyCacheRefresh(
                        allocator,
                        cfg,
                        state,
                        cache_key,
                        .commands,
                        cfg.proxy_pass_commands_prefix,
                        upstream_path,
                        envelope,
                        client_ip,
                        ctx.identity,
                        ctx.api_version,
                    );
                }
                return;
            }

            if (!try state.proxyCacheTryLock(cache_key)) {
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
                    logAccess(&ctx, request.method.toString(), "/v1/commands", post_wait_lookup.cached.status, request.headers.get("user-agent") orelse "");
                    return;
                }
            }
            proxy_cache_locked = try state.proxyCacheTryLock(cache_key);
        }

        // --- Forward to upstream ---

        // --- Circuit breaker check ---
        if (!state.circuitTryAcquire()) {
            state.logger.warn(null, "circuit breaker open, rejecting /v1/commands", .{});
            try sendApiError(allocator, writer, .service_unavailable, "upstream_unavailable", "Upstream unavailable", correlation_id, keep_alive, state);
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

        const cmd_exec = proxyJsonExecute(
            allocator,
            cfg,
            .commands,
            cfg.proxy_pass_commands_prefix,
            upstream_path,
            envelope,
            correlation_id,
            client_ip,
            ctx.identity,
            ctx.api_version,
            request.headers.get("host"),
            request.headers.get("x-forwarded-for"),
            writer,
            state,
            effective_idem_key == null,
        ) catch |err| {
            state.circuitRecordFailure();
            state.logger.warn(null, "circuit breaker: recorded failure, state={s}", .{state.circuitStateName()});
            const mapped = mapProxyExecutionError(err);
            try sendApiError(allocator, writer, mapped.status, mapped.code, mapped.message, correlation_id, keep_alive, state);
            // Audit
            const cmd_audit = http.command.CommandAudit{
                .command = cmd.command_type.toString(),
                .correlation_id = correlation_id,
                .identity = ctx.identity orelse "-",
                .status = @intFromEnum(mapped.status),
                .latency_ms = ctx.elapsedMs(),
            };
            cmd_audit.log();
            return;
        };
        var cmd_final_status: u16 = undefined;
        var cmd_final_body: []const u8 = "";
        var cmd_final_content_type: []const u8 = JSON_CONTENT_TYPE;
        var cmd_final_content_disposition: ?[]const u8 = null;
        var cmd_final_content_type_alloc: ?[]u8 = null;
        var cmd_final_content_disposition_alloc: ?[]u8 = null;
        var cmd_error_body: ?[]const u8 = null;
        defer if (cmd_final_content_type_alloc) |ct| allocator.free(ct);
        defer if (cmd_final_content_disposition_alloc) |cd| allocator.free(cd);
        switch (cmd_exec) {
            .streamed_status => |status| {
                cmd_final_status = status;
                if (status >= 500) {
                    state.circuitRecordFailure();
                } else {
                    state.circuitRecordSuccess();
                }
                state.metricsRecord(status);

                const streamed_audit = http.command.CommandAudit{
                    .command = cmd.command_type.toString(),
                    .correlation_id = correlation_id,
                    .identity = ctx.identity orelse "-",
                    .status = status,
                    .latency_ms = ctx.elapsedMs(),
                };
                streamed_audit.log();
                logAccess(&ctx, request.method.toString(), "/v1/commands", status, request.headers.get("user-agent") orelse "");
                return;
            },
            .buffered => |proxy_result| {
                defer allocator.free(proxy_result.body);

                if (proxy_result.status >= 500) {
                    state.circuitRecordFailure();
                } else {
                    state.circuitRecordSuccess();
                }

                cmd_final_status = proxy_result.status;
                cmd_final_body = proxy_result.body;
                if (proxy_result.status != 200) {
                    allocator.free(proxy_result.content_type);
                    if (proxy_result.content_disposition) |cd| allocator.free(cd);
                    const mapped = mapUpstreamError(proxy_result.status);
                    cmd_final_status = mapped.status;
                    cmd_final_body = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
                    cmd_final_content_type = JSON_CONTENT_TYPE;
                    cmd_final_content_disposition = null;
                    cmd_error_body = cmd_final_body;
                } else {
                    cmd_final_content_type_alloc = proxy_result.content_type;
                    cmd_final_content_type = proxy_result.content_type;
                    if (proxy_result.content_disposition) |cd| {
                        cmd_final_content_disposition_alloc = cd;
                        cmd_final_content_disposition = cd;
                    } else {
                        cmd_final_content_disposition = null;
                    }
                }
            },
        }
        defer {
            if (cmd_error_body) |eb| allocator.free(eb);
        }

        // --- Compress and send ---
        const cmd_accept_encoding = request.headers.get("Accept-Encoding");
        const cmd_comp = http.compression.compressResponse(allocator, cmd_final_body, cmd_final_content_type, cmd_accept_encoding, state.compression_config);
        defer if (cmd_comp.body) |cb| allocator.free(cb);
        const cmd_resp_body = if (cmd_comp.body) |cb| cb else cmd_final_body;
        var response = http.Response.init(allocator);
        defer response.deinit();
        _ = response
            .setStatus(@enumFromInt(cmd_final_status))
            .setBody(cmd_resp_body)
            .setContentType(cmd_final_content_type)
            .setConnection(keep_alive)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        if (cmd_final_content_disposition) |cd| {
            _ = response.setHeader("Content-Disposition", cd);
        }
        if (cmd_comp.compressed and cmd_comp.encoding != null) {
            _ = response.setHeader("Content-Encoding", cmd_comp.encoding.?.headerValue());
        }
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(cmd_final_status);

        if (proxy_cache_key) |cache_key| {
            if (cmd_final_status == 200) {
                state.proxyCachePut(cache_key, cmd_final_status, cmd_final_body, cmd_final_content_type) catch |err| {
                    std.log.warn("proxy cache store error: {}", .{err});
                };
            }
        }

        // --- Store idempotency result ---
        if (effective_idem_key) |idem_key| {
            state.idempotencyPut(idem_key, cmd_final_status, cmd_final_body, JSON_CONTENT_TYPE) catch |err| {
                std.log.warn("idempotency store error: {}", .{err});
            };
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
                logAccess(&ctx, request.method.toString(), "/v1/chat", cached.status, request.headers.get("user-agent") orelse "");
                return;
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
            if (http.session.fromHeaders(&request.headers)) |session_token| {
                if (state.validateSessionIdentity(allocator, session_token)) |identity| {
                    defer allocator.free(identity);
                    ctx.setIdentity(identity);
                    authenticated = true;
                }
            }
        }
        if (!authenticated) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", 401, request.headers.get("user-agent") orelse "");
            return;
        }

        // --- Content-Type validation ---
        if (!isJsonContentType(request.contentType())) {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Content-Type must be application/json", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", 400, request.headers.get("user-agent") orelse "");
            return;
        }

        // --- Body validation ---
        const body = request.body orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing request body", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", 400, request.headers.get("user-agent") orelse "");
            return;
        };

        const proxy_cache_bypass = shouldBypassProxyCache(&request.headers) or ctx.idempotency_key != null;
        const proxy_cache_key = if (cfg.proxy_cache_ttl_seconds > 0 and !proxy_cache_bypass)
            try buildProxyCacheKey(allocator, cfg.proxy_cache_key_template, request.method.toString(), "/v1/chat", body, ctx.identity, ctx.api_version)
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
                logAccess(&ctx, request.method.toString(), "/v1/chat", lookup.cached.status, request.headers.get("user-agent") orelse "");
                if (lookup.is_stale) {
                    spawnProxyCacheRefresh(
                        allocator,
                        cfg,
                        state,
                        cache_key,
                        .chat,
                        cfg.proxy_pass_chat,
                        null,
                        body,
                        client_ip,
                        ctx.identity,
                        ctx.api_version,
                    );
                }
                return;
            }

            if (!try state.proxyCacheTryLock(cache_key)) {
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
                    logAccess(&ctx, request.method.toString(), "/v1/chat", post_wait_lookup.cached.status, request.headers.get("user-agent") orelse "");
                    return;
                }
            }
            proxy_cache_locked = try state.proxyCacheTryLock(cache_key);
        }

        const message = parseChatMessage(allocator, body, cfg.max_message_chars) catch |err| {
            const msg = switch (err) {
                error.EmptyMessage => "message must not be empty",
                error.MessageTooLarge => "message too long",
                else => "invalid chat payload",
            };
            try sendApiError(allocator, writer, .bad_request, "invalid_request", msg, correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", 400, request.headers.get("user-agent") orelse "");
            return;
        };

        // --- Circuit breaker check ---
        if (!state.circuitTryAcquire()) {
            state.logger.warn(null, "circuit breaker open, rejecting /v1/chat", .{});
            try sendApiError(allocator, writer, .service_unavailable, "upstream_unavailable", "Upstream unavailable", correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", 503, request.headers.get("user-agent") orelse "");
            return;
        }

        // --- Upstream proxy ---
        const chat_request_body = try std.fmt.allocPrint(allocator, "{{\"message\":{s}}}", .{std.json.fmt(message, .{})});
        defer allocator.free(chat_request_body);

        const chat_exec = proxyJsonExecute(
            allocator,
            cfg,
            .chat,
            cfg.proxy_pass_chat,
            null,
            chat_request_body,
            correlation_id,
            client_ip,
            ctx.identity,
            ctx.api_version,
            request.headers.get("host"),
            request.headers.get("x-forwarded-for"),
            writer,
            state,
            ctx.idempotency_key == null,
        ) catch |err| {
            state.circuitRecordFailure();
            state.logger.warn(null, "circuit breaker: recorded failure, state={s}", .{state.circuitStateName()});
            const mapped = mapProxyExecutionError(err);
            try sendApiError(allocator, writer, mapped.status, mapped.code, mapped.message, correlation_id, keep_alive, state);
            logAccess(&ctx, request.method.toString(), "/v1/chat", @intFromEnum(mapped.status), request.headers.get("user-agent") orelse "");
            return;
        };
        defer allocator.free(message);

        var final_status: u16 = undefined;
        var final_body: []const u8 = "";
        var final_content_type: []const u8 = JSON_CONTENT_TYPE;
        var final_content_disposition: ?[]const u8 = null;
        var final_content_type_alloc: ?[]u8 = null;
        var final_content_disposition_alloc: ?[]u8 = null;
        var error_body_to_free: ?[]const u8 = null;
        defer if (final_content_type_alloc) |ct| allocator.free(ct);
        defer if (final_content_disposition_alloc) |cd| allocator.free(cd);
        switch (chat_exec) {
            .streamed_status => |status| {
                final_status = status;
                if (status >= 500) {
                    state.circuitRecordFailure();
                } else {
                    state.circuitRecordSuccess();
                }
                state.metricsRecord(status);
                logAccess(&ctx, request.method.toString(), "/v1/chat", status, request.headers.get("user-agent") orelse "");
                return;
            },
            .buffered => |proxy_result| {
                defer allocator.free(proxy_result.body);

                if (proxy_result.status >= 500) {
                    state.circuitRecordFailure();
                } else {
                    state.circuitRecordSuccess();
                }

                final_status = proxy_result.status;
                final_body = proxy_result.body;
                if (proxy_result.status != 200) {
                    allocator.free(proxy_result.content_type);
                    if (proxy_result.content_disposition) |cd| allocator.free(cd);
                    const mapped = mapUpstreamError(proxy_result.status);
                    final_status = mapped.status;
                    final_body = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
                    final_content_type = JSON_CONTENT_TYPE;
                    final_content_disposition = null;
                    error_body_to_free = final_body;
                } else {
                    final_content_type_alloc = proxy_result.content_type;
                    final_content_type = proxy_result.content_type;
                    if (proxy_result.content_disposition) |cd| {
                        final_content_disposition_alloc = cd;
                        final_content_disposition = cd;
                    } else {
                        final_content_disposition = null;
                    }
                }
            },
        }
        defer {
            if (error_body_to_free) |eb| allocator.free(eb);
        }

        // --- Compress and send ---
        const chat_accept_encoding = request.headers.get("Accept-Encoding");
        const chat_comp = http.compression.compressResponse(allocator, final_body, final_content_type, chat_accept_encoding, state.compression_config);
        defer if (chat_comp.body) |cb| allocator.free(cb);
        const chat_resp_body = if (chat_comp.body) |cb| cb else final_body;
        var response = http.Response.init(allocator);
        defer response.deinit();
        _ = response
            .setStatus(@enumFromInt(final_status))
            .setBody(chat_resp_body)
            .setContentType(final_content_type)
            .setConnection(keep_alive)
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        if (final_content_disposition) |cd| {
            _ = response.setHeader("Content-Disposition", cd);
        }
        if (chat_comp.compressed and chat_comp.encoding != null) {
            _ = response.setHeader("Content-Encoding", chat_comp.encoding.?.headerValue());
        }
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(final_status);

        if (proxy_cache_key) |cache_key| {
            if (final_status == 200) {
                state.proxyCachePut(cache_key, final_status, final_body, final_content_type) catch |err| {
                    std.log.warn("proxy cache store error: {}", .{err});
                };
            }
        }

        // --- Store idempotency result ---
        if (ctx.idempotency_key) |idem_key| {
            state.idempotencyPut(idem_key, final_status, final_body, JSON_CONTENT_TYPE) catch |err| {
                std.log.warn("idempotency store error: {}", .{err});
            };
        }

        logAccess(&ctx, request.method.toString(), "/v1/chat", final_status, request.headers.get("user-agent") orelse "");
        return;
    }

    if (serveTryFilesFallback(allocator, cfg, request.method.toString(), request.uri.path, correlation_id, keep_alive, writer, state)) |status| {
        state.metricsRecord(status);
        logAccess(&ctx, request.method.toString(), request.uri.path, status, request.headers.get("user-agent") orelse "");
        return;
    } else |_| {}

    try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive, state);
    logAccess(&ctx, request.method.toString(), request.uri.path, 404, request.headers.get("user-agent") orelse "");
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
    var last_ping_ms = last_activity_ms;

    while (!http.shutdown.isShutdownRequested()) {
        const frame = http.websocket.readFrame(conn, allocator, cfg.websocket_max_frame_size) catch |err| switch (err) {
            error.ConnectionClosed => return,
            error.WouldBlock => {
                const now_ms = http.event_loop.monotonicMs();
                if (cfg.websocket_ping_interval_ms > 0 and now_ms - last_ping_ms >= cfg.websocket_ping_interval_ms) {
                    try http.websocket.writeFrame(writer, .ping, "", true);
                    last_ping_ms = now_ms;
                }
                if (cfg.websocket_idle_timeout_ms > 0 and now_ms - last_activity_ms >= cfg.websocket_idle_timeout_ms) return;
                continue;
            },
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
                        try state.event_hub.publish("ws.chat.responses", result.body, http.event_loop.monotonicMs());
                    } else {
                        try state.event_hub.publish("ws.commands.responses", result.body, http.event_loop.monotonicMs());
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

        var response = http.Response.ok(allocator, if (std.ascii.eqlIgnoreCase(method, "HEAD")) "" else file_data);
        defer response.deinit();
        _ = response
            .setContentType("application/octet-stream")
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

const BackendProtocol = enum {
    fastcgi,
    uwsgi,
    scgi,
};

fn handleBackendProtocolRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    upstream: []const u8,
    method: []const u8,
    path: []const u8,
    body: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
    kind: BackendProtocol,
) !void {
    const endpoint = std.mem.trim(u8, upstream, " \t\r\n");
    if (endpoint.len == 0) {
        try sendApiError(allocator, writer, .not_implemented, "tool_unavailable", "Backend upstream not configured", correlation_id, keep_alive, state);
        return;
    }
    const wire = switch (kind) {
        .fastcgi => try http.fastcgi.buildRequest(allocator, method, "/index.php", path, body),
        .uwsgi => try http.uwsgi.buildPacket(allocator, method, path, body),
        .scgi => try http.scgi.buildRequest(allocator, method, path, body),
    };
    defer allocator.free(wire);
    const resp = executeRawProtocolRequest(allocator, endpoint, wire) catch |err| {
        std.log.warn("backend protocol request failed: {}", .{err});
        try sendApiError(allocator, writer, .bad_gateway, "tool_unavailable", "Backend protocol request failed", correlation_id, keep_alive, state);
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

fn executeRawProtocolRequest(allocator: std.mem.Allocator, endpoint: []const u8, payload: []const u8) ![]u8 {
    const ep = try http.memcached.parseEndpoint(endpoint);
    const stream = try std.net.tcpConnectToHost(allocator, ep.host, ep.port);
    defer stream.close();
    try stream.writer().writeAll(payload);
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    var buf: [16 * 1024]u8 = undefined;
    const n = try stream.read(&buf);
    if (n > 0) try out.appendSlice(buf[0..n]);
    return out.toOwnedSlice();
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

fn hostMatchesServerNames(cfg: *const edge_config.EdgeConfig, request: *const http.Request) bool {
    if (cfg.server_names.len == 0) return true;
    const raw_host = request.headers.get("host") orelse return false;
    const host = stripHostPort(raw_host);
    for (cfg.server_names) |pattern| {
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

const DeviceRegistration = struct {
    device_id: []const u8,
    public_key: []const u8,
};

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
        return allocator.dupe(u8, auth_res.token_hash.?);
    }
    if (http.session.fromHeaders(&request.headers)) |session_token| {
        if (state.validateSessionIdentity(allocator, session_token)) |identity| return identity;
    }
    return null;
}

fn evaluatePolicy(
    cfg: *const edge_config.EdgeConfig,
    method: []const u8,
    path: []const u8,
    identity: ?[]const u8,
    device_id: ?[]const u8,
    headers: *const http.Headers,
) ?[]const u8 {
    if (cfg.policy_approval_routes_raw.len > 0 and routeNeedsApproval(method, path, cfg.policy_approval_routes_raw)) {
        const approval = headers.get("x-approval-token") orelse return "Approval required";
        if (std.mem.trim(u8, approval, " \t\r\n").len == 0) return "Approval required";
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
            const approval = headers.get("x-approval-token") orelse return "Approval required";
            if (std.mem.trim(u8, approval, " \t\r\n").len == 0) return "Approval required";
        }
        if (allowed_hours.len > 0 and !timeWindowAllows(allowed_hours)) return "Route not allowed at this time";
        if (device_pattern.len > 0) {
            const did = device_id orelse return "Device restriction denied";
            if (!http.rewrite.regexMatches(device_pattern, did)) return "Device restriction denied";
        }
    }
    return null;
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
        task.allocator.free(task.cache_key);
        if (task.suffix_path) |suffix| task.allocator.free(suffix);
        task.allocator.free(task.payload);
        task.allocator.free(task.client_ip);
        if (task.identity) |id| task.allocator.free(id);
        task.state.proxyCacheUnlock(task.cache_key);
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
    allocator: std.mem.Allocator,
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
    if (!(state.proxyCacheTryLock(cache_key) catch false)) return;

    const task = allocator.create(ProxyCacheRefreshTask) catch {
        state.proxyCacheUnlock(cache_key);
        return;
    };
    errdefer allocator.destroy(task);

    const owned_key = allocator.dupe(u8, cache_key) catch {
        state.proxyCacheUnlock(cache_key);
        return;
    };
    errdefer allocator.free(owned_key);
    const owned_payload = allocator.dupe(u8, payload) catch {
        state.proxyCacheUnlock(cache_key);
        return;
    };
    errdefer allocator.free(owned_payload);
    const owned_ip = allocator.dupe(u8, client_ip) catch {
        state.proxyCacheUnlock(cache_key);
        return;
    };
    errdefer allocator.free(owned_ip);
    const owned_suffix = if (suffix_path) |suffix|
        allocator.dupe(u8, suffix) catch {
            state.proxyCacheUnlock(cache_key);
            return;
        }
    else
        null;
    errdefer if (owned_suffix) |s| allocator.free(s);
    const owned_identity = if (identity) |id|
        allocator.dupe(u8, id) catch {
            state.proxyCacheUnlock(cache_key);
            return;
        }
    else
        null;
    errdefer if (owned_identity) |id| allocator.free(id);

    task.* = .{
        .allocator = allocator,
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
        allocator.free(owned_key);
        allocator.free(owned_payload);
        allocator.free(owned_ip);
        if (owned_suffix) |s| allocator.free(s);
        if (owned_identity) |id| allocator.free(id);
        allocator.destroy(task);
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
    const configured_upstream_count = if (upstream_pool.primary_urls.len > 0 or upstream_pool.backup_urls.len > 0)
        upstream_pool.primary_urls.len + upstream_pool.backup_urls.len
    else
        @as(usize, 1);
    const max_attempts = @min(configured_attempts, configured_upstream_count);
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
    defer allocator.free(resolved_target.url);

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

    var server_header_buffer: [16 * 1024]u8 = undefined;
    const uri = try std.Uri.parse(resolved_target.url);
    const unix_conn: ?*std.http.Client.Connection = if (resolved_target.unix_socket_path) |socket_path|
        try state.upstream_client.connectUnix(socket_path)
    else
        null;
    var req = try state.upstream_client.open(.POST, uri, .{
        .server_header_buffer = &server_header_buffer,
        .connection = unix_conn,
        .headers = .{ .content_type = .{ .override = "application/json" } },
        .extra_headers = extra_headers.items,
        .keep_alive = true,
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
    const upstream_content_type = req.response.content_type orelse JSON_CONTENT_TYPE;
    const upstream_content_disposition = req.response.content_disposition;
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
        },
    };
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

const ResolvedProxyTarget = struct {
    url: []u8,
    upstream_host: []const u8,
    unix_socket_path: ?[]const u8 = null,
};

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
    status: http.status.StatusCode,
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

        const n = conn.read(buf[total_read..]) catch |err| switch (err) {
            error.WouldBlock => return 0,
            else => return err,
        };
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
    const url = try buildHealthProbeUrl(allocator, "http://127.0.0.1:8080/", "/health");
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
    var pool = ConnectionSessionPool.init(std.testing.allocator, 4);
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
        .internal_redirect_rules = &[_]edge_config.EdgeConfig.InternalRedirectRule{},
        .named_locations = &[_]edge_config.EdgeConfig.NamedLocation{},
        .mirror_rules = &[_]edge_config.EdgeConfig.MirrorRule{},
        .fastcgi_upstream = "",
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
        .internal_redirect_rules = &[_]edge_config.EdgeConfig.InternalRedirectRule{},
        .named_locations = &[_]edge_config.EdgeConfig.NamedLocation{},
        .mirror_rules = &[_]edge_config.EdgeConfig.MirrorRule{},
        .fastcgi_upstream = "",
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
