//! Owned upstream connection pool (#141).
//!
//! A single shared, mutex-guarded map of `host:port → { idle connections,
//! per-host counters }` reused across all worker threads. Restores keep-alive
//! reuse on top of the manual bounded transport from #196. See
//! `docs/UPSTREAM_POOLING.md` for the design rationale and deferred work.
//!
//! Scope: HTTP/1.1 over TCP, plain or TLS (#141 Phase 1c). For TLS the pooled
//! entry owns the OpenSSL connection; the key is scheme-prefixed so plain and
//! TLS connections to the same host are never confused. Unix-socket pooling is
//! deferred. The caller owns the HTTP exchange and decides reusability before
//! calling `release`.
//!
//! Phase 1b adds per-upstream counters (new/reused/idle/active/stale), an
//! `active` gauge (connections currently checked out), and a connect-latency
//! histogram, surfaced as per-upstream labelled Prometheus series.

const std = @import("std");
const compat = @import("../zig_compat.zig");
const tls_termination = @import("tls_backend.zig");

pub const Config = struct {
    enabled: bool = true,
    /// Maximum idle connections cached per origin.
    max_idle_per_host: usize = 32,
    /// Evict an idle connection unused for at least this long.
    idle_timeout_ms: u64 = 90_000,
    /// Hard cap on total connection age (0 = unlimited).
    max_lifetime_ms: u64 = 0,
    /// Hard cap on concurrently checked-out connections per origin
    /// (0 = unlimited). Enforced **fail-fast** (#239): `checkout`/`reserveSlot`
    /// return `error.UpstreamAtCapacity` instead of queueing, and the proxy
    /// maps it to 503 `upstream_saturated`. In the thread-per-connection
    /// worker model, blocking here would let one slow origin absorb the whole
    /// worker pool — queueing/watermark semantics are #140's scope.
    max_active_per_host: usize = 0,
};

/// Identifier of the worker thread that last released a connection. Used purely
/// to classify a reuse as local (same thread parked and reclaimed it) vs
/// cross-worker (one thread parked it, another reclaimed it — the shared-pool
/// behaviour #147 set out to measure). Not used for socket ownership.
pub fn currentWorkerId() u64 {
    return @intCast(std.Thread.getCurrentId());
}

/// A pooled connection: an owned transport plus age bookkeeping. `stream` may
/// wrap a raw fd (data-plane, via `netStreamFromFd`) or an event-loop stream
/// (FastCGI, via `connectUnixSocket`/`tcpConnectToHost`). For TLS upstreams
/// `tls` holds the heap-owned OpenSSL connection (allocated with the pool's
/// allocator); the pool deinits and frees it when the connection is closed.
/// `tls` is null for plain HTTP and FastCGI. `released_by` records the worker
/// that last parked it (set on `release`, read on `acquire`).
pub const PooledConn = struct {
    stream: compat.NetStream,
    tls: ?*tls_termination.UpstreamTlsConn = null,
    created_ms: u64,
    last_used_ms: u64,
    released_by: u64 = 0,
};

/// Per-origin counters. `idle`/`active` are gauges; the rest are monotonic.
/// `reused_local_total` + `reused_cross_worker_total` partition `reused_total`.
pub const HostStats = struct {
    new_total: u64 = 0,
    reused_total: u64 = 0,
    reused_local_total: u64 = 0,
    reused_cross_worker_total: u64 = 0,
    stale_retries_total: u64 = 0,
    /// Checkouts rejected fail-fast at `max_active_per_host` (#239).
    at_capacity_total: u64 = 0,
    active: u64 = 0,
    idle: u64 = 0,
};

/// Aggregate (all-origin) counters, summed from the per-host map.
pub const Stats = struct {
    new_total: u64 = 0,
    reused_total: u64 = 0,
    reused_local_total: u64 = 0,
    reused_cross_worker_total: u64 = 0,
    stale_retries_total: u64 = 0,
    at_capacity_total: u64 = 0,
    idle: u64 = 0,
    active: u64 = 0,
};

/// A copy of one origin's identity + counters for rendering. `host` is owned by
/// the caller and freed via `freeHostSnapshots`.
pub const HostSnapshot = struct {
    host: []u8,
    stats: HostStats,
};

/// Connect-latency histogram buckets (milliseconds, cumulative `le` bounds).
pub const connect_latency_bounds_ms = [_]u64{ 1, 5, 10, 25, 50, 100, 250, 500, 1000 };

pub const ConnectLatencySnapshot = struct {
    /// Per-bucket (non-cumulative) counts; index `bounds.len` is the overflow.
    buckets: [connect_latency_bounds_ms.len + 1]u64,
    count: u64,
    sum_ms: u64,
};

/// Request-latency histogram buckets (milliseconds, cumulative `le` bounds).
/// Wider tail than connect latency: a request includes the full response
/// (buffered read or streaming relay), not just the TCP handshake.
pub const request_latency_bounds_ms = [_]u64{ 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 10_000 };

/// One completed-exchange latency histogram (#145 — "upstream p99 by
/// protocol"). Recorded per negotiated protocol on successful exchanges only,
/// measured from starting the exchange on an acquired connection to the
/// response being fully received (buffered path) or fully relayed downstream
/// (streaming path).
pub const RequestLatencyHist = struct {
    /// Per-bucket (non-cumulative) counts; index `bounds.len` is the overflow.
    buckets: [request_latency_bounds_ms.len + 1]u64 = [_]u64{0} ** (request_latency_bounds_ms.len + 1),
    count: u64 = 0,
    sum_ms: u64 = 0,

    fn record(self: *RequestLatencyHist, latency_ms: u64) void {
        self.count += 1;
        self.sum_ms += latency_ms;
        for (request_latency_bounds_ms, 0..) |bound, i| {
            if (latency_ms <= bound) {
                self.buckets[i] += 1;
                return;
            }
        }
        self.buckets[request_latency_bounds_ms.len] += 1;
    }
};

pub const RequestLatencySnapshot = struct {
    h1: RequestLatencyHist,
    h2: RequestLatencyHist,
};

const HostEntry = struct {
    idle: std.ArrayList(PooledConn) = .empty,
    stats: HostStats = .{},
};

pub const UpstreamPool = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    config: Config,
    hosts: std.StringHashMap(HostEntry),
    connect_latency_buckets: [connect_latency_bounds_ms.len + 1]u64 = [_]u64{0} ** (connect_latency_bounds_ms.len + 1),
    connect_latency_count: u64 = 0,
    connect_latency_sum_ms: u64 = 0,
    /// Completed-exchange latency per negotiated protocol (#145), mutex-guarded
    /// like the connect-latency histogram.
    request_latency_h1: RequestLatencyHist = .{},
    request_latency_h2: RequestLatencyHist = .{},
    /// Upstream requests by negotiated application protocol (#145). Atomic so
    /// the hot proxy path need not take the pool mutex just to count.
    protocol_h1_requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    protocol_h2_requests: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Count streaming uploads that requested h2/h2c but still had to use h1
    /// because the h2 pool was unavailable for the exchange.
    h2_streaming_upload_fallbacks: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init(allocator: std.mem.Allocator, config: Config) UpstreamPool {
        return .{
            .allocator = allocator,
            .config = config,
            .hosts = std.StringHashMap(HostEntry).init(allocator),
        };
    }

    pub fn deinit(self: *UpstreamPool) void {
        var it = self.hosts.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.idle.items) |conn| self.closeConn(conn);
            entry.value_ptr.idle.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.hosts.deinit();
        self.* = undefined;
    }

    fn isExpired(self: *const UpstreamPool, conn: PooledConn, now_ms: u64) bool {
        if (self.config.idle_timeout_ms > 0 and now_ms -| conn.last_used_ms >= self.config.idle_timeout_ms) return true;
        if (self.config.max_lifetime_ms > 0 and now_ms -| conn.created_ms >= self.config.max_lifetime_ms) return true;
        return false;
    }

    /// Close a connection: tear down the owned TLS connection (if any), then
    /// close the transport.
    fn closeConn(self: *UpstreamPool, conn: PooledConn) void {
        if (conn.tls) |t| {
            t.deinit();
            self.allocator.destroy(t);
        }
        conn.stream.close();
    }

    /// Get or create the per-host entry for `key`, duping the key on insert.
    /// Returns null only on allocation failure. Caller holds the mutex.
    fn hostEntry(self: *UpstreamPool, key: []const u8) ?*HostEntry {
        const gop = self.hosts.getOrPut(key) catch return null;
        if (!gop.found_existing) {
            const owned_key = self.allocator.dupe(u8, key) catch {
                _ = self.hosts.remove(key);
                return null;
            };
            gop.key_ptr.* = owned_key;
            gop.value_ptr.* = .{};
        }
        return gop.value_ptr;
    }

    /// Reuse-or-reserve checkout with fail-fast active-cap enforcement (#239).
    /// Returns a still-fresh pooled connection (now counted `active`), or null
    /// after **reserving** an active slot for the caller to open a fresh
    /// connection — on that path the caller MUST call `noteNewConnection` once
    /// connected, or `releaseSlot` if the connect fails, so the reservation is
    /// not leaked. Reserving before connecting (rather than counting after) is
    /// what makes the cap a real hard cap: concurrent callers cannot race past
    /// it during their connect/handshake window.
    ///
    /// When the pool is disabled, returns null without reserving (the caller's
    /// fresh connection is untracked, as before). At `max_active_per_host`
    /// the checkout fails fast with `error.UpstreamAtCapacity` instead of
    /// queueing; see `Config.max_active_per_host` for the rationale.
    pub fn checkout(self: *UpstreamPool, key: []const u8, now_ms: u64) error{UpstreamAtCapacity}!?PooledConn {
        if (!self.config.enabled) return null;
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.hostEntry(key) orelse return null; // OOM: proceed untracked
        if (self.config.max_active_per_host > 0 and entry.stats.active >= self.config.max_active_per_host) {
            entry.stats.at_capacity_total += 1;
            return error.UpstreamAtCapacity;
        }
        while (entry.idle.pop()) |conn| {
            if (self.isExpired(conn, now_ms)) {
                self.closeConn(conn);
                continue;
            }
            entry.stats.reused_total += 1;
            if (conn.released_by == currentWorkerId()) {
                entry.stats.reused_local_total += 1;
            } else {
                entry.stats.reused_cross_worker_total += 1;
            }
            entry.stats.active += 1;
            entry.stats.idle = entry.idle.items.len;
            return conn;
        }
        entry.stats.idle = 0;
        entry.stats.active += 1; // reservation for the caller's fresh connection
        return null;
    }

    /// Reserve an active slot for a fresh connection without considering idle
    /// reuse (the stale-retry path deliberately wants a new connection). Same
    /// contract as `checkout`'s null return: pair with `noteNewConnection` or
    /// `releaseSlot`.
    pub fn reserveSlot(self: *UpstreamPool, key: []const u8) error{UpstreamAtCapacity}!void {
        if (!self.config.enabled) return;
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.hostEntry(key) orelse return;
        if (self.config.max_active_per_host > 0 and entry.stats.active >= self.config.max_active_per_host) {
            entry.stats.at_capacity_total += 1;
            return error.UpstreamAtCapacity;
        }
        entry.stats.active += 1;
    }

    /// Undo a `checkout`/`reserveSlot` reservation after a fresh connect
    /// failed. No-op for untracked (disabled/OOM) checkouts.
    pub fn releaseSlot(self: *UpstreamPool, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.hosts.getPtr(key) orelse return;
        if (entry.stats.active > 0) entry.stats.active -= 1;
    }

    /// Record that the caller opened a fresh connection for `key`. The active
    /// slot was already reserved by `checkout`/`reserveSlot`; this only counts.
    pub fn noteNewConnection(self: *UpstreamPool, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.hostEntry(key) orelse return;
        entry.stats.new_total += 1;
    }

    /// Hand a checked-out connection back. It is returned to the idle pool when
    /// `reusable` and there is room and it has not aged out; otherwise it is
    /// closed. Either way the origin's `active` gauge is decremented.
    pub fn release(self: *UpstreamPool, key: []const u8, conn: PooledConn, reusable: bool, now_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.hostEntry(key) orelse {
            self.closeConn(conn);
            return;
        };
        if (entry.stats.active > 0) entry.stats.active -= 1;

        if (!self.config.enabled or !reusable or self.isExpired(conn, now_ms) or
            entry.idle.items.len >= self.config.max_idle_per_host)
        {
            self.closeConn(conn);
            return;
        }
        var updated = conn;
        updated.last_used_ms = now_ms;
        updated.released_by = currentWorkerId();
        entry.idle.append(self.allocator, updated) catch {
            self.closeConn(conn);
            return;
        };
        entry.stats.idle = entry.idle.items.len;
    }

    pub fn recordStaleRetry(self: *UpstreamPool, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.hostEntry(key) orelse return;
        entry.stats.stale_retries_total += 1;
    }

    pub fn recordConnectLatency(self: *UpstreamPool, latency_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.connect_latency_count += 1;
        self.connect_latency_sum_ms += latency_ms;
        for (connect_latency_bounds_ms, 0..) |bound, i| {
            if (latency_ms <= bound) {
                self.connect_latency_buckets[i] += 1;
                return;
            }
        }
        self.connect_latency_buckets[connect_latency_bounds_ms.len] += 1;
    }

    /// Close and drop every idle connection that has aged out, refreshing each
    /// origin's idle gauge. Intended to run from the gateway maintenance tick.
    pub fn reapIdle(self: *UpstreamPool, now_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.hosts.iterator();
        while (it.next()) |entry| {
            const list = &entry.value_ptr.idle;
            var i: usize = 0;
            while (i < list.items.len) {
                if (self.isExpired(list.items[i], now_ms)) {
                    self.closeConn(list.orderedRemove(i));
                } else {
                    i += 1;
                }
            }
            entry.value_ptr.stats.idle = list.items.len;
        }
    }

    /// Aggregate counters across all origins.
    pub fn aggregateStats(self: *UpstreamPool) Stats {
        self.mutex.lock();
        defer self.mutex.unlock();
        var agg = Stats{};
        var it = self.hosts.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr.stats;
            agg.new_total += s.new_total;
            agg.reused_total += s.reused_total;
            agg.reused_local_total += s.reused_local_total;
            agg.reused_cross_worker_total += s.reused_cross_worker_total;
            agg.stale_retries_total += s.stale_retries_total;
            agg.at_capacity_total += s.at_capacity_total;
            agg.active += s.active;
            agg.idle += entry.value_ptr.idle.items.len;
        }
        return agg;
    }

    /// Snapshot per-origin counters for rendering. Caller frees with
    /// `freeHostSnapshots`.
    pub fn snapshotHosts(self: *UpstreamPool, allocator: std.mem.Allocator) ![]HostSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        var out = std.array_list.Managed(HostSnapshot).init(allocator);
        errdefer {
            for (out.items) |snap| allocator.free(snap.host);
            out.deinit();
        }
        var it = self.hosts.iterator();
        while (it.next()) |entry| {
            var stats = entry.value_ptr.stats;
            stats.idle = entry.value_ptr.idle.items.len;
            const host = try allocator.dupe(u8, entry.key_ptr.*);
            try out.append(.{ .host = host, .stats = stats });
        }
        return out.toOwnedSlice();
    }

    /// Count an upstream request by negotiated protocol (#145).
    pub fn recordProtocol(self: *UpstreamPool, is_h2: bool) void {
        if (is_h2) {
            _ = self.protocol_h2_requests.fetchAdd(1, .monotonic);
        } else {
            _ = self.protocol_h1_requests.fetchAdd(1, .monotonic);
        }
    }

    /// Total upstream requests served per negotiated protocol.
    pub fn protocolCounts(self: *const UpstreamPool) struct { h1: u64, h2: u64 } {
        return .{
            .h1 = self.protocol_h1_requests.load(.monotonic),
            .h2 = self.protocol_h2_requests.load(.monotonic),
        };
    }

    pub fn recordH2StreamingUploadFallback(self: *UpstreamPool) void {
        _ = self.h2_streaming_upload_fallbacks.fetchAdd(1, .monotonic);
    }

    pub fn h2StreamingUploadFallbacks(self: *const UpstreamPool) u64 {
        return self.h2_streaming_upload_fallbacks.load(.monotonic);
    }

    pub fn connectLatencySnapshot(self: *UpstreamPool) ConnectLatencySnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .buckets = self.connect_latency_buckets,
            .count = self.connect_latency_count,
            .sum_ms = self.connect_latency_sum_ms,
        };
    }

    /// Record one completed upstream exchange for the per-protocol latency
    /// histogram (#145 — "upstream p99 by protocol").
    pub fn recordRequestLatency(self: *UpstreamPool, is_h2: bool, latency_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (is_h2) {
            self.request_latency_h2.record(latency_ms);
        } else {
            self.request_latency_h1.record(latency_ms);
        }
    }

    pub fn requestLatencySnapshot(self: *UpstreamPool) RequestLatencySnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{ .h1 = self.request_latency_h1, .h2 = self.request_latency_h2 };
    }
};

pub fn freeHostSnapshots(allocator: std.mem.Allocator, snaps: []HostSnapshot) void {
    for (snaps) |snap| allocator.free(snap.host);
    allocator.free(snaps);
}

const testing = std.testing;

fn testPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    try testing.expect(std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) == 0);
    return fds;
}

test "checkout on an empty pool reserves a slot for a fresh connection" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    try testing.expect((try pool.checkout("a:1", 1000)) == null);
    var agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 0), agg.reused_total);
    try testing.expectEqual(@as(u64, 1), agg.active); // the reservation
    pool.releaseSlot("a:1"); // fresh connect "failed" — undo
    agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 0), agg.active);
}

test "max_active_per_host fails checkout fast and counts at_capacity" {
    var pool = UpstreamPool.init(testing.allocator, .{ .max_active_per_host = 2 });
    defer pool.deinit();
    try testing.expect((try pool.checkout("h:80", 0)) == null); // reserve 1
    try pool.reserveSlot("h:80"); // reserve 2 — at the cap now
    try testing.expectError(error.UpstreamAtCapacity, pool.checkout("h:80", 0));
    try testing.expectError(error.UpstreamAtCapacity, pool.reserveSlot("h:80"));
    const agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 2), agg.active);
    try testing.expectEqual(@as(u64, 2), agg.at_capacity_total);
    // Releasing one slot frees capacity again.
    pool.releaseSlot("h:80");
    try testing.expect((try pool.checkout("h:80", 0)) == null);
    // Other origins are unaffected by this origin's saturation.
    try testing.expect((try pool.checkout("other:80", 0)) == null);
    pool.releaseSlot("other:80");
}

test "new connection then release pools it; acquire reuses and tracks active" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    try testing.expect((try pool.checkout("h:80", 1000)) == null); // reserve
    pool.noteNewConnection("h:80");
    try testing.expectEqual(@as(u64, 1), pool.aggregateStats().active);
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 1000, .last_used_ms = 1000 }, true, 1000);

    var agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 0), agg.active);
    try testing.expectEqual(@as(u64, 1), agg.idle);
    try testing.expectEqual(@as(u64, 1), agg.new_total);

    const got = (try pool.checkout("h:80", 1500)) orelse return error.TestExpectedReuse;
    try testing.expectEqual(fds[0], got.stream.handle);
    agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 1), agg.reused_total);
    try testing.expectEqual(@as(u64, 1), agg.active);
    try testing.expectEqual(@as(u64, 0), agg.idle);
    pool.release("h:80", got, false, 1500); // close it
    try testing.expectEqual(@as(u64, 0), pool.aggregateStats().active);
}

test "reuse on the releasing thread counts as local" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    try pool.reserveSlot("h:80");
    pool.noteNewConnection("h:80");
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 0, .last_used_ms = 0 }, true, 0);
    // Same thread reclaims it → local reuse.
    const got = (try pool.checkout("h:80", 1)) orelse return error.TestExpectedReuse;
    const agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 1), agg.reused_total);
    try testing.expectEqual(@as(u64, 1), agg.reused_local_total);
    try testing.expectEqual(@as(u64, 0), agg.reused_cross_worker_total);
    pool.release("h:80", got, false, 1);
}

test "reuse after a different worker parked it counts as cross-worker" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    // Simulate a connection parked by another worker: release stamps the current
    // thread id, so forge a different one directly on the idle entry.
    try pool.reserveSlot("h:80");
    pool.noteNewConnection("h:80");
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 0, .last_used_ms = 0 }, true, 0);
    pool.hosts.getPtr("h:80").?.idle.items[0].released_by = currentWorkerId() +% 1;

    const got = (try pool.checkout("h:80", 1)) orelse return error.TestExpectedReuse;
    defer pool.release("h:80", got, false, 1); // close the checked-out fd
    const agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 1), agg.reused_cross_worker_total);
    try testing.expectEqual(@as(u64, 0), agg.reused_local_total);
}

test "release drops a connection past the idle timeout" {
    var pool = UpstreamPool.init(testing.allocator, .{ .idle_timeout_ms = 1000 });
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    try pool.reserveSlot("h:80");
    pool.noteNewConnection("h:80");
    // released 2s later, past the 1s idle timeout → closed, not pooled.
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 0, .last_used_ms = 0 }, true, 2000);
    try testing.expectEqual(@as(u64, 0), pool.aggregateStats().idle);
}

test "release honors max_idle_per_host" {
    var pool = UpstreamPool.init(testing.allocator, .{ .max_idle_per_host = 1 });
    defer pool.deinit();
    const a = try testPair();
    const b = try testPair();
    defer _ = std.c.close(a[1]);
    defer _ = std.c.close(b[1]);

    pool.release("h:80", .{ .stream = compat.netStreamFromFd(a[0]), .created_ms = 0, .last_used_ms = 0 }, true, 0);
    pool.release("h:80", .{ .stream = compat.netStreamFromFd(b[0]), .created_ms = 0, .last_used_ms = 0 }, true, 0);
    try testing.expectEqual(@as(u64, 1), pool.aggregateStats().idle);
}

test "reapIdle evicts aged connections and refreshes the gauge" {
    var pool = UpstreamPool.init(testing.allocator, .{ .idle_timeout_ms = 1000 });
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    pool.release("h:80", .{ .stream = compat.netStreamFromFd(fds[0]), .created_ms = 0, .last_used_ms = 0 }, true, 0);
    pool.reapIdle(500);
    try testing.expectEqual(@as(u64, 1), pool.aggregateStats().idle);
    pool.reapIdle(2000);
    try testing.expectEqual(@as(u64, 0), pool.aggregateStats().idle);
}

test "request-latency histogram buckets by protocol" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    pool.recordRequestLatency(false, 3); // h1, <= 5 bucket
    pool.recordRequestLatency(true, 40); // h2, <= 50 bucket
    pool.recordRequestLatency(true, 99_999); // h2, overflow

    const snap = pool.requestLatencySnapshot();
    try testing.expectEqual(@as(u64, 1), snap.h1.count);
    try testing.expectEqual(@as(u64, 3), snap.h1.sum_ms);
    try testing.expectEqual(@as(u64, 1), snap.h1.buckets[1]); // le=5
    try testing.expectEqual(@as(u64, 2), snap.h2.count);
    try testing.expectEqual(@as(u64, 1), snap.h2.buckets[request_latency_bounds_ms.len]); // overflow
}

test "h2 streaming upload fallback counter is atomic and monotonic" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    try testing.expectEqual(@as(u64, 0), pool.h2StreamingUploadFallbacks());
    pool.recordH2StreamingUploadFallback();
    pool.recordH2StreamingUploadFallback();
    try testing.expectEqual(@as(u64, 2), pool.h2StreamingUploadFallbacks());
}

test "per-host snapshot and connect-latency histogram" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    pool.noteNewConnection("a:80");
    pool.noteNewConnection("b:80");
    pool.recordStaleRetry("a:80");
    pool.recordConnectLatency(3); // <= 5 bucket
    pool.recordConnectLatency(40); // <= 50 bucket
    pool.recordConnectLatency(5000); // overflow

    const snaps = try pool.snapshotHosts(testing.allocator);
    defer freeHostSnapshots(testing.allocator, snaps);
    try testing.expectEqual(@as(usize, 2), snaps.len);

    const lat = pool.connectLatencySnapshot();
    try testing.expectEqual(@as(u64, 3), lat.count);
    try testing.expectEqual(@as(u64, 5043), lat.sum_ms);
    try testing.expectEqual(@as(u64, 1), lat.buckets[connect_latency_bounds_ms.len]); // overflow
}
