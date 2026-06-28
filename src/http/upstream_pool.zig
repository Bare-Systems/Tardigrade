//! Owned upstream connection pool (#141).
//!
//! A single shared, mutex-guarded map of `host:port → { idle connections,
//! per-host counters }` reused across all worker threads. Restores keep-alive
//! reuse on top of the manual bounded transport from #196. See
//! `docs/UPSTREAM_POOLING.md` for the design rationale and deferred work.
//!
//! Scope: plain HTTP/1.1 TCP connections. TLS/mTLS and Unix-socket pooling are
//! deferred. The pool stores raw fds and timestamps; the caller owns the HTTP
//! exchange and decides reusability before calling `release`.
//!
//! Phase 1b adds per-upstream counters (new/reused/idle/active/stale), an
//! `active` gauge (connections currently checked out), and a connect-latency
//! histogram, surfaced as per-upstream labelled Prometheus series.

const std = @import("std");
const compat = @import("../zig_compat.zig");

pub const Config = struct {
    enabled: bool = true,
    /// Maximum idle connections cached per origin.
    max_idle_per_host: usize = 32,
    /// Evict an idle connection unused for at least this long.
    idle_timeout_ms: u64 = 90_000,
    /// Hard cap on total connection age (0 = unlimited).
    max_lifetime_ms: u64 = 0,
};

/// A pooled connection: an owned socket fd plus age bookkeeping.
pub const PooledConn = struct {
    fd: std.posix.fd_t,
    created_ms: u64,
    last_used_ms: u64,
};

/// Per-origin counters. `idle`/`active` are gauges; the rest are monotonic.
pub const HostStats = struct {
    new_total: u64 = 0,
    reused_total: u64 = 0,
    stale_retries_total: u64 = 0,
    active: u64 = 0,
    idle: u64 = 0,
};

/// Aggregate (all-origin) counters, summed from the per-host map.
pub const Stats = struct {
    new_total: u64 = 0,
    reused_total: u64 = 0,
    stale_retries_total: u64 = 0,
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

const HostEntry = struct {
    idle: std.ArrayList(PooledConn) = .empty,
    stats: HostStats = .{},
};

fn closeFd(fd: std.posix.fd_t) void {
    _ = std.c.close(fd);
}

pub const UpstreamPool = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    config: Config,
    hosts: std.StringHashMap(HostEntry),
    connect_latency_buckets: [connect_latency_bounds_ms.len + 1]u64 = [_]u64{0} ** (connect_latency_bounds_ms.len + 1),
    connect_latency_count: u64 = 0,
    connect_latency_sum_ms: u64 = 0,

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
            for (entry.value_ptr.idle.items) |conn| closeFd(conn.fd);
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

    /// Take a still-fresh idle connection for `key`, dropping any that have aged
    /// out. On success the connection becomes `active` and the caller owns the
    /// fd until it calls `release`.
    pub fn acquire(self: *UpstreamPool, key: []const u8, now_ms: u64) ?PooledConn {
        if (!self.config.enabled) return null;
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.hosts.getPtr(key) orelse return null;
        while (entry.idle.pop()) |conn| {
            if (self.isExpired(conn, now_ms)) {
                closeFd(conn.fd);
                continue;
            }
            entry.stats.reused_total += 1;
            entry.stats.active += 1;
            return conn;
        }
        return null;
    }

    /// Record that the caller opened a fresh connection for `key` (an idle-pool
    /// miss). The connection is `active` until `release`.
    pub fn noteNewConnection(self: *UpstreamPool, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.hostEntry(key) orelse return;
        entry.stats.new_total += 1;
        entry.stats.active += 1;
    }

    /// Hand a checked-out connection back. It is returned to the idle pool when
    /// `reusable` and there is room and it has not aged out; otherwise it is
    /// closed. Either way the origin's `active` gauge is decremented.
    pub fn release(self: *UpstreamPool, key: []const u8, conn: PooledConn, reusable: bool, now_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.hostEntry(key) orelse {
            closeFd(conn.fd);
            return;
        };
        if (entry.stats.active > 0) entry.stats.active -= 1;

        if (!self.config.enabled or !reusable or self.isExpired(conn, now_ms) or
            entry.idle.items.len >= self.config.max_idle_per_host)
        {
            closeFd(conn.fd);
            return;
        }
        var updated = conn;
        updated.last_used_ms = now_ms;
        entry.idle.append(self.allocator, updated) catch {
            closeFd(conn.fd);
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
                    closeFd(list.orderedRemove(i).fd);
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
            agg.stale_retries_total += s.stale_retries_total;
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

    pub fn connectLatencySnapshot(self: *UpstreamPool) ConnectLatencySnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .buckets = self.connect_latency_buckets,
            .count = self.connect_latency_count,
            .sum_ms = self.connect_latency_sum_ms,
        };
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

test "acquire returns null on an empty pool" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    try testing.expect(pool.acquire("a:1", 1000) == null);
    try testing.expectEqual(@as(u64, 0), pool.aggregateStats().reused_total);
}

test "new connection then release pools it; acquire reuses and tracks active" {
    var pool = UpstreamPool.init(testing.allocator, .{});
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    pool.noteNewConnection("h:80");
    try testing.expectEqual(@as(u64, 1), pool.aggregateStats().active);
    pool.release("h:80", .{ .fd = fds[0], .created_ms = 1000, .last_used_ms = 1000 }, true, 1000);

    var agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 0), agg.active);
    try testing.expectEqual(@as(u64, 1), agg.idle);
    try testing.expectEqual(@as(u64, 1), agg.new_total);

    const got = pool.acquire("h:80", 1500) orelse return error.TestExpectedReuse;
    try testing.expectEqual(fds[0], got.fd);
    agg = pool.aggregateStats();
    try testing.expectEqual(@as(u64, 1), agg.reused_total);
    try testing.expectEqual(@as(u64, 1), agg.active);
    try testing.expectEqual(@as(u64, 0), agg.idle);
    pool.release("h:80", got, false, 1500); // close it
    try testing.expectEqual(@as(u64, 0), pool.aggregateStats().active);
}

test "release drops a connection past the idle timeout" {
    var pool = UpstreamPool.init(testing.allocator, .{ .idle_timeout_ms = 1000 });
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    pool.noteNewConnection("h:80");
    // released 2s later, past the 1s idle timeout → closed, not pooled.
    pool.release("h:80", .{ .fd = fds[0], .created_ms = 0, .last_used_ms = 0 }, true, 2000);
    try testing.expectEqual(@as(u64, 0), pool.aggregateStats().idle);
}

test "release honors max_idle_per_host" {
    var pool = UpstreamPool.init(testing.allocator, .{ .max_idle_per_host = 1 });
    defer pool.deinit();
    const a = try testPair();
    const b = try testPair();
    defer _ = std.c.close(a[1]);
    defer _ = std.c.close(b[1]);

    pool.release("h:80", .{ .fd = a[0], .created_ms = 0, .last_used_ms = 0 }, true, 0);
    pool.release("h:80", .{ .fd = b[0], .created_ms = 0, .last_used_ms = 0 }, true, 0);
    try testing.expectEqual(@as(u64, 1), pool.aggregateStats().idle);
}

test "reapIdle evicts aged connections and refreshes the gauge" {
    var pool = UpstreamPool.init(testing.allocator, .{ .idle_timeout_ms = 1000 });
    defer pool.deinit();
    const fds = try testPair();
    defer _ = std.c.close(fds[1]);

    pool.release("h:80", .{ .fd = fds[0], .created_ms = 0, .last_used_ms = 0 }, true, 0);
    pool.reapIdle(500);
    try testing.expectEqual(@as(u64, 1), pool.aggregateStats().idle);
    pool.reapIdle(2000);
    try testing.expectEqual(@as(u64, 0), pool.aggregateStats().idle);
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
