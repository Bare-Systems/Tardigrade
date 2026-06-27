//! Owned upstream connection pool (#141 Phase 1).
//!
//! Restores keep-alive reuse on top of the manual bounded transport introduced
//! in #196. A single shared, mutex-guarded map of `host:port → LIFO idle
//! connections` is reused across all worker threads. See
//! `docs/UPSTREAM_POOLING.md` for the design rationale and deferred work.
//!
//! Scope: plain HTTP/1.1 TCP connections. TLS/mTLS and Unix-socket pooling are
//! deferred. The pool stores raw fds and timestamps; the caller owns the HTTP
//! exchange and decides reusability before calling `release`.

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

pub const Stats = struct {
    /// Connections opened (cache misses).
    new_total: u64 = 0,
    /// Connections handed back out of the idle pool (cache hits).
    reused_total: u64 = 0,
    /// Idempotent retries after a reused connection was found dead.
    stale_retries_total: u64 = 0,
    /// Connections currently held idle in the pool.
    idle: u64 = 0,
};

fn closeFd(fd: std.posix.fd_t) void {
    _ = std.c.close(fd);
}

pub const UpstreamPool = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    config: Config,
    idle: std.StringHashMap(std.ArrayList(PooledConn)),
    stats: Stats = .{},

    pub fn init(allocator: std.mem.Allocator, config: Config) UpstreamPool {
        return .{
            .allocator = allocator,
            .config = config,
            .idle = std.StringHashMap(std.ArrayList(PooledConn)).init(allocator),
        };
    }

    pub fn deinit(self: *UpstreamPool) void {
        var it = self.idle.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |conn| closeFd(conn.fd);
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.idle.deinit();
        self.* = undefined;
    }

    fn isExpired(self: *const UpstreamPool, conn: PooledConn, now_ms: u64) bool {
        if (self.config.idle_timeout_ms > 0 and now_ms -| conn.last_used_ms >= self.config.idle_timeout_ms) return true;
        if (self.config.max_lifetime_ms > 0 and now_ms -| conn.created_ms >= self.config.max_lifetime_ms) return true;
        return false;
    }

    /// Take a still-fresh idle connection for `key`, dropping any that have aged
    /// out. Returns null when the pool is disabled or has no usable connection.
    /// On success the caller owns the fd and must `release` or close it.
    pub fn acquire(self: *UpstreamPool, key: []const u8, now_ms: u64) ?PooledConn {
        if (!self.config.enabled) return null;
        self.mutex.lock();
        defer self.mutex.unlock();
        const list = self.idle.getPtr(key) orelse return null;
        while (list.pop()) |conn| {
            self.stats.idle -|= 1;
            if (self.isExpired(conn, now_ms)) {
                closeFd(conn.fd);
                continue;
            }
            self.stats.reused_total += 1;
            return conn;
        }
        return null;
    }

    /// Return a connection to the idle pool, or close it if the pool is
    /// disabled/full or the connection has aged out. Stamps `last_used_ms`.
    pub fn release(self: *UpstreamPool, key: []const u8, conn: PooledConn, now_ms: u64) void {
        if (!self.config.enabled or self.isExpired(conn, now_ms)) {
            closeFd(conn.fd);
            return;
        }
        self.mutex.lock();
        defer self.mutex.unlock();

        const gop = self.idle.getOrPut(key) catch {
            closeFd(conn.fd);
            return;
        };
        if (!gop.found_existing) {
            const owned_key = self.allocator.dupe(u8, key) catch {
                _ = self.idle.remove(key);
                closeFd(conn.fd);
                return;
            };
            gop.key_ptr.* = owned_key;
            gop.value_ptr.* = .empty;
        }
        if (gop.value_ptr.items.len >= self.config.max_idle_per_host) {
            closeFd(conn.fd);
            return;
        }
        var updated = conn;
        updated.last_used_ms = now_ms;
        gop.value_ptr.append(self.allocator, updated) catch {
            closeFd(conn.fd);
            return;
        };
        self.stats.idle += 1;
    }

    pub fn recordNew(self: *UpstreamPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.new_total += 1;
    }

    pub fn recordStaleRetry(self: *UpstreamPool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stats.stale_retries_total += 1;
    }

    /// Close and drop every idle connection that has aged out. Intended to run
    /// from the gateway maintenance tick.
    pub fn reapIdle(self: *UpstreamPool, now_ms: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.idle.iterator();
        while (it.next()) |entry| {
            const list = entry.value_ptr;
            var i: usize = 0;
            while (i < list.items.len) {
                if (self.isExpired(list.items[i], now_ms)) {
                    const conn = list.orderedRemove(i);
                    closeFd(conn.fd);
                    self.stats.idle -|= 1;
                } else {
                    i += 1;
                }
            }
        }
    }

    pub fn snapshotStats(self: *UpstreamPool) Stats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.stats;
    }
};

test "acquire returns null on an empty pool and counts nothing" {
    var pool = UpstreamPool.init(std.testing.allocator, .{});
    defer pool.deinit();
    try std.testing.expect(pool.acquire("a:1", 1000) == null);
    const s = pool.snapshotStats();
    try std.testing.expectEqual(@as(u64, 0), s.reused_total);
}

test "release then acquire reuses the same connection" {
    var pool = UpstreamPool.init(std.testing.allocator, .{});
    defer pool.deinit();
    // Use a socketpair fd so close() is harmless and the fd is valid.
    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) == 0);
    defer _ = std.c.close(fds[1]);

    pool.release("h:80", .{ .fd = fds[0], .created_ms = 1000, .last_used_ms = 1000 }, 1000);
    try std.testing.expectEqual(@as(u64, 1), pool.snapshotStats().idle);

    const got = pool.acquire("h:80", 1500) orelse return error.TestExpectedReuse;
    try std.testing.expectEqual(fds[0], got.fd);
    try std.testing.expectEqual(@as(u64, 1), pool.snapshotStats().reused_total);
    try std.testing.expectEqual(@as(u64, 0), pool.snapshotStats().idle);
    closeFd(got.fd);
}

test "acquire drops a connection past the idle timeout" {
    var pool = UpstreamPool.init(std.testing.allocator, .{ .idle_timeout_ms = 1000 });
    defer pool.deinit();
    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) == 0);
    defer _ = std.c.close(fds[1]);

    pool.release("h:80", .{ .fd = fds[0], .created_ms = 0, .last_used_ms = 0 }, 0);
    // 2s later, past the 1s idle timeout → not reusable.
    try std.testing.expect(pool.acquire("h:80", 2000) == null);
    try std.testing.expectEqual(@as(u64, 0), pool.snapshotStats().idle);
    try std.testing.expectEqual(@as(u64, 0), pool.snapshotStats().reused_total);
}

test "release honors max_idle_per_host" {
    var pool = UpstreamPool.init(std.testing.allocator, .{ .max_idle_per_host = 1 });
    defer pool.deinit();
    var a: [2]std.posix.fd_t = undefined;
    var b: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &a) == 0);
    try std.testing.expect(std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &b) == 0);
    defer _ = std.c.close(a[1]);
    defer _ = std.c.close(b[1]);

    pool.release("h:80", .{ .fd = a[0], .created_ms = 0, .last_used_ms = 0 }, 0);
    // Second release exceeds the cap → connection is closed, not pooled.
    pool.release("h:80", .{ .fd = b[0], .created_ms = 0, .last_used_ms = 0 }, 0);
    try std.testing.expectEqual(@as(u64, 1), pool.snapshotStats().idle);
}

test "reapIdle evicts aged connections" {
    var pool = UpstreamPool.init(std.testing.allocator, .{ .idle_timeout_ms = 1000 });
    defer pool.deinit();
    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) == 0);
    defer _ = std.c.close(fds[1]);

    pool.release("h:80", .{ .fd = fds[0], .created_ms = 0, .last_used_ms = 0 }, 0);
    pool.reapIdle(500); // not yet aged
    try std.testing.expectEqual(@as(u64, 1), pool.snapshotStats().idle);
    pool.reapIdle(2000); // past idle timeout
    try std.testing.expectEqual(@as(u64, 0), pool.snapshotStats().idle);
}
