const compat = @import("zig_compat");
/// DNS-based upstream service discovery for Tardigrade.
///
/// Two modes share one live-set structure:
///
///  * A/AAAA mode (`host`): resolves a hostname to `http[s]://addr:port` URLs.
///  * SRV mode (`srv_name`, #766): resolves `_service._proto.name` SRV records,
///    resolves each target to A/AAAA, and builds the live set from SRV
///    semantics. The lowest-priority group is the primary set, served by a
///    weighted round-robin `slots` schedule; every higher-priority group is a
///    backup, used only when all primaries are unhealthy.
///
/// Stale policy (SRV mode): NXDOMAIN, or an SRV answer that is empty / the
/// RFC 2782 "." target, is authoritative and clears the live set at once.
/// SERVFAIL, timeouts and "no target resolved" keep the last good set for up
/// to `stale_max_ms` since the last success, retrying on a short backoff, then
/// clear it. The set therefore never outlives `stale_max_ms` of DNS failure.
///
/// Memory safety: callers receive URL slices that outlive the discovery lock,
/// so URL strings are interned and only freed `retire_grace_ms` after they
/// leave the live set. Refresh swaps the whole snapshot under the mutex.
///
/// Readers hold `disc.mutex` while reading `urls`, `backup_urls` and `slots`.
const std = @import("std");
const dns_srv = @import("dns_srv.zig");

/// How long a URL string stays valid after leaving the live set.
pub const retire_grace_ms: u64 = 10 * 60 * 1000;
/// Hard caps keeping the live set and the weighted schedule bounded.
pub const max_endpoints = 64;
const max_slots = 256;
const max_addrs_per_target = 8;

pub const Config = struct {
    /// Hostname to resolve for A/AAAA mode (empty string disables it).
    host: []const u8 = "",
    /// Port number to attach to each resolved address (A/AAAA mode).
    port: u16 = 80,
    /// Use HTTPS for discovered upstreams.
    tls: bool = false,
    /// A/AAAA: re-resolve interval. SRV: maximum refresh interval.
    refresh_interval_ms: u64 = 30_000,
    /// SRV owner name, e.g. `_api._tcp.service.internal`. Wins over `host`.
    srv_name: []const u8 = "",
    /// SRV: lower bound on the TTL-derived refresh interval.
    min_refresh_ms: u64 = 5_000,
    /// SRV: how long the last good set survives continuous DNS failure.
    stale_max_ms: u64 = 300_000,
    /// SRV: per-nameserver UDP timeout.
    query_timeout_ms: u32 = 2_000,
};

/// One resolved SRV endpoint, before grouping.
pub const Endpoint = struct {
    priority: u16,
    weight: u16,
    url: []const u8,
};

pub const DnsDiscovery = struct {
    allocator: std.mem.Allocator,
    config: Config,
    mutex: compat.Mutex,
    /// Primary endpoints (unique, slices into interned strings).
    urls: std.ArrayList([]const u8),
    /// Lower-precedence SRV endpoints, ordered by ascending priority.
    backup_urls: std.ArrayList([]const u8),
    /// Weighted round-robin schedule: indexes into `urls`.
    slots: std.ArrayList(u16),
    /// Interned URL strings with retirement time (0 = live).
    interned: std.ArrayList(Interned),
    /// Epoch-ms timestamp of the last successful resolution.
    last_refresh_ms: u64,
    /// Monotonic ms when the next refresh is due (SRV mode; 0 = now).
    next_refresh_ms: u64,
    /// Number of times the URL set has changed since init.
    change_count: u64,
    refresh_total: u64,
    refresh_failures_total: u64,
    consecutive_failures: u32,
    /// True while serving the last good set after a DNS failure.
    stale: bool,
    last_error: []const u8,
    /// Set while a refresh thread is in flight.
    refreshing: std.atomic.Value(bool),

    const Interned = struct { url: []u8, retired_at_ms: u64 };

    pub fn init(allocator: std.mem.Allocator, config: Config) DnsDiscovery {
        return .{
            .allocator = allocator,
            .config = config,
            .mutex = .{},
            .urls = .empty,
            .backup_urls = .empty,
            .slots = .empty,
            .interned = .empty,
            .last_refresh_ms = 0,
            .next_refresh_ms = 0,
            .change_count = 0,
            .refresh_total = 0,
            .refresh_failures_total = 0,
            .consecutive_failures = 0,
            .stale = false,
            .last_error = "",
            .refreshing = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *DnsDiscovery) void {
        // Let an in-flight detached refresh finish (bounded by DNS timeouts).
        var spins: usize = 0;
        while (self.refreshing.load(.acquire) and spins < 50_000_000) : (spins += 1) std.Thread.yield() catch {};
        for (self.interned.items) |e| self.allocator.free(e.url);
        self.interned.deinit(self.allocator);
        self.urls.deinit(self.allocator);
        self.backup_urls.deinit(self.allocator);
        self.slots.deinit(self.allocator);
    }

    pub fn enabled(self: *const DnsDiscovery) bool {
        return self.config.host.len > 0 or self.config.srv_name.len > 0;
    }

    pub fn srvMode(self: *const DnsDiscovery) bool {
        return self.config.srv_name.len > 0;
    }

    /// Returns true when the next refresh is due.
    pub fn needsRefresh(self: *const DnsDiscovery, now_ms: u64) bool {
        if (!self.enabled()) return false;
        if (self.srvMode()) return now_ms >= self.next_refresh_ms;
        if (self.last_refresh_ms == 0) return true;
        return now_ms -| self.last_refresh_ms >= self.config.refresh_interval_ms;
    }

    /// Resolve and swap in a new live set. Blocking; never call it from the
    /// event loop thread. Thread-safe.
    pub fn refresh(self: *DnsDiscovery, now_ms: u64) void {
        if (self.srvMode()) return self.refreshSrv(now_ms);
        if (self.config.host.len == 0) return;
        var eps: std.ArrayList(Endpoint) = .empty;
        defer freeEndpoints(self.allocator, &eps);
        self.collectAddrs(self.config.host, self.config.port, 0, 1, &eps);
        if (eps.items.len == 0) {
            std.debug.print("dns_discovery: resolve {s}:{d} failed\n", .{ self.config.host, self.config.port });
            return;
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        self.applySuccess(now_ms, eps.items, self.config.refresh_interval_ms);
    }

    fn refreshSrv(self: *DnsDiscovery, now_ms: u64) void {
        const resp = dns_srv.lookupSrv(self.allocator, self.config.srv_name, self.config.query_timeout_ms) catch |err| {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.applyFailure(now_ms, err == error.NxDomain, @errorName(err));
            return;
        };
        defer resp.deinit(self.allocator);

        var eps: std.ArrayList(Endpoint) = .empty;
        defer freeEndpoints(self.allocator, &eps);
        var unavailable = true;
        for (resp.records) |rec| {
            if (rec.target.len == 0) continue; // RFC 2782 "." = unavailable
            unavailable = false;
            self.collectAddrs(rec.target, rec.port, rec.priority, rec.weight, &eps);
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        if (unavailable) return self.applyFailure(now_ms, true, "no_records");
        if (eps.items.len == 0) return self.applyFailure(now_ms, false, "no_targets_resolved");
        const ttl_ms = @as(u64, resp.min_ttl) * 1000;
        self.applySuccess(now_ms, eps.items, ttl_ms);
    }

    /// Resolve `host` to A/AAAA and append `Endpoint`s (weight split across
    /// the target's addresses so a multi-address target keeps its SRV weight).
    fn collectAddrs(self: *DnsDiscovery, host: []const u8, port: u16, priority: u16, weight: u16, eps: *std.ArrayList(Endpoint)) void {
        var addrs: [compat.max_resolved_addresses]std.Io.net.IpAddress = undefined;
        const resolved = compat.resolveHostAddresses(host, port, &addrs) catch return;
        const n = @min(resolved.len, max_addrs_per_target);
        const per_addr: u16 = @intCast(@max(1, @as(u32, weight) / @as(u32, @intCast(n))));
        for (resolved[0..n]) |a| {
            if (eps.items.len >= max_endpoints) return;
            const url = formatUrl(self.allocator, self.config.tls, a) catch return;
            eps.append(self.allocator, .{ .priority = priority, .weight = per_addr, .url = url }) catch {
                self.allocator.free(url);
                return;
            };
        }
    }

    /// Install a fresh snapshot. Caller holds `mutex`.
    pub fn applySuccess(self: *DnsDiscovery, now_ms: u64, eps: []const Endpoint, ttl_ms: u64) void {
        self.refresh_total += 1;
        self.consecutive_failures = 0;
        self.stale = false;
        self.last_error = "";
        self.last_refresh_ms = now_ms;
        self.next_refresh_ms = now_ms + self.nextDelay(now_ms, ttl_ms);

        var lowest: u16 = std.math.maxInt(u16);
        for (eps) |e| lowest = @min(lowest, e.priority);
        var prim: std.ArrayList([]const u8) = .empty;
        defer prim.deinit(self.allocator);
        var weights: std.ArrayList(u16) = .empty;
        defer weights.deinit(self.allocator);
        var back: std.ArrayList([]const u8) = .empty;
        defer back.deinit(self.allocator);
        // Backups ordered by ascending priority.
        var prio_floor: u32 = @as(u32, lowest) + 1;
        for (eps) |e| if (e.priority == lowest) {
            const url = self.intern(e.url) orelse return;
            if (containsUrl(prim.items, url)) continue;
            prim.append(self.allocator, url) catch return;
            weights.append(self.allocator, e.weight) catch return;
        };
        while (prio_floor <= std.math.maxInt(u16)) {
            var next: u32 = std.math.maxInt(u32);
            for (eps) |e| if (e.priority >= prio_floor) {
                next = @min(next, e.priority);
            };
            if (next == std.math.maxInt(u32)) break;
            for (eps) |e| if (e.priority == next) {
                const url = self.intern(e.url) orelse return;
                if (containsUrl(prim.items, url) or containsUrl(back.items, url)) continue;
                back.append(self.allocator, url) catch return;
            };
            prio_floor = next + 1;
        }
        var sched: std.ArrayList(u16) = .empty;
        defer sched.deinit(self.allocator);
        buildSchedule(self.allocator, weights.items, &sched) catch return;

        const changed = !sameUrls(self.urls.items, prim.items) or !sameUrls(self.backup_urls.items, back.items);
        // Atomic swap of every live-set field (caller holds the mutex).
        std.mem.swap(std.ArrayList([]const u8), &self.urls, &prim);
        std.mem.swap(std.ArrayList([]const u8), &self.backup_urls, &back);
        std.mem.swap(std.ArrayList(u16), &self.slots, &sched);
        if (changed) {
            self.change_count += 1;
            std.debug.print("dns_discovery: {s} resolved to {d} primary + {d} backup upstream(s) (change #{d})\n", .{
                self.sourceName(), self.urls.items.len, self.backup_urls.items.len, self.change_count,
            });
        }
        self.retireUnused(now_ms);
    }

    /// Record a failed refresh. `authoritative` (NXDOMAIN / empty answer)
    /// clears the set; otherwise it is kept until `stale_max_ms` elapses.
    /// Caller holds `mutex`.
    pub fn applyFailure(self: *DnsDiscovery, now_ms: u64, authoritative: bool, reason: []const u8) void {
        self.refresh_failures_total += 1;
        self.consecutive_failures +|= 1;
        self.last_error = reason;
        const backoff = @min(self.config.refresh_interval_ms, @max(self.config.min_refresh_ms, 1_000) << @intCast(@min(self.consecutive_failures, 6)));
        self.next_refresh_ms = now_ms + self.jitter(now_ms, backoff);
        const have = self.urls.items.len + self.backup_urls.items.len > 0;
        const expired = self.last_refresh_ms == 0 or now_ms -| self.last_refresh_ms > self.config.stale_max_ms;
        if (have and (authoritative or expired)) {
            self.urls.clearRetainingCapacity();
            self.backup_urls.clearRetainingCapacity();
            self.slots.clearRetainingCapacity();
            self.change_count += 1;
            self.stale = false;
            std.debug.print("dns_discovery: {s} cleared ({s})\n", .{ self.sourceName(), reason });
            self.retireUnused(now_ms);
        } else if (have) {
            self.stale = true;
        }
    }

    fn sourceName(self: *const DnsDiscovery) []const u8 {
        return if (self.srvMode()) self.config.srv_name else self.config.host;
    }

    /// TTL-aware delay clamped to [min_refresh_ms, refresh_interval_ms] with
    /// +-10% jitter. A zero TTL falls back to the configured maximum.
    fn nextDelay(self: *const DnsDiscovery, now_ms: u64, ttl_ms: u64) u64 {
        if (!self.srvMode()) return self.config.refresh_interval_ms;
        const hi = @max(self.config.refresh_interval_ms, self.config.min_refresh_ms);
        const base = if (ttl_ms == 0) hi else std.math.clamp(ttl_ms, self.config.min_refresh_ms, hi);
        return self.jitter(now_ms, base);
    }

    fn jitter(self: *const DnsDiscovery, now_ms: u64, base: u64) u64 {
        _ = self;
        const span = base / 5; // total +-10% window
        if (span == 0) return base;
        const r = (now_ms *% 0x9E3779B97F4A7C15) >> 33;
        return base - span / 2 + r % (span + 1);
    }

    fn intern(self: *DnsDiscovery, url: []const u8) ?[]const u8 {
        for (self.interned.items) |*e| {
            if (std.mem.eql(u8, e.url, url)) {
                e.retired_at_ms = 0;
                return e.url;
            }
        }
        const owned = self.allocator.dupe(u8, url) catch return null;
        self.interned.append(self.allocator, .{ .url = owned, .retired_at_ms = 0 }) catch {
            self.allocator.free(owned);
            return null;
        };
        return owned;
    }

    /// Mark interned strings absent from the live set as retired and free
    /// those retired longer than `retire_grace_ms`.
    fn retireUnused(self: *DnsDiscovery, now_ms: u64) void {
        var i: usize = 0;
        while (i < self.interned.items.len) {
            const e = &self.interned.items[i];
            const live = containsUrl(self.urls.items, e.url) or containsUrl(self.backup_urls.items, e.url);
            if (live) {
                e.retired_at_ms = 0;
            } else if (e.retired_at_ms == 0) {
                e.retired_at_ms = @max(now_ms, 1);
            } else if (now_ms -| e.retired_at_ms > retire_grace_ms) {
                self.allocator.free(e.url);
                _ = self.interned.swapRemove(i);
                continue;
            }
            i += 1;
        }
    }

    /// Copy current primary URL strings. Caller owns the slice and each string.
    /// Must NOT be called while holding self.mutex.
    pub fn copyUrls(self: *DnsDiscovery, allocator: std.mem.Allocator) ![][]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const out = try allocator.alloc([]const u8, self.urls.items.len);
        var done: usize = 0;
        errdefer {
            for (out[0..done]) |u| allocator.free(u);
            allocator.free(out);
        }
        for (self.urls.items, 0..) |url, i| {
            out[i] = try allocator.dupe(u8, url);
            done += 1;
        }
        return out;
    }
};

fn freeEndpoints(allocator: std.mem.Allocator, eps: *std.ArrayList(Endpoint)) void {
    for (eps.items) |e| allocator.free(e.url);
    eps.deinit(allocator);
}

fn containsUrl(list: []const []const u8, url: []const u8) bool {
    for (list) |u| if (std.mem.eql(u8, u, url)) return true;
    return false;
}

fn sameUrls(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a) |ua| if (!containsUrl(b, ua)) return false;
    return true;
}

fn formatUrl(allocator: std.mem.Allocator, tls: bool, addr: std.Io.net.IpAddress) ![]u8 {
    const scheme: []const u8 = if (tls) "https" else "http";
    return switch (addr) {
        .ip4 => |ip4| std.fmt.allocPrint(allocator, "{s}://{d}.{d}.{d}.{d}:{d}", .{
            scheme, ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3], ip4.port,
        }),
        .ip6 => |ip6| std.fmt.allocPrint(allocator, "{s}://[{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}]:{d}", .{
            scheme,
            std.mem.readInt(u16, ip6.bytes[0..2], .big),
            std.mem.readInt(u16, ip6.bytes[2..4], .big),
            std.mem.readInt(u16, ip6.bytes[4..6], .big),
            std.mem.readInt(u16, ip6.bytes[6..8], .big),
            std.mem.readInt(u16, ip6.bytes[8..10], .big),
            std.mem.readInt(u16, ip6.bytes[10..12], .big),
            std.mem.readInt(u16, ip6.bytes[12..14], .big),
            std.mem.readInt(u16, ip6.bytes[14..16], .big),
            ip6.port,
        }),
    };
}

fn gcd(a: u32, b: u32) u32 {
    var x = a;
    var y = b;
    while (y != 0) {
        const t = x % y;
        x = y;
        y = t;
    }
    return x;
}

/// Smooth weighted round-robin schedule over `weights` (zero is treated as
/// one, per RFC 2782's "small chance" for weight 0). Weights are reduced by
/// their GCD and scaled down so the schedule has at most `max_slots` entries.
pub fn buildSchedule(allocator: std.mem.Allocator, weights: []const u16, out: *std.ArrayList(u16)) !void {
    if (weights.len == 0) return;
    var w: [max_endpoints]u32 = undefined;
    const n = @min(weights.len, max_endpoints);
    var g: u32 = 0;
    for (weights[0..n], 0..) |x, i| {
        w[i] = @max(x, 1);
        g = gcd(g, w[i]);
    }
    var total: u32 = 0;
    for (w[0..n]) |*x| {
        x.* /= g;
        total += x.*;
    }
    if (total > max_slots) {
        const div = (total + max_slots - 1) / max_slots;
        total = 0;
        for (w[0..n]) |*x| {
            x.* = @max(1, x.* / div);
            total += x.*;
        }
    }
    var cur = [_]i64{0} ** max_endpoints;
    var s: u32 = 0;
    while (s < total) : (s += 1) {
        var best: usize = 0;
        for (w[0..n], 0..) |x, i| {
            cur[i] += x;
            if (cur[i] > cur[best]) best = i;
        }
        cur[best] -= total;
        try out.append(allocator, @intCast(best));
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────
const testing = std.testing;

test "needsRefresh when disabled" {
    const config: Config = .{ .host = "", .port = 8080, .tls = false, .refresh_interval_ms = 30_000 };
    var disc = DnsDiscovery.init(testing.allocator, config);
    defer disc.deinit();
    try testing.expect(!disc.needsRefresh(0));
    try testing.expect(!disc.needsRefresh(1_000_000));
}

test "needsRefresh when never refreshed" {
    const config: Config = .{ .host = "localhost", .port = 8080, .tls = false, .refresh_interval_ms = 30_000 };
    var disc = DnsDiscovery.init(testing.allocator, config);
    defer disc.deinit();
    try testing.expect(disc.needsRefresh(0));
}

test "needsRefresh respects interval" {
    const config: Config = .{ .host = "localhost", .port = 8080, .tls = false, .refresh_interval_ms = 30_000 };
    var disc = DnsDiscovery.init(testing.allocator, config);
    defer disc.deinit();
    disc.last_refresh_ms = 10_000;
    try testing.expect(!disc.needsRefresh(10_000 + 29_999));
    try testing.expect(disc.needsRefresh(10_000 + 30_000));
}

fn ep(prio: u16, weight: u16, url: []const u8) Endpoint {
    return .{ .priority = prio, .weight = weight, .url = url };
}

test "buildSchedule honours weights, interleaves, and bounds size" {
    var out: std.ArrayList(u16) = .empty;
    defer out.deinit(testing.allocator);
    try buildSchedule(testing.allocator, &.{ 60, 30, 0 }, &out);
    var counts = [_]u32{ 0, 0, 0 };
    for (out.items) |i| counts[i] += 1;
    // 60:30:1 -> total 91, no GCD reduction.
    try testing.expectEqual(@as(u32, 60), counts[0]);
    try testing.expectEqual(@as(u32, 30), counts[1]);
    try testing.expectEqual(@as(u32, 1), counts[2]);
    out.clearRetainingCapacity();
    try buildSchedule(testing.allocator, &.{ 2, 4 }, &out); // reduces to 1:2
    try testing.expectEqual(@as(usize, 3), out.items.len);
    out.clearRetainingCapacity();
    try buildSchedule(testing.allocator, &.{ 65535, 65535, 1 }, &out);
    try testing.expect(out.items.len <= max_slots + 3);
}

test "srv snapshot: lowest priority is primary, others are ordered backups" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test" });
    defer d.deinit();
    d.applySuccess(1_000, &.{
        ep(20, 1, "http://10.0.0.3:80"),
        ep(10, 3, "http://10.0.0.1:80"),
        ep(10, 1, "http://10.0.0.2:80"),
        ep(30, 1, "http://10.0.0.4:80"),
    }, 30_000);
    try testing.expectEqual(@as(usize, 2), d.urls.items.len);
    try testing.expectEqual(@as(usize, 4), d.slots.items.len);
    try testing.expectEqual(@as(usize, 2), d.backup_urls.items.len);
    try testing.expectEqualStrings("http://10.0.0.3:80", d.backup_urls.items[0]);
    try testing.expectEqualStrings("http://10.0.0.4:80", d.backup_urls.items[1]);
    try testing.expectEqual(@as(u64, 1), d.change_count);
    // Identical set does not count as a change.
    d.applySuccess(2_000, &.{
        ep(10, 3, "http://10.0.0.1:80"), ep(10, 1, "http://10.0.0.2:80"),
        ep(20, 1, "http://10.0.0.3:80"), ep(30, 1, "http://10.0.0.4:80"),
    }, 30_000);
    try testing.expectEqual(@as(u64, 1), d.change_count);
}

test "srv refresh delay follows TTL within bounds and jitter" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test", .refresh_interval_ms = 60_000, .min_refresh_ms = 5_000 });
    defer d.deinit();
    const cases = [_]struct { ttl: u64, lo: u64, hi: u64 }{
        .{ .ttl = 1_000, .lo = 4_500, .hi = 5_500 }, // raised to min
        .{ .ttl = 20_000, .lo = 18_000, .hi = 22_000 },
        .{ .ttl = 900_000, .lo = 54_000, .hi = 66_000 }, // capped to max
        .{ .ttl = 0, .lo = 54_000, .hi = 66_000 },
    };
    for (cases, 0..) |c, i| {
        d.applySuccess(100_000 + i * 7_919, &.{ep(0, 1, "http://10.0.0.1:80")}, c.ttl);
        const delay = d.next_refresh_ms - (100_000 + i * 7_919);
        try testing.expect(delay >= c.lo and delay <= c.hi);
    }
    try testing.expect(!d.needsRefresh(100_000));
}

test "srv stale policy keeps last good set until stale_max_ms, NXDOMAIN clears" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test", .stale_max_ms = 60_000 });
    defer d.deinit();
    d.applySuccess(1_000, &.{ ep(0, 1, "http://10.0.0.1:80"), ep(1, 1, "http://10.0.0.2:80") }, 10_000);
    d.applyFailure(20_000, false, "Timeout");
    try testing.expect(d.stale);
    try testing.expectEqual(@as(usize, 1), d.urls.items.len);
    try testing.expectEqual(@as(u32, 1), d.consecutive_failures);
    d.applyFailure(50_000, false, "ServFail");
    try testing.expectEqual(@as(usize, 1), d.urls.items.len);
    d.applyFailure(62_000, false, "ServFail"); // > 60s since success
    try testing.expectEqual(@as(usize, 0), d.urls.items.len);
    try testing.expectEqual(@as(usize, 0), d.backup_urls.items.len);
    try testing.expect(!d.stale);
    // Recovery resets failure state.
    d.applySuccess(70_000, &.{ep(0, 1, "http://10.0.0.1:80")}, 10_000);
    try testing.expectEqual(@as(u32, 0), d.consecutive_failures);
    d.applyFailure(71_000, true, "NxDomain");
    try testing.expectEqual(@as(usize, 0), d.urls.items.len);
}

test "removed URLs stay valid for the grace period then are freed" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test" });
    defer d.deinit();
    d.applySuccess(1_000, &.{ep(0, 1, "http://10.0.0.1:80")}, 10_000);
    const held = d.urls.items[0];
    d.applySuccess(2_000, &.{ep(0, 1, "http://10.0.0.2:80")}, 10_000);
    try testing.expectEqualStrings("http://10.0.0.1:80", held); // in-flight reader still safe
    try testing.expectEqual(@as(usize, 2), d.interned.items.len);
    d.applySuccess(2_000 + retire_grace_ms + 1, &.{ep(0, 1, "http://10.0.0.2:80")}, 10_000);
    try testing.expectEqual(@as(usize, 1), d.interned.items.len);
}
