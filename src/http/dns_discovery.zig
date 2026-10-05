const compat = @import("zig_compat");
/// DNS-based upstream service discovery for Tardigrade.
///
/// Two modes share one live-set structure:
///
///  * A/AAAA mode (`host`): resolves a hostname to `http[s]://addr:port` URLs.
///  * SRV mode (`srv_name`, #766): resolves `_service._proto.name` SRV records,
///    resolves each target to A/AAAA, and builds priority groups.
///
/// Live set: `urls`/`weights` hold every endpoint ordered by SRV priority;
/// `group_ends` marks priority-group boundaries. Group 0 is the primary set,
/// later groups are backups. The gateway feeds the first group that has a
/// healthy endpoint through the normal pool machinery (all LB algorithms,
/// sticky affinity, slow start), so RFC 2782 weights apply inside whichever
/// priority group is active, and lower-precedence groups are only used once
/// every endpoint of the current group is unavailable.
///
/// Weights: the SRV *target* is the weighted unit. A target's weight is split
/// evenly over its resolved addresses (fixed-point, exact for <= 8 addresses)
/// so its aggregate share is independent of how many addresses it has.
///
/// Stale policy (SRV mode): NXDOMAIN, or an SRV answer that is empty / the
/// RFC 2782 "." target, is authoritative and clears the live set at once.
/// SERVFAIL, timeouts and "no target resolved" keep the last good set for up
/// to `stale_max_ms` since the last success, retrying on a short backoff, then
/// clear it.
///
/// Memory safety: callers receive URL slices that outlive the discovery lock,
/// so URL strings are interned and only freed `retire_grace_ms` after they
/// leave the live set. Refresh swaps the whole snapshot under the mutex.
/// The refresh worker is a joinable thread; `deinit` joins it, so shutdown
/// waits for an in-flight resolution (bounded by the resolver's own timeouts)
/// rather than racing it.
///
/// Readers hold `disc.mutex` while reading the snapshot fields.
const std = @import("std");
const dns_srv = @import("dns_srv.zig");
const event_loop = @import("event_loop.zig");

/// How long a URL string stays valid after leaving the live set.
pub const retire_grace_ms: u64 = 10 * 60 * 1000;
/// Hard caps keeping the live set bounded.
pub const max_endpoints = 64;
const max_addrs_per_target = 8;
/// Fixed-point factor: divisible by every address count 1..8.
const weight_scale: u32 = 840;
/// Upper bound on a group's total weight (the pool machinery walks tickets).
const max_group_weight: u32 = 1024;

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
    /// SRV: explicit nameservers; empty means /etc/resolv.conf.
    nameservers: []const std.Io.net.IpAddress = &.{},
};

/// One resolved endpoint, before grouping.
pub const Endpoint = struct {
    priority: u16,
    /// The SRV target's weight (shared by all of that target's addresses).
    weight: u16,
    /// Identifies the SRV target within one refresh.
    target_id: u16,
    url: []const u8,
};

pub const DnsDiscovery = struct {
    allocator: std.mem.Allocator,
    config: Config,
    mutex: compat.Mutex,
    /// All endpoints ordered by priority group, then URL (interned strings).
    urls: std.ArrayList([]const u8),
    /// Pool weight per endpoint (parallel to `urls`).
    weights: std.ArrayList(u32),
    /// Exclusive end index of each priority group in `urls`.
    group_ends: std.ArrayList(usize),
    /// Interned URL strings with retirement time (0 = live).
    interned: std.ArrayList(Interned),
    /// Monotonic ms of the last successful resolution.
    last_refresh_ms: u64,
    /// Monotonic ms when the next refresh is due (SRV mode; 0 = now).
    next_refresh_ms: u64,
    /// Number of routing-visible live-set changes since init.
    change_count: u64,
    refresh_total: u64,
    refresh_failures_total: u64,
    consecutive_failures: u32,
    /// True while serving the last good set after a DNS failure.
    stale: bool,
    last_error: []const u8,
    /// True while the refresh worker is running.
    refreshing: std.atomic.Value(bool),
    /// Joinable refresh worker; only touched by the scheduling thread/deinit.
    refresh_thread: ?std.Thread,

    const Interned = struct { url: []u8, retired_at_ms: u64 };

    pub fn init(allocator: std.mem.Allocator, config: Config) DnsDiscovery {
        return .{
            .allocator = allocator,
            .config = config,
            .mutex = .{},
            .urls = .empty,
            .weights = .empty,
            .group_ends = .empty,
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
            .refresh_thread = null,
        };
    }

    pub fn deinit(self: *DnsDiscovery) void {
        if (self.refresh_thread) |t| t.join();
        self.refresh_thread = null;
        for (self.interned.items) |e| self.allocator.free(e.url);
        self.interned.deinit(self.allocator);
        self.urls.deinit(self.allocator);
        self.weights.deinit(self.allocator);
        self.group_ends.deinit(self.allocator);
    }

    pub fn enabled(self: *const DnsDiscovery) bool {
        return self.config.host.len > 0 or self.config.srv_name.len > 0;
    }

    pub fn srvMode(self: *const DnsDiscovery) bool {
        return self.config.srv_name.len > 0;
    }

    /// Returns true when the next refresh is due. Takes the mutex because the
    /// refresh worker writes the schedule fields.
    pub fn needsRefresh(self: *DnsDiscovery, now_ms: u64) bool {
        if (!self.enabled()) return false;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.srvMode()) return now_ms >= self.next_refresh_ms;
        if (self.last_refresh_ms == 0) return true;
        return now_ms -| self.last_refresh_ms >= self.config.refresh_interval_ms;
    }

    /// Start the background refresh worker if one is not already running.
    /// Must be called from a single scheduling thread (the event loop).
    pub fn startRefresh(self: *DnsDiscovery) void {
        if (self.refresh_thread) |t| {
            if (self.refreshing.load(.acquire)) return;
            t.join();
            self.refresh_thread = null;
        }
        self.refreshing.store(true, .release);
        self.refresh_thread = std.Thread.spawn(.{}, refreshWorker, .{self}) catch {
            self.refreshing.store(false, .release);
            return;
        };
    }

    fn refreshWorker(self: *DnsDiscovery) void {
        defer self.refreshing.store(false, .release);
        self.refresh(event_loop.monotonicMs());
    }

    /// Resolve and swap in a new live set. Blocking; never call it from the
    /// event loop thread. Thread-safe.
    pub fn refresh(self: *DnsDiscovery, now_ms: u64) void {
        if (self.srvMode()) return self.refreshSrv(now_ms);
        if (self.config.host.len == 0) return;
        var eps: std.ArrayList(Endpoint) = .empty;
        defer freeEndpoints(self.allocator, &eps);
        self.collectAddrs(self.config.host, self.config.port, 0, 1, 0, &eps);
        if (eps.items.len == 0) {
            std.debug.print("dns_discovery: resolve {s}:{d} failed\n", .{ self.config.host, self.config.port });
            return;
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        self.applySuccess(now_ms, eps.items, self.config.refresh_interval_ms);
    }

    fn refreshSrv(self: *DnsDiscovery, now_ms: u64) void {
        const looked_up = if (self.config.nameservers.len > 0)
            dns_srv.lookupSrvVia(self.allocator, self.config.nameservers, self.config.srv_name, self.config.query_timeout_ms)
        else
            dns_srv.lookupSrv(self.allocator, self.config.srv_name, self.config.query_timeout_ms);
        const resp = looked_up catch |err| {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.applyFailure(now_ms, err == error.NxDomain, @errorName(err));
            return;
        };
        defer resp.deinit(self.allocator);

        var eps: std.ArrayList(Endpoint) = .empty;
        defer freeEndpoints(self.allocator, &eps);
        var unavailable = true;
        for (resp.records, 0..) |rec, i| {
            if (rec.target.len == 0) continue; // RFC 2782 "." = unavailable
            unavailable = false;
            self.collectAddrs(rec.target, rec.port, rec.priority, rec.weight, @intCast(i), &eps);
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        if (unavailable) return self.applyFailure(now_ms, true, "no_records");
        if (eps.items.len == 0) return self.applyFailure(now_ms, false, "no_targets_resolved");
        self.applySuccess(now_ms, eps.items, @as(u64, resp.min_ttl) * 1000);
    }

    /// Resolve `host` to A/AAAA and append `Endpoint`s for it.
    fn collectAddrs(self: *DnsDiscovery, host: []const u8, port: u16, priority: u16, weight: u16, target_id: u16, eps: *std.ArrayList(Endpoint)) void {
        var addrs: [compat.max_resolved_addresses]std.Io.net.IpAddress = undefined;
        const resolved = compat.resolveHostAddresses(host, port, &addrs) catch return;
        for (resolved[0..@min(resolved.len, max_addrs_per_target)]) |a| {
            if (eps.items.len >= max_endpoints) return;
            const url = formatUrl(self.allocator, self.config.tls, a) catch return;
            eps.append(self.allocator, .{ .priority = priority, .weight = weight, .target_id = target_id, .url = url }) catch {
                self.allocator.free(url);
                return;
            };
        }
    }

    /// Install a fresh snapshot. Caller holds `mutex`.
    pub fn applySuccess(self: *DnsDiscovery, now_ms: u64, eps: []const Endpoint, ttl_ms: u64) void {
        var urls: std.ArrayList([]const u8) = .empty;
        defer urls.deinit(self.allocator);
        var weights: std.ArrayList(u32) = .empty;
        defer weights.deinit(self.allocator);
        var ends: std.ArrayList(usize) = .empty;
        defer ends.deinit(self.allocator);

        var floor: u32 = 0;
        while (floor <= std.math.maxInt(u16)) {
            var prio: u32 = std.math.maxInt(u32);
            for (eps) |e| if (e.priority >= floor) {
                prio = @min(prio, e.priority);
            };
            if (prio == std.math.maxInt(u32)) break;
            floor = prio + 1;
            const start = urls.items.len;
            for (eps) |e| if (e.priority == prio) {
                const url = self.intern(e.url) orelse return;
                if (containsUrl(urls.items[start..], url)) continue;
                // Target weight split over the target's addresses.
                var n: u32 = 0;
                for (eps) |o| if (o.priority == prio and o.target_id == e.target_id) {
                    n += 1;
                };
                urls.append(self.allocator, url) catch return;
                weights.append(self.allocator, @max(e.weight, 1) * weight_scale / @max(n, 1)) catch return;
            };
            sortGroup(urls.items[start..], weights.items[start..]);
            normalizeWeights(weights.items[start..]);
            ends.append(self.allocator, urls.items.len) catch return;
        }

        self.refresh_total += 1;
        self.consecutive_failures = 0;
        self.stale = false;
        self.last_error = "";
        self.last_refresh_ms = now_ms;
        self.next_refresh_ms = now_ms + self.nextDelay(now_ms, ttl_ms);

        const changed = !std.mem.eql(usize, self.group_ends.items, ends.items) or
            !std.mem.eql(u32, self.weights.items, weights.items) or
            !orderedUrlsEqual(self.urls.items, urls.items);
        // Atomic swap of every live-set field (caller holds the mutex).
        std.mem.swap(std.ArrayList([]const u8), &self.urls, &urls);
        std.mem.swap(std.ArrayList(u32), &self.weights, &weights);
        std.mem.swap(std.ArrayList(usize), &self.group_ends, &ends);
        if (changed) {
            self.change_count += 1;
            std.debug.print("dns_discovery: {s} resolved to {d} upstream(s) in {d} priority group(s) (change #{d})\n", .{
                self.sourceName(), self.urls.items.len, self.group_ends.items.len, self.change_count,
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
        self.next_refresh_ms = now_ms + jitter(now_ms, backoff);
        const have = self.urls.items.len > 0;
        const expired = self.last_refresh_ms == 0 or now_ms -| self.last_refresh_ms > self.config.stale_max_ms;
        if (have and (authoritative or expired)) {
            self.urls.clearRetainingCapacity();
            self.weights.clearRetainingCapacity();
            self.group_ends.clearRetainingCapacity();
            self.change_count += 1;
            self.stale = false;
            std.debug.print("dns_discovery: {s} cleared ({s})\n", .{ self.sourceName(), reason });
            self.retireUnused(now_ms);
        } else if (have) {
            self.stale = true;
        }
    }

    /// Number of endpoints in the primary (first) priority group.
    pub fn primaryCount(self: *const DnsDiscovery) usize {
        return if (self.group_ends.items.len > 0) self.group_ends.items[0] else 0;
    }

    pub fn groupStart(self: *const DnsDiscovery, g: usize) usize {
        return if (g == 0) 0 else self.group_ends.items[g - 1];
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
        return jitter(now_ms, base);
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
            if (containsUrl(self.urls.items, e.url)) {
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

    /// Copy all live URL strings (every priority group). Caller owns the
    /// slice and each string. Must NOT be called while holding self.mutex.
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

fn jitter(now_ms: u64, base: u64) u64 {
    const span = base / 5; // total +-10% window
    if (span == 0) return base;
    const r = (now_ms *% 0x9E3779B97F4A7C15) >> 33;
    return base - span / 2 + r % (span + 1);
}

fn freeEndpoints(allocator: std.mem.Allocator, eps: *std.ArrayList(Endpoint)) void {
    for (eps.items) |e| allocator.free(e.url);
    eps.deinit(allocator);
}

fn containsUrl(list: []const []const u8, url: []const u8) bool {
    for (list) |u| if (std.mem.eql(u8, u, url)) return true;
    return false;
}

fn orderedUrlsEqual(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

/// Insertion sort by URL (groups are tiny) so snapshots compare deterministically.
fn sortGroup(urls: [][]const u8, weights: []u32) void {
    var i: usize = 1;
    while (i < urls.len) : (i += 1) {
        var j = i;
        while (j > 0 and std.mem.lessThan(u8, urls[j], urls[j - 1])) : (j -= 1) {
            std.mem.swap([]const u8, &urls[j], &urls[j - 1]);
            std.mem.swap(u32, &weights[j], &weights[j - 1]);
        }
    }
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

/// Reduce a group's weights by their GCD, then scale down proportionally
/// (never below 1) so the total stays <= `max_group_weight`.
fn normalizeWeights(weights: []u32) void {
    if (weights.len == 0) return;
    var g: u32 = 0;
    for (weights) |w| g = gcd(g, w);
    var total: u32 = 0;
    for (weights) |*w| {
        w.* = @max(w.* / g, 1);
        total += w.*;
    }
    if (total > max_group_weight) {
        const div = (total + max_group_weight - 1) / max_group_weight;
        for (weights) |*w| w.* = @max(1, w.* / div);
    }
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


fn ep(prio: u16, weight: u16, target: u16, url: []const u8) Endpoint {
    return .{ .priority = prio, .weight = weight, .target_id = target, .url = url };
}

test "target weight is preserved regardless of address count (1:8)" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test" });
    defer d.deinit();
    var eps: [9]Endpoint = undefined;
    var urls: [8][24]u8 = undefined;
    for (0..8) |i| {
        const u = std.fmt.bufPrint(&urls[i], "http://10.0.0.{d}:80", .{i + 1}) catch unreachable;
        eps[i] = ep(0, 1, 0, u); // target A: weight 1, 8 addresses
    }
    eps[8] = ep(0, 8, 1, "http://10.0.1.1:80"); // target B: weight 8, one address
    d.applySuccess(1_000, &eps, 30_000);
    try testing.expectEqual(@as(usize, 9), d.urls.items.len);
    var a: u32 = 0;
    var b: u32 = 0;
    for (d.urls.items, d.weights.items) |u, w| {
        if (std.mem.startsWith(u8, u, "http://10.0.1.")) b += w else a += w;
    }
    try testing.expectEqual(b, a * 8);
}

test "priority groups keep their own weights and ordering" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test" });
    defer d.deinit();
    d.applySuccess(1_000, &.{
        ep(20, 3, 0, "http://10.0.0.3:80"),
        ep(10, 1, 1, "http://10.0.0.1:80"),
        ep(20, 1, 2, "http://10.0.0.4:80"),
        ep(10, 1, 3, "http://10.0.0.2:80"),
        ep(30, 1, 4, "http://10.0.0.5:80"),
    }, 30_000);
    try testing.expectEqual(@as(usize, 3), d.group_ends.items.len);
    try testing.expectEqual(@as(usize, 2), d.primaryCount());
    // Group 1 (priority 20) is sorted by URL and keeps its 3:1 weights.
    try testing.expectEqualStrings("http://10.0.0.3:80", d.urls.items[2]);
    try testing.expectEqualStrings("http://10.0.0.4:80", d.urls.items[3]);
    try testing.expectEqual(d.weights.items[2], d.weights.items[3] * 3);
    try testing.expectEqual(@as(usize, 2), d.groupStart(1));
    try testing.expectEqual(@as(usize, 4), d.groupStart(2));
    try testing.expectEqualStrings("http://10.0.0.5:80", d.urls.items[4]);
}

test "routing-only changes (weights, priority order) count as changes" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test" });
    defer d.deinit();
    const base = [_]Endpoint{ ep(10, 1, 0, "http://10.0.0.1:80"), ep(10, 1, 1, "http://10.0.0.2:80"), ep(20, 1, 2, "http://10.0.0.3:80") };
    d.applySuccess(1_000, &base, 30_000);
    try testing.expectEqual(@as(u64, 1), d.change_count);
    d.applySuccess(2_000, &base, 30_000);
    try testing.expectEqual(@as(u64, 1), d.change_count); // identical
    d.applySuccess(3_000, &.{ ep(10, 3, 0, "http://10.0.0.1:80"), ep(10, 1, 1, "http://10.0.0.2:80"), ep(20, 1, 2, "http://10.0.0.3:80") }, 30_000);
    try testing.expectEqual(@as(u64, 2), d.change_count); // weight only
    d.applySuccess(4_000, &.{ ep(10, 3, 0, "http://10.0.0.1:80"), ep(20, 1, 1, "http://10.0.0.2:80"), ep(10, 1, 2, "http://10.0.0.3:80") }, 30_000);
    try testing.expectEqual(@as(u64, 3), d.change_count); // same URLs, different priority groups
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
        const now = 100_000 + i * 7_919;
        d.applySuccess(now, &.{ep(0, 1, 0, "http://10.0.0.1:80")}, c.ttl);
        const delay = d.next_refresh_ms - now;
        try testing.expect(delay >= c.lo and delay <= c.hi);
    }
    try testing.expect(!d.needsRefresh(100_000));
}

test "srv stale policy keeps last good set until stale_max_ms, NXDOMAIN clears" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test", .stale_max_ms = 60_000 });
    defer d.deinit();
    d.applySuccess(1_000, &.{ ep(0, 1, 0, "http://10.0.0.1:80"), ep(1, 1, 1, "http://10.0.0.2:80") }, 10_000);
    d.applyFailure(20_000, false, "Timeout");
    try testing.expect(d.stale);
    try testing.expectEqual(@as(usize, 2), d.urls.items.len);
    d.applyFailure(50_000, false, "ServFail");
    try testing.expectEqual(@as(usize, 2), d.urls.items.len);
    d.applyFailure(62_000, false, "ServFail"); // > 60s since success
    try testing.expectEqual(@as(usize, 0), d.urls.items.len);
    try testing.expectEqual(@as(usize, 0), d.group_ends.items.len);
    try testing.expect(!d.stale);
    d.applySuccess(70_000, &.{ep(0, 1, 0, "http://10.0.0.1:80")}, 10_000);
    try testing.expectEqual(@as(u32, 0), d.consecutive_failures);
    d.applyFailure(71_000, true, "NxDomain");
    try testing.expectEqual(@as(usize, 0), d.urls.items.len);
}

test "removed URLs stay valid for the grace period then are freed" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test" });
    defer d.deinit();
    d.applySuccess(1_000, &.{ep(0, 1, 0, "http://10.0.0.1:80")}, 10_000);
    const held = d.urls.items[0];
    d.applySuccess(2_000, &.{ep(0, 1, 0, "http://10.0.0.2:80")}, 10_000);
    try testing.expectEqualStrings("http://10.0.0.1:80", held); // in-flight reader still safe
    try testing.expectEqual(@as(usize, 2), d.interned.items.len);
    d.applySuccess(2_000 + retire_grace_ms + 1, &.{ep(0, 1, 0, "http://10.0.0.2:80")}, 10_000);
    try testing.expectEqual(@as(usize, 1), d.interned.items.len);
}

// ── Local DNS fixture: SRV -> target A -> port, rotation, removal, stale ────

const Fixture = struct {
    sock: c_int,
    port: u16,
    thread: ?std.Thread = null,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    mutex: compat.Mutex = .{},
    mode: enum { answer, servfail, nxdomain, silent } = .answer,
    recs: [4]Rec = undefined,
    nrecs: usize = 0,

    const Rec = struct { prio: u16, weight: u16, port: u16, target: []const u8 };

    fn start(self: *Fixture) !void {
        const sock = std.c.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
        if (sock < 0) return error.SkipZigTest;
        var sin = std.c.sockaddr.in{
            .family = std.posix.AF.INET,
            .port = 0,
            .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
            .zero = [_]u8{0} ** 8,
        };
        if (std.c.bind(sock, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) != 0) {
            _ = std.c.close(sock);
            return error.SkipZigTest;
        }
        var len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        _ = std.c.getsockname(sock, @ptrCast(&sin), &len);
        const tv = std.c.timeval{ .sec = 0, .usec = 50_000 };
        _ = std.c.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(std.c.timeval));
        self.sock = sock;
        self.port = std.mem.bigToNative(u16, sin.port);
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
    }

    fn deinit(self: *Fixture) void {
        self.stop.store(true, .release);
        if (self.thread) |t| t.join();
        _ = std.c.close(self.sock);
    }

    fn set(self: *Fixture, mode: @TypeOf(@as(Fixture, undefined).mode), recs: []const Rec) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.mode = mode;
        self.nrecs = recs.len;
        for (recs, 0..) |r, i| self.recs[i] = r;
    }

    fn serve(self: *Fixture) void {
        var buf: [512]u8 = undefined;
        while (!self.stop.load(.acquire)) {
            var from: std.c.sockaddr.storage = undefined;
            var flen: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);
            const n = std.c.recvfrom(self.sock, &buf, buf.len, 0, @ptrCast(&from), &flen);
            if (n < 12) continue;
            var out: [1024]u8 = undefined;
            self.mutex.lock();
            const len = self.respond(buf[0..@intCast(n)], &out);
            self.mutex.unlock();
            if (len == 0) continue;
            _ = std.c.sendto(self.sock, &out, len, 0, @ptrCast(&from), flen);
        }
    }

    /// Build the reply to `query` (id + question echoed) into `out`.
    fn respond(self: *Fixture, query: []const u8, out: []u8) usize {
        if (self.mode == .silent) return 0;
        // Question section ends after the name's terminating zero + 4 bytes.
        var q: usize = 12;
        while (query[q] != 0) q += @as(usize, query[q]) + 1;
        q += 5;
        @memcpy(out[0..q], query[0..q]);
        const rcode: u16 = switch (self.mode) {
            .servfail => 2,
            .nxdomain => 3,
            else => 0,
        };
        std.mem.writeInt(u16, out[2..4], 0x8180 | rcode, .big);
        const answers: u16 = if (self.mode == .answer) @intCast(self.nrecs) else 0;
        std.mem.writeInt(u16, out[6..8], answers, .big);
        var pos = q;
        for (self.recs[0..answers]) |r| {
            out[pos] = 0xC0;
            out[pos + 1] = 12;
            std.mem.writeInt(u16, out[pos + 2 ..][0..2], 33, .big);
            std.mem.writeInt(u16, out[pos + 4 ..][0..2], 1, .big);
            std.mem.writeInt(u32, out[pos + 6 ..][0..4], 30, .big);
            const rd = pos + 12;
            std.mem.writeInt(u16, out[rd..][0..2], r.prio, .big);
            std.mem.writeInt(u16, out[rd + 2 ..][0..2], r.weight, .big);
            std.mem.writeInt(u16, out[rd + 4 ..][0..2], r.port, .big);
            var w = rd + 6;
            var it = std.mem.splitScalar(u8, r.target, '.');
            while (it.next()) |label| {
                out[w] = @intCast(label.len);
                @memcpy(out[w + 1 ..][0..label.len], label);
                w += 1 + label.len;
            }
            out[w] = 0;
            w += 1;
            std.mem.writeInt(u16, out[pos + 10 ..][0..2], @intCast(w - rd), .big);
            pos = w;
        }
        return pos;
    }
};

test "dns fixture: SRV to target to port, rotation, removal, stale and recovery" {
    var fx: Fixture = .{ .sock = -1, .port = 0 };
    try fx.start();
    defer fx.deinit();
    const ns = [_]std.Io.net.IpAddress{.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = fx.port } }};
    var d = DnsDiscovery.init(testing.allocator, .{
        .srv_name = "_api._tcp.service.test",
        .nameservers = &ns,
        .query_timeout_ms = 200,
        .stale_max_ms = 10_000,
        .tls = true,
    });
    defer d.deinit();

    fx.set(.answer, &.{
        .{ .prio = 10, .weight = 5, .port = 8443, .target = "127.0.0.2" },
        .{ .prio = 10, .weight = 1, .port = 9443, .target = "127.0.0.3" },
        .{ .prio = 20, .weight = 1, .port = 8443, .target = "127.0.0.9" },
    });
    d.refresh(1_000);
    try testing.expectEqual(@as(usize, 3), d.urls.items.len);
    try testing.expectEqual(@as(usize, 2), d.primaryCount());
    try testing.expectEqualStrings("https://127.0.0.2:8443", d.urls.items[0]);
    try testing.expectEqualStrings("https://127.0.0.3:9443", d.urls.items[1]);
    try testing.expectEqual(d.weights.items[0], d.weights.items[1] * 5);
    try testing.expectEqualStrings("https://127.0.0.9:8443", d.urls.items[2]);

    // Target A rotation + port change + target removal.
    fx.set(.answer, &.{
        .{ .prio = 10, .weight = 5, .port = 8444, .target = "127.0.0.7" },
        .{ .prio = 20, .weight = 1, .port = 8443, .target = "127.0.0.9" },
    });
    d.refresh(2_000);
    try testing.expectEqual(@as(usize, 2), d.urls.items.len);
    try testing.expectEqualStrings("https://127.0.0.7:8444", d.urls.items[0]);
    try testing.expectEqual(@as(u64, 2), d.change_count);

    // SERVFAIL and silence keep the last good set (stale)...
    fx.set(.servfail, &.{});
    d.refresh(3_000);
    try testing.expect(d.stale);
    try testing.expectEqual(@as(usize, 2), d.urls.items.len);
    fx.set(.silent, &.{});
    d.refresh(4_000);
    try testing.expect(d.stale);
    try testing.expectEqual(@as(usize, 2), d.urls.items.len);
    // ...until the stale bound passes.
    d.refresh(2_000 + 10_001);
    try testing.expectEqual(@as(usize, 0), d.urls.items.len);

    // Recovery.
    fx.set(.answer, &.{.{ .prio = 1, .weight = 1, .port = 80, .target = "127.0.0.4" }});
    d.refresh(20_000);
    try testing.expectEqual(@as(usize, 1), d.urls.items.len);
    try testing.expect(!d.stale);

    // NXDOMAIN clears immediately.
    fx.set(.nxdomain, &.{});
    d.refresh(21_000);
    try testing.expectEqual(@as(usize, 0), d.urls.items.len);
}

test "background refresh worker is joined before state is freed" {
    var fx: Fixture = .{ .sock = -1, .port = 0 };
    try fx.start();
    defer fx.deinit();
    fx.set(.silent, &.{});
    const ns = [_]std.Io.net.IpAddress{.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = fx.port } }};
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test", .nameservers = &ns, .query_timeout_ms = 300 });
    d.startRefresh();
    d.startRefresh(); // second call while running is a no-op
    d.deinit(); // must block until the worker (a 300ms timeout) has finished
    try testing.expect(!d.refreshing.load(.acquire));
}
