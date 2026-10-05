const compat = @import("zig_compat");
/// DNS-based upstream service discovery for Tardigrade.
///
/// Two modes share one live-set structure:
///
///  * A/AAAA mode (`host`): resolves a hostname to `http[s]://addr:port` URLs.
///  * SRV mode (`srv_name`, #766): resolves `_service._proto.name` SRV records,
///    resolves each target to A/AAAA, and builds priority groups.
///
/// Live set: priority groups are first-class. Each group holds weighted
/// *targets* (the SRV target is the weighted unit), each target holds its
/// resolved addresses; `urls` is the flat, interned address list ordered
/// group -> target -> address. Selection only ever looks inside the first
/// group that has a healthy endpoint, so lower-priority groups are never
/// reachable while a higher-priority one has any healthy member. Inside the
/// group, `pickWeighted` runs nginx-style smooth weighted round-robin over the
/// targets with their exact SRV weights (O(targets), no ratio quantization)
/// and then rotates over the chosen target's addresses.
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
    /// Optional A/AAAA resolver for SRV targets (tests); null uses the system
    /// resolver. Returns the addresses (empty = resolution failed).
    target_resolver: ?TargetResolver = null,
};

pub const TargetResolver = struct {
    ctx: ?*anyopaque,
    resolve: *const fn (ctx: ?*anyopaque, host: []const u8, port: u16, out: *[compat.max_resolved_addresses]std.Io.net.IpAddress) []const std.Io.net.IpAddress,
};

/// A weighted SRV target and the span of `urls` holding its addresses.
pub const Target = struct {
    weight: u32,
    first: u32,
    count: u32,
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
    /// All endpoints ordered group -> target -> URL (interned strings).
    urls: std.ArrayList([]const u8),
    /// Weighted targets in the same order; each spans `count` entries of `urls`.
    targets: std.ArrayList(Target),
    /// Exclusive end index of each priority group in `targets`.
    group_ends: std.ArrayList(usize),
    /// Smooth-WRR running weight and address rotor per target (selection
    /// state, reset whenever a new snapshot is installed).
    wrr_current: std.ArrayList(i64),
    rotor: std.ArrayList(u32),
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
            .targets = .empty,
            .group_ends = .empty,
            .wrr_current = .empty,
            .rotor = .empty,
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
        self.targets.deinit(self.allocator);
        self.group_ends.deinit(self.allocator);
        self.wrr_current.deinit(self.allocator);
        self.rotor.deinit(self.allocator);
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
        const resolved = if (self.config.target_resolver) |r|
            r.resolve(r.ctx, host, port, &addrs)
        else
            compat.resolveHostAddresses(host, port, &addrs) catch return;
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
        var targets: std.ArrayList(Target) = .empty;
        defer targets.deinit(self.allocator);
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

            // Distinct targets of this priority, ordered by their lowest URL
            // so snapshots compare deterministically.
            var tids: [max_endpoints]u16 = undefined;
            var tmin: [max_endpoints][]const u8 = undefined;
            var tw: [max_endpoints]u16 = undefined;
            var nt: usize = 0;
            for (eps) |e| if (e.priority == prio) {
                var found: ?usize = null;
                for (tids[0..nt], 0..) |id, i| if (id == e.target_id) {
                    found = i;
                };
                if (found) |i| {
                    if (std.mem.lessThan(u8, e.url, tmin[i])) tmin[i] = e.url;
                } else {
                    tids[nt] = e.target_id;
                    tmin[nt] = e.url;
                    tw[nt] = e.weight;
                    nt += 1;
                }
            };
            var order: [max_endpoints]usize = undefined;
            for (0..nt) |i| order[i] = i;
            var oi: usize = 1;
            while (oi < nt) : (oi += 1) {
                var j = oi;
                while (j > 0 and std.mem.lessThan(u8, tmin[order[j]], tmin[order[j - 1]])) : (j -= 1) {
                    std.mem.swap(usize, &order[j], &order[j - 1]);
                }
            }
            for (order[0..nt]) |ti| {
                const first = urls.items.len;
                for (eps) |e| if (e.priority == prio and e.target_id == tids[ti]) {
                    const url = self.intern(e.url) orelse return;
                    if (containsUrl(urls.items[first..], url)) continue;
                    urls.append(self.allocator, url) catch return;
                };
                sortUrls(urls.items[first..]);
                if (urls.items.len == first) continue;
                targets.append(self.allocator, .{
                    .weight = @max(tw[ti], 1), // RFC 2782: weight 0 still gets a small share
                    .first = @intCast(first),
                    .count = @intCast(urls.items.len - first),
                }) catch return;
            }
            ends.append(self.allocator, targets.items.len) catch return;
        }

        var wrr: std.ArrayList(i64) = .empty;
        defer wrr.deinit(self.allocator);
        var rotor: std.ArrayList(u32) = .empty;
        defer rotor.deinit(self.allocator);
        wrr.appendNTimes(self.allocator, 0, targets.items.len) catch return;
        rotor.appendNTimes(self.allocator, 0, targets.items.len) catch return;

        self.refresh_total += 1;
        self.consecutive_failures = 0;
        self.stale = false;
        self.last_error = "";
        self.last_refresh_ms = now_ms;
        self.next_refresh_ms = now_ms + self.nextDelay(now_ms, ttl_ms);

        const changed = !std.mem.eql(usize, self.group_ends.items, ends.items) or
            !targetsEqual(self.targets.items, targets.items) or
            !orderedUrlsEqual(self.urls.items, urls.items);
        // Atomic swap of every live-set field (caller holds the mutex).
        std.mem.swap(std.ArrayList([]const u8), &self.urls, &urls);
        std.mem.swap(std.ArrayList(Target), &self.targets, &targets);
        std.mem.swap(std.ArrayList(usize), &self.group_ends, &ends);
        if (changed) {
            // Selection state only resets when routing actually changed so an
            // unchanged refresh does not perturb the rotation.
            std.mem.swap(std.ArrayList(i64), &self.wrr_current, &wrr);
            std.mem.swap(std.ArrayList(u32), &self.rotor, &rotor);
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
            self.targets.clearRetainingCapacity();
            self.group_ends.clearRetainingCapacity();
            self.wrr_current.clearRetainingCapacity();
            self.rotor.clearRetainingCapacity();
            self.change_count += 1;
            self.stale = false;
            std.debug.print("dns_discovery: {s} cleared ({s})\n", .{ self.sourceName(), reason });
            self.retireUnused(now_ms);
        } else if (have) {
            self.stale = true;
        }
    }

    pub fn groupCount(self: *const DnsDiscovery) usize {
        return self.group_ends.items.len;
    }

    fn groupTargetStart(self: *const DnsDiscovery, g: usize) usize {
        return if (g == 0) 0 else self.group_ends.items[g - 1];
    }

    /// The addresses of priority group `g`.
    pub fn groupUrls(self: *const DnsDiscovery, g: usize) []const []const u8 {
        const ts = self.groupTargetStart(g);
        const te = self.group_ends.items[g];
        if (ts == te) return &.{};
        const last = self.targets.items[te - 1];
        return self.urls.items[self.targets.items[ts].first .. last.first + last.count];
    }

    /// Number of endpoints in the primary (first) priority group.
    pub fn primaryCount(self: *const DnsDiscovery) usize {
        return if (self.groupCount() > 0) self.groupUrls(0).len else 0;
    }

    /// Index of the first priority group with any healthy endpoint.
    /// `isHealthy(ctx, url)`; caller holds `mutex`.
    pub fn firstHealthyGroup(self: *const DnsDiscovery, ctx: anytype, comptime isHealthy: fn (@TypeOf(ctx), []const u8) bool) ?usize {
        for (0..self.groupCount()) |g| {
            for (self.groupUrls(g)) |u| if (isHealthy(ctx, u)) return g;
        }
        return null;
    }

    /// Smooth weighted round-robin over group `g`'s targets using their exact
    /// SRV weights, then rotation over the chosen target's addresses. Targets
    /// without a healthy address are skipped. Caller holds `mutex`.
    pub fn pickWeighted(self: *DnsDiscovery, g: usize, ctx: anytype, comptime isHealthy: fn (@TypeOf(ctx), []const u8) bool) ?[]const u8 {
        const ts = self.groupTargetStart(g);
        const te = self.group_ends.items[g];
        var total: i64 = 0;
        var best: ?usize = null;
        for (ts..te) |t| {
            const tg = self.targets.items[t];
            if (!self.targetHasHealthy(tg, ctx, isHealthy)) continue;
            self.wrr_current.items[t] += tg.weight;
            total += tg.weight;
            if (best == null or self.wrr_current.items[t] > self.wrr_current.items[best.?]) best = t;
        }
        const b = best orelse return null;
        self.wrr_current.items[b] -= total;
        const tg = self.targets.items[b];
        const start = self.rotor.items[b] % tg.count;
        var off: u32 = 0;
        while (off < tg.count) : (off += 1) {
            const idx = (start + off) % tg.count;
            const url = self.urls.items[tg.first + idx];
            if (!isHealthy(ctx, url)) continue;
            self.rotor.items[b] = idx + 1;
            return url;
        }
        return null;
    }

    fn targetHasHealthy(self: *const DnsDiscovery, tg: Target, ctx: anytype, comptime isHealthy: fn (@TypeOf(ctx), []const u8) bool) bool {
        for (self.urls.items[tg.first .. tg.first + tg.count]) |u| if (isHealthy(ctx, u)) return true;
        return false;
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

fn targetsEqual(a: []const Target, b: []const Target) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x.weight != y.weight or x.first != y.first or x.count != y.count) return false;
    }
    return true;
}

/// Insertion sort by URL (a target has at most 8 addresses).
fn sortUrls(urls: [][]const u8) void {
    var i: usize = 1;
    while (i < urls.len) : (i += 1) {
        var j = i;
        while (j > 0 and std.mem.lessThan(u8, urls[j], urls[j - 1])) : (j -= 1) {
            std.mem.swap([]const u8, &urls[j], &urls[j - 1]);
        }
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

const Health = struct {
    down: []const []const u8 = &.{},

    fn check(self: *const Health, url: []const u8) bool {
        for (self.down) |d| if (std.mem.eql(u8, d, url)) return false;
        return true;
    }
};

fn countPicks(d: *DnsDiscovery, g: usize, h: *const Health, picks: usize, hits: []usize, urls: []const []const u8) void {
    for (0..picks) |_| {
        const u = d.pickWeighted(g, h, Health.check) orelse continue;
        for (urls, 0..) |want, i| if (std.mem.eql(u8, u, want)) {
            hits[i] += 1;
        };
    }
}

test "extreme target weight ratio is exact: 65535 (1 addr) vs 1 (8 addrs)" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test" });
    defer d.deinit();
    var eps: [9]Endpoint = undefined;
    var bufs: [8][24]u8 = undefined;
    for (0..8) |i| {
        eps[i] = ep(0, 1, 1, std.fmt.bufPrint(&bufs[i], "http://10.0.1.{d}:80", .{i + 1}) catch unreachable);
    }
    eps[8] = ep(0, 65535, 0, "http://10.0.0.1:80");
    d.applySuccess(1_000, &eps, 30_000);
    const h: Health = .{};
    var a: usize = 0;
    var b: usize = 0;
    for (0..65536) |_| {
        const u = d.pickWeighted(0, &h, Health.check).?;
        if (std.mem.startsWith(u8, u, "http://10.0.0.")) a += 1 else b += 1;
    }
    try testing.expectEqual(@as(usize, 65535), a);
    try testing.expectEqual(@as(usize, 1), b);
}

test "weight does not multiply with address count (1:8) and addresses rotate" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test" });
    defer d.deinit();
    var eps: [9]Endpoint = undefined;
    var bufs: [8][24]u8 = undefined;
    for (0..8) |i| {
        eps[i] = ep(0, 1, 0, std.fmt.bufPrint(&bufs[i], "http://10.0.0.{d}:80", .{i + 1}) catch unreachable);
    }
    eps[8] = ep(0, 8, 1, "http://10.0.1.1:80");
    d.applySuccess(1_000, &eps, 30_000);
    const h: Health = .{};
    var a: usize = 0;
    var b: usize = 0;
    var seen = [_]usize{0} ** 8;
    for (0..90) |_| {
        const u = d.pickWeighted(0, &h, Health.check).?;
        if (std.mem.startsWith(u8, u, "http://10.0.1.")) {
            b += 1;
        } else {
            a += 1;
            seen[u["http://10.0.0.".len] - '1'] += 1;
        }
    }
    try testing.expectEqual(@as(usize, 10), a); // 1/9 of 90
    try testing.expectEqual(@as(usize, 80), b);
    for (seen) |c| try testing.expect(c >= 1);
}

test "selection stays inside the first group with a healthy endpoint" {
    var d = DnsDiscovery.init(testing.allocator, .{ .srv_name = "_a._tcp.x.test" });
    defer d.deinit();
    d.applySuccess(1_000, &.{
        ep(10, 1, 0, "http://10.0.0.1:80"),
        ep(10, 1, 1, "http://10.0.0.2:80"),
        ep(10, 1, 2, "http://10.0.0.3:80"),
        ep(20, 3, 3, "http://10.0.0.4:80"),
        ep(20, 1, 4, "http://10.0.0.5:80"),
    }, 30_000);
    try testing.expectEqual(@as(usize, 2), d.groupCount());
    try testing.expectEqual(@as(usize, 3), d.primaryCount());
    var h: Health = .{};
    try testing.expectEqual(@as(?usize, 0), d.firstHealthyGroup(&h, Health.check));
    // Two of three primaries down: the survivor takes everything, never group 20.
    h.down = &.{ "http://10.0.0.1:80", "http://10.0.0.2:80" };
    var hits = [_]usize{0} ** 5;
    const all = [_][]const u8{ "http://10.0.0.1:80", "http://10.0.0.2:80", "http://10.0.0.3:80", "http://10.0.0.4:80", "http://10.0.0.5:80" };
    countPicks(&d, 0, &h, 100, &hits, &all);
    try testing.expectEqual(@as(usize, 100), hits[2]);
    // All primaries down: group 1 becomes active, weighted 3:1.
    h.down = &.{ "http://10.0.0.1:80", "http://10.0.0.2:80", "http://10.0.0.3:80" };
    try testing.expectEqual(@as(?usize, 1), d.firstHealthyGroup(&h, Health.check));
    hits = [_]usize{0} ** 5;
    countPicks(&d, 1, &h, 40, &hits, &all);
    try testing.expectEqual(@as(usize, 30), hits[3]);
    try testing.expectEqual(@as(usize, 10), hits[4]);
    // Primaries recover: back to group 0 immediately.
    h.down = &.{};
    try testing.expectEqual(@as(?usize, 0), d.firstHealthyGroup(&h, Health.check));
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
        .{ .ttl = 1_000, .lo = 4_500, .hi = 5_500 },
        .{ .ttl = 20_000, .lo = 18_000, .hi = 22_000 },
        .{ .ttl = 900_000, .lo = 54_000, .hi = 66_000 },
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
    d.applyFailure(62_000, false, "ServFail");
    try testing.expectEqual(@as(usize, 0), d.urls.items.len);
    try testing.expectEqual(@as(usize, 0), d.groupCount());
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
    try testing.expectEqualStrings("http://10.0.0.1:80", held);
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

/// Scripted A/AAAA answers for SRV targets: the SRV names stay constant while
/// their address sets change between refreshes.
const TargetAnswers = struct {
    mutex: compat.Mutex = .{},
    backend: [2]?[4]u8 = .{ null, null },
    other: [2]?[4]u8 = .{ null, null },

    fn resolve(ctx: ?*anyopaque, host: []const u8, port: u16, out: *[compat.max_resolved_addresses]std.Io.net.IpAddress) []const std.Io.net.IpAddress {
        const self: *TargetAnswers = @ptrCast(@alignCast(ctx.?));
        self.mutex.lock();
        defer self.mutex.unlock();
        const set = if (std.mem.eql(u8, host, "backend.service.test")) self.backend else if (std.mem.eql(u8, host, "other.service.test")) self.other else return out[0..0];
        var n: usize = 0;
        for (set) |maybe| if (maybe) |bytes| {
            out[n] = .{ .ip4 = .{ .bytes = bytes, .port = port } };
            n += 1;
        };
        return out[0..n];
    }
};

test "dns fixture: SRV -> target A rotation -> port, removal, stale, recovery" {
    var fx: Fixture = .{ .sock = -1, .port = 0 };
    try fx.start();
    defer fx.deinit();
    var answers: TargetAnswers = .{};
    const ns = [_]std.Io.net.IpAddress{.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = fx.port } }};
    var d = DnsDiscovery.init(testing.allocator, .{
        .srv_name = "_api._tcp.service.test",
        .nameservers = &ns,
        .query_timeout_ms = 200,
        .stale_max_ms = 10_000,
        .tls = true,
        .target_resolver = .{ .ctx = &answers, .resolve = TargetAnswers.resolve },
    });
    defer d.deinit();

    const recs = [_]Fixture.Rec{
        .{ .prio = 10, .weight = 5, .port = 8443, .target = "backend.service.test" },
        .{ .prio = 10, .weight = 1, .port = 9443, .target = "other.service.test" },
        .{ .prio = 20, .weight = 1, .port = 8443, .target = "backend.service.test" },
    };
    fx.set(.answer, &recs);
    answers.backend = .{ .{ 10, 0, 0, 1 }, null };
    answers.other = .{ .{ 10, 0, 1, 1 }, .{ 10, 0, 1, 2 } };
    d.refresh(1_000);
    try testing.expectEqual(@as(usize, 2), d.groupCount());
    try testing.expectEqual(@as(usize, 3), d.primaryCount());
    try testing.expectEqualStrings("https://10.0.0.1:8443", d.urls.items[0]);
    try testing.expectEqualStrings("https://10.0.1.1:9443", d.urls.items[1]);
    try testing.expectEqualStrings("https://10.0.1.2:9443", d.urls.items[2]);
    try testing.expectEqualStrings("https://10.0.0.1:8443", d.urls.items[3]); // same target, backup priority
    try testing.expectEqual(@as(u64, 1), d.change_count);

    // Only the SRV target's A set changes (same SRV answer): atomic replacement.
    answers.backend = .{ .{ 10, 0, 0, 7 }, null };
    d.refresh(2_000);
    try testing.expectEqualStrings("https://10.0.0.7:8443", d.urls.items[0]);
    try testing.expectEqual(@as(u64, 2), d.change_count);

    // Target removal: only the "other" target remains in the primary group.
    fx.set(.answer, &.{recs[0]});
    d.refresh(3_000);
    try testing.expectEqual(@as(usize, 1), d.groupCount());
    try testing.expectEqual(@as(usize, 1), d.urls.items.len);

    // SERVFAIL and silence keep the last good set (stale)...
    fx.set(.servfail, &.{});
    d.refresh(4_000);
    try testing.expect(d.stale);
    fx.set(.silent, &.{});
    d.refresh(5_000);
    try testing.expect(d.stale);
    try testing.expectEqual(@as(usize, 1), d.urls.items.len);
    // ...until the stale bound passes.
    d.refresh(3_000 + 10_001);
    try testing.expectEqual(@as(usize, 0), d.urls.items.len);

    fx.set(.answer, &.{recs[0]});
    d.refresh(20_000);
    try testing.expectEqual(@as(usize, 1), d.urls.items.len);
    try testing.expect(!d.stale);

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
    d.startRefresh();
    d.deinit();
    try testing.expect(!d.refreshing.load(.acquire));
}
