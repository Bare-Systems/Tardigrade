/// DNS-based upstream service discovery for Tardigrade.
///
/// Resolves a configured hostname to its A/AAAA addresses and produces a list
/// of `http[s]://addr:port` upstream URLs. The list is refreshed periodically
/// and can be merged with statically configured upstream pools.
///
/// Usage:
///   var disc = DnsDiscovery.init(allocator, config);
///   defer disc.deinit();
///
///   // Refresh now (call periodically):
///   if (disc.needsRefresh(now_ms)) {
///       try disc.refresh(now_ms);
///   }
///
///   // Read current upstream URLs (hold disc.mutex while reading):
///   disc.mutex.lock(); defer disc.mutex.unlock();
///   for (disc.urls.items) |url| { ... }
const std = @import("std");

pub const Config = struct {
    /// Hostname to resolve (empty string disables discovery).
    host: []const u8,
    /// Port number to attach to each resolved address.
    port: u16,
    /// Use HTTPS for discovered upstreams.
    tls: bool,
    /// How often to re-resolve the hostname, in milliseconds.
    refresh_interval_ms: u64,
};

pub const DnsDiscovery = struct {
    allocator: std.mem.Allocator,
    config: Config,
    mutex: std.Thread.Mutex,
    /// Currently known upstream URLs (owned strings).
    urls: std.ArrayList([]u8),
    /// Epoch-ms timestamp of the last successful resolution.
    last_refresh_ms: u64,
    /// Number of times the URL set has changed since init.
    change_count: u64,

    pub fn init(allocator: std.mem.Allocator, config: Config) DnsDiscovery {
        return .{
            .allocator = allocator,
            .config = config,
            .mutex = .{},
            .urls = std.ArrayList([]u8).init(allocator),
            .last_refresh_ms = 0,
            .change_count = 0,
        };
    }

    pub fn deinit(self: *DnsDiscovery) void {
        for (self.urls.items) |url| self.allocator.free(url);
        self.urls.deinit();
    }

    /// Returns true when the next refresh is due.
    pub fn needsRefresh(self: *const DnsDiscovery, now_ms: u64) bool {
        if (self.config.host.len == 0) return false;
        if (self.last_refresh_ms == 0) return true;
        return now_ms -| self.last_refresh_ms >= self.config.refresh_interval_ms;
    }

    /// Resolve the configured hostname and update the URL list.
    /// Thread-safe: acquires self.mutex while updating the list.
    /// Logs changes to stderr.
    pub fn refresh(self: *DnsDiscovery, now_ms: u64) void {
        if (self.config.host.len == 0) return;

        // Resolve — getAddressList is blocking and must not be called under
        // our mutex (it can be slow). Build the new list without the lock.
        var new_urls = std.ArrayList([]u8).init(self.allocator);
        defer {
            // On any early return free what we built.
            for (new_urls.items) |u| self.allocator.free(u);
            new_urls.deinit();
        }

        const list = std.net.getAddressList(self.allocator, self.config.host, self.config.port) catch |err| {
            std.debug.print("dns_discovery: resolve {s}:{d} failed: {s}\n", .{
                self.config.host, self.config.port, @errorName(err),
            });
            return;
        };
        defer list.deinit();

        const scheme: []const u8 = if (self.config.tls) "https" else "http";
        for (list.addrs) |addr| {
            const url = switch (addr.any.family) {
                std.posix.AF.INET => blk: {
                    const ip4 = addr.in;
                    const b = std.mem.toBytes(ip4.sa.addr);
                    break :blk std.fmt.allocPrint(self.allocator, "{s}://{d}.{d}.{d}.{d}:{d}", .{
                        scheme, b[0], b[1], b[2], b[3], self.config.port,
                    }) catch continue;
                },
                std.posix.AF.INET6 => blk: {
                    // Format IPv6 as [addr]:port
                    var buf: [64]u8 = undefined;
                    const ip6_str = std.fmt.bufPrint(&buf, "{}", .{addr}) catch continue;
                    // ip6_str includes the port, e.g. "[::1]:8080"; strip it.
                    const bracket_end = std.mem.indexOfScalar(u8, ip6_str, ']') orelse continue;
                    const ip6_only = ip6_str[0 .. bracket_end + 1];
                    break :blk std.fmt.allocPrint(self.allocator, "{s}://{s}:{d}", .{
                        scheme, ip6_only, self.config.port,
                    }) catch continue;
                },
                else => continue,
            };
            new_urls.append(url) catch {
                self.allocator.free(url);
                continue;
            };
        }

        // Swap under the lock.
        self.mutex.lock();
        defer self.mutex.unlock();

        const changed = !urlSetsEqual(self.urls.items, new_urls.items);
        if (changed) {
            self.change_count += 1;
            std.debug.print("dns_discovery: {s} resolved to {d} upstream(s) (change #{d})\n", .{
                self.config.host, new_urls.items.len, self.change_count,
            });
            for (new_urls.items) |u| {
                std.debug.print("  + {s}\n", .{u});
            }
        }

        // Free old URLs and swap in the new list.
        for (self.urls.items) |u| self.allocator.free(u);
        self.urls.clearRetainingCapacity();
        // Transfer ownership of new_urls items to self.urls.
        for (new_urls.items) |u| {
            self.urls.append(u) catch {};
        }
        // Prevent new_urls defer from double-freeing transferred items.
        new_urls.clearRetainingCapacity();

        self.last_refresh_ms = now_ms;
    }

    /// Copy current URL strings into `out`. Caller owns the returned slice and
    /// each string. Must NOT be called while holding self.mutex.
    pub fn copyUrls(self: *DnsDiscovery, allocator: std.mem.Allocator) ![][]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const out = try allocator.alloc([]const u8, self.urls.items.len);
        for (self.urls.items, 0..) |url, i| {
            out[i] = try allocator.dupe(u8, url);
        }
        return out;
    }
};

/// Returns true when both sets contain identical URLs (order-independent).
fn urlSetsEqual(a: []const []u8, b: []const []u8) bool {
    if (a.len != b.len) return false;
    for (a) |ua| {
        var found = false;
        for (b) |ub| {
            if (std.mem.eql(u8, ua, ub)) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
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

test "urlSetsEqual" {
    var a = [_][]u8{ @constCast("http://1.2.3.4:80"), @constCast("http://5.6.7.8:80") };
    var b = [_][]u8{ @constCast("http://5.6.7.8:80"), @constCast("http://1.2.3.4:80") };
    var c = [_][]u8{ @constCast("http://1.2.3.4:80") };
    try testing.expect(urlSetsEqual(&a, &b));
    try testing.expect(!urlSetsEqual(&a, &c));
    try testing.expect(urlSetsEqual(&c, &c));
}
