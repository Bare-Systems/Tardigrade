//! Conservative, bounded, in-memory GET response cache for the generic
//! `proxy_pass` data plane (#901, C1 of the #900 caching roadmap).
//!
//! This is a deliberately narrow slice: only complete, buffered, successful
//! `GET` responses with explicit origin freshness (`max-age`/`s-maxage`) are
//! considered, and only when the request carries no personalized signal
//! (`Authorization`, `Cookie`, verified client certificate, built-in auth,
//! `forward_auth`, or any configured policy rule). `Vary`, `Set-Cookie`, and
//! `no-store`/`private`/`no-cache` responses are never stored. There is no
//! `Vary`-keyed variant handling, no conditional/validator support, and no
//! disk tier here -- those are #902/#903. The entry representation below is
//! intentionally separate from `http.idempotency.IdempotencyStore`, which
//! only models `status/body/content_type` and is not a fit for replaying
//! arbitrary response headers with a correct `Age`.

const std = @import("std");
const compat = @import("zig_compat");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");

/// A response header pair owned by the cache (deep-copied at fill/lookup
/// time so an entry can be replaced or evicted without racing a concurrent
/// reader that is still writing a previously returned copy downstream).
pub const CacheHeader = struct {
    name: []u8,
    value: []u8,
};

/// A borrowed view of a response header, used only while filling an entry:
/// `put` deep-copies every field before it returns, so the caller's buffers
/// (typically the live upstream response) never need to outlive the call.
pub const CacheHeaderView = struct {
    name: []const u8,
    value: []const u8,
};

pub const Limits = struct {
    max_object_bytes: usize,
    max_entries: usize,
    max_total_bytes: usize,
};

pub const PutParams = struct {
    status_code: u16,
    reason: []const u8,
    headers: []const CacheHeaderView,
    body: []const u8,
    /// Already capped by the configured ceiling; `0` means "not cacheable"
    /// and `put` refuses it.
    ttl_seconds: u32,
    /// Age reported by the origin when the response was received. It is kept
    /// separately from resident time so replay emits the RFC-correct current
    /// age even if the process monotonic clock started after the origin did.
    initial_age_seconds: u32 = 0,
};

pub const LookupResult = struct {
    status_code: u16,
    reason: []u8,
    headers: []CacheHeader,
    body: []u8,
    age_seconds: u32,
};

const Entry = struct {
    /// Owns `reason` and every header name/value; `body` is allocated
    /// directly on the cache's allocator (mirrors `BufferedUpstreamResponse`
    /// in `gateway_proxy.zig`, which separates its metadata arena from its
    /// body allocation the same way).
    metadata_arena: std.heap.ArenaAllocator,
    status_code: u16,
    reason: []u8,
    headers: []CacheHeader,
    body: []u8,
    stored_at_ms: u64,
    expires_at_ms: u64,
    initial_age_seconds: u32,
    /// Accounted size used for the aggregate/per-object caps; computed once
    /// at fill time from the same fields.
    bytes: usize,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        self.metadata_arena.deinit();
        allocator.free(self.body);
        self.* = undefined;
    }
};

/// Bounded, generation-free (purged wholesale on reload by its owner)
/// in-memory store. Every public method here assumes the caller already
/// holds whatever mutex `GatewayState` guards it with -- this type has no
/// synchronization of its own, the same ownership split `GatewayState`
/// already uses for `proxy_cache_store`.
pub const ProxyResponseCache = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap(Entry),
    total_bytes: usize = 0,
    limits: Limits,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) ProxyResponseCache {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap(Entry).init(allocator),
            .limits = limits,
        };
    }

    pub fn deinit(self: *ProxyResponseCache) void {
        var it = self.map.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            kv.value_ptr.deinit(self.allocator);
        }
        self.map.deinit();
        self.* = undefined;
    }

    fn removeLocked(self: *ProxyResponseCache, key: []const u8) void {
        if (self.map.fetchRemove(key)) |old| {
            self.total_bytes -= old.value.bytes;
            self.allocator.free(old.key);
            var old_entry = old.value;
            old_entry.deinit(self.allocator);
        }
    }

    /// Deep-copies a live, unexpired entry into `scratch` (expected to be an
    /// arena the caller tears down once the response is written). Returns
    /// `null` on a miss or an expired entry (which this also evicts).
    pub fn lookup(self: *ProxyResponseCache, scratch: std.mem.Allocator, key: []const u8, now_ms: u64) !?LookupResult {
        const entry = self.map.getPtr(key) orelse return null;
        if (now_ms >= entry.expires_at_ms) {
            self.removeLocked(key);
            return null;
        }
        const reason_copy = try scratch.dupe(u8, entry.reason);
        const headers_copy = try scratch.alloc(CacheHeader, entry.headers.len);
        for (entry.headers, 0..) |h, i| {
            headers_copy[i] = .{
                .name = try scratch.dupe(u8, h.name),
                .value = try scratch.dupe(u8, h.value),
            };
        }
        const body_copy = try scratch.dupe(u8, entry.body);
        // Monotonic clock: `now_ms` can only be >= `stored_at_ms`. Preserve
        // any Age the origin already assigned, then add resident time.
        const resident_seconds = (now_ms - entry.stored_at_ms) / 1000;
        const age_seconds: u32 = @intCast(@min(
            @as(u64, entry.initial_age_seconds) + resident_seconds,
            std.math.maxInt(u32),
        ));
        return LookupResult{
            .status_code = entry.status_code,
            .reason = reason_copy,
            .headers = headers_copy,
            .body = body_copy,
            .age_seconds = age_seconds,
        };
    }

    fn objectBytes(key: []const u8, params: PutParams) usize {
        var total: usize = key.len + params.reason.len + params.body.len + 64;
        for (params.headers) |h| total += h.name.len + h.value.len + 2;
        return total;
    }

    /// Stores (or replaces) one entry. Fails open: any error here (object
    /// too large, store at capacity, or allocation failure) leaves the
    /// cache exactly as it was -- the caller already proxied the response
    /// normally and only needs this for metrics.
    pub fn put(self: *ProxyResponseCache, now_ms: u64, key: []const u8, params: PutParams) !void {
        if (params.ttl_seconds == 0 or params.initial_age_seconds >= params.ttl_seconds) return error.NotCacheable;
        const object_bytes = objectBytes(key, params);
        if (object_bytes > self.limits.max_object_bytes) return error.ObjectTooLarge;

        // Reserve map capacity before taking ownership away from an existing
        // entry. A failed reservation/allocation therefore leaves a live
        // entry untouched even when concurrent misses race to fill one key.
        try self.map.ensureUnusedCapacity(1);
        const replacing = self.map.getPtr(key);
        const prior_bytes: usize = if (replacing) |old| old.bytes else 0;
        const retained_bytes = self.total_bytes - prior_bytes;
        if ((replacing == null and self.map.count() >= self.limits.max_entries) or
            object_bytes > self.limits.max_total_bytes - retained_bytes)
        {
            return error.CacheAtCapacity;
        }

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        const owned_reason = try a.dupe(u8, params.reason);
        const owned_headers = try a.alloc(CacheHeader, params.headers.len);
        for (params.headers, 0..) |h, i| {
            owned_headers[i] = .{
                .name = try a.dupe(u8, h.name),
                .value = try a.dupe(u8, h.value),
            };
        }
        const owned_body = try self.allocator.dupe(u8, params.body);
        errdefer self.allocator.free(owned_body);
        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);

        const entry = Entry{
            .metadata_arena = arena,
            .status_code = params.status_code,
            .reason = owned_reason,
            .headers = owned_headers,
            .body = owned_body,
            .stored_at_ms = now_ms,
            .expires_at_ms = now_ms + @as(u64, params.ttl_seconds - params.initial_age_seconds) * 1000,
            .initial_age_seconds = params.initial_age_seconds,
            .bytes = object_bytes,
        };

        self.removeLocked(key);
        self.map.putAssumeCapacity(owned_key, entry);
        self.total_bytes += object_bytes;
    }
};

pub const KeyParts = struct {
    scheme: []const u8,
    host: []const u8,
    method: []const u8,
    /// The matched location's own pattern: distinguishes two locations that
    /// happen to proxy the same literal path to different upstreams after a
    /// rewrite, and is always the *effective* (post-rewrite) location by
    /// construction, since the cache check runs after routing settles.
    location_id: []const u8,
    /// The location's configured `proxy_pass` target, not the load-balancer-
    /// selected pool member: round-robin rotation across a pool must not
    /// fragment the cache.
    upstream_target: []const u8,
    path: []const u8,
    query: []const u8,
};

/// Canonical, collision-resistant cache key: a SHA-256 digest over each
/// field, length-prefixed so no delimiter choice can make two distinct field
/// splits hash identically. Every input is already bounded by existing
/// request-size/config limits, so this is O(request size) bounded work, not
/// unbounded per-request cost.
pub fn buildCacheKey(out: *[64]u8, parts: KeyParts) []const u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (.{
        parts.scheme,
        parts.host,
        parts.method,
        parts.location_id,
        parts.upstream_target,
        parts.path,
        parts.query,
    }) |field| {
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, @intCast(field.len), .little);
        hasher.update(&len_buf);
        hasher.update(field);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    _ = std.fmt.bufPrint(out, "{f}", .{compat.fmtSliceHexLower(&digest)}) catch unreachable;
    return out[0..];
}

/// Request-side eligibility: conservative by construction (#901 contract).
/// Any personalization signal -- built-in auth, `forward_auth`, a verified
/// client certificate, a configured policy table, or a client-supplied
/// `Authorization`/`Cookie` -- disqualifies the request outright rather than
/// trying to partition the cache by identity. Conditional/`Range` requests
/// are also excluded: C1 has no validator or partial-content story.
pub fn isCacheableRequest(
    cfg: *const edge_config.EdgeConfig,
    block: *const edge_config.EdgeConfig.LocationBlock,
    method: []const u8,
    headers: *const http.Headers,
) bool {
    if (!std.mem.eql(u8, method, "GET")) return false;
    if (block.auth != .off) return false;
    if (block.forward_auth != null) return false;
    if (!block.client_cert.isEmpty()) return false;
    if (headers.client_cert != null) return false;
    if (cfg.policy_rules_raw.len > 0 or cfg.policy_approval_routes_raw.len > 0) return false;
    if (headers.get("authorization") != null) return false;
    if (headers.get("cookie") != null) return false;
    if (headers.get("range") != null) return false;
    if (headers.get("if-range") != null) return false;
    if (headers.get("if-match") != null) return false;
    if (headers.get("if-none-match") != null) return false;
    if (headers.get("if-modified-since") != null) return false;
    if (headers.get("if-unmodified-since") != null) return false;
    return true;
}

pub const Freshness = struct {
    /// The total freshness lifetime, capped by the operator's configured
    /// ceiling, before subtracting an origin-supplied Age.
    ttl_seconds: u32,
    initial_age_seconds: u32,
};

/// Response-side cacheability and effective freshness. Requires an explicit
/// `max-age`/`s-maxage` from the origin (no heuristic/`Expires`-only
/// freshness); `Set-Cookie`, `Vary` (any value), `no-store`, `private`, and
/// `no-cache` all refuse caching. The returned TTL is already capped by
/// `ceiling_seconds` (the operator's configured maximum). `headers` is
/// `anytype` so both the H1 and H3 proxy paths can pass their own
/// upstream-header slice shape without an extra copy.
pub fn responseFreshness(headers: anytype, ceiling_seconds: u32) ?Freshness {
    if (ceiling_seconds == 0) return null;
    var max_age: ?u32 = null;
    var s_maxage: ?u32 = null;
    var response_age: ?u32 = null;
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "set-cookie")) return null;
        if (std.ascii.eqlIgnoreCase(h.name, "vary")) return null;
        if (std.ascii.eqlIgnoreCase(h.name, "age")) {
            if (response_age != null) return null;
            response_age = std.fmt.parseInt(u32, std.mem.trim(u8, h.value, " \t"), 10) catch return null;
            continue;
        }
        if (!std.ascii.eqlIgnoreCase(h.name, "cache-control")) continue;
        var it = std.mem.splitScalar(u8, h.value, ',');
        while (it.next()) |raw_tok| {
            const tok = std.mem.trim(u8, raw_tok, " \t");
            if (std.ascii.eqlIgnoreCase(tok, "no-store") or
                std.ascii.eqlIgnoreCase(tok, "private") or
                std.ascii.eqlIgnoreCase(tok, "no-cache")) return null;
            if (std.ascii.startsWithIgnoreCase(tok, "s-maxage=")) {
                s_maxage = std.fmt.parseInt(u32, std.mem.trim(u8, tok["s-maxage=".len..], " \t"), 10) catch null;
            } else if (std.ascii.startsWithIgnoreCase(tok, "max-age=")) {
                max_age = std.fmt.parseInt(u32, std.mem.trim(u8, tok["max-age=".len..], " \t"), 10) catch null;
            }
        }
    }
    const ttl_seconds = @min(s_maxage orelse max_age orelse return null, ceiling_seconds);
    if (ttl_seconds == 0) return null;
    const initial_age_seconds = response_age orelse 0;
    // A stale response must not become fresh merely because it was received
    // by this cache. C1 has no revalidation support.
    if (initial_age_seconds >= ttl_seconds) return null;
    return .{ .ttl_seconds = ttl_seconds, .initial_age_seconds = initial_age_seconds };
}

test "isCacheableRequest accepts a plain GET and refuses personalized signals" {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.policy_rules_raw = "";
    cfg.policy_approval_routes_raw = "";
    var block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:1" },
    };

    var headers = http.Headers.init(std.testing.allocator);
    defer headers.deinit();
    try std.testing.expect(isCacheableRequest(&cfg, &block, "GET", &headers));
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "POST", &headers));
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "HEAD", &headers));

    try headers.append("Authorization", "Bearer x");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    try headers.append("Cookie", "a=b");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    try headers.append("Range", "bytes=0-10");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers));

    block.auth = .required;
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &http.Headers.init(std.testing.allocator)));
}

test "isCacheableRequest refuses forward_auth, client-cert policy, client identity and route policy" {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.policy_rules_raw = "";
    cfg.policy_approval_routes_raw = "";
    var empty_headers = http.Headers.init(std.testing.allocator);
    defer empty_headers.deinit();

    var fa_block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:1" },
        .forward_auth = .{ .url = "http://127.0.0.1:1/verify" },
    };
    try std.testing.expect(!isCacheableRequest(&cfg, &fa_block, "GET", &empty_headers));

    var cert_block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:1" },
        .client_cert = .{ .required = true },
    };
    try std.testing.expect(!isCacheableRequest(&cfg, &cert_block, "GET", &empty_headers));

    var plain_block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:1" },
    };
    var identified_headers = http.Headers.init(std.testing.allocator);
    defer identified_headers.deinit();
    identified_headers.client_cert = .{ .fingerprint_sha256 = "ab" ** 32, .subject = "CN=alice" };
    try std.testing.expect(!isCacheableRequest(&cfg, &plain_block, "GET", &identified_headers));

    cfg.policy_rules_raw = "GET|^/$|read|false||";
    try std.testing.expect(!isCacheableRequest(&cfg, &plain_block, "GET", &empty_headers));
}

const TestHeader = struct { name: []const u8, value: []const u8 };

test "responseFreshness requires explicit max-age, caps by ceiling and honors Age" {
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{}, 300));
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Content-Type", .value = "text/plain" },
    }, 300));
    try std.testing.expectEqual(Freshness{ .ttl_seconds = 60, .initial_age_seconds = 0 }, responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "public, max-age=60" },
    }, 300));
    try std.testing.expectEqual(Freshness{ .ttl_seconds = 300, .initial_age_seconds = 0 }, responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=3600" },
    }, 300));
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60" },
        .{ .name = "Set-Cookie", .value = "a=b" },
    }, 300));
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60" },
        .{ .name = "Vary", .value = "Accept-Encoding" },
    }, 300));
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "private, max-age=60" },
    }, 300));
    try std.testing.expectEqual(Freshness{ .ttl_seconds = 10, .initial_age_seconds = 0 }, responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60, s-maxage=10" },
    }, 300));
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=0" },
    }, 300));
    try std.testing.expectEqual(Freshness{ .ttl_seconds = 60, .initial_age_seconds = 20 }, responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60" },
        .{ .name = "Age", .value = "20" },
    }, 300));
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60" },
        .{ .name = "Age", .value = "60" },
    }, 300));
}

test "buildCacheKey is deterministic and distinguishes field splits" {
    var out1: [64]u8 = undefined;
    const k1 = buildCacheKey(&out1, .{
        .scheme = "http",
        .host = "a",
        .method = "GET",
        .location_id = "/",
        .upstream_target = "http://up",
        .path = "/ab",
        .query = "",
    });
    var out2: [64]u8 = undefined;
    const k2 = buildCacheKey(&out2, .{
        .scheme = "http",
        .host = "a",
        .method = "GET",
        .location_id = "/",
        .upstream_target = "http://up",
        .path = "/a",
        .query = "b",
    });
    var out3: [64]u8 = undefined;
    const k3 = buildCacheKey(&out3, .{
        .scheme = "http",
        .host = "a",
        .method = "GET",
        .location_id = "/",
        .upstream_target = "http://up",
        .path = "/ab",
        .query = "",
    });
    try std.testing.expectEqual(@as(usize, 64), k1.len);
    try std.testing.expect(!std.mem.eql(u8, k1, k2));
    try std.testing.expectEqualStrings(k1, k3);
}

test "ProxyResponseCache stores, replays with Age, expires and evicts" {
    const allocator = std.testing.allocator;
    var cache = ProxyResponseCache.init(allocator, .{
        .max_object_bytes = 4096,
        .max_entries = 4,
        .max_total_bytes = 16 * 1024,
    });
    defer cache.deinit();

    try cache.put(1_000, "key-a", .{
        .status_code = 200,
        .reason = "OK",
        .headers = &[_]CacheHeaderView{.{ .name = "Content-Type", .value = "text/plain" }},
        .body = "hello",
        .ttl_seconds = 10,
    });

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const hit = (try cache.lookup(arena.allocator(), "key-a", 3_000)).?;
    try std.testing.expectEqual(@as(u16, 200), hit.status_code);
    try std.testing.expectEqualStrings("hello", hit.body);
    try std.testing.expectEqual(@as(u32, 2), hit.age_seconds);

    try cache.put(3_000, "key-with-origin-age", .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{},
        .body = "aged",
        .ttl_seconds = 10,
        .initial_age_seconds = 6,
    });
    const aged_hit = (try cache.lookup(arena.allocator(), "key-with-origin-age", 5_000)).?;
    try std.testing.expectEqual(@as(u32, 8), aged_hit.age_seconds);
    try std.testing.expectEqual(@as(?LookupResult, null), try cache.lookup(arena.allocator(), "key-with-origin-age", 7_001));

    try std.testing.expectEqual(@as(?LookupResult, null), try cache.lookup(arena.allocator(), "key-missing", 3_000));
    try std.testing.expectEqual(@as(?LookupResult, null), try cache.lookup(arena.allocator(), "key-a", 11_001));
    try std.testing.expectEqual(@as(usize, 0), cache.map.count());
}

test "ProxyResponseCache fails open on an oversized object and a full store" {
    const allocator = std.testing.allocator;
    var cache = ProxyResponseCache.init(allocator, .{
        .max_object_bytes = 32,
        .max_entries = 1,
        .max_total_bytes = 1024,
    });
    defer cache.deinit();

    try std.testing.expectError(error.ObjectTooLarge, cache.put(0, "too-big", .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{},
        .body = "this body is much too large for the cap",
        .ttl_seconds = 10,
    }));
    try std.testing.expectEqual(@as(usize, 0), cache.map.count());

    var small_cache = ProxyResponseCache.init(allocator, .{
        .max_object_bytes = 4096,
        .max_entries = 1,
        .max_total_bytes = 4096,
    });
    defer small_cache.deinit();
    try small_cache.put(0, "first", .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{},
        .body = "a",
        .ttl_seconds = 10,
    });
    try std.testing.expectError(error.CacheAtCapacity, small_cache.put(0, "second", .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{},
        .body = "b",
        .ttl_seconds = 10,
    }));
    try std.testing.expectEqual(@as(usize, 1), small_cache.map.count());
}
