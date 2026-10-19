//! Conservative, bounded, in-memory GET response cache for the generic
//! `proxy_pass` data plane (#901 C1, extended by #902 C2).
//!
//! C1 is a deliberately narrow slice: only complete, buffered, successful
//! `GET` responses with explicit origin freshness (`max-age`/`s-maxage`) are
//! considered, and only when the request carries no personalized signal
//! (`Authorization`, `Cookie`, verified client certificate, built-in auth,
//! `forward_auth`, or any configured policy rule). `Set-Cookie` and
//! `no-store`/`private`/`no-cache` responses are never stored, and neither is
//! a response carrying any `Vary` value this cache does not understand. No
//! disk tier here -- that is #903.
//!
//! C2 adds, on top of that conservative base: a bounded, FIFO-capped
//! `Vary: Accept-Encoding` variant store (every other `Vary` field name, and
//! `Vary: *`, still refuse storage outright rather than attempt a general
//! per-header variant space); `ETag`/`Last-Modified` validator-based
//! conditional responses answered entirely from an already-fresh cache entry
//! (`If-None-Match`/`If-Modified-Since` -> `304`); and serving `HEAD` from a
//! stored `GET` entry's metadata. Upstream-initiated revalidation of a
//! *stale* entry (the cache itself issuing a conditional request to the
//! origin and refreshing metadata on a `304`) and bounded single-flight fill
//! collapsing are not implemented here; see the C2 follow-up issue. The entry
//! representation below is intentionally separate from
//! `http.idempotency.IdempotencyStore`, which only models
//! `status/body/content_type` and is not a fit for replaying arbitrary
//! response headers with a correct `Age`.

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
    /// Bounded count of distinct `Vary: Accept-Encoding` representations
    /// retained per resource (clamped to `hard_max_vary_variants`). Beyond
    /// this, the oldest variant is evicted FIFO to admit a new one rather
    /// than let a high-cardinality `Accept-Encoding` set grow one resource's
    /// storage without bound.
    max_vary_variants: usize = 8,
};

/// Absolute ceiling on `Limits.max_vary_variants`, independent of operator
/// configuration: bounds `VaryIndexEntry`'s inline storage at compile time.
pub const hard_max_vary_variants: usize = 16;

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

/// Tracks, for one primary (Vary-insensitive) key, the bounded set of
/// secondary keys actually storing a `Vary: Accept-Encoding` representation.
/// Once a primary key has an index entry, `lookup`/`put` for that resource
/// always go through a secondary key -- a direct entry at the primary key
/// itself is never consulted again (see `putVaryVariant`), so there is no
/// ambiguity about which representation a plain lookup would return.
const VaryIndexEntry = struct {
    variant_keys: [hard_max_vary_variants][64]u8 = undefined,
    count: usize = 0,
    /// Next slot to evict FIFO once `count` reaches the configured cap.
    next_write: usize = 0,
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
    vary_index: std.StringHashMap(VaryIndexEntry),
    max_vary_variants: usize,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) ProxyResponseCache {
        return .{
            .allocator = allocator,
            .map = std.StringHashMap(Entry).init(allocator),
            .limits = limits,
            .vary_index = std.StringHashMap(VaryIndexEntry).init(allocator),
            .max_vary_variants = @max(1, @min(limits.max_vary_variants, hard_max_vary_variants)),
        };
    }

    pub fn deinit(self: *ProxyResponseCache) void {
        var it = self.map.iterator();
        while (it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
            kv.value_ptr.deinit(self.allocator);
        }
        self.map.deinit();
        var vit = self.vary_index.iterator();
        while (vit.next()) |kv| self.allocator.free(kv.key_ptr.*);
        self.vary_index.deinit();
        self.* = undefined;
    }

    /// Whether `primary_key` (from `buildCacheKey`) currently resolves
    /// through the `Vary` variant index rather
    /// than storing a direct entry under that key itself.
    pub fn isVaryTracked(self: *const ProxyResponseCache, primary_key: []const u8) bool {
        return self.vary_index.contains(primary_key);
    }

    /// Stores a `Vary: Accept-Encoding` representation under `secondary_key`
    /// (the primary key's fields plus this fill's normalized discriminator)
    /// and registers it in the bounded per-resource variant index.
    pub fn putVaryVariant(self: *ProxyResponseCache, now_ms: u64, primary_key: []const u8, secondary_key: []const u8, params: PutParams) !void {
        // A resource transitioning from a direct (non-Vary) entry into
        // tracked-variant storage must not leave the stale direct entry
        // permanently resident: once tracked, lookup() never looks at the
        // primary slot again, so an orphan there would just occupy capacity
        // until a reload wholesale-purges the cache.
        if (!self.vary_index.contains(primary_key)) self.removeLocked(primary_key);
        try self.put(now_ms, secondary_key, params);
        // Index bookkeeping is opportunistic like the rest of this cache:
        // the representation above is already correctly stored and
        // reachable by any future lookup that independently recomputes the
        // same secondary key, so a failure here just means this particular
        // variant will not be retired by FIFO eviction later (acceptable --
        // still bounded by `max_entries`/`max_total_bytes`).
        self.registerVaryVariant(primary_key, secondary_key) catch {};
    }

    fn registerVaryVariant(self: *ProxyResponseCache, primary_key: []const u8, secondary_key: []const u8) !void {
        std.debug.assert(secondary_key.len == 64);
        if (self.vary_index.getPtr(primary_key)) |existing| {
            self.appendOrEvictVariant(existing, secondary_key);
            return;
        }
        try self.vary_index.ensureUnusedCapacity(1);
        const owned_key = try self.allocator.dupe(u8, primary_key);
        errdefer self.allocator.free(owned_key);
        var fresh = VaryIndexEntry{};
        self.appendOrEvictVariant(&fresh, secondary_key);
        self.vary_index.putAssumeCapacity(owned_key, fresh);
    }

    fn appendOrEvictVariant(self: *ProxyResponseCache, index: *VaryIndexEntry, secondary_key: []const u8) void {
        for (index.variant_keys[0..index.count]) |existing_key| {
            if (std.mem.eql(u8, existing_key[0..], secondary_key)) return;
        }
        if (index.count < self.max_vary_variants) {
            @memcpy(index.variant_keys[index.count][0..], secondary_key[0..64]);
            index.count += 1;
            return;
        }
        // Bounded FIFO: evict the oldest variant to admit this one rather
        // than let a high-cardinality Accept-Encoding set grow this
        // resource's variant storage without bound (#902).
        const slot = index.next_write % self.max_vary_variants;
        self.removeLocked(index.variant_keys[slot][0..]);
        @memcpy(index.variant_keys[slot][0..], secondary_key[0..64]);
        index.next_write = slot + 1;
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
/// unbounded per-request cost. This is always the *primary* (Vary-insensitive)
/// key -- see `buildVaryVariantKey` for the secondary key a tracked `Vary:
/// Accept-Encoding` resource actually stores/looks up under.
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

/// Derives the secondary key for one `Vary: Accept-Encoding` representation
/// from a resource's already-computed primary key (`buildCacheKey`) and a
/// bounded, normalized discriminator (`varyAcceptEncodingDiscriminator`).
/// Defined as a function of the primary key rather than the original
/// `KeyParts` so a lookup/fill call site only needs to carry one extra
/// 64-byte buffer forward, not the whole request-derived field set again.
pub fn buildVaryVariantKey(out: *[64]u8, primary_key: []const u8, discriminator: []const u8) []const u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (.{ primary_key, discriminator }) |field| {
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

/// Bounded scratch space for `varyAcceptEncodingDiscriminator`'s joined
/// output -- large enough for `max_vary_tokens` short coding names with
/// room to spare, never sized from the request itself.
pub const max_vary_discriminator_bytes: usize = 128;
/// Bounded count of distinct codings a request's `Accept-Encoding` may list
/// and still participate in `Vary: Accept-Encoding` variant caching. A
/// request listing more than this is treated as unrepresentable here --
/// never silently truncated -- and the caller must bypass the cache for it.
pub const max_vary_tokens: usize = 8;

fn qualityIsZero(coding_params: []const u8) bool {
    var it = std.mem.splitScalar(u8, coding_params, ';');
    _ = it.next(); // the coding name slot itself; parameters start after it
    while (it.next()) |raw_param| {
        const param = std.mem.trim(u8, raw_param, " \t");
        if (!std.ascii.startsWithIgnoreCase(param, "q=")) continue;
        const q = std.mem.trim(u8, param["q=".len..], " \t");
        const value = std.fmt.parseFloat(f64, q) catch return false;
        return value <= 0.0;
    }
    return false;
}

fn lessThanAsciiOrder(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// A bounded, order/case/whitespace-insensitive discriminator for a `Vary:
/// Accept-Encoding` variant: the request's acceptable coding names (q=0
/// exclusions dropped, q-weights otherwise ignored), lowercased, deduped by
/// exact match, sorted, and comma-joined. Two requests whose `Accept-Encoding`
/// differ only in weighting, order, or case collapse onto the same
/// representation instead of fragmenting the cache. Returns `null` when the
/// header lists more codings than `max_vary_tokens` or overflows the output
/// buffer -- the caller must treat that as unrepresentable (bypass), never
/// as an unbounded key.
pub fn varyAcceptEncodingDiscriminator(buf: *[max_vary_discriminator_bytes]u8, accept_encoding: ?[]const u8) ?[]const u8 {
    const raw = accept_encoding orelse return buf[0..0];
    var tokens: [max_vary_tokens][]const u8 = undefined;
    var count: usize = 0;
    var lower_buf: [max_vary_discriminator_bytes]u8 = undefined;
    var lower_used: usize = 0;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const semi = std.mem.indexOfScalar(u8, part, ';') orelse part.len;
        const name = std.mem.trim(u8, part[0..semi], " \t");
        if (name.len == 0) continue;
        if (qualityIsZero(part[semi..])) continue;
        if (count >= max_vary_tokens) return null;
        if (lower_used + name.len > lower_buf.len) return null;
        const lowered = std.ascii.lowerString(lower_buf[lower_used..][0..name.len], name);
        lower_used += name.len;
        // A duplicate coding name (same lowered bytes) contributes no new
        // information to the discriminator.
        var duplicate = false;
        for (tokens[0..count]) |seen| {
            if (std.mem.eql(u8, seen, lowered)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        tokens[count] = lowered;
        count += 1;
    }
    std.sort.insertion([]const u8, tokens[0..count], {}, lessThanAsciiOrder);
    var stream = compat.fixedBufferStream(buf);
    const writer = stream.writer();
    for (tokens[0..count], 0..) |tok, i| {
        if (i != 0) writer.writeByte(',') catch return null;
        writer.writeAll(tok) catch return null;
    }
    return stream.getWritten();
}

/// Request-side eligibility: conservative by construction (#901 contract).
/// Any personalization signal -- built-in auth, `forward_auth`, a verified
/// client certificate, a configured policy table, an already-authenticated
/// request context, or a client-supplied `Authorization`/`Cookie` --
/// disqualifies the request outright rather than
/// trying to partition the cache by identity. `Range`/`If-Range` requests are
/// also excluded: this cache has no partial-content story (#902 explicitly
/// defers it). `If-None-Match`/`If-Modified-Since` are *not* excluded here
/// since #902 -- `decideCacheServe` evaluates them once a hit is found, and
/// falls back to the origin itself when the hit cannot be safely validated
/// (no stored validator). `If-Match`/`If-Unmodified-Since` remain excluded:
/// their semantics are for conditional mutation, not GET freshness, and this
/// cache does not implement them.
pub fn isCacheableRequest(
    cfg: *const edge_config.EdgeConfig,
    block: *const edge_config.EdgeConfig.LocationBlock,
    method: []const u8,
    headers: *const http.Headers,
    request_has_body: bool,
    streaming_request_body: bool,
    encountered_identity_gate: bool,
) bool {
    // HEAD is answered only from an already-stored GET entry's metadata
    // (never filled from a HEAD response itself -- callers gate fill on the
    // original method being GET).
    if (!std.mem.eql(u8, method, "GET") and !std.mem.eql(u8, method, "HEAD")) return false;
    // C1 deliberately has no request-body cache key. A bodyful (or not-yet
    // materialized streaming) GET must therefore always reach the origin.
    if (request_has_body or streaming_request_body) return false;
    if (headers.get("transfer-encoding") != null) return false;
    if (headers.get("content-length")) |raw_length| {
        const content_length = std.fmt.parseInt(usize, std.mem.trim(u8, raw_length, " \t"), 10) catch return false;
        if (content_length != 0) return false;
    }
    // The final location may be public even though an earlier rewrite hop
    // authenticated the caller and asserted origin-facing identity headers.
    // A session/bearer identity can be established before location routing,
    // so route-gate history alone is not sufficient here. Callers fold the
    // request context's authenticated/identity state into this flag.
    if (encountered_identity_gate) return false;
    if (block.auth != .off) return false;
    if (block.forward_auth != null) return false;
    if (!block.client_cert.isEmpty()) return false;
    if (headers.client_cert != null) return false;
    if (cfg.policy_rules_raw.len > 0 or cfg.policy_approval_routes_raw.len > 0) return false;
    if (headers.get("authorization") != null) return false;
    if (headers.get("cookie") != null) return false;
    // An event-stream is an open-ended, per-subscriber representation even
    // when an upstream happens to finish one response. C1 intentionally has
    // no streaming semantics, so an explicit client request for SSE must
    // never look up or fill the shared cache. Likewise an Upgrade request is
    // not an ordinary GET representation (including WebSocket handshakes).
    if (headers.get("accept")) |accept| {
        if (hasEventStreamMediaType(accept)) return false;
    }
    if (headers.get("upgrade") != null) return false;
    // `X-Session-Token` is consumed before routing and becomes an asserted
    // upstream identity header. Reject it even if validation failed or a
    // caller did not have a context to report.
    if (headers.get("x-session-token") != null) return false;
    if (headers.get("range") != null) return false;
    if (headers.get("if-range") != null) return false;
    if (headers.get("if-match") != null) return false;
    if (headers.get("if-unmodified-since") != null) return false;
    return true;
}

pub const Freshness = struct {
    /// The total freshness lifetime, capped by the operator's configured
    /// ceiling, before subtracting an origin-supplied Age.
    ttl_seconds: u32,
    initial_age_seconds: u32,
    /// Set when the response's `Vary` is exactly (and only) `Accept-Encoding`
    /// -- the one bounded `Vary` form this cache stores as a variant rather
    /// than refusing outright. Every other `Vary` content, including `*` or
    /// any additional field name, still makes this function return `null`.
    vary_on_accept_encoding: bool = false,
};

/// Match an HTTP media type while ignoring case, surrounding whitespace, and
/// parameters. `Accept` may contain a comma-separated list; response
/// Content-Type normally contains one item, and both forms are handled here.
fn hasEventStreamMediaType(value: []const u8) bool {
    var values = std.mem.splitScalar(u8, value, ',');
    while (values.next()) |raw_value| {
        const media_type = std.mem.trim(u8, raw_value[0 .. std.mem.indexOfScalar(u8, raw_value, ';') orelse raw_value.len], " \t");
        if (std.ascii.eqlIgnoreCase(media_type, "text/event-stream")) return true;
    }
    return false;
}

/// Response-side cacheability and effective freshness. Requires an explicit
/// `max-age`/`s-maxage` from the origin (no heuristic/`Expires`-only
/// freshness); `Set-Cookie`, `no-store`, `private`, and `no-cache` all refuse
/// caching. `Vary` refuses caching too *unless* its only field name (across
/// every `Vary` field line) is `Accept-Encoding` -- the one bounded variant
/// form this cache implements (#902); `Vary: *` and any other field name
/// still bypass entirely, matching the #901 conservative default. The
/// returned TTL is already capped by `ceiling_seconds` (the operator's
/// configured maximum). `headers` is `anytype` so both the H1 and H3 proxy
/// paths can pass their own upstream-header slice shape without an extra
/// copy.
pub fn responseFreshness(headers: anytype, ceiling_seconds: u32) ?Freshness {
    if (ceiling_seconds == 0) return null;
    var max_age: ?u32 = null;
    var s_maxage: ?u32 = null;
    var response_age: ?u32 = null;
    var saw_vary = false;
    var vary_is_only_accept_encoding = true;
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "set-cookie")) return null;
        if (std.ascii.eqlIgnoreCase(h.name, "vary")) {
            saw_vary = true;
            var vary_it = std.mem.splitScalar(u8, h.value, ',');
            while (vary_it.next()) |raw_field| {
                const field = std.mem.trim(u8, raw_field, " \t");
                if (!std.ascii.eqlIgnoreCase(field, "accept-encoding")) vary_is_only_accept_encoding = false;
            }
            continue;
        }
        if (std.ascii.eqlIgnoreCase(h.name, "content-type") and hasEventStreamMediaType(h.value)) return null;
        if (std.ascii.eqlIgnoreCase(h.name, "age")) {
            if (response_age != null) return null;
            response_age = std.fmt.parseInt(u32, std.mem.trim(u8, h.value, " \t"), 10) catch return null;
            continue;
        }
        if (!std.ascii.eqlIgnoreCase(h.name, "cache-control")) continue;
        var it = std.mem.splitScalar(u8, h.value, ',');
        while (it.next()) |raw_tok| {
            const tok = std.mem.trim(u8, raw_tok, " \t");
            const directive_name = std.mem.trim(u8, if (std.mem.indexOfScalar(u8, tok, '=')) |eq| tok[0..eq] else tok, " \t");
            // C1 does not strip named fields or implement field-qualified
            // validation, so every form of these directives is unsafe.
            if (std.ascii.eqlIgnoreCase(directive_name, "no-store") or
                std.ascii.eqlIgnoreCase(directive_name, "private") or
                std.ascii.eqlIgnoreCase(directive_name, "no-cache")) return null;
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
    // by this cache. There is no stale-serving/revalidate-on-fill support
    // here (#902 defers upstream-initiated revalidation of a stale entry).
    if (initial_age_seconds >= ttl_seconds) return null;
    if (saw_vary and !vary_is_only_accept_encoding) return null;
    return .{
        .ttl_seconds = ttl_seconds,
        .initial_age_seconds = initial_age_seconds,
        .vary_on_accept_encoding = saw_vary and vary_is_only_accept_encoding,
    };
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
    try std.testing.expect(isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "POST", &headers, false, false, false));
    // #902: HEAD may be answered from a stored GET entry's metadata.
    try std.testing.expect(isCacheableRequest(&cfg, &block, "HEAD", &headers, false, false, false));

    try headers.append("Authorization", "Bearer x");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    try headers.append("Cookie", "a=b");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    // Session authentication is established before location routing and its
    // asserted identity is origin-facing, so it can never use a shared key.
    try headers.append("X-Session-Token", "opaque-session-token");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    try headers.append("Range", "bytes=0-10");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));

    block.auth = .required;
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &http.Headers.init(std.testing.allocator), false, false, false));
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
    try std.testing.expect(!isCacheableRequest(&cfg, &fa_block, "GET", &empty_headers, false, false, false));

    var cert_block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:1" },
        .client_cert = .{ .required = true },
    };
    try std.testing.expect(!isCacheableRequest(&cfg, &cert_block, "GET", &empty_headers, false, false, false));

    var plain_block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:1" },
    };
    var identified_headers = http.Headers.init(std.testing.allocator);
    defer identified_headers.deinit();
    identified_headers.client_cert = .{ .fingerprint_sha256 = "ab" ** 32, .subject = "CN=alice" };
    try std.testing.expect(!isCacheableRequest(&cfg, &plain_block, "GET", &identified_headers, false, false, false));

    cfg.policy_rules_raw = "GET|^/$|read|false||";
    try std.testing.expect(!isCacheableRequest(&cfg, &plain_block, "GET", &empty_headers, false, false, false));
}

test "isCacheableRequest refuses bodyful, framed, streamed, and gated GETs" {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.policy_rules_raw = "";
    cfg.policy_approval_routes_raw = "";
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:1" },
    };
    var headers = http.Headers.init(std.testing.allocator);
    defer headers.deinit();
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, true, false, false));
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, true, false));
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, true));
    try headers.append("Content-Length", "1");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);
    try headers.append("Accept", "text/event-stream; charset=utf-8, application/json");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);
    try headers.append("Upgrade", "websocket");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
}

test "isCacheableRequest refuses Range/If-Range/If-Match/If-Unmodified-Since but accepts conditional validators (#902)" {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.policy_rules_raw = "";
    cfg.policy_approval_routes_raw = "";
    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:1" },
    };
    var headers = http.Headers.init(std.testing.allocator);
    defer headers.deinit();
    try headers.append("Range", "bytes=0-10");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);
    try headers.append("If-Range", "\"etag\"");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);
    try headers.append("If-Match", "\"etag\"");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);
    try headers.append("If-Unmodified-Since", "Thu, 01 Jan 1970 00:00:00 GMT");
    try std.testing.expect(!isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
    headers.deinit();
    // #902: these are no longer a blanket exclusion -- `decideCacheServe`
    // evaluates them once a hit is found.
    headers = http.Headers.init(std.testing.allocator);
    try headers.append("If-None-Match", "\"etag\"");
    try std.testing.expect(isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);
    try headers.append("If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT");
    try std.testing.expect(isCacheableRequest(&cfg, &block, "GET", &headers, false, false, false));
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
    // #902: `Vary: Accept-Encoding` is the one bounded variant form this
    // cache stores rather than refusing outright.
    try std.testing.expectEqual(Freshness{ .ttl_seconds = 60, .initial_age_seconds = 0, .vary_on_accept_encoding = true }, responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60" },
        .{ .name = "Vary", .value = "Accept-Encoding" },
    }, 300));
    // Case-insensitive and tolerant of surrounding whitespace.
    try std.testing.expectEqual(Freshness{ .ttl_seconds = 60, .initial_age_seconds = 0, .vary_on_accept_encoding = true }, responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60" },
        .{ .name = "Vary", .value = " accept-encoding " },
    }, 300));
    // `Vary: *` and any other field name still bypass entirely.
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60" },
        .{ .name = "Vary", .value = "*" },
    }, 300));
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60" },
        .{ .name = "Vary", .value = "Accept-Language" },
    }, 300));
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60" },
        .{ .name = "Vary", .value = "Accept-Encoding, Accept-Language" },
    }, 300));
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "private, max-age=60" },
    }, 300));
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60, private=\"Authorization\"" },
    }, 300));
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Cache-Control", .value = "max-age=60" },
        .{ .name = "Cache-Control", .value = "no-cache=\"X-Secret\"" },
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
    try std.testing.expectEqual(@as(?Freshness, null), responseFreshness(&[_]TestHeader{
        .{ .name = "Content-Type", .value = "Text/Event-Stream; charset=utf-8" },
        .{ .name = "Cache-Control", .value = "public, max-age=60" },
    }, 300));
}

/// How an already-looked-up, fresh cache hit should answer the request that
/// found it.
pub const ServeDisposition = enum {
    /// Serve the hit's status/headers/body as stored (body omitted by the
    /// caller when the original request method was `HEAD`).
    full,
    /// Serve `304 Not Modified` with only the headers RFC 9110 §15.4.5 says
    /// a `304` may carry, and no body.
    not_modified,
    /// This hit cannot safely answer a conditional request (no stored
    /// validator of the kind the request asked about): treat exactly like a
    /// miss and let the caller proceed to the origin.
    require_origin,
};

fn findStoredHeader(headers: []const CacheHeader, name: []const u8) ?[]const u8 {
    for (headers) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

/// Evaluates `If-None-Match`/`If-Modified-Since` against the validators the
/// hit itself retained (never against a live upstream round-trip -- that is
/// the #902 follow-up's stale-revalidation work, not this). Only one of the
/// two preconditions is evaluated per RFC 9110 §13.1.1 precedence
/// (`If-None-Match` wins when both are present). A request without either
/// header, or a hit this cache cannot validate at all, resolves to `.full`
/// or `.require_origin` respectively -- see each field's doc comment.
pub fn decideCacheServe(hit_headers: []const CacheHeader, request_headers: *const http.Headers) ServeDisposition {
    if (request_headers.get("if-none-match")) |client_validator| {
        const stored_etag = findStoredHeader(hit_headers, "etag") orelse return .require_origin;
        return if (http.etag.matchesIfNoneMatch(stored_etag, client_validator)) .not_modified else .full;
    }
    if (request_headers.get("if-modified-since")) |raw_client_date| {
        const stored_last_modified = findStoredHeader(hit_headers, "last-modified") orelse return .require_origin;
        // An unparsable date on either side makes the precondition
        // indeterminate; RFC 9110 §13.1.3 says to ignore it and process the
        // request normally in that case.
        const client_secs = http.dates.parseHttpDate(raw_client_date) orelse return .full;
        const stored_secs = http.dates.parseHttpDate(stored_last_modified) orelse return .full;
        return if (client_secs >= stored_secs) .not_modified else .full;
    }
    return .full;
}

/// RFC 9110 §15.4.5: a `304` reply may repeat any of these header fields
/// from the `200` it is validating, and must not carry anything that
/// describes a representation body (`Content-Type`/`Content-Length`/content
/// encoding, etc.) since no body is sent.
pub fn isReplayableOn304(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "cache-control") or
        std.ascii.eqlIgnoreCase(name, "content-location") or
        std.ascii.eqlIgnoreCase(name, "date") or
        std.ascii.eqlIgnoreCase(name, "etag") or
        std.ascii.eqlIgnoreCase(name, "expires") or
        std.ascii.eqlIgnoreCase(name, "vary");
}

test "decideCacheServe validates If-None-Match and If-Modified-Since against stored validators only" {
    const stored: []const CacheHeader = &.{
        .{ .name = @constCast("ETag"), .value = @constCast("\"v1\"") },
        .{ .name = @constCast("Last-Modified"), .value = @constCast("Wed, 21 Oct 2015 07:28:00 GMT") },
    };
    var headers = http.Headers.init(std.testing.allocator);
    defer headers.deinit();

    // No conditional headers: full replay.
    try std.testing.expectEqual(ServeDisposition.full, decideCacheServe(stored, &headers));

    try headers.append("If-None-Match", "\"v1\"");
    try std.testing.expectEqual(ServeDisposition.not_modified, decideCacheServe(stored, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    try headers.append("If-None-Match", "\"stale\"");
    try std.testing.expectEqual(ServeDisposition.full, decideCacheServe(stored, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    // No stored ETag at all: this hit cannot validate the condition.
    const no_etag: []const CacheHeader = &.{
        .{ .name = @constCast("Last-Modified"), .value = @constCast("Wed, 21 Oct 2015 07:28:00 GMT") },
    };
    try headers.append("If-None-Match", "\"v1\"");
    try std.testing.expectEqual(ServeDisposition.require_origin, decideCacheServe(no_etag, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    try headers.append("If-Modified-Since", "Thu, 22 Oct 2015 07:28:00 GMT");
    try std.testing.expectEqual(ServeDisposition.not_modified, decideCacheServe(stored, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    try headers.append("If-Modified-Since", "Tue, 20 Oct 2015 07:28:00 GMT");
    try std.testing.expectEqual(ServeDisposition.full, decideCacheServe(stored, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    // If-None-Match takes precedence over If-Modified-Since when both are
    // present (RFC 9110 §13.1.1).
    try headers.append("If-None-Match", "\"v1\"");
    try headers.append("If-Modified-Since", "Tue, 20 Oct 2015 07:28:00 GMT");
    try std.testing.expectEqual(ServeDisposition.not_modified, decideCacheServe(stored, &headers));
}

test "isReplayableOn304 allow-lists only validator/freshness-describing fields" {
    try std.testing.expect(isReplayableOn304("ETag"));
    try std.testing.expect(isReplayableOn304("cache-control"));
    try std.testing.expect(isReplayableOn304("Date"));
    try std.testing.expect(isReplayableOn304("Expires"));
    try std.testing.expect(isReplayableOn304("Vary"));
    try std.testing.expect(isReplayableOn304("Content-Location"));
    try std.testing.expect(!isReplayableOn304("Content-Type"));
    try std.testing.expect(!isReplayableOn304("Content-Length"));
    try std.testing.expect(!isReplayableOn304("Content-Encoding"));
}

test "varyAcceptEncodingDiscriminator normalizes order, case, whitespace and q=0 exclusions" {
    var buf: [max_vary_discriminator_bytes]u8 = undefined;
    try std.testing.expectEqualStrings("br,gzip", varyAcceptEncodingDiscriminator(&buf, "gzip, br").?);
    try std.testing.expectEqualStrings("br,gzip", varyAcceptEncodingDiscriminator(&buf, "BR;q=0.8, GZIP;q=1.0").?);
    try std.testing.expectEqualStrings("br,gzip", varyAcceptEncodingDiscriminator(&buf, "  br ,gzip  ").?);
    // Excluded by q=0.
    try std.testing.expectEqualStrings("gzip", varyAcceptEncodingDiscriminator(&buf, "gzip, br;q=0").?);
    // No header at all: the canonical empty-set discriminator.
    try std.testing.expectEqualStrings("", varyAcceptEncodingDiscriminator(&buf, null).?);
    // Duplicate coding names collapse.
    try std.testing.expectEqualStrings("gzip", varyAcceptEncodingDiscriminator(&buf, "gzip, gzip;q=0.5").?);
    // More codings than the bounded cap: unrepresentable.
    try std.testing.expectEqual(@as(?[]const u8, null), varyAcceptEncodingDiscriminator(&buf, "a,b,c,d,e,f,g,h,i"));
}

test "ProxyResponseCache stores and isolates Vary: Accept-Encoding variants without crossing representations" {
    const allocator = std.testing.allocator;
    var cache = ProxyResponseCache.init(allocator, .{
        .max_object_bytes = 4096,
        .max_entries = 16,
        .max_total_bytes = 16 * 1024,
        .max_vary_variants = 2,
    });
    defer cache.deinit();

    var primary_buf: [64]u8 = undefined;
    const primary = buildCacheKey(&primary_buf, .{
        .scheme = "http",
        .host = "a",
        .method = "GET",
        .location_id = "/",
        .upstream_target = "http://up",
        .path = "/asset",
        .query = "",
    });
    try std.testing.expect(!cache.isVaryTracked(primary));

    // Seed a stale direct (non-Vary) entry at the primary key, as if this
    // resource had been cached before the origin started sending `Vary`.
    try cache.put(0, primary, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{},
        .body = "stale-direct-body",
        .ttl_seconds = 60,
    });

    var gzip_buf: [64]u8 = undefined;
    const gzip_key = buildVaryVariantKey(&gzip_buf, primary, "gzip");
    try cache.putVaryVariant(0, primary, gzip_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "gzip-body",
        .ttl_seconds = 60,
    });
    try std.testing.expect(cache.isVaryTracked(primary));

    var identity_buf: [64]u8 = undefined;
    const identity_key = buildVaryVariantKey(&identity_buf, primary, "");
    try cache.putVaryVariant(0, primary, identity_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "identity-body",
        .ttl_seconds = 60,
    });

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const gzip_hit = (try cache.lookup(arena.allocator(), gzip_key, 1_000)).?;
    try std.testing.expectEqualStrings("gzip-body", gzip_hit.body);
    const identity_hit = (try cache.lookup(arena.allocator(), identity_key, 1_000)).?;
    try std.testing.expectEqualStrings("identity-body", identity_hit.body);

    // A third distinct variant, with `max_vary_variants = 2`, evicts the
    // oldest (gzip) rather than growing without bound.
    var br_buf: [64]u8 = undefined;
    const br_key = buildVaryVariantKey(&br_buf, primary, "br");
    try cache.putVaryVariant(0, primary, br_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "br-body",
        .ttl_seconds = 60,
    });
    try std.testing.expectEqual(@as(?LookupResult, null), try cache.lookup(arena.allocator(), gzip_key, 1_000));
    const br_hit = (try cache.lookup(arena.allocator(), br_key, 1_000)).?;
    try std.testing.expectEqualStrings("br-body", br_hit.body);

    // A stale direct (non-Vary) entry at the primary key is retired once the
    // resource becomes vary-tracked, instead of lingering unreachable.
    try std.testing.expectEqual(@as(?LookupResult, null), try cache.lookup(arena.allocator(), primary, 1_000));
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

test "ProxyResponseCache preserves a live entry when cache-only copies run out of memory" {
    // Cache memory is strictly opportunistic.  A failed lookup copy must not
    // damage the resident entry, and a failed replacement must leave the old
    // representation available to a later request using a healthy allocator.
    const allocator = std.testing.allocator;
    var cache = ProxyResponseCache.init(allocator, .{
        .max_object_bytes = 4096,
        .max_entries = 1,
        .max_total_bytes = 4096,
    });
    defer cache.deinit();
    try cache.put(0, "key", .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
        .body = "live-body",
        .ttl_seconds = 60,
    });

    var lookup_fail = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, cache.lookup(lookup_fail.allocator(), "key", 1));

    // The map has already reserved capacity for this key, so the first cache
    // allocation is one of the replacement's owned copies.  Its failure must
    // happen before `removeLocked` can retire the old entry.
    var put_fail = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    cache.allocator = put_fail.allocator();
    try std.testing.expectError(error.OutOfMemory, cache.put(1, "key", .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{},
        .body = "replacement-body",
        .ttl_seconds = 60,
    }));
    cache.allocator = allocator;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const hit = (try cache.lookup(arena.allocator(), "key", 2)).?;
    try std.testing.expectEqualStrings("live-body", hit.body);
    try std.testing.expectEqual(@as(usize, 1), cache.map.count());
}
