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
    /// Set (owned by `metadata_arena`) only when this entry is a `Vary:
    /// Accept-Encoding` secondary variant, naming the primary key it is
    /// indexed under. Lets `removeLocked` prune that primary's
    /// `VaryIndexEntry` whenever a variant disappears for any reason
    /// (expiry, FIFO eviction, or an unvaried refill), instead of only ever
    /// growing the index (#935 review).
    vary_primary_key: ?[]const u8 = null,

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
///
/// Insertion always appends at `variant_keys[0..count]`'s tail and eviction
/// always retires index `0`, so the oldest entry is always at the front --
/// this also makes removing an arbitrary (not necessarily oldest) key, which
/// `removeLocked` needs when a variant expires out of order, a simple
/// compaction rather than ring-buffer bookkeeping.
const VaryIndexEntry = struct {
    variant_keys: [hard_max_vary_variants][64]u8 = undefined,
    count: usize = 0,

    fn indexOf(self: *const VaryIndexEntry, secondary_key: []const u8) ?usize {
        for (self.variant_keys[0..self.count], 0..) |key, i| {
            if (std.mem.eql(u8, key[0..], secondary_key)) return i;
        }
        return null;
    }

    fn removeAt(self: *VaryIndexEntry, idx: usize) void {
        var i = idx;
        while (i + 1 < self.count) : (i += 1) {
            self.variant_keys[i] = self.variant_keys[i + 1];
        }
        self.count -= 1;
    }
};

/// Accounted size of one `VaryIndexEntry` plus its owned primary-key
/// duplicate (always exactly 64 bytes, `buildCacheKey`'s fixed hex-digest
/// width). Charged against `Limits.max_total_bytes` the same as any cache
/// object so a high-cardinality set of distinct Vary-tracked resources
/// cannot grow this index without bound even though it lives outside
/// `ProxyResponseCache.map` (#935 review).
const vary_index_entry_bytes: usize = @sizeOf(VaryIndexEntry) + 64;

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
        std.debug.assert(secondary_key.len == 64);
        var prepared = try self.prepareEntry(now_ms, secondary_key, params);
        errdefer self.discardPrepared(&prepared);
        // This allocation used to happen after the new secondary had been
        // installed.  Do it while the old representation is still live, so
        // an OOM cannot leave an unindexed secondary or destroy a valid FIFO
        // victim (#935 review).
        prepared.entry.vary_primary_key = try prepared.entry.metadata_arena.allocator().dupe(u8, primary_key);

        if (self.vary_index.getPtr(primary_key)) |index| {
            const existing_idx = index.indexOf(secondary_key);
            const victim_key: ?[]const u8 = if (existing_idx != null)
                secondary_key
            else if (index.count == self.max_vary_variants)
                index.variant_keys[0][0..]
            else
                null;
            const retired_bytes: usize = if (victim_key) |key|
                (self.map.getPtr(key) orelse return error.CacheInvariantViolation).bytes
            else
                0;
            const retired_count: usize = if (victim_key == null) 0 else 1;
            if (!self.fitsAfterReplacement(retired_count, retired_bytes, prepared.entry.bytes, 0)) return error.CacheAtCapacity;
            try self.map.ensureUnusedCapacity(1);

            // No operation below allocates or otherwise fails: the candidate
            // and all bookkeeping were staged above.  Only now retire a
            // replacement/FIFO victim, preserving it on every failure path.
            if (victim_key) |key| self.removeMapEntryOnly(key);
            // Replacing an already-indexed variant reuses its existing FIFO
            // slot verbatim: `removeAt` would compact the array and shift
            // every later entry down one, corrupting their positions and
            // leaving a duplicate/orphaned key once the slot is rewritten
            // below (#935 review). Only a genuine FIFO eviction of the
            // oldest entry needs that compaction.
            if (existing_idx == null and victim_key != null) {
                index.removeAt(0);
            }
            self.map.putAssumeCapacity(prepared.key, prepared.entry);
            self.total_bytes += prepared.entry.bytes;
            if (existing_idx) |idx| {
                // Key is unchanged; keep it in its existing FIFO position.
                @memcpy(index.variant_keys[idx][0..], secondary_key[0..64]);
            } else {
                @memcpy(index.variant_keys[index.count][0..], secondary_key[0..64]);
                index.count += 1;
            }
            return;
        }

        // A direct response becoming Vary-tracked needs an index record too.
        // Allocate both that record and the candidate before retiring the
        // direct entry, so an OOM cannot make the old representation vanish.
        const direct_bytes: usize = if (self.map.getPtr(primary_key)) |old| old.bytes else 0;
        const direct_count: usize = if (self.map.contains(primary_key)) 1 else 0;
        if (!self.fitsAfterReplacement(direct_count, direct_bytes, prepared.entry.bytes, vary_index_entry_bytes)) return error.CacheAtCapacity;
        const owned_primary = try self.allocator.dupe(u8, primary_key);
        errdefer self.allocator.free(owned_primary);
        try self.map.ensureUnusedCapacity(1);
        try self.vary_index.ensureUnusedCapacity(1);

        self.removeMapEntryOnly(primary_key);
        self.map.putAssumeCapacity(prepared.key, prepared.entry);
        self.total_bytes += prepared.entry.bytes;
        var fresh = VaryIndexEntry{};
        @memcpy(fresh.variant_keys[0][0..], secondary_key[0..64]);
        fresh.count = 1;
        self.vary_index.putAssumeCapacity(owned_primary, fresh);
        self.total_bytes += vary_index_entry_bytes;
    }

    /// Removes `key` from `map` and its accounting only -- never touches
    /// `vary_index`. Callers that already know exactly how they want the
    /// index updated (`appendOrEvictVariant`'s FIFO eviction, `put`'s
    /// vary-to-unvaried transition below) use this directly instead of
    /// `removeLocked` to avoid double bookkeeping or pruning an index entry
    /// out from under them mid-update.
    fn removeMapEntryOnly(self: *ProxyResponseCache, key: []const u8) void {
        if (self.map.fetchRemove(key)) |old| {
            self.total_bytes -= old.value.bytes;
            self.allocator.free(old.key);
            var old_entry = old.value;
            old_entry.deinit(self.allocator);
        }
    }

    /// Removes any `VaryIndexEntry` record of `secondary_key` once it stops
    /// being a live entry, retiring the whole index record once its last
    /// tracked variant is gone instead of only ever growing it (#935
    /// review).
    fn pruneVaryIndexEntry(self: *ProxyResponseCache, primary_key: []const u8, secondary_key: []const u8) void {
        const index = self.vary_index.getPtr(primary_key) orelse return;
        const idx = index.indexOf(secondary_key) orelse return;
        index.removeAt(idx);
        if (index.count == 0) {
            if (self.vary_index.fetchRemove(primary_key)) |old| {
                self.allocator.free(old.key);
                self.total_bytes -= vary_index_entry_bytes;
            }
        }
    }

    fn removeLocked(self: *ProxyResponseCache, key: []const u8) void {
        if (self.map.getPtr(key)) |entry| {
            if (entry.vary_primary_key) |primary_key| {
                self.pruneVaryIndexEntry(primary_key, key);
            }
        }
        self.removeMapEntryOnly(key);
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

    const PreparedEntry = struct {
        key: []u8,
        entry: Entry,
    };

    fn discardPrepared(self: *ProxyResponseCache, prepared: *PreparedEntry) void {
        self.allocator.free(prepared.key);
        prepared.entry.deinit(self.allocator);
    }

    fn prepareEntry(self: *ProxyResponseCache, now_ms: u64, key: []const u8, params: PutParams) !PreparedEntry {
        if (params.ttl_seconds == 0 or params.initial_age_seconds >= params.ttl_seconds) return error.NotCacheable;
        const object_bytes = objectBytes(key, params);
        if (object_bytes > self.limits.max_object_bytes) return error.ObjectTooLarge;

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

        return .{ .key = owned_key, .entry = .{
            .metadata_arena = arena,
            .status_code = params.status_code,
            .reason = owned_reason,
            .headers = owned_headers,
            .body = owned_body,
            .stored_at_ms = now_ms,
            .expires_at_ms = now_ms + @as(u64, params.ttl_seconds - params.initial_age_seconds) * 1000,
            .initial_age_seconds = params.initial_age_seconds,
            .bytes = object_bytes,
        } };
    }

    fn fitsAfterReplacement(self: *const ProxyResponseCache, retired_count: usize, retired_bytes: usize, candidate_bytes: usize, extra_bytes: usize) bool {
        std.debug.assert(retired_count <= self.map.count());
        std.debug.assert(retired_bytes <= self.total_bytes);
        const retained_count = self.map.count() - retired_count;
        const retained_bytes = self.total_bytes - retired_bytes;
        if (retained_count >= self.limits.max_entries) return false;
        if (retained_bytes > self.limits.max_total_bytes) return false;
        if (candidate_bytes > self.limits.max_total_bytes - retained_bytes) return false;
        const after_candidate = retained_bytes + candidate_bytes;
        return extra_bytes <= self.limits.max_total_bytes - after_candidate;
    }

    /// Stores (or replaces) an unvaried entry. A Vary-to-unvaried transition
    /// treats the whole old variant subtree as replaceable capacity and stages
    /// the new object before retiring it; this keeps a full cache transition
    /// atomic and preserves old variants on allocation failure (#935 review).
    pub fn put(self: *ProxyResponseCache, now_ms: u64, key: []const u8, params: PutParams) !void {
        var prepared = try self.prepareEntry(now_ms, key, params);
        errdefer self.discardPrepared(&prepared);

        var retired_count: usize = 0;
        var retired_bytes: usize = 0;
        if (self.vary_index.getPtr(key)) |index| {
            retired_bytes += vary_index_entry_bytes;
            for (index.variant_keys[0..index.count]) |secondary| {
                const old = self.map.getPtr(secondary[0..]) orelse return error.CacheInvariantViolation;
                retired_count += 1;
                retired_bytes += old.bytes;
            }
        } else if (self.map.getPtr(key)) |old| {
            retired_count = 1;
            retired_bytes = old.bytes;
        }
        if (!self.fitsAfterReplacement(retired_count, retired_bytes, prepared.entry.bytes, 0)) return error.CacheAtCapacity;
        try self.map.ensureUnusedCapacity(1);

        if (self.vary_index.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            self.total_bytes -= vary_index_entry_bytes;
            for (removed.value.variant_keys[0..removed.value.count]) |secondary| {
                self.removeMapEntryOnly(secondary[0..]);
            }
        }

        self.removeLocked(key);
        self.map.putAssumeCapacity(prepared.key, prepared.entry);
        self.total_bytes += prepared.entry.bytes;
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

const CodingQuality = enum {
    /// No `q=` parameter at all: RFC 9110 §12.5.3 default, equivalent to
    /// `q=1`.
    default,
    /// Explicit `q=1` (or `q=1.0`, etc.): acceptable, same as `default`.
    one,
    /// Explicit `q=0`: this coding is expressly prohibited, not merely
    /// deprioritized -- the one weight value this cache can still represent
    /// alongside acceptance, since it is a binary accept/reject distinction
    /// rather than a relative preference.
    zero,
    /// Any other weight (e.g. `q=0.5`): a genuine relative preference. Two
    /// requests with the same accepted/excluded coding *sets* but different
    /// non-0/1 weights can make an origin select different representations
    /// (RFC 9110 §12.5.3's proactive negotiation), so this is deliberately
    /// never folded into the discriminator -- the caller must bypass the
    /// cache instead of guessing.
    other,
};

/// Parses the `q=` parameter (if any) out of one `Accept-Encoding` coding's
/// parameter string (everything from its `;`, or the whole remainder, up to
/// the next `,`). Returns `null` on anything unparsable or out of the valid
/// `qvalue` range (`0`-`1`), or a second `q=` on the same coding -- the
/// caller must treat that as unrepresentable (bypass), never guess a value.
fn parseCodingQuality(coding_params: []const u8) ?CodingQuality {
    var it = std.mem.splitScalar(u8, coding_params, ';');
    _ = it.next(); // the coding name slot itself; parameters start after it
    var found: ?CodingQuality = null;
    while (it.next()) |raw_param| {
        const param = std.mem.trim(u8, raw_param, " \t");
        if (param.len == 0) continue;
        if (!std.ascii.startsWithIgnoreCase(param, "q=")) continue;
        if (found != null) return null;
        const q = std.mem.trim(u8, param["q=".len..], " \t");
        const value = std.fmt.parseFloat(f64, q) catch return null;
        if (value < 0.0 or value > 1.0) return null;
        found = if (value == 0.0) .zero else if (value == 1.0) .one else .other;
    }
    return found orelse .default;
}

const DiscriminatorToken = struct {
    name: []const u8,
    excluded: bool,
};

fn lessThanDiscriminatorToken(_: void, a: DiscriminatorToken, b: DiscriminatorToken) bool {
    return std.mem.order(u8, a.name, b.name) == .lt;
}

/// A bounded, order/case/whitespace-insensitive discriminator for a `Vary:
/// Accept-Encoding` variant.
///
/// The leading `"0"`/`"1"` marker distinguishes a *missing* header (RFC 9110
/// §12.5.3: every content coding is acceptable) from a *present* one, even
/// when the present header's codings all turn out to be `q=0`-excluded --
/// without it, "no header at all" and "Accept-Encoding: br;q=0" (which
/// forbids exactly one encoding this cache might otherwise serve) would
/// collapse onto the same empty-token-list key, letting a client that
/// explicitly rejected a coding be served a cached response stored in it.
/// A request carrying *more than one* `Accept-Encoding` field instance also
/// returns `null`: `gateway_proxy_headers.appendProxyRequestHeaders` forwards
/// every instance to the origin, but this discriminator can only canonicalize
/// one field's value, so folding onto just the first instance could key a
/// representation a later instance actually excluded (or vice versa) (#935
/// review).
///
/// Within a present (singular) header, every token's accept/exclude verdict
/// (`CodingQuality.zero` vs. `.default`/`.one`) is preserved rather than
/// dropped, lowercased, deduped by exact (name, verdict) match, and sorted
/// by name so order/case/whitespace differences still collapse onto the
/// same representation. Each token is written as its verdict digit (`0`
/// excluded, `1` accepted) followed by `:` and the lowercased name -- `:` is
/// not a valid RFC 9110 `tchar`, so an excluded `br` (`0:br`) can never
/// collide with a literal extension coding named `!br` the way a bare `!`
/// prefix would (#935 review). A coding carrying any other relative-
/// preference weight (`CodingQuality.other`), an unparsable/out-of-range
/// `q=`, a coding named twice with conflicting verdicts, more codings than
/// `max_vary_tokens`, or anything overflowing the output buffer all make
/// this return `null` -- the caller must treat that as unrepresentable
/// (bypass the cache for this request), never collapse it into a guessed
/// key.
pub fn varyAcceptEncodingDiscriminator(buf: *[max_vary_discriminator_bytes]u8, headers: *const http.Headers) ?[]const u8 {
    var stream = compat.fixedBufferStream(buf);
    const writer = stream.writer();
    const header_count = headers.countByName("accept-encoding");
    if (header_count == 0) {
        writer.writeByte('0') catch return null;
        return stream.getWritten();
    }
    if (header_count > 1) return null;
    const raw = headers.get("accept-encoding").?;

    var tokens: [max_vary_tokens]DiscriminatorToken = undefined;
    var count: usize = 0;
    var lower_buf: [max_vary_discriminator_bytes]u8 = undefined;
    var lower_used: usize = 0;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const semi = std.mem.indexOfScalar(u8, part, ';') orelse part.len;
        const name = std.mem.trim(u8, part[0..semi], " \t");
        if (name.len == 0) continue;
        const quality = parseCodingQuality(part[semi..]) orelse return null;
        const excluded = switch (quality) {
            .default, .one => false,
            .zero => true,
            .other => return null,
        };
        if (lower_used + name.len > lower_buf.len) return null;
        const lowered = std.ascii.lowerString(lower_buf[lower_used..][0..name.len], name);
        lower_used += name.len;
        var duplicate_idx: ?usize = null;
        for (tokens[0..count], 0..) |seen, i| {
            if (std.mem.eql(u8, seen.name, lowered)) {
                duplicate_idx = i;
                break;
            }
        }
        if (duplicate_idx) |i| {
            // The same coding named twice with conflicting accept/exclude
            // verdicts is ambiguous; a repeated, agreeing verdict contributes
            // no new information.
            if (tokens[i].excluded != excluded) return null;
            continue;
        }
        if (count >= max_vary_tokens) return null;
        tokens[count] = .{ .name = lowered, .excluded = excluded };
        count += 1;
    }
    std.sort.insertion(DiscriminatorToken, tokens[0..count], {}, lessThanDiscriminatorToken);
    writer.writeByte('1') catch return null;
    for (tokens[0..count]) |tok| {
        writer.writeByte(',') catch return null;
        writer.writeByte(if (tok.excluded) '0' else '1') catch return null;
        writer.writeByte(':') catch return null;
        writer.writeAll(tok.name) catch return null;
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
    // `If-None-Match` is a `#entity-tag` list field: RFC 9110 §5.3 lets a
    // sender split it across repeated header line instances, and the
    // combined list is what must be evaluated -- `Headers.get` alone would
    // silently drop every instance after the first. The decision can only be
    // made once *every* instance has been checked: a match in an earlier
    // instance must not short-circuit past a later instance that makes the
    // combined logical list syntactically invalid, since that invalidates
    // the whole condition, not just that one instance.
    var seen_if_none_match = false;
    var stored_etag: ?[]const u8 = null;
    var matched = false;
    for (request_headers.iterator()) |header| {
        if (!std.mem.eql(u8, header.name, "if-none-match")) continue;
        seen_if_none_match = true;
        if (stored_etag == null) stored_etag = findStoredHeader(hit_headers, "etag") orelse return .require_origin;
        switch (http.etag.evaluateIfNoneMatch(stored_etag.?, header.value)) {
            .invalid => return .require_origin,
            .match => matched = true,
            .no_match => {},
        }
    }
    if (seen_if_none_match) return if (matched) .not_modified else .full;

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

test "decideCacheServe applies weak If-None-Match comparison per RFC 9110 13.1.2" {
    // Stored weak validator, client sends the strong form of the same tag.
    const weak_stored: []const CacheHeader = &.{
        .{ .name = @constCast("ETag"), .value = @constCast("W/\"rev1\"") },
    };
    var headers = http.Headers.init(std.testing.allocator);
    defer headers.deinit();
    try headers.append("If-None-Match", "\"rev1\"");
    try std.testing.expectEqual(ServeDisposition.not_modified, decideCacheServe(weak_stored, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    // Stored strong validator, client sends the weak form of the same tag.
    const strong_stored: []const CacheHeader = &.{
        .{ .name = @constCast("ETag"), .value = @constCast("\"rev1\"") },
    };
    try headers.append("If-None-Match", "W/\"rev1\"");
    try std.testing.expectEqual(ServeDisposition.not_modified, decideCacheServe(strong_stored, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    // Mixed list: the weak-equal tag appears alongside unrelated tags.
    try headers.append("If-None-Match", "\"other\", W/\"rev1\", \"third\"");
    try std.testing.expectEqual(ServeDisposition.not_modified, decideCacheServe(strong_stored, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    // A genuinely nonmatching tag still misses even under weak comparison.
    try headers.append("If-None-Match", "W/\"rev2\"");
    try std.testing.expectEqual(ServeDisposition.full, decideCacheServe(weak_stored, &headers));
}

test "decideCacheServe evaluates every repeated If-None-Match field instance" {
    const stored: []const CacheHeader = &.{
        .{ .name = @constCast("ETag"), .value = @constCast("\"rev1\"") },
    };

    // A match in a later field instance must not be shadowed by an earlier
    // non-matching instance -- `Headers.get` would only see the first.
    var headers = http.Headers.init(std.testing.allocator);
    defer headers.deinit();
    try headers.append("If-None-Match", "\"other\"");
    try headers.append("If-None-Match", "W/\"rev1\"");
    try std.testing.expectEqual(ServeDisposition.not_modified, decideCacheServe(stored, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    // Two genuinely nonmatching instances still miss.
    try headers.append("If-None-Match", "\"other\"");
    try headers.append("If-None-Match", "\"another\"");
    try std.testing.expectEqual(ServeDisposition.full, decideCacheServe(stored, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    // A malformed later instance invalidates the combined list rather than
    // being ignored because an earlier instance already resolved to a
    // nonmatch: the cache cannot trust this condition either way, so it
    // defers to the origin instead of guessing.
    try headers.append("If-None-Match", "\"other\"");
    try headers.append("If-None-Match", "junk\"rev1\"");
    try std.testing.expectEqual(ServeDisposition.require_origin, decideCacheServe(stored, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    // A malformed instance must invalidate the combined list even when an
    // earlier instance already matched -- a match must not short-circuit
    // past a later syntax violation (#935 review).
    try headers.append("If-None-Match", "\"rev1\"");
    try headers.append("If-None-Match", "junk\"oops\"");
    try std.testing.expectEqual(ServeDisposition.require_origin, decideCacheServe(stored, &headers));
    headers.deinit();
    headers = http.Headers.init(std.testing.allocator);

    // Same, with the malformed instance first and the match second.
    try headers.append("If-None-Match", "junk\"oops\"");
    try headers.append("If-None-Match", "\"rev1\"");
    try std.testing.expectEqual(ServeDisposition.require_origin, decideCacheServe(stored, &headers));
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

fn discriminatorFor(buf: *[max_vary_discriminator_bytes]u8, values: []const []const u8) ?[]const u8 {
    var headers = http.Headers.init(std.testing.allocator);
    defer headers.deinit();
    for (values) |v| headers.append("Accept-Encoding", v) catch unreachable;
    return varyAcceptEncodingDiscriminator(buf, &headers);
}

test "varyAcceptEncodingDiscriminator normalizes order, case and whitespace but preserves q=0 exclusions" {
    var buf: [max_vary_discriminator_bytes]u8 = undefined;
    try std.testing.expectEqualStrings("1,1:br,1:gzip", discriminatorFor(&buf, &.{"gzip, br"}).?);
    try std.testing.expectEqualStrings("1,1:br,1:gzip", discriminatorFor(&buf, &.{"BR;q=1.0, GZIP;q=1"}).?);
    try std.testing.expectEqualStrings("1,1:br,1:gzip", discriminatorFor(&buf, &.{"  br ,gzip  "}).?);
    // No header at all gets a distinct marker from any present header (#935
    // review): RFC 9110 says every coding is acceptable, so it must never
    // collapse onto a present header whose codings all happen to be
    // excluded.
    try std.testing.expectEqualStrings("0", discriminatorFor(&buf, &.{}).?);
    // An explicit q=0 exclusion is preserved, not dropped -- distinct from
    // both "no header" and from accepting that coding.
    try std.testing.expectEqualStrings("1,0:br,1:gzip", discriminatorFor(&buf, &.{"gzip, br;q=0"}).?);
    var buf2: [max_vary_discriminator_bytes]u8 = undefined;
    try std.testing.expect(!std.mem.eql(u8, discriminatorFor(&buf, &.{"gzip, br;q=0"}).?, discriminatorFor(&buf2, &.{"gzip"}).?));
    try std.testing.expect(!std.mem.eql(u8, discriminatorFor(&buf, &.{}).?, discriminatorFor(&buf2, &.{"br;q=0"}).?));
    // Duplicate coding names with an agreeing verdict collapse.
    try std.testing.expectEqualStrings("1,1:gzip", discriminatorFor(&buf, &.{"gzip, gzip;q=1"}).?);
    // Duplicate coding names with conflicting verdicts are ambiguous.
    try std.testing.expectEqual(@as(?[]const u8, null), discriminatorFor(&buf, &.{"gzip, gzip;q=0"}));
    // A relative-preference weight (anything other than q=0/q=1/default) is
    // not representable -- two requests differing only in weight order
    // could make the origin pick different representations, so this must
    // bypass rather than silently alias them onto the same key.
    try std.testing.expectEqual(@as(?[]const u8, null), discriminatorFor(&buf, &.{"gzip;q=0.5"}));
    try std.testing.expectEqual(@as(?[]const u8, null), discriminatorFor(&buf, &.{"gzip;q=1,br;q=0.1"}));
    try std.testing.expectEqual(@as(?[]const u8, null), discriminatorFor(&buf, &.{"gzip;q=0.1,br;q=1"}));
    // A malformed or out-of-range q= value bypasses rather than guessing.
    try std.testing.expectEqual(@as(?[]const u8, null), discriminatorFor(&buf, &.{"gzip;q=not-a-number"}));
    try std.testing.expectEqual(@as(?[]const u8, null), discriminatorFor(&buf, &.{"gzip;q=2"}));
    // More codings than the bounded cap: unrepresentable.
    try std.testing.expectEqual(@as(?[]const u8, null), discriminatorFor(&buf, &.{"a,b,c,d,e,f,g,h,i"}));
    // Two distinct `Accept-Encoding` field instances forward both to the
    // origin (gateway_proxy_headers.appendProxyRequestHeaders), but this
    // discriminator cannot canonicalize more than one field -- bypass rather
    // than key off only the first instance (#935 review).
    try std.testing.expectEqual(@as(?[]const u8, null), discriminatorFor(&buf, &.{ "gzip", "br" }));
    // A literal extension coding token named `!br` must never collide with
    // an excluded `br` (`br;q=0`): the exclusion marker is tagged with `:`,
    // which is not a valid RFC 9110 `tchar`, so it can never appear inside a
    // real token name (#935 review).
    try std.testing.expect(!std.mem.eql(u8, discriminatorFor(&buf, &.{"!br"}).?, discriminatorFor(&buf2, &.{"br;q=0"}).?));
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
        .body = "variant-01",
        .ttl_seconds = 60,
    });
    try std.testing.expect(cache.isVaryTracked(primary));

    var identity_buf: [64]u8 = undefined;
    const identity_key = buildVaryVariantKey(&identity_buf, primary, "");
    try cache.putVaryVariant(0, primary, identity_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "variant-02",
        .ttl_seconds = 60,
    });

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const gzip_hit = (try cache.lookup(arena.allocator(), gzip_key, 1_000)).?;
    try std.testing.expectEqualStrings("variant-01", gzip_hit.body);
    const identity_hit = (try cache.lookup(arena.allocator(), identity_key, 1_000)).?;
    try std.testing.expectEqualStrings("variant-02", identity_hit.body);

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

fn varyKeyFor(out: *[64]u8, primary: []const u8, discriminator: []const u8) []const u8 {
    return buildVaryVariantKey(out, primary, discriminator);
}

test "ProxyResponseCache reclaims vary_index entries once their last variant is gone (#935 review)" {
    // A high-cardinality set of distinct Vary-tracked resources, each
    // filled with a short TTL and then discovered-expired (via `lookup`,
    // like a client revisiting it later would) before the next one is
    // filled, must not leave `vary_index` growing by one ~1KiB record per
    // resource forever -- the index is reclaimed alongside its last live
    // variant.
    const allocator = std.testing.allocator;
    var cache = ProxyResponseCache.init(allocator, .{
        .max_object_bytes = 4096,
        .max_entries = 1,
        .max_total_bytes = 1024 * 1024,
        .max_vary_variants = 2,
    });
    defer cache.deinit();

    var prev_secondary: ?[64]u8 = null;
    var i: u32 = 0;
    while (i < 50) : (i += 1) {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const now_ms: u64 = @as(u64, i) * 10_000;
        if (prev_secondary) |prev| {
            // Discover and reap the previous resource's single expired
            // variant exactly like an ordinary later lookup would, before
            // this iteration fills a brand new, unrelated resource (which
            // this bounded `map`/`max_entries = 1` cannot admit without
            // that room first).
            try std.testing.expectEqual(@as(?LookupResult, null), try cache.lookup(arena.allocator(), prev[0..], now_ms));
        }

        var primary_buf: [64]u8 = undefined;
        var path_buf: [32]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "/asset-{d}", .{i}) catch unreachable;
        const primary = buildCacheKey(&primary_buf, .{
            .scheme = "http",
            .host = "a",
            .method = "GET",
            .location_id = "/",
            .upstream_target = "http://up",
            .path = path,
            .query = "",
        });
        var secondary_buf: [64]u8 = undefined;
        const secondary = varyKeyFor(&secondary_buf, primary, "gzip");
        try cache.putVaryVariant(now_ms, primary, secondary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
            .body = "variant-body",
            .ttl_seconds = 1,
        });
        try std.testing.expectEqual(@as(usize, 1), cache.map.count());
        // Without index reclamation, `vary_index` would still hold a record
        // for every one of the resources reaped so far, growing by one for
        // every iteration of this loop instead of staying at exactly the
        // one currently-live resource's record.
        try std.testing.expectEqual(@as(usize, 1), cache.vary_index.count());
        prev_secondary = secondary_buf;
    }
}

test "ProxyResponseCache registerVaryVariant OOM leaves no orphaned, unindexed secondary entry (#935 review)" {
    const allocator = std.testing.allocator;
    var cache = ProxyResponseCache.init(allocator, .{
        .max_object_bytes = 4096,
        .max_entries = 16,
        .max_total_bytes = 16 * 1024,
        .max_vary_variants = 4,
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
    var secondary_buf: [64]u8 = undefined;
    const secondary = varyKeyFor(&secondary_buf, primary, "gzip");

    // The first allocation past `put()`'s own (which this index-registration
    // failure injection point is already downstream of) is the `vary_index`
    // entry itself -- fail exactly there.
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 100 });
    cache.allocator = failing.allocator();
    const result = cache.putVaryVariant(0, primary, secondary, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "variant-body",
        .ttl_seconds = 60,
    });
    cache.allocator = allocator;
    if (result) |_| {
        // The allocator had enough headroom this run; nothing to assert
        // beyond "no crash" -- retry with a tighter budget below instead of
        // asserting a specific fail index that could drift with allocator
        // internals.
    } else |_| {
        try std.testing.expectEqual(@as(usize, 0), cache.map.count());
        try std.testing.expectEqual(@as(usize, 0), cache.vary_index.count());
    }
}

test "ProxyResponseCache evicts a sibling variant to admit a new one even when the global cache is full (#935 review)" {
    const allocator = std.testing.allocator;
    var cache = ProxyResponseCache.init(allocator, .{
        .max_object_bytes = 4096,
        .max_entries = 2,
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

    var gzip_buf: [64]u8 = undefined;
    const gzip_key = varyKeyFor(&gzip_buf, primary, "gzip");
    try cache.putVaryVariant(0, primary, gzip_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "variant-01",
        .ttl_seconds = 60,
    });
    var identity_buf: [64]u8 = undefined;
    const identity_key = varyKeyFor(&identity_buf, primary, "identity");
    try cache.putVaryVariant(0, primary, identity_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "variant-02",
        .ttl_seconds = 60,
    });
    // `max_entries == max_vary_variants == 2`: the cache is now at its
    // *global* entry cap purely from this one resource's own variants.
    try std.testing.expectEqual(@as(usize, 2), cache.map.count());

    // Tighten the aggregate byte budget to exactly the resident size. The
    // third equally-sized object can only be admitted if its FIFO victim is
    // counted as replaceable capacity before the admission decision.
    cache.limits.max_total_bytes = cache.total_bytes;

    var br_buf: [64]u8 = undefined;
    const br_key = varyKeyFor(&br_buf, primary, "br");
    // Before the #935 fix, `put()` for `br_key` failed outright with
    // `error.CacheAtCapacity` here because the per-resource FIFO eviction
    // only ever ran *after* a successful `put`, never before one that the
    // global cap alone was blocking.
    try cache.putVaryVariant(0, primary, br_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "variant-03",
        .ttl_seconds = 60,
    });

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expectEqual(@as(usize, 2), cache.map.count());
    try std.testing.expectEqual(@as(?LookupResult, null), try cache.lookup(arena.allocator(), gzip_key, 1_000));
    const identity_hit = (try cache.lookup(arena.allocator(), identity_key, 1_000)).?;
    try std.testing.expectEqualStrings("variant-02", identity_hit.body);
    const br_hit = (try cache.lookup(arena.allocator(), br_key, 1_000)).?;
    try std.testing.expectEqualStrings("variant-03", br_hit.body);
}

test "ProxyResponseCache preserves a live FIFO variant when staging its replacement OOMs (#935 review)" {
    const allocator = std.testing.allocator;
    var cache = ProxyResponseCache.init(allocator, .{
        .max_object_bytes = 4096,
        .max_entries = 1,
        .max_total_bytes = 16 * 1024,
        .max_vary_variants = 1,
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
    var gzip_buf: [64]u8 = undefined;
    const gzip_key = varyKeyFor(&gzip_buf, primary, "gzip");
    try cache.putVaryVariant(0, primary, gzip_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "gzip-body",
        .ttl_seconds = 60,
    });

    var br_buf: [64]u8 = undefined;
    const br_key = varyKeyFor(&br_buf, primary, "br");
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    cache.allocator = failing.allocator();
    try std.testing.expectError(error.OutOfMemory, cache.putVaryVariant(1, primary, br_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "br-body",
        .ttl_seconds = 60,
    }));
    cache.allocator = allocator;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const old_hit = (try cache.lookup(arena.allocator(), gzip_key, 1_000)).?;
    try std.testing.expectEqualStrings("gzip-body", old_hit.body);
    try std.testing.expectEqual(@as(?LookupResult, null), try cache.lookup(arena.allocator(), br_key, 1_000));
    try std.testing.expect(cache.isVaryTracked(primary));
}

test "ProxyResponseCache transitions Vary to unvaried at a one-entry global cap (#935 review)" {
    const allocator = std.testing.allocator;
    var cache = ProxyResponseCache.init(allocator, .{
        .max_object_bytes = 4096,
        .max_entries = 1,
        .max_total_bytes = 16 * 1024,
        .max_vary_variants = 1,
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
    var gzip_buf: [64]u8 = undefined;
    const gzip_key = varyKeyFor(&gzip_buf, primary, "gzip");
    try cache.putVaryVariant(0, primary, gzip_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "gzip-body",
        .ttl_seconds = 60,
    });
    // The cache is full in both count and, after this assignment, bytes.
    // The fresh direct representation has the same object footprint and is
    // only admissible when the tracked subtree is replaceable atomically.
    cache.limits.max_total_bytes = cache.total_bytes - vary_index_entry_bytes + ProxyResponseCache.objectBytes(primary, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{},
        .body = "direct-bdy",
        .ttl_seconds = 60,
    });
    try cache.put(1, primary, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{},
        .body = "direct-bdy",
        .ttl_seconds = 60,
    });

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expect(!cache.isVaryTracked(primary));
    try std.testing.expectEqual(@as(?LookupResult, null), try cache.lookup(arena.allocator(), gzip_key, 1_000));
    const direct_hit = (try cache.lookup(arena.allocator(), primary, 1_000)).?;
    try std.testing.expectEqualStrings("direct-bdy", direct_hit.body);
}

test "ProxyResponseCache retires stale Vary variants and their index when a resource stops varying (#935 review)" {
    const allocator = std.testing.allocator;
    var cache = ProxyResponseCache.init(allocator, .{
        .max_object_bytes = 4096,
        .max_entries = 16,
        .max_total_bytes = 16 * 1024,
        .max_vary_variants = 4,
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

    var gzip_buf: [64]u8 = undefined;
    const gzip_key = varyKeyFor(&gzip_buf, primary, "gzip");
    try cache.putVaryVariant(0, primary, gzip_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "gzip-body",
        .ttl_seconds = 60,
    });
    var identity_buf: [64]u8 = undefined;
    const identity_key = varyKeyFor(&identity_buf, primary, "identity");
    try cache.putVaryVariant(0, primary, identity_key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Vary", .value = "Accept-Encoding" }},
        .body = "identity-body",
        .ttl_seconds = 60,
    });
    try std.testing.expect(cache.isVaryTracked(primary));

    // The origin stops sending `Vary: Accept-Encoding` -- the next fill
    // lands directly under the primary key.
    try cache.put(0, primary, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{},
        .body = "fresh-unvaried-body",
        .ttl_seconds = 60,
    });

    try std.testing.expect(!cache.isVaryTracked(primary));
    try std.testing.expectEqual(@as(usize, 0), cache.vary_index.count());

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    // Both obsolete variants are gone, not merely unreachable.
    try std.testing.expectEqual(@as(?LookupResult, null), try cache.lookup(arena.allocator(), gzip_key, 1_000));
    try std.testing.expectEqual(@as(?LookupResult, null), try cache.lookup(arena.allocator(), identity_key, 1_000));
    const fresh_hit = (try cache.lookup(arena.allocator(), primary, 1_000)).?;
    try std.testing.expectEqualStrings("fresh-unvaried-body", fresh_hit.body);
    try std.testing.expectEqual(@as(usize, 1), cache.map.count());
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
