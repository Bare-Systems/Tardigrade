//! Bounded, transport-neutral client and stateful-server session-resumption
//! storage (#364).
//!
//! This module owns everything #360's `session.zig` and #362's
//! `pre_shared_key.zig` deliberately do not: capacity/lifetime/LRU/eviction
//! policy, canonical origin indexing, deep-clone ownership, stateful opaque
//! handles, internal lease/pinning for single-use consumption, thread
//! safety, and secure cleanup. It does not parse PSK wire extensions,
//! generate or verify binders, or perform key-schedule derivation, and it
//! does not evaluate `session.CandidateContext` compatibility itself: the
//! shared #362 path (`session.evaluateCompatibility`, driven from
//! `tls13_backend.zig`) owns that decision for both stateless and stateful
//! identities, so this module only resolves storage and leaves protocol
//! selection to the caller.
//!
//! Two independent bounded stores are defined here:
//!
//!   - `ClientSessionCache` — keyed by a canonical origin/compatibility
//!     digest, retains deep-cloned `session.ClientTicketState`, and returns
//!     an owned `pre_shared_key.ClientPskOfferSet` in deterministic order.
//!   - `StatefulServerCache` — keyed by a fixed-size unpredictable opaque
//!     handle ("TDSH" v1), owns `session.ServerRecoverableState`, and exposes
//!     an internal lease/commit/release model for single-use consumption.
//!
//! Per issue #364's canonical plan, this module intentionally does not yet
//! adapt `StatefulServerCache` to the public `pre_shared_key.ServerPskResolver`
//! contract, does not add the `TDSH`/`TDTK` composite adapter, and does not
//! touch `root.zig` — those land once the two-phase issuance / resolver-lease
//! predecessor amendments described in issue #364 are made. The
//! lease/commit/release shape defined here already matches what that future
//! resolver adapter will need, so wiring it up should not require reshaping
//! this module.
//!
//! Sequence counters (`insertion_sequence`, `lru_sequence`, `entry_id`,
//! `lease_epoch`) are plain wrapping `u64` counters, never renumbered:
//! renumbering would require physically reordering backing storage while
//! other code may be holding array indices/pointers into it, which is a
//! correctness hazard for a marginal (and, at `u64` widths, practically
//! unreachable) benefit. Wrapping after `2^64` assignments is accepted as
//! out of scope, matching the existing `entry_id`-style counters elsewhere
//! in this codebase.

const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("crypto");
const session = @import("session.zig");
const pre_shared_key = @import("pre_shared_key.zig");
const zig_compat = @import("zig_compat");

const secrets = crypto.secrets;

// -----------------------------------------------------------------------
// Limits
// -----------------------------------------------------------------------

pub const hard_max_entries: usize = 65_536;
pub const hard_max_origins: usize = 65_536;
pub const hard_max_entries_per_origin: usize = 256;
pub const hard_max_entry_bytes: usize = 64 * 1024;
pub const hard_max_total_bytes: usize = 256 * 1024 * 1024;

/// Fixed logical per-entry bookkeeping overhead added to the encoded-state
/// length for byte accounting. This is a sensitive-state *budget*, not exact
/// allocator/data-structure overhead.
const entry_overhead_bytes: usize = 64;

/// Caller-tightenable capacity/lifetime bounds for a cache instance. Both
/// `ClientSessionCache` and `StatefulServerCache` use this same shape;
/// `client_default` / `stateful_server_default` are the issue's recommended
/// first defaults.
pub const Limits = struct {
    max_entries: usize,
    max_origins: usize,
    max_entries_per_origin: usize,
    max_entry_bytes: usize,
    max_total_bytes: usize,

    pub const client_default: Limits = .{
        .max_entries = 256,
        .max_origins = 64,
        .max_entries_per_origin = 8,
        .max_entry_bytes = 8 * 1024,
        .max_total_bytes = 2 * 1024 * 1024,
    };

    pub const stateful_server_default: Limits = .{
        .max_entries = 4096,
        .max_origins = 1024,
        .max_entries_per_origin = 8,
        .max_entry_bytes = 8 * 1024,
        .max_total_bytes = 32 * 1024 * 1024,
    };

    pub fn validate(self: Limits) error{InvalidLimits}!void {
        if (self.max_entries == 0 or self.max_entries > hard_max_entries) return error.InvalidLimits;
        if (self.max_origins == 0 or self.max_origins > hard_max_origins) return error.InvalidLimits;
        if (self.max_entries_per_origin == 0 or self.max_entries_per_origin > hard_max_entries_per_origin)
            return error.InvalidLimits;
        if (self.max_entry_bytes == 0 or self.max_entry_bytes > hard_max_entry_bytes) return error.InvalidLimits;
        if (self.max_total_bytes == 0 or self.max_total_bytes > hard_max_total_bytes) return error.InvalidLimits;
        if (self.max_entry_bytes > self.max_total_bytes) return error.InvalidLimits;
    }
};

/// Single-use versus reusable ticket/session semantics. Single-use consuming
/// commit wiring for the client side is deferred to #365 (see
/// `ClientSessionCache.consumeSingleUse`); the stateful server cache's
/// lease/commit/release model is fully implemented here.
pub const UsagePolicy = enum { reusable, single_use };

/// Store/insert outcomes. Never an error union: a cache refusal or storage
/// failure is a normal, typed result the caller folds into "did not offer
/// resumption this time" — it must never fail the TLS connection that
/// delivered the ticket (#364 acceptance criteria).
pub const StoreResult = enum {
    stored,
    replaced,
    rejected_capacity,
    /// Stateful-server-only: bounded CSPRNG handle-collision retries were
    /// exhausted.
    rejected_handle_generation_failed,
    /// Allocation failure. Distinguished from `rejected_capacity` (an
    /// ordinary policy decision) per the "typed results distinguish ...
    /// capacity rejection[] and storage failure" requirement.
    storage_failed,
};

// -----------------------------------------------------------------------
// Metrics / observer seam
// -----------------------------------------------------------------------

pub const CacheEvent = enum {
    stored,
    replaced,
    evicted,
    rejected_capacity,
    rejected_handle_generation_failed,
    storage_failed,
    lookup_hit,
    lookup_miss,
    lookup_expired,
    lookup_incompatible,
    /// A single-use resolution was refused because a persistence snapshot
    /// is currently in progress (see `StatefulServerCache.resolveLease`).
    lookup_busy,
};

/// Non-secret observer seam. Implementations must not log or format cache
/// keys/tickets/handles; only `CacheEvent` is ever passed. Callers must
/// never be invoked while a cache mutex is held (see module doc) — every
/// call site below computes its result/event inside a locked block and
/// notifies only after that block (and therefore the lock) has exited, so a
/// re-entrant observer that calls back into the same cache cannot deadlock.
pub const Observer = struct {
    ctx: *anyopaque = @ptrCast(@constCast(&empty_observer_dummy)),
    onEventFn: ?*const fn (ctx: *anyopaque, event: CacheEvent) void = null,

    pub fn notify(self: Observer, event: CacheEvent) void {
        if (self.onEventFn) |f| f(self.ctx, event);
    }
};

var empty_observer_dummy: u8 = 0;

// -----------------------------------------------------------------------
// Canonical origin digest
// -----------------------------------------------------------------------

pub const origin_digest_len = 32;
pub const OriginDigest = [origin_digest_len]u8;

const origin_digest_domain = "TARDIGRADE-TLS-SESSION-CACHE-ORIGIN-V1";

fn hashPresenceLenBytes(hasher: *std.crypto.hash.sha2.Sha256, present: bool, bytes: []const u8) void {
    hasher.update(&[_]u8{if (present) 1 else 0});
    var len_be: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_be, @intCast(bytes.len), .big);
    hasher.update(&len_be);
    hasher.update(bytes);
}

fn hashCompat(hasher: *std.crypto.hash.sha2.Sha256, present: bool, format_id: u16, format_version: u16, bytes: []const u8) void {
    hasher.update(&[_]u8{if (present) 1 else 0});
    if (!present) return;
    var hdr: [4]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], format_id, .big);
    std.mem.writeInt(u16, hdr[2..4], format_version, .big);
    hasher.update(&hdr);
    var len_be: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_be, @intCast(bytes.len), .big);
    hasher.update(&len_be);
    hasher.update(bytes);
}

/// Domain-separated SHA-256 digest over the stored session's compatibility
/// identity. Never includes ticket identity, PSK, ticket nonce, issue time,
/// lifetime, or early-data policy (#364 required interface properties). A
/// digest match is only a bucketing hint: `session.evaluateCompatibility`
/// is always re-checked afterward.
pub fn originDigestFromCommon(common: *const session.ResumableSessionCommon) OriginDigest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(origin_digest_domain);
    var cs: [2]u8 = undefined;
    std.mem.writeInt(u16, &cs, @intFromEnum(common.cipher_suite), .big);
    hasher.update(&cs);
    if (common.server_name) |*s| hashPresenceLenBytes(&hasher, true, s.slice()) else hashPresenceLenBytes(&hasher, false, &.{});
    if (common.application_protocol) |*a|
        hashPresenceLenBytes(&hasher, true, a.slice())
    else
        hashPresenceLenBytes(&hasher, false, &.{});
    hasher.update(&common.auth_binding.bytes);
    if (common.transport_compat) |*snap|
        hashCompat(&hasher, true, snap.format_id, snap.format_version, snap.slice())
    else
        hashCompat(&hasher, false, 0, 0, &.{});
    if (common.application_compat) |*snap|
        hashCompat(&hasher, true, snap.format_id, snap.format_version, snap.slice())
    else
        hashCompat(&hasher, false, 0, 0, &.{});
    var out: OriginDigest = undefined;
    hasher.final(&out);
    return out;
}

/// Same digest, computed from a lookup candidate. Attacker-controlled
/// lengths are capped at the same bounds the stored side enforces before
/// hashing (SNI/ALPN/compat blobs cannot be unbounded here); a truncated
/// candidate can only ever produce a spurious digest bucket hit, never a
/// spurious accept, because `session.evaluateCompatibility` re-checks the
/// full untruncated candidate afterward.
pub fn originDigestFromCandidate(candidate: session.CandidateContext) OriginDigest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(origin_digest_domain);
    var cs: [2]u8 = undefined;
    std.mem.writeInt(u16, &cs, @intFromEnum(candidate.cipher_suite), .big);
    hasher.update(&cs);

    if (candidate.server_name) |raw| {
        var lowered: [session.max_sni_len]u8 = undefined;
        const n = @min(raw.len, lowered.len);
        for (raw[0..n], 0..) |ch, i| lowered[i] = asciiLower(ch);
        hashPresenceLenBytes(&hasher, true, lowered[0..n]);
    } else {
        hashPresenceLenBytes(&hasher, false, &.{});
    }

    if (candidate.application_protocol) |raw| {
        const n = @min(raw.len, session.max_alpn_len);
        hashPresenceLenBytes(&hasher, true, raw[0..n]);
    } else {
        hashPresenceLenBytes(&hasher, false, &.{});
    }

    hasher.update(&candidate.auth_binding.bytes);

    if (candidate.transport_compat) |tc| {
        const n = @min(tc.bytes.len, session.hard_max_compat_len);
        hashCompat(&hasher, true, tc.format_id, tc.format_version, tc.bytes[0..n]);
    } else {
        hashCompat(&hasher, false, 0, 0, &.{});
    }

    if (candidate.application_compat) |ac| {
        const n = @min(ac.bytes.len, session.hard_max_compat_len);
        hashCompat(&hasher, true, ac.format_id, ac.format_version, ac.bytes[0..n]);
    } else {
        hashCompat(&hasher, false, 0, 0, &.{});
    }

    var out: OriginDigest = undefined;
    hasher.final(&out);
    return out;
}

fn asciiLower(ch: u8) u8 {
    return if (ch >= 'A' and ch <= 'Z') ch + ('a' - 'A') else ch;
}

fn accountedBytes(encoded_len: usize, extra: usize) usize {
    return encoded_len + entry_overhead_bytes + extra;
}

fn clientAccountedBytes(ticket: *const session.ClientTicketState) usize {
    return accountedBytes(session.clientEncodedLen(ticket), 0);
}

fn serverAccountedBytes(state: *const session.ServerRecoverableState) usize {
    return accountedBytes(session.serverEncodedLen(state), stateful_identity_len);
}

// -----------------------------------------------------------------------
// Client session cache
// -----------------------------------------------------------------------

const ClientEntry = struct {
    ticket: session.ClientTicketState = .{},
    origin: OriginDigest = [_]u8{0} ** origin_digest_len,
    usage: UsagePolicy = .reusable,
    /// Assigned once at store/replace time; drives the canonical offer
    /// order (newest insertion first). Never changed by a lookup.
    insertion_sequence: u64 = 0,
    /// Bumped on every store/replace *and* on every successful lookup touch;
    /// drives LRU eviction order. Distinct from `insertion_sequence` so a
    /// read-heavy, rarely-replaced entry is still protected from eviction.
    lru_sequence: u64 = 0,
    entry_id: u64 = 0,
    bytes: usize = 0,
};

pub const PersistedClientEntry = struct {
    ticket: session.ClientTicketState = .{},
    usage: UsagePolicy = .reusable,
    insertion_sequence: u64 = 0,
    lru_sequence: u64 = 0,

    pub fn deinit(self: *PersistedClientEntry) void {
        self.ticket.deinit();
    }
};

/// Typed lookup outcome. `.hit` is the only variant that owns anything
/// (the returned offer set); an allocation failure partway through cloning
/// never surfaces as a partial `.hit` — it is always the distinct
/// `.storage_failed` outcome instead.
pub const ClientLookupResult = union(enum) {
    hit: pre_shared_key.ClientPskOfferSet,
    miss,
    expired,
    incompatible,
    storage_failed,

    pub fn deinit(self: *ClientLookupResult) void {
        switch (self.*) {
            .hit => |*o| o.deinit(),
            else => {},
        }
    }
};

/// Bounded client-side ticket store keyed by canonical origin digest.
/// Process-shared and thread-safe: see module doc for the mutex/observer
/// discipline.
pub const ClientSessionCache = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    observer: Observer = .{},
    mutex: zig_compat.Mutex = .{},
    entries: std.ArrayListUnmanaged(ClientEntry) = .empty,
    total_bytes: usize = 0,
    next_insertion_sequence: u64 = 0,
    next_lru_sequence: u64 = 0,
    next_entry_id: u64 = 0,
    /// Set for the duration of `cloneLiveForPersistence`; while set,
    /// `consumeSingleUse` refuses to consume anything, closing the race
    /// where a ticket is selected/consumed after being cloned into a
    /// snapshot but before that snapshot reaches durable storage (which
    /// would otherwise let a restart resurrect an already-consumed
    /// ticket). Save/load calls on one cache are expected to be serialized
    /// by the caller; this guards a single in-flight snapshot, not
    /// concurrent snapshots of the same cache racing each other.
    persistence_in_progress: bool = false,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) error{InvalidLimits}!ClientSessionCache {
        try limits.validate();
        return .{ .allocator = allocator, .limits = limits };
    }

    /// Requires quiescence: no concurrent callers and no outstanding borrows
    /// (all cache returns are owned clones, so there is nothing else to
    /// invalidate).
    pub fn deinit(self: *ClientSessionCache) void {
        for (self.entries.items) |*e| e.ticket.deinit();
        self.entries.deinit(self.allocator);
        self.entries = .empty;
        self.total_bytes = 0;
    }

    pub fn setObserver(self: *ClientSessionCache, observer: Observer) void {
        self.observer = observer;
    }

    pub fn count(self: *ClientSessionCache) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.items.len;
    }

    pub fn totalBytes(self: *ClientSessionCache) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.total_bytes;
    }

    /// Removes every expired entry regardless of origin. Called
    /// automatically before every store/replace decision (so an expired
    /// entry in an unrelated origin can never permanently block that
    /// origin's cardinality limit), and exposed publicly for periodic/
    /// reload/shutdown maintenance.
    pub fn cleanup(self: *ClientSessionCache, now_unix_ms: i64) usize {
        var removed: usize = 0;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.purgeExpiredAllLocked(now_unix_ms, &removed);
        }
        var i: usize = 0;
        while (i < removed) : (i += 1) self.observer.notify(.evicted);
        return removed;
    }

    /// Deep-clones `ticket` and stores the clone. `ticket` itself is never
    /// mutated or consumed — the #361 callback argument this is fed from is
    /// only borrowed for the callback's duration. Never fails the caller's
    /// TLS connection: every rejection is a plain `StoreResult`.
    pub fn storeClone(
        self: *ClientSessionCache,
        ticket: *const session.ClientTicketState,
        now_unix_ms: i64,
        usage: UsagePolicy,
    ) StoreResult {
        var cloned: session.ClientTicketState = .{};
        ticket.cloneInto(self.allocator, &cloned) catch {
            self.observer.notify(.storage_failed);
            return .storage_failed;
        };

        const origin = originDigestFromCommon(&cloned.common);
        var evicted: usize = 0;
        var result: StoreResult = undefined;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            result = self.storeLocked(&cloned, origin, now_unix_ms, usage, &evicted);
        }

        if (result != .stored and result != .replaced) cloned.deinit();

        var i: usize = 0;
        while (i < evicted) : (i += 1) self.observer.notify(.evicted);
        self.observer.notify(switch (result) {
            .stored => .stored,
            .replaced => .replaced,
            .rejected_capacity => .rejected_capacity,
            .storage_failed => .storage_failed,
            .rejected_handle_generation_failed => unreachable,
        });
        return result;
    }

    fn storeLocked(
        self: *ClientSessionCache,
        cloned: *session.ClientTicketState,
        origin: OriginDigest,
        now_unix_ms: i64,
        usage: UsagePolicy,
        evicted: *usize,
    ) StoreResult {
        self.purgeExpiredAllLocked(now_unix_ms, evicted);

        var dup_idx: ?usize = null;
        for (self.entries.items, 0..) |*e, i| {
            if (!std.mem.eql(u8, &e.origin, &origin)) continue;
            if (!e.ticket.ticket.eql(&cloned.ticket)) continue;
            dup_idx = i;
            break;
        }

        if (dup_idx) |i| {
            // Preflight the replacement fully before touching the old
            // entry: a repeated ticket identity with a larger encoded
            // payload must not be able to exceed either limit, and a
            // rejection here must leave the previous entry completely
            // intact.
            const replacement_bytes = clientAccountedBytes(cloned);
            if (replacement_bytes > self.limits.max_entry_bytes) return .rejected_capacity;
            const projected = self.total_bytes - self.entries.items[i].bytes + replacement_bytes;
            if (projected > self.limits.max_total_bytes) return .rejected_capacity;

            // Compute both sequence numbers *before* mutating the entry:
            // these are plain wrapping counters (see module doc) and never
            // reorder `entries.items`, so `i` stays valid across them, but
            // keeping the increments and the field writes separated makes
            // that invariant easy to audit rather than incidental.
            const new_insertion_seq = self.nextInsertionSequence();
            const new_lru_seq = self.nextLruSequence();

            const e = &self.entries.items[i];
            var old = e.ticket;
            e.ticket = .{};
            e.ticket.moveFrom(cloned);
            e.usage = usage;
            e.insertion_sequence = new_insertion_seq;
            e.lru_sequence = new_lru_seq;
            e.bytes = replacement_bytes;
            self.total_bytes = projected;
            old.deinit();
            return .replaced;
        }

        const new_bytes = clientAccountedBytes(cloned);
        if (new_bytes > self.limits.max_entry_bytes) return .rejected_capacity;

        const origin_count = self.countOrigin(origin);
        if (origin_count == 0 and self.countDistinctOrigins() >= self.limits.max_origins) {
            return .rejected_capacity;
        }

        self.entries.ensureUnusedCapacity(self.allocator, 1) catch return .storage_failed;

        while (self.countOrigin(origin) >= self.limits.max_entries_per_origin) {
            if (!self.evictOldestInOrigin(origin)) return .rejected_capacity;
            evicted.* += 1;
        }
        while (self.entries.items.len >= self.limits.max_entries or
            self.total_bytes + new_bytes > self.limits.max_total_bytes)
        {
            if (self.entries.items.len == 0) return .rejected_capacity;
            if (!self.evictOldestGlobal()) return .rejected_capacity;
            evicted.* += 1;
        }

        var entry: ClientEntry = .{
            .origin = origin,
            .usage = usage,
            .insertion_sequence = self.nextInsertionSequence(),
            .lru_sequence = self.nextLruSequence(),
            .entry_id = self.nextEntryId(),
            .bytes = new_bytes,
        };
        entry.ticket.moveFrom(cloned);
        self.entries.appendAssumeCapacity(entry);
        self.total_bytes += new_bytes;
        return .stored;
    }

    /// Recomputes exact expiry/compatibility, returns up to
    /// `pre_shared_key.max_offered_identities` fully owned clones in
    /// deterministic order (newest `insertion_sequence` first, then newer
    /// `received_at_unix_ms`, then internal entry ID), and never aliases
    /// cache storage. A clone failure partway through never returns a
    /// partial offer set: the whole lookup reports `.storage_failed`
    /// instead. Every returned entry's `lru_sequence` is refreshed so a
    /// lookup protects the touched entries from the next eviction.
    pub fn lookupOffers(self: *ClientSessionCache, candidate: session.CandidateContext, now_unix_ms: i64) ClientLookupResult {
        const origin = originDigestFromCandidate(candidate);
        const Candidate = struct {
            idx: usize,
            insertion_sequence: u64,
            received_at: i64,
            entry_id: u64,

            fn moreRecent(_: void, a: @This(), b: @This()) bool {
                if (a.insertion_sequence != b.insertion_sequence) return a.insertion_sequence > b.insertion_sequence;
                if (a.received_at != b.received_at) return a.received_at > b.received_at;
                return a.entry_id > b.entry_id;
            }
        };
        var buf: [hard_max_entries_per_origin]Candidate = undefined;
        var n: usize = 0;
        var had_expired_removal = false;
        var had_incompatible = false;
        var storage_failed = false;
        var offers: pre_shared_key.ClientPskOfferSet = .{};

        {
            self.mutex.lock();
            defer self.mutex.unlock();

            var i: usize = 0;
            while (i < self.entries.items.len) {
                const e = &self.entries.items[i];
                if (!std.mem.eql(u8, &e.origin, &origin)) {
                    i += 1;
                    continue;
                }
                if (e.ticket.common.isExpired(now_unix_ms)) {
                    var removed = self.entries.swapRemove(i);
                    self.total_bytes -= removed.bytes;
                    removed.ticket.deinit();
                    had_expired_removal = true;
                    continue;
                }
                const decision = session.evaluateCompatibility(&e.ticket.common, candidate, now_unix_ms);
                if (decision.resumption == .eligible and n < buf.len) {
                    buf[n] = .{ .idx = i, .insertion_sequence = e.insertion_sequence, .received_at = e.ticket.received_at_unix_ms, .entry_id = e.entry_id };
                    n += 1;
                } else if (decision.resumption != .eligible) {
                    had_incompatible = true;
                }
                i += 1;
            }

            std.mem.sort(Candidate, buf[0..n], {}, Candidate.moreRecent);
            const take = @min(n, pre_shared_key.max_offered_identities);

            // `nextLruSequence` is a plain wrapping increment (see module
            // doc): it never reorders `entries.items`, so the physical
            // `idx` captured above stays valid across every call here.
            var touched: [pre_shared_key.max_offered_identities]usize = undefined;
            var touched_len: usize = 0;
            for (buf[0..take]) |c| {
                var clone: session.ClientTicketState = .{};
                self.entries.items[c.idx].ticket.cloneInto(self.allocator, &clone) catch {
                    storage_failed = true;
                    break;
                };
                offers.push(&clone) catch {
                    // Unreachable in practice: `take` is bounded by
                    // `max_offered_identities`, the set's capacity.
                    clone.deinit();
                    storage_failed = true;
                    break;
                };
                touched[touched_len] = c.idx;
                touched_len += 1;
            }

            if (storage_failed) {
                offers.deinit();
            } else {
                for (touched[0..touched_len]) |idx| {
                    self.entries.items[idx].lru_sequence = self.nextLruSequence();
                }
            }
        }

        const result: ClientLookupResult = if (storage_failed)
            .storage_failed
        else if (!offers.isEmpty())
            .{ .hit = offers }
        else if (had_expired_removal)
            .expired
        else if (had_incompatible)
            .incompatible
        else
            .miss;

        self.observer.notify(switch (result) {
            .hit => .lookup_hit,
            .miss => .lookup_miss,
            .expired => .lookup_expired,
            .incompatible => .lookup_incompatible,
            .storage_failed => .storage_failed,
        });
        return result;
    }

    /// Removes and wipes the single-use entry matching `ticket_identity`
    /// within `origin` once the server-selected offer has been consumed.
    /// Reusable entries are left untouched. Returns `false` (without
    /// consuming anything) both when no matching entry is found and while
    /// a persistence snapshot is in progress (see `persistence_in_progress`)
    /// — the latter closes a race where a ticket consumed after being
    /// cloned into a snapshot, but before that snapshot reaches durable
    /// storage, would otherwise let a restart resurrect it.
    ///
    /// This is the cache-side half of client single-use commit; wiring the
    /// resolved offer index back from the TLS 1.3 backend is deferred to
    /// #365 per issue #364's canonical plan.
    pub fn consumeSingleUse(self: *ClientSessionCache, origin: OriginDigest, ticket_identity: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.persistence_in_progress) return false;
        var i: usize = 0;
        while (i < self.entries.items.len) : (i += 1) {
            const e = &self.entries.items[i];
            if (!std.mem.eql(u8, &e.origin, &origin)) continue;
            if (e.usage != .single_use) continue;
            if (!secrets.constantTimeEqual(e.ticket.ticket.slice(), ticket_identity)) continue;
            var removed = self.entries.swapRemove(i);
            self.total_bytes -= removed.bytes;
            removed.ticket.deinit();
            return true;
        }
        return false;
    }

    /// Deep-clones every non-expired entry for a persistence save,
    /// including its exact insertion/LRU order. Sets
    /// `persistence_in_progress` for the duration of the *whole* save
    /// (through `endPersistenceSnapshot`, which the caller must invoke once
    /// the snapshot has been durably written or the save has failed) so
    /// `consumeSingleUse` cannot race a concurrent snapshot.
    pub fn cloneLiveForPersistence(
        self: *ClientSessionCache,
        allocator: std.mem.Allocator,
        now_unix_ms: i64,
    ) error{OutOfMemory}!std.ArrayListUnmanaged(PersistedClientEntry) {
        self.mutex.lock();
        self.persistence_in_progress = true;

        var out: std.ArrayListUnmanaged(PersistedClientEntry) = .empty;
        var failed = false;
        out.ensureTotalCapacityPrecise(allocator, self.entries.items.len) catch {
            failed = true;
        };
        if (!failed) {
            for (self.entries.items) |*e| {
                if (e.ticket.common.isExpired(now_unix_ms)) continue;
                var clone: PersistedClientEntry = .{
                    .usage = e.usage,
                    .insertion_sequence = e.insertion_sequence,
                    .lru_sequence = e.lru_sequence,
                };
                e.ticket.cloneInto(allocator, &clone.ticket) catch {
                    failed = true;
                    break;
                };
                out.appendAssumeCapacity(clone);
            }
        }
        self.mutex.unlock();

        if (failed) {
            for (out.items) |*p| p.deinit();
            out.deinit(allocator);
            self.endPersistenceSnapshot();
            return error.OutOfMemory;
        }
        return out;
    }

    /// Clears `persistence_in_progress`. Must be called exactly once after
    /// `cloneLiveForPersistence` succeeds, once the snapshot it returned is
    /// either durably saved or abandoned.
    pub fn endPersistenceSnapshot(self: *ClientSessionCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.persistence_in_progress = false;
    }

    pub const RestoreError = error{OutOfMemory};

    /// Restores previously-persisted entries, enforcing current limits and
    /// discarding expired ones, while preserving each entry's original
    /// `insertion_sequence`/`lru_sequence` exactly (unlike `storeClone`,
    /// which always assigns fresh values) so post-reload offer order and
    /// eviction order match the pre-save cache. Duplicate `(origin,
    /// ticket-identity)` records — which a corrupted or hostile snapshot
    /// could contain even though the live store never produces them — are
    /// resolved deterministically: only the record with the largest
    /// `insertion_sequence` (ties broken by later array position) survives,
    /// matching the live store's own replace-on-duplicate rule.
    ///
    /// Every item is consumed (deinitialized) regardless of outcome. This
    /// is fallible and atomic per call: any allocation failure aborts
    /// immediately with `error.OutOfMemory`, and the caller must not treat
    /// a partially-restored cache as successful. A record that is merely
    /// rejected for ordinary capacity reasons (e.g. the current limits are
    /// tighter than when the snapshot was taken) is *not* an error — that
    /// entry is deterministically dropped and restoration continues; this
    /// is an explicit truncation policy, not a silent failure.
    pub fn restoreClones(self: *ClientSessionCache, items: []PersistedClientEntry, now_unix_ms: i64) RestoreError!void {
        defer for (items) |*item| item.deinit();

        markDuplicateClientRecords(items);

        for (items) |*item| {
            if (item.ticket.ticket.len == 0) continue; // dropped as a duplicate loser
            if (item.ticket.common.isExpired(now_unix_ms)) continue;

            const origin = originDigestFromCommon(&item.ticket.common);
            var evicted: usize = 0;
            self.mutex.lock();
            const result = self.restoreLocked(&item.ticket, origin, item.usage, item.insertion_sequence, item.lru_sequence, now_unix_ms, &evicted);
            self.mutex.unlock();
            if (result == .storage_failed) return error.OutOfMemory;
        }
    }

    fn restoreLocked(
        self: *ClientSessionCache,
        ticket: *session.ClientTicketState,
        origin: OriginDigest,
        usage: UsagePolicy,
        insertion_sequence: u64,
        lru_sequence: u64,
        now_unix_ms: i64,
        evicted: *usize,
    ) StoreResult {
        self.purgeExpiredAllLocked(now_unix_ms, evicted);

        const new_bytes = clientAccountedBytes(ticket);
        if (new_bytes > self.limits.max_entry_bytes) return .rejected_capacity;

        const origin_count = self.countOrigin(origin);
        if (origin_count == 0 and self.countDistinctOrigins() >= self.limits.max_origins) {
            return .rejected_capacity;
        }

        self.entries.ensureUnusedCapacity(self.allocator, 1) catch return .storage_failed;

        while (self.countOrigin(origin) >= self.limits.max_entries_per_origin) {
            if (!self.evictOldestInOrigin(origin)) return .rejected_capacity;
            evicted.* += 1;
        }
        while (self.entries.items.len >= self.limits.max_entries or
            self.total_bytes + new_bytes > self.limits.max_total_bytes)
        {
            if (self.entries.items.len == 0) return .rejected_capacity;
            if (!self.evictOldestGlobal()) return .rejected_capacity;
            evicted.* += 1;
        }

        var entry: ClientEntry = .{
            .origin = origin,
            .usage = usage,
            .insertion_sequence = insertion_sequence,
            .lru_sequence = lru_sequence,
            .entry_id = self.nextEntryId(),
            .bytes = new_bytes,
        };
        entry.ticket.moveFrom(ticket);
        self.entries.appendAssumeCapacity(entry);
        self.total_bytes += new_bytes;

        if (insertion_sequence >= self.next_insertion_sequence) self.next_insertion_sequence = insertion_sequence +% 1;
        if (lru_sequence >= self.next_lru_sequence) self.next_lru_sequence = lru_sequence +% 1;
        return .stored;
    }

    fn purgeExpiredAllLocked(self: *ClientSessionCache, now_unix_ms: i64, evicted: *usize) void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const e = &self.entries.items[i];
            if (e.ticket.common.isExpired(now_unix_ms)) {
                var removed = self.entries.swapRemove(i);
                self.total_bytes -= removed.bytes;
                removed.ticket.deinit();
                evicted.* += 1;
                continue;
            }
            i += 1;
        }
    }

    fn countOrigin(self: *ClientSessionCache, origin: OriginDigest) usize {
        var n: usize = 0;
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, &e.origin, &origin)) n += 1;
        }
        return n;
    }

    fn countDistinctOrigins(self: *ClientSessionCache) usize {
        var n: usize = 0;
        outer: for (self.entries.items, 0..) |*e, i| {
            for (self.entries.items[0..i]) |*prev| {
                if (std.mem.eql(u8, &prev.origin, &e.origin)) continue :outer;
            }
            n += 1;
        }
        return n;
    }

    fn evictOldestInOrigin(self: *ClientSessionCache, origin: OriginDigest) bool {
        var best: ?usize = null;
        for (self.entries.items, 0..) |*e, i| {
            if (!std.mem.eql(u8, &e.origin, &origin)) continue;
            if (best == null or e.lru_sequence < self.entries.items[best.?].lru_sequence) best = i;
        }
        const idx = best orelse return false;
        var removed = self.entries.swapRemove(idx);
        self.total_bytes -= removed.bytes;
        removed.ticket.deinit();
        return true;
    }

    fn evictOldestGlobal(self: *ClientSessionCache) bool {
        var best: ?usize = null;
        for (self.entries.items, 0..) |*e, i| {
            if (best == null or e.lru_sequence < self.entries.items[best.?].lru_sequence) best = i;
        }
        const idx = best orelse return false;
        var removed = self.entries.swapRemove(idx);
        self.total_bytes -= removed.bytes;
        removed.ticket.deinit();
        return true;
    }

    fn nextInsertionSequence(self: *ClientSessionCache) u64 {
        const s = self.next_insertion_sequence;
        self.next_insertion_sequence +%= 1;
        return s;
    }

    fn nextLruSequence(self: *ClientSessionCache) u64 {
        const s = self.next_lru_sequence;
        self.next_lru_sequence +%= 1;
        return s;
    }

    fn nextEntryId(self: *ClientSessionCache) u64 {
        const id = self.next_entry_id;
        self.next_entry_id +%= 1;
        return id;
    }
};

/// Keeps, for each duplicate `(origin, ticket-identity)` pair, only the
/// record with the largest `insertion_sequence` (ties broken by later
/// array position); losers are deinitialized in place (their `ticket.len`
/// becomes `0`, which `restoreClones` uses as a "already dropped" marker —
/// a real ticket can never have length `0`, so this is unambiguous).
fn markDuplicateClientRecords(items: []PersistedClientEntry) void {
    var i: usize = 0;
    while (i < items.len) : (i += 1) {
        if (items[i].ticket.ticket.len == 0) continue;
        const origin_i = originDigestFromCommon(&items[i].ticket.common);
        var j = i + 1;
        while (j < items.len) : (j += 1) {
            if (items[j].ticket.ticket.len == 0) continue;
            const origin_j = originDigestFromCommon(&items[j].ticket.common);
            if (!std.mem.eql(u8, &origin_i, &origin_j)) continue;
            if (!items[i].ticket.ticket.eql(&items[j].ticket.ticket)) continue;
            if (items[i].insertion_sequence <= items[j].insertion_sequence) {
                items[i].deinit();
                break;
            } else {
                items[j].deinit();
            }
        }
    }
}

// -----------------------------------------------------------------------
// Stateful server cache
// -----------------------------------------------------------------------

/// `"TDSH" | version:u16 | reserved:u16 | 32 random bytes` = 40 bytes. An
/// unpredictable bearer secret: no timestamp, origin, PSK, key ID, or state
/// metadata is ever encoded in it.
pub const stateful_identity_len: usize = 40;
const stateful_magic = [4]u8{ 'T', 'D', 'S', 'H' };
const stateful_version: u16 = 1;
const max_handle_generation_attempts: usize = 8;

/// Injectable entropy source so handle-collision retry/exhaustion behavior
/// is deterministically testable without weakening the production path
/// (`system_random_source` draws from the OS CSPRNG). Same shape as
/// `crypto.provider.Entropy`, kept as its own type so a handle-generation
/// failure is distinguishable from a handshake-entropy failure.
pub const RandomSource = struct {
    ctx: *anyopaque,
    fillFn: *const fn (ctx: *anyopaque, buf: []u8) error{EntropyFailure}!void,

    pub fn fill(self: RandomSource, buf: []u8) error{EntropyFailure}!void {
        return self.fillFn(self.ctx, buf);
    }
};

var system_random_dummy: u8 = 0;

fn systemRandomFill(_: *anyopaque, buf: []u8) error{EntropyFailure}!void {
    if (buf.len == 0) return;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var offset: usize = 0;
        while (offset < buf.len) {
            const rc = linux.getrandom(buf[offset..].ptr, buf.len - offset, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return error.EntropyFailure;
                    offset += rc;
                },
                .INTR => {},
                else => return error.EntropyFailure,
            }
        }
        return;
    }
    if (@TypeOf(std.c.arc4random_buf) != void) {
        std.c.arc4random_buf(buf.ptr, buf.len);
        return;
    }
    return error.EntropyFailure;
}

pub const system_random_source: RandomSource = .{ .ctx = &system_random_dummy, .fillFn = systemRandomFill };

pub const HandleError = error{HandleGenerationFailed};

/// Validates the complete `TDSH` v1 wire shape: exact length, magic,
/// version, and a zero reserved field. Used both when resolving a
/// caller-supplied identity and when validating a persisted handle before
/// it re-enters the cache.
pub fn isValidStatefulHandleShape(identity: []const u8) bool {
    if (identity.len != stateful_identity_len) return false;
    if (!std.mem.eql(u8, identity[0..4], &stateful_magic)) return false;
    if (std.mem.readInt(u16, identity[4..6], .big) != stateful_version) return false;
    if (std.mem.readInt(u16, identity[6..8], .big) != 0) return false;
    return true;
}

const ServerEntry = struct {
    state: session.ServerRecoverableState = .{},
    origin: OriginDigest = [_]u8{0} ** origin_digest_len,
    handle: [stateful_identity_len]u8 = [_]u8{0} ** stateful_identity_len,
    usage: UsagePolicy = .reusable,
    /// Set while a single-use entry is pinned to an in-flight resolution;
    /// `null` for reusable entries (which are never pinned) and for
    /// single-use entries that are currently resolvable. The specific
    /// value is this acquisition's unique epoch (see `ServerLease`).
    active_lease_epoch: ?u64 = null,
    lru_sequence: u64 = 0,
    bytes: usize = 0,
};

pub const PersistedServerEntry = struct {
    handle: [stateful_identity_len]u8 = [_]u8{0} ** stateful_identity_len,
    usage: UsagePolicy = .reusable,
    state: session.ServerRecoverableState = .{},
    lru_sequence: u64 = 0,

    pub fn deinit(self: *PersistedServerEntry) void {
        self.state.deinit();
        secrets.secureZero(&self.handle);
    }
};

/// An owned, exactly-once lease over a single resolution of a stateful
/// entry. `entry_id` identifies the storage slot; `lease_epoch` identifies
/// *this specific acquisition* — a fresh epoch is assigned every time a
/// single-use entry transitions from resolvable to pinned, so a stale token
/// from an earlier acquisition can never commit or release a later,
/// unrelated one of the same entry. Reusable leases carry
/// `single_use = false`; `commit` still touches their recency (see
/// `StatefulServerCache.commitLease`), but `release` is a no-op for them
/// since they are never pinned.
///
/// `deinit` releases the lease if it is still outstanding, so a caller that
/// forgets to explicitly `commit`/`release` (e.g. an early-return error
/// path) cannot leave a single-use entry pinned forever — call it via
/// `defer lease.deinit()` immediately after a successful resolve.
pub const ServerLease = struct {
    cache: *StatefulServerCache,
    entry_id: u64,
    lease_epoch: u64,
    single_use: bool,
    active: bool = true,

    /// Call after the shared #362 path has verified compatibility and the
    /// binder for this resolution: for a single-use entry this consumes
    /// it; for a reusable entry this only refreshes its LRU recency
    /// (recency is deliberately updated here, on confirmed use, rather
    /// than on the earlier `resolveLease` call).
    pub fn commit(self: *ServerLease) void {
        if (!self.active) return;
        self.active = false;
        self.cache.commitLease(self.entry_id, self.lease_epoch, self.single_use);
    }

    pub fn release(self: *ServerLease) void {
        if (!self.active) return;
        self.active = false;
        if (!self.single_use) return;
        self.cache.releaseLease(self.entry_id, self.lease_epoch);
    }

    pub fn deinit(self: *ServerLease) void {
        self.release();
    }
};

pub const ResolveLeaseResult = union(enum) {
    hit: struct { state: session.ServerRecoverableState, lease: ServerLease },
    miss,
    expired,
    /// A single-use identity is otherwise resolvable, but a persistence
    /// snapshot is currently in progress (see `persistence_in_progress`):
    /// refused rather than risk a just-persisted-then-consumed ticket.
    busy,
    storage_failed,

    pub fn deinit(self: *ResolveLeaseResult) void {
        switch (self.*) {
            .hit => |*h| {
                h.lease.deinit();
                h.state.deinit();
            },
            else => {},
        }
    }
};

const OriginBucket = std.ArrayListUnmanaged(u64);

/// Bounded stateful server-side ticket/session store keyed by a random
/// opaque handle. Primary index is `handle -> entry_id` (O(1)); `entry_id`
/// is the stable storage key so LRU/eviction never invalidates it. A
/// secondary `origin -> [entry_id]` index bounds per-origin operations
/// without scanning the whole cache. Process-shared and thread-safe (see
/// module doc).
///
/// Compatibility (SNI/ALPN/cipher/auth/transport/application/expiry) is
/// deliberately *not* evaluated here: `resolveLease` only resolves storage.
/// The shared #362 path (`session.evaluateCompatibility`, driven from
/// `tls13_backend.zig`) evaluates the returned state exactly once for both
/// stateless and stateful identities, then commits or releases the lease.
pub const StatefulServerCache = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    random: RandomSource,
    observer: Observer = .{},
    mutex: zig_compat.Mutex = .{},
    entries: std.AutoHashMapUnmanaged(u64, ServerEntry) = .empty,
    handle_index: std.AutoHashMapUnmanaged([stateful_identity_len]u8, u64) = .empty,
    origin_index: std.AutoHashMapUnmanaged(OriginDigest, OriginBucket) = .empty,
    total_bytes: usize = 0,
    next_entry_id: u64 = 1,
    next_lru_sequence: u64 = 0,
    next_lease_epoch: u64 = 1,
    /// See `ClientSessionCache.persistence_in_progress`: set for the whole
    /// duration of a save (through `endPersistenceSnapshot`), during which
    /// new single-use leases are refused (`.busy`) rather than risk a
    /// just-persisted-then-consumed ticket being resurrected on reload.
    persistence_in_progress: bool = false,

    pub fn init(allocator: std.mem.Allocator, limits: Limits, random: RandomSource) error{InvalidLimits}!StatefulServerCache {
        try limits.validate();
        return .{ .allocator = allocator, .limits = limits, .random = random };
    }

    /// Requires quiescence: no outstanding leases and no concurrent callers.
    pub fn deinit(self: *StatefulServerCache) void {
        var it = self.entries.valueIterator();
        while (it.next()) |e| {
            e.state.deinit();
            secrets.secureZero(&e.handle);
        }
        self.entries.deinit(self.allocator);
        self.handle_index.deinit(self.allocator);
        var bucket_it = self.origin_index.valueIterator();
        while (bucket_it.next()) |b| b.deinit(self.allocator);
        self.origin_index.deinit(self.allocator);
        self.entries = .empty;
        self.handle_index = .empty;
        self.origin_index = .empty;
        self.total_bytes = 0;
    }

    pub fn setObserver(self: *StatefulServerCache, observer: Observer) void {
        self.observer = observer;
    }

    pub fn count(self: *StatefulServerCache) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.count();
    }

    pub fn totalBytes(self: *StatefulServerCache) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.total_bytes;
    }

    pub fn cleanup(self: *StatefulServerCache, now_unix_ms: i64) usize {
        var removed: usize = 0;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.purgeExpiredAllLocked(now_unix_ms, &removed);
        }
        var i: usize = 0;
        while (i < removed) : (i += 1) self.observer.notify(.evicted);
        return removed;
    }

    /// Moves ownership of `state` into the cache on success (`state.*`
    /// becomes zero-valued); on any rejection `state.*` is left completely
    /// unchanged. Generates and returns a fresh unpredictable `out_identity`
    /// on success only.
    pub fn insertMove(
        self: *StatefulServerCache,
        state: *session.ServerRecoverableState,
        now_unix_ms: i64,
        usage: UsagePolicy,
        out_identity: *[stateful_identity_len]u8,
    ) StoreResult {
        const bytes = serverAccountedBytes(state);
        if (bytes > self.limits.max_entry_bytes) {
            self.observer.notify(.rejected_capacity);
            return .rejected_capacity;
        }
        const origin = originDigestFromCommon(&state.common);

        var handle: [stateful_identity_len]u8 = undefined;
        var evicted: usize = 0;
        var result: StoreResult = undefined;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            result = blk: {
                self.generateHandleLocked(&handle) catch break :blk .rejected_handle_generation_failed;
                break :blk self.insertLocked(state, handle, origin, usage, now_unix_ms, bytes, self.nextLruSequenceLocked(), &evicted);
            };
        }

        if (result == .stored) out_identity.* = handle;

        var i: usize = 0;
        while (i < evicted) : (i += 1) self.observer.notify(.evicted);
        self.observer.notify(switch (result) {
            .stored => .stored,
            .rejected_capacity => .rejected_capacity,
            .rejected_handle_generation_failed => .rejected_handle_generation_failed,
            .storage_failed => .storage_failed,
            .replaced => unreachable,
        });
        return result;
    }

    /// Whether `bytes` could possibly fit without evicting any currently
    /// leased entry — a pure, non-mutating preflight. Leased entries are
    /// never eviction candidates, so if the cache could never get under
    /// its count/byte/per-origin limits using only *unleased* entries as
    /// victims, the insert must be rejected before anything is mutated
    /// (rather than evicting some unleased entries and only then
    /// discovering the rest are leased).
    fn canFitLocked(self: *StatefulServerCache, origin: OriginDigest, new_bytes: usize) bool {
        var leased_count: usize = 0;
        var leased_bytes: usize = 0;
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.active_lease_epoch != null) {
                leased_count += 1;
                leased_bytes += kv.value_ptr.bytes;
            }
        }
        if (leased_count >= self.limits.max_entries) return false;
        if (leased_bytes + new_bytes > self.limits.max_total_bytes) return false;

        if (self.origin_index.get(origin)) |bucket| {
            var origin_leased: usize = 0;
            for (bucket.items) |id| {
                const e = self.entries.getPtr(id) orelse continue;
                if (e.active_lease_epoch != null) origin_leased += 1;
            }
            if (origin_leased >= self.limits.max_entries_per_origin) return false;
        }
        return true;
    }

    /// `lru_sequence` is supplied by the caller (rather than always
    /// assigned fresh) so `restoreEntries` can preserve a persisted entry's
    /// original recency instead of it always appearing most-recent.
    fn insertLocked(
        self: *StatefulServerCache,
        state: *session.ServerRecoverableState,
        handle: [stateful_identity_len]u8,
        origin: OriginDigest,
        usage: UsagePolicy,
        now_unix_ms: i64,
        bytes: usize,
        lru_sequence: u64,
        evicted: *usize,
    ) StoreResult {
        self.purgeExpiredAllLocked(now_unix_ms, evicted);
        if (self.handle_index.contains(handle)) return .rejected_capacity;

        const is_new_origin = !self.origin_index.contains(origin);
        if (is_new_origin and self.origin_index.count() >= self.limits.max_origins) {
            return .rejected_capacity;
        }
        if (!self.canFitLocked(origin, bytes)) return .rejected_capacity;

        self.entries.ensureUnusedCapacity(self.allocator, 1) catch return .storage_failed;
        self.handle_index.ensureUnusedCapacity(self.allocator, 1) catch return .storage_failed;

        // Evict purely by origin/handle lookup each call (never by a
        // pointer/index retained across mutations): `removeEntryLocked`
        // can delete or rehash the origin's bucket entirely (e.g. when it
        // empties out), which would invalidate any pointer held across it.
        while (self.originBucketLen(origin) >= self.limits.max_entries_per_origin) {
            if (!self.evictOldestUnleasedInOrigin(origin)) return .rejected_capacity;
            evicted.* += 1;
        }
        while (self.entries.count() >= self.limits.max_entries or
            self.total_bytes + bytes > self.limits.max_total_bytes)
        {
            if (!self.evictOldestUnleasedGlobal()) return .rejected_capacity;
            evicted.* += 1;
        }

        // Only now — after every eviction that could possibly touch
        // `origin`'s bucket has already happened — resolve (or create) the
        // bucket we're about to append to and reserve its capacity.
        self.origin_index.ensureUnusedCapacity(self.allocator, 1) catch return .storage_failed;
        var created_new_bucket = false;
        var bucket_ptr = self.origin_index.getPtr(origin);
        if (bucket_ptr == null) {
            self.origin_index.putAssumeCapacityNoClobber(origin, .empty);
            bucket_ptr = self.origin_index.getPtr(origin).?;
            created_new_bucket = true;
        }
        bucket_ptr.?.ensureUnusedCapacity(self.allocator, 1) catch {
            // Do not leave a phantom empty origin behind: it would
            // permanently consume a `max_origins` slot for nothing.
            if (created_new_bucket) _ = self.origin_index.remove(origin);
            return .storage_failed;
        };

        const entry_id = self.next_entry_id;
        self.next_entry_id +%= 1;
        var entry: ServerEntry = .{ .origin = origin, .handle = handle, .usage = usage, .lru_sequence = lru_sequence, .bytes = bytes };
        entry.state.moveFrom(state);
        self.entries.putAssumeCapacity(entry_id, entry);
        self.handle_index.putAssumeCapacity(handle, entry_id);
        bucket_ptr.?.appendAssumeCapacity(entry_id);
        self.total_bytes += bytes;
        if (lru_sequence >= self.next_lru_sequence) self.next_lru_sequence = lru_sequence +% 1;
        return .stored;
    }

    /// Resolves `identity` to owned state plus a lease, without evaluating
    /// any compatibility policy: the caller (the shared #362/#365 path)
    /// evaluates `session.evaluateCompatibility` on the returned state and
    /// then commits or releases the lease. A single-use entry already
    /// leased by a concurrent resolution, or one that would require a
    /// *new* lease while a persistence snapshot is in progress, reports a
    /// miss-shaped outcome rather than a hit (`.miss` / `.busy`
    /// respectively) — never a second hit. The observer is notified only
    /// after the cache mutex has been released, so a re-entrant observer
    /// cannot deadlock.
    pub fn resolveLease(self: *StatefulServerCache, identity: []const u8, now_unix_ms: i64) ResolveLeaseResult {
        if (!isValidStatefulHandleShape(identity)) {
            self.observer.notify(.lookup_miss);
            return .miss;
        }
        var key: [stateful_identity_len]u8 = undefined;
        @memcpy(&key, identity);

        var event: CacheEvent = .lookup_miss;
        const result: ResolveLeaseResult = blk: {
            self.mutex.lock();
            defer self.mutex.unlock();

            const entry_id = self.handle_index.get(key) orelse break :blk .miss;
            const e = self.entries.getPtr(entry_id).?;

            const single_use = e.usage == .single_use;
            if (single_use and e.active_lease_epoch != null) {
                event = .lookup_miss;
                break :blk .miss;
            }
            if (single_use and self.persistence_in_progress) {
                event = .lookup_busy;
                break :blk .busy;
            }

            if (e.state.common.isExpired(now_unix_ms)) {
                self.removeEntryLocked(entry_id);
                event = .lookup_expired;
                break :blk .expired;
            }

            var cloned: session.ServerRecoverableState = .{};
            e.state.cloneInto(self.allocator, &cloned) catch {
                event = .storage_failed;
                break :blk .storage_failed;
            };

            var epoch: u64 = 0;
            if (single_use) {
                epoch = self.next_lease_epoch;
                self.next_lease_epoch +%= 1;
                e.active_lease_epoch = epoch;
            }

            event = .lookup_hit;
            break :blk .{ .hit = .{
                .state = cloned,
                .lease = .{ .cache = self, .entry_id = entry_id, .lease_epoch = epoch, .single_use = single_use },
            } };
        };

        self.observer.notify(event);
        return result;
    }

    /// Consumes a single-use entry after binder success, before any
    /// PSK-selected ServerHello byte is emitted; no-op if `lease_epoch`
    /// does not match the entry's current epoch (already committed,
    /// released and re-leased by someone else, or removed/evicted). For a
    /// reusable entry, refreshes its LRU recency instead of removing it —
    /// recency is updated here (on confirmed, binder-verified use) rather
    /// than at `resolveLease` time, so a session that keeps being
    /// successfully resumed stays protected from eviction.
    fn commitLease(self: *StatefulServerCache, entry_id: u64, lease_epoch: u64, single_use: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const e = self.entries.getPtr(entry_id) orelse return;
        if (single_use) {
            if (e.active_lease_epoch != lease_epoch) return;
            self.removeEntryLocked(entry_id);
        } else {
            e.lru_sequence = self.nextLruSequenceLocked();
        }
    }

    /// Releases a pinned single-use entry (incompatibility, bad binder, or
    /// teardown) so it can be resolved again under a fresh epoch. No-op if
    /// `lease_epoch` is stale (see `commitLease`).
    fn releaseLease(self: *StatefulServerCache, entry_id: u64, lease_epoch: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const e = self.entries.getPtr(entry_id) orelse return;
        if (e.active_lease_epoch != lease_epoch) return;
        e.active_lease_epoch = null;
    }

    pub const PersistenceError = error{ OutOfMemory, CacheBusy };

    /// Deep-clones every non-expired entry for a persistence save,
    /// including its exact `lru_sequence`. Refuses with `error.CacheBusy`
    /// if any single-use entry is currently leased. Sets
    /// `persistence_in_progress` for the duration of the *whole* save
    /// (through `endPersistenceSnapshot`), during which `resolveLease`
    /// refuses to hand out any *new* single-use lease — together these
    /// close the race where a ticket is resolved and committed after being
    /// cloned into a snapshot but before that snapshot reaches durable
    /// storage, which would otherwise let a restart resurrect an
    /// already-consumed ticket.
    pub fn cloneLiveForPersistence(
        self: *StatefulServerCache,
        allocator: std.mem.Allocator,
        now_unix_ms: i64,
    ) PersistenceError!std.ArrayListUnmanaged(PersistedServerEntry) {
        self.mutex.lock();
        if (self.hasOutstandingLeaseLocked()) {
            self.mutex.unlock();
            return error.CacheBusy;
        }
        self.persistence_in_progress = true;

        var out: std.ArrayListUnmanaged(PersistedServerEntry) = .empty;
        var failed = false;
        out.ensureTotalCapacityPrecise(allocator, self.entries.count()) catch {
            failed = true;
        };
        if (!failed) {
            var it = self.entries.valueIterator();
            while (it.next()) |e| {
                if (e.state.common.isExpired(now_unix_ms)) continue;
                var clone: PersistedServerEntry = .{ .handle = e.handle, .usage = e.usage, .lru_sequence = e.lru_sequence };
                e.state.cloneInto(allocator, &clone.state) catch {
                    failed = true;
                    break;
                };
                out.appendAssumeCapacity(clone);
            }
        }
        self.mutex.unlock();

        if (failed) {
            for (out.items) |*p| p.deinit();
            out.deinit(allocator);
            self.endPersistenceSnapshot();
            return error.OutOfMemory;
        }
        return out;
    }

    /// Clears `persistence_in_progress`. Must be called exactly once after
    /// `cloneLiveForPersistence` succeeds, once the snapshot it returned is
    /// either durably saved or abandoned.
    pub fn endPersistenceSnapshot(self: *StatefulServerCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.persistence_in_progress = false;
    }

    /// Whether any single-use entry currently has an outstanding lease.
    /// Exposed so a persistence load can re-check the *live* cache for
    /// outstanding leases immediately before swapping it out, in addition
    /// to `cloneLiveForPersistence`'s own check on the snapshot side.
    pub fn hasOutstandingLease(self: *StatefulServerCache) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.hasOutstandingLeaseLocked();
    }

    fn hasOutstandingLeaseLocked(self: *StatefulServerCache) bool {
        var it = self.entries.valueIterator();
        while (it.next()) |e| {
            if (e.usage == .single_use and e.active_lease_epoch != null) return true;
        }
        return false;
    }

    pub const RestoreError = error{ OutOfMemory, DuplicateHandle };

    /// Restores previously-persisted entries, preserving each entry's
    /// original `lru_sequence`, enforcing current limits, discarding
    /// expired entries, and rejecting any with a malformed handle shape.
    /// Two different states sharing one bearer handle is an unambiguous
    /// sign of a corrupted snapshot (never produced by the live store, which
    /// generates handles unpredictably and checks for collisions): the
    /// *whole* restore is rejected with `error.DuplicateHandle` rather than
    /// silently keeping whichever record happens to be processed first.
    ///
    /// Every item is consumed regardless of outcome. Otherwise fallible and
    /// atomic per call: an allocation failure aborts immediately with
    /// `error.OutOfMemory`. An ordinary capacity rejection for an
    /// individual record is an explicit, documented truncation, not an
    /// error — see `ClientSessionCache.restoreClones`.
    pub fn restoreEntries(self: *StatefulServerCache, items: []PersistedServerEntry, now_unix_ms: i64) RestoreError!void {
        defer for (items) |*item| item.deinit();

        if (hasDuplicateServerHandle(items)) return error.DuplicateHandle;

        for (items) |*item| {
            if (item.state.common.isExpired(now_unix_ms)) continue;
            if (!isValidStatefulHandleShape(&item.handle)) continue;

            const bytes = serverAccountedBytes(&item.state);
            const origin = originDigestFromCommon(&item.state.common);
            var evicted: usize = 0;
            self.mutex.lock();
            const result = self.insertLocked(&item.state, item.handle, origin, item.usage, now_unix_ms, bytes, item.lru_sequence, &evicted);
            self.mutex.unlock();
            if (result == .storage_failed) return error.OutOfMemory;
        }
    }

    fn generateHandleLocked(self: *StatefulServerCache, out: *[stateful_identity_len]u8) HandleError!void {
        var attempt: usize = 0;
        while (attempt < max_handle_generation_attempts) : (attempt += 1) {
            var candidate: [stateful_identity_len]u8 = undefined;
            @memcpy(candidate[0..4], &stateful_magic);
            std.mem.writeInt(u16, candidate[4..6], stateful_version, .big);
            std.mem.writeInt(u16, candidate[6..8], 0, .big);
            self.random.fill(candidate[8..stateful_identity_len]) catch return error.HandleGenerationFailed;
            if (!self.handle_index.contains(candidate)) {
                out.* = candidate;
                return;
            }
        }
        return error.HandleGenerationFailed;
    }

    fn purgeExpiredAllLocked(self: *StatefulServerCache, now_unix_ms: i64, evicted: *usize) void {
        // Allocation-free by construction (repeated single-pass scans)
        // rather than collecting stale ids into a temporary list: an
        // allocation failure here must never silently leave expired
        // entries behind (they could then permanently block capacity).
        while (true) {
            var found: ?u64 = null;
            var it = self.entries.iterator();
            while (it.next()) |kv| {
                if (kv.value_ptr.active_lease_epoch != null) continue;
                if (kv.value_ptr.state.common.isExpired(now_unix_ms)) {
                    found = kv.key_ptr.*;
                    break;
                }
            }
            const id = found orelse break;
            self.removeEntryLocked(id);
            evicted.* += 1;
        }
    }

    fn originBucketLen(self: *StatefulServerCache, origin: OriginDigest) usize {
        return if (self.origin_index.get(origin)) |b| b.items.len else 0;
    }

    /// Removes and wipes a stored entry by its stable `entry_id`,
    /// unindexing its handle and updating (and, if now empty, removing) its
    /// origin bucket.
    fn removeEntryLocked(self: *StatefulServerCache, entry_id: u64) void {
        const kv = self.entries.fetchRemove(entry_id) orelse return;
        var entry = kv.value;
        self.total_bytes -= entry.bytes;
        _ = self.handle_index.remove(entry.handle);
        if (self.origin_index.getPtr(entry.origin)) |bucket| {
            for (bucket.items, 0..) |id, i| {
                if (id == entry_id) {
                    _ = bucket.swapRemove(i);
                    break;
                }
            }
            if (bucket.items.len == 0) {
                if (self.origin_index.fetchRemove(entry.origin)) |removed_bucket| {
                    var b = removed_bucket.value;
                    b.deinit(self.allocator);
                }
            }
        }
        entry.state.deinit();
        secrets.secureZero(&entry.handle);
    }

    /// Finds and evicts the globally-oldest (by `lru_sequence`) unleased
    /// entry within `origin`'s bucket. Re-fetches the bucket internally on
    /// every call rather than accepting a caller-held pointer: eviction can
    /// delete/rehash the bucket, so no pointer to it may survive across a
    /// mutation.
    fn evictOldestUnleasedInOrigin(self: *StatefulServerCache, origin: OriginDigest) bool {
        const bucket = self.origin_index.getPtr(origin) orelse return false;
        var best_id: ?u64 = null;
        var best_seq: u64 = undefined;
        for (bucket.items) |id| {
            const e = self.entries.getPtr(id) orelse continue;
            if (e.active_lease_epoch != null) continue;
            if (best_id == null or e.lru_sequence < best_seq) {
                best_id = id;
                best_seq = e.lru_sequence;
            }
        }
        const id = best_id orelse return false;
        self.removeEntryLocked(id);
        return true;
    }

    fn evictOldestUnleasedGlobal(self: *StatefulServerCache) bool {
        var best_id: ?u64 = null;
        var best_seq: u64 = undefined;
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr;
            if (e.active_lease_epoch != null) continue;
            if (best_id == null or e.lru_sequence < best_seq) {
                best_id = kv.key_ptr.*;
                best_seq = e.lru_sequence;
            }
        }
        const id = best_id orelse return false;
        self.removeEntryLocked(id);
        return true;
    }

    fn nextLruSequenceLocked(self: *StatefulServerCache) u64 {
        const s = self.next_lru_sequence;
        self.next_lru_sequence +%= 1;
        return s;
    }
};

fn hasDuplicateServerHandle(items: []const PersistedServerEntry) bool {
    var i: usize = 0;
    while (i < items.len) : (i += 1) {
        var j = i + 1;
        while (j < items.len) : (j += 1) {
            if (std.mem.eql(u8, &items[i].handle, &items[j].handle)) return true;
        }
    }
    return false;
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

const testing = std.testing;

fn testCommonParams(psk: []const u8, sni: []const u8, alpn: []const u8, issued_at_unix_ms: i64, lifetime_seconds: u32) session.ResumableSessionCommon.InitParams {
    return .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = psk,
        .server_name = sni,
        .application_protocol = alpn,
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf-der"),
        .issued_at_unix_ms = issued_at_unix_ms,
        .lifetime_seconds = lifetime_seconds,
    };
}

fn testClient(allocator: std.mem.Allocator, ticket: []const u8, sni: []const u8, issued_at_unix_ms: i64, lifetime_seconds: u32, received_at_unix_ms: i64) !session.ClientTicketState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, testCommonParams(&([_]u8{0xab} ** 32), sni, "h3", issued_at_unix_ms, lifetime_seconds));
    var state: session.ClientTicketState = .{};
    try state.init(allocator, session.Limits.default, &common, .{
        .ticket = ticket,
        .ticket_age_add = 1,
        .ticket_nonce = "n",
        .received_at_unix_ms = received_at_unix_ms,
    });
    return state;
}

fn testServerState(allocator: std.mem.Allocator, sni: []const u8, issued_at_unix_ms: i64, lifetime_seconds: u32) !session.ServerRecoverableState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, testCommonParams(&([_]u8{0xcd} ** 32), sni, "h3", issued_at_unix_ms, lifetime_seconds));
    var state: session.ServerRecoverableState = .{};
    state.init(&common, 42);
    return state;
}

fn testCandidate(sni: []const u8) session.CandidateContext {
    return .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .server_name = sni,
        .application_protocol = "h3",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf-der"),
    };
}

fn fixedFill(bytes: []const u8) RandomSource {
    return .{ .ctx = @ptrCast(@constCast(bytes.ptr)), .fillFn = struct {
        fn fill(ctx: *anyopaque, buf: []u8) error{EntropyFailure}!void {
            const src: [*]const u8 = @ptrCast(@alignCast(ctx));
            @memcpy(buf, src[0..buf.len]);
        }
    }.fill };
}

test "origin digest ignores ticket identity but distinguishes SNI/ALPN/auth" {
    var a = try testClient(testing.allocator, "ticket-a", "example.test", 0, 100, 0);
    defer a.deinit();
    var b = try testClient(testing.allocator, "ticket-b", "example.test", 0, 100, 0);
    defer b.deinit();
    var c = try testClient(testing.allocator, "ticket-a", "other.test", 0, 100, 0);
    defer c.deinit();

    try testing.expectEqualSlices(u8, &originDigestFromCommon(&a.common), &originDigestFromCommon(&b.common));
    try testing.expect(!std.mem.eql(u8, &originDigestFromCommon(&a.common), &originDigestFromCommon(&c.common)));

    const candidate = testCandidate("EXAMPLE.test");
    try testing.expectEqualSlices(u8, &originDigestFromCommon(&a.common), &originDigestFromCandidate(candidate));
}

test "client cache stores and returns a matching offer" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var ticket = try testClient(testing.allocator, "ticket-1", "example.test", 0, 100, 0);
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&ticket, 0, .reusable));
    ticket.deinit();

    var result = cache.lookupOffers(testCandidate("example.test"), 10);
    defer result.deinit();
    const offers = result.hit;
    try testing.expectEqual(@as(usize, 1), offers.len);
    try testing.expectEqualStrings("ticket-1", offers.constSlice()[0].ticket.slice());
}

test "client lookup never aliases cache storage" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var ticket = try testClient(testing.allocator, "ticket-1", "example.test", 0, 100, 0);
    _ = cache.storeClone(&ticket, 0, .reusable);
    ticket.deinit();

    var result = cache.lookupOffers(testCandidate("example.test"), 10);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), cache.count());
    // Mutate the returned clone; the stored copy must be unaffected.
    result.hit.slice()[0].ticket_age_add = 999;

    var result2 = cache.lookupOffers(testCandidate("example.test"), 10);
    defer result2.deinit();
    try testing.expectEqual(@as(u32, 1), result2.hit.constSlice()[0].ticket_age_add);
}

test "client lookup rechecks exact expiry and reports .expired" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var ticket = try testClient(testing.allocator, "ticket-1", "example.test", 0, 100, 0);
    _ = cache.storeClone(&ticket, 0, .reusable);
    ticket.deinit();

    // Exact lifetime boundary: age_ms == lifetime_ms is expired.
    var at_boundary = cache.lookupOffers(testCandidate("example.test"), 100_000);
    defer at_boundary.deinit();
    try testing.expectEqual(ClientLookupResult.expired, at_boundary);
    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "client lookup reports .incompatible for SNI/ALPN/auth-binding mismatches without evicting" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var ticket = try testClient(testing.allocator, "ticket-1", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&ticket, 0, .reusable);
    ticket.deinit();

    var mismatched_sni = cache.lookupOffers(testCandidate("other.test"), 10);
    defer mismatched_sni.deinit();
    try testing.expectEqual(ClientLookupResult.miss, mismatched_sni); // different origin digest entirely: a plain miss

    var candidate = testCandidate("example.test");
    candidate.application_protocol = "h2";
    var mismatched_alpn = cache.lookupOffers(candidate, 10);
    defer mismatched_alpn.deinit();
    try testing.expectEqual(ClientLookupResult.miss, mismatched_alpn);

    // The entry itself is still present (a lookup miss must not evict a
    // still-valid, merely-incompatible entry).
    try testing.expectEqual(@as(usize, 1), cache.count());
}

test "client cache replaces an exact duplicate ticket identity and wipes the old copy" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var first = try testClient(testing.allocator, "dup-ticket", "example.test", 0, 100, 0);
    _ = cache.storeClone(&first, 0, .reusable);
    first.deinit();

    var second = try testClient(testing.allocator, "dup-ticket", "example.test", 5, 200, 5);
    try testing.expectEqual(StoreResult.replaced, cache.storeClone(&second, 5, .single_use));
    second.deinit();

    try testing.expectEqual(@as(usize, 1), cache.count());
    var result = cache.lookupOffers(testCandidate("example.test"), 5);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.hit.len);
}

test "duplicate replacement preflights byte limits and leaves the original entry untouched on rejection" {
    var first = try testClient(testing.allocator, "dup", "example.test", 0, 1000, 0);
    const first_bytes = clientAccountedBytes(&first);

    var limits = Limits.client_default;
    limits.max_entry_bytes = first_bytes + 4;
    limits.max_total_bytes = first_bytes + 4;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();

    _ = cache.storeClone(&first, 0, .reusable);
    first.deinit();
    try testing.expectEqual(@as(usize, 1), cache.count());
    const total_before = cache.totalBytes();

    // Same identity, but with a much larger ticket nonce so the replacement
    // would blow both the per-entry and total byte limits.
    var oversized_nonce = [_]u8{0xEE} ** 200;
    var common: session.ResumableSessionCommon = .{};
    try common.init(testing.allocator, session.Limits.default, testCommonParams(&([_]u8{0xab} ** 32), "example.test", "h3", 0, 1000));
    var replacement: session.ClientTicketState = .{};
    try replacement.init(testing.allocator, session.Limits.default, &common, .{
        .ticket = "dup",
        .ticket_age_add = 1,
        .ticket_nonce = &oversized_nonce,
        .received_at_unix_ms = 0,
    });
    defer replacement.deinit();

    try testing.expectEqual(StoreResult.rejected_capacity, cache.storeClone(&replacement, 1, .reusable));
    try testing.expectEqual(@as(usize, 1), cache.count());
    try testing.expectEqual(total_before, cache.totalBytes());

    var result = cache.lookupOffers(testCandidate("example.test"), 1);
    defer result.deinit();
    try testing.expectEqual(@as(u32, 1), result.hit.constSlice()[0].ticket_age_add);
}

test "expired entries in another origin never permanently block max_origins, and cleanup() removes them" {
    var limits = Limits.client_default;
    limits.max_origins = 1;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();

    var a = try testClient(testing.allocator, "a", "a.test", 0, 10, 0);
    _ = cache.storeClone(&a, 0, .reusable);
    a.deinit();
    try testing.expectEqual(@as(usize, 1), cache.count());

    // `a.test`'s only entry is now expired, but nothing has looked it up
    // yet. A fresh origin must still be storable: the store path's own
    // global expiry purge must not need a prior lookup to clear it out.
    var b = try testClient(testing.allocator, "b", "b.test", 0, 1000, 0);
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&b, 1_000_000, .reusable));
    b.deinit();
    try testing.expectEqual(@as(usize, 1), cache.count());

    var c = try testClient(testing.allocator, "c", "c.test", 0, 10, 0);
    _ = cache.storeClone(&c, 1_000_000, .reusable);
    c.deinit();
    // `cleanup` also works as an explicit maintenance entry point.
    const removed = cache.cleanup(2_000_000);
    try testing.expect(removed >= 1);
}

test "client cache enforces exact per-origin capacity and evicts oldest first (deterministic LRU)" {
    var limits = Limits.client_default;
    limits.max_entries_per_origin = 2;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();

    var t1 = try testClient(testing.allocator, "t1", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();
    var t2 = try testClient(testing.allocator, "t2", "example.test", 0, 1000, 1);
    _ = cache.storeClone(&t2, 1, .reusable);
    t2.deinit();
    try testing.expectEqual(@as(usize, 2), cache.count());

    // One-over capacity: storing a third for the same origin evicts t1 (oldest).
    var t3 = try testClient(testing.allocator, "t3", "example.test", 0, 1000, 2);
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t3, 2, .reusable));
    t3.deinit();
    try testing.expectEqual(@as(usize, 2), cache.count());

    var result = cache.lookupOffers(testCandidate("example.test"), 3);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 2), result.hit.len);
    // Deterministic order: newest insertion sequence first.
    try testing.expectEqualStrings("t3", result.hit.constSlice()[0].ticket.slice());
    try testing.expectEqualStrings("t2", result.hit.constSlice()[1].ticket.slice());
}

test "a lookup touch protects an entry from the next LRU eviction even though it isn't the newest insertion" {
    var limits = Limits.client_default;
    limits.max_entries_per_origin = 2;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();

    var t1 = try testClient(testing.allocator, "t1", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();
    var t2 = try testClient(testing.allocator, "t2", "example.test", 0, 1000, 1);
    _ = cache.storeClone(&t2, 1, .reusable);
    t2.deinit();

    // Touch t1 via a lookup so it becomes the LRU-freshest entry even
    // though t2 has the newer insertion sequence.
    var touch = cache.lookupOffers(testCandidate("example.test"), 2);
    touch.deinit();

    var t3 = try testClient(testing.allocator, "t3", "example.test", 0, 1000, 2);
    _ = cache.storeClone(&t3, 2, .reusable);
    t3.deinit();

    // t2 (not touched since insertion) is the LRU victim, not t1.
    try testing.expectEqual(@as(usize, 2), cache.count());
    var result = cache.lookupOffers(testCandidate("example.test"), 3);
    defer result.deinit();
    var saw_t1 = false;
    for (result.hit.constSlice()) |*t| {
        if (std.mem.eql(u8, t.ticket.slice(), "t1")) saw_t1 = true;
        try testing.expect(!std.mem.eql(u8, t.ticket.slice(), "t2"));
    }
    try testing.expect(saw_t1);
}

test "client lookup allocation failure returns .storage_failed rather than a partial offer set" {
    var backing: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var cache = try ClientSessionCache.init(fba.allocator(), Limits.client_default);
    defer cache.deinit();

    var t1 = try testClient(testing.allocator, "t1", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();
    var t2 = try testClient(testing.allocator, "t2", "example.test", 0, 1000, 1);
    _ = cache.storeClone(&t2, 1, .reusable);
    t2.deinit();

    var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = 0 });
    var failing_cache = ClientSessionCache{ .allocator = failing.allocator(), .limits = Limits.client_default, .entries = cache.entries };
    var result = failing_cache.lookupOffers(testCandidate("example.test"), 2);
    defer result.deinit();
    try testing.expectEqual(ClientLookupResult.storage_failed, result);
    // The live entries must be untouched by the failed clone attempt.
    try testing.expectEqual(@as(usize, 2), failing_cache.entries.items.len);
    failing_cache.entries = .empty; // avoid double-deinit; `cache.deinit()` above owns these.
}

test "client cache enforces total entry and origin cardinality limits" {
    var limits = Limits.client_default;
    limits.max_entries = 2;
    limits.max_entries_per_origin = 2;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();

    var t1 = try testClient(testing.allocator, "t1", "a.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();
    var t2 = try testClient(testing.allocator, "t2", "b.test", 0, 1000, 1);
    _ = cache.storeClone(&t2, 1, .reusable);
    t2.deinit();
    try testing.expectEqual(@as(usize, 2), cache.count());

    // Global entry limit evicts the oldest across origins.
    var t3 = try testClient(testing.allocator, "t3", "c.test", 0, 1000, 2);
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t3, 2, .reusable));
    t3.deinit();
    try testing.expectEqual(@as(usize, 2), cache.count());

    var origin_limits = Limits.client_default;
    origin_limits.max_origins = 1;
    var origin_cache = try ClientSessionCache.init(testing.allocator, origin_limits);
    defer origin_cache.deinit();
    var v1 = try testClient(testing.allocator, "v1", "a.test", 0, 1000, 0);
    try testing.expectEqual(StoreResult.stored, origin_cache.storeClone(&v1, 0, .reusable));
    v1.deinit();
    var v2 = try testClient(testing.allocator, "v2", "b.test", 0, 1000, 1);
    try testing.expectEqual(StoreResult.rejected_capacity, origin_cache.storeClone(&v2, 1, .reusable));
    v2.deinit();
}

test "client cache enforces per-entry and total byte limits" {
    var limits = Limits.client_default;
    limits.max_entry_bytes = 16;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();
    var oversized = try testClient(testing.allocator, "a-ticket-well-over-sixteen-bytes", "example.test", 0, 100, 0);
    defer oversized.deinit();
    try testing.expectEqual(StoreResult.rejected_capacity, cache.storeClone(&oversized, 0, .reusable));

    var reference = try testClient(testing.allocator, "t", "a.test", 0, 100, 0);
    const reference_bytes = clientAccountedBytes(&reference);
    reference.deinit();

    var byte_limits = Limits.client_default;
    byte_limits.max_entries = 100;
    byte_limits.max_entries_per_origin = 100;
    byte_limits.max_total_bytes = reference_bytes + 10;
    byte_limits.max_entry_bytes = reference_bytes + 10;
    var byte_cache = try ClientSessionCache.init(testing.allocator, byte_limits);
    defer byte_cache.deinit();

    var b1 = try testClient(testing.allocator, "t1", "a.test", 0, 1000, 0);
    _ = byte_cache.storeClone(&b1, 0, .reusable);
    b1.deinit();
    try testing.expectEqual(@as(usize, 1), byte_cache.count());

    var b2 = try testClient(testing.allocator, "t2", "b.test", 0, 1000, 1);
    _ = byte_cache.storeClone(&b2, 1, .reusable);
    b2.deinit();
    // Total-byte pressure evicts b1 to make room for b2.
    try testing.expectEqual(@as(usize, 1), byte_cache.count());
    var result = byte_cache.lookupOffers(testCandidate("b.test"), 2);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.hit.len);
}

test "client cache single-use consumption removes only the matching entry" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "single", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .single_use);
    t1.deinit();
    var t2 = try testClient(testing.allocator, "reusable", "example.test", 0, 1000, 1);
    _ = cache.storeClone(&t2, 1, .reusable);
    t2.deinit();

    const origin = originDigestFromCandidate(testCandidate("example.test"));
    try testing.expect(cache.consumeSingleUse(origin, "single"));
    try testing.expectEqual(@as(usize, 1), cache.count());
    var result = cache.lookupOffers(testCandidate("example.test"), 2);
    defer result.deinit();
    try testing.expectEqualStrings("reusable", result.hit.constSlice()[0].ticket.slice());
}

test "consumeSingleUse refuses to consume while a persistence snapshot is in progress" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "single", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .single_use);
    t1.deinit();

    cache.persistence_in_progress = true;
    const origin = originDigestFromCandidate(testCandidate("example.test"));
    try testing.expect(!cache.consumeSingleUse(origin, "single"));
    try testing.expectEqual(@as(usize, 1), cache.count());
    cache.persistence_in_progress = false;
    try testing.expect(cache.consumeSingleUse(origin, "single"));
}

test "client cache allocation failure during storeClone leaves the cache unchanged" {
    var backing: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var cache = try ClientSessionCache.init(fba.allocator(), Limits.client_default);
    defer cache.deinit();

    var t1 = try testClient(testing.allocator, "t1", "example.test", 0, 1000, 0);
    defer t1.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t1, 0, .reusable));

    var fail_index: usize = 0;
    while (fail_index < 6) : (fail_index += 1) {
        var t2 = try testClient(testing.allocator, "t2-would-be-cloned", "other.test", 0, 1000, 0);
        defer t2.deinit();
        var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        var failing_cache = ClientSessionCache{ .allocator = failing.allocator(), .limits = Limits.client_default };
        defer failing_cache.entries.deinit(fba.allocator());
        const result = failing_cache.storeClone(&t2, 0, .reusable);
        if (result == .stored) break;
        try testing.expectEqual(@as(usize, 0), failing_cache.entries.items.len);
    }
}

test "client cache zeroizes ticket bytes on eviction and deinit" {
    var backing: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var cache = try ClientSessionCache.init(fba.allocator(), Limits.client_default);

    var t1 = try testClient(testing.allocator, "zeroize-me-please", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();

    cache.deinit();
    try testing.expect(std.mem.indexOf(u8, &backing, "zeroize-me-please") == null);
}

test "client cache sequence counters wrap safely near u64 max without corrupting order" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    cache.next_insertion_sequence = std.math.maxInt(u64);
    cache.next_lru_sequence = std.math.maxInt(u64);

    var t1 = try testClient(testing.allocator, "t1", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();
    var t2 = try testClient(testing.allocator, "t2", "example.test", 0, 1000, 1);
    _ = cache.storeClone(&t2, 1, .reusable);
    t2.deinit();

    var result = cache.lookupOffers(testCandidate("example.test"), 2);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 2), result.hit.len);
}

test "restoreClones preserves persisted insertion/LRU order rather than reassigning by array position" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "t1", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();
    var t2 = try testClient(testing.allocator, "t2", "example.test", 0, 1000, 1);
    _ = cache.storeClone(&t2, 1, .reusable);
    t2.deinit();
    var t3 = try testClient(testing.allocator, "t3", "example.test", 0, 1000, 2);
    _ = cache.storeClone(&t3, 2, .reusable);
    t3.deinit();

    // Touch t1 so its LRU recency (but not its insertion order) becomes
    // newest.
    var touch = cache.lookupOffers(testCandidate("example.test"), 3);
    touch.deinit();

    var snapshot = try cache.cloneLiveForPersistence(testing.allocator, 4);
    defer {
        for (snapshot.items) |*p| p.deinit();
        snapshot.deinit(testing.allocator);
    }

    var restored = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer restored.deinit();
    try restored.restoreClones(snapshot.items, 4);

    var before = cache.lookupOffers(testCandidate("example.test"), 4);
    defer before.deinit();
    var after = restored.lookupOffers(testCandidate("example.test"), 4);
    defer after.deinit();

    try testing.expectEqual(before.hit.len, after.hit.len);
    for (before.hit.constSlice(), after.hit.constSlice()) |*b, *a| {
        try testing.expectEqualStrings(b.ticket.slice(), a.ticket.slice());
    }
}

test "restoreClones deduplicates repeated (origin, ticket) records, keeping the newest" {
    const older = try testClient(testing.allocator, "dup", "example.test", 0, 1000, 0);
    const newer = try testClient(testing.allocator, "dup", "example.test", 0, 1000, 0);
    var items = [_]PersistedClientEntry{
        .{ .ticket = older, .usage = .reusable, .insertion_sequence = 3, .lru_sequence = 3 },
        .{ .ticket = newer, .usage = .single_use, .insertion_sequence = 9, .lru_sequence = 9 },
    };

    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    try cache.restoreClones(&items, 1);
    try testing.expectEqual(@as(usize, 1), cache.count());

    var result = cache.lookupOffers(testCandidate("example.test"), 1);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.hit.len);
    try testing.expectEqualStrings("dup", result.hit.constSlice()[0].ticket.slice());

    // The surviving record is the newer one (single_use): consuming it via
    // the single-use path must succeed.
    const origin = originDigestFromCandidate(testCandidate("example.test"));
    try testing.expect(cache.consumeSingleUse(origin, "dup"));
}

test "restoreClones aborts atomically on allocation failure without touching the live cache" {
    var backing: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);

    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "already-here", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();

    var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = 0 });
    var restore_target = ClientSessionCache{ .allocator = failing.allocator(), .limits = Limits.client_default };
    defer restore_target.entries.deinit(fba.allocator());

    var persisted: PersistedClientEntry = .{};
    persisted.ticket = try testClient(testing.allocator, "to-restore", "example.test", 0, 1000, 0);
    var items = [_]PersistedClientEntry{persisted};
    try testing.expectError(error.OutOfMemory, restore_target.restoreClones(&items, 1));
    try testing.expectEqual(@as(usize, 0), restore_target.entries.items.len);

    // The live `cache` (unrelated to `restore_target`) must be untouched.
    try testing.expectEqual(@as(usize, 1), cache.count());
}

test "expired entries are discarded on restore rather than reinserted" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var expired: PersistedClientEntry = .{ .usage = .reusable };
    expired.ticket = try testClient(testing.allocator, "already-expired", "example.test", 0, 10, 0);
    var items = [_]PersistedClientEntry{expired};
    try cache.restoreClones(&items, 1_000_000);
    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "Limits.validate rejects zero and over-ceiling values" {
    var bad = Limits.client_default;
    bad.max_entries = 0;
    try testing.expectError(error.InvalidLimits, bad.validate());

    bad = Limits.client_default;
    bad.max_entries = hard_max_entries + 1;
    try testing.expectError(error.InvalidLimits, bad.validate());

    bad = Limits.client_default;
    bad.max_entry_bytes = bad.max_total_bytes + 1;
    try testing.expectError(error.InvalidLimits, bad.validate());

    try Limits.client_default.validate();
    try Limits.stateful_server_default.validate();
}

test "observer receives store, eviction, and lookup events without holding the mutex" {
    const Recorder = struct {
        events: std.ArrayListUnmanaged(CacheEvent) = .empty,

        fn onEvent(ctx: *anyopaque, event: CacheEvent) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.events.append(testing.allocator, event) catch {};
        }
    };
    var recorder: Recorder = .{};
    defer recorder.events.deinit(testing.allocator);

    var limits = Limits.client_default;
    limits.max_entries_per_origin = 1;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();
    cache.setObserver(.{ .ctx = @ptrCast(&recorder), .onEventFn = Recorder.onEvent });

    var t1 = try testClient(testing.allocator, "t1", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();
    var t2 = try testClient(testing.allocator, "t2", "example.test", 0, 1000, 1);
    _ = cache.storeClone(&t2, 1, .reusable);
    t2.deinit();

    try testing.expect(std.mem.indexOfScalar(CacheEvent, recorder.events.items, .stored) != null);
    try testing.expect(std.mem.indexOfScalar(CacheEvent, recorder.events.items, .evicted) != null);

    var lookup_result = cache.lookupOffers(testCandidate("example.test"), 2);
    defer lookup_result.deinit();
    try testing.expect(std.mem.indexOfScalar(CacheEvent, recorder.events.items, .lookup_hit) != null);
}

test "stateful server cache issues distinct TDSH handles and resolves a reusable hit" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();

    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&state, 0, .reusable, &handle));
    // Ownership moved: state is now zero-valued.
    try testing.expectEqual(@as(i64, 0), state.common.issued_at_unix_ms);

    try testing.expect(std.mem.eql(u8, handle[0..4], "TDSH"));

    var result = cache.resolveLease(&handle, 10);
    defer result.deinit();
    switch (result) {
        .hit => |*h| {
            try expectEligible(&h.state, testCandidate("example.test"), 10);
            try testing.expect(!h.lease.single_use);
            h.lease.commit();
        },
        else => try testing.expect(false),
    }
    // Reusable: resolving again must still hit.
    var result2 = cache.resolveLease(&handle, 10);
    defer result2.deinit();
    try testing.expect(result2 == .hit);
}

test "stateful server commit refreshes LRU recency for a reusable entry" {
    var limits = Limits.stateful_server_default;
    limits.max_entries = 2;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var s1 = try testServerState(testing.allocator, "a.test", 0, 1000);
    var h1: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .reusable, &h1);
    var s2 = try testServerState(testing.allocator, "b.test", 0, 1000);
    var h2: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s2, 1, .reusable, &h2);

    // Resolve+commit the older entry (h1) so its recency refreshes.
    var result = cache.resolveLease(&h1, 2);
    switch (result) {
        .hit => |*h| h.lease.commit(),
        else => try testing.expect(false),
    }
    result.deinit();

    // Insert a third entry under a capacity of 2: without the commit-time
    // recency refresh, h1 (inserted first) would be evicted; with it, h2
    // (never touched since insertion) is the true LRU victim instead.
    var s3 = try testServerState(testing.allocator, "c.test", 0, 1000);
    var h3: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s3, 3, .reusable, &h3);

    var still_h1 = cache.resolveLease(&h1, 4);
    defer still_h1.deinit();
    try testing.expect(still_h1 == .hit);
    const gone_h2 = cache.resolveLease(&h2, 4);
    try testing.expect(gone_h2 == .miss);
}

test "stateful server single-use entry is pinned during resolution and consumed on commit" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .single_use, &handle);

    var result = cache.resolveLease(&handle, 10);
    // Concurrent resolution while pinned must miss, not double-hit.
    const concurrent = cache.resolveLease(&handle, 10);
    try testing.expect(concurrent == .miss);

    switch (result) {
        .hit => |*h| h.lease.commit(),
        else => try testing.expect(false),
    }
    result.deinit();

    var after_commit = cache.resolveLease(&handle, 10);
    defer after_commit.deinit();
    try testing.expect(after_commit == .miss);
    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "stateful server single-use release restores resolvability without consuming" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .single_use, &handle);

    var result = cache.resolveLease(&handle, 10);
    switch (result) {
        .hit => |*h| h.lease.release(),
        else => try testing.expect(false),
    }
    result.deinit();

    var again = cache.resolveLease(&handle, 10);
    defer again.deinit();
    try testing.expect(again == .hit);
}

test "a stale lease token cannot commit or release a later, unrelated resolution of the same entry" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .single_use, &handle);

    // A resolves, then releases.
    var a = cache.resolveLease(&handle, 10);
    var a_lease = a.hit.lease;
    a_lease.release();
    a.hit.state.deinit();

    // B resolves the same (still-live) entry under a fresh epoch.
    var b = cache.resolveLease(&handle, 10);
    defer b.deinit();
    try testing.expect(b == .hit);

    // A's stale token must not be able to commit B's active lease...
    a_lease.commit();
    try testing.expectEqual(@as(usize, 1), cache.count());

    // ...nor release it back to resolvable out from under B.
    a_lease.release();
    const concurrent_after_stale_release = cache.resolveLease(&handle, 10);
    try testing.expect(concurrent_after_stale_release == .miss);

    b.hit.lease.commit();
}

test "double-commit, double-release, and an abandoned result's deinit are all safe no-ops" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .single_use, &handle);

    var result = cache.resolveLease(&handle, 10);
    switch (result) {
        .hit => |*h| {
            h.lease.commit();
            h.lease.commit(); // double-commit: no-op, does not touch a reinserted entry
            h.lease.release(); // already inactive: no-op
        },
        else => try testing.expect(false),
    }
    result.deinit(); // abandoned-result deinit after manual commit: also a no-op
    try testing.expectEqual(@as(usize, 0), cache.count());

    // A lease whose result is simply dropped without commit/release must
    // still release automatically via `deinit`, leaving the entry
    // resolvable again.
    var state2 = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle2: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state2, 0, .single_use, &handle2);
    var abandoned = cache.resolveLease(&handle2, 10);
    abandoned.deinit();

    var again = cache.resolveLease(&handle2, 10);
    defer again.deinit();
    try testing.expect(again == .hit);
}

test "stateful server rejects unknown, malformed, and expired identities without consuming" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .reusable, &handle);

    const too_short = cache.resolveLease("short", 10);
    try testing.expect(too_short == .miss);

    var wrong_magic = handle;
    wrong_magic[0] = 'X';
    const unknown = cache.resolveLease(&wrong_magic, 10);
    try testing.expect(unknown == .miss);

    var nonzero_reserved = handle;
    std.mem.writeInt(u16, nonzero_reserved[6..8], 1, .big);
    const bad_reserved = cache.resolveLease(&nonzero_reserved, 10);
    try testing.expect(bad_reserved == .miss);

    const expired = cache.resolveLease(&handle, 1_000_001);
    try testing.expect(expired == .expired);
    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "resolveLease refuses a new single-use lease while a persistence snapshot is in progress" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .single_use, &handle);

    cache.persistence_in_progress = true;
    const busy = cache.resolveLease(&handle, 1);
    try testing.expect(busy == .busy);
    try testing.expectEqual(@as(usize, 1), cache.count());

    cache.persistence_in_progress = false;
    var hit = cache.resolveLease(&handle, 1);
    defer hit.deinit();
    try testing.expect(hit == .hit);
}

test "stateful server bounded handle-generation collisions return a typed failure" {
    const fixed = [_]u8{0xAA} ** 32;
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, fixedFill(&fixed));
    defer cache.deinit();

    var first = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle1: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&first, 0, .reusable, &handle1));

    var second = try testServerState(testing.allocator, "other.test", 0, 1000);
    defer second.deinit();
    var handle2: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.rejected_handle_generation_failed, cache.insertMove(&second, 0, .reusable, &handle2));
    // Rejected: the caller's state must be untouched.
    try testing.expectEqualStrings("other.test", second.common.server_name.?.slice());
}

test "expired server entries in other origins never permanently block max_origins, and cleanup() removes them" {
    var limits = Limits.stateful_server_default;
    limits.max_origins = 1;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    // Store a server entry for a.test with a very short lifetime (10 ms).
    var s1 = try testServerState(testing.allocator, "a.test", 0, 10);
    var h1: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .reusable, &h1);
    try testing.expectEqual(@as(usize, 1), cache.count());

    // `a.test`'s only entry is now expired, but nothing has looked it up
    // yet. A fresh origin must still be storable: `insertLocked`'s own
    // global expiry purge must not need a prior lookup to clear it out.
    var s2 = try testServerState(testing.allocator, "b.test", 0, 1000);
    var h2: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s2, 1_000_000, .reusable, &h2));
    try testing.expectEqual(@as(usize, 1), cache.count());

    // `cleanup` works as an explicit periodic maintenance entry point: it
    // skips actively leased single-use entries and returns the evicted count.
    var s3 = try testServerState(testing.allocator, "c.test", 0, 10);
    var h3: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s3, 1_000_000, .reusable, &h3);
    const removed = cache.cleanup(2_000_000);
    try testing.expectEqual(@as(usize, 1), removed);
}

test "stateful server enforces per-origin and global capacity with deterministic eviction and consistent indexes" {
    var limits = Limits.stateful_server_default;
    limits.max_entries_per_origin = 2;
    limits.max_entries = 3;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var h: [3][stateful_identity_len]u8 = undefined;
    var s1 = try testServerState(testing.allocator, "a.test", 0, 1000);
    _ = cache.insertMove(&s1, 0, .reusable, &h[0]);
    var s2 = try testServerState(testing.allocator, "a.test", 0, 1000);
    _ = cache.insertMove(&s2, 1, .reusable, &h[1]);
    try testing.expectEqual(@as(usize, 2), cache.count());

    // Per-origin cap of 2: a third for the same origin evicts the oldest (s1).
    var s3 = try testServerState(testing.allocator, "a.test", 0, 1000);
    _ = cache.insertMove(&s3, 2, .reusable, &h[2]);
    try testing.expectEqual(@as(usize, 2), cache.count());
    const miss = cache.resolveLease(&h[0], 3);
    try testing.expect(miss == .miss);
    var hit = cache.resolveLease(&h[2], 3);
    defer hit.deinit();
    try testing.expect(hit == .hit);

    // Sanity check the indexes stay consistent after eviction: the handle
    // index must not still contain the evicted handle.
    try testing.expect(!cache.handle_index.contains(h[0]));
}

test "per-origin eviction at capacity 1 does not leave a dangling bucket pointer (regression)" {
    var limits = Limits.stateful_server_default;
    limits.max_entries_per_origin = 1;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var s1 = try testServerState(testing.allocator, "a.test", 0, 1000);
    var h1: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .reusable, &h1);

    // Inserting a second entry for the same origin evicts the only bucket
    // member, which removes and deinitializes the (now-empty) bucket from
    // `origin_index` mid-insert. The insert must still complete correctly
    // with all indexes consistent rather than using a stale bucket pointer.
    var s2 = try testServerState(testing.allocator, "a.test", 0, 1000);
    var h2: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s2, 1, .reusable, &h2));
    try testing.expectEqual(@as(usize, 1), cache.count());
    try testing.expect(!cache.handle_index.contains(h1));
    try testing.expect(cache.handle_index.contains(h2));

    var hit = cache.resolveLease(&h2, 2);
    defer hit.deinit();
    try testing.expect(hit == .hit);
}

test "stateful server leased single-use entries are never eviction candidates" {
    var limits = Limits.stateful_server_default;
    limits.max_entries = 1;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var s1 = try testServerState(testing.allocator, "a.test", 0, 1000);
    var h1: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .single_use, &h1);

    var leased = cache.resolveLease(&h1, 1);
    // Keep `leased` pinned; do not commit/release yet.

    var s2 = try testServerState(testing.allocator, "b.test", 0, 1000);
    defer s2.deinit();
    var h2: [stateful_identity_len]u8 = undefined;
    // No unleased entry to evict, and capacity is exactly 1: rejected
    // *without* first evicting anything (canFitLocked's preflight).
    try testing.expectEqual(StoreResult.rejected_capacity, cache.insertMove(&s2, 1, .reusable, &h2));
    try testing.expectEqual(@as(usize, 1), cache.count());

    switch (leased) {
        .hit => |*h| h.lease.release(),
        else => try testing.expect(false),
    }
    leased.deinit();
}

test "stateful server allocation failure during insertMove leaves state and cache unchanged" {
    var backing: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);

    var fail_index: usize = 0;
    while (fail_index < 4) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        var cache = StatefulServerCache{ .allocator = failing.allocator(), .limits = Limits.stateful_server_default, .random = system_random_source };
        defer cache.deinit();

        var state = try testServerState(testing.allocator, "example.test", 0, 1000);
        defer state.deinit();
        var handle: [stateful_identity_len]u8 = undefined;
        const result = cache.insertMove(&state, 0, .reusable, &handle);
        if (result == .stored) {
            // No longer inducing failure at this index; ownership moved
            // into the cache, so `state` is already zero-valued and safe
            // for the `defer state.deinit()` above to no-op on.
            break;
        }
        try testing.expectEqual(StoreResult.storage_failed, result);
        try testing.expectEqualStrings("example.test", state.common.server_name.?.slice());
    }
}

test "stateful server zeroizes handle and state bytes on removal and deinit" {
    var backing: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var cache = try StatefulServerCache.init(fba.allocator(), Limits.stateful_server_default, system_random_source);

    var state = try testServerState(testing.allocator, "zeroize-server-sni", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .reusable, &handle);

    cache.deinit();
    try testing.expect(std.mem.indexOf(u8, &backing, "zeroize-server-sni") == null);
    try testing.expect(std.mem.indexOf(u8, &backing, handle[8..stateful_identity_len]) == null);
}

test "a re-entrant observer calling back into the cache does not deadlock" {
    const Recorder = struct {
        cache: *StatefulServerCache,
        saw_count: usize = 0,

        fn onEvent(ctx: *anyopaque, _: CacheEvent) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.saw_count = self.cache.count();
        }
    };
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var recorder: Recorder = .{ .cache = &cache };
    cache.setObserver(.{ .ctx = @ptrCast(&recorder), .onEventFn = Recorder.onEvent });

    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .reusable, &handle);

    var result = cache.resolveLease(&handle, 1);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), recorder.saw_count);
}

test "cloneLiveForPersistence refuses to snapshot a currently-leased single-use entry" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .single_use, &handle);

    var leased = cache.resolveLease(&handle, 1);
    try testing.expectError(error.CacheBusy, cache.cloneLiveForPersistence(testing.allocator, 2));
    try testing.expect(cache.hasOutstandingLease());

    switch (leased) {
        .hit => |*h| h.lease.commit(),
        else => try testing.expect(false),
    }
    leased.deinit();

    // Consumed: no longer leased, and no longer present (single-use).
    try testing.expect(!cache.hasOutstandingLease());
    var snapshot = try cache.cloneLiveForPersistence(testing.allocator, 2);
    defer {
        for (snapshot.items) |*p| p.deinit();
        snapshot.deinit(testing.allocator);
        cache.endPersistenceSnapshot();
    }
    try testing.expectEqual(@as(usize, 0), snapshot.items.len);
}

test "restoreEntries rejects duplicate handles as a corrupted snapshot" {
    const s1 = try testServerState(testing.allocator, "a.test", 0, 1000);
    const s2 = try testServerState(testing.allocator, "b.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    @memcpy(handle[0..4], "TDSH");
    std.mem.writeInt(u16, handle[4..6], 1, .big);
    std.mem.writeInt(u16, handle[6..8], 0, .big);
    @memset(handle[8..], 0xAB);

    var items = [_]PersistedServerEntry{
        .{ .handle = handle, .usage = .reusable, .state = s1 },
        .{ .handle = handle, .usage = .reusable, .state = s2 },
    };

    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    try testing.expectError(error.DuplicateHandle, cache.restoreEntries(&items, 1));
    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "client and server persistence snapshots round trip through clone/restore" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "persist-me", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .single_use);
    t1.deinit();

    var snapshot = try cache.cloneLiveForPersistence(testing.allocator, 1);
    defer {
        for (snapshot.items) |*p| p.deinit();
        snapshot.deinit(testing.allocator);
        cache.endPersistenceSnapshot();
    }
    try testing.expectEqual(@as(usize, 1), snapshot.items.len);
    try testing.expectEqual(UsagePolicy.single_use, snapshot.items[0].usage);

    var restored = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer restored.deinit();
    try restored.restoreClones(snapshot.items, 1);
    try testing.expectEqual(@as(usize, 1), restored.count());

    var server_cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer server_cache.deinit();
    var s1 = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = server_cache.insertMove(&s1, 0, .reusable, &handle);

    var server_snapshot = try server_cache.cloneLiveForPersistence(testing.allocator, 1);
    defer {
        for (server_snapshot.items) |*p| p.deinit();
        server_snapshot.deinit(testing.allocator);
        server_cache.endPersistenceSnapshot();
    }
    try testing.expectEqual(@as(usize, 1), server_snapshot.items.len);
    try testing.expect(std.mem.eql(u8, &server_snapshot.items[0].handle, &handle));

    var restored_server = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer restored_server.deinit();
    try restored_server.restoreEntries(server_snapshot.items, 1);
    try testing.expectEqual(@as(usize, 1), restored_server.count());
    var hit = restored_server.resolveLease(&handle, 2);
    defer hit.deinit();
    try testing.expect(hit == .hit);
}

fn expectEligible(state: *const session.ServerRecoverableState, candidate: session.CandidateContext, now_unix_ms: i64) !void {
    const decision = session.evaluateCompatibility(&state.common, candidate, now_unix_ms);
    try testing.expectEqual(session.ResumeEligibility.eligible, decision.resumption);
}
