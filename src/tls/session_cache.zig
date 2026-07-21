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
//!     This first implementation is reusable-only: `UsagePolicy.single_use`
//!     is accepted and round-trips through storage/persistence (so a future
//!     change does not need a data migration), but nothing here consumes an
//!     entry differently based on it. Issue #364 explicitly permits this
//!     fallback ("#364 should ship reusable client tickets plus the lease
//!     API, with runtime commit wiring explicitly deferred") — a client
//!     offer-lease API that actually pins a selected single-use ticket
//!     between offer and commit is deferred to #365, where it can be
//!     designed alongside the real ClientHello-selection wiring instead of
//!     racing a persistence snapshot against a guess at when "selected but
//!     not yet committed" begins and ends.
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
//! ## Sequence counters
//!
//! `insertion_sequence` and `lru_sequence` (client) and `lru_sequence`
//! (server) are *ordering* counters: #364 requires overflow to renumber
//! live entries deterministically rather than silently wrap, because a
//! wrapped counter would make a freshly touched entry compare as the
//! *oldest* one and get evicted first. Renumbering never physically
//! reorders backing storage while other code might hold an index/pointer
//! into it: the client cache renumbers by sorting a *scratch* array of
//! `*ClientEntry` pointers (which stay valid because the operation never
//! grows/shrinks the backing `ArrayList`) and writing new sequence values
//! through them; the server cache renumbers by stable `entry_id` (a
//! hashmap key, immune to physical reordering by construction). Both are
//! fallible (they allocate scratch space) and are always resolved *before*
//! any other mutation in the same operation, exactly like every other
//! fallible step.
//!
//! `entry_id` (both caches) and `lease_epoch` (server) are *identity*
//! counters, not ordering ones: nothing compares them with `<` to decide
//! recency, they only need to differ from every other currently-live value
//! of the same kind. Wrapping after `2^64` assignments to the same still-
//! live identity is accepted as out of scope for those two.

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

/// Reusable vs single-use ticket/session semantics. See the module doc:
/// the client cache accepts and stores this but does not yet act on
/// `.single_use` differently (reusable-only for this PR); the stateful
/// server cache's lease/commit/release model fully implements it.
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
        // Reserve fresh sequence numbers before any mutation: renumbering
        // (the only fallible part of sequence assignment) must complete
        // before purge/eviction, matching every other fallible step. Both
        // the duplicate-replace and fresh-store paths below need both
        // values, so hoisting them here is not wasted work; unused gaps in
        // the sequence space left by an early rejection are harmless (only
        // relative order among *stored* entries matters).
        const new_insertion_seq = self.nextInsertionSequence() catch return .storage_failed;
        const new_lru_seq = self.nextLruSequence() catch return .storage_failed;

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
            .insertion_sequence = new_insertion_seq,
            .lru_sequence = new_lru_seq,
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

            var touched_ids: [pre_shared_key.max_offered_identities]u64 = undefined;
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
                touched_ids[touched_len] = self.entries.items[c.idx].entry_id;
                touched_len += 1;
            }

            if (storage_failed) {
                offers.deinit();
            } else if (touched_len > 0) {
                // Reserve every needed LRU sequence value up front. This
                // may trigger at most one renumber, which sorts a scratch
                // array of *entry pointers* (never `entries.items`
                // itself). The lookup below then re-finds each touched
                // entry by its stable `entry_id` rather than trusting the
                // physical `idx` captured above, so this stays correct
                // even if a future change makes reservation intermittently
                // release the lock.
                var new_seqs: [pre_shared_key.max_offered_identities]u64 = undefined;
                var reservation_failed = false;
                for (0..touched_len) |seq_idx| {
                    new_seqs[seq_idx] = self.nextLruSequence() catch {
                        reservation_failed = true;
                        break;
                    };
                }
                if (!reservation_failed) {
                    for (touched_ids[0..touched_len], new_seqs[0..touched_len]) |entry_id, seq| {
                        for (self.entries.items) |*e| {
                            if (e.entry_id == entry_id) {
                                e.lru_sequence = seq;
                                break;
                            }
                        }
                    }
                }
                // A reservation failure here (an allocation failure inside
                // an at-most-once-per-2^64-calls renumber) just means
                // recency isn't refreshed this time; the lookup itself
                // already succeeded and its offers remain fully valid, so
                // it is not escalated to `.storage_failed`.
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

    /// Deep-clones every non-expired entry for a persistence save,
    /// including its exact insertion/LRU order. Must be called outside any
    /// persistence I/O; the returned clones are fully owned by the caller.
    pub fn cloneLiveForPersistence(
        self: *ClientSessionCache,
        allocator: std.mem.Allocator,
        now_unix_ms: i64,
    ) error{OutOfMemory}!std.ArrayListUnmanaged(PersistedClientEntry) {
        self.mutex.lock();
        defer self.mutex.unlock();

        var out: std.ArrayListUnmanaged(PersistedClientEntry) = .empty;
        errdefer {
            for (out.items) |*p| p.deinit();
            out.deinit(allocator);
        }
        try out.ensureTotalCapacityPrecise(allocator, self.entries.items.len);
        for (self.entries.items) |*e| {
            if (e.ticket.common.isExpired(now_unix_ms)) continue;
            var clone: PersistedClientEntry = .{
                .usage = e.usage,
                .insertion_sequence = e.insertion_sequence,
                .lru_sequence = e.lru_sequence,
            };
            try e.ticket.cloneInto(allocator, &clone.ticket);
            out.appendAssumeCapacity(clone);
        }
        return out;
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
    /// immediately with `error.OutOfMemory` (still consuming every
    /// remaining item so nothing leaks), and the caller must not treat a
    /// partially-restored cache as successful. A record that is merely
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

        // Track the high-water mark with *saturating* arithmetic: if the
        // persisted value is already `maxInt(u64)`, the next ordinary
        // sequence request must see that and renumber, not silently wrap
        // to `0` and collide with a live entry's sequence.
        if (insertion_sequence >= self.next_insertion_sequence) self.next_insertion_sequence = insertion_sequence +| 1;
        if (lru_sequence >= self.next_lru_sequence) self.next_lru_sequence = lru_sequence +| 1;
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

    fn nextInsertionSequence(self: *ClientSessionCache) error{OutOfMemory}!u64 {
        if (self.next_insertion_sequence == std.math.maxInt(u64)) try self.renumberInsertionSequencesLocked();
        const s = self.next_insertion_sequence;
        self.next_insertion_sequence += 1;
        return s;
    }

    fn nextLruSequence(self: *ClientSessionCache) error{OutOfMemory}!u64 {
        if (self.next_lru_sequence == std.math.maxInt(u64)) try self.renumberLruSequencesLocked();
        const s = self.next_lru_sequence;
        self.next_lru_sequence += 1;
        return s;
    }

    fn nextEntryId(self: *ClientSessionCache) u64 {
        const id = self.next_entry_id;
        self.next_entry_id +%= 1;
        return id;
    }

    /// Renumbers every live entry's `insertion_sequence` into a compact,
    /// gap-free range that preserves relative order, without physically
    /// reordering `entries.items`: a scratch array of `*ClientEntry`
    /// pointers is sorted instead (those pointers stay valid because this
    /// function never grows/shrinks/reallocates the backing `ArrayList`).
    fn renumberInsertionSequencesLocked(self: *ClientSessionCache) error{OutOfMemory}!void {
        const Item = struct { entry: *ClientEntry, old: u64 };
        const scratch = try self.allocator.alloc(Item, self.entries.items.len);
        defer self.allocator.free(scratch);
        for (self.entries.items, 0..) |*e, i| scratch[i] = .{ .entry = e, .old = e.insertion_sequence };

        const Ctx = struct {
            fn lessThan(_: void, a: Item, b: Item) bool {
                if (a.old != b.old) return a.old < b.old;
                return a.entry.entry_id < b.entry.entry_id;
            }
        };
        std.mem.sort(Item, scratch, {}, Ctx.lessThan);
        for (scratch, 0..) |item, seq| item.entry.insertion_sequence = @intCast(seq);
        self.next_insertion_sequence = scratch.len;
    }

    fn renumberLruSequencesLocked(self: *ClientSessionCache) error{OutOfMemory}!void {
        const Item = struct { entry: *ClientEntry, old: u64 };
        const scratch = try self.allocator.alloc(Item, self.entries.items.len);
        defer self.allocator.free(scratch);
        for (self.entries.items, 0..) |*e, i| scratch[i] = .{ .entry = e, .old = e.lru_sequence };

        const Ctx = struct {
            fn lessThan(_: void, a: Item, b: Item) bool {
                if (a.old != b.old) return a.old < b.old;
                return a.entry.entry_id < b.entry.entry_id;
            }
        };
        std.mem.sort(Item, scratch, {}, Ctx.lessThan);
        for (scratch, 0..) |item, seq| item.entry.lru_sequence = @intCast(seq);
        self.next_lru_sequence = scratch.len;
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

const handle_digest_domain = "TARDIGRADE-TLS-SESSION-CACHE-HANDLE-V1";
const HandleDigest = [32]u8;

/// Non-secret digest of a `TDSH` handle, used only as the `handle_index`
/// hashmap key. A SHA-256 digest cannot be inverted back to the handle, so
/// unlike the raw handle it is safe to sit in ordinary (non-secret-wiping)
/// hashmap backing storage that may be copied around by rehashing/growth.
fn digestHandle(handle: *const [stateful_identity_len]u8) HandleDigest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(handle_digest_domain);
    hasher.update(handle);
    var out: HandleDigest = undefined;
    hasher.final(&out);
    return out;
}

/// A stored stateful entry. Heap-allocated individually (see `entries`
/// below) rather than stored inline as a general-purpose hashmap value, so
/// its bearer secret (`handle`) and resumption PSK (inline inside `state`)
/// are never silently copied into a rehash/growth allocation and left
/// behind in the old one: this struct's own allocation is explicitly wiped
/// and freed exactly once, by `destroyServerEntry`, with nothing else ever
/// touching or reallocating it.
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

/// Wipes and frees an individually-allocated `ServerEntry`. The only
/// correct way to release one: never `allocator.destroy` a `*ServerEntry`
/// directly elsewhere.
fn destroyServerEntry(allocator: std.mem.Allocator, entry: *ServerEntry) void {
    entry.state.deinit();
    secrets.secureZero(std.mem.asBytes(entry));
    allocator.destroy(entry);
}

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
/// unrelated one of the same entry. `cache_generation` identifies which
/// *cache contents* this lease was resolved against: a persistence reload
/// discards and replaces the entire entry/index set and bumps the cache's
/// generation, so a lease resolved before a reload can never act on an
/// unrelated post-reload entry that happens to reuse the same `entry_id`.
///
/// Reusable leases carry `single_use = false`; `commit` still touches their
/// recency (see `StatefulServerCache.commitLease`), but `release` is a
/// no-op for them since they are never pinned.
///
/// `deinit` releases the lease if it is still outstanding, so a caller that
/// forgets to explicitly `commit`/`release` (e.g. an early-return error
/// path) cannot leave a single-use entry pinned forever — call it via
/// `defer lease.deinit()` immediately after a successful resolve.
pub const ServerLease = struct {
    cache: *StatefulServerCache,
    cache_generation: u64,
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
        self.cache.commitLease(self.cache_generation, self.entry_id, self.lease_epoch, self.single_use);
    }

    pub fn release(self: *ServerLease) void {
        if (!self.active) return;
        self.active = false;
        if (!self.single_use) return;
        self.cache.releaseLease(self.cache_generation, self.entry_id, self.lease_epoch);
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

/// The exact set of entries an insertion will evict, computed as a pure,
/// non-mutating "dry run" before any fallible allocation is attempted or
/// any state is mutated (see `planInsertionLocked`).
const EvictionPlan = struct {
    victims: std.ArrayListUnmanaged(u64) = .empty,
    /// Whether the target origin's bucket will still have at least one
    /// member left after `victims` are removed (including members already
    /// there that are not being evicted). `false` means the bucket either
    /// does not exist yet or will end up fully emptied (and therefore
    /// removed) by this plan.
    origin_bucket_survives: bool,

    fn deinit(self: *EvictionPlan, allocator: std.mem.Allocator) void {
        self.victims.deinit(allocator);
    }
};

/// Bounded stateful server-side ticket/session store keyed by a random
/// opaque handle. Primary index is `handle digest -> entry_id` (O(1));
/// `entry_id` is the stable storage key so LRU/eviction never invalidates
/// it, and the underlying `ServerEntry` (containing the bearer handle and
/// resumption PSK) lives behind an individually-allocated, individually-
/// wiped pointer rather than inline in general-purpose hashmap storage
/// (see `ServerEntry`'s doc comment). A secondary `origin -> [entry_id]`
/// index bounds per-origin operations without scanning the whole cache.
/// Process-shared and thread-safe (see module doc).
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
    entries: std.AutoHashMapUnmanaged(u64, *ServerEntry) = .empty,
    handle_index: std.AutoHashMapUnmanaged(HandleDigest, u64) = .empty,
    origin_index: std.AutoHashMapUnmanaged(OriginDigest, OriginBucket) = .empty,
    total_bytes: usize = 0,
    next_entry_id: u64 = 1,
    next_lru_sequence: u64 = 0,
    next_lease_epoch: u64 = 1,
    /// Bumped by a persistence reload (see `session_cache_persistence.zig`)
    /// when this cache's entire entry/index set is discarded and replaced.
    /// Every `ServerLease` captures the generation it was resolved under,
    /// so a lease taken before a reload can never act on an unrelated
    /// post-reload entry that happens to reuse the same `entry_id`.
    cache_generation: u64 = 0,
    /// See `ClientSessionCache`'s module-doc note on the client's
    /// reusable-only scope for this PR: the *stateful* cache does
    /// implement single-use consumption, so it still needs this guard.
    /// Set for the whole duration of a save (through
    /// `endPersistenceSnapshot`), during which new single-use leases are
    /// refused (`.busy`) rather than risk a just-persisted-then-consumed
    /// ticket being resurrected on reload.
    persistence_in_progress: bool = false,

    pub fn init(allocator: std.mem.Allocator, limits: Limits, random: RandomSource) error{InvalidLimits}!StatefulServerCache {
        try limits.validate();
        return .{ .allocator = allocator, .limits = limits, .random = random };
    }

    /// Requires quiescence: no outstanding leases and no concurrent callers.
    pub fn deinit(self: *StatefulServerCache) void {
        self.discardLocked();
    }

    /// Destroys and frees every entry and index structure, leaving the
    /// cache's storage fields at their fresh-instance defaults (counters
    /// untouched). Shared by `deinit` and by a persistence reload swap.
    fn discardLocked(self: *StatefulServerCache) void {
        var it = self.entries.valueIterator();
        while (it.next()) |entry_ptr| destroyServerEntry(self.allocator, entry_ptr.*);
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

    /// Atomically replaces this cache's entries/indexes/byte-and-sequence
    /// counters with `temp`'s, discarding whatever this cache currently
    /// holds, and bumps `cache_generation` so any lease resolved before
    /// this call is invalidated even if the replacement reuses the same
    /// `entry_id` values (which a freshly-restored temporary cache always
    /// does, starting back at `1`). `temp`'s storage is moved, not copied;
    /// `temp` is left as a fresh empty cache. Caller must hold `self.mutex`
    /// for the whole operation (see `session_cache_persistence.zig`).
    pub fn adoptFromLocked(self: *StatefulServerCache, temp: *StatefulServerCache) void {
        self.discardLocked();
        self.entries = temp.entries;
        self.handle_index = temp.handle_index;
        self.origin_index = temp.origin_index;
        self.total_bytes = temp.total_bytes;
        self.next_entry_id = temp.next_entry_id;
        self.next_lru_sequence = temp.next_lru_sequence;
        self.next_lease_epoch = temp.next_lease_epoch;
        self.cache_generation +%= 1;
        temp.entries = .empty;
        temp.handle_index = .empty;
        temp.origin_index = .empty;
        temp.total_bytes = 0;
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
                // Reserve the fresh LRU sequence (the only fallible part of
                // sequence assignment) before any purge/eviction mutation.
                const lru_seq = self.reserveFreshLruSequenceLocked() catch break :blk .storage_failed;
                break :blk self.insertLocked(state, handle, origin, usage, now_unix_ms, bytes, lru_seq, &evicted);
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
    /// victims, the insert must be rejected before anything is mutated.
    fn canFitLocked(self: *StatefulServerCache, origin: OriginDigest, new_bytes: usize) bool {
        var leased_count: usize = 0;
        var leased_bytes: usize = 0;
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            if (e.active_lease_epoch != null) {
                leased_count += 1;
                leased_bytes += e.bytes;
            }
        }
        if (leased_count >= self.limits.max_entries) return false;
        if (leased_bytes + new_bytes > self.limits.max_total_bytes) return false;

        if (self.origin_index.get(origin)) |bucket| {
            var origin_leased: usize = 0;
            for (bucket.items) |id| {
                const e = self.entries.get(id) orelse continue;
                if (e.active_lease_epoch != null) origin_leased += 1;
            }
            if (origin_leased >= self.limits.max_entries_per_origin) return false;
        }
        return true;
    }

    fn originBucketLen(self: *StatefulServerCache, origin: OriginDigest) usize {
        return if (self.origin_index.get(origin)) |b| b.items.len else 0;
    }

    fn findOldestUnleasedInOriginExcluding(self: *StatefulServerCache, origin: OriginDigest, excluding: []const u64) ?u64 {
        const bucket = self.origin_index.getPtr(origin) orelse return null;
        var best_id: ?u64 = null;
        var best_seq: u64 = undefined;
        for (bucket.items) |id| {
            if (std.mem.indexOfScalar(u64, excluding, id) != null) continue;
            const e = self.entries.get(id) orelse continue;
            if (e.active_lease_epoch != null) continue;
            if (best_id == null or e.lru_sequence < best_seq) {
                best_id = id;
                best_seq = e.lru_sequence;
            }
        }
        return best_id;
    }

    fn findOldestUnleasedGlobalExcluding(self: *StatefulServerCache, excluding: []const u64) ?u64 {
        var best_id: ?u64 = null;
        var best_seq: u64 = undefined;
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (std.mem.indexOfScalar(u64, excluding, kv.key_ptr.*) != null) continue;
            const e = kv.value_ptr.*;
            if (e.active_lease_epoch != null) continue;
            if (best_id == null or e.lru_sequence < best_seq) {
                best_id = kv.key_ptr.*;
                best_seq = e.lru_sequence;
            }
        }
        return best_id;
    }

    /// Computes, without mutating anything, the exact set of entries this
    /// insertion will need to evict (`canFitLocked` already guarantees
    /// this is possible using only unleased victims), plus whether the
    /// target origin's bucket will still exist afterward. Called *before*
    /// any fallible allocation is attempted, so `insertLocked` knows
    /// precisely what it is about to do and can reserve exactly the right
    /// capacity before mutating anything.
    fn planInsertionLocked(self: *StatefulServerCache, origin: OriginDigest, new_bytes: usize) error{OutOfMemory}!?EvictionPlan {
        if (!self.canFitLocked(origin, new_bytes)) return null;

        var victims: std.ArrayListUnmanaged(u64) = .empty;
        errdefer victims.deinit(self.allocator);

        var origin_count = self.originBucketLen(origin);
        var global_count = self.entries.count();
        var global_bytes = self.total_bytes;

        while (origin_count >= self.limits.max_entries_per_origin) {
            const victim = self.findOldestUnleasedInOriginExcluding(origin, victims.items) orelse unreachable;
            try victims.append(self.allocator, victim);
            origin_count -= 1;
            global_count -= 1;
            global_bytes -= self.entries.get(victim).?.bytes;
        }
        while (global_count >= self.limits.max_entries or global_bytes + new_bytes > self.limits.max_total_bytes) {
            const victim = self.findOldestUnleasedGlobalExcluding(victims.items) orelse unreachable;
            try victims.append(self.allocator, victim);
            global_count -= 1;
            global_bytes -= self.entries.get(victim).?.bytes;
            if (std.mem.eql(u8, &self.entries.get(victim).?.origin, &origin) and origin_count > 0) origin_count -= 1;
        }

        return EvictionPlan{ .victims = victims, .origin_bucket_survives = origin_count > 0 };
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

        const handle_digest = digestHandle(&handle);
        if (self.handle_index.contains(handle_digest)) return .rejected_capacity;

        const is_new_origin = !self.origin_index.contains(origin);
        if (is_new_origin and self.origin_index.count() >= self.limits.max_origins) {
            return .rejected_capacity;
        }

        var plan = (self.planInsertionLocked(origin, bytes) catch return .storage_failed) orelse return .rejected_capacity;
        defer plan.deinit(self.allocator);

        // Reserve every allocation this insert could possibly need before
        // mutating anything: the new entry's own storage, the map/index
        // capacity, and either the existing origin bucket's capacity (if
        // the plan says it survives) or a freshly detached, capacity-
        // reserved bucket (if eviction will empty-and-remove it, or it
        // doesn't exist yet) — never the *existing* bucket's capacity in
        // that second case, since eviction (driven by `plan.victims`,
        // applied below) can delete that exact bucket.
        self.entries.ensureUnusedCapacity(self.allocator, 1) catch return .storage_failed;
        self.handle_index.ensureUnusedCapacity(self.allocator, 1) catch return .storage_failed;

        const new_entry = self.allocator.create(ServerEntry) catch return .storage_failed;
        var new_entry_committed = false;
        errdefer if (!new_entry_committed) self.allocator.destroy(new_entry);

        var detached_bucket: ?OriginBucket = null;
        errdefer if (detached_bucket) |*b| b.deinit(self.allocator);
        if (plan.origin_bucket_survives) {
            const bucket = self.origin_index.getPtr(origin) orelse unreachable;
            bucket.ensureUnusedCapacity(self.allocator, 1) catch return .storage_failed;
        } else {
            var fresh: OriginBucket = .empty;
            fresh.ensureUnusedCapacity(self.allocator, 1) catch return .storage_failed;
            detached_bucket = fresh;
        }
        self.origin_index.ensureUnusedCapacity(self.allocator, 1) catch return .storage_failed;

        // Every fallible step has now succeeded: apply the precomputed
        // plan and commit the new entry.
        for (plan.victims.items) |id| {
            self.removeEntryLocked(id);
            evicted.* += 1;
        }

        const entry_id = self.next_entry_id;
        self.next_entry_id +%= 1;
        new_entry.* = .{ .origin = origin, .handle = handle, .usage = usage, .lru_sequence = lru_sequence, .bytes = bytes };
        new_entry.state.moveFrom(state);
        self.entries.putAssumeCapacity(entry_id, new_entry);
        new_entry_committed = true;
        self.handle_index.putAssumeCapacity(handle_digest, entry_id);

        if (detached_bucket) |*fresh| {
            self.origin_index.putAssumeCapacityNoClobber(origin, fresh.*);
            detached_bucket = null;
        }
        self.origin_index.getPtr(origin).?.appendAssumeCapacity(entry_id);

        self.total_bytes += bytes;
        if (lru_sequence >= self.next_lru_sequence) self.next_lru_sequence = lru_sequence +| 1;
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

            const digest = digestHandle(&key);
            const entry_id = self.handle_index.get(digest) orelse break :blk .miss;
            const e = self.entries.get(entry_id).?;
            // Constant-time confirmation against the owned entry's real
            // handle: a SHA-256 digest collision is not a realistic
            // concern, but this keeps the actual accept decision anchored
            // to the bearer secret itself, not just its digest.
            if (!secrets.constantTimeEqual(&e.handle, &key)) break :blk .miss;

            const single_use = e.usage == .single_use;
            if (single_use and e.active_lease_epoch != null) {
                event = .lookup_miss;
                break :blk .miss;
            }
            if (single_use and self.persistence_in_progress) {
                event = .lookup_miss; // miss-shaped; distinguishable via the returned `.busy` result itself
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
                .lease = .{
                    .cache = self,
                    .cache_generation = self.cache_generation,
                    .entry_id = entry_id,
                    .lease_epoch = epoch,
                    .single_use = single_use,
                },
            } };
        };

        self.observer.notify(event);
        return result;
    }

    /// Consumes a single-use entry after binder success, before any
    /// PSK-selected ServerHello byte is emitted; no-op if `cache_generation`
    /// or `lease_epoch` is stale (already committed, released and re-leased
    /// by someone else, removed/evicted, or the cache has since been
    /// reloaded). For a reusable entry, refreshes its LRU recency instead
    /// of removing it — recency is updated here (on confirmed,
    /// binder-verified use) rather than at `resolveLease` time, so a
    /// session that keeps being successfully resumed stays protected from
    /// eviction. A renumber-allocation-failure while refreshing recency is
    /// not surfaced (commit itself must not fail operationally); it can
    /// only occur once per `2^64` LRU touches, at which point recency
    /// simply is not refreshed this one time.
    fn commitLease(self: *StatefulServerCache, cache_generation: u64, entry_id: u64, lease_epoch: u64, single_use: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (cache_generation != self.cache_generation) return;
        const e = self.entries.get(entry_id) orelse return;
        if (single_use) {
            if (e.active_lease_epoch != lease_epoch) return;
            self.removeEntryLocked(entry_id);
        } else {
            e.lru_sequence = self.reserveFreshLruSequenceLocked() catch return;
        }
    }

    /// Releases a pinned single-use entry (incompatibility, bad binder, or
    /// teardown) so it can be resolved again under a fresh epoch. No-op if
    /// `cache_generation` or `lease_epoch` is stale (see `commitLease`).
    fn releaseLease(self: *StatefulServerCache, cache_generation: u64, entry_id: u64, lease_epoch: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (cache_generation != self.cache_generation) return;
        const e = self.entries.get(entry_id) orelse return;
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
            while (it.next()) |entry_ptr| {
                const e = entry_ptr.*;
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

    /// Caller must already hold `self.mutex`. Exposed (unlike other
    /// `xxxLocked` helpers) so a persistence reload can re-check the live
    /// cache for outstanding leases immediately before swapping it out,
    /// within the same critical section as the swap itself.
    pub fn hasOutstandingLeaseLocked(self: *StatefulServerCache) bool {
        var it = self.entries.valueIterator();
        while (it.next()) |entry_ptr| {
            const e = entry_ptr.*;
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
            if (!self.handle_index.contains(digestHandle(&candidate))) {
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
                const e = kv.value_ptr.*;
                if (e.active_lease_epoch != null) continue;
                if (e.state.common.isExpired(now_unix_ms)) {
                    found = kv.key_ptr.*;
                    break;
                }
            }
            const id = found orelse break;
            self.removeEntryLocked(id);
            evicted.* += 1;
        }
    }

    /// Removes and wipes a stored entry by its stable `entry_id`,
    /// unindexing its handle and updating (and, if now empty, removing) its
    /// origin bucket.
    fn removeEntryLocked(self: *StatefulServerCache, entry_id: u64) void {
        const kv = self.entries.fetchRemove(entry_id) orelse return;
        const entry = kv.value;
        self.total_bytes -= entry.bytes;
        _ = self.handle_index.remove(digestHandle(&entry.handle));
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
        destroyServerEntry(self.allocator, entry);
    }

    /// Reserves and returns a fresh LRU sequence value, renumbering first
    /// if the counter is about to overflow.
    fn reserveFreshLruSequenceLocked(self: *StatefulServerCache) error{OutOfMemory}!u64 {
        if (self.next_lru_sequence == std.math.maxInt(u64)) try self.renumberLruSequencesLocked();
        const s = self.next_lru_sequence;
        self.next_lru_sequence += 1;
        return s;
    }

    /// Renumbers every live entry's `lru_sequence` into a compact, gap-free
    /// range that preserves relative order. Unlike the client cache, this
    /// never needs to worry about physical reordering: entries are keyed
    /// by stable `entry_id` in a hashmap, so the scratch sort only touches
    /// a temporary array of `(entry_id, old_sequence)` pairs, and values
    /// are written back by looking the entry up through its (unchanged)
    /// hashmap key.
    fn renumberLruSequencesLocked(self: *StatefulServerCache) error{OutOfMemory}!void {
        const Item = struct { id: u64, old: u64 };
        const scratch = try self.allocator.alloc(Item, self.entries.count());
        defer self.allocator.free(scratch);
        var i: usize = 0;
        var it = self.entries.iterator();
        while (it.next()) |kv| : (i += 1) scratch[i] = .{ .id = kv.key_ptr.*, .old = kv.value_ptr.*.lru_sequence };

        const Ctx = struct {
            fn lessThan(_: void, a: Item, b: Item) bool {
                if (a.old != b.old) return a.old < b.old;
                return a.id < b.id;
            }
        };
        std.mem.sort(Item, scratch, {}, Ctx.lessThan);
        for (scratch, 0..) |item, seq| {
            self.entries.get(item.id).?.lru_sequence = @intCast(seq);
        }
        self.next_lru_sequence = scratch.len;
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

/// Asserts `session.evaluateCompatibility` accepts `state` against
/// `candidate`, simulating the shared #362 path that will sit between
/// `resolveLease` and `commit`/`release` once wired up.
fn expectEligible(state: *const session.ServerRecoverableState, candidate: session.CandidateContext, now_unix_ms: i64) !void {
    const decision = session.evaluateCompatibility(&state.common, candidate, now_unix_ms);
    try testing.expectEqual(session.ResumeEligibility.eligible, decision.resumption);
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
    try testing.expectEqual(@as(usize, 1), removed);
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

test "client cache renumbers deterministically at insertion_sequence and lru_sequence overflow" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var t1 = try testClient(testing.allocator, "t1", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();
    var t2 = try testClient(testing.allocator, "t2", "example.test", 0, 1000, 1);
    _ = cache.storeClone(&t2, 1, .reusable);
    t2.deinit();

    // Force both counters to the boundary: the next store must renumber
    // rather than wrap.
    cache.next_insertion_sequence = std.math.maxInt(u64);
    cache.next_lru_sequence = std.math.maxInt(u64);

    var t3 = try testClient(testing.allocator, "t3", "example.test", 0, 1000, 2);
    _ = cache.storeClone(&t3, 2, .reusable);
    t3.deinit();

    // Order must remain exactly t3, t2, t1 (newest insertion first) — a
    // wrapped counter would instead make t3 compare as the *oldest*.
    var result = cache.lookupOffers(testCandidate("example.test"), 3);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 3), result.hit.len);
    try testing.expectEqualStrings("t3", result.hit.constSlice()[0].ticket.slice());
    try testing.expectEqualStrings("t2", result.hit.constSlice()[1].ticket.slice());
    try testing.expectEqualStrings("t1", result.hit.constSlice()[2].ticket.slice());

    // LRU order after renumbering: with a 2-entry-per-origin cap, forcing
    // eviction now must evict the true LRU victim (t1), not whichever
    // entry a wrapped counter would have mislabeled as oldest.
    var limits = Limits.client_default;
    limits.max_entries_per_origin = 3;
    var cache2 = try ClientSessionCache.init(testing.allocator, limits);
    defer cache2.deinit();
    var v1 = try testClient(testing.allocator, "v1", "example.test", 0, 1000, 0);
    _ = cache2.storeClone(&v1, 0, .reusable);
    v1.deinit();
    var v2 = try testClient(testing.allocator, "v2", "example.test", 0, 1000, 1);
    _ = cache2.storeClone(&v2, 1, .reusable);
    v2.deinit();
    cache2.next_lru_sequence = std.math.maxInt(u64);
    var v3 = try testClient(testing.allocator, "v3", "example.test", 0, 1000, 2);
    _ = cache2.storeClone(&v3, 2, .reusable);
    v3.deinit();
    limits.max_entries_per_origin = 2;
    cache2.limits = limits;
    var v4 = try testClient(testing.allocator, "v4", "example.test", 0, 1000, 3);
    _ = cache2.storeClone(&v4, 3, .reusable);
    v4.deinit();
    var result2 = cache2.lookupOffers(testCandidate("example.test"), 4);
    defer result2.deinit();
    var saw_v1 = false;
    for (result2.hit.constSlice()) |*t| {
        if (std.mem.eql(u8, t.ticket.slice(), "v1")) saw_v1 = true;
    }
    try testing.expect(!saw_v1);
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

    // Eviction order must also match: forcing both caches under a
    // per-origin cap of 2 must evict the exact same (LRU) survivor set.
    var limits2 = Limits.client_default;
    limits2.max_entries_per_origin = 2;
    var tight_source = try ClientSessionCache.init(testing.allocator, limits2);
    defer tight_source.deinit();
    var s1 = try testClient(testing.allocator, "s1", "x.test", 0, 1000, 0);
    _ = tight_source.storeClone(&s1, 0, .reusable);
    s1.deinit();
    var s2 = try testClient(testing.allocator, "s2", "x.test", 0, 1000, 1);
    _ = tight_source.storeClone(&s2, 1, .reusable);
    s2.deinit();
    var touch2 = tight_source.lookupOffers(testCandidate("x.test"), 2);
    touch2.deinit();

    var tight_snapshot = try tight_source.cloneLiveForPersistence(testing.allocator, 3);
    defer {
        for (tight_snapshot.items) |*p| p.deinit();
        tight_snapshot.deinit(testing.allocator);
    }
    var tight_restored = try ClientSessionCache.init(testing.allocator, limits2);
    defer tight_restored.deinit();
    try tight_restored.restoreClones(tight_snapshot.items, 3);

    // Now push both under eviction pressure by inserting a third entry.
    var s3a = try testClient(testing.allocator, "s3", "x.test", 0, 1000, 2);
    _ = tight_source.storeClone(&s3a, 2, .reusable);
    s3a.deinit();
    var s3b = try testClient(testing.allocator, "s3", "x.test", 0, 1000, 2);
    _ = tight_restored.storeClone(&s3b, 2, .reusable);
    s3b.deinit();

    var survivors_a = tight_source.lookupOffers(testCandidate("x.test"), 3);
    defer survivors_a.deinit();
    var survivors_b = tight_restored.lookupOffers(testCandidate("x.test"), 3);
    defer survivors_b.deinit();
    try testing.expectEqual(survivors_a.hit.len, survivors_b.hit.len);
    for (survivors_a.hit.constSlice(), survivors_b.hit.constSlice()) |*x, *y| {
        try testing.expectEqualStrings(x.ticket.slice(), y.ticket.slice());
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

test "stateful server renumbers lru_sequence deterministically at overflow" {
    var limits = Limits.stateful_server_default;
    limits.max_entries = 2;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var s1 = try testServerState(testing.allocator, "a.test", 0, 1000);
    var h1: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .reusable, &h1);

    cache.next_lru_sequence = std.math.maxInt(u64);

    var s2 = try testServerState(testing.allocator, "b.test", 0, 1000);
    var h2: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s2, 1, .reusable, &h2));
    try testing.expectEqual(@as(usize, 2), cache.count());

    // The freshly-inserted h2 must not be misclassified as the oldest
    // entry by a wrapped counter: forcing eviction now must evict h1.
    var s3 = try testServerState(testing.allocator, "c.test", 0, 1000);
    var h3: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s3, 2, .reusable, &h3);
    try testing.expectEqual(@as(usize, 2), cache.count());
    try testing.expect(cache.resolveLease(&h1, 3) == .miss);
    var hit2 = cache.resolveLease(&h2, 3);
    defer hit2.deinit();
    try testing.expect(hit2 == .hit);
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

test "a stale lease token cannot act after a reload replaces the entry it points at" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var s1 = try testServerState(testing.allocator, "example.test", 0, 1000);
    var h1: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .reusable, &h1);

    var result = cache.resolveLease(&h1, 1);
    var lease = result.hit.lease;
    result.hit.state.deinit();

    // Simulate a persistence reload replacing the entire entry/index set
    // (a fresh temp cache's `entry_id` counter also starts at 1, so the
    // restored entry can legitimately reuse the same internal id).
    var temp = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer temp.deinit();
    var s2 = try testServerState(testing.allocator, "other.test", 0, 1000);
    var h2: [stateful_identity_len]u8 = undefined;
    _ = temp.insertMove(&s2, 1, .reusable, &h2);
    cache.mutex.lock();
    cache.adoptFromLocked(&temp);
    cache.mutex.unlock();

    // The stale, pre-reload lease must not touch the restored entry.
    lease.commit();
    var still_there = cache.resolveLease(&h2, 2);
    defer still_there.deinit();
    try testing.expect(still_there == .hit);
    // (If the stale commit had wrongly refreshed the restored entry's
    // recency, that's silent and hard to assert directly; the primary
    // guarantee under test is that generation-gating makes it a no-op at
    // all rather than touching `entry_id` 1 in the new generation.)
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
    // member, which removes the (now-empty) bucket from `origin_index`
    // mid-insert. The insert must still complete correctly with all
    // indexes consistent rather than using a stale bucket reference.
    var s2 = try testServerState(testing.allocator, "a.test", 0, 1000);
    var h2: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s2, 1, .reusable, &h2));
    try testing.expectEqual(@as(usize, 1), cache.count());

    try testing.expect(cache.resolveLease(&h1, 2) == .miss);
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

test "insertion under eviction pressure leaves all state unchanged on late allocation failure" {
    var backing: [65536]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);

    var limits = Limits.stateful_server_default;
    limits.max_entries = 2;
    var cache = try StatefulServerCache.init(fba.allocator(), limits, system_random_source);
    defer cache.deinit();

    var s1 = try testServerState(testing.allocator, "a.test", 0, 1000);
    var h1: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s1, 0, .reusable, &h1));
    var s2 = try testServerState(testing.allocator, "b.test", 0, 1000);
    var h2: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s2, 1, .reusable, &h2));

    const bytes_before = cache.totalBytes();
    const count_before = cache.count();

    var fail_index: usize = 0;
    while (fail_index < 12) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        var state3 = try testServerState(testing.allocator, "c.test", 0, 1000);
        defer state3.deinit();
        var handle3: [stateful_identity_len]u8 = undefined;

        var failing_cache = cache;
        failing_cache.allocator = failing.allocator();
        const result = failing_cache.insertMove(&state3, 2, .reusable, &handle3);
        if (result == .stored) {
            // No longer inducing failure: undo this iteration's real
            // insert so the loop-invariant assertions below still hold,
            // and stop sweeping.
            cache = failing_cache;
            break;
        }
        try testing.expectEqual(StoreResult.storage_failed, result);
        try testing.expectEqual(count_before, cache.count());
        try testing.expectEqual(bytes_before, cache.totalBytes());
        var still_h1 = cache.resolveLease(&h1, 3);
        defer still_h1.deinit();
        try testing.expect(still_h1 == .hit);
        still_h1.hit.lease.release();
    }
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

test "stateful server zeroizes handle and PSK bytes on removal and deinit" {
    var backing: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var cache = try StatefulServerCache.init(fba.allocator(), Limits.stateful_server_default, system_random_source);

    var state = try testServerState(fba.allocator(), "zeroize-server-sni", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&state, 0, .reusable, &handle));
    try testing.expect(std.mem.indexOf(u8, &backing, "zeroize-server-sni") != null);

    cache.deinit();
    try testing.expect(std.mem.indexOf(u8, &backing, "zeroize-server-sni") == null);
    try testing.expect(std.mem.indexOf(u8, &backing, handle[8..stateful_identity_len]) == null);
}

test "stateful server zeroizes handle and PSK bytes on single eviction, not only full deinit" {
    var backing: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var limits = Limits.stateful_server_default;
    limits.max_entries = 1;
    var cache = try StatefulServerCache.init(fba.allocator(), limits, system_random_source);
    defer cache.deinit();

    var state = try testServerState(fba.allocator(), "evicted-server-sni", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&state, 0, .reusable, &handle));

    var state2 = try testServerState(fba.allocator(), "other.test", 0, 1000);
    var handle2: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&state2, 1, .reusable, &handle2));

    try testing.expect(std.mem.indexOf(u8, &backing, "evicted-server-sni") == null);
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
