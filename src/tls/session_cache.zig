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
//!     an owned `pre_shared_key.ClientOfferLease` in deterministic order.
//!     Reusable tickets remain clone-only. Single-use tickets are pinned
//!     while in a live offer lease and are consumed only after the shared
//!     TLS backend reports the server-selected PSK identity index.
//!   - `StatefulServerCache` — keyed by a fixed-size unpredictable opaque
//!     handle ("TDSH" v1), owns `session.ServerRecoverableState`, and exposes
//!     an internal lease/commit/release model for single-use consumption.
//!
//! The stateful server cache exposes its lease model through the public
//! `pre_shared_key.ServerPskResolver` contract used by the shared backend:
//! successful resolution returns owned state plus a live lease, compatibility
//! and binder verification happen in `tls13_backend.zig`, and the lease is
//! committed or released from that single protocol decision point.
//!
//! ## Sequence counters
//!
//! `insertion_sequence` and `lru_sequence` (client) and `lru_sequence`
//! (server) are *ordering* counters: #364 requires overflow to renumber
//! live entries deterministically rather than silently wrap, because a
//! wrapped counter would make a freshly touched entry compare as the
//! *oldest* one and get evicted first. Renumbering is allocation-free and
//! therefore infallible, which matters for two reasons: it can never leave
//! the cache in a "partially renumbered, now out of memory" state, and it
//! can never silently fail to refresh recency for a use the caller was
//! told succeeded. The client cache renumbers by sorting `entries.items`
//! in place (`std.mem.sort` is in-place / O(log n) stack space, no heap
//! allocation) and reassigning a compact `0..n-1` range; the server cache
//! renumbers by a transient `pending_lru_sequence` scratch field on each
//! `ServerEntry` (computing every entry's rank against the others in a
//! first pass, then committing in a second pass, so no separate scratch
//! buffer is ever allocated).
//!
//! Because the client renumber physically reorders `entries.items`, no
//! code may hold a physical array index across a call that might trigger
//! it (`nextInsertionSequence`, `nextLruSequence`,
//! `reserveLruSequenceBatchLocked`) — see `lookupOffers`, which re-finds
//! each entry by its stable `entry_id` immediately after reserving a batch
//! of LRU sequence values, rather than trusting an index captured before
//! that reservation.
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
const Mutex = zig_compat.Mutex;

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

/// Reusable vs single-use ticket/session semantics. Client and stateful
/// server caches both implement `.single_use` through lease tokens that are
/// completed exactly once by the TLS backend.
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
    /// Legacy/adapter-only result value retained for callers that still
    /// surface unsupported usage from outside this cache. `ClientSessionCache`
    /// itself accepts `.single_use`.
    rejected_unsupported_usage,
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
    rejected_unsupported_usage,
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

/// Individually heap-allocated and individually wiped (see
/// `destroyClientEntry`) rather than stored inline inside
/// `ArrayListUnmanaged(ClientEntry)`: `ticket.common.resumption_psk` and
/// `ticket.ticket_nonce` are fixed-size secret arrays embedded directly in
/// this struct (not behind a separate heap pointer), so a raw bitwise copy
/// of the struct — which `ArrayListUnmanaged(ClientEntry)` growth,
/// `std.mem.sort`-based renumbering, and `swapRemove`'s tail-slot copy all
/// perform — would leave a stale, unwiped copy of those secrets sitting in
/// old/unused backing memory. Storing `*ClientEntry` instead means only
/// the *pointer* is ever copied by those operations; the pointed-to struct
/// itself is mutated in place and is wiped exactly once, when it is
/// actually destroyed.
const ClientEntry = struct {
    ticket: session.ClientTicketState = .{},
    origin: OriginDigest = [_]u8{0} ** origin_digest_len,
    usage: UsagePolicy = .reusable,
    active_lease_epoch: ?u64 = null,
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

/// Wipes and frees an individually-allocated `ClientEntry`. The only
/// correct way to release one: never `allocator.destroy` a `*ClientEntry`
/// directly elsewhere.
fn destroyClientEntry(allocator: std.mem.Allocator, entry: *ClientEntry) void {
    entry.ticket.deinit();
    secrets.secureZero(std.mem.asBytes(entry));
    if (builtin.is_test) {
        for (std.mem.asBytes(entry)) |byte| std.debug.assert(byte == 0);
        test_client_entry_destroy_count +%= 1;
    }
    allocator.destroy(entry);
}

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
    hit: pre_shared_key.ClientOfferLease,
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

/// The exact set of entries a client-side insertion will evict, computed
/// as a pure, non-mutating "dry run" before any fallible allocation is
/// attempted or any state is mutated — see `ClientSessionCache.planClientInsertionLocked`.
const ClientEvictionPlan = struct {
    victims: std.ArrayListUnmanaged(*ClientEntry) = .empty,
};

fn containsClientEntryPtr(list: []const *ClientEntry, needle: *ClientEntry) bool {
    for (list) |p| {
        if (p == needle) return true;
    }
    return false;
}

/// Bounded client-side ticket store keyed by canonical origin digest.
/// Process-shared and thread-safe: see module doc for the mutex/observer
/// discipline.
pub const ClientSessionCache = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    observer: Observer = .{},
    mutex: Mutex = .{},
    entries: std.ArrayListUnmanaged(*ClientEntry) = .empty,
    total_bytes: usize = 0,
    next_insertion_sequence: u64 = 0,
    next_lru_sequence: u64 = 0,
    next_entry_id: u64 = 0,
    next_lease_epoch: u64 = 1,
    cache_generation: u64 = 0,
    persistence_epoch: u64 = 0,
    next_persistence_token: u64 = 1,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) error{InvalidLimits}!ClientSessionCache {
        try limits.validate();
        return .{ .allocator = allocator, .limits = limits };
    }

    /// Requires quiescence: no concurrent callers and no outstanding client
    /// offer leases. Reusable returns are clone-only, but single-use hits
    /// carry callback tokens that must be finished before teardown.
    pub fn deinit(self: *ClientSessionCache) void {
        for (self.entries.items) |e| destroyClientEntry(self.allocator, e);
        self.entries.deinit(self.allocator);
        self.entries = .empty;
        self.total_bytes = 0;
    }

    /// Atomically replaces this cache's entries/counters with `temp`'s,
    /// discarding whatever this cache currently holds. `temp`'s storage is
    /// moved, not copied; `temp` is left as a fresh empty cache. Caller
    /// must hold `self.mutex` for the whole operation.
    pub fn adoptFromLocked(self: *ClientSessionCache, temp: *ClientSessionCache) void {
        for (self.entries.items) |e| destroyClientEntry(self.allocator, e);
        self.entries.deinit(self.allocator);
        self.entries = temp.entries;
        self.total_bytes = temp.total_bytes;
        self.next_insertion_sequence = temp.next_insertion_sequence;
        self.next_lru_sequence = temp.next_lru_sequence;
        self.next_entry_id = temp.next_entry_id;
        self.next_lease_epoch = temp.next_lease_epoch;
        self.cache_generation +%= 1;
        temp.entries = .empty;
        temp.total_bytes = 0;
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

    /// Removes every expired entry regardless of origin. Exposed for
    /// periodic/reload/shutdown maintenance. Unlike `storeClone`, this is
    /// always allowed to mutate immediately: there is no fallible work
    /// after it whose failure would need the removal undone.
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
    ///
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
            .rejected_handle_generation_failed, .rejected_unsupported_usage => unreachable,
        });
        return result;
    }

    /// Mutation order: locate a possible duplicate and fully validate
    /// every capacity/byte limit (pure, non-mutating) first; only once
    /// every fallible allocation this call could possibly need has
    /// already succeeded does it purge/evict/insert/advance any counter.
    /// A rejection or `storage_failed` therefore always leaves `self`
    /// byte-for-byte unchanged, including any already-expired entry that
    /// happened not to be needed for this store's eviction plan.
    fn storeLocked(
        self: *ClientSessionCache,
        cloned: *session.ClientTicketState,
        origin: OriginDigest,
        now_unix_ms: i64,
        usage: UsagePolicy,
        evicted: *usize,
    ) StoreResult {
        var dup: ?*ClientEntry = null;
        for (self.entries.items) |e| {
            if (!std.mem.eql(u8, &e.origin, &origin)) continue;
            if (!e.ticket.ticket.eql(&cloned.ticket)) continue;
            dup = e;
            break;
        }

        if (dup) |e| {
            if (e.usage == .single_use and e.active_lease_epoch != null) return .rejected_capacity;
            // Preflight the replacement fully before touching the old
            // entry: a repeated ticket identity with a larger encoded
            // payload must not be able to exceed either limit, and a
            // rejection here must leave the previous entry completely
            // intact.
            const replacement_bytes = clientAccountedBytes(cloned);
            if (replacement_bytes > self.limits.max_entry_bytes) return .rejected_capacity;
            const projected = self.total_bytes - e.bytes + replacement_bytes;
            if (projected > self.limits.max_total_bytes) return .rejected_capacity;

            // Nothing below this point can fail: commit.
            const new_insertion_seq = self.nextInsertionSequence();
            const new_lru_seq = self.nextLruSequence();
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

        // `planClientInsertionLocked` folds expiry purging and the
        // new-origin/`max_origins` admission decision into the same
        // non-mutating dry run as ordinary capacity eviction — see its
        // doc comment for why an origin's cardinality must be judged
        // against a *post-purge* view, not raw current counts.
        var plan = (self.planClientInsertionLocked(origin, new_bytes, now_unix_ms) catch return .storage_failed) orelse
            return .rejected_capacity;

        self.entries.ensureUnusedCapacity(self.allocator, 1) catch {
            plan.victims.deinit(self.allocator);
            return .storage_failed;
        };
        const new_entry = self.allocator.create(ClientEntry) catch {
            plan.victims.deinit(self.allocator);
            return .storage_failed;
        };

        // Every fallible step has now succeeded: commit the plan.
        self.commitEvictionPlanLocked(&plan, evicted);

        new_entry.* = .{
            .origin = origin,
            .usage = usage,
            .insertion_sequence = self.nextInsertionSequence(),
            .lru_sequence = self.nextLruSequence(),
            .entry_id = self.nextEntryId(),
            .bytes = new_bytes,
        };
        new_entry.ticket.moveFrom(cloned);
        self.entries.appendAssumeCapacity(new_entry);
        self.total_bytes += new_bytes;
        return .stored;
    }

    /// Recomputes exact expiry/compatibility, returns up to
    /// `pre_shared_key.max_offered_identities` fully owned clones in
    /// deterministic order (newest `insertion_sequence` first, then newer
    /// `received_at_unix_ms`, then internal entry ID), and never aliases
    /// cache storage. Every selected offer is cloned *before* any LRU
    /// recency state is reserved or applied: if cloning a later offer
    /// fails, every earlier successful clone in this call is discarded and
    /// the whole lookup reports `.storage_failed`, with `next_lru_sequence`
    /// and every entry's `lru_sequence` left completely unchanged — a
    /// lookup that returns no usable offers can never still have altered
    /// the next eviction victim. Only once every selected clone has
    /// already succeeded does the method reserve the (infallible) LRU
    /// batch and apply it, so a returned `.hit` always means every offered
    /// entry's recency was actually refreshed.
    pub fn lookupOffers(self: *ClientSessionCache, candidate: session.CandidateContext, now_unix_ms: i64) ClientLookupResult {
        const origin = originDigestFromCandidate(candidate);
        const Candidate = struct {
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
        var expired_ids: [hard_max_entries_per_origin]u64 = undefined;
        var n: usize = 0;
        var expired_count: usize = 0;
        var had_expired_removal = false;
        var had_incompatible = false;
        var storage_failed = false;

        var clones: [pre_shared_key.max_offered_identities]session.ClientTicketState =
            [_]session.ClientTicketState{.{}} ** pre_shared_key.max_offered_identities;
        var clone_entry_ids: [pre_shared_key.max_offered_identities]u64 = undefined;
        var clone_lease_epochs: [pre_shared_key.max_offered_identities]u64 = undefined;
        var clone_single_use: [pre_shared_key.max_offered_identities]bool = undefined;
        var clone_count: usize = 0;
        var lease_generation: u64 = 0;

        {
            self.mutex.lock();
            defer self.mutex.unlock();
            lease_generation = self.cache_generation;

            var i: usize = 0;
            while (i < self.entries.items.len) {
                const e = self.entries.items[i];
                if (!std.mem.eql(u8, &e.origin, &origin)) {
                    i += 1;
                    continue;
                }
                if (e.ticket.common.isExpired(now_unix_ms) and e.active_lease_epoch == null) {
                    if (expired_count < expired_ids.len) {
                        expired_ids[expired_count] = e.entry_id;
                        expired_count += 1;
                    }
                    had_expired_removal = true;
                    i += 1;
                    continue;
                }
                if (e.usage == .single_use and e.active_lease_epoch != null) {
                    i += 1;
                    continue;
                }
                if (e.usage == .single_use and self.persistence_epoch != 0) {
                    i += 1;
                    continue;
                }
                const decision = session.evaluateCompatibility(&e.ticket.common, candidate, now_unix_ms);
                if (decision.resumption == .eligible and n < buf.len) {
                    buf[n] = .{ .insertion_sequence = e.insertion_sequence, .received_at = e.ticket.received_at_unix_ms, .entry_id = e.entry_id };
                    n += 1;
                } else if (decision.resumption != .eligible) {
                    had_incompatible = true;
                }
                i += 1;
            }

            std.mem.sort(Candidate, buf[0..n], {}, Candidate.moreRecent);
            const take = @min(n, pre_shared_key.max_offered_identities);

            // Phase 1: clone every selected offer. Nothing about LRU
            // recency is touched here, so a failure partway through
            // leaves the cache's eviction order completely unaffected.
            for (buf[0..take]) |c| {
                const idx = self.findIndexByEntryId(c.entry_id) orelse continue;
                const e = self.entries.items[idx];
                if (e.usage == .single_use and e.active_lease_epoch != null) continue;
                e.ticket.cloneInto(self.allocator, &clones[clone_count]) catch {
                    storage_failed = true;
                    break;
                };
                clone_entry_ids[clone_count] = c.entry_id;
                clone_count += 1;
            }

            // Phase 2: only now — with every selected clone already
            // successful — remove staged expired entries, then reserve the
            // LRU batch (infallible, see module doc) and apply it. Re-find
            // each entry by its stable `entry_id` rather than trusting a
            // physical index captured before this point, since expiry
            // removal or reservation may reorder the backing array.
            if (!storage_failed and clone_count > 0) {
                for (expired_ids[0..expired_count]) |entry_id| {
                    const idx = self.findIndexByEntryId(entry_id) orelse continue;
                    const e = self.entries.items[idx];
                    if (!e.ticket.common.isExpired(now_unix_ms) or e.active_lease_epoch != null) continue;
                    _ = self.entries.swapRemove(idx);
                    self.total_bytes -= e.bytes;
                    destroyClientEntry(self.allocator, e);
                }

                const first_seq = self.reserveLruSequenceBatchLocked(clone_count);
                for (0..clone_count) |offset| {
                    const idx = self.findIndexByEntryId(clone_entry_ids[offset]) orelse continue;
                    const e = self.entries.items[idx];
                    e.lru_sequence = first_seq + offset;
                    if (e.usage == .single_use) {
                        e.active_lease_epoch = self.next_lease_epoch;
                        self.next_lease_epoch +%= 1;
                    }
                    clone_lease_epochs[offset] = e.active_lease_epoch orelse 0;
                    clone_single_use[offset] = e.usage == .single_use;
                }
            } else if (!storage_failed and clone_count == 0 and expired_count > 0) {
                for (expired_ids[0..expired_count]) |entry_id| {
                    const idx = self.findIndexByEntryId(entry_id) orelse continue;
                    const e = self.entries.items[idx];
                    if (!e.ticket.common.isExpired(now_unix_ms) or e.active_lease_epoch != null) continue;
                    _ = self.entries.swapRemove(idx);
                    self.total_bytes -= e.bytes;
                    destroyClientEntry(self.allocator, e);
                }
            }
        }

        if (storage_failed) {
            for (0..clone_count) |i| clones[i].deinit();
            self.observer.notify(.storage_failed);
            return .storage_failed;
        }

        var lease = pre_shared_key.ClientOfferLease{
            .cache_ctx = self,
            .cache_generation = lease_generation,
            .finishFn = finishClientOfferLeasePins,
            .dropFn = dropClientOfferLeasePin,
            .active = clone_count > 0,
        };
        for (0..clone_count) |i| {
            // Unreachable in practice: `clone_count` is bounded by `take`,
            // which is itself bounded by `max_offered_identities` — the
            // set's exact capacity.
            lease.offers.push(&clones[i]) catch unreachable;
            lease.tokens[i] = .{
                .entry_id = clone_entry_ids[i],
                .lease_epoch = clone_lease_epochs[i],
                .single_use = clone_single_use[i],
            };
        }

        const result: ClientLookupResult = if (!lease.offers.isEmpty())
            .{ .hit = lease }
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

    fn finishClientOfferLeasePins(lease: *pre_shared_key.ClientOfferLease, outcome: pre_shared_key.ClientOfferOutcome) void {
        const cache: *ClientSessionCache = @ptrCast(@alignCast(lease.cache_ctx.?));
        const selected_index: ?usize = switch (outcome) {
            .selected => |idx| idx,
            .not_selected, .aborted => null,
        };
        for (0..lease.offers.len) |i| {
            const token = lease.tokens[i];
            if (!token.single_use) continue;
            if (selected_index != null and selected_index.? == i) {
                cache.commitClientOfferLease(lease.cache_generation, token.entry_id, token.lease_epoch);
            } else {
                cache.releaseClientOfferLease(lease.cache_generation, token.entry_id, token.lease_epoch);
            }
        }
    }

    fn dropClientOfferLeasePin(lease: *pre_shared_key.ClientOfferLease, index: usize) void {
        const token = lease.tokens[index];
        if (!token.single_use) return;
        const cache: *ClientSessionCache = @ptrCast(@alignCast(lease.cache_ctx.?));
        cache.releaseClientOfferLease(lease.cache_generation, token.entry_id, token.lease_epoch);
    }

    fn commitClientOfferLease(self: *ClientSessionCache, cache_generation: u64, entry_id: u64, lease_epoch: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (cache_generation != self.cache_generation) return;
        const idx = self.findIndexByEntryId(entry_id) orelse return;
        const e = self.entries.items[idx];
        if (e.active_lease_epoch != lease_epoch) return;
        _ = self.entries.swapRemove(idx);
        self.total_bytes -= e.bytes;
        destroyClientEntry(self.allocator, e);
    }

    fn releaseClientOfferLease(self: *ClientSessionCache, cache_generation: u64, entry_id: u64, lease_epoch: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (cache_generation != self.cache_generation) return;
        const idx = self.findIndexByEntryId(entry_id) orelse return;
        const e = self.entries.items[idx];
        if (e.active_lease_epoch != lease_epoch) return;
        e.active_lease_epoch = null;
    }

    pub const BusyError = error{CacheBusy};

    pub fn beginPersistenceOperation(self: *ClientSessionCache) BusyError!u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.persistence_epoch != 0) return error.CacheBusy;
        if (self.hasOutstandingLeaseLocked()) return error.CacheBusy;
        const token = self.next_persistence_token;
        self.next_persistence_token +%= 1;
        self.persistence_epoch = token;
        return token;
    }

    pub fn endPersistenceOperation(self: *ClientSessionCache, token: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.persistence_epoch == token) self.persistence_epoch = 0;
    }

    pub fn hasOutstandingLease(self: *ClientSessionCache) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.hasOutstandingLeaseLocked();
    }

    pub fn hasOutstandingLeaseLocked(self: *ClientSessionCache) bool {
        for (self.entries.items) |e| {
            if (e.usage == .single_use and e.active_lease_epoch != null) return true;
        }
        return false;
    }

    /// Deep-clones every non-expired entry for a persistence save,
    /// including its exact insertion/LRU order. Must be called outside any
    /// persistence I/O; the returned clones are fully owned by the caller.
    pub fn cloneLiveForPersistence(
        self: *ClientSessionCache,
        allocator: std.mem.Allocator,
        now_unix_ms: i64,
    ) error{ OutOfMemory, CacheBusy }!std.ArrayListUnmanaged(PersistedClientEntry) {
        self.mutex.lock();
        if (self.hasOutstandingLeaseLocked()) {
            self.mutex.unlock();
            return error.CacheBusy;
        }

        var out: std.ArrayListUnmanaged(PersistedClientEntry) = .empty;
        var failed = false;
        out.ensureTotalCapacityPrecise(allocator, self.entries.items.len) catch {
            failed = true;
        };
        if (!failed) {
            for (self.entries.items) |e| {
                if (e.ticket.common.isExpired(now_unix_ms) and e.active_lease_epoch == null) continue;
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
            return error.OutOfMemory;
        }
        return out;
    }

    pub const RestoreError = error{OutOfMemory};

    /// Restores previously-persisted entries, enforcing current limits and
    /// discarding expired ones, while preserving each entry's original
    /// `insertion_sequence`/`lru_sequence` exactly (unlike `storeClone`,
    /// which always assigns fresh values) so post-reload offer order and
    /// eviction order match the pre-save cache. Duplicate
    /// `(origin, ticket-identity)` records — which a corrupted or hostile
    /// snapshot could contain even though the live store never produces
    /// them — are resolved deterministically: only the record with the
    /// largest `insertion_sequence` (ties broken by later array position)
    /// survives, matching the live store's own replace-on-duplicate rule.
    ///
    /// Every item is consumed (deinitialized) regardless of outcome. This
    /// method is genuinely atomic regardless of `self`'s prior state: it
    /// restores into an internal temporary cache first and adopts it into
    /// `self` only after every record has been processed without an
    /// allocation failure; on `error.OutOfMemory` `self` is left completely
    /// untouched. A record that is merely rejected for ordinary capacity
    /// reasons (e.g. the current limits are tighter than when the snapshot
    /// was taken) is *not* an error — that entry is deterministically
    /// dropped and restoration continues; this is an explicit truncation
    /// policy, not a silent failure.
    pub fn restoreClones(self: *ClientSessionCache, items: []PersistedClientEntry, now_unix_ms: i64) RestoreError!void {
        defer for (items) |*item| item.deinit();

        markDuplicateClientRecords(items);

        var temp = ClientSessionCache.init(self.allocator, self.limits) catch return error.OutOfMemory;
        defer temp.deinit();

        for (items) |*item| {
            if (item.ticket.ticket.len == 0) continue; // dropped as a duplicate loser
            if (item.ticket.common.isExpired(now_unix_ms)) continue;

            const origin = originDigestFromCommon(&item.ticket.common);
            var evicted: usize = 0;
            temp.mutex.lock();
            const result = temp.restoreLocked(&item.ticket, origin, item.usage, item.insertion_sequence, item.lru_sequence, now_unix_ms, &evicted);
            temp.mutex.unlock();
            if (result == .storage_failed) return error.OutOfMemory;
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        self.adoptFromLocked(&temp);
    }

    /// Same mutation-order discipline as `storeLocked`: every fallible
    /// allocation this restore could need completes before anything is
    /// mutated. Unlike `storeLocked`, the caller supplies the exact
    /// `insertion_sequence`/`lru_sequence` to preserve (rather than
    /// generating fresh ones) so post-reload ordering matches the
    /// pre-save cache.
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
        const new_bytes = clientAccountedBytes(ticket);
        if (new_bytes > self.limits.max_entry_bytes) return .rejected_capacity;

        var plan = (self.planClientInsertionLocked(origin, new_bytes, now_unix_ms) catch return .storage_failed) orelse
            return .rejected_capacity;

        self.entries.ensureUnusedCapacity(self.allocator, 1) catch {
            plan.victims.deinit(self.allocator);
            return .storage_failed;
        };
        const new_entry = self.allocator.create(ClientEntry) catch {
            plan.victims.deinit(self.allocator);
            return .storage_failed;
        };

        self.commitEvictionPlanLocked(&plan, evicted);

        new_entry.* = .{
            .origin = origin,
            .usage = usage,
            .insertion_sequence = insertion_sequence,
            .lru_sequence = lru_sequence,
            .entry_id = self.nextEntryId(),
            .bytes = new_bytes,
        };
        new_entry.ticket.moveFrom(ticket);
        self.entries.appendAssumeCapacity(new_entry);
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
            const e = self.entries.items[i];
            if (e.ticket.common.isExpired(now_unix_ms) and e.active_lease_epoch == null) {
                _ = self.entries.swapRemove(i);
                self.total_bytes -= e.bytes;
                destroyClientEntry(self.allocator, e);
                evicted.* += 1;
                continue;
            }
            i += 1;
        }
    }

    /// Distinct origins among entries that are *not* expired as of
    /// `now_unix_ms` — an origin whose every entry has expired doesn't
    /// count, since `planClientInsertionLocked` always plans removal of
    /// every expired entry regardless of whether eviction pressure
    /// otherwise requires it (see that function's doc comment).
    fn countDistinctLiveOrigins(self: *ClientSessionCache, now_unix_ms: i64) usize {
        var n: usize = 0;
        outer: for (self.entries.items, 0..) |e, i| {
            if (e.ticket.common.isExpired(now_unix_ms) and e.active_lease_epoch == null) continue;
            for (self.entries.items[0..i]) |prev| {
                if (prev.ticket.common.isExpired(now_unix_ms) and prev.active_lease_epoch == null) continue;
                if (std.mem.eql(u8, &prev.origin, &e.origin)) continue :outer;
            }
            n += 1;
        }
        return n;
    }

    /// A non-mutating dry run: computes the exact set of entries a new
    /// `new_bytes`-sized entry in `origin` would need this cache to evict
    /// (`null` if there is no way to make room, e.g. `new_bytes` itself
    /// exceeds the total byte budget, or `origin` would exceed
    /// `max_origins`), without touching any cache state. Called *before*
    /// any fallible allocation is attempted, so `storeLocked`/
    /// `restoreLocked` know precisely what they are about to do and can
    /// reserve exactly the right capacity before mutating anything.
    ///
    /// Every already-expired entry, anywhere in the cache, is
    /// unconditionally included in the plan — not merely *preferred* as a
    /// victim when eviction pressure happens to need one. This is what
    /// lets the `max_origins` admission decision below be judged against
    /// the cache's state *as it will be immediately after this insert
    /// commits* (i.e. with every stale entry already gone) rather than
    /// its raw current state: without this, an origin whose only entries
    /// have expired but were never purged (nothing since #364's
    /// deliberate removal of eager purging — see the module doc — forces
    /// that to happen promptly) would permanently occupy an `max_origins`
    /// slot forever, blocking every other origin indefinitely. Because
    /// removal is still only *planned* here, not applied, this stays
    /// fully compatible with the atomicity guarantee: a rejected or
    /// later-failed insert leaves every expired entry exactly as it was.
    ///
    /// Single-use client offers can pin live entries until the TLS backend
    /// reports selected/not-selected/aborted. Pinned entries remain counted
    /// against capacity and are never eviction candidates; only unpinned
    /// live entries can be planned as victims once expired entries are
    /// accounted for.
    fn planClientInsertionLocked(
        self: *ClientSessionCache,
        origin: OriginDigest,
        new_bytes: usize,
        now_unix_ms: i64,
    ) error{OutOfMemory}!?ClientEvictionPlan {
        if (new_bytes > self.limits.max_total_bytes) return null;

        var victims: std.ArrayListUnmanaged(*ClientEntry) = .empty;
        errdefer victims.deinit(self.allocator);

        var origin_count: usize = 0;
        var global_count: usize = 0;
        var global_bytes: usize = 0;
        for (self.entries.items) |e| {
            if (e.ticket.common.isExpired(now_unix_ms) and e.active_lease_epoch == null) {
                try victims.append(self.allocator, e);
                continue;
            }
            if (e.active_lease_epoch != null) continue;
            global_count += 1;
            global_bytes += e.bytes;
            if (std.mem.eql(u8, &e.origin, &origin)) origin_count += 1;
        }

        var leased_count: usize = 0;
        var leased_bytes: usize = 0;
        var origin_leased: usize = 0;
        for (self.entries.items) |e| {
            if (e.active_lease_epoch == null) continue;
            leased_count += 1;
            leased_bytes += e.bytes;
            if (std.mem.eql(u8, &e.origin, &origin)) origin_leased += 1;
        }

        if (leased_count >= self.limits.max_entries) {
            victims.deinit(self.allocator);
            return null;
        }
        if (leased_bytes + new_bytes > self.limits.max_total_bytes) {
            victims.deinit(self.allocator);
            return null;
        }
        if (origin_leased >= self.limits.max_entries_per_origin) {
            victims.deinit(self.allocator);
            return null;
        }

        if (origin_count + origin_leased == 0 and self.countDistinctLiveOrigins(now_unix_ms) >= self.limits.max_origins) {
            victims.deinit(self.allocator);
            return null;
        }

        while (origin_leased + origin_count >= self.limits.max_entries_per_origin) {
            const victim = self.findOldestLiveInOriginExcluding(origin, victims.items) orelse unreachable;
            try victims.append(self.allocator, victim);
            origin_count -= 1;
            global_count -= 1;
            global_bytes -= victim.bytes;
        }
        while (leased_count + global_count >= self.limits.max_entries or leased_bytes + global_bytes + new_bytes > self.limits.max_total_bytes) {
            const victim = self.findOldestLiveGlobalExcluding(victims.items) orelse unreachable;
            try victims.append(self.allocator, victim);
            global_count -= 1;
            global_bytes -= victim.bytes;
            if (std.mem.eql(u8, &victim.origin, &origin) and origin_count > 0) origin_count -= 1;
        }

        return ClientEvictionPlan{ .victims = victims };
    }

    /// Applies a plan already computed by `planClientInsertionLocked`:
    /// every victim is guaranteed evictable (see that function), so this
    /// is infallible. Frees the plan's own scratch list as it goes.
    fn commitEvictionPlanLocked(self: *ClientSessionCache, plan: *ClientEvictionPlan, evicted: *usize) void {
        for (plan.victims.items) |victim| {
            const idx = self.findIndexByPointer(victim) orelse unreachable;
            _ = self.entries.swapRemove(idx);
            self.total_bytes -= victim.bytes;
            destroyClientEntry(self.allocator, victim);
            evicted.* += 1;
        }
        plan.victims.deinit(self.allocator);
    }

    /// Oldest-by-LRU search among candidates that are neither already
    /// planned as a victim nor expired. Every expired entry is already
    /// unconditionally included in `excluding` by the time this is
    /// called (see `planClientInsertionLocked`), so — unlike earlier
    /// revisions of this search — no separate expiry preference is
    /// needed here: no expired candidate can remain.
    fn findOldestLiveInOriginExcluding(
        self: *ClientSessionCache,
        origin: OriginDigest,
        excluding: []const *ClientEntry,
    ) ?*ClientEntry {
        var best: ?*ClientEntry = null;
        for (self.entries.items) |e| {
            if (!std.mem.eql(u8, &e.origin, &origin)) continue;
            if (containsClientEntryPtr(excluding, e)) continue;
            if (e.active_lease_epoch != null) continue;
            if (best == null or e.lru_sequence < best.?.lru_sequence) best = e;
        }
        return best;
    }

    fn findOldestLiveGlobalExcluding(
        self: *ClientSessionCache,
        excluding: []const *ClientEntry,
    ) ?*ClientEntry {
        var best: ?*ClientEntry = null;
        for (self.entries.items) |e| {
            if (containsClientEntryPtr(excluding, e)) continue;
            if (e.active_lease_epoch != null) continue;
            if (best == null or e.lru_sequence < best.?.lru_sequence) best = e;
        }
        return best;
    }

    fn findIndexByEntryId(self: *ClientSessionCache, entry_id: u64) ?usize {
        for (self.entries.items, 0..) |e, i| {
            if (e.entry_id == entry_id) return i;
        }
        return null;
    }

    fn findIndexByPointer(self: *ClientSessionCache, needle: *ClientEntry) ?usize {
        for (self.entries.items, 0..) |e, i| {
            if (e == needle) return i;
        }
        return null;
    }

    fn nextInsertionSequence(self: *ClientSessionCache) u64 {
        if (self.next_insertion_sequence == std.math.maxInt(u64)) self.renumberInsertionSequencesLocked();
        const s = self.next_insertion_sequence;
        self.next_insertion_sequence += 1;
        return s;
    }

    fn nextLruSequence(self: *ClientSessionCache) u64 {
        return self.reserveLruSequenceBatchLocked(1);
    }

    /// Reserves `n` consecutive fresh LRU sequence values atomically
    /// (renumbering first if the remaining range is too small), returning
    /// the first. Calling `nextLruSequence` in a loop instead — one
    /// reservation per touched entry — is exactly the bug this exists to
    /// avoid: if renumbering happened partway through such a loop, values
    /// obtained before and after it would be on two different numbering
    /// scales, corrupting relative order among the entries touched in the
    /// same batch.
    ///
    /// The guard reserves room for the batch *and* the value the counter
    /// itself will hold immediately afterward, not just the batch's last
    /// value: reserving only through `first + (n - 1)` (the last value
    /// actually handed out) would let `next_lru_sequence` land exactly on
    /// `maxInt(u64)` via saturating assignment, and a *later* reservation
    /// would then see `next_lru_sequence > maxInt(u64) - m` fail to hold
    /// (maxInt is not `>` itself) and skip renumbering — handing out
    /// `maxInt(u64)` a second time. Renumbering here first instead keeps
    /// every live sequence value unique.
    fn reserveLruSequenceBatchLocked(self: *ClientSessionCache, n: u64) u64 {
        std.debug.assert(n > 0);
        if (self.next_lru_sequence > std.math.maxInt(u64) - n) self.renumberLruSequencesLocked();
        const first = self.next_lru_sequence;
        self.next_lru_sequence = first + n; // safe: the guard above proved no overflow.
        return first;
    }

    fn nextEntryId(self: *ClientSessionCache) u64 {
        const id = self.next_entry_id;
        self.next_entry_id +%= 1;
        return id;
    }

    /// Renumbers every live entry's `insertion_sequence` into a compact,
    /// gap-free range that preserves relative order, by sorting
    /// `entries.items` in place (allocation-free, infallible — see module
    /// doc) and reassigning `0..n-1`. Sorting an array of `*ClientEntry`
    /// only ever swaps pointers, never the secret-bearing `ClientEntry`
    /// structs themselves.
    fn renumberInsertionSequencesLocked(self: *ClientSessionCache) void {
        const Ctx = struct {
            fn lessThan(_: void, a: *ClientEntry, b: *ClientEntry) bool {
                if (a.insertion_sequence != b.insertion_sequence) return a.insertion_sequence < b.insertion_sequence;
                return a.entry_id < b.entry_id;
            }
        };
        std.mem.sort(*ClientEntry, self.entries.items, {}, Ctx.lessThan);
        for (self.entries.items, 0..) |e, i| e.insertion_sequence = @intCast(i);
        self.next_insertion_sequence = self.entries.items.len;
    }

    fn renumberLruSequencesLocked(self: *ClientSessionCache) void {
        const Ctx = struct {
            fn lessThan(_: void, a: *ClientEntry, b: *ClientEntry) bool {
                if (a.lru_sequence != b.lru_sequence) return a.lru_sequence < b.lru_sequence;
                return a.entry_id < b.entry_id;
            }
        };
        std.mem.sort(*ClientEntry, self.entries.items, {}, Ctx.lessThan);
        for (self.entries.items, 0..) |e, i| e.lru_sequence = @intCast(i);
        self.next_lru_sequence = self.entries.items.len;
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
    /// Transient scratch used only by `renumberLruSequencesLocked`'s
    /// allocation-free two-pass rank computation; always `null` outside
    /// of that function.
    pending_lru_sequence: ?u64 = null,
    bytes: usize = 0,
};

/// Wipes and frees an individually-allocated `ServerEntry`. The only
/// correct way to release one: never `allocator.destroy` a `*ServerEntry`
/// directly elsewhere.
fn destroyServerEntry(allocator: std.mem.Allocator, entry: *ServerEntry) void {
    entry.state.deinit();
    secrets.secureZero(std.mem.asBytes(entry));
    if (builtin.is_test) {
        for (std.mem.asBytes(entry)) |byte| std.debug.assert(byte == 0);
        test_server_entry_destroy_count +%= 1;
    }
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
    /// operation (save or load) is currently in progress: refused rather
    /// than risk a just-persisted-then-consumed ticket, or a ticket
    /// resolved against a cache that is about to be replaced by a
    /// concurrent reload.
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

const PublicServerLeaseBox = struct {
    allocator: std.mem.Allocator,
    lease: ServerLease,

    fn commit(ctx: *anyopaque) void {
        const self: *PublicServerLeaseBox = @ptrCast(@alignCast(ctx));
        self.lease.commit();
    }

    fn release(ctx: *anyopaque) void {
        const self: *PublicServerLeaseBox = @ptrCast(@alignCast(ctx));
        self.lease.release();
    }

    fn deinit(ctx: *anyopaque) void {
        const self: *PublicServerLeaseBox = @ptrCast(@alignCast(ctx));
        const allocator = self.allocator;
        secrets.secureZero(std.mem.asBytes(self));
        if (builtin.is_test) {
            for (std.mem.asBytes(self)) |byte| std.debug.assert(byte == 0);
            test_public_server_lease_box_destroy_count +%= 1;
        }
        allocator.destroy(self);
    }
};

fn completeReusableServerPsk(ctx: *anyopaque, cache_generation: u64, entry_id: u64, lease_epoch: u64) void {
    const cache: *StatefulServerCache = @ptrCast(@alignCast(ctx));
    cache.commitLease(cache_generation, entry_id, lease_epoch, false);
}

/// Public adapter from the stateful cache's internal lease model to the
/// shared TLS backend resolver contract.
pub const StatefulServerPskResolverAdapter = struct {
    cache: *StatefulServerCache,
    allocator: std.mem.Allocator,
    now_unix_ms: i64,

    pub fn resolver(self: *StatefulServerPskResolverAdapter) pre_shared_key.ServerPskResolver {
        return .{
            .ctx = self,
            .nowUnixMsFn = nowUnixMs,
            .resolveFn = resolve,
        };
    }

    fn nowUnixMs(ctx: *anyopaque) i64 {
        const self: *StatefulServerPskResolverAdapter = @ptrCast(@alignCast(ctx));
        return self.now_unix_ms;
    }

    fn resolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
        const self: *StatefulServerPskResolverAdapter = @ptrCast(@alignCast(ctx));
        return resolveStatefulServerPsk(self.cache, self.allocator, identity, self.now_unix_ms);
    }
};

pub fn resolveStatefulServerPsk(
    cache: *StatefulServerCache,
    allocator: std.mem.Allocator,
    identity: []const u8,
    now_unix_ms: i64,
) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
    var result = cache.resolveLease(identity, now_unix_ms);
    switch (result) {
        .hit => |*hit| {
            if (!hit.lease.single_use) {
                var state: session.ServerRecoverableState = .{};
                state.moveFrom(&hit.state);
                return .{ .hit = .{
                    .state = state,
                    .lease = pre_shared_key.ServerPskLease.initNoop(),
                    .on_selected = .{
                        .ctx = hit.lease.cache,
                        .arg0 = hit.lease.cache_generation,
                        .arg1 = hit.lease.entry_id,
                        .arg2 = hit.lease.lease_epoch,
                        .completeFn = completeReusableServerPsk,
                    },
                    .current_process_stateful = true,
                } };
            }

            const box = allocator.create(PublicServerLeaseBox) catch {
                result.deinit();
                return error.ResolverFailed;
            };
            box.* = .{ .allocator = allocator, .lease = hit.lease };
            hit.lease.active = false;

            var state: session.ServerRecoverableState = .{};
            state.moveFrom(&hit.state);
            return .{ .hit = .{
                .state = state,
                .lease = pre_shared_key.ServerPskLease.initOwned(
                    box,
                    PublicServerLeaseBox.commit,
                    PublicServerLeaseBox.release,
                    PublicServerLeaseBox.deinit,
                ),
                .current_process_stateful = true,
            } };
        },
        .miss, .expired, .busy => return .miss,
        .storage_failed => return error.ResolverFailed,
    }
}

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
    mutex: Mutex = .{},
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
    /// so a lease resolved before a reload can never act on an unrelated
    /// post-reload entry that happens to reuse the same `entry_id`.
    cache_generation: u64 = 0,
    /// Non-zero while a save or load is in progress (see
    /// `beginPersistenceOperation`/`endPersistenceOperation`); the exact
    /// value is the token of the operation currently holding it, so `end`
    /// can only ever clear its own operation's guard, never a different,
    /// overlapping one's. `resolveLease` refuses to hand out a *new*
    /// single-use lease while this is set, closing the race where a
    /// ticket is resolved-and-committed after being cloned into a
    /// snapshot but before that snapshot reaches durable storage (which
    /// would otherwise let a restart resurrect an already-consumed
    /// ticket), and preventing a save and a load (or two saves) on the
    /// same cache from overlapping and silently clobbering each other.
    persistence_epoch: u64 = 0,
    next_persistence_token: u64 = 1,

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
    /// for the whole operation.
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
                // `lru_sequence: null` means "assign a fresh value at
                // commit time" (see `insertLocked`) — deferred rather
                // than reserved here, so a later rejection/failure never
                // advances/renumbers the counter for an insert that did
                // not actually happen.
                break :blk self.insertLocked(state, handle, origin, usage, now_unix_ms, bytes, null, &evicted);
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
            .replaced, .rejected_unsupported_usage => unreachable,
        });
        return result;
    }

    /// Distinct origins with at least one entry that would survive a
    /// purge as of `now_unix_ms` — leased entries always survive
    /// (regardless of expiry, since leased entries are never purged), an
    /// unleased entry survives only if it is not yet expired. An origin
    /// whose every entry has expired-and-is-unleased doesn't count, since
    /// `planInsertionLocked` always plans removal of every such entry
    /// regardless of whether eviction pressure otherwise requires it (see
    /// that function's doc comment).
    fn countDistinctLiveOriginsLocked(self: *StatefulServerCache, now_unix_ms: i64) usize {
        var n: usize = 0;
        var it = self.origin_index.iterator();
        while (it.next()) |kv| {
            for (kv.value_ptr.items) |id| {
                const e = self.entries.get(id) orelse continue;
                if (e.active_lease_epoch != null or !e.state.common.isExpired(now_unix_ms)) {
                    n += 1;
                    break;
                }
            }
        }
        return n;
    }

    /// Oldest-by-LRU search among unleased candidates that are neither
    /// already planned as a victim nor expired. Every expired-and-unleased
    /// entry is already unconditionally included in `excluding` by the
    /// time this is called (see `planInsertionLocked`), so no separate
    /// expiry preference is needed here: no expired candidate can remain.
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
    /// insertion will need to evict, plus whether the target origin's
    /// bucket will still exist afterward. Called *before* any fallible
    /// allocation is attempted, so `insertLocked` knows precisely what it
    /// is about to do and can reserve exactly the right capacity before
    /// mutating anything.
    ///
    /// Every already-expired, unleased entry anywhere in the cache is
    /// unconditionally included in the plan — not merely *preferred* as a
    /// victim when eviction pressure happens to need one (leased entries
    /// are never purged, matching `purgeExpiredAllLocked`'s own
    /// discipline). This is what lets the `max_origins` admission
    /// decision below be judged against the cache's state *as it will be
    /// immediately after this insert commits*, rather than its raw
    /// current state: without this, an origin whose only entries have
    /// expired but were never purged would permanently occupy an
    /// `max_origins` slot forever, blocking every other origin
    /// indefinitely. Because removal is still only *planned* here, not
    /// applied, this stays fully compatible with the atomicity guarantee:
    /// a rejected or later-failed insert leaves every expired entry
    /// exactly as it was.
    fn planInsertionLocked(self: *StatefulServerCache, origin: OriginDigest, new_bytes: usize, now_unix_ms: i64) error{OutOfMemory}!?EvictionPlan {
        var victims: std.ArrayListUnmanaged(u64) = .empty;
        errdefer victims.deinit(self.allocator);

        var leased_count: usize = 0;
        var leased_bytes: usize = 0;
        var origin_leased: usize = 0;
        var global_count: usize = 0;
        var global_bytes: usize = 0;
        var origin_count: usize = 0;

        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            const in_origin = std.mem.eql(u8, &e.origin, &origin);
            if (e.active_lease_epoch != null) {
                leased_count += 1;
                leased_bytes += e.bytes;
                if (in_origin) origin_leased += 1;
                continue;
            }
            if (e.state.common.isExpired(now_unix_ms)) {
                try victims.append(self.allocator, kv.key_ptr.*);
                continue;
            }
            global_count += 1;
            global_bytes += e.bytes;
            if (in_origin) origin_count += 1;
        }

        // Leased entries are never eviction candidates: if the cache
        // could never get under its count/byte/per-origin limits using
        // only unleased entries as victims (this insert's own new entry
        // included), reject before anything is mutated.
        if (leased_count >= self.limits.max_entries) {
            victims.deinit(self.allocator);
            return null;
        }
        if (leased_bytes + new_bytes > self.limits.max_total_bytes) {
            victims.deinit(self.allocator);
            return null;
        }
        if (origin_leased >= self.limits.max_entries_per_origin) {
            victims.deinit(self.allocator);
            return null;
        }

        const is_new_origin = (origin_count + origin_leased) == 0;
        if (is_new_origin and self.countDistinctLiveOriginsLocked(now_unix_ms) >= self.limits.max_origins) {
            victims.deinit(self.allocator);
            return null;
        }

        // Enforce every limit against the *combined* leased+unleased
        // totals that will actually survive — leased entries occupy real
        // count/byte/per-origin budget even though they can never be
        // evicted. Comparing only the unleased totals here (as an
        // earlier revision of this function did) let a mix of leased and
        // unleased entries commit above every configured bound: leased
        // entries alone not yet being at the limit doesn't mean there's
        // room for *this* new entry once the still-live unleased entries
        // are also counted.
        while (origin_leased + origin_count >= self.limits.max_entries_per_origin) {
            const victim = self.findOldestUnleasedInOriginExcluding(origin, victims.items) orelse unreachable;
            try victims.append(self.allocator, victim);
            origin_count -= 1;
            global_count -= 1;
            global_bytes -= self.entries.get(victim).?.bytes;
        }
        while (leased_count + global_count >= self.limits.max_entries or
            leased_bytes + global_bytes + new_bytes > self.limits.max_total_bytes)
        {
            const victim = self.findOldestUnleasedGlobalExcluding(victims.items) orelse unreachable;
            try victims.append(self.allocator, victim);
            global_count -= 1;
            global_bytes -= self.entries.get(victim).?.bytes;
            if (std.mem.eql(u8, &self.entries.get(victim).?.origin, &origin) and origin_count > 0) origin_count -= 1;
        }

        return EvictionPlan{ .victims = victims, .origin_bucket_survives = (origin_count + origin_leased) > 0 };
    }

    /// Mutation order: no expiry purge and no LRU-sequence reservation
    /// happen until every fallible allocation this insert could possibly
    /// need has already succeeded — see `planInsertionLocked`'s doc
    /// comment for how expired entries are folded into that plan while
    /// still leaving a rejected/failed insert's state completely
    /// unchanged.
    ///
    /// `lru_sequence` is `null` for a fresh insertion (a value is reserved
    /// — infallibly — only once the insert is guaranteed to commit) or a
    /// caller-supplied value so `restoreEntries` can preserve a persisted
    /// entry's original recency instead of it always appearing
    /// most-recent.
    fn insertLocked(
        self: *StatefulServerCache,
        state: *session.ServerRecoverableState,
        handle: [stateful_identity_len]u8,
        origin: OriginDigest,
        usage: UsagePolicy,
        now_unix_ms: i64,
        bytes: usize,
        lru_sequence: ?u64,
        evicted: *usize,
    ) StoreResult {
        const handle_digest = digestHandle(&handle);
        if (self.handle_index.contains(handle_digest)) return .rejected_capacity;

        // `planInsertionLocked` folds expiry purging and the
        // new-origin/`max_origins` admission decision into the same
        // non-mutating dry run as ordinary capacity eviction — see its
        // doc comment for why an origin's cardinality must be judged
        // against a *post-purge* view, not raw current counts.
        var plan = (self.planInsertionLocked(origin, bytes, now_unix_ms) catch return .storage_failed) orelse
            return .rejected_capacity;

        // Reserve every allocation this insert could possibly need before
        // mutating anything: the new entry's own storage, the map/index
        // capacity, and either the existing origin bucket's capacity (if
        // the plan says it survives) or a freshly detached, capacity-
        // reserved bucket (if eviction will empty-and-remove it, or it
        // doesn't exist yet) — never the *existing* bucket's capacity in
        // that second case, since eviction (driven by `plan.victims`,
        // applied below) can delete that exact bucket. `StoreResult` is a
        // plain enum, not an error union, so a bare `return` here would
        // never trigger `errdefer`; every failure path below explicitly
        // releases whatever this function has already reserved.
        self.entries.ensureUnusedCapacity(self.allocator, 1) catch {
            plan.deinit(self.allocator);
            return .storage_failed;
        };
        self.handle_index.ensureUnusedCapacity(self.allocator, 1) catch {
            plan.deinit(self.allocator);
            return .storage_failed;
        };

        const new_entry = self.allocator.create(ServerEntry) catch {
            plan.deinit(self.allocator);
            return .storage_failed;
        };

        var detached_bucket: ?OriginBucket = null;
        if (plan.origin_bucket_survives) {
            const bucket = self.origin_index.getPtr(origin) orelse unreachable;
            bucket.ensureUnusedCapacity(self.allocator, 1) catch {
                self.allocator.destroy(new_entry);
                plan.deinit(self.allocator);
                return .storage_failed;
            };
        } else {
            var fresh: OriginBucket = .empty;
            fresh.ensureUnusedCapacity(self.allocator, 1) catch {
                self.allocator.destroy(new_entry);
                plan.deinit(self.allocator);
                return .storage_failed;
            };
            detached_bucket = fresh;
        }
        self.origin_index.ensureUnusedCapacity(self.allocator, 1) catch {
            if (detached_bucket) |*b| b.deinit(self.allocator);
            self.allocator.destroy(new_entry);
            plan.deinit(self.allocator);
            return .storage_failed;
        };

        // Every fallible step has now succeeded: apply the precomputed
        // plan (this is also where any expired-but-not-yet-purged victims
        // it selected are actually removed — see the doc comment above)
        // and commit the new entry. LRU-sequence assignment is
        // allocation-free and therefore infallible (see module doc), so
        // deferring it to this exact point — rather than reserving it
        // before this insert was known to succeed — cannot leave the
        // counter advanced/renumbered for a rejected/failed insert.
        for (plan.victims.items) |id| {
            self.removeEntryLocked(id);
            evicted.* += 1;
        }
        plan.victims.deinit(self.allocator);

        const entry_id = self.next_entry_id;
        self.next_entry_id +%= 1;
        const final_lru_sequence = lru_sequence orelse self.reserveFreshLruSequenceLocked();
        new_entry.* = .{ .origin = origin, .handle = handle, .usage = usage, .lru_sequence = final_lru_sequence, .bytes = bytes };
        new_entry.state.moveFrom(state);
        self.entries.putAssumeCapacity(entry_id, new_entry);
        self.handle_index.putAssumeCapacity(handle_digest, entry_id);

        if (detached_bucket) |*fresh| {
            self.origin_index.putAssumeCapacityNoClobber(origin, fresh.*);
        }
        self.origin_index.getPtr(origin).?.appendAssumeCapacity(entry_id);

        self.total_bytes += bytes;
        // Track the high-water mark with *saturating* arithmetic: only
        // relevant when `lru_sequence` was caller-supplied (a restore) and
        // already at/near `maxInt(u64)`.
        if (final_lru_sequence >= self.next_lru_sequence) self.next_lru_sequence = final_lru_sequence +| 1;
        return .stored;
    }

    /// Resolves `identity` to owned state plus a lease, without evaluating
    /// any compatibility policy: the caller (the shared #362/#365 path)
    /// evaluates `session.evaluateCompatibility` on the returned state and
    /// then commits or releases the lease. A single-use entry already
    /// leased by a concurrent resolution, or one that would require a
    /// *new* lease while a persistence operation is in progress, reports a
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
            if (single_use and self.persistence_epoch != 0) {
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
    /// eviction. This can no longer fail (see module doc), so a
    /// binder-verified reuse always becomes MRU.
    fn commitLease(self: *StatefulServerCache, cache_generation: u64, entry_id: u64, lease_epoch: u64, single_use: bool) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (cache_generation != self.cache_generation) return;
        const e = self.entries.get(entry_id) orelse return;
        if (single_use) {
            if (e.active_lease_epoch != lease_epoch) return;
            self.removeEntryLocked(entry_id);
        } else {
            e.lru_sequence = self.reserveFreshLruSequenceLocked();
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

    pub const BusyError = error{CacheBusy};

    /// Begins a persistence operation (save or load), returning a token
    /// that must be passed to `endPersistenceOperation` exactly once when
    /// the operation (including all of its backend I/O) is complete,
    /// success or failure. Fails with `error.CacheBusy` if either:
    ///
    ///   - another persistence operation on this cache is already in
    ///     progress (saves and loads on the same cache are never allowed
    ///     to overlap, so a consumed single-use ticket can never be
    ///     resurrected by a second operation racing the first, and a load
    ///     can never be overtaken by a concurrent save or vice versa); or
    ///   - a single-use lease acquired *before* this call is still
    ///     outstanding.
    ///
    /// The second condition closes a race `resolveLease`'s in-progress
    /// check alone cannot: once this call succeeds, `resolveLease` refuses
    /// to start any *new* single-use lease for as long as the token is
    /// held, but nothing stops an already-outstanding lease (acquired
    /// before this call) from being committed *during* a load — including
    /// after the load has already decoded/validated a snapshot but before
    /// it swaps that snapshot in. A snapshot loaded from durable storage
    /// necessarily reflects state from *before* that in-flight commit, so
    /// adopting it could resurrect the ticket the commit just consumed.
    /// Refusing to begin at all while any single-use lease is outstanding
    /// guarantees that, by the time a persistence operation is running,
    /// no consumption can race it: no lease can start (blocked by the
    /// token) and none was already outstanding (checked here).
    pub fn beginPersistenceOperation(self: *StatefulServerCache) BusyError!u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.persistence_epoch != 0) return error.CacheBusy;
        if (self.hasOutstandingLeaseLocked()) return error.CacheBusy;
        const token = self.next_persistence_token;
        self.next_persistence_token +%= 1;
        self.persistence_epoch = token;
        return token;
    }

    /// Clears the persistence guard, but only if `token` is still the
    /// active operation's token — ending one (already-superseded) call
    /// can therefore never clear a different, later operation's guard.
    pub fn endPersistenceOperation(self: *StatefulServerCache, token: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.persistence_epoch == token) self.persistence_epoch = 0;
    }

    pub const PersistenceError = error{ OutOfMemory, CacheBusy };

    /// Deep-clones every non-expired entry for a persistence save,
    /// including its exact `lru_sequence`. Refuses with `error.CacheBusy`
    /// if any single-use entry is currently leased. Callers must already
    /// hold a token from `beginPersistenceOperation` for the whole
    /// save/load, not just this clone step.
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
            return error.OutOfMemory;
        }
        return out;
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
    /// Every item is consumed regardless of outcome. This method is
    /// genuinely atomic regardless of `self`'s prior state: it restores
    /// into an internal temporary cache first and adopts it into `self`
    /// (bumping `cache_generation`) only after every record has been
    /// processed without an allocation failure; on `error.OutOfMemory` or
    /// `error.DuplicateHandle` `self` is left completely untouched. An
    /// ordinary capacity rejection for an individual record is an
    /// explicit, documented truncation, not an error — see
    /// `ClientSessionCache.restoreClones`.
    pub fn restoreEntries(self: *StatefulServerCache, items: []PersistedServerEntry, now_unix_ms: i64) RestoreError!void {
        defer for (items) |*item| item.deinit();

        if (hasDuplicateServerHandle(items)) return error.DuplicateHandle;

        var temp = StatefulServerCache.init(self.allocator, self.limits, self.random) catch return error.OutOfMemory;
        defer temp.deinit();

        for (items) |*item| {
            if (item.state.common.isExpired(now_unix_ms)) continue;
            if (!isValidStatefulHandleShape(&item.handle)) continue;

            const bytes = serverAccountedBytes(&item.state);
            const origin = originDigestFromCommon(&item.state.common);
            var evicted: usize = 0;
            temp.mutex.lock();
            const result = temp.insertLocked(&item.state, item.handle, origin, item.usage, now_unix_ms, bytes, @as(?u64, item.lru_sequence), &evicted);
            temp.mutex.unlock();
            if (result == .storage_failed) return error.OutOfMemory;
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        self.adoptFromLocked(&temp);
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

    /// Unconditionally removes and wipes a just-inserted entry by its
    /// bearer handle, regardless of lease/expiry state (#488 issuance
    /// rollback: a handle `insertMove` already committed to storage but
    /// whose `NewSessionTicket` never reached the peer — e.g. post-
    /// handshake emission/queueing failed — must not remain resolvable, or
    /// a client could never plausibly have received; a peer can never
    /// legitimately offer it). Ordinary consumption after successful
    /// delivery goes through `resolveLease`/`ServerLease`, never this. A
    /// handle that is not present (already rolled back, evicted, or never
    /// stored) is a silent no-op.
    pub fn revokeHandle(self: *StatefulServerCache, handle: *const [stateful_identity_len]u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry_id = self.handle_index.get(digestHandle(handle)) orelse return;
        self.removeEntryLocked(entry_id);
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
    /// if the counter is about to overflow. Allocation-free and therefore
    /// infallible (see module doc).
    fn reserveFreshLruSequenceLocked(self: *StatefulServerCache) u64 {
        if (self.next_lru_sequence == std.math.maxInt(u64)) self.renumberLruSequencesLocked();
        const s = self.next_lru_sequence;
        self.next_lru_sequence += 1;
        return s;
    }

    /// Renumbers every live entry's `lru_sequence` into a compact, gap-free
    /// range that preserves relative order, without allocating any scratch
    /// storage: each entry's rank (how many other entries compare as
    /// older) is computed into its own transient `pending_lru_sequence`
    /// field in a first pass — reading only the *original* `lru_sequence`
    /// values, never a value another entry has already been rewritten to
    /// — and only committed into `lru_sequence` in a second pass. Mutating
    /// `lru_sequence` directly during the ranking pass would let later
    /// comparisons mix pre- and post-renumber scales, silently corrupting
    /// relative order.
    fn renumberLruSequencesLocked(self: *StatefulServerCache) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const e = kv.value_ptr.*;
            var rank: u64 = 0;
            var it2 = self.entries.iterator();
            while (it2.next()) |kv2| {
                if (kv2.key_ptr.* == kv.key_ptr.*) continue;
                const other = kv2.value_ptr.*;
                if (other.lru_sequence < e.lru_sequence or
                    (other.lru_sequence == e.lru_sequence and kv2.key_ptr.* < kv.key_ptr.*))
                {
                    rank += 1;
                }
            }
            e.pending_lru_sequence = rank;
        }

        var total: u64 = 0;
        var it3 = self.entries.iterator();
        while (it3.next()) |kv| {
            const e = kv.value_ptr.*;
            e.lru_sequence = e.pending_lru_sequence.?;
            e.pending_lru_sequence = null;
            total += 1;
        }
        self.next_lru_sequence = total;
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

var test_client_entry_destroy_count: u64 = 0;
var test_server_entry_destroy_count: u64 = 0;
var test_public_server_lease_box_destroy_count: u64 = 0;

const fuzz_cache_limits: Limits = .{
    .max_entries = 4,
    .max_origins = 2,
    .max_entries_per_origin = 2,
    .max_entry_bytes = 2 * 1024,
    .max_total_bytes = 4 * 1024,
};
const fuzz_max_operations: usize = 16;
const fuzz_max_live_client_leases: usize = 2;
const fuzz_max_live_server_leases: usize = 2;
const fuzz_max_persisted_records: usize = 6;
const fuzz_max_oom_fail_index: usize = 64;
const fuzz_clock_steps = [_]i64{ 0, 1, 999, 1000, 10_000 };

fn fingerprintBytes(domain: []const u8, bytes: []const u8) [32]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(domain);
    var len: [8]u8 = undefined;
    std.mem.writeInt(u64, &len, @intCast(bytes.len), .big);
    hasher.update(&len);
    hasher.update(bytes);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

fn fingerprintClientTicket(ticket: *const session.ClientTicketState) ![32]u8 {
    var encoded: [4096]u8 = undefined;
    const bytes = try session.encodeClient(ticket, session.Limits.default, &encoded);
    return fingerprintBytes("TARDIGRADE-TEST-CLIENT-CACHE-FINGERPRINT-V1", bytes);
}

fn fingerprintServerState(state: *const session.ServerRecoverableState) ![32]u8 {
    var encoded: [4096]u8 = undefined;
    const bytes = try session.encodeServer(state, session.Limits.default, &encoded);
    return fingerprintBytes("TARDIGRADE-TEST-SERVER-CACHE-FINGERPRINT-V1", bytes);
}

const ClientSnapshotEntry = struct {
    ptr: usize,
    entry_id: u64,
    origin: OriginDigest,
    usage: UsagePolicy,
    active_lease_epoch: ?u64,
    insertion_sequence: u64,
    lru_sequence: u64,
    bytes: usize,
    fingerprint: [32]u8,

    fn wipe(self: *ClientSnapshotEntry) void {
        secrets.secureZero(std.mem.asBytes(self));
    }
};

const ClientCacheState = struct {
    entries_len: usize,
    entries_ptr: usize,
    total_bytes: usize,
    next_insertion_sequence: u64,
    next_lru_sequence: u64,
    next_entry_id: u64,
    next_lease_epoch: u64,
    cache_generation: u64,
    persistence_epoch: u64,
    next_persistence_token: u64,
    entries: [fuzz_cache_limits.max_entries]ClientSnapshotEntry = undefined,

    fn capture(cache: *ClientSessionCache) !ClientCacheState {
        cache.mutex.lock();
        defer cache.mutex.unlock();
        var out = ClientCacheState{
            .entries_len = cache.entries.items.len,
            .entries_ptr = @intFromPtr(cache.entries.items.ptr),
            .total_bytes = cache.total_bytes,
            .next_insertion_sequence = cache.next_insertion_sequence,
            .next_lru_sequence = cache.next_lru_sequence,
            .next_entry_id = cache.next_entry_id,
            .next_lease_epoch = cache.next_lease_epoch,
            .cache_generation = cache.cache_generation,
            .persistence_epoch = cache.persistence_epoch,
            .next_persistence_token = cache.next_persistence_token,
        };
        try testing.expect(cache.entries.items.len <= out.entries.len);
        for (cache.entries.items, 0..) |entry, i| {
            out.entries[i] = .{
                .ptr = @intFromPtr(entry),
                .entry_id = entry.entry_id,
                .origin = entry.origin,
                .usage = entry.usage,
                .active_lease_epoch = entry.active_lease_epoch,
                .insertion_sequence = entry.insertion_sequence,
                .lru_sequence = entry.lru_sequence,
                .bytes = entry.bytes,
                .fingerprint = try fingerprintClientTicket(&entry.ticket),
            };
        }
        return out;
    }

    fn expectEqual(self: *const ClientCacheState, other: *const ClientCacheState) !void {
        try testing.expectEqual(self.entries_len, other.entries_len);
        try testing.expectEqual(self.entries_ptr, other.entries_ptr);
        try testing.expectEqual(self.total_bytes, other.total_bytes);
        try testing.expectEqual(self.next_insertion_sequence, other.next_insertion_sequence);
        try testing.expectEqual(self.next_lru_sequence, other.next_lru_sequence);
        try testing.expectEqual(self.next_entry_id, other.next_entry_id);
        try testing.expectEqual(self.next_lease_epoch, other.next_lease_epoch);
        try testing.expectEqual(self.cache_generation, other.cache_generation);
        try testing.expectEqual(self.persistence_epoch, other.persistence_epoch);
        try testing.expectEqual(self.next_persistence_token, other.next_persistence_token);
        for (0..self.entries_len) |i| try testing.expectEqualDeep(self.entries[i], other.entries[i]);
    }

    fn deinit(self: *ClientCacheState) void {
        for (0..self.entries_len) |i| self.entries[i].wipe();
        self.entries_len = 0;
    }
};

const ServerSnapshotEntry = struct {
    ptr: usize,
    entry_id: u64,
    origin: OriginDigest,
    usage: UsagePolicy,
    active_lease_epoch: ?u64,
    lru_sequence: u64,
    pending_lru_sequence: ?u64,
    bytes: usize,
    handle_fingerprint: [32]u8,
    state_fingerprint: [32]u8,

    fn wipe(self: *ServerSnapshotEntry) void {
        secrets.secureZero(std.mem.asBytes(self));
    }
};

const ServerCacheState = struct {
    entries_count: usize,
    handle_index_count: usize,
    origin_index_count: usize,
    total_bytes: usize,
    next_entry_id: u64,
    next_lru_sequence: u64,
    next_lease_epoch: u64,
    cache_generation: u64,
    persistence_epoch: u64,
    next_persistence_token: u64,
    entries: [fuzz_cache_limits.max_entries]ServerSnapshotEntry = undefined,
    handle_index: [fuzz_cache_limits.max_entries]struct { digest: HandleDigest, entry_id: u64 } = undefined,
    origin_members: [fuzz_cache_limits.max_entries]struct { origin: OriginDigest, entry_id: u64 } = undefined,
    origin_member_count: usize = 0,

    fn entryLess(_: void, a: ServerSnapshotEntry, b: ServerSnapshotEntry) bool {
        return a.entry_id < b.entry_id;
    }

    fn capture(cache: *StatefulServerCache) !ServerCacheState {
        cache.mutex.lock();
        defer cache.mutex.unlock();
        var out = ServerCacheState{
            .entries_count = cache.entries.count(),
            .handle_index_count = cache.handle_index.count(),
            .origin_index_count = cache.origin_index.count(),
            .total_bytes = cache.total_bytes,
            .next_entry_id = cache.next_entry_id,
            .next_lru_sequence = cache.next_lru_sequence,
            .next_lease_epoch = cache.next_lease_epoch,
            .cache_generation = cache.cache_generation,
            .persistence_epoch = cache.persistence_epoch,
            .next_persistence_token = cache.next_persistence_token,
        };
        try testing.expect(cache.entries.count() <= out.entries.len);
        var it = cache.entries.iterator();
        var i: usize = 0;
        while (it.next()) |kv| : (i += 1) {
            const entry = kv.value_ptr.*;
            out.entries[i] = .{
                .ptr = @intFromPtr(entry),
                .entry_id = kv.key_ptr.*,
                .origin = entry.origin,
                .usage = entry.usage,
                .active_lease_epoch = entry.active_lease_epoch,
                .lru_sequence = entry.lru_sequence,
                .pending_lru_sequence = entry.pending_lru_sequence,
                .bytes = entry.bytes,
                .handle_fingerprint = fingerprintBytes("TARDIGRADE-TEST-SERVER-HANDLE-FINGERPRINT-V1", &entry.handle),
                .state_fingerprint = try fingerprintServerState(&entry.state),
            };
        }
        std.mem.sort(ServerSnapshotEntry, out.entries[0..out.entries_count], {}, ServerCacheState.entryLess);

        var hi = cache.handle_index.iterator();
        i = 0;
        while (hi.next()) |kv| : (i += 1) {
            try testing.expect(i < out.handle_index.len);
            out.handle_index[i] = .{ .digest = kv.key_ptr.*, .entry_id = kv.value_ptr.* };
        }

        var oi = cache.origin_index.iterator();
        while (oi.next()) |kv| {
            for (kv.value_ptr.items) |entry_id| {
                try testing.expect(out.origin_member_count < out.origin_members.len);
                out.origin_members[out.origin_member_count] = .{ .origin = kv.key_ptr.*, .entry_id = entry_id };
                out.origin_member_count += 1;
            }
        }
        return out;
    }

    fn expectEqual(self: *const ServerCacheState, other: *const ServerCacheState) !void {
        try testing.expectEqual(self.entries_count, other.entries_count);
        try testing.expectEqual(self.handle_index_count, other.handle_index_count);
        try testing.expectEqual(self.origin_index_count, other.origin_index_count);
        try testing.expectEqual(self.total_bytes, other.total_bytes);
        try testing.expectEqual(self.next_entry_id, other.next_entry_id);
        try testing.expectEqual(self.next_lru_sequence, other.next_lru_sequence);
        try testing.expectEqual(self.next_lease_epoch, other.next_lease_epoch);
        try testing.expectEqual(self.cache_generation, other.cache_generation);
        try testing.expectEqual(self.persistence_epoch, other.persistence_epoch);
        try testing.expectEqual(self.next_persistence_token, other.next_persistence_token);
        try testing.expectEqual(self.origin_member_count, other.origin_member_count);
        for (0..self.entries_count) |i| try testing.expectEqualDeep(self.entries[i], other.entries[i]);
        for (0..self.handle_index_count) |i| try testing.expectEqualDeep(self.handle_index[i], other.handle_index[i]);
        for (0..self.origin_member_count) |i| try testing.expectEqualDeep(self.origin_members[i], other.origin_members[i]);
    }

    fn deinit(self: *ServerCacheState) void {
        for (0..self.entries_count) |i| self.entries[i].wipe();
        self.entries_count = 0;
    }
};

fn expectClientCacheInvariants(cache: *ClientSessionCache) !void {
    cache.mutex.lock();
    defer cache.mutex.unlock();
    try testing.expect(cache.entries.items.len <= cache.limits.max_entries);
    var total_bytes: usize = 0;
    var distinct_origins: usize = 0;
    for (cache.entries.items, 0..) |entry, i| {
        try testing.expect(entry.bytes <= cache.limits.max_entry_bytes);
        total_bytes += entry.bytes;
        try testing.expect(entry.active_lease_epoch == null or entry.usage == .single_use);
        var origin_seen_before = false;
        var per_origin: usize = 0;
        for (cache.entries.items, 0..) |other, j| {
            if (i != j) {
                try testing.expect(entry.entry_id != other.entry_id);
                try testing.expect(entry.insertion_sequence != other.insertion_sequence);
                try testing.expect(entry.lru_sequence != other.lru_sequence);
            }
            if (std.mem.eql(u8, &entry.origin, &other.origin)) {
                per_origin += 1;
                if (j < i) origin_seen_before = true;
                if (i != j) try testing.expect(!entry.ticket.ticket.eql(&other.ticket.ticket));
            }
        }
        if (!origin_seen_before) distinct_origins += 1;
        try testing.expect(per_origin <= cache.limits.max_entries_per_origin);
    }
    try testing.expectEqual(total_bytes, cache.total_bytes);
    try testing.expect(cache.total_bytes <= cache.limits.max_total_bytes);
    try testing.expect(distinct_origins <= cache.limits.max_origins);
}

fn expectServerCacheInvariants(cache: *StatefulServerCache) !void {
    cache.mutex.lock();
    defer cache.mutex.unlock();
    try testing.expect(cache.entries.count() <= cache.limits.max_entries);
    try testing.expectEqual(cache.entries.count(), cache.handle_index.count());
    var total_bytes: usize = 0;
    var origin_members: usize = 0;
    var it = cache.entries.iterator();
    while (it.next()) |kv| {
        const entry_id = kv.key_ptr.*;
        const entry = kv.value_ptr.*;
        try testing.expect(entry.bytes <= cache.limits.max_entry_bytes);
        try testing.expect(entry.pending_lru_sequence == null);
        try testing.expect(entry.active_lease_epoch == null or entry.usage == .single_use);
        total_bytes += entry.bytes;
        try testing.expectEqual(entry_id, cache.handle_index.get(digestHandle(&entry.handle)).?);
        const bucket = cache.origin_index.get(entry.origin).?;
        try testing.expect(std.mem.indexOfScalar(u64, bucket.items, entry_id) != null);
        var it2 = cache.entries.iterator();
        while (it2.next()) |kv2| {
            if (entry_id == kv2.key_ptr.*) continue;
            const other = kv2.value_ptr.*;
            try testing.expect(entry.lru_sequence != other.lru_sequence);
            try testing.expect(!std.mem.eql(u8, &entry.handle, &other.handle));
        }
    }
    try testing.expectEqual(total_bytes, cache.total_bytes);
    try testing.expect(cache.total_bytes <= cache.limits.max_total_bytes);

    var origin_it = cache.origin_index.iterator();
    while (origin_it.next()) |kv| {
        try testing.expect(kv.value_ptr.items.len <= cache.limits.max_entries_per_origin);
        origin_members += kv.value_ptr.items.len;
        for (kv.value_ptr.items) |entry_id| {
            const entry = cache.entries.get(entry_id).?;
            try testing.expectEqualDeep(kv.key_ptr.*, entry.origin);
        }
    }
    try testing.expectEqual(cache.entries.count(), origin_members);
    try testing.expect(cache.origin_index.count() <= cache.limits.max_origins);

    var handle_it = cache.handle_index.iterator();
    while (handle_it.next()) |kv| {
        const entry = cache.entries.get(kv.value_ptr.*).?;
        try testing.expectEqualDeep(kv.key_ptr.*, digestHandle(&entry.handle));
    }
}

fn testResetDestroyCounters() struct { client: u64, server: u64, box: u64 } {
    return .{
        .client = test_client_entry_destroy_count,
        .server = test_server_entry_destroy_count,
        .box = test_public_server_lease_box_destroy_count,
    };
}

fn expectDestroyDelta(before: anytype, client: u64, server: u64, box: u64) !void {
    try testing.expectEqual(before.client + client, test_client_entry_destroy_count);
    try testing.expectEqual(before.server + server, test_server_entry_destroy_count);
    try testing.expectEqual(before.box + box, test_public_server_lease_box_destroy_count);
}

fn commonParams(psk: []const u8, sni: []const u8) session.ResumableSessionCommon.InitParams {
    return .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = psk,
        .server_name = sni,
        .application_protocol = "h3",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf-der"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 1000,
    };
}

fn makeClient(allocator: std.mem.Allocator, ticket: []const u8, sni: []const u8) !session.ClientTicketState {
    return makeClientWithSecret(allocator, ticket, sni, &([_]u8{0xab} ** 32), "n");
}

fn makeClientIssuedAt(allocator: std.mem.Allocator, ticket: []const u8, sni: []const u8, issued_at_unix_ms: i64) !session.ClientTicketState {
    var params = commonParams(&([_]u8{0xab} ** 32), sni);
    params.issued_at_unix_ms = issued_at_unix_ms;
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, params);
    var state: session.ClientTicketState = .{};
    try state.init(allocator, session.Limits.default, &common, .{
        .ticket = ticket,
        .ticket_age_add = 1,
        .ticket_nonce = "n",
        .received_at_unix_ms = issued_at_unix_ms,
    });
    return state;
}

fn makeClientWithSecret(allocator: std.mem.Allocator, ticket: []const u8, sni: []const u8, psk: []const u8, nonce: []const u8) !session.ClientTicketState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, commonParams(psk, sni));
    var state: session.ClientTicketState = .{};
    try state.init(allocator, session.Limits.default, &common, .{
        .ticket = ticket,
        .ticket_age_add = 1,
        .ticket_nonce = nonce,
        .received_at_unix_ms = 0,
    });
    return state;
}

fn makeServer(allocator: std.mem.Allocator, sni: []const u8) !session.ServerRecoverableState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, commonParams(&([_]u8{0xcd} ** 32), sni));
    var state: session.ServerRecoverableState = .{};
    state.init(&common, 7);
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

const FixedRandom = struct {
    calls: usize = 0,
    /// Each call fills the buffer with this repeating byte pattern, cycled
    /// by `calls` so successive calls can be made to collide or differ.
    pattern_for_call: []const u8 = &[_]u8{0xAA},

    fn source(self: *FixedRandom) RandomSource {
        return .{ .ctx = self, .fillFn = fill };
    }
    fn fill(ctx: *anyopaque, buf: []u8) error{EntropyFailure}!void {
        const self: *FixedRandom = @ptrCast(@alignCast(ctx));
        const byte = if (self.calls < self.pattern_for_call.len) self.pattern_for_call[self.calls] else 0xFF;
        @memset(buf, byte);
        self.calls += 1;
    }
};

const AlwaysFailRandom = struct {
    fn source() RandomSource {
        return .{ .ctx = @ptrCast(@constCast(&dummy)), .fillFn = fill };
    }
    var dummy: u8 = 0;
    fn fill(_: *anyopaque, _: []u8) error{EntropyFailure}!void {
        return error.EntropyFailure;
    }
};

test "storeClone then lookupOffers returns a hit in newest-insertion-first order" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var t1 = try makeClient(testing.allocator, "t1", "example.test");
    defer t1.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t1, 0, .reusable));

    var t2 = try makeClient(testing.allocator, "t2", "example.test");
    defer t2.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t2, 1, .reusable));

    var result = cache.lookupOffers(testCandidate("example.test"), 2);
    defer result.deinit();
    try testing.expect(result == .hit);
    try testing.expectEqual(@as(usize, 2), result.hit.offers.len);
    try testing.expectEqualStrings("t2", result.hit.offers.constSlice()[0].ticket.slice());
    try testing.expectEqualStrings("t1", result.hit.offers.constSlice()[1].ticket.slice());
}

test "storeClone with a repeated ticket identity replaces rather than duplicates" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var t1a = try makeClient(testing.allocator, "same-ticket", "example.test");
    defer t1a.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t1a, 0, .reusable));
    try testing.expectEqual(@as(usize, 1), cache.count());

    var t1b = try makeClient(testing.allocator, "same-ticket", "example.test");
    defer t1b.deinit();
    try testing.expectEqual(StoreResult.replaced, cache.storeClone(&t1b, 5, .reusable));
    try testing.expectEqual(@as(usize, 1), cache.count());
}

test "storeClone accepts single_use and makes it available for lookup" {
    var events = std.ArrayListUnmanaged(CacheEvent).empty;
    defer events.deinit(testing.allocator);
    const Ctx = struct {
        fn onEvent(ctx: *anyopaque, event: CacheEvent) void {
            const list: *std.ArrayListUnmanaged(CacheEvent) = @ptrCast(@alignCast(ctx));
            list.append(testing.allocator, event) catch {};
        }
    };

    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    cache.setObserver(.{ .ctx = &events, .onEventFn = Ctx.onEvent });

    var t1 = try makeClient(testing.allocator, "single-use-ticket", "example.test");
    defer t1.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t1, 0, .single_use));
    try testing.expectEqual(@as(usize, 1), cache.count());
    try testing.expectEqual(CacheEvent.stored, events.items[events.items.len - 1]);

    var result = cache.lookupOffers(testCandidate("example.test"), 1);
    defer result.deinit();
    try testing.expect(result == .hit);
    try testing.expectEqual(@as(usize, 1), result.hit.offers.len);
    try testing.expectEqualStrings("single-use-ticket", result.hit.offers.constSlice()[0].ticket.slice());
}

test "single_use lookup pins entries until selected outcome consumes exactly one" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var t1 = try makeClient(testing.allocator, "single-1", "example.test");
    defer t1.deinit();
    var t2 = try makeClient(testing.allocator, "single-2", "example.test");
    defer t2.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t1, 0, .single_use));
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t2, 1, .single_use));

    var lease = cache.lookupOffers(testCandidate("example.test"), 2);
    try testing.expect(lease == .hit);
    try testing.expectEqual(@as(usize, 2), lease.hit.offers.len);

    var concurrent = cache.lookupOffers(testCandidate("example.test"), 2);
    defer concurrent.deinit();
    try testing.expect(concurrent == .miss);

    lease.hit.finish(.{ .selected = 0 });
    lease.deinit();
    try testing.expectEqual(@as(usize, 1), cache.count());

    var after = cache.lookupOffers(testCandidate("example.test"), 3);
    defer after.deinit();
    try testing.expect(after == .hit);
    try testing.expectEqual(@as(usize, 1), after.hit.offers.len);
    try testing.expectEqualStrings("single-1", after.hit.offers.constSlice()[0].ticket.slice());
}

test "consumed single_use client entry wipes inline secrets from allocator backing memory" {
    var backing: [1 << 16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var cache = try ClientSessionCache.init(fba.allocator(), Limits.client_default);
    defer cache.deinit();

    const consumed_psk = [_]u8{0x47} ** 32;
    const consumed_nonce = "CONSUMED-CLIENT-ENTRY-SECRET-NONCE";

    var target = try makeClientWithSecret(fba.allocator(), "consume-ticket", "consume.test", &consumed_psk, consumed_nonce);
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&target, 0, .single_use));
    target.deinit();

    try testing.expect(std.mem.indexOf(u8, &backing, &consumed_psk) != null);
    try testing.expect(std.mem.indexOf(u8, &backing, consumed_nonce) != null);

    var lease = cache.lookupOffers(testCandidate("consume.test"), 1);
    try testing.expect(lease == .hit);
    lease.hit.finish(.{ .selected = 0 });
    lease.deinit();
    try testing.expectEqual(@as(usize, 0), cache.count());

    try testing.expect(std.mem.indexOf(u8, &backing, &consumed_psk) == null);
    try testing.expect(std.mem.indexOf(u8, &backing, consumed_nonce) == null);
}

test "lookupOffers clone allocation failure leaves expired entries and accounting unchanged" {
    var backing: [1 << 16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var cache = try ClientSessionCache.init(fba.allocator(), Limits.client_default);
    defer cache.deinit();

    var expired = try makeClient(fba.allocator(), "expired-during-oom", "oom.test");
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&expired, 0, .single_use));
    expired.deinit();

    var live = try makeClientIssuedAt(fba.allocator(), "live-during-oom", "oom.test", 1_500_000);
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&live, 1, .single_use));
    live.deinit();

    const snapshot_count = cache.count();
    const snapshot_bytes = cache.total_bytes;
    const snapshot_next_ins = cache.next_insertion_sequence;
    const snapshot_next_lru = cache.next_lru_sequence;
    const snapshot_next_lease = cache.next_lease_epoch;
    const snapshot_generation = cache.cache_generation;
    var snapshot_ids: [2]u64 = undefined;
    var snapshot_lru: [2]u64 = undefined;
    var snapshot_active: [2]?u64 = undefined;
    var snapshot_tickets: [2][32]u8 = undefined;
    var snapshot_ticket_lens: [2]usize = undefined;
    for (cache.entries.items, 0..) |entry, i| {
        snapshot_ids[i] = entry.entry_id;
        snapshot_lru[i] = entry.lru_sequence;
        snapshot_active[i] = entry.active_lease_epoch;
        const ticket = entry.ticket.ticket.slice();
        snapshot_ticket_lens[i] = ticket.len;
        @memcpy(snapshot_tickets[i][0..ticket.len], ticket);
    }

    var failing = testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = 0 });
    const original_allocator = cache.allocator;
    cache.allocator = failing.allocator();
    var result = cache.lookupOffers(testCandidate("oom.test"), 2_000_000);
    result.deinit();
    cache.allocator = original_allocator;
    try testing.expect(result == .storage_failed);

    try testing.expectEqual(snapshot_count, cache.count());
    try testing.expectEqual(snapshot_bytes, cache.total_bytes);
    try testing.expectEqual(snapshot_next_ins, cache.next_insertion_sequence);
    try testing.expectEqual(snapshot_next_lru, cache.next_lru_sequence);
    try testing.expectEqual(snapshot_next_lease, cache.next_lease_epoch);
    try testing.expectEqual(snapshot_generation, cache.cache_generation);
    try testing.expectEqual(@as(usize, 2), cache.entries.items.len);
    for (cache.entries.items, 0..) |entry, i| {
        try testing.expectEqual(snapshot_ids[i], entry.entry_id);
        try testing.expectEqual(snapshot_lru[i], entry.lru_sequence);
        try testing.expectEqual(snapshot_active[i], entry.active_lease_epoch);
        try testing.expectEqualStrings(snapshot_tickets[i][0..snapshot_ticket_lens[i]], entry.ticket.ticket.slice());
    }
}

test "single_use not_selected and aborted outcomes release without consuming" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var t1 = try makeClient(testing.allocator, "not-selected", "example.test");
    defer t1.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t1, 0, .single_use));

    var not_selected = cache.lookupOffers(testCandidate("example.test"), 1);
    try testing.expect(not_selected == .hit);
    not_selected.hit.finish(.not_selected);
    not_selected.deinit();
    try testing.expectEqual(@as(usize, 1), cache.count());

    var aborted = cache.lookupOffers(testCandidate("example.test"), 2);
    try testing.expect(aborted == .hit);
    aborted.hit.finish(.aborted);
    aborted.deinit();
    try testing.expectEqual(@as(usize, 1), cache.count());
}

test "pinned single_use entries are not eviction or persistence candidates" {
    var limits = Limits.client_default;
    limits.max_entries_per_origin = 2;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();

    var pinned_ticket = try makeClient(testing.allocator, "pinned", "example.test");
    defer pinned_ticket.deinit();
    var evictable = try makeClient(testing.allocator, "evictable", "example.test");
    defer evictable.deinit();
    var replacement = try makeClient(testing.allocator, "replacement", "example.test");
    defer replacement.deinit();

    try testing.expectEqual(StoreResult.stored, cache.storeClone(&pinned_ticket, 0, .single_use));
    var lease = cache.lookupOffers(testCandidate("example.test"), 1);
    defer lease.deinit();
    try testing.expect(lease == .hit);
    try testing.expectError(error.CacheBusy, cache.beginPersistenceOperation());

    try testing.expectEqual(StoreResult.stored, cache.storeClone(&evictable, 2, .reusable));
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&replacement, 3, .reusable));
    try testing.expectEqual(@as(usize, 2), cache.count());

    lease.hit.finish(.aborted);
    var after = cache.lookupOffers(testCandidate("example.test"), 4);
    defer after.deinit();
    try testing.expect(after == .hit);
    try testing.expectEqual(@as(usize, 2), after.hit.offers.len);
    try testing.expectEqualStrings("replacement", after.hit.offers.constSlice()[0].ticket.slice());
    try testing.expectEqualStrings("pinned", after.hit.offers.constSlice()[1].ticket.slice());
}

test "lookupOffers reports miss and expired distinctly" {
    // Note: `.incompatible` is intentionally not exercised here. The origin
    // digest is computed over every field `evaluateCompatibility` checks
    // (see `originDigestFromCandidate`), so within a matching bucket the
    // full re-check can only disagree in the truncation-based edge case
    // the module doc describes, not via an ordinary field mismatch (an
    // ordinary mismatch changes the digest itself, producing `.miss`).
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var miss = cache.lookupOffers(testCandidate("example.test"), 0);
    defer miss.deinit();
    try testing.expect(miss == .miss);

    var t1 = try makeClient(testing.allocator, "expiring", "example.test");
    defer t1.deinit();
    _ = cache.storeClone(&t1, 0, .reusable);

    var expired = cache.lookupOffers(testCandidate("example.test"), 2_000_000);
    defer expired.deinit();
    try testing.expect(expired == .expired);
}

test "per-origin capacity evicts the least-recently-used entry first" {
    var limits = Limits.client_default;
    limits.max_entries_per_origin = 2;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();

    var t1 = try makeClient(testing.allocator, "t1", "example.test");
    defer t1.deinit();
    _ = cache.storeClone(&t1, 0, .reusable);
    var t2 = try makeClient(testing.allocator, "t2", "example.test");
    defer t2.deinit();
    _ = cache.storeClone(&t2, 1, .reusable);

    // Touch t1 so it becomes more-recently-used than t2.
    var touch = cache.lookupOffers(testCandidate("example.test"), 2);
    touch.deinit();

    var t3 = try makeClient(testing.allocator, "t3", "example.test");
    defer t3.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t3, 3, .reusable));
    try testing.expectEqual(@as(usize, 2), cache.count());

    var result = cache.lookupOffers(testCandidate("example.test"), 4);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 2), result.hit.offers.len);
    for (result.hit.offers.constSlice()) |*t| try testing.expect(!std.mem.eql(u8, t.ticket.slice(), "t2"));
}

test "max_origins rejects a new origin once the distinct-origin cap is reached" {
    var limits = Limits.client_default;
    limits.max_origins = 1;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();

    var t1 = try makeClient(testing.allocator, "t1", "a.test");
    defer t1.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t1, 0, .reusable));

    var t2 = try makeClient(testing.allocator, "t2", "b.test");
    defer t2.deinit();
    try testing.expectEqual(StoreResult.rejected_capacity, cache.storeClone(&t2, 1, .reusable));
}

test "max_origins reclaims an already-expired origin without an explicit cleanup() call" {
    // Round-6 review #1 regression. `storeLocked` no longer purges
    // expired entries eagerly (see round 5), but the `max_origins`
    // admission check must still be judged against the cache's
    // *post-purge* state, not raw current origin counts — otherwise an
    // origin whose only entry has expired but was never purged would
    // permanently occupy an `max_origins` slot, blocking every other
    // origin indefinitely until some unrelated caller happens to invoke
    // `cleanup()` first.
    var limits = Limits.client_default;
    limits.max_origins = 1;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();

    var t1 = try makeClient(testing.allocator, "t1", "a.test");
    defer t1.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t1, 0, .reusable));

    // Far past t1's lifetime — a.test's only entry is now expired, but
    // nothing has purged it yet.
    var t2 = try makeClient(testing.allocator, "t2", "b.test");
    defer t2.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t2, 2_000_000, .reusable));

    try testing.expectEqual(@as(usize, 1), cache.count());
    try testing.expectEqualStrings("t2", cache.entries.items[0].ticket.ticket.slice());
}

test "FailingAllocator sweep: a failed client store never purges an already-expired origin's entry it needed to reclaim" {
    // Companion to the atomicity sweep above: this specifically forces
    // the plan to select the expired entry as a victim *because* the
    // origin-cardinality check requires reclaiming it (max_origins = 1,
    // new origin), not because of ordinary count/byte pressure. A late
    // allocation failure must still leave it completely untouched.
    var backing: [1 << 16]u8 = undefined;
    var limits = Limits.client_default;
    limits.max_origins = 1;

    var found_a_failure = false;
    var fail_index: usize = 0;
    while (fail_index < 32) : (fail_index += 1) {
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var cache = try ClientSessionCache.init(fba.allocator(), limits);
        defer cache.deinit();

        var stale = try makeClient(fba.allocator(), "already-expired", "a.test");
        _ = cache.storeClone(&stale, 0, .reusable);
        stale.deinit();

        const snapshot_bytes = cache.total_bytes;
        const snapshot_count = cache.entries.items.len;

        var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();
        var incoming = try makeClient(std.testing.allocator, "incoming", "b.test");
        defer incoming.deinit();
        const result = cache.storeClone(&incoming, 2_000_000, .reusable);
        cache.allocator = fba.allocator();

        if (result != .storage_failed) {
            cache.deinit();
            break;
        }

        found_a_failure = true;
        try testing.expectEqual(snapshot_count, cache.entries.items.len);
        try testing.expectEqual(snapshot_bytes, cache.total_bytes);
        try testing.expectEqualStrings("already-expired", cache.entries.items[0].ticket.ticket.slice());
    }
    try testing.expect(found_a_failure);
}

test "max_entry_bytes rejects an oversized entry" {
    var limits = Limits.client_default;
    limits.max_entry_bytes = 8;
    var cache = try ClientSessionCache.init(testing.allocator, limits);
    defer cache.deinit();

    var t1 = try makeClient(testing.allocator, "way-too-large-a-ticket-value", "example.test");
    defer t1.deinit();
    try testing.expectEqual(StoreResult.rejected_capacity, cache.storeClone(&t1, 0, .reusable));
}

test "client LRU batch reservation near u64 boundary preserves exact recency order" {
    // Round-4 review #1 regression: reserving one LRU sequence per touched
    // offer inside a loop could apply a stale (pre-renumber) value to the
    // first offer and a fresh (post-renumber) value to the second, making
    // the first touched entry immortal and reversing relative recency.
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var t1 = try makeClient(testing.allocator, "t1", "example.test");
    defer t1.deinit();
    _ = cache.storeClone(&t1, 0, .reusable);
    var t2 = try makeClient(testing.allocator, "t2", "example.test");
    defer t2.deinit();
    _ = cache.storeClone(&t2, 1, .reusable);

    // No room left for even one more value, let alone the two this lookup
    // batch needs: this forces a renumber before either offer's value is
    // assigned, rather than one being assigned from the old scale and the
    // other from a renumbered one.
    cache.next_lru_sequence = std.math.maxInt(u64);

    var touch = cache.lookupOffers(testCandidate("example.test"), 2);
    touch.deinit();

    // Both touched entries must now be numbered on the *same*, freshly
    // renumbered scale (a contiguous pair, neither left at a stale
    // near-`maxInt` value from before the renumber): neither can end up
    // "immortal" relative to the other. Relative order *between* the two
    // simultaneously-touched entries is not itself meaningful — only that
    // they land on one consistent post-renumber scale.
    var e1: ?*ClientEntry = null;
    var e2: ?*ClientEntry = null;
    for (cache.entries.items) |e| {
        if (e.ticket.ticket.eql(&t1.ticket)) e1 = e;
        if (e.ticket.ticket.eql(&t2.ticket)) e2 = e;
    }
    const lo = @min(e1.?.lru_sequence, e2.?.lru_sequence);
    const hi = @max(e1.?.lru_sequence, e2.?.lru_sequence);
    try testing.expectEqual(lo + 1, hi);
    try testing.expect(hi < std.math.maxInt(u64) - 1000);

    // A subsequent store must not evict either entry as though it were
    // ancient: capacity pressure should evict a genuinely older/unrelated
    // entry, not one of the two just-touched ones.
    var limits2 = Limits.client_default;
    limits2.max_entries_per_origin = 2;
    var cache2 = try ClientSessionCache.init(testing.allocator, limits2);
    defer cache2.deinit();
    var a = try makeClient(testing.allocator, "a", "example.test");
    defer a.deinit();
    _ = cache2.storeClone(&a, 0, .reusable);
    var b = try makeClient(testing.allocator, "b", "example.test");
    defer b.deinit();
    _ = cache2.storeClone(&b, 1, .reusable);
    cache2.next_lru_sequence = std.math.maxInt(u64) - 1;
    var touch2 = cache2.lookupOffers(testCandidate("example.test"), 2);
    touch2.deinit();
    var c = try makeClient(testing.allocator, "c", "example.test");
    defer c.deinit();
    try testing.expectEqual(StoreResult.stored, cache2.storeClone(&c, 3, .reusable));
    // The oldest-by-recency of {a, b} must be the one evicted; c (freshly
    // stored) and the more-recently-touched of {a, b} must both survive.
    try testing.expectEqual(@as(usize, 2), cache2.count());
    var has_c = false;
    for (cache2.entries.items) |e| {
        if (e.ticket.ticket.eql(&c.ticket)) has_c = true;
    }
    try testing.expect(has_c);
}

test "reserveLruSequenceBatchLocked never hands out maxInt(u64) twice" {
    // Round-6 review #2 regression: the previous guard only reserved room
    // for the batch's *last* value, not for the counter value the field
    // would be left holding afterward. With `n = 2` and
    // `next_lru_sequence = maxInt(u64) - 1`, the old guard didn't
    // renumber (the batch's last value, `maxInt(u64)`, is representable),
    // `next_lru_sequence` then saturated to `maxInt(u64)` via `+|`, and a
    // *subsequent* `n = 1` reservation also didn't renumber (`maxInt(u64)
    // > maxInt(u64)` is false) — handing out `maxInt(u64)` a second time.
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    cache.next_lru_sequence = std.math.maxInt(u64) - 1;
    const first_batch = cache.reserveLruSequenceBatchLocked(2);
    const next_single = cache.reserveLruSequenceBatchLocked(1);

    // Every value handed out (`first_batch`, `first_batch + 1`, and
    // `next_single`) must be distinct.
    try testing.expect(next_single != first_batch);
    try testing.expect(next_single != first_batch + 1);
    try testing.expect(first_batch + 1 != first_batch);
}

test "reserveLruSequenceBatchLocked renumbers when next_lru_sequence is already at maxInt(u64)" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var t1 = try makeClient(testing.allocator, "t1", "example.test");
    defer t1.deinit();
    _ = cache.storeClone(&t1, 0, .reusable);

    cache.next_lru_sequence = std.math.maxInt(u64);
    const v = cache.reserveLruSequenceBatchLocked(1);
    try testing.expect(v < std.math.maxInt(u64) - 1000);
    try testing.expect(cache.next_lru_sequence < std.math.maxInt(u64) - 1000);
}

test "client insertion-sequence renumbering preserves offer order across overflow" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var t1 = try makeClient(testing.allocator, "t1", "example.test");
    defer t1.deinit();
    _ = cache.storeClone(&t1, 0, .reusable);

    cache.next_insertion_sequence = std.math.maxInt(u64);
    var t2 = try makeClient(testing.allocator, "t2", "example.test");
    defer t2.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t2, 1, .reusable));

    var result = cache.lookupOffers(testCandidate("example.test"), 2);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 2), result.hit.offers.len);
    // t2 was stored after (and therefore must remain newer than) t1, even
    // though its raw insertion sequence value renumbered down to a small
    // number.
    try testing.expectEqualStrings("t2", result.hit.offers.constSlice()[0].ticket.slice());
    try testing.expectEqualStrings("t1", result.hit.offers.constSlice()[1].ticket.slice());
}

test "server LRU renumbering at overflow preserves relative recency and next eviction victim" {
    var limits = Limits.stateful_server_default;
    limits.max_entries_per_origin = 3;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var s1 = try makeServer(testing.allocator, "example.test");
    var h1: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s1, 0, .reusable, &h1));
    var s2 = try makeServer(testing.allocator, "example.test");
    var h2: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s2, 1, .reusable, &h2));

    cache.next_lru_sequence = std.math.maxInt(u64);
    var s3 = try makeServer(testing.allocator, "example.test");
    var h3: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s3, 2, .reusable, &h3));

    // s3 was inserted last and must remain the most-recently-used even
    // though the counter renumbered during its insertion.
    limits.max_entries_per_origin = 2;
    // Apply eviction pressure via a 4th insert on a cache with a tighter
    // per-origin cap to observe which of {s1, s2} (never touched again)
    // is treated as older than the other, and confirm s3 always survives.
    var cache2 = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache2.deinit();
    var a = try makeServer(testing.allocator, "example.test");
    var ha: [stateful_identity_len]u8 = undefined;
    _ = cache2.insertMove(&a, 0, .reusable, &ha);
    var b = try makeServer(testing.allocator, "example.test");
    var hb: [stateful_identity_len]u8 = undefined;
    _ = cache2.insertMove(&b, 1, .reusable, &hb);
    cache2.next_lru_sequence = std.math.maxInt(u64);
    var c = try makeServer(testing.allocator, "example.test");
    var hc: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache2.insertMove(&c, 2, .reusable, &hc));
    var d = try makeServer(testing.allocator, "example.test");
    var hd: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache2.insertMove(&d, 3, .reusable, &hd));
    // The per-origin cap (2) is enforced on every insert: by the time d is
    // inserted, both a and b must have been evicted (in some order) and
    // only c and d — the two most recently inserted — remain.
    try testing.expectEqual(@as(usize, 2), cache2.count());
    var hit_c = cache2.resolveLease(&hc, 3);
    defer hit_c.deinit();
    try testing.expect(hit_c == .hit);
    var hit_d = cache2.resolveLease(&hd, 3);
    defer hit_d.deinit();
    try testing.expect(hit_d == .hit);
}

test "stateful single-use lease: resolve pins the entry, commit consumes it exactly once" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var s1 = try makeServer(testing.allocator, "example.test");
    var handle: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s1, 0, .single_use, &handle));

    // A second concurrent resolve while the first lease is outstanding
    // must miss, not double-hit.
    var first = cache.resolveLease(&handle, 1);
    try testing.expect(first == .hit);
    var second = cache.resolveLease(&handle, 1);
    defer second.deinit();
    try testing.expect(second == .miss);

    switch (first) {
        .hit => |*h| h.lease.commit(),
        else => unreachable,
    }
    first.deinit();

    var after_commit = cache.resolveLease(&handle, 1);
    defer after_commit.deinit();
    try testing.expect(after_commit == .miss);
}

test "stateful single-use lease: release makes the entry resolvable again" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var s1 = try makeServer(testing.allocator, "example.test");
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .single_use, &handle);

    var first = cache.resolveLease(&handle, 1);
    try testing.expect(first == .hit);
    switch (first) {
        .hit => |*h| h.lease.release(),
        else => unreachable,
    }
    first.deinit();

    var second = cache.resolveLease(&handle, 1);
    defer second.deinit();
    try testing.expect(second == .hit);
}

test "reusable lease commit refreshes LRU recency without consuming the entry" {
    var limits = Limits.stateful_server_default;
    limits.max_entries_per_origin = 2;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var s1 = try makeServer(testing.allocator, "example.test");
    var h1: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .reusable, &h1);
    var s2 = try makeServer(testing.allocator, "example.test");
    var h2: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s2, 1, .reusable, &h2);

    var hit = cache.resolveLease(&h1, 2);
    try testing.expect(hit == .hit);
    switch (hit) {
        .hit => |*h| h.lease.commit(),
        else => unreachable,
    }
    hit.deinit();

    var s3 = try makeServer(testing.allocator, "example.test");
    var h3: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s3, 3, .reusable, &h3));

    var still_there = cache.resolveLease(&h1, 3);
    defer still_there.deinit();
    try testing.expect(still_there == .hit);
    var evicted = cache.resolveLease(&h2, 3);
    defer evicted.deinit();
    try testing.expect(evicted == .miss);
}

test "planInsertionLocked enforces max_entries against leased+unleased combined" {
    // Round-7 review regression: the eviction while-loops compared the
    // configured limits against unleased-only totals, so a leased entry
    // not yet at the limit by itself let the *combined* leased+unleased
    // count silently exceed max_entries.
    var limits = Limits.stateful_server_default;
    limits.max_entries = 2;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var sa = try makeServer(testing.allocator, "a.test");
    var ha: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&sa, 0, .single_use, &ha));
    var leased_a = cache.resolveLease(&ha, 1);
    try testing.expect(leased_a == .hit);

    var sb = try makeServer(testing.allocator, "b.test");
    var hb: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&sb, 1, .reusable, &hb));

    // With A pinned (never evictable) and B live, inserting C at
    // max_entries = 2 must evict B — the only evictable entry — rather
    // than growing the cache to 3 live entries.
    var sc = try makeServer(testing.allocator, "c.test");
    var hc: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&sc, 2, .reusable, &hc));

    try testing.expectEqual(@as(usize, 2), cache.count());
    var hit_b = cache.resolveLease(&hb, 2);
    defer hit_b.deinit();
    try testing.expect(hit_b == .miss);
    var hit_c = cache.resolveLease(&hc, 2);
    defer hit_c.deinit();
    try testing.expect(hit_c == .hit);

    switch (leased_a) {
        .hit => |*h| h.lease.release(),
        else => unreachable,
    }
    leased_a.deinit();
    var still_a = cache.resolveLease(&ha, 2);
    defer still_a.deinit();
    try testing.expect(still_a == .hit);
}

test "planInsertionLocked enforces max_entries_per_origin against leased+unleased combined" {
    var limits = Limits.stateful_server_default;
    limits.max_entries_per_origin = 2;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var sa = try makeServer(testing.allocator, "same.test");
    var ha: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&sa, 0, .single_use, &ha));
    var leased_a = cache.resolveLease(&ha, 1);
    try testing.expect(leased_a == .hit);

    var sb = try makeServer(testing.allocator, "same.test");
    var hb: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&sb, 1, .reusable, &hb));

    // Same origin for all three: A pinned, B live, cap of 2. Inserting C
    // must evict B rather than growing the origin's bucket to 3.
    var sc = try makeServer(testing.allocator, "same.test");
    var hc: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&sc, 2, .reusable, &hc));

    try testing.expectEqual(@as(usize, 2), cache.count());
    var hit_b = cache.resolveLease(&hb, 2);
    defer hit_b.deinit();
    try testing.expect(hit_b == .miss);
    var hit_c = cache.resolveLease(&hc, 2);
    defer hit_c.deinit();
    try testing.expect(hit_c == .hit);

    switch (leased_a) {
        .hit => |*h| h.lease.release(),
        else => unreachable,
    }
    leased_a.deinit();
}

test "planInsertionLocked enforces max_total_bytes against leased+unleased combined" {
    // Byte costs are measured dynamically (rather than hard-coded) so this
    // test stays valid regardless of the exact accounting formula.
    var scratch = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer scratch.deinit();
    var probe = try makeServer(testing.allocator, "probe.test");
    var hp: [stateful_identity_len]u8 = undefined;
    _ = scratch.insertMove(&probe, 0, .reusable, &hp);
    const one_entry_bytes = scratch.totalBytes();

    var limits = Limits.stateful_server_default;
    limits.max_entry_bytes = one_entry_bytes;
    limits.max_total_bytes = one_entry_bytes * 2; // room for exactly two entries.
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var sa = try makeServer(testing.allocator, "a.test");
    var ha: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&sa, 0, .single_use, &ha));
    var leased_a = cache.resolveLease(&ha, 1);
    try testing.expect(leased_a == .hit);

    var sb = try makeServer(testing.allocator, "b.test");
    var hb: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&sb, 1, .reusable, &hb));

    // Cache now holds leased A + unleased B, exactly at the byte cap. A
    // third entry must force B's eviction rather than silently exceeding
    // max_total_bytes with A's pinned bytes plus two more live entries.
    var sc = try makeServer(testing.allocator, "c.test");
    var hc: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&sc, 2, .reusable, &hc));

    try testing.expect(cache.totalBytes() <= limits.max_total_bytes);
    var hit_b = cache.resolveLease(&hb, 2);
    defer hit_b.deinit();
    try testing.expect(hit_b == .miss);
    var hit_c = cache.resolveLease(&hc, 2);
    defer hit_c.deinit();
    try testing.expect(hit_c == .hit);

    switch (leased_a) {
        .hit => |*h| h.lease.release(),
        else => unreachable,
    }
    leased_a.deinit();
}

test "a reusable lease resolved before a reload cannot mutate an unrelated post-reload entry" {
    // Round-3 review #4 regression: `cache_generation` must invalidate a
    // lease across a swap even though the swap reuses the same internal
    // entry_id values.
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var s1 = try makeServer(testing.allocator, "example.test");
    var h1: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .reusable, &h1);

    var stale = cache.resolveLease(&h1, 1);
    try testing.expect(stale == .hit);
    stale.deinit();
    var stale_lease = ServerLease{ .cache = &cache, .cache_generation = 0, .entry_id = 1, .lease_epoch = 0, .single_use = false };

    var temp = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    var s2 = try makeServer(testing.allocator, "reloaded.test");
    var h2: [stateful_identity_len]u8 = undefined;
    _ = temp.insertMove(&s2, 0, .reusable, &h2);
    cache.mutex.lock();
    cache.adoptFromLocked(&temp);
    cache.mutex.unlock();
    temp.deinit();

    const before = cache.resolveLease(&h2, 1);
    var lru_before: u64 = undefined;
    switch (before) {
        .hit => {
            cache.mutex.lock();
            lru_before = cache.entries.get(1).?.lru_sequence;
            cache.mutex.unlock();
        },
        else => unreachable,
    }
    var mutable_before = before;
    mutable_before.deinit();

    stale_lease.commit();

    cache.mutex.lock();
    const lru_after = cache.entries.get(1).?.lru_sequence;
    cache.mutex.unlock();
    try testing.expectEqual(lru_before, lru_after);
}

test "handle generation retries on collision and fails after exhausting attempts" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();

    const always_fail = AlwaysFailRandom.source();
    cache.random = always_fail;
    var s1 = try makeServer(testing.allocator, "example.test");
    var handle: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.rejected_handle_generation_failed, cache.insertMove(&s1, 0, .reusable, &handle));
    s1.deinit();
}

test "max_origins reclaims an already-expired server origin without an explicit cleanup() call" {
    // Server-side counterpart to the client regression above.
    var limits = Limits.stateful_server_default;
    limits.max_origins = 1;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var s1 = try makeServer(testing.allocator, "a.test");
    var h1: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s1, 0, .reusable, &h1));

    // Far past s1's lifetime — a.test's only entry is now expired, but
    // nothing has purged it yet.
    var s2 = try makeServer(testing.allocator, "b.test");
    var h2: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s2, 2_000_000, .reusable, &h2));

    try testing.expectEqual(@as(usize, 1), cache.count());
    // Resolved at a time *before* the fixture's fixed `issued_at_unix_ms`
    // (0) plus its lifetime would itself expire — `now_unix_ms = 2_000_000`
    // above was only the timestamp `insertMove` used to judge `s1`'s
    // expiry, not `s2`'s own issue time.
    var hit_s2 = cache.resolveLease(&h2, 1);
    defer hit_s2.deinit();
    try testing.expect(hit_s2 == .hit);
}

test "FailingAllocator sweep: a failed stateful insert never purges an already-expired origin's entry it needed to reclaim" {
    var backing: [1 << 16]u8 = undefined;
    var limits = Limits.stateful_server_default;
    limits.max_origins = 1;

    var found_a_failure = false;
    var fail_index: usize = 0;
    while (fail_index < 32) : (fail_index += 1) {
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var cache = try StatefulServerCache.init(fba.allocator(), limits, system_random_source);
        var s1 = try makeServer(fba.allocator(), "a.test");
        var h1: [stateful_identity_len]u8 = undefined;
        try testing.expectEqual(StoreResult.stored, cache.insertMove(&s1, 0, .reusable, &h1));

        const snapshot_count = cache.entries.count();
        const snapshot_bytes = cache.total_bytes;

        var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();
        var s2 = try makeServer(std.testing.allocator, "b.test");
        defer s2.deinit();
        var h2: [stateful_identity_len]u8 = undefined;
        const result = cache.insertMove(&s2, 2_000_000, .reusable, &h2);
        cache.allocator = fba.allocator();

        if (result != .storage_failed) {
            cache.deinit();
            break;
        }

        found_a_failure = true;
        try testing.expectEqual(snapshot_count, cache.entries.count());
        try testing.expectEqual(snapshot_bytes, cache.total_bytes);
        var still_there = cache.resolveLease(&h1, 1);
        defer still_there.deinit();
        try testing.expect(still_there == .hit);
        cache.deinit();
    }
    try testing.expect(found_a_failure);
}

test "resolveLease refuses a new single-use lease while a persistence operation is in progress" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var s1 = try makeServer(testing.allocator, "example.test");
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .single_use, &handle);

    const token = try cache.beginPersistenceOperation();
    var busy = cache.resolveLease(&handle, 1);
    defer busy.deinit();
    try testing.expect(busy == .busy);
    cache.endPersistenceOperation(token);

    var ok = cache.resolveLease(&handle, 1);
    defer ok.deinit();
    try testing.expect(ok == .hit);
}

test "beginPersistenceOperation refuses to start while a pre-existing single-use lease is outstanding" {
    // Round-5 review #4 regression. Refusing only *new* lease acquisition
    // once a persistence token is held (the previous test above) is not
    // enough: a lease acquired *before* a load starts could still be
    // committed *during* that load's decode/validate window, before the
    // load swaps in a snapshot that was necessarily read from durable
    // storage before that commit — resurrecting the just-consumed ticket.
    // `beginPersistenceOperation` must therefore also refuse to start at
    // all while any single-use lease is already outstanding.
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var s1 = try makeServer(testing.allocator, "example.test");
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .single_use, &handle);

    var leased = cache.resolveLease(&handle, 1);
    try testing.expect(leased == .hit);

    try testing.expectError(error.CacheBusy, cache.beginPersistenceOperation());

    // Committing (consuming) the pre-existing lease releases the
    // invariant that was blocking `begin`: a persistence operation can
    // now safely start, since no outstanding single-use lease remains to
    // race it.
    switch (leased) {
        .hit => |*h| h.lease.commit(),
        else => unreachable,
    }
    leased.deinit();

    const token = try cache.beginPersistenceOperation();
    cache.endPersistenceOperation(token);
}

test "stateful bearer handle is wiped from allocator backing memory on removal" {
    var backing: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var cache = try StatefulServerCache.init(fba.allocator(), Limits.stateful_server_default, system_random_source);
    defer cache.deinit();

    var s1 = try makeServer(fba.allocator(), "example.test");
    var handle: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s1, 0, .single_use, &handle));

    var hit = cache.resolveLease(&handle, 1);
    try testing.expect(hit == .hit);
    switch (hit) {
        .hit => |*h| h.lease.commit(),
        else => unreachable,
    }
    hit.deinit();

    try testing.expect(std.mem.indexOf(u8, &backing, &handle) == null);
}

test "stateful public adapter returns noop lease for reusable hits without lease-box allocation" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var s1 = try makeServer(testing.allocator, "example.test");
    var handle: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&s1, 0, .reusable, &handle));

    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var result = try resolveStatefulServerPsk(&cache, failing.allocator(), &handle, 1);
    defer result.deinit();
    switch (result) {
        .hit => |*hit| {
            try testing.expectEqual(pre_shared_key.ServerPskLease.noop, hit.lease);
            try testing.expect(hit.on_selected != null);
        },
        .miss => return error.TestExpectedEqual,
    }
}

test "FailingAllocator sweep: client store under eviction pressure is atomic on allocation failure" {
    var backing: [1 << 20]u8 = undefined;
    var fail_index: usize = 0;
    while (fail_index < 64) : (fail_index += 1) {
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var limits = Limits.client_default;
        limits.max_entries_per_origin = 1;
        var cache = try ClientSessionCache.init(fba.allocator(), limits);
        var t1 = try makeClient(fba.allocator(), "t1", "example.test");
        try testing.expectEqual(StoreResult.stored, cache.storeClone(&t1, 0, .reusable));
        t1.deinit();

        const snapshot_bytes = cache.total_bytes;
        const snapshot_next_ins = cache.next_insertion_sequence;
        const snapshot_next_lru = cache.next_lru_sequence;
        var snapshot_ticket = cache.entries.items[0].ticket.ticket;
        const snapshot_ticket_copy = snapshot_ticket.slice();
        var snapshot_buf: [64]u8 = undefined;
        @memcpy(snapshot_buf[0..snapshot_ticket_copy.len], snapshot_ticket_copy);

        var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();

        var t2 = try makeClient(std.testing.allocator, "t2-eviction-pressure", "example.test");
        defer t2.deinit();
        const result = cache.storeClone(&t2, 1, .reusable);

        cache.allocator = fba.allocator();
        if (result != .storage_failed) {
            // This fail_index no longer induces a failure anywhere in the
            // path; nothing further to sweep.
            cache.deinit();
            break;
        }

        try testing.expectEqual(@as(usize, 1), cache.entries.items.len);
        try testing.expectEqual(snapshot_bytes, cache.total_bytes);
        try testing.expectEqual(snapshot_next_ins, cache.next_insertion_sequence);
        try testing.expectEqual(snapshot_next_lru, cache.next_lru_sequence);
        try testing.expectEqualStrings(snapshot_buf[0..snapshot_ticket_copy.len], cache.entries.items[0].ticket.ticket.slice());
        cache.deinit();
    }
}

test "FailingAllocator sweep: a failed client store never purges an already-expired entry it didn't need to evict" {
    // Round-5 review #2 regression. `storeLocked` no longer purges expired
    // entries eagerly; expiry is folded into eviction-victim *preference*
    // instead (see `findEvictionCandidateInOriginExcluding`). This proves
    // the two halves of that design together: with a tight per-origin cap
    // forcing the plan to select the already-expired entry as its
    // preferred victim, a late allocation failure must still leave that
    // entry completely untouched — the plan having *selected* it as a
    // victim must not be conflated with it actually being removed.
    var backing: [1 << 16]u8 = undefined;
    var limits = Limits.client_default;
    limits.max_entries_per_origin = 1;

    var found_a_failure = false;
    var fail_index: usize = 0;
    while (fail_index < 32) : (fail_index += 1) {
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var cache = try ClientSessionCache.init(fba.allocator(), limits);
        defer cache.deinit();

        var stale = try makeClient(fba.allocator(), "already-expired", "same-origin.test");
        _ = cache.storeClone(&stale, 0, .reusable);
        stale.deinit();

        const snapshot_bytes = cache.total_bytes;
        const snapshot_count = cache.entries.items.len;

        var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();
        var incoming = try makeClient(std.testing.allocator, "incoming", "same-origin.test");
        defer incoming.deinit();
        // Far past the stale entry's lifetime, and same origin with a cap
        // of 1: this store would need to evict the stale entry to fit.
        const result = cache.storeClone(&incoming, 2_000_000, .reusable);
        cache.allocator = fba.allocator();

        if (result != .storage_failed) {
            cache.deinit();
            break;
        }

        found_a_failure = true;
        try testing.expectEqual(snapshot_count, cache.entries.items.len);
        try testing.expectEqual(snapshot_bytes, cache.total_bytes);
        try testing.expectEqualStrings("already-expired", cache.entries.items[0].ticket.ticket.slice());
    }
    try testing.expect(found_a_failure);
}

test "FailingAllocator sweep: stateful insert under eviction pressure is atomic on allocation failure" {
    var backing: [1 << 20]u8 = undefined;
    var fail_index: usize = 0;
    while (fail_index < 64) : (fail_index += 1) {
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var limits = Limits.stateful_server_default;
        limits.max_entries_per_origin = 1;
        var cache = try StatefulServerCache.init(fba.allocator(), limits, system_random_source);
        var s1 = try makeServer(fba.allocator(), "example.test");
        var h1: [stateful_identity_len]u8 = undefined;
        try testing.expectEqual(StoreResult.stored, cache.insertMove(&s1, 0, .reusable, &h1));

        const snapshot_count = cache.entries.count();
        const snapshot_bytes = cache.total_bytes;

        var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();

        var s2 = try makeServer(std.testing.allocator, "example.test");
        defer s2.deinit();
        var h2: [stateful_identity_len]u8 = undefined;
        const result = cache.insertMove(&s2, 1, .reusable, &h2);

        cache.allocator = fba.allocator();
        if (result != .storage_failed) {
            cache.deinit();
            break;
        }

        try testing.expectEqual(snapshot_count, cache.entries.count());
        try testing.expectEqual(snapshot_bytes, cache.total_bytes);
        var still_there = cache.resolveLease(&h1, 1);
        defer still_there.deinit();
        try testing.expect(still_there == .hit);
        cache.deinit();
    }
}

test "FailingAllocator sweep: a failed stateful insert never purges an already-expired entry it didn't need to evict" {
    // Server-side counterpart to the client regression above: with a
    // tight per-origin cap forcing `planInsertionLocked` to prefer the
    // already-expired, unleased entry as its eviction victim, a late
    // allocation failure must leave that entry completely untouched.
    var backing: [1 << 20]u8 = undefined;
    var limits = Limits.stateful_server_default;
    limits.max_entries_per_origin = 1;

    var found_a_failure = false;
    var fail_index: usize = 0;
    while (fail_index < 32) : (fail_index += 1) {
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var cache = try StatefulServerCache.init(fba.allocator(), limits, system_random_source);
        var s1 = try makeServer(fba.allocator(), "same-origin.test");
        var h1: [stateful_identity_len]u8 = undefined;
        try testing.expectEqual(StoreResult.stored, cache.insertMove(&s1, 0, .reusable, &h1));

        const snapshot_count = cache.entries.count();
        const snapshot_bytes = cache.total_bytes;

        var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();
        var s2 = try makeServer(std.testing.allocator, "same-origin.test");
        defer s2.deinit();
        var h2: [stateful_identity_len]u8 = undefined;
        // Far past `s1`'s lifetime, same origin, cap of 1: this insert
        // would need to evict `s1` to fit.
        const result = cache.insertMove(&s2, 2_000_000, .reusable, &h2);
        cache.allocator = fba.allocator();

        if (result != .storage_failed) {
            cache.deinit();
            break;
        }

        found_a_failure = true;
        try testing.expectEqual(snapshot_count, cache.entries.count());
        try testing.expectEqual(snapshot_bytes, cache.total_bytes);
        // Resolved at a time *before* `s1`'s expiry, so a hit here proves
        // the entry itself (not just the count) survived untouched,
        // without the lookup's own lazy-expiry purge interfering.
        var still_there = cache.resolveLease(&h1, 1);
        defer still_there.deinit();
        try testing.expect(still_there == .hit);
        cache.deinit();
    }
    try testing.expect(found_a_failure);
}

test "restoreClones aborts atomically on a mid-stream allocation failure, leaving the target untouched" {
    var found_a_failure = false;
    var fail_index: usize = 0;
    while (fail_index < 64) : (fail_index += 1) {
        var backing: [8192]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var cache = try ClientSessionCache.init(fba.allocator(), Limits.client_default);
        defer cache.deinit();
        var existing = try makeClient(fba.allocator(), "already-here", "example.test");
        _ = cache.storeClone(&existing, 0, .reusable);
        existing.deinit();

        var p1 = PersistedClientEntry{ .ticket = try makeClient(std.testing.allocator, "p1", "other.test"), .usage = .reusable, .insertion_sequence = 1, .lru_sequence = 1 };
        var p2 = PersistedClientEntry{ .ticket = try makeClient(std.testing.allocator, "p2", "other.test"), .usage = .reusable, .insertion_sequence = 2, .lru_sequence = 2 };
        var items = [_]PersistedClientEntry{ p1, p2 };
        _ = &p1;
        _ = &p2;

        var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();
        const result = cache.restoreClones(&items, 3);
        cache.allocator = fba.allocator();

        if (result) |_| {
            // No failure was induced at this index; the sweep has passed
            // every reachable allocation point.
            try testing.expectEqual(@as(usize, 2), cache.count());
            break;
        } else |_| {
            found_a_failure = true;
            // The pre-existing entry must be completely untouched, no
            // matter which allocation inside `restoreClones` failed.
            try testing.expectEqual(@as(usize, 1), cache.count());
            try testing.expectEqualStrings("already-here", cache.entries.items[0].ticket.ticket.slice());
        }
    }
    try testing.expect(found_a_failure);
}

test "restoreClones deterministically resolves a duplicate origin/ticket-identity pair by insertion_sequence" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var older = PersistedClientEntry{ .ticket = try makeClient(testing.allocator, "dup", "example.test"), .usage = .reusable, .insertion_sequence = 1, .lru_sequence = 1 };
    var newer = PersistedClientEntry{ .ticket = try makeClient(testing.allocator, "dup", "example.test"), .usage = .reusable, .insertion_sequence = 9, .lru_sequence = 9 };
    var items = [_]PersistedClientEntry{ older, newer };
    _ = &older;
    _ = &newer;

    try cache.restoreClones(&items, 10);
    try testing.expectEqual(@as(usize, 1), cache.count());
    try testing.expectEqual(@as(u64, 9), cache.entries.items[0].insertion_sequence);
}

test "single_use duplicate restore follows newest insertion metadata" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var older_reusable = PersistedClientEntry{ .ticket = try makeClient(testing.allocator, "dup", "example.test"), .usage = .reusable, .insertion_sequence = 1, .lru_sequence = 1 };
    var newer_single_use = PersistedClientEntry{ .ticket = try makeClient(testing.allocator, "dup", "example.test"), .usage = .single_use, .insertion_sequence = 9, .lru_sequence = 9 };
    var items = [_]PersistedClientEntry{ older_reusable, newer_single_use };
    _ = &older_reusable;
    _ = &newer_single_use;

    try cache.restoreClones(&items, 10);
    try testing.expectEqual(@as(usize, 1), cache.count());
    try testing.expectEqual(UsagePolicy.single_use, cache.entries.items[0].usage);
    try testing.expectEqual(@as(u64, 9), cache.entries.items[0].insertion_sequence);
}

test "restoreEntries aborts atomically on a mid-stream allocation failure, leaving the target untouched" {
    var backing: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var cache = try StatefulServerCache.init(fba.allocator(), Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var existing = try makeServer(fba.allocator(), "already-here");
    var existing_handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&existing, 0, .reusable, &existing_handle);

    var h1: [stateful_identity_len]u8 = [_]u8{0xAA} ** stateful_identity_len;
    @memcpy(h1[0..4], "TDSH");
    std.mem.writeInt(u16, h1[4..6], stateful_version, .big);
    std.mem.writeInt(u16, h1[6..8], 0, .big);
    var h2: [stateful_identity_len]u8 = [_]u8{0xBB} ** stateful_identity_len;
    @memcpy(h2[0..4], "TDSH");
    std.mem.writeInt(u16, h2[4..6], stateful_version, .big);
    std.mem.writeInt(u16, h2[6..8], 0, .big);

    var p1 = PersistedServerEntry{ .handle = h1, .usage = .reusable, .state = try makeServer(std.testing.allocator, "p1"), .lru_sequence = 1 };
    var p2 = PersistedServerEntry{ .handle = h2, .usage = .reusable, .state = try makeServer(std.testing.allocator, "p2"), .lru_sequence = 2 };
    var items = [_]PersistedServerEntry{ p1, p2 };
    _ = &p1;
    _ = &p2;

    var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = 2 });
    cache.allocator = failing.allocator();
    const result = cache.restoreEntries(&items, 3);
    cache.allocator = fba.allocator();

    try testing.expectError(error.OutOfMemory, result);
    try testing.expectEqual(@as(usize, 1), cache.count());
    var still_there = cache.resolveLease(&existing_handle, 3);
    defer still_there.deinit();
    try testing.expect(still_there == .hit);
}

test "an observer that re-enters the cache from inside notify() does not deadlock" {
    const Ctx = struct {
        cache: *ClientSessionCache,
        fn onEvent(ctx: *anyopaque, _: CacheEvent) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = self.cache.count();
        }
    };
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var reentrant_ctx = Ctx{ .cache = &cache };
    cache.setObserver(.{ .ctx = &reentrant_ctx, .onEventFn = Ctx.onEvent });

    var t1 = try makeClient(testing.allocator, "t1", "example.test");
    defer t1.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&t1, 0, .reusable));
}

test "a removed client entry's inline secrets are wiped from allocator backing memory, surviving growth/swapRemove/renumbering around it" {
    // Round-5 review #1 regression. `ClientEntry` embeds
    // `ResumableSessionCommon.resumption_psk` and `ClientTicketState.ticket_nonce`
    // inline (fixed-size arrays, not behind a separate heap pointer). Before
    // the pointer-based redesign, `ArrayListUnmanaged(ClientEntry)` growth,
    // `std.mem.sort`-based renumbering, and `swapRemove`'s tail-slot copy
    // could all bitwise-copy those secrets around, leaving stale unwiped
    // copies in old/unused backing capacity. `entries` is now
    // `ArrayListUnmanaged(*ClientEntry)`, so those operations only ever
    // copy pointers; each `ClientEntry`'s own secret-bearing storage is
    // wiped exactly once, by `destroyClientEntry`, when it is destroyed.
    var backing: [1 << 16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var cache = try ClientSessionCache.init(fba.allocator(), Limits.client_default);
    defer cache.deinit();

    const target_psk = [_]u8{0x37} ** 32;
    const target_nonce = "REMOVED-CLIENT-ENTRY-SECRET-NONCE";

    // Insert several filler entries first, forcing the `*ClientEntry`
    // pointer array to grow at least once before the target is inserted.
    var i: u8 = 0;
    while (i < 6) : (i += 1) {
        var buf: [16]u8 = undefined;
        const sni = std.fmt.bufPrint(&buf, "host{d}.test", .{i}) catch unreachable;
        var t = try makeClient(fba.allocator(), "filler-ticket", sni);
        _ = cache.storeClone(&t, 0, .reusable);
        t.deinit();
    }

    var target = try makeClientWithSecret(fba.allocator(), "target-ticket", "target.test", &target_psk, target_nonce);
    _ = cache.storeClone(&target, 1, .reusable);
    target.deinit();

    // A filler entry stored *after* the target ensures the target is not
    // the physically-last array element, so removing it below exercises
    // `swapRemove`'s tail-slot-copy path (moving a different, later
    // entry's pointer into the target's old slot) rather than a trivial
    // pop.
    var trailing = try makeClient(fba.allocator(), "trailing-ticket", "trailing.test");
    _ = cache.storeClone(&trailing, 2, .reusable);
    trailing.deinit();

    try testing.expect(std.mem.indexOf(u8, &backing, &target_psk) != null);
    try testing.expect(std.mem.indexOf(u8, &backing, target_nonce) != null);

    // Remove the target specifically (expiry-driven `swapRemove`, not the
    // last element) while other entries remain live around it.
    var expired_lookup = cache.lookupOffers(testCandidate("target.test"), 2_000_000);
    expired_lookup.deinit();

    // Force an insertion-sequence renumber (sorts the pointer array) after
    // the target is already gone, to confirm renumbering cannot resurrect
    // a wiped entry's secret bytes by copying stale struct content.
    cache.next_insertion_sequence = std.math.maxInt(u64);
    var another = try makeClient(fba.allocator(), "another-ticket", "another.test");
    _ = cache.storeClone(&another, 3, .reusable);
    another.deinit();

    try testing.expect(std.mem.indexOf(u8, &backing, &target_psk) == null);
    try testing.expect(std.mem.indexOf(u8, &backing, target_nonce) == null);
}

const ClientFuzzOp = enum {
    store_reusable,
    store_single_use,
    replace_existing,
    lookup_compatible,
    lookup_incompatible,
    finish_selected,
    drop_offer,
    finish_not_selected,
    abort_or_deinit,
    advance_clock,
    cleanup,
    begin_persistence,
    end_persistence_correct,
    end_persistence_wrong_or_stale,
    clone_for_persistence,
    restore_clones,
    force_sequence_renumber,
    quiescent_reset,
    client_oom_sweep,
};

const ServerFuzzOp = enum {
    insert_reusable,
    insert_single_use,
    resolve_known,
    resolve_unknown,
    resolve_malformed_shape,
    resolve_through_public_adapter,
    commit_lease,
    release_lease,
    deinit_lease,
    complete_reusable_selection_hook,
    advance_clock,
    cleanup,
    begin_persistence,
    end_persistence_correct,
    end_persistence_wrong_or_stale,
    clone_for_persistence,
    restore_entries,
    entropy_failure,
    handle_collision_then_success,
    handle_collision_exhaustion,
    force_lru_renumber,
    quiescent_reset,
    server_oom_sweep,
};

fn smithCorpusWords(comptime words: []const u64) [words.len * 8]u8 {
    var out = [_]u8{0} ** (words.len * 8);
    inline for (words, 0..) |word, i| {
        std.mem.writeInt(u64, out[i * 8 ..][0..8], word, .little);
    }
    return out;
}

fn wrongPersistenceToken(smith: *std.testing.Smith, active: ?u64) u64 {
    var candidate = smith.value(u64);
    if (active) |token| {
        if (candidate == token) candidate +%= 1;
    }
    return candidate;
}

fn fuzzClientTicket(allocator: std.mem.Allocator, id: u64, usage_byte: u64, now_ms: i64) !session.ClientTicketState {
    var ticket_buf: [32]u8 = undefined;
    const ticket = try std.fmt.bufPrint(&ticket_buf, "ct-{d}-{d}", .{ id % 23, usage_byte % 5 });
    var sni_buf: [32]u8 = undefined;
    const sni = try std.fmt.bufPrint(&sni_buf, "c{d}.example.test", .{id % fuzz_cache_limits.max_origins});
    var psk = [_]u8{0x51} ** 32;
    psk[0] = @truncate(id);
    var nonce_buf: [16]u8 = undefined;
    const nonce = try std.fmt.bufPrint(&nonce_buf, "n{d}", .{usage_byte % 97});
    var state = try makeClientWithSecret(allocator, ticket, sni, &psk, nonce);
    state.received_at_unix_ms = now_ms;
    return state;
}

fn fuzzServerState(allocator: std.mem.Allocator, id: u64) !session.ServerRecoverableState {
    var sni_buf: [32]u8 = undefined;
    const sni = try std.fmt.bufPrint(&sni_buf, "s{d}.example.test", .{id % fuzz_cache_limits.max_origins});
    return makeServer(allocator, sni);
}

fn fuzzServerStateWithCompat(allocator: std.mem.Allocator, id: u64) !session.ServerRecoverableState {
    var sni_buf: [32]u8 = undefined;
    const sni = try std.fmt.bufPrint(&sni_buf, "sc{d}.example.test", .{id % fuzz_cache_limits.max_origins});
    var params = commonParams(&([_]u8{0xcd} ** 32), sni);
    params.transport_compat = .{ .format_id = 7, .format_version = 1, .bytes = "clone-alloc-compat" };
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, params);
    var state: session.ServerRecoverableState = .{};
    state.init(&common, 7);
    return state;
}

const ClientLeaseTransition = struct {
    len: usize = 0,
    present: [pre_shared_key.max_offered_identities]bool = [_]bool{false} ** pre_shared_key.max_offered_identities,
    entry_ids: [pre_shared_key.max_offered_identities]u64 = [_]u64{0} ** pre_shared_key.max_offered_identities,
    single_use: [pre_shared_key.max_offered_identities]bool = [_]bool{false} ** pre_shared_key.max_offered_identities,
    lease_epochs: [pre_shared_key.max_offered_identities]u64 = [_]u64{0} ** pre_shared_key.max_offered_identities,
    fingerprints: [pre_shared_key.max_offered_identities][32]u8 = undefined,
};

fn captureClientLeaseTransition(cache: *ClientSessionCache, lease: *pre_shared_key.ClientOfferLease) !ClientLeaseTransition {
    var out: ClientLeaseTransition = .{ .len = lease.offers.len };
    cache.mutex.lock();
    defer cache.mutex.unlock();
    for (0..lease.offers.len) |i| {
        const token = lease.tokens[i];
        out.entry_ids[i] = token.entry_id;
        out.single_use[i] = token.single_use;
        out.lease_epochs[i] = token.lease_epoch;
        const idx = cache.findIndexByEntryId(token.entry_id) orelse {
            try testing.expect(!token.single_use);
            continue;
        };
        const entry = cache.entries.items[idx];
        out.present[i] = true;
        if (token.single_use) {
            try testing.expectEqual(token.lease_epoch, entry.active_lease_epoch.?);
        }
        out.fingerprints[i] = try fingerprintClientTicket(&entry.ticket);
    }
    return out;
}

// A reusable ticket may legitimately be offered into more than one
// concurrent lease (nothing pins it, unlike a single-use ticket), and
// re-storing the same ticket identity can reclassify it single_use<->
// reusable in place (storeDedup's guard only blocks reclassifying an
// already-pinned single-use entry, not a reusable one). So a lease that
// never itself held a pin on an entry (`.no_claim`) cannot assert
// anything about that entry's current pin state — a different,
// independently created lease may hold a legitimate, unrelated pin on
// the very same (now-reclassified) entry. A lease that DID hold a pin
// can only assert facts about its OWN epoch: that it is still exactly
// that epoch (`.still_pinned`), or that it is no longer that epoch
// (`.released_own` — a different, newer epoch belonging to another
// lease is not evidence of a stuck release).
const PinExpectation = union(enum) {
    no_claim,
    still_pinned: u64,
    released_own: u64,
};

fn expectClientEntryState(cache: *ClientSessionCache, entry_id: u64, expected_fp: [32]u8, should_exist: bool, expect: PinExpectation) !void {
    const idx = cache.findIndexByEntryId(entry_id);
    if (!should_exist) {
        try testing.expect(idx == null);
        return;
    }
    const entry = cache.entries.items[idx orelse return error.ClientLeaseTransitionEntryMissing];
    try testing.expectEqualDeep(expected_fp, try fingerprintClientTicket(&entry.ticket));
    switch (expect) {
        .no_claim => {},
        .still_pinned => |epoch| try testing.expectEqual(@as(?u64, epoch), entry.active_lease_epoch),
        .released_own => |epoch| try testing.expect(entry.active_lease_epoch != epoch),
    }
}

fn expectClientLeaseTransition(cache: *ClientSessionCache, before: ClientLeaseTransition, outcome: pre_shared_key.ClientOfferOutcome) !void {
    cache.mutex.lock();
    defer cache.mutex.unlock();
    const selected_index: ?usize = switch (outcome) {
        .selected => |idx| if (idx < before.len) idx else null,
        .not_selected, .aborted => null,
    };
    for (0..before.len) |i| {
        if (!before.present[i]) {
            try testing.expect(cache.findIndexByEntryId(before.entry_ids[i]) == null);
            continue;
        }
        const consumed = selected_index != null and selected_index.? == i and before.single_use[i];
        const expect: PinExpectation = if (!before.single_use[i])
            .no_claim
        else
            .{ .released_own = before.lease_epochs[i] };
        try expectClientEntryState(cache, before.entry_ids[i], before.fingerprints[i], !consumed, expect);
    }
}

fn expectClientDropOfferTransition(cache: *ClientSessionCache, before: ClientLeaseTransition, dropped_index: usize) !void {
    cache.mutex.lock();
    defer cache.mutex.unlock();
    for (0..before.len) |i| {
        if (!before.present[i]) {
            try testing.expect(cache.findIndexByEntryId(before.entry_ids[i]) == null);
            continue;
        }
        const expect: PinExpectation = if (!before.single_use[i])
            .no_claim
        else if (i == dropped_index)
            .{ .released_own = before.lease_epochs[i] }
        else
            .{ .still_pinned = before.lease_epochs[i] };
        try expectClientEntryState(cache, before.entry_ids[i], before.fingerprints[i], true, expect);
    }
}

const ServerLeaseTransition = struct {
    present: bool,
    entry_id: u64,
    single_use: bool,
    lru_sequence: u64,
    state_fingerprint: [32]u8,
};

fn captureServerLeaseTransition(cache: *StatefulServerCache, lease: *const ServerLease) !ServerLeaseTransition {
    cache.mutex.lock();
    defer cache.mutex.unlock();
    const entry = cache.entries.get(lease.entry_id) orelse {
        try testing.expect(!lease.single_use);
        return .{
            .present = false,
            .entry_id = lease.entry_id,
            .single_use = lease.single_use,
            .lru_sequence = 0,
            .state_fingerprint = [_]u8{0} ** 32,
        };
    };
    try testing.expectEqual(lease.single_use, entry.usage == .single_use);
    if (lease.single_use) try testing.expectEqual(lease.lease_epoch, entry.active_lease_epoch.?);
    return .{
        .present = true,
        .entry_id = lease.entry_id,
        .single_use = lease.single_use,
        .lru_sequence = entry.lru_sequence,
        .state_fingerprint = try fingerprintServerState(&entry.state),
    };
}

fn captureServerHandleTransition(cache: *StatefulServerCache, handle: *const [stateful_identity_len]u8) !ServerLeaseTransition {
    cache.mutex.lock();
    defer cache.mutex.unlock();
    const entry_id = cache.handle_index.get(digestHandle(handle)) orelse return error.ServerHandleTransitionMissingEntry;
    const entry = cache.entries.get(entry_id) orelse return error.ServerHandleTransitionMissingEntry;
    return .{
        .present = true,
        .entry_id = entry_id,
        .single_use = entry.usage == .single_use,
        .lru_sequence = entry.lru_sequence,
        .state_fingerprint = try fingerprintServerState(&entry.state),
    };
}

fn expectServerLeaseTransition(cache: *StatefulServerCache, before: ServerLeaseTransition, action: enum { commit, release }) !void {
    cache.mutex.lock();
    defer cache.mutex.unlock();
    if (!before.present) {
        try testing.expect(cache.entries.get(before.entry_id) == null);
        return;
    }
    const entry = cache.entries.get(before.entry_id);
    if (action == .commit and before.single_use) {
        try testing.expect(entry == null);
        return;
    }
    const live = entry orelse return error.ServerLeaseTransitionEntryMissing;
    try testing.expectEqualDeep(before.state_fingerprint, try fingerprintServerState(&live.state));
    try testing.expectEqual(@as(?u64, null), live.active_lease_epoch);
    if (action == .commit and !before.single_use) {
        // Not `live.lru_sequence != before.lru_sequence`: `commitLease`'s
        // `reserveFreshLruSequenceLocked()` call can trigger
        // `renumberLruSequencesLocked()` first (when `next_lru_sequence`
        // has saturated to `maxInt`), which resets the whole numbering
        // scale to `0..liveCount()-1`. The freshly reserved value this
        // entry gets can then coincidentally equal its OWN pre-renumber
        // `before.lru_sequence` (#675 campaign FINDING F5: e.g. 3 live
        // entries renumbered to 0/1/2 sets next_lru_sequence=3, and the
        // entry being committed -- whose before-snapshot happened to be
        // lru_sequence=3 from an earlier commit -- gets freshly reserved
        // sequence 3 right back). That coincidence doesn't mean the
        // commit failed to advance anything: `commitLease` always assigns
        // the value `reserveFreshLruSequenceLocked()` just returned,
        // which is unconditionally `cache.next_lru_sequence - 1` the
        // instant this synchronous check runs (nothing else can reserve a
        // sequence in between in this single-threaded fuzz model) --
        // checking that directly is robust across a renumber and is what
        // "this entry is now the freshest" actually means.
        try testing.expectEqual(cache.next_lru_sequence - 1, live.lru_sequence);
    } else {
        try testing.expectEqual(before.lru_sequence, live.lru_sequence);
    }
}

fn cleanupAllClientLeases(leases: *[fuzz_max_live_client_leases]ClientLookupResult) void {
    for (leases) |*lease| {
        lease.deinit();
        lease.* = .miss;
    }
}

fn firstClientLeaseSlot(leases: *[fuzz_max_live_client_leases]ClientLookupResult) ?usize {
    for (leases, 0..) |*lease, i| {
        if (lease.* != .hit) return i;
    }
    return null;
}

fn finishAllClientLeasesChecked(cache: *ClientSessionCache, leases: *[fuzz_max_live_client_leases]ClientLookupResult) !void {
    for (leases) |*lease| {
        if (lease.* != .hit) continue;
        const before = try captureClientLeaseTransition(cache, &lease.hit);
        lease.deinit();
        lease.* = .miss;
        try expectClientLeaseTransition(cache, before, .aborted);
    }
}

fn expectClientLeaseModel(
    cache: *ClientSessionCache,
    leases: *const [fuzz_max_live_client_leases]ClientLookupResult,
    persistence_token: ?u64,
) !void {
    cache.mutex.lock();
    defer cache.mutex.unlock();

    try testing.expectEqual(persistence_token orelse 0, cache.persistence_epoch);

    var modeled_pins: usize = 0;
    for (leases) |*lease| {
        if (lease.* != .hit) continue;
        try testing.expect(lease.hit.active);
        try testing.expectEqual(cache.cache_generation, lease.hit.cache_generation);
        for (0..lease.hit.offers.len) |i| {
            const token = lease.hit.tokens[i];
            if (!token.single_use) continue;
            modeled_pins += 1;
            try testing.expectEqual(@as(?u64, null), persistence_token);
            const idx = cache.findIndexByEntryId(token.entry_id) orelse return error.ClientLeaseModelMissingPinnedEntry;
            const entry = cache.entries.items[idx];
            try testing.expectEqual(UsagePolicy.single_use, entry.usage);
            try testing.expectEqual(token.lease_epoch, entry.active_lease_epoch.?);
        }
    }

    var cache_pins: usize = 0;
    for (cache.entries.items) |entry| {
        const epoch = entry.active_lease_epoch orelse continue;
        cache_pins += 1;
        try testing.expectEqual(UsagePolicy.single_use, entry.usage);
        try testing.expectEqual(@as(?u64, null), persistence_token);
        var owners: usize = 0;
        for (leases) |*lease| {
            if (lease.* != .hit) continue;
            try testing.expectEqual(cache.cache_generation, lease.hit.cache_generation);
            for (0..lease.hit.offers.len) |i| {
                const token = lease.hit.tokens[i];
                if (token.single_use and token.entry_id == entry.entry_id and token.lease_epoch == epoch) owners += 1;
            }
        }
        try testing.expectEqual(@as(usize, 1), owners);
    }
    try testing.expectEqual(modeled_pins, cache_pins);
}

fn clientStoreOomSweep() !void {
    var saw_failure = false;
    var saw_success = false;
    for (0..fuzz_max_oom_fail_index + 1) |fail_index| {
        var backing: [1 << 18]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var cache = try ClientSessionCache.init(fba.allocator(), fuzz_cache_limits);
        defer cache.deinit();

        var existing = try fuzzClientTicket(fba.allocator(), 1, 0, 0);
        try testing.expectEqual(StoreResult.stored, cache.storeClone(&existing, 0, .reusable));
        existing.deinit();
        var before = try ClientCacheState.capture(&cache);
        defer before.deinit();

        var incoming = try fuzzClientTicket(testing.allocator, 2, 0, 1);
        defer incoming.deinit();
        var failing = testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();
        const result = cache.storeClone(&incoming, 1, .reusable);
        cache.allocator = fba.allocator();

        if (result == .storage_failed) {
            saw_failure = true;
            var after = try ClientCacheState.capture(&cache);
            defer after.deinit();
            try before.expectEqual(&after);
        } else {
            try testing.expectEqual(StoreResult.stored, result);
            saw_success = true;
            break;
        }
    }
    try testing.expect(saw_failure);
    try testing.expect(saw_success);
}

fn clientLookupOomSweep() !void {
    var saw_failure = false;
    var saw_success = false;
    for (0..fuzz_max_oom_fail_index + 1) |fail_index| {
        var backing: [1 << 18]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var cache = try ClientSessionCache.init(fba.allocator(), fuzz_cache_limits);
        defer cache.deinit();
        for (0..2) |i| {
            var ticket = try fuzzClientTicket(fba.allocator(), @intCast(i), 0, @intCast(i));
            try testing.expectEqual(StoreResult.stored, cache.storeClone(&ticket, @intCast(i), .single_use));
            ticket.deinit();
        }
        var before = try ClientCacheState.capture(&cache);
        defer before.deinit();

        var failing = testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();
        var result = cache.lookupOffers(testCandidate("c0.example.test"), 2);
        cache.allocator = fba.allocator();
        defer result.deinit();

        if (result == .storage_failed) {
            saw_failure = true;
            var after = try ClientCacheState.capture(&cache);
            defer after.deinit();
            try before.expectEqual(&after);
        } else {
            try testing.expect(result == .hit);
            saw_success = true;
            break;
        }
    }
    try testing.expect(saw_failure);
    try testing.expect(saw_success);
}

fn clientPersistenceOomSweep() !void {
    var saw_failure = false;
    var saw_success = false;
    for (0..fuzz_max_oom_fail_index + 1) |fail_index| {
        var backing: [1 << 18]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var cache = try ClientSessionCache.init(fba.allocator(), fuzz_cache_limits);
        defer cache.deinit();
        var existing = try fuzzClientTicket(fba.allocator(), 0, 0, 0);
        try testing.expectEqual(StoreResult.stored, cache.storeClone(&existing, 0, .reusable));
        existing.deinit();
        var before = try ClientCacheState.capture(&cache);
        defer before.deinit();

        var p0 = PersistedClientEntry{ .ticket = try fuzzClientTicket(testing.allocator, 1, 0, 1), .usage = .reusable, .insertion_sequence = 1, .lru_sequence = 1 };
        var p1 = PersistedClientEntry{ .ticket = try fuzzClientTicket(testing.allocator, 2, 0, 2), .usage = .single_use, .insertion_sequence = 2, .lru_sequence = 2 };
        var items = [_]PersistedClientEntry{ p0, p1 };
        _ = &p0;
        _ = &p1;

        var failing = testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();
        const result = cache.restoreClones(&items, 3);
        cache.allocator = fba.allocator();

        if (result) |_| {
            saw_success = true;
            break;
        } else |err| {
            try testing.expectEqual(error.OutOfMemory, err);
            saw_failure = true;
            var after = try ClientCacheState.capture(&cache);
            defer after.deinit();
            try before.expectEqual(&after);
        }
    }
    try testing.expect(saw_failure);
    try testing.expect(saw_success);
}

fn runClientFuzzCase(smith: *std.testing.Smith) !void {
    var cache = try ClientSessionCache.init(testing.allocator, fuzz_cache_limits);
    var leases = [_]ClientLookupResult{.miss} ** fuzz_max_live_client_leases;
    var persistence_token: ?u64 = null;
    var now_ms: i64 = 0;
    errdefer {
        cleanupAllClientLeases(&leases);
        if (persistence_token) |token| cache.endPersistenceOperation(token);
        cache.deinit();
    }

    for (0..fuzz_max_operations) |_| {
        const op = @as(ClientFuzzOp, @enumFromInt(smith.index(@typeInfo(ClientFuzzOp).@"enum".fields.len)));
        switch (op) {
            .store_reusable, .store_single_use => {
                const id = smith.value(u64);
                var ticket = try fuzzClientTicket(testing.allocator, id, smith.value(u64), now_ms);
                defer ticket.deinit();
                const before = try fingerprintClientTicket(&ticket);
                const result = cache.storeClone(&ticket, now_ms, if (op == .store_single_use) .single_use else .reusable);
                try testing.expect(result == .stored or result == .replaced or result == .rejected_capacity or result == .storage_failed);
                try testing.expectEqualDeep(before, try fingerprintClientTicket(&ticket));
            },
            .replace_existing => {
                var first = try fuzzClientTicket(testing.allocator, 7, 0, now_ms);
                defer first.deinit();
                _ = cache.storeClone(&first, now_ms, .reusable);
                var replacement = try fuzzClientTicket(testing.allocator, 7, 1, now_ms + 1);
                defer replacement.deinit();
                _ = cache.storeClone(&replacement, now_ms + 1, .single_use);
            },
            .lookup_compatible, .lookup_incompatible => {
                const sni = if (op == .lookup_compatible) "c0.example.test" else "not-present.example.test";
                var result = cache.lookupOffers(testCandidate(sni), now_ms);
                if (result == .hit) {
                    if (firstClientLeaseSlot(&leases)) |slot| {
                        leases[slot].deinit();
                        leases[slot] = result;
                    } else {
                        result.deinit();
                    }
                } else {
                    result.deinit();
                }
            },
            .finish_selected => for (&leases) |*lease| {
                if (lease.* == .hit) {
                    const selected = if (lease.hit.offers.len == 0) 0 else smith.index(lease.hit.offers.len + 1);
                    const outcome: pre_shared_key.ClientOfferOutcome = .{ .selected = selected };
                    const before = try captureClientLeaseTransition(&cache, &lease.hit);
                    lease.hit.finish(outcome);
                    lease.deinit();
                    lease.* = .miss;
                    try expectClientLeaseTransition(&cache, before, outcome);
                    break;
                }
            },
            .drop_offer => for (&leases) |*lease| {
                if (lease.* == .hit and lease.hit.offers.len > 0) {
                    const dropped = smith.index(lease.hit.offers.len);
                    const before = try captureClientLeaseTransition(&cache, &lease.hit);
                    lease.hit.dropOffer(dropped);
                    try expectClientDropOfferTransition(&cache, before, dropped);
                    break;
                }
            },
            .finish_not_selected => for (&leases) |*lease| {
                if (lease.* == .hit) {
                    const before = try captureClientLeaseTransition(&cache, &lease.hit);
                    lease.hit.finish(.not_selected);
                    lease.deinit();
                    lease.* = .miss;
                    try expectClientLeaseTransition(&cache, before, .not_selected);
                    break;
                }
            },
            .abort_or_deinit => for (&leases) |*lease| {
                if (lease.* == .hit) {
                    const before = try captureClientLeaseTransition(&cache, &lease.hit);
                    lease.deinit();
                    lease.* = .miss;
                    try expectClientLeaseTransition(&cache, before, .aborted);
                    break;
                }
            },
            .advance_clock => now_ms +|= fuzz_clock_steps[smith.index(fuzz_clock_steps.len)],
            .cleanup => _ = cache.cleanup(now_ms),
            .begin_persistence => if (persistence_token == null) {
                persistence_token = cache.beginPersistenceOperation() catch null;
            } else {
                try testing.expectError(error.CacheBusy, cache.beginPersistenceOperation());
            },
            .end_persistence_correct => if (persistence_token) |token| {
                cache.endPersistenceOperation(token);
                persistence_token = null;
            },
            .end_persistence_wrong_or_stale => cache.endPersistenceOperation(wrongPersistenceToken(smith, persistence_token)),
            .clone_for_persistence => {
                var clones = cache.cloneLiveForPersistence(testing.allocator, now_ms) catch |err| switch (err) {
                    error.CacheBusy, error.OutOfMemory => null,
                };
                if (clones) |*list| {
                    for (list.items) |*item| item.deinit();
                    list.deinit(testing.allocator);
                }
            },
            .restore_clones => {
                try finishAllClientLeasesChecked(&cache, &leases);
                if (persistence_token) |token| {
                    cache.endPersistenceOperation(token);
                    persistence_token = null;
                }
                var items: [fuzz_max_persisted_records]PersistedClientEntry = undefined;
                const n = 1 + smith.index(3);
                for (0..n) |i| {
                    const sequence: u64 = @intCast(i + 1);
                    items[i] = .{
                        .ticket = try fuzzClientTicket(testing.allocator, smith.value(u64), @intCast(i), now_ms),
                        .usage = if (smith.index(2) == 0) .reusable else .single_use,
                        .insertion_sequence = sequence,
                        .lru_sequence = sequence,
                    };
                }
                cache.restoreClones(items[0..n], now_ms) catch |err| try testing.expectEqual(error.OutOfMemory, err);
            },
            .force_sequence_renumber => {
                cache.mutex.lock();
                cache.next_insertion_sequence = std.math.maxInt(u64);
                cache.next_lru_sequence = std.math.maxInt(u64);
                cache.mutex.unlock();
                var ticket = try fuzzClientTicket(testing.allocator, 13, 0, now_ms);
                defer ticket.deinit();
                _ = cache.storeClone(&ticket, now_ms, .reusable);
            },
            .quiescent_reset => {
                try finishAllClientLeasesChecked(&cache, &leases);
                if (persistence_token) |token| {
                    cache.endPersistenceOperation(token);
                    persistence_token = null;
                }
                cache.deinit();
                cache = try ClientSessionCache.init(testing.allocator, fuzz_cache_limits);
            },
            .client_oom_sweep => switch (smith.index(3)) {
                0 => try clientStoreOomSweep(),
                1 => try clientLookupOomSweep(),
                else => try clientPersistenceOomSweep(),
            },
        }
        try expectClientCacheInvariants(&cache);
        try expectClientLeaseModel(&cache, &leases, persistence_token);
    }

    try finishAllClientLeasesChecked(&cache, &leases);
    if (persistence_token) |token| cache.endPersistenceOperation(token);
    try testing.expect(!cache.hasOutstandingLease());
    const before_destroy = testResetDestroyCounters();
    const remaining = cache.count();
    cache.deinit();
    try expectDestroyDelta(before_destroy, @intCast(remaining), 0, 0);
}

fn serverHandleWithByte(byte: u8) [stateful_identity_len]u8 {
    var handle = [_]u8{byte} ** stateful_identity_len;
    @memcpy(handle[0..4], &stateful_magic);
    std.mem.writeInt(u16, handle[4..6], stateful_version, .big);
    std.mem.writeInt(u16, handle[6..8], 0, .big);
    return handle;
}

fn cleanupAllServerLeases(leases: *[fuzz_max_live_server_leases]ResolveLeaseResult) void {
    for (leases) |*lease| {
        lease.deinit();
        lease.* = .miss;
    }
}

fn firstServerLeaseSlot(leases: *[fuzz_max_live_server_leases]ResolveLeaseResult) ?usize {
    for (leases, 0..) |*lease, i| {
        if (lease.* != .hit) return i;
    }
    return null;
}

fn finishAllServerLeasesChecked(cache: *StatefulServerCache, leases: *[fuzz_max_live_server_leases]ResolveLeaseResult) !void {
    for (leases) |*lease| {
        if (lease.* != .hit) continue;
        const before = try captureServerLeaseTransition(cache, &lease.hit.lease);
        lease.deinit();
        lease.* = .miss;
        try expectServerLeaseTransition(cache, before, .release);
    }
}

fn expectServerLeaseModel(
    cache: *StatefulServerCache,
    leases: *const [fuzz_max_live_server_leases]ResolveLeaseResult,
    persistence_token: ?u64,
) !void {
    cache.mutex.lock();
    defer cache.mutex.unlock();

    try testing.expectEqual(persistence_token orelse 0, cache.persistence_epoch);

    var modeled_pins: usize = 0;
    for (leases) |*result| {
        if (result.* != .hit) continue;
        try testing.expect(result.hit.lease.active);
        try testing.expectEqual(cache.cache_generation, result.hit.lease.cache_generation);
        const entry = cache.entries.get(result.hit.lease.entry_id) orelse {
            try testing.expect(!result.hit.lease.single_use);
            continue;
        };
        try testing.expectEqual(result.hit.lease.single_use, entry.usage == .single_use);
        if (result.hit.lease.single_use) {
            modeled_pins += 1;
            try testing.expectEqual(@as(?u64, null), persistence_token);
            try testing.expectEqual(result.hit.lease.lease_epoch, entry.active_lease_epoch.?);
        }
    }

    var cache_pins: usize = 0;
    var it = cache.entries.iterator();
    while (it.next()) |kv| {
        const entry = kv.value_ptr.*;
        const epoch = entry.active_lease_epoch orelse continue;
        cache_pins += 1;
        try testing.expectEqual(UsagePolicy.single_use, entry.usage);
        try testing.expectEqual(@as(?u64, null), persistence_token);
        var owners: usize = 0;
        for (leases) |*result| {
            if (result.* != .hit) continue;
            const lease = result.hit.lease;
            try testing.expectEqual(cache.cache_generation, lease.cache_generation);
            if (lease.single_use and lease.entry_id == kv.key_ptr.* and lease.lease_epoch == epoch) owners += 1;
        }
        try testing.expectEqual(@as(usize, 1), owners);
    }
    try testing.expectEqual(modeled_pins, cache_pins);
}

fn serverInsertOomSweep() !void {
    var saw_failure = false;
    var saw_success = false;
    for (0..fuzz_max_oom_fail_index + 1) |fail_index| {
        var backing: [1 << 18]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var fixed = FixedRandom{ .pattern_for_call = &.{ 1, 2, 3, 4, 5 } };
        var cache = try StatefulServerCache.init(fba.allocator(), fuzz_cache_limits, fixed.source());
        defer cache.deinit();
        var existing = try fuzzServerState(fba.allocator(), 0);
        var h0: [stateful_identity_len]u8 = undefined;
        try testing.expectEqual(StoreResult.stored, cache.insertMove(&existing, 0, .reusable, &h0));
        var before = try ServerCacheState.capture(&cache);
        defer before.deinit();

        var incoming = try fuzzServerState(testing.allocator, 1);
        defer incoming.deinit();
        var out: [stateful_identity_len]u8 = [_]u8{0xEE} ** stateful_identity_len;
        var failing = testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();
        const result = cache.insertMove(&incoming, 1, .reusable, &out);
        cache.allocator = fba.allocator();
        if (result == .storage_failed) {
            saw_failure = true;
            try testing.expectEqualSlices(u8, &([_]u8{0xEE} ** stateful_identity_len), &out);
            var after = try ServerCacheState.capture(&cache);
            defer after.deinit();
            try before.expectEqual(&after);
        } else {
            try testing.expectEqual(StoreResult.stored, result);
            saw_success = true;
            break;
        }
    }
    try testing.expect(saw_failure);
    try testing.expect(saw_success);
}

fn serverResolveOomSweep() !void {
    var saw_failure = false;
    var saw_success = false;
    for (0..fuzz_max_oom_fail_index + 1) |fail_index| {
        var backing: [1 << 18]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var fixed = FixedRandom{ .pattern_for_call = &.{ 9, 10, 11 } };
        var cache = try StatefulServerCache.init(fba.allocator(), fuzz_cache_limits, fixed.source());
        defer cache.deinit();
        var state = try fuzzServerStateWithCompat(fba.allocator(), 0);
        var handle: [stateful_identity_len]u8 = undefined;
        try testing.expectEqual(StoreResult.stored, cache.insertMove(&state, 0, .single_use, &handle));
        var before = try ServerCacheState.capture(&cache);
        defer before.deinit();

        var failing = testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();
        var result = cache.resolveLease(&handle, 1);
        cache.allocator = fba.allocator();
        defer result.deinit();

        if (result == .storage_failed) {
            saw_failure = true;
            var after = try ServerCacheState.capture(&cache);
            defer after.deinit();
            try before.expectEqual(&after);
        } else {
            try testing.expect(result == .hit);
            saw_success = true;
            break;
        }
    }
    try testing.expect(saw_failure);
    try testing.expect(saw_success);
}

fn serverPersistenceOomSweep() !void {
    var saw_failure = false;
    var saw_success = false;
    for (0..fuzz_max_oom_fail_index + 1) |fail_index| {
        var backing: [1 << 18]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&backing);
        var fixed = FixedRandom{ .pattern_for_call = &.{ 21, 22, 23 } };
        var cache = try StatefulServerCache.init(fba.allocator(), fuzz_cache_limits, fixed.source());
        defer cache.deinit();
        var existing = try fuzzServerState(fba.allocator(), 0);
        var h0: [stateful_identity_len]u8 = undefined;
        try testing.expectEqual(StoreResult.stored, cache.insertMove(&existing, 0, .reusable, &h0));
        var before = try ServerCacheState.capture(&cache);
        defer before.deinit();

        var p0 = PersistedServerEntry{ .handle = serverHandleWithByte(0xA1), .usage = .reusable, .state = try fuzzServerState(testing.allocator, 1), .lru_sequence = 1 };
        var p1 = PersistedServerEntry{ .handle = serverHandleWithByte(0xA2), .usage = .single_use, .state = try fuzzServerState(testing.allocator, 2), .lru_sequence = 2 };
        var items = [_]PersistedServerEntry{ p0, p1 };
        _ = &p0;
        _ = &p1;

        var failing = testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = fail_index });
        cache.allocator = failing.allocator();
        const result = cache.restoreEntries(&items, 3);
        cache.allocator = fba.allocator();

        if (result) |_| {
            saw_success = true;
            break;
        } else |err| switch (err) {
            error.OutOfMemory => {
                saw_failure = true;
                var after = try ServerCacheState.capture(&cache);
                defer after.deinit();
                try before.expectEqual(&after);
            },
            error.DuplicateHandle => return error.TestUnexpectedResult,
        }
    }
    try testing.expect(saw_failure);
    try testing.expect(saw_success);
}

fn publicLeaseBoxOomReleasesPin() !void {
    var fixed = FixedRandom{ .pattern_for_call = &.{ 0x31, 0x32, 0x33 } };
    var cache = try StatefulServerCache.init(testing.allocator, fuzz_cache_limits, fixed.source());
    defer cache.deinit();
    var state = try fuzzServerState(testing.allocator, 0);
    var handle: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&state, 0, .single_use, &handle));

    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.ResolverFailed, resolveStatefulServerPsk(&cache, failing.allocator(), &handle, 1));

    var retry = try resolveStatefulServerPsk(&cache, testing.allocator, &handle, 1);
    defer retry.deinit();
    try testing.expect(retry == .hit);
}

fn controlledServerCollisionProgram(expect_retry_success: bool) !void {
    var random = FixedRandom{ .pattern_for_call = if (expect_retry_success) &.{ 0x44, 0x44, 0x45 } else &.{ 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 } };
    var cache = try StatefulServerCache.init(testing.allocator, fuzz_cache_limits, random.source());
    defer cache.deinit();

    var a = try fuzzServerState(testing.allocator, 44);
    var ha: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&a, 0, .reusable, &ha));

    var b = try fuzzServerState(testing.allocator, 45);
    defer b.deinit();
    const b_fingerprint = try fingerprintServerState(&b);
    var hb: [stateful_identity_len]u8 = [_]u8{0xEE} ** stateful_identity_len;
    var before = try ServerCacheState.capture(&cache);
    defer before.deinit();

    const result = cache.insertMove(&b, 1, .reusable, &hb);
    if (expect_retry_success) {
        try testing.expectEqual(StoreResult.stored, result);
        try testing.expect(!std.mem.eql(u8, &ha, &hb));
    } else {
        try testing.expectEqual(StoreResult.rejected_handle_generation_failed, result);
        try testing.expectEqualSlices(u8, &([_]u8{0xEE} ** stateful_identity_len), &hb);
        var after = try ServerCacheState.capture(&cache);
        defer after.deinit();
        try before.expectEqual(&after);
        try testing.expectEqualDeep(b_fingerprint, try fingerprintServerState(&b));
    }
}

fn runServerFuzzCase(smith: *std.testing.Smith) !void {
    var fixed = FixedRandom{ .pattern_for_call = &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 } };
    var cache = try StatefulServerCache.init(testing.allocator, fuzz_cache_limits, fixed.source());
    var leases = [_]ResolveLeaseResult{.miss} ** fuzz_max_live_server_leases;
    var handles = [_][stateful_identity_len]u8{([_]u8{0} ** stateful_identity_len)} ** fuzz_cache_limits.max_entries;
    var handle_count: usize = 0;
    var persistence_token: ?u64 = null;
    var now_ms: i64 = 0;
    errdefer {
        cleanupAllServerLeases(&leases);
        if (persistence_token) |token| cache.endPersistenceOperation(token);
        cache.deinit();
    }

    for (0..fuzz_max_operations) |_| {
        const op = @as(ServerFuzzOp, @enumFromInt(smith.index(@typeInfo(ServerFuzzOp).@"enum".fields.len)));
        switch (op) {
            .insert_reusable, .insert_single_use => {
                var state = try fuzzServerState(testing.allocator, smith.value(u64));
                defer state.deinit();
                const before = try fingerprintServerState(&state);
                var out: [stateful_identity_len]u8 = undefined;
                const result = cache.insertMove(&state, now_ms, if (op == .insert_single_use) .single_use else .reusable, &out);
                if (!(result == .stored or result == .rejected_capacity or result == .rejected_handle_generation_failed or result == .storage_failed))
                    return error.ServerFuzzUnexpectedInsertResult;
                if (result == .stored) {
                    if (handle_count < handles.len) {
                        handles[handle_count] = out;
                        handle_count += 1;
                    }
                    if (!isValidStatefulHandleShape(&out)) return error.ServerFuzzInvalidInsertedHandle;
                } else {
                    try testing.expectEqualDeep(before, try fingerprintServerState(&state));
                }
            },
            .resolve_known => if (handle_count > 0) {
                var result = cache.resolveLease(&handles[smith.index(handle_count)], now_ms);
                if (result == .hit) {
                    if (firstServerLeaseSlot(&leases)) |slot| {
                        leases[slot].deinit();
                        leases[slot] = result;
                    } else {
                        result.deinit();
                    }
                } else result.deinit();
            },
            .resolve_unknown => {
                var unknown = serverHandleWithByte(@truncate(smith.value(u64)));
                var result = cache.resolveLease(&unknown, now_ms);
                defer result.deinit();
            },
            .resolve_malformed_shape => {
                var malformed = serverHandleWithByte(0x42);
                switch (smith.index(4)) {
                    0 => malformed[0] ^= 0xff,
                    1 => std.mem.writeInt(u16, malformed[4..6], 2, .big),
                    2 => std.mem.writeInt(u16, malformed[6..8], 1, .big),
                    else => {},
                }
                const slice = if (smith.index(2) == 0) malformed[0 .. stateful_identity_len - 1] else malformed[0..];
                var result = cache.resolveLease(slice, now_ms);
                defer result.deinit();
            },
            .resolve_through_public_adapter => if (handle_count > 0) {
                const handle = &handles[smith.index(handle_count)];
                var result = try resolveStatefulServerPsk(&cache, testing.allocator, handle, now_ms);
                if (result == .hit) {
                    const before = try captureServerHandleTransition(&cache, handle);
                    const box_before = test_public_server_lease_box_destroy_count;
                    switch (smith.index(3)) {
                        0 => {
                            if (result.hit.on_selected) |hook| hook.complete();
                            result.hit.lease.commit();
                            result.deinit();
                            try expectServerLeaseTransition(&cache, before, .commit);
                        },
                        1 => {
                            result.hit.lease.release();
                            result.deinit();
                            try expectServerLeaseTransition(&cache, before, .release);
                        },
                        else => {
                            result.deinit();
                            try expectServerLeaseTransition(&cache, before, .release);
                        },
                    }
                    const expected_box_delta: u64 = if (before.single_use) 1 else 0;
                    try testing.expectEqual(box_before + expected_box_delta, test_public_server_lease_box_destroy_count);
                } else {
                    result.deinit();
                }
            },
            .commit_lease => for (&leases) |*lease| {
                if (lease.* == .hit) {
                    const before = try captureServerLeaseTransition(&cache, &lease.hit.lease);
                    lease.hit.lease.commit();
                    lease.deinit();
                    lease.* = .miss;
                    try expectServerLeaseTransition(&cache, before, .commit);
                    break;
                }
            },
            .release_lease => for (&leases) |*lease| {
                if (lease.* == .hit) {
                    const before = try captureServerLeaseTransition(&cache, &lease.hit.lease);
                    lease.hit.lease.release();
                    lease.deinit();
                    lease.* = .miss;
                    try expectServerLeaseTransition(&cache, before, .release);
                    break;
                }
            },
            .deinit_lease => for (&leases) |*lease| {
                if (lease.* == .hit) {
                    const before = try captureServerLeaseTransition(&cache, &lease.hit.lease);
                    lease.deinit();
                    lease.* = .miss;
                    try expectServerLeaseTransition(&cache, before, .release);
                    break;
                }
            },
            .complete_reusable_selection_hook => if (handle_count > 0) {
                const handle = &handles[smith.index(handle_count)];
                var result = try resolveStatefulServerPsk(&cache, testing.allocator, handle, now_ms);
                if (result == .hit) {
                    if (result.hit.on_selected) |hook| {
                        const before = try captureServerHandleTransition(&cache, handle);
                        hook.complete();
                        try expectServerLeaseTransition(&cache, before, .commit);
                    }
                }
                result.deinit();
            },
            .advance_clock => now_ms +|= fuzz_clock_steps[smith.index(fuzz_clock_steps.len)],
            .cleanup => _ = cache.cleanup(now_ms),
            .begin_persistence => if (persistence_token == null) {
                persistence_token = cache.beginPersistenceOperation() catch null;
            } else {
                try testing.expectError(error.CacheBusy, cache.beginPersistenceOperation());
            },
            .end_persistence_correct => if (persistence_token) |token| {
                cache.endPersistenceOperation(token);
                persistence_token = null;
            },
            .end_persistence_wrong_or_stale => cache.endPersistenceOperation(wrongPersistenceToken(smith, persistence_token)),
            .clone_for_persistence => {
                var clones = cache.cloneLiveForPersistence(testing.allocator, now_ms) catch |err| switch (err) {
                    error.CacheBusy, error.OutOfMemory => null,
                };
                if (clones) |*list| {
                    for (list.items) |*item| item.deinit();
                    list.deinit(testing.allocator);
                }
            },
            .restore_entries => {
                try finishAllServerLeasesChecked(&cache, &leases);
                if (persistence_token) |token| {
                    cache.endPersistenceOperation(token);
                    persistence_token = null;
                }
                var items: [fuzz_max_persisted_records]PersistedServerEntry = undefined;
                const n = 1 + smith.index(3);
                for (0..n) |i| {
                    const sequence: u64 = @intCast(i + 1);
                    items[i] = .{
                        .handle = serverHandleWithByte(@truncate(0xA0 + i + smith.index(5))),
                        .usage = if (smith.index(2) == 0) .reusable else .single_use,
                        .state = try fuzzServerState(testing.allocator, smith.value(u64)),
                        .lru_sequence = sequence,
                    };
                }
                cache.restoreEntries(items[0..n], now_ms) catch |err| switch (err) {
                    error.OutOfMemory, error.DuplicateHandle => {},
                };
            },
            .entropy_failure => {
                const old = cache.random;
                cache.random = AlwaysFailRandom.source();
                var state = try fuzzServerState(testing.allocator, smith.value(u64));
                defer state.deinit();
                var out: [stateful_identity_len]u8 = [_]u8{0xEE} ** stateful_identity_len;
                var before = try ServerCacheState.capture(&cache);
                defer before.deinit();
                if (cache.insertMove(&state, now_ms, .reusable, &out) != .rejected_handle_generation_failed)
                    return error.ServerFuzzEntropyFailureNotTyped;
                if (!std.mem.eql(u8, &([_]u8{0xEE} ** stateful_identity_len), &out))
                    return error.ServerFuzzEntropyFailureMutatedOutput;
                var after = try ServerCacheState.capture(&cache);
                defer after.deinit();
                try before.expectEqual(&after);
                cache.random = old;
            },
            .handle_collision_then_success, .handle_collision_exhaustion => {
                try controlledServerCollisionProgram(op == .handle_collision_then_success);
            },
            .force_lru_renumber => {
                cache.mutex.lock();
                cache.next_lru_sequence = std.math.maxInt(u64);
                cache.mutex.unlock();
                var state = try fuzzServerState(testing.allocator, 60);
                defer state.deinit();
                var out: [stateful_identity_len]u8 = undefined;
                _ = cache.insertMove(&state, now_ms, .reusable, &out);
                if (handle_count < handles.len and isValidStatefulHandleShape(&out)) {
                    handles[handle_count] = out;
                    handle_count += 1;
                }
            },
            .quiescent_reset => {
                try finishAllServerLeasesChecked(&cache, &leases);
                if (persistence_token) |token| {
                    cache.endPersistenceOperation(token);
                    persistence_token = null;
                }
                cache.deinit();
                fixed = .{ .pattern_for_call = &.{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 } };
                cache = try StatefulServerCache.init(testing.allocator, fuzz_cache_limits, fixed.source());
                handle_count = 0;
            },
            .server_oom_sweep => switch (smith.index(4)) {
                0 => try serverInsertOomSweep(),
                1 => try serverResolveOomSweep(),
                2 => try serverPersistenceOomSweep(),
                else => try publicLeaseBoxOomReleasesPin(),
            },
        }
        expectServerCacheInvariants(&cache) catch return error.ServerFuzzCacheInvariant;
        try expectServerLeaseModel(&cache, &leases, persistence_token);
    }

    try finishAllServerLeasesChecked(&cache, &leases);
    if (persistence_token) |token| cache.endPersistenceOperation(token);
    if (cache.hasOutstandingLease()) return error.ServerFuzzOutstandingLease;
    const before_destroy = testResetDestroyCounters();
    const remaining = cache.count();
    cache.deinit();
    expectDestroyDelta(before_destroy, 0, @intCast(remaining), 0) catch return error.ServerFuzzDestroyDelta;
}

test "dropping a stale lease's offer must not assert a reusable-then-reclassified entry is globally unpinned" {
    // Found 2026-09-02 by the #675 campaign (test-tls-resumption-fuzz
    // --fuzz=10M, "client session cache operation sequence" target).
    // Reproduces the exact scenario that broke the old boolean
    // expectClientDropOfferTransition assertion, rather than a minimized
    // raw fuzzer input: this is a fuzz-*model* defect (see c7f5b675),
    // and the compact hand-written scenario below documents it more
    // durably than opaque delta-minimized Smith bytes would.
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var reusable = try makeClient(testing.allocator, "shared", "example.test");
    defer reusable.deinit();
    try testing.expectEqual(StoreResult.stored, cache.storeClone(&reusable, 0, .reusable));

    // Lease A: offered while the entry is still reusable, so its own
    // token correctly records single_use=false — it never held a pin.
    var lease_a = cache.lookupOffers(testCandidate("example.test"), 1);
    defer lease_a.deinit();
    try testing.expect(lease_a == .hit);
    const entry_id = lease_a.hit.tokens[0].entry_id;
    try testing.expect(!lease_a.hit.tokens[0].single_use);

    // Re-storing the same ticket identity reclassifies the entry in
    // place (storeClone's replace path keeps entry_id stable) — a
    // reusable entry is never pinned, so its own dedup guard does not
    // block this.
    var reclassified = try makeClient(testing.allocator, "shared", "example.test");
    defer reclassified.deinit();
    try testing.expectEqual(StoreResult.replaced, cache.storeClone(&reclassified, 2, .single_use));

    // Lease B: an independent, later offer of the now-single_use entry
    // legitimately pins it under a fresh epoch.
    var lease_b = cache.lookupOffers(testCandidate("example.test"), 3);
    defer lease_b.deinit();
    try testing.expect(lease_b == .hit);
    try testing.expectEqual(entry_id, lease_b.hit.tokens[0].entry_id);
    try testing.expect(lease_b.hit.tokens[0].single_use);

    const idx = cache.findIndexByEntryId(entry_id) orelse return error.TestUnexpectedResult;
    try testing.expect(cache.entries.items[idx].active_lease_epoch != null);

    // Drive the drop through the exact same helpers
    // runClientFuzzCase's .drop_offer case uses. Before c7f5b675,
    // expectClientDropOfferTransition asserted this entry must show
    // active_lease_epoch == null after the drop — lease A's own token
    // was never single_use, so per the old boolean model dropping it
    // could not leave anything pinned. That assertion is exactly what
    // failed against this scenario: dropping lease A's stale offer must
    // not disturb, or be asserted to have cleared, lease B's unrelated,
    // still-active pin.
    const before = try captureClientLeaseTransition(&cache, &lease_a.hit);
    lease_a.hit.dropOffer(0);
    try expectClientDropOfferTransition(&cache, before, 0);

    const still_idx = cache.findIndexByEntryId(entry_id) orelse return error.TestUnexpectedResult;
    try testing.expect(cache.entries.items[still_idx].active_lease_epoch != null);
}

fn fuzzClientCacheSequenceInput(_: void, smith: *std.testing.Smith) !void {
    try runClientFuzzCase(smith);
}

fn fuzzServerCacheSequenceInput(_: void, smith: *std.testing.Smith) !void {
    try runServerFuzzCase(smith);
}

test "fuzz: TLS resumption: client session cache operation sequence preserves transactional state, ownership, eviction, and lease semantics" {
    try testing.fuzz({}, fuzzClientCacheSequenceInput, .{
        .corpus = &.{
            // smith.index(ClientFuzzOp), then operation-specific ids/choices.
            &smithCorpusWords(&.{ 0, 3, 8 }),
            &smithCorpusWords(&.{ 1, 1, 0, 1, 2, 0, 5 }),
            &smithCorpusWords(&.{ 1, 2, 0, 3, 7 }),
            &smithCorpusWords(&.{ 1, 3, 0, 3, 8, 3 }),
            &smithCorpusWords(&.{ 1, 4, 0, 3, 6, 7 }),
            &smithCorpusWords(&.{ 1, 5, 0, 3, 17, 0, 0, 11 }),
            &smithCorpusWords(&.{ 0, 7, 0, 2 }),
            &smithCorpusWords(&.{ 1, 8, 0, 3, 18, 1 }),
            &smithCorpusWords(&.{ 18, 0 }),
            &smithCorpusWords(&.{ 11, 3, 12, 3 }),
            &smithCorpusWords(&.{ 11, 13, 1 }),
            &smithCorpusWords(&.{ 15, 1, 9, 15, 10, 3 }),
            &smithCorpusWords(&.{ 16, 0, 3 }),
            &smithCorpusWords(&.{ 0, 13, 0, 17 }),
        },
    });
}

test "fuzz: TLS resumption: stateful server cache operation sequence preserves transactional indexes, ownership, handle, and lease semantics" {
    try testing.fuzz({}, fuzzServerCacheSequenceInput, .{
        .corpus = &.{
            // smith.index(ServerFuzzOp), then operation-specific ids/choices.
            &smithCorpusWords(&.{ 0, 0, 2, 6 }),
            &smithCorpusWords(&.{ 0, 1, 2, 9, 3 }),
            &smithCorpusWords(&.{ 1, 2, 2, 6, 2 }),
            &smithCorpusWords(&.{ 1, 3, 2, 6 }),
            &smithCorpusWords(&.{ 1, 4, 2, 8 }),
            &smithCorpusWords(&.{ 1, 5, 2, 10, 2, 8 }),
            &smithCorpusWords(&.{ 1, 6, 2, 11, 8 }),
            &smithCorpusWords(&.{ 0, 7, 12, 2, 14, 13, 2 }),
            &smithCorpusWords(&.{ 12, 14, 1 }),
            &smithCorpusWords(&.{18}),
            &smithCorpusWords(&.{19}),
            &smithCorpusWords(&.{ 22, 0 }),
            &smithCorpusWords(&.{ 22, 1 }),
            &smithCorpusWords(&.{ 22, 3 }),
            &smithCorpusWords(&.{ 16, 2, 2, 1, 2, 3 }),
            &smithCorpusWords(&.{ 0, 15, 2, 6, 16 }),
            &smithCorpusWords(&.{ 20, 0 }),
            &smithCorpusWords(&.{ 4, 0, 4, 1, 4, 2, 4, 3 }),
            &smithCorpusWords(&.{ 0, 12, 0, 21 }),
        },
    });
}

test "server LRU freshest-sequence check holds across a saturation-forced renumber (#675 campaign FINDING F5)" {
    // FINDING F5: `commitLease`'s `reserveFreshLruSequenceLocked()` call
    // can trigger `renumberLruSequencesLocked()` when `next_lru_sequence`
    // has saturated to `maxInt(u64)` (forced here directly, exactly like
    // the fuzz model's `.force_lru_renumber` op does to probe the
    // boundary). Renumbering compacts every live entry into
    // `0..liveCount()-1` and sets `next_lru_sequence` to that count. The
    // freshly reserved value the entry being committed gets can then
    // coincidentally equal its own PRE-renumber `lru_sequence` -- a
    // numeric collision between two independently-scaled values, not a
    // failure to advance anything -- which the old
    // `live.lru_sequence != before.lru_sequence` check mistook for one.
    // Reproduced directly (no raw fuzz bytes) with 3 live entries and an
    // entry whose earlier commit happened to land on sequence 3, which a
    // rejected insert (capacity) then a second commit of that same entry
    // reproduces exactly: 3 live entries renumber to 0/1/2,
    // next_lru_sequence becomes 3, and the entry gets that freshly
    // reserved 3 right back.
    var probe = try fuzzServerState(testing.allocator, 0);
    defer probe.deinit();
    var limits = Limits.stateful_server_default;
    limits.max_entry_bytes = serverAccountedBytes(&probe) + 4;
    var cache = try StatefulServerCache.init(testing.allocator, limits, system_random_source);
    defer cache.deinit();

    var handle_a: [stateful_identity_len]u8 = undefined;
    var handle_b: [stateful_identity_len]u8 = undefined;
    var handle_c: [stateful_identity_len]u8 = undefined;

    var state_a = try fuzzServerState(testing.allocator, 0);
    defer state_a.deinit();
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&state_a, 0, .reusable, &handle_a));
    var state_b = try fuzzServerState(testing.allocator, 1);
    defer state_b.deinit();
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&state_b, 0, .reusable, &handle_b));
    var state_c = try fuzzServerState(testing.allocator, 2);
    defer state_c.deinit();
    try testing.expectEqual(StoreResult.stored, cache.insertMove(&state_c, 0, .reusable, &handle_c));

    // A, B, C consumed fresh sequences 0, 1, 2 at insert time.
    try testing.expectEqual(@as(u64, 3), cache.next_lru_sequence);

    // Commit A once: it's handed the next fresh sequence, 3.
    {
        var result = try resolveStatefulServerPsk(&cache, testing.allocator, &handle_a, 1);
        defer result.deinit();
        try testing.expect(result.hit.on_selected != null);
        result.hit.on_selected.?.complete();
    }
    try testing.expectEqual(@as(u64, 4), cache.next_lru_sequence);

    // Force the saturation boundary the fuzz model's .force_lru_renumber
    // probes.
    cache.next_lru_sequence = std.math.maxInt(u64);

    // A rejected insert (state too large for this cache's limits) must
    // not touch next_lru_sequence -- pin that assumption explicitly so a
    // future change to insertMove's rejection path that broke it would
    // fail loudly here instead of silently invalidating the rest of this
    // test.
    var oversized = try fuzzServerStateWithCompat(testing.allocator, 3);
    defer oversized.deinit();
    var discard_handle: [stateful_identity_len]u8 = undefined;
    try testing.expectEqual(StoreResult.rejected_capacity, cache.insertMove(&oversized, 0, .reusable, &discard_handle));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), cache.next_lru_sequence);

    // Commit A again. `before`'s captured lru_sequence is its stale
    // pre-renumber value (3); completing the hook renumbers the 3 live
    // entries to 0/1/2, sets next_lru_sequence=3, and hands A that
    // freshly reserved 3 right back -- the exact collision.
    const before = try captureServerHandleTransition(&cache, &handle_a);
    try testing.expectEqual(@as(u64, 3), before.lru_sequence);
    {
        var result = try resolveStatefulServerPsk(&cache, testing.allocator, &handle_a, 2);
        defer result.deinit();
        try testing.expect(result.hit.on_selected != null);
        result.hit.on_selected.?.complete();
    }
    try expectServerLeaseTransition(&cache, before, .commit);
}

test "resolveStatefulServerPsk lease-box OOM releases an acquired single-use pin and permits retry" {
    try publicLeaseBoxOomReleasesPin();
}

test "session cache test-only zeroization probes count exact client/server/lease-box destruction" {
    const before = testResetDestroyCounters();
    {
        var cache = try ClientSessionCache.init(testing.allocator, fuzz_cache_limits);
        var ticket = try fuzzClientTicket(testing.allocator, 1, 0, 0);
        defer ticket.deinit();
        try testing.expectEqual(StoreResult.stored, cache.storeClone(&ticket, 0, .reusable));
        cache.deinit();
    }
    try expectDestroyDelta(before, 1, 0, 0);

    const after_client = testResetDestroyCounters();
    {
        var fixed = FixedRandom{ .pattern_for_call = &.{0x55} };
        var cache = try StatefulServerCache.init(testing.allocator, fuzz_cache_limits, fixed.source());
        var state = try fuzzServerState(testing.allocator, 1);
        var handle: [stateful_identity_len]u8 = undefined;
        try testing.expectEqual(StoreResult.stored, cache.insertMove(&state, 0, .single_use, &handle));
        var resolved = try resolveStatefulServerPsk(&cache, testing.allocator, &handle, 1);
        resolved.deinit();
        cache.deinit();
    }
    try expectDestroyDelta(after_client, 0, 1, 1);
}
