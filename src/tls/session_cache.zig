//! Bounded, transport-neutral client and stateful-server session-resumption
//! storage (#364).
//!
//! This module owns everything #360's `session.zig` and #362's
//! `pre_shared_key.zig` deliberately do not: capacity/lifetime/LRU/eviction
//! policy, canonical origin indexing, deep-clone ownership, stateful opaque
//! handles, internal lease/pinning for single-use consumption, thread
//! safety, and secure cleanup. It does not parse PSK wire extensions,
//! generate or verify binders, or perform key-schedule derivation — see
//! `pre_shared_key.zig` / `tls13_backend.zig` (#362/PR #479) for that.
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
//! touch `root.zig` — those land once #363 (the sibling `TDTK` stateless
//! protector) merges and the two-phase issuance / resolver-lease predecessor
//! amendments described in issue #364 are made. The lease/commit/release
//! shape defined here already matches what that future resolver adapter will
//! need, so wiring it up should not require reshaping this module.

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
};

/// Non-secret observer seam. Implementations must not log or format cache
/// keys/tickets/handles; only `CacheEvent` is ever passed. Callers must
/// never be invoked while a cache mutex is held (see module doc).
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
    sequence: u64 = 0,
    entry_id: u64 = 0,
    bytes: usize = 0,
};

pub const PersistedClientEntry = struct {
    ticket: session.ClientTicketState = .{},
    usage: UsagePolicy = .reusable,

    pub fn deinit(self: *PersistedClientEntry) void {
        self.ticket.deinit();
    }
};

pub const ClientLookupResult = struct {
    offers: pre_shared_key.ClientPskOfferSet = .{},

    pub fn deinit(self: *ClientLookupResult) void {
        self.offers.deinit();
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
    next_sequence: u64 = 0,
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
        self.purgeExpiredOrigin(origin, now_unix_ms, evicted);

        for (self.entries.items) |*e| {
            if (!std.mem.eql(u8, &e.origin, &origin)) continue;
            if (!e.ticket.ticket.eql(&cloned.ticket)) continue;
            self.total_bytes -= e.bytes;
            e.ticket.deinit();
            e.ticket.moveFrom(cloned);
            e.usage = usage;
            e.sequence = self.nextSequence();
            e.bytes = clientAccountedBytes(&e.ticket);
            self.total_bytes += e.bytes;
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
            .sequence = self.nextSequence(),
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
    /// deterministic order (newest insertion sequence first, then newer
    /// `received_at_unix_ms`, then internal entry ID), and never aliases
    /// cache storage.
    pub fn lookupOffers(self: *ClientSessionCache, candidate: session.CandidateContext, now_unix_ms: i64) ClientLookupResult {
        const origin = originDigestFromCandidate(candidate);
        const Candidate = struct {
            idx: usize,
            sequence: u64,
            received_at: i64,
            entry_id: u64,

            fn moreRecent(_: void, a: @This(), b: @This()) bool {
                if (a.sequence != b.sequence) return a.sequence > b.sequence;
                if (a.received_at != b.received_at) return a.received_at > b.received_at;
                return a.entry_id > b.entry_id;
            }
        };
        var buf: [hard_max_entries_per_origin]Candidate = undefined;
        var n: usize = 0;
        var had_incompatible = false;

        var result: ClientLookupResult = .{};
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
                    continue;
                }
                const decision = session.evaluateCompatibility(&e.ticket.common, candidate, now_unix_ms);
                if (decision.resumption == .eligible and n < buf.len) {
                    buf[n] = .{ .idx = i, .sequence = e.sequence, .received_at = e.ticket.received_at_unix_ms, .entry_id = e.entry_id };
                    n += 1;
                } else if (decision.resumption != .eligible) {
                    had_incompatible = true;
                }
                i += 1;
            }

            std.mem.sort(Candidate, buf[0..n], {}, Candidate.moreRecent);

            const take = @min(n, pre_shared_key.max_offered_identities);
            for (buf[0..take]) |c| {
                var clone: session.ClientTicketState = .{};
                self.entries.items[c.idx].ticket.cloneInto(self.allocator, &clone) catch break;
                result.offers.push(&clone) catch {
                    clone.deinit();
                    break;
                };
            }
        }

        self.observer.notify(if (!result.offers.isEmpty())
            .lookup_hit
        else if (had_incompatible)
            .lookup_incompatible
        else
            .lookup_miss);
        return result;
    }

    /// Removes and wipes the single-use entry matching `ticket_identity`
    /// within `origin` once the server-selected offer has been consumed.
    /// Reusable entries are left untouched. This is the cache-side half of
    /// client single-use commit; wiring the resolved offer index back from
    /// the TLS 1.3 backend is deferred to #365 per issue #364's canonical
    /// plan (`storeClone`/`lookupOffers` already ship the reusable path plus
    /// this consumption primitive).
    pub fn consumeSingleUse(self: *ClientSessionCache, origin: OriginDigest, ticket_identity: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var i: usize = 0;
        while (i < self.entries.items.len) : (i += 1) {
            const e = &self.entries.items[i];
            if (!std.mem.eql(u8, &e.origin, &origin)) continue;
            if (e.usage != .single_use) continue;
            if (!secrets.constantTimeEqual(e.ticket.ticket.slice(), ticket_identity)) continue;
            var removed = self.entries.swapRemove(i);
            self.total_bytes -= removed.bytes;
            removed.ticket.deinit();
            return;
        }
    }

    /// Deep-clones every non-expired entry for a persistence save. Must be
    /// called outside any persistence I/O; the returned clones are fully
    /// owned by the caller.
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
            var clone: PersistedClientEntry = .{ .usage = e.usage };
            try e.ticket.cloneInto(allocator, &clone.ticket);
            out.appendAssumeCapacity(clone);
        }
        return out;
    }

    /// Restores previously-persisted entries, enforcing current limits and
    /// discarding expired ones. Each item is consumed (moved out and either
    /// stored or wiped) regardless of outcome.
    pub fn restoreClones(self: *ClientSessionCache, items: []PersistedClientEntry, now_unix_ms: i64) void {
        for (items) |*item| {
            defer item.deinit();
            if (item.ticket.common.isExpired(now_unix_ms)) continue;
            _ = self.storeClone(&item.ticket, now_unix_ms, item.usage);
        }
    }

    fn purgeExpiredOrigin(self: *ClientSessionCache, origin: OriginDigest, now_unix_ms: i64, evicted: *usize) void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const e = &self.entries.items[i];
            if (std.mem.eql(u8, &e.origin, &origin) and e.ticket.common.isExpired(now_unix_ms)) {
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
            if (best == null or e.sequence < self.entries.items[best.?].sequence) best = i;
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
            if (best == null or e.sequence < self.entries.items[best.?].sequence) best = i;
        }
        const idx = best orelse return false;
        var removed = self.entries.swapRemove(idx);
        self.total_bytes -= removed.bytes;
        removed.ticket.deinit();
        return true;
    }

    fn nextSequence(self: *ClientSessionCache) u64 {
        if (self.next_sequence == std.math.maxInt(u64)) self.renumberSequences();
        const s = self.next_sequence;
        self.next_sequence += 1;
        return s;
    }

    fn nextEntryId(self: *ClientSessionCache) u64 {
        const id = self.next_entry_id;
        self.next_entry_id +%= 1;
        return id;
    }

    fn renumberSequences(self: *ClientSessionCache) void {
        const Ctx = struct {
            fn lessThan(_: void, a: ClientEntry, b: ClientEntry) bool {
                return a.sequence < b.sequence;
            }
        };
        std.mem.sort(ClientEntry, self.entries.items, {}, Ctx.lessThan);
        for (self.entries.items, 0..) |*e, i| e.sequence = @intCast(i);
        self.next_sequence = self.entries.items.len;
    }
};

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

const ServerEntry = struct {
    state: session.ServerRecoverableState = .{},
    origin: OriginDigest = [_]u8{0} ** origin_digest_len,
    handle: [stateful_identity_len]u8 = [_]u8{0} ** stateful_identity_len,
    usage: UsagePolicy = .reusable,
    generation: u64 = 0,
    leased: bool = false,
    sequence: u64 = 0,
    bytes: usize = 0,
};

pub const PersistedServerEntry = struct {
    handle: [stateful_identity_len]u8 = [_]u8{0} ** stateful_identity_len,
    usage: UsagePolicy = .reusable,
    state: session.ServerRecoverableState = .{},

    pub fn deinit(self: *PersistedServerEntry) void {
        self.state.deinit();
        secrets.secureZero(&self.handle);
    }
};

/// An owned lease over a resolved single-use or reusable stateful entry.
/// Reusable leases are a no-op on `commit`/`release`. `generation` guards
/// against ABA if the same handle bytes were ever reinserted between
/// resolution and commit/release.
pub const ServerLeaseToken = struct {
    handle: [stateful_identity_len]u8,
    generation: u64,
    single_use: bool,
};

pub const ServerLookupResult = union(enum) {
    hit: struct { state: session.ServerRecoverableState, lease: ServerLeaseToken },
    miss,
    expired,
    incompatible: session.ResumeMismatch,
    storage_failed,

    pub fn deinit(self: *ServerLookupResult) void {
        switch (self.*) {
            .hit => |*h| h.state.deinit(),
            else => {},
        }
    }
};

/// Bounded stateful server-side ticket/session store keyed by a random
/// opaque handle. Process-shared and thread-safe (see module doc).
pub const StatefulServerCache = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    random: RandomSource,
    observer: Observer = .{},
    mutex: zig_compat.Mutex = .{},
    entries: std.ArrayListUnmanaged(ServerEntry) = .empty,
    total_bytes: usize = 0,
    next_sequence: u64 = 0,
    next_generation: u64 = 1,

    pub fn init(allocator: std.mem.Allocator, limits: Limits, random: RandomSource) error{InvalidLimits}!StatefulServerCache {
        try limits.validate();
        return .{ .allocator = allocator, .limits = limits, .random = random };
    }

    /// Requires quiescence: no outstanding leases and no concurrent callers.
    pub fn deinit(self: *StatefulServerCache) void {
        for (self.entries.items) |*e| {
            e.state.deinit();
            secrets.secureZero(&e.handle);
        }
        self.entries.deinit(self.allocator);
        self.entries = .empty;
        self.total_bytes = 0;
    }

    pub fn setObserver(self: *StatefulServerCache, observer: Observer) void {
        self.observer = observer;
    }

    pub fn count(self: *StatefulServerCache) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.items.len;
    }

    pub fn totalBytes(self: *StatefulServerCache) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.total_bytes;
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
                break :blk self.insertLocked(state, handle, origin, usage, now_unix_ms, bytes, &evicted);
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

    fn insertLocked(
        self: *StatefulServerCache,
        state: *session.ServerRecoverableState,
        handle: [stateful_identity_len]u8,
        origin: OriginDigest,
        usage: UsagePolicy,
        now_unix_ms: i64,
        bytes: usize,
        evicted: *usize,
    ) StoreResult {
        self.purgeExpiredOrigin(origin, now_unix_ms, evicted);
        if (self.handleExistsLocked(&handle)) return .rejected_capacity;

        const origin_count = self.countOrigin(origin);
        if (origin_count == 0 and self.countDistinctOrigins() >= self.limits.max_origins) {
            return .rejected_capacity;
        }

        self.entries.ensureUnusedCapacity(self.allocator, 1) catch return .storage_failed;

        while (self.countOrigin(origin) >= self.limits.max_entries_per_origin) {
            if (!self.evictOldestUnleasedInOrigin(origin)) return .rejected_capacity;
            evicted.* += 1;
        }
        while (self.entries.items.len >= self.limits.max_entries or
            self.total_bytes + bytes > self.limits.max_total_bytes)
        {
            if (self.entries.items.len == 0) return .rejected_capacity;
            if (!self.evictOldestUnleasedGlobal()) return .rejected_capacity;
            evicted.* += 1;
        }

        var entry: ServerEntry = .{
            .origin = origin,
            .handle = handle,
            .usage = usage,
            .generation = self.nextGeneration(),
            .sequence = self.nextSequence(),
            .bytes = bytes,
        };
        entry.state.moveFrom(state);
        self.entries.appendAssumeCapacity(entry);
        self.total_bytes += bytes;
        return .stored;
    }

    /// Recheck-on-lookup path. A hit returns an owned clone plus a lease:
    /// call `commit` after binder verification succeeds (single-use entries
    /// are then removed and wiped) or `release` on any incompatibility/bad
    /// binder/teardown path (single-use entries become resolvable again).
    /// A single-use entry already leased by a concurrent resolution is
    /// reported as `.miss`, never as a second hit.
    pub fn lookupLease(self: *StatefulServerCache, identity: []const u8, candidate: session.CandidateContext, now_unix_ms: i64) ServerLookupResult {
        if (!isValidHandleShape(identity)) {
            self.observer.notify(.lookup_miss);
            return .miss;
        }

        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.entries.items, 0..) |*e, i| {
            if (!secrets.constantTimeEqual(&e.handle, identity)) continue;

            if (e.usage == .single_use and e.leased) {
                self.observer.notify(.lookup_miss);
                return .miss;
            }

            if (e.state.common.isExpired(now_unix_ms)) {
                var removed = self.entries.swapRemove(i);
                self.total_bytes -= removed.bytes;
                removed.state.deinit();
                secrets.secureZero(&removed.handle);
                self.observer.notify(.lookup_expired);
                return .expired;
            }

            const decision = session.evaluateCompatibility(&e.state.common, candidate, now_unix_ms);
            if (decision.resumption != .eligible) {
                self.observer.notify(.lookup_incompatible);
                return .{ .incompatible = decision.resumption.rejected };
            }

            var cloned: session.ServerRecoverableState = .{};
            e.state.cloneInto(self.allocator, &cloned) catch {
                self.observer.notify(.storage_failed);
                return .storage_failed;
            };

            const single_use = e.usage == .single_use;
            if (single_use) e.leased = true;

            self.observer.notify(.lookup_hit);
            return .{ .hit = .{
                .state = cloned,
                .lease = .{ .handle = e.handle, .generation = e.generation, .single_use = single_use },
            } };
        }

        self.observer.notify(.lookup_miss);
        return .miss;
    }

    /// Consumes a single-use entry after binder success, before any
    /// PSK-selected ServerHello byte is emitted. No-op for reusable leases
    /// or a lease whose entry has already been removed/replaced (stale
    /// generation).
    pub fn commit(self: *StatefulServerCache, lease: ServerLeaseToken) void {
        if (!lease.single_use) return;
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.entries.items, 0..) |*e, i| {
            if (!secrets.constantTimeEqual(&e.handle, &lease.handle)) continue;
            if (e.generation != lease.generation) return;
            var removed = self.entries.swapRemove(i);
            self.total_bytes -= removed.bytes;
            removed.state.deinit();
            secrets.secureZero(&removed.handle);
            return;
        }
    }

    /// Releases a pinned single-use entry (incompatibility, bad binder, or
    /// teardown) so it can be resolved again. No-op for reusable leases.
    pub fn release(self: *StatefulServerCache, lease: ServerLeaseToken) void {
        if (!lease.single_use) return;
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.entries.items) |*e| {
            if (!secrets.constantTimeEqual(&e.handle, &lease.handle)) continue;
            if (e.generation != lease.generation) return;
            e.leased = false;
            return;
        }
    }

    pub fn cloneLiveForPersistence(
        self: *StatefulServerCache,
        allocator: std.mem.Allocator,
        now_unix_ms: i64,
    ) error{OutOfMemory}!std.ArrayListUnmanaged(PersistedServerEntry) {
        self.mutex.lock();
        defer self.mutex.unlock();

        var out: std.ArrayListUnmanaged(PersistedServerEntry) = .empty;
        errdefer {
            for (out.items) |*p| p.deinit();
            out.deinit(allocator);
        }
        try out.ensureTotalCapacityPrecise(allocator, self.entries.items.len);
        for (self.entries.items) |*e| {
            if (e.state.common.isExpired(now_unix_ms)) continue;
            var clone: PersistedServerEntry = .{ .handle = e.handle, .usage = e.usage };
            try e.state.cloneInto(allocator, &clone.state);
            out.appendAssumeCapacity(clone);
        }
        return out;
    }

    /// Restores previously-persisted entries, enforcing current limits,
    /// discarding expired ones, and skipping any that collide with an
    /// already-live handle. Each item is consumed regardless of outcome.
    pub fn restoreEntries(self: *StatefulServerCache, items: []PersistedServerEntry, now_unix_ms: i64) void {
        for (items) |*item| {
            defer item.deinit();
            if (item.state.common.isExpired(now_unix_ms)) continue;

            const bytes = serverAccountedBytes(&item.state);
            const origin = originDigestFromCommon(&item.state.common);
            var evicted: usize = 0;
            self.mutex.lock();
            const result = self.insertLocked(&item.state, item.handle, origin, item.usage, now_unix_ms, bytes, &evicted);
            self.mutex.unlock();
            _ = result;
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
            if (!self.handleExistsLocked(&candidate)) {
                out.* = candidate;
                return;
            }
        }
        return error.HandleGenerationFailed;
    }

    fn handleExistsLocked(self: *StatefulServerCache, handle: *const [stateful_identity_len]u8) bool {
        for (self.entries.items) |*e| {
            if (secrets.constantTimeEqual(&e.handle, handle)) return true;
        }
        return false;
    }

    fn purgeExpiredOrigin(self: *StatefulServerCache, origin: OriginDigest, now_unix_ms: i64, evicted: *usize) void {
        var i: usize = 0;
        while (i < self.entries.items.len) {
            const e = &self.entries.items[i];
            if (e.leased) {
                i += 1;
                continue;
            }
            if (std.mem.eql(u8, &e.origin, &origin) and e.state.common.isExpired(now_unix_ms)) {
                var removed = self.entries.swapRemove(i);
                self.total_bytes -= removed.bytes;
                removed.state.deinit();
                secrets.secureZero(&removed.handle);
                evicted.* += 1;
                continue;
            }
            i += 1;
        }
    }

    fn countOrigin(self: *StatefulServerCache, origin: OriginDigest) usize {
        var n: usize = 0;
        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, &e.origin, &origin)) n += 1;
        }
        return n;
    }

    fn countDistinctOrigins(self: *StatefulServerCache) usize {
        var n: usize = 0;
        outer: for (self.entries.items, 0..) |*e, i| {
            for (self.entries.items[0..i]) |*prev| {
                if (std.mem.eql(u8, &prev.origin, &e.origin)) continue :outer;
            }
            n += 1;
        }
        return n;
    }

    fn evictOldestUnleasedInOrigin(self: *StatefulServerCache, origin: OriginDigest) bool {
        var best: ?usize = null;
        for (self.entries.items, 0..) |*e, i| {
            if (e.leased) continue;
            if (!std.mem.eql(u8, &e.origin, &origin)) continue;
            if (best == null or e.sequence < self.entries.items[best.?].sequence) best = i;
        }
        const idx = best orelse return false;
        var removed = self.entries.swapRemove(idx);
        self.total_bytes -= removed.bytes;
        removed.state.deinit();
        secrets.secureZero(&removed.handle);
        return true;
    }

    fn evictOldestUnleasedGlobal(self: *StatefulServerCache) bool {
        var best: ?usize = null;
        for (self.entries.items, 0..) |*e, i| {
            if (e.leased) continue;
            if (best == null or e.sequence < self.entries.items[best.?].sequence) best = i;
        }
        const idx = best orelse return false;
        var removed = self.entries.swapRemove(idx);
        self.total_bytes -= removed.bytes;
        removed.state.deinit();
        secrets.secureZero(&removed.handle);
        return true;
    }

    fn nextSequence(self: *StatefulServerCache) u64 {
        if (self.next_sequence == std.math.maxInt(u64)) self.renumberSequences();
        const s = self.next_sequence;
        self.next_sequence += 1;
        return s;
    }

    fn nextGeneration(self: *StatefulServerCache) u64 {
        const g = self.next_generation;
        self.next_generation +%= 1;
        return g;
    }

    fn renumberSequences(self: *StatefulServerCache) void {
        const Ctx = struct {
            fn lessThan(_: void, a: ServerEntry, b: ServerEntry) bool {
                return a.sequence < b.sequence;
            }
        };
        std.mem.sort(ServerEntry, self.entries.items, {}, Ctx.lessThan);
        for (self.entries.items, 0..) |*e, i| e.sequence = @intCast(i);
        self.next_sequence = self.entries.items.len;
    }
};

fn isValidHandleShape(identity: []const u8) bool {
    if (identity.len != stateful_identity_len) return false;
    if (!std.mem.eql(u8, identity[0..4], &stateful_magic)) return false;
    if (std.mem.readInt(u16, identity[4..6], .big) != stateful_version) return false;
    return true;
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
    try testing.expectEqual(@as(usize, 1), result.offers.len);
    try testing.expectEqualStrings("ticket-1", result.offers.constSlice()[0].ticket.slice());
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
    result.offers.slice()[0].ticket_age_add = 999;

    var result2 = cache.lookupOffers(testCandidate("example.test"), 10);
    defer result2.deinit();
    try testing.expectEqual(@as(u32, 1), result2.offers.constSlice()[0].ticket_age_add);
}

test "client lookup rechecks exact expiry and compatibility" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();

    var ticket = try testClient(testing.allocator, "ticket-1", "example.test", 0, 100, 0);
    _ = cache.storeClone(&ticket, 0, .reusable);
    ticket.deinit();

    // Exact lifetime boundary: age_ms == lifetime_ms is expired.
    var at_boundary = cache.lookupOffers(testCandidate("example.test"), 100_000);
    defer at_boundary.deinit();
    try testing.expectEqual(@as(usize, 0), at_boundary.offers.len);
    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "client lookup rejects SNI/ALPN/auth-binding mismatches without returning the session" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var ticket = try testClient(testing.allocator, "ticket-1", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&ticket, 0, .reusable);
    ticket.deinit();

    var mismatched_sni = cache.lookupOffers(testCandidate("other.test"), 10);
    defer mismatched_sni.deinit();
    try testing.expectEqual(@as(usize, 0), mismatched_sni.offers.len);

    var candidate = testCandidate("example.test");
    candidate.application_protocol = "h2";
    var mismatched_alpn = cache.lookupOffers(candidate, 10);
    defer mismatched_alpn.deinit();
    try testing.expectEqual(@as(usize, 0), mismatched_alpn.offers.len);

    var candidate2 = testCandidate("example.test");
    candidate2.auth_binding = session.AuthBinding.fromLeafCertificateDer("different-leaf");
    var mismatched_auth = cache.lookupOffers(candidate2, 10);
    defer mismatched_auth.deinit();
    try testing.expectEqual(@as(usize, 0), mismatched_auth.offers.len);

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
    try testing.expectEqual(@as(usize, 1), result.offers.len);
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
    try testing.expectEqual(@as(usize, 2), result.offers.len);
    // Deterministic order: newest insertion sequence first.
    try testing.expectEqualStrings("t3", result.offers.constSlice()[0].ticket.slice());
    try testing.expectEqualStrings("t2", result.offers.constSlice()[1].ticket.slice());
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
    try testing.expectEqual(@as(usize, 1), result.offers.len);
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
    cache.consumeSingleUse(origin, "single");
    try testing.expectEqual(@as(usize, 1), cache.count());
    var result = cache.lookupOffers(testCandidate("example.test"), 2);
    defer result.deinit();
    try testing.expectEqualStrings("reusable", result.offers.constSlice()[0].ticket.slice());
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

test "client cache sequence renumbering preserves relative order" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    cache.next_sequence = std.math.maxInt(u64) - 1;

    var t1 = try testClient(testing.allocator, "t1", "example.test", 0, 1000, 0);
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();
    // This store forces a renumber (next_sequence was at max - 1, so the
    // second store's nextSequence() call hits the max case).
    var t2 = try testClient(testing.allocator, "t2", "example.test", 0, 1000, 1);
    _ = cache.storeClone(&t2, 1, .reusable);
    t2.deinit();

    var result = cache.lookupOffers(testCandidate("example.test"), 2);
    defer result.deinit();
    try testing.expectEqual(@as(usize, 2), result.offers.len);
    try testing.expectEqualStrings("t2", result.offers.constSlice()[0].ticket.slice());
    try testing.expectEqualStrings("t1", result.offers.constSlice()[1].ticket.slice());
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

    var result = cache.lookupLease(&handle, testCandidate("example.test"), 10);
    defer result.deinit();
    switch (result) {
        .hit => |*h| {
            try testing.expect(!h.lease.single_use);
            cache.commit(h.lease);
        },
        else => try testing.expect(false),
    }
    // Reusable: resolving again must still hit.
    var result2 = cache.lookupLease(&handle, testCandidate("example.test"), 10);
    defer result2.deinit();
    try testing.expect(result2 == .hit);
}

test "stateful server single-use entry is pinned during resolution and consumed on commit" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .single_use, &handle);

    var result = cache.lookupLease(&handle, testCandidate("example.test"), 10);
    // Concurrent resolution while pinned must miss, not double-hit.
    const concurrent = cache.lookupLease(&handle, testCandidate("example.test"), 10);
    try testing.expect(concurrent == .miss);

    switch (result) {
        .hit => |*h| cache.commit(h.lease),
        else => try testing.expect(false),
    }
    result.deinit();

    var after_commit = cache.lookupLease(&handle, testCandidate("example.test"), 10);
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

    var result = cache.lookupLease(&handle, testCandidate("example.test"), 10);
    switch (result) {
        .hit => |*h| cache.release(h.lease),
        else => try testing.expect(false),
    }
    result.deinit();

    var again = cache.lookupLease(&handle, testCandidate("example.test"), 10);
    defer again.deinit();
    try testing.expect(again == .hit);
}

test "stateful server rejects unknown, malformed, and expired identities without consuming" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .reusable, &handle);

    const too_short = cache.lookupLease("short", testCandidate("example.test"), 10);
    try testing.expect(too_short == .miss);

    var wrong_magic = handle;
    wrong_magic[0] = 'X';
    const unknown = cache.lookupLease(&wrong_magic, testCandidate("example.test"), 10);
    try testing.expect(unknown == .miss);

    const expired = cache.lookupLease(&handle, testCandidate("example.test"), 1_000_001);
    try testing.expect(expired == .expired);
    try testing.expectEqual(@as(usize, 0), cache.count());
}

test "stateful server incompatible candidate reports the mismatch reason without consuming" {
    var cache = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer cache.deinit();
    var state = try testServerState(testing.allocator, "example.test", 0, 1000);
    var handle: [stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&state, 0, .single_use, &handle);

    const result = cache.lookupLease(&handle, testCandidate("other.test"), 10);
    try testing.expectEqual(session.ResumeMismatch.sni_mismatch, result.incompatible);

    // Still resolvable afterward (an incompatible lookup must not consume).
    var again = cache.lookupLease(&handle, testCandidate("example.test"), 10);
    defer again.deinit();
    try testing.expect(again == .hit);
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

test "stateful server enforces per-origin and global capacity with deterministic eviction" {
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
    const miss = cache.lookupLease(&h[0], testCandidate("a.test"), 3);
    try testing.expect(miss == .miss);
    var hit = cache.lookupLease(&h[2], testCandidate("a.test"), 3);
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

    var leased = cache.lookupLease(&h1, testCandidate("a.test"), 1);
    // Keep `leased` pinned; do not commit/release yet.

    var s2 = try testServerState(testing.allocator, "b.test", 0, 1000);
    defer s2.deinit();
    var h2: [stateful_identity_len]u8 = undefined;
    // No unleased entry to evict, and capacity is exactly 1: rejected.
    try testing.expectEqual(StoreResult.rejected_capacity, cache.insertMove(&s2, 1, .reusable, &h2));

    switch (leased) {
        .hit => |*h| cache.release(h.lease),
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
        defer cache.entries.deinit(fba.allocator());

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
    restored.restoreClones(snapshot.items, 1);
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
    }
    try testing.expectEqual(@as(usize, 1), server_snapshot.items.len);
    try testing.expect(std.mem.eql(u8, &server_snapshot.items[0].handle, &handle));

    var restored_server = try StatefulServerCache.init(testing.allocator, Limits.stateful_server_default, system_random_source);
    defer restored_server.deinit();
    restored_server.restoreEntries(server_snapshot.items, 1);
    try testing.expectEqual(@as(usize, 1), restored_server.count());
    var hit = restored_server.lookupLease(&handle, testCandidate("example.test"), 2);
    defer hit.deinit();
    try testing.expect(hit == .hit);
}

test "expired entries are discarded on restore rather than reinserted" {
    var cache = try ClientSessionCache.init(testing.allocator, Limits.client_default);
    defer cache.deinit();
    var expired: PersistedClientEntry = .{ .usage = .reusable };
    expired.ticket = try testClient(testing.allocator, "already-expired", "example.test", 0, 10, 0);
    var items = [_]PersistedClientEntry{expired};
    cache.restoreClones(&items, 1_000_000);
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
