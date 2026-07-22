//! TLS 1.3 resumption `pre_shared_key` / `psk_key_exchange_modes` extensions
//! (RFC 8446 §4.2.11, RFC 9846). Resumption PSKs only — no external PSKs, no
//! `ext binder`, no `psk_ke` selection, no 0-RTT.
//!
//! Owns only:
//!   - `psk_key_exchange_modes` encode/decode;
//!   - `OfferedPsks` (identities + binders) encode/decode and borrowed
//!     paired iteration;
//!   - the exact ClientHello binder-vector offset calculation;
//!   - resumption binder derivation/verification for SHA-256 and SHA-384;
//!   - obfuscated-ticket-age and age-observation helpers;
//!   - the owned, move-oriented client offer set (`ClientPskOfferSet`);
//!   - the provider-neutral server resolver contract (`ServerPskResolver`).
//!
//! It does not parse ClientHello beyond this one extension, does not choose
//! the final selected identity (that is the backend's server-selection
//! algorithm), does not own full-handshake fallback, and must not import
//! cache, keyring, HTTP, QUIC packet, record-layer, or runtime policy types.

const std = @import("std");
const provider = @import("crypto").provider;
const messages = @import("messages.zig");
const session = @import("session.zig");

const crypto = std.crypto;
const tls = crypto.tls;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;
const HmacSha384 = crypto.auth.hmac.sha2.HmacSha384;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha384 = crypto.kdf.hkdf.Hkdf(HmacSha384);
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;

pub const ext_pre_shared_key: u16 = 41;
pub const ext_psk_key_exchange_modes: u16 = 45;

/// Hard ceiling on offered/candidate identities per ClientHello (also the
/// bound on server-side identity-resolution attempts).
pub const max_offered_identities: usize = 8;

pub const min_binder_len: usize = 32;
pub const max_binder_len: usize = 255;

pub const PskKeyExchangeMode = enum(u8) {
    psk_ke = 0,
    psk_dhe_ke = 1,
};

pub const WriteError = messages.WriteError || error{
    TooManyIdentities,
    EmptyIdentity,
    IdentityTooLarge,
    IdentitiesVectorTooLarge,
    InvalidBinderLength,
    BindersVectorTooLarge,
    ExtensionTooLarge,
};

pub const ReadError = error{
    MalformedHandshake,
    EmptyVector,
    EmptyIdentity,
    CountMismatch,
    InvalidBinderLength,
};

pub const BinderError = error{InvalidSecretLength};

// -----------------------------------------------------------------------
// psk_key_exchange_modes (RFC 8446 §4.2.9)
// -----------------------------------------------------------------------

pub const ModeError = error{ EmptyModes, TooManyModes };

/// Writes `struct { PskKeyExchangeMode ke_modes<1..255>; }` into `w`. Rejects
/// an empty or over-255 list before touching `w` — the 1-byte vector length
/// otherwise cannot represent the count, and patching it would trap.
pub fn writeModes(w: *messages.Writer, modes: []const PskKeyExchangeMode) (messages.WriteError || ModeError)!void {
    if (modes.len == 0) return error.EmptyModes;
    if (modes.len > 255) return error.TooManyModes;
    const len_idx = try w.reserve(1);
    for (modes) |m| try w.u8_(@intFromEnum(m));
    w.patch(1, len_idx);
}

/// Whether `mode` appears in a decoded `psk_key_exchange_modes` extension
/// body. Malformed length/truncation/trailing bytes are decode failures.
pub fn hasMode(ext_data: []const u8, mode: PskKeyExchangeMode) ReadError!bool {
    var r = messages.Reader{ .bytes = ext_data };
    const len = try r.u8_();
    if (len == 0) return error.EmptyVector;
    const list = try r.slice(len);
    try r.expectEnd();
    return std.mem.indexOfScalar(u8, list, @intFromEnum(mode)) != null;
}

// -----------------------------------------------------------------------
// OfferedPsks (RFC 8446 §4.2.11): PskIdentity identities, PskBinderEntry
// binders.
// -----------------------------------------------------------------------

pub const Identity = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
};

/// A parsed, borrowed view over a received `pre_shared_key` extension body.
/// Identities and binders are validated to be non-empty, well-formed, and
/// of exactly equal entry count at parse time; per-entry contents are read
/// lazily through `pairs()`.
pub const OfferedPsks = struct {
    identities_bytes: []const u8,
    binders_bytes: []const u8,
    /// Offset within the extension body (`ext_data`) where the 2-byte
    /// binders-vector length field begins. Binders are computed over the
    /// exact framed ClientHello up to (but excluding) this point — see
    /// `deriveBinder`.
    binder_vector_offset: usize,
    count: usize,

    pub fn parse(ext_data: []const u8) ReadError!OfferedPsks {
        var r = messages.Reader{ .bytes = ext_data };
        const identities_len = try r.u16_();
        if (identities_len == 0) return error.EmptyVector;
        const identities_bytes = try r.slice(identities_len);

        const binder_vector_offset = r.offset;
        const binders_len = try r.u16_();
        if (binders_len == 0) return error.EmptyVector;
        const binders_bytes = try r.slice(binders_len);
        try r.expectEnd();

        var id_count: usize = 0;
        {
            var ir = messages.Reader{ .bytes = identities_bytes };
            while (ir.remaining() > 0) {
                const id_len = try ir.u16_();
                if (id_len == 0) return error.EmptyIdentity;
                _ = try ir.slice(id_len);
                _ = try ir.slice(4); // obfuscated_ticket_age
                id_count += 1;
            }
        }
        var binder_count: usize = 0;
        {
            var br = messages.Reader{ .bytes = binders_bytes };
            while (br.remaining() > 0) {
                const blen = try br.u8_();
                if (blen < min_binder_len or blen > max_binder_len) return error.InvalidBinderLength;
                _ = try br.slice(blen);
                binder_count += 1;
            }
        }
        if (id_count == 0 or binder_count == 0) return error.EmptyVector;
        if (id_count != binder_count) return error.CountMismatch;

        return .{
            .identities_bytes = identities_bytes,
            .binders_bytes = binders_bytes,
            .binder_vector_offset = binder_vector_offset,
            .count = id_count,
        };
    }

    pub const PairIterator = struct {
        id_reader: messages.Reader,
        binder_reader: messages.Reader,

        pub const Pair = struct { identity: Identity, binder: []const u8 };

        pub fn next(self: *PairIterator) ReadError!?Pair {
            if (self.id_reader.remaining() == 0) return null;
            const id_len = try self.id_reader.u16_();
            const identity = try self.id_reader.slice(id_len);
            const age_bytes = try self.id_reader.slice(4);
            const age = std.mem.readInt(u32, age_bytes[0..4], .big);
            const blen = try self.binder_reader.u8_();
            const binder = try self.binder_reader.slice(blen);
            return .{ .identity = .{ .identity = identity, .obfuscated_ticket_age = age }, .binder = binder };
        }
    };

    /// A borrowed, in-order (identity, binder) iterator. Both vectors were
    /// already validated to have exactly equal, well-formed entry counts by
    /// `parse`, so this cannot desynchronize.
    pub fn pairs(self: *const OfferedPsks) PairIterator {
        return .{
            .id_reader = .{ .bytes = self.identities_bytes },
            .binder_reader = .{ .bytes = self.binders_bytes },
        };
    }
};

pub const OfferItem = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
    /// The binder digest length for this identity's associated hash
    /// (32 for SHA-256, 48 for SHA-384) — the caller computes and
    /// overwrites this many placeholder bytes after `writeOffer` returns.
    digest_len: usize,
};

pub const BinderSlot = struct { offset: usize, len: usize };

pub const ClientOfferWrite = struct {
    /// The exact prefix of the framed ClientHello (measured from the start
    /// of the writer's buffer, i.e. including the handshake header) that
    /// every binder must be computed over, once every enclosing length
    /// field — message, extensions block, this extension, identities, and
    /// binders — has been patched to its final value (RFC 8446 §4.2.11.2).
    truncated_len: usize,
    slots: [max_offered_identities]BinderSlot = undefined,
    count: usize = 0,
};

pub const max_vector_len = std.math.maxInt(u16);

/// Writes the `pre_shared_key` extension: identities followed by
/// zero-valued binder placeholders sized to each item's digest length, with
/// every length field patched. Per RFC 8446 §4.2.11, this must be the last
/// extension the caller writes into `w`; the caller still patches the
/// outer extensions-vector and message-length fields afterward, and must do
/// so *before* hashing `w.written()[0..result.truncated_len]` — see
/// `deriveBinder`. Returns the binder slot positions so the caller can
/// overwrite each placeholder with the real binder afterward.
///
/// The complete structure — entry count, every identity length, and both
/// vector totals — is validated against the wire's u16 vector limits before
/// `w` is touched at all, so a caller-input structure this function's own
/// parser would reject can never be written, and an oversized field can
/// never reach the writer's `@intCast` length patch.
pub fn writeOffer(w: *messages.Writer, items: []const OfferItem) WriteError!ClientOfferWrite {
    if (items.len == 0 or items.len > max_offered_identities) return error.TooManyIdentities;

    var identities_total: usize = 0;
    var binders_total: usize = 0;
    for (items) |item| {
        if (item.identity.len == 0) return error.EmptyIdentity;
        if (item.identity.len > max_vector_len) return error.IdentityTooLarge;
        identities_total += 2 + item.identity.len + 4;
        if (identities_total > max_vector_len) return error.IdentitiesVectorTooLarge;
        // The full wire range (RFC 8446 §4.2.11: `PskBinderEntry<32..255>`),
        // matching what `OfferedPsks.parse` accepts — this is a general
        // wire codec, not specific to the two digest lengths this module's
        // own binder derivation happens to support. A caller preparing an
        // actual offer (see `tls13_backend.zig`) is the one that only ever
        // constructs 32- or 48-byte entries; that is backend policy, not a
        // codec-level restriction.
        if (item.digest_len < min_binder_len or item.digest_len > max_binder_len)
            return error.InvalidBinderLength;
        binders_total += 1 + item.digest_len;
        if (binders_total > max_vector_len) return error.BindersVectorTooLarge;
    }
    // extension_data = 2-byte identities_len + identities + 2-byte
    // binders_len + binders; not itself wire-length-limited beyond the
    // enclosing 2-byte extension-data length field.
    const ext_data_len = 2 + identities_total + 2 + binders_total;
    if (ext_data_len > max_vector_len) return error.ExtensionTooLarge;

    try w.u16_(ext_pre_shared_key);
    const ext_len_idx = try w.reserve(2);

    const ids_len_idx = try w.reserve(2);
    for (items) |item| {
        try w.u16_(@intCast(item.identity.len));
        try w.bytes(item.identity);
        var age_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &age_bytes, item.obfuscated_ticket_age, .big);
        try w.bytes(&age_bytes);
    }
    w.patch(2, ids_len_idx);

    var result: ClientOfferWrite = .{ .truncated_len = w.len };

    const binders_len_idx = try w.reserve(2);
    for (items, 0..) |item, i| {
        const entry_len_idx = try w.reserve(1);
        const slot_offset = w.len;
        const zeros = [_]u8{0} ** max_binder_len;
        try w.bytes(zeros[0..item.digest_len]);
        w.patch(1, entry_len_idx);
        result.slots[i] = .{ .offset = slot_offset, .len = item.digest_len };
        result.count += 1;
    }
    w.patch(2, binders_len_idx);
    w.patch(2, ext_len_idx);
    return result;
}

// -----------------------------------------------------------------------
// Resumption binder derivation (RFC 8446 §4.2.11.2, §7.1):
//   early_secret  = HKDF-Extract(0, PSK)
//   binder_key    = Derive-Secret(early_secret, "res binder", "")
//   finished_key  = HKDF-Expand-Label(binder_key, "finished", "", L)
//   binder        = HMAC(finished_key, Hash(truncated ClientHello))
// -----------------------------------------------------------------------

/// Derives the resumption binder for `psk` (already exactly
/// `hash.digestLength()` bytes — the caller derives it via
/// `key_schedule.KeySchedule.resumptionPsk`) over `truncated_client_hello`
/// (the exact framed-message prefix ending just before the binders
/// vector's own length field) into `out` (must be exactly
/// `hash.digestLength()` bytes).
pub fn deriveBinder(
    hash: provider.Hash,
    psk: []const u8,
    truncated_client_hello: []const u8,
    out: []u8,
) BinderError!void {
    const expected_len = hash.digestLength();
    if (psk.len != expected_len or out.len != expected_len) return error.InvalidSecretLength;
    switch (hash) {
        .sha256 => {
            var empty_hash: [Sha256.digest_length]u8 = undefined;
            Sha256.hash("", &empty_hash, .{});

            var psk_fixed: [Sha256.digest_length]u8 = undefined;
            @memcpy(&psk_fixed, psk);
            defer crypto.secureZero(u8, &psk_fixed);

            var early_secret = HkdfSha256.extract("", &psk_fixed);
            defer crypto.secureZero(u8, &early_secret);
            var binder_key = tls.hkdfExpandLabel(HkdfSha256, early_secret, "res binder", &empty_hash, Sha256.digest_length);
            defer crypto.secureZero(u8, &binder_key);
            var finished_key = tls.hkdfExpandLabel(HkdfSha256, binder_key, "finished", "", Sha256.digest_length);
            defer crypto.secureZero(u8, &finished_key);

            var transcript_hash: [Sha256.digest_length]u8 = undefined;
            Sha256.hash(truncated_client_hello, &transcript_hash, .{});
            var mac: [HmacSha256.mac_length]u8 = undefined;
            HmacSha256.create(&mac, &transcript_hash, &finished_key);
            @memcpy(out, &mac);
        },
        .sha384 => {
            var empty_hash: [Sha384.digest_length]u8 = undefined;
            Sha384.hash("", &empty_hash, .{});

            var psk_fixed: [HmacSha384.mac_length]u8 = undefined;
            @memcpy(&psk_fixed, psk);
            defer crypto.secureZero(u8, &psk_fixed);

            var early_secret = HkdfSha384.extract("", &psk_fixed);
            defer crypto.secureZero(u8, &early_secret);
            var binder_key = tls.hkdfExpandLabel(HkdfSha384, early_secret, "res binder", &empty_hash, HmacSha384.mac_length);
            defer crypto.secureZero(u8, &binder_key);
            var finished_key = tls.hkdfExpandLabel(HkdfSha384, binder_key, "finished", "", HmacSha384.mac_length);
            defer crypto.secureZero(u8, &finished_key);

            var transcript_hash: [Sha384.digest_length]u8 = undefined;
            Sha384.hash(truncated_client_hello, &transcript_hash, .{});
            var mac: [HmacSha384.mac_length]u8 = undefined;
            HmacSha384.create(&mac, &transcript_hash, &finished_key);
            @memcpy(out, &mac);
        },
    }
}

/// Constant-time binder verification: derives the expected binder for `psk`
/// over `truncated_client_hello` and compares it against `candidate_binder`
/// without early-exiting on a byte mismatch. A length mismatch (the binder
/// on the wire is not `hash.digestLength()` bytes) is reported as a
/// non-match, not an error — a wrong-length binder is simply wrong.
pub fn verifyBinder(
    hash: provider.Hash,
    psk: []const u8,
    truncated_client_hello: []const u8,
    candidate_binder: []const u8,
) BinderError!bool {
    var computed: [provider.max_digest_len]u8 = undefined;
    const out = computed[0..hash.digestLength()];
    defer crypto.secureZero(u8, out);
    try deriveBinder(hash, psk, truncated_client_hello, out);
    if (out.len != candidate_binder.len) return false;
    return switch (out.len) {
        32 => crypto.timing_safe.eql([32]u8, out[0..32].*, candidate_binder[0..32].*),
        48 => crypto.timing_safe.eql([48]u8, out[0..48].*, candidate_binder[0..48].*),
        else => false,
    };
}

// -----------------------------------------------------------------------
// Obfuscated ticket age (RFC 8446 §4.2.11.1).
// -----------------------------------------------------------------------

/// `obfuscated_ticket_age = uint32(age_ms mod 2^32) +% ticket_age_add`.
pub fn obfuscateTicketAge(age_ms: u64, ticket_age_add: u32) u32 {
    const age_mod: u32 = @truncate(age_ms);
    return age_mod +% ticket_age_add;
}

/// Recovers the client's apparent ticket age via wrapping subtraction.
pub fn deobfuscateTicketAge(obfuscated_ticket_age: u32, ticket_age_add: u32) u32 {
    return obfuscated_ticket_age -% ticket_age_add;
}

pub const AgeSkew = struct {
    /// The apparent age the client reported (after deobfuscation).
    apparent_age_ms: u32,
    /// The server's own view of elapsed time since issuance.
    actual_age_ms: u64,
    /// `apparent - actual`, in milliseconds; positive means the client
    /// reported an older ticket than the server's clock would expect.
    skew_ms: i64,
};

/// Computes the signed age-skew observation used by #366 to reject or allow
/// early data; skew alone never rejects ordinary 1-RTT resumption.
pub fn observeAgeSkew(obfuscated_ticket_age: u32, ticket_age_add: u32, actual_age_ms: u64) AgeSkew {
    const apparent = deobfuscateTicketAge(obfuscated_ticket_age, ticket_age_add);
    const bounded_actual: i64 = @intCast(@min(actual_age_ms, @as(u64, std.math.maxInt(i64))));
    return .{
        .apparent_age_ms = apparent,
        .actual_age_ms = actual_age_ms,
        .skew_ms = @as(i64, apparent) - bounded_actual,
    };
}

// -----------------------------------------------------------------------
// Client offer ownership.
// -----------------------------------------------------------------------

/// An owned, move-oriented set of resumption tickets a client may offer,
/// bounded to `max_offered_identities`. The backend takes ownership of a
/// caller-built set at ClientHello emission and is responsible for wiping
/// every entry on every success, fallback, and teardown path.
pub const ClientPskOfferSet = struct {
    tickets: [max_offered_identities]session.ClientTicketState = [_]session.ClientTicketState{.{}} ** max_offered_identities,
    len: usize = 0,

    pub const Error = error{TooManyOffers};

    /// Moves ownership of `ticket` into the set; `ticket` is zero-valued on
    /// success. Fails (leaving `ticket` untouched) once the set is full.
    pub fn push(self: *ClientPskOfferSet, ticket: *session.ClientTicketState) Error!void {
        if (self.len >= max_offered_identities) return error.TooManyOffers;
        self.tickets[self.len].moveFrom(ticket);
        self.len += 1;
    }

    pub fn slice(self: *ClientPskOfferSet) []session.ClientTicketState {
        return self.tickets[0..self.len];
    }

    pub fn constSlice(self: *const ClientPskOfferSet) []const session.ClientTicketState {
        return self.tickets[0..self.len];
    }

    pub fn isEmpty(self: *const ClientPskOfferSet) bool {
        return self.len == 0;
    }

    /// Transfers ownership of `source`'s tickets into `self`, deinitializing
    /// whatever `self` previously held first. `source` is left empty.
    pub fn moveFrom(self: *ClientPskOfferSet, source: *ClientPskOfferSet) void {
        if (self == source) return;
        self.deinit();
        self.* = source.*;
        source.* = .{};
    }

    /// Wipes and deinitializes every remaining offer (unselected offers
    /// after a selection, or the whole set when the server did not select
    /// PSK, or on any error/teardown path).
    pub fn deinit(self: *ClientPskOfferSet) void {
        for (self.tickets[0..self.len]) |*t| t.deinit();
        self.len = 0;
    }

    /// Moves the ticket at `index` out into `dest` (the backend's resumed
    /// session state) and wipes every other, now-unselected offer.
    pub fn takeSelected(self: *ClientPskOfferSet, index: usize, dest: *session.ClientTicketState) void {
        dest.moveFrom(&self.tickets[index]);
        self.deinit();
    }
};

// -----------------------------------------------------------------------
// Server resolver contract, shared by stateful (#364) and stateless (#363)
// providers.
// -----------------------------------------------------------------------

pub const ResolveError = error{ResolverFailed};

/// Provider-neutral, exactly-once server PSK lease. Stateful single-use
/// providers pin cache entries until binder verification proves the identity
/// was actually selected; reusable and stateless providers use `.noop`.
pub const ServerPskLease = union(enum) {
    noop,
    owned: Owned,
    finished,

    const Owned = struct {
        ctx: *anyopaque,
        commitFn: *const fn (*anyopaque) void,
        releaseFn: *const fn (*anyopaque) void,
        deinitFn: *const fn (*anyopaque) void,
    };

    pub fn initNoop() ServerPskLease {
        return .noop;
    }

    pub fn initOwned(
        ctx: *anyopaque,
        commitFn: *const fn (*anyopaque) void,
        releaseFn: *const fn (*anyopaque) void,
        deinitFn: *const fn (*anyopaque) void,
    ) ServerPskLease {
        return .{ .owned = .{
            .ctx = ctx,
            .commitFn = commitFn,
            .releaseFn = releaseFn,
            .deinitFn = deinitFn,
        } };
    }

    pub fn commit(self: *ServerPskLease) void {
        switch (self.*) {
            .owned => |owned_lease| {
                self.* = .finished;
                owned_lease.commitFn(owned_lease.ctx);
                owned_lease.deinitFn(owned_lease.ctx);
            },
            .noop, .finished => self.* = .finished,
        }
    }

    pub fn release(self: *ServerPskLease) void {
        switch (self.*) {
            .owned => |owned_lease| {
                self.* = .finished;
                owned_lease.releaseFn(owned_lease.ctx);
                owned_lease.deinitFn(owned_lease.ctx);
            },
            .noop, .finished => self.* = .finished,
        }
    }

    pub fn deinit(self: *ServerPskLease) void {
        self.release();
    }
};

/// Allocation-free completion callback for resolver state that needs a
/// binder-confirmed selection signal without transferring ownership through
/// `ServerPskLease`. Reusable stateful cache hits use this to refresh LRU
/// recency only after compatibility and binder verification succeed, while
/// their public ownership lease remains `.noop`.
pub const ServerPskSelectionHook = struct {
    ctx: *anyopaque,
    arg0: u64 = 0,
    arg1: u64 = 0,
    arg2: u64 = 0,
    completeFn: *const fn (*anyopaque, u64, u64, u64) void,

    pub fn complete(self: ServerPskSelectionHook) void {
        self.completeFn(self.ctx, self.arg0, self.arg1, self.arg2);
    }
};

pub const ServerPskResolveResult = union(enum) {
    miss,
    hit: struct {
        state: session.ServerRecoverableState,
        lease: ServerPskLease,
        on_selected: ?ServerPskSelectionHook = null,
    },

    pub fn deinit(self: *ServerPskResolveResult) void {
        switch (self.*) {
            .hit => |*h| {
                h.lease.deinit();
                h.state.deinit();
            },
            .miss => {},
        }
    }
};

/// Provider-neutral identity resolver. `resolveFn` returns `.hit` with
/// completely owned state plus a live lease when `identity` is usable, or
/// `.miss` for malformed, unknown, retired, expired, or otherwise unusable
/// identities — including stateless envelope decode/authentication failures.
/// Operational failures (allocation, provider/configuration faults) are the
/// typed `ResolveError`, never silently folded into an ordinary miss.
pub const ServerPskResolver = struct {
    ctx: *anyopaque,
    nowUnixMsFn: *const fn (*anyopaque) i64,
    resolveFn: *const fn (
        ctx: *anyopaque,
        identity: []const u8,
    ) ResolveError!ServerPskResolveResult,

    pub fn nowUnixMs(self: ServerPskResolver) i64 {
        return self.nowUnixMsFn(self.ctx);
    }

    pub fn resolve(self: ServerPskResolver, identity: []const u8) ResolveError!ServerPskResolveResult {
        return self.resolveFn(self.ctx, identity);
    }
};

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

const testing = std.testing;

test "psk_key_exchange_modes round-trips and rejects malformed vectors" {
    var buf: [16]u8 = undefined;
    var w = messages.Writer{ .buf = &buf };
    try writeModes(&w, &.{ .psk_ke, .psk_dhe_ke });
    try testing.expectEqualSlices(u8, &.{ 2, 0, 1 }, w.written());

    try testing.expect(try hasMode(w.written(), .psk_dhe_ke));
    try testing.expect(try hasMode(w.written(), .psk_ke));

    // Empty vector.
    try testing.expectError(error.EmptyVector, hasMode(&.{0}, .psk_dhe_ke));
    // Truncated (declares 2 bytes, has 1).
    try testing.expectError(error.MalformedHandshake, hasMode(&.{ 2, 1 }, .psk_dhe_ke));
    // Trailing bytes after the declared vector.
    try testing.expectError(error.MalformedHandshake, hasMode(&.{ 1, 1, 0xff }, .psk_dhe_ke));
}

test "writeModes rejects empty and over-255 mode lists before touching the writer" {
    var buf: [16]u8 = undefined;
    var w = messages.Writer{ .buf = &buf };
    try testing.expectError(error.EmptyModes, writeModes(&w, &.{}));
    try testing.expectEqual(@as(usize, 0), w.len);

    const too_many = [_]PskKeyExchangeMode{.psk_ke} ** 256;
    try testing.expectError(error.TooManyModes, writeModes(&w, &too_many));
    try testing.expectEqual(@as(usize, 0), w.len);
}

test "ServerPskLease owned transitions are exactly once" {
    const Ctx = struct {
        commit_count: usize = 0,
        release_count: usize = 0,
        deinit_count: usize = 0,

        fn commit(ctx: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.commit_count += 1;
        }

        fn release(ctx: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.release_count += 1;
        }

        fn deinitLease(ctx: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.deinit_count += 1;
        }
    };

    var ctx = Ctx{};
    var lease = ServerPskLease.initOwned(&ctx, Ctx.commit, Ctx.release, Ctx.deinitLease);
    lease.commit();
    lease.commit();
    lease.release();
    lease.deinit();
    try testing.expectEqual(@as(usize, 1), ctx.commit_count);
    try testing.expectEqual(@as(usize, 0), ctx.release_count);
    try testing.expectEqual(@as(usize, 1), ctx.deinit_count);
    try testing.expect(lease == .finished);

    var ctx2 = Ctx{};
    var lease2 = ServerPskLease.initOwned(&ctx2, Ctx.commit, Ctx.release, Ctx.deinitLease);
    lease2.deinit();
    lease2.release();
    lease2.commit();
    try testing.expectEqual(@as(usize, 0), ctx2.commit_count);
    try testing.expectEqual(@as(usize, 1), ctx2.release_count);
    try testing.expectEqual(@as(usize, 1), ctx2.deinit_count);
    try testing.expect(lease2 == .finished);

    var noop_lease = ServerPskLease.initNoop();
    noop_lease.deinit();
    noop_lease.commit();
    try testing.expect(noop_lease == .finished);
}

test "writeOffer rejects illegal shapes without ever mutating the writer" {
    var buf: [512]u8 = undefined;

    // Zero items.
    {
        var w = messages.Writer{ .buf = &buf };
        try testing.expectError(error.TooManyIdentities, writeOffer(&w, &.{}));
        try testing.expectEqual(@as(usize, 0), w.len);
    }
    // More than the maximum offered identities.
    {
        var w = messages.Writer{ .buf = &buf };
        const items = [_]OfferItem{.{ .identity = "x", .obfuscated_ticket_age = 0, .digest_len = 32 }} ** (max_offered_identities + 1);
        try testing.expectError(error.TooManyIdentities, writeOffer(&w, &items));
        try testing.expectEqual(@as(usize, 0), w.len);
    }
    // Empty identity.
    {
        var w = messages.Writer{ .buf = &buf };
        const items = [_]OfferItem{.{ .identity = "", .obfuscated_ticket_age = 0, .digest_len = 32 }};
        try testing.expectError(error.EmptyIdentity, writeOffer(&w, &items));
        try testing.expectEqual(@as(usize, 0), w.len);
    }
    // Binder length boundary, over the full RFC 8446 wire range (32..255),
    // matching `OfferedPsks.parse` exactly rather than this module's own
    // narrower SHA-256/384 digest lengths: 31 rejected, 32/48/255 accepted,
    // 256 unrepresentable on the wire and rejected.
    {
        var w = messages.Writer{ .buf = &buf };
        const too_short = [_]OfferItem{.{ .identity = "id", .obfuscated_ticket_age = 0, .digest_len = 31 }};
        try testing.expectError(error.InvalidBinderLength, writeOffer(&w, &too_short));
        try testing.expectEqual(@as(usize, 0), w.len);

        inline for (.{ 32, 48, 255 }) |ok_len| {
            var w_ok = messages.Writer{ .buf = &buf };
            const items = [_]OfferItem{.{ .identity = "id", .obfuscated_ticket_age = 0, .digest_len = ok_len }};
            const offer = try writeOffer(&w_ok, &items);
            try testing.expectEqual(@as(usize, ok_len), offer.slots[0].len);
        }

        var w_too_long = messages.Writer{ .buf = &buf };
        const too_long = [_]OfferItem{.{ .identity = "id", .obfuscated_ticket_age = 0, .digest_len = 256 }};
        try testing.expectError(error.InvalidBinderLength, writeOffer(&w_too_long, &too_long));
        try testing.expectEqual(@as(usize, 0), w_too_long.len);
    }
    // Exact boundary values succeed: min/max supported digest length, and a
    // full eight-identity offer.
    {
        var w = messages.Writer{ .buf = &buf };
        const items = [_]OfferItem{
            .{ .identity = "a", .obfuscated_ticket_age = 0, .digest_len = min_binder_len },
            .{ .identity = "b", .obfuscated_ticket_age = 0, .digest_len = max_binder_len },
        };
        _ = try writeOffer(&w, &items);

        var w3 = messages.Writer{ .buf = &buf };
        var eight: [max_offered_identities]OfferItem = undefined;
        for (&eight) |*item| item.* = .{ .identity = "id", .obfuscated_ticket_age = 0, .digest_len = 32 };
        const offer = try writeOffer(&w3, &eight);
        try testing.expectEqual(max_offered_identities, offer.count);
    }
}

test "a literal framed ClientHello proves the exact binder truncation boundary" {
    // A hand-assembled, fully framed ClientHello (handshake header through a
    // trailing `pre_shared_key` extension with one identity "abcd" and one
    // 32-byte binder), constructed byte-by-byte from the RFC 8446 grammar
    // rather than via this module's own writer — every enclosing length
    // (message, extensions vector, `pre_shared_key` extension, identities
    // vector) is already final, exactly as the wire requires before hashing.
    // The embedded binder itself was computed independently (Python
    // hashlib/hmac, not this module) over the expected truncated prefix.
    const message = hexBytes(
        "0100006503037777777777777777777777777777777777777777777777777777" ++
            "77777777777700000213010100003a002b00030203040029002f000a00046162" ++
            "6364112233440021208f6e79d089388cd1e7ca42e346e44ba217289f0450609a" ++
            "9827c4ee59f16568e6",
    );
    // The `pre_shared_key` extension_data begins at a fixed, independently
    // computed offset within `message` (4-byte header + fixed ClientHello
    // fields + the `supported_versions` extension that precedes it).
    const ext_data_offset = 58;
    const ext_data = message[ext_data_offset..];

    var offered = try OfferedPsks.parse(ext_data);
    try testing.expectEqual(@as(usize, 1), offered.count);
    // Exactly the offset of the *2-byte binders-vector length field* —
    // not the binder payload two bytes later.
    try testing.expectEqual(@as(usize, 12), offered.binder_vector_offset);

    const truncated_len = ext_data_offset + offered.binder_vector_offset;
    try testing.expectEqual(@as(usize, 70), truncated_len);
    const prefix = message[0..truncated_len];
    const expected_prefix = hexBytes(
        "0100006503037777777777777777777777777777777777777777777777777777" ++
            "77777777777700000213010100003a002b00030203040029002f000a00046162" ++
            "636411223344",
    );
    try testing.expectEqualSlices(u8, &expected_prefix, prefix);

    const psk = [_]u8{0xaa} ** 32;
    const expected_binder = hexBytes("8f6e79d089388cd1e7ca42e346e44ba217289f0450609a9827c4ee59f16568e6");
    var binder: [32]u8 = undefined;
    try deriveBinder(.sha256, &psk, prefix, &binder);
    try testing.expectEqualSlices(u8, &expected_binder, &binder);

    // Confirm the embedded pair's identity/binder round-trip through the
    // borrowed paired iterator too.
    var it = offered.pairs();
    const pair = (try it.next()).?;
    try testing.expectEqualStrings("abcd", pair.identity.identity);
    try testing.expectEqual(@as(u32, 0x11223344), pair.identity.obfuscated_ticket_age);
    try testing.expectEqualSlices(u8, &expected_binder, pair.binder);
    try testing.expectEqual(@as(?OfferedPsks.PairIterator.Pair, null), try it.next());

    // The offset is exact, not "close enough": hashing two bytes further
    // (as if the binders-vector length field were mistakenly included in
    // the prefix) must *not* reproduce the same binder.
    var wrong_binder: [32]u8 = undefined;
    try deriveBinder(.sha256, &psk, message[0 .. truncated_len + 2], &wrong_binder);
    try testing.expect(!std.mem.eql(u8, &expected_binder, &wrong_binder));
}

test "every strict prefix of a valid OfferedPsks fixture is rejected, none silently accepted" {
    // The `pre_shared_key` extension_data from the literal ClientHello
    // fixture above: identities_len(2) + one identity(10) + binders_len(2)
    // + one 32-byte binder(33). Every vector is length-prefixed and spans
    // the whole fixture, so there is no shorter prefix that could
    // coincidentally look complete.
    const ext_data = hexBytes(
        "000a000461626364112233440021208f6e79d089388cd1e7ca42e346e44ba217" ++
            "289f0450609a9827c4ee59f16568e6",
    );
    try testing.expectEqual(@as(usize, 47), ext_data.len);
    _ = try OfferedPsks.parse(&ext_data); // the full fixture does parse

    var cut: usize = 0;
    while (cut < ext_data.len) : (cut += 1) {
        if (OfferedPsks.parse(ext_data[0..cut])) |_| {
            std.debug.print("unexpected successful parse at cut={d}\n", .{cut});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "OfferedPsks identity length boundaries: zero, one, max representable, truncated" {
    // identity length 0 is illegal regardless of what follows.
    {
        var buf: [64]u8 = undefined;
        var w = messages.Writer{ .buf = &buf };
        try w.u16_(6); // identities_len: 2(id_len)+0+4(age)
        try w.u16_(0); // identity length 0
        try w.bytes(&[_]u8{0} ** 4); // age
        try w.u16_(33);
        try w.u8_(32);
        try w.bytes(&[_]u8{0} ** 32);
        try testing.expectError(error.EmptyIdentity, OfferedPsks.parse(w.written()));
    }
    // identity length 1 (minimum non-empty) succeeds.
    {
        var buf: [64]u8 = undefined;
        var w = messages.Writer{ .buf = &buf };
        try w.u16_(7); // 2+1+4
        try w.u16_(1);
        try w.u8_('x');
        try w.bytes(&[_]u8{0} ** 4);
        try w.u16_(33);
        try w.u8_(32);
        try w.bytes(&[_]u8{0} ** 32);
        const offered = try OfferedPsks.parse(w.written());
        try testing.expectEqual(@as(usize, 1), offered.count);
    }
    // Declared identity length longer than the remaining identities-vector
    // bytes (truncated identity) is a decode failure, not silently clamped.
    {
        var buf: [64]u8 = undefined;
        var w = messages.Writer{ .buf = &buf };
        try w.u16_(6); // claims 6, but only provides a 2-byte length + 2 bytes
        try w.u16_(10); // identity claims length 10
        try w.bytes(&[_]u8{ 'a', 'b' }); // only 2 bytes actually present
        try testing.expectError(error.MalformedHandshake, OfferedPsks.parse(w.written()));
    }
    // Truncated obfuscated_ticket_age (identity present, age cut short).
    {
        var buf: [64]u8 = undefined;
        var w = messages.Writer{ .buf = &buf };
        try w.u16_(5); // 2(id_len)+1(id)+2(only 2 of 4 age bytes)
        try w.u16_(1);
        try w.u8_('x');
        try w.bytes(&[_]u8{ 0, 0 }); // age truncated to 2 bytes
        try testing.expectError(error.MalformedHandshake, OfferedPsks.parse(w.written()));
    }
    // The maximum representable single-entry identity length: the
    // enclosing identities_len field is itself a u16, so the largest a
    // lone identity can be is 65535 - 2 (its own length prefix) - 4 (age).
    {
        const max_identity_len = std.math.maxInt(u16) - 2 - 4;
        const total = 2 + (2 + max_identity_len + 4) + 2 + (1 + 32);
        const buf = try testing.allocator.alloc(u8, total);
        defer testing.allocator.free(buf);
        var w = messages.Writer{ .buf = buf };
        try w.u16_(@intCast(2 + max_identity_len + 4));
        try w.u16_(@intCast(max_identity_len));
        try w.bytes(&[_]u8{'x'} ** max_identity_len);
        try w.bytes(&[_]u8{0} ** 4);
        try w.u16_(33);
        try w.u8_(32);
        try w.bytes(&[_]u8{0} ** 32);
        const offered = try OfferedPsks.parse(w.written());
        try testing.expectEqual(@as(usize, 1), offered.count);
        var it = offered.pairs();
        const pair = (try it.next()).?;
        try testing.expectEqual(max_identity_len, pair.identity.identity.len);
    }
}

test "OfferedPsks vector-length boundaries: identities/binders zero, one-over, count mismatch" {
    // identities_len = 0 is EmptyVector even with a well-formed binders
    // vector following.
    {
        var buf: [64]u8 = undefined;
        var w = messages.Writer{ .buf = &buf };
        try w.u16_(0);
        try w.u16_(33);
        try w.u8_(32);
        try w.bytes(&[_]u8{0} ** 32);
        try testing.expectError(error.EmptyVector, OfferedPsks.parse(w.written()));
    }
    // binders_len = 0 is EmptyVector even with a well-formed identities
    // vector preceding it.
    {
        var buf: [64]u8 = undefined;
        var w = messages.Writer{ .buf = &buf };
        try w.u16_(7);
        try w.u16_(1);
        try w.u8_('x');
        try w.bytes(&[_]u8{0} ** 4);
        try w.u16_(0);
        try testing.expectError(error.EmptyVector, OfferedPsks.parse(w.written()));
    }
    // identities_len one byte short of what the single entry needs. Bytes
    // after the truncation point are misinterpreted (this is a
    // length-prefixed format, not self-delimiting), so the *specific*
    // resulting error legitimately varies with the exact misalignment —
    // this asserts only that decoding never silently succeeds.
    {
        var buf: [64]u8 = undefined;
        var w = messages.Writer{ .buf = &buf };
        try w.u16_(6); // needs 7 (2+1+4) for one entry; declares only 6
        try w.u16_(1);
        try w.u8_('x');
        try w.bytes(&[_]u8{0} ** 4);
        try w.u16_(33);
        try w.u8_(32);
        try w.bytes(&[_]u8{0} ** 32);
        if (OfferedPsks.parse(w.written())) |_| {
            return error.TestUnexpectedResult;
        } else |_| {}
    }
    // Two identities, one binder: count mismatch.
    {
        var buf: [64]u8 = undefined;
        var w = messages.Writer{ .buf = &buf };
        try w.u16_(14); // two 7-byte entries
        for (0..2) |_| {
            try w.u16_(1);
            try w.u8_('x');
            try w.bytes(&[_]u8{0} ** 4);
        }
        try w.u16_(33);
        try w.u8_(32);
        try w.bytes(&[_]u8{0} ** 32);
        try testing.expectError(error.CountMismatch, OfferedPsks.parse(w.written()));
    }
    // One identity, two binders: count mismatch the other direction.
    {
        var buf: [96]u8 = undefined;
        var w = messages.Writer{ .buf = &buf };
        try w.u16_(7);
        try w.u16_(1);
        try w.u8_('x');
        try w.bytes(&[_]u8{0} ** 4);
        try w.u16_(66); // two 33-byte binder entries
        for (0..2) |_| {
            try w.u8_(32);
            try w.bytes(&[_]u8{0} ** 32);
        }
        try testing.expectError(error.CountMismatch, OfferedPsks.parse(w.written()));
    }
}

test "psk_key_exchange_modes: duplicate-mode bytes, single non-psk_dhe_ke mode, and every truncation" {
    // Duplicate mode bytes are wire-legal (the vector is just a byte list;
    // this module reports whether a mode is *present*, not distinctness) —
    // `hasMode` still correctly reports presence.
    const dup = [_]u8{ 2, 1, 1 }; // len=2, [psk_dhe_ke, psk_dhe_ke]
    try testing.expect(try hasMode(&dup, .psk_dhe_ke));
    try testing.expect(!try hasMode(&dup, .psk_ke));

    // A single psk_ke-only offer: psk_dhe_ke is correctly reported absent
    // (the #362 profile only ever selects psk_dhe_ke, so the backend must
    // treat this as "PSK not usable", not error).
    var buf: [8]u8 = undefined;
    var w = messages.Writer{ .buf = &buf };
    try writeModes(&w, &.{.psk_ke});
    try testing.expect(!try hasMode(w.written(), .psk_dhe_ke));

    // Every strict prefix of a valid modes vector is rejected.
    const valid = [_]u8{ 2, 0, 1 };
    var cut: usize = 0;
    while (cut < valid.len) : (cut += 1) {
        try testing.expectError(error.MalformedHandshake, hasMode(valid[0..cut], .psk_dhe_ke));
    }
}

test "OfferedPsks encode/decode round-trip via writeOffer and parse" {
    var buf: [512]u8 = undefined;
    var w = messages.Writer{ .buf = &buf };
    const items = [_]OfferItem{
        .{ .identity = "ticket-one", .obfuscated_ticket_age = 0x11223344, .digest_len = 32 },
        .{ .identity = "ticket-two", .obfuscated_ticket_age = 0xaabbccdd, .digest_len = 48 },
    };
    const offer = try writeOffer(&w, &items);
    try testing.expectEqual(@as(usize, 2), offer.count);

    // ext_id(2) + ext_len(2) precede the region writeOffer wrote.
    const ext_data = w.written()[4..];
    var parsed = try OfferedPsks.parse(ext_data);
    try testing.expectEqual(@as(usize, 2), parsed.count);

    var it = parsed.pairs();
    const first = (try it.next()).?;
    try testing.expectEqualStrings("ticket-one", first.identity.identity);
    try testing.expectEqual(@as(u32, 0x11223344), first.identity.obfuscated_ticket_age);
    try testing.expectEqual(@as(usize, 32), first.binder.len);
    try testing.expect(std.mem.allEqual(u8, first.binder, 0)); // placeholder, not yet patched

    const second = (try it.next()).?;
    try testing.expectEqualStrings("ticket-two", second.identity.identity);
    try testing.expectEqual(@as(usize, 48), second.binder.len);

    try testing.expectEqual(@as(?OfferedPsks.PairIterator.Pair, null), try it.next());
}

test "OfferedPsks.parse rejects mismatched identity/binder counts" {
    // One identity, zero binders.
    var buf: [64]u8 = undefined;
    var w = messages.Writer{ .buf = &buf };
    const id_len_idx = try w.reserve(2);
    try w.u16_(4);
    try w.bytes("abcd");
    try w.bytes(&[_]u8{0} ** 4); // age
    w.patch(2, id_len_idx);
    try w.u16_(0); // empty binders vector length -- caught as EmptyVector first
    try testing.expectError(error.EmptyVector, OfferedPsks.parse(w.written()));
}

test "OfferedPsks.parse rejects truncated and oversized binder lengths" {
    var buf: [64]u8 = undefined;

    // Binder length 31 (< 32) is illegal.
    {
        var w = messages.Writer{ .buf = &buf };
        const id_len_idx = try w.reserve(2);
        try w.u16_(4);
        try w.bytes("abcd");
        try w.bytes(&[_]u8{0} ** 4);
        w.patch(2, id_len_idx);
        const b_len_idx = try w.reserve(2);
        try w.u8_(31);
        try w.bytes(&[_]u8{0} ** 31);
        w.patch(2, b_len_idx);
        try testing.expectError(error.InvalidBinderLength, OfferedPsks.parse(w.written()));
    }
}

test "resumption binder derivation matches an independently computed SHA-256 binder" {
    // Checked-in literal, computed independently of this module (Python
    // hashlib/hmac against the same RFC 8446 §4.2.11.2/§7.1 label chain) —
    // not derived with the same `std.crypto.tls.hkdfExpandLabel` helper the
    // implementation under test uses, so this actually detects a wrong
    // label, wrong empty-hash input, or wrong transcript hash rather than
    // only cross-checking this module against itself.
    const psk = hexBytes("c1392efd98f6932d62f5ccd42c724230871638e8ad0ac9ce9b2af89f5f919fed");
    const client_hello_prefix = "pretend-truncated-clienthello-bytes";
    const expected = hexBytes("de7c7afec445f9419e4f769b6ef8e6371e1f599405eff6ecc014499f234a008e");

    var binder: [32]u8 = undefined;
    try deriveBinder(.sha256, &psk, client_hello_prefix, &binder);
    try testing.expectEqualSlices(u8, &expected, &binder);

    try testing.expect(try verifyBinder(.sha256, &psk, client_hello_prefix, &binder));
    try testing.expect(!try verifyBinder(.sha256, &psk, "different prefix bytes here", &binder));
}

test "resumption binder derivation matches an independently computed SHA-384 binder" {
    // Checked-in literal, independently computed (see the SHA-256 test
    // above); the module's own concrete SHA-384 code path is entirely
    // separate from the SHA-256 one, so this is not redundant with it.
    const psk384 = [_]u8{0x77} ** 48;
    const expected = hexBytes(
        "138b767e68513f232636a0d2b2c53d7a923ff2c0d7879985d4ea916281c5134" ++
            "d3bc2b1ae31178e736fe22f2d906cfdd3",
    );
    var binder: [48]u8 = undefined;
    try deriveBinder(.sha384, &psk384, "prefix", &binder);
    try testing.expectEqualSlices(u8, &expected, &binder);

    var short_binder: [47]u8 = undefined;
    try testing.expectError(error.InvalidSecretLength, deriveBinder(.sha384, &psk384, "prefix", &short_binder));
    try testing.expectError(error.InvalidSecretLength, deriveBinder(.sha256, &psk384, "prefix", short_binder[0..32]));
}

test "verifyBinder rejects a wrong-length candidate without erroring" {
    const psk = [_]u8{0x11} ** 32;
    var binder: [32]u8 = undefined;
    try deriveBinder(.sha256, &psk, "prefix", &binder);
    try testing.expect(!try verifyBinder(.sha256, &psk, "prefix", binder[0..31]));
}

test "obfuscated ticket age round-trips including u32 wraparound" {
    const add: u32 = 0xffff_fff0;
    const age_ms: u64 = 1000;
    const obfuscated = obfuscateTicketAge(age_ms, add);
    try testing.expectEqual(@as(u32, 1000) +% add, obfuscated);
    try testing.expectEqual(@as(u32, 1000), deobfuscateTicketAge(obfuscated, add));

    // age_ms itself exceeds 2^32: only the low 32 bits participate.
    const huge_age: u64 = (@as(u64, 1) << 33) + 42;
    const obfuscated2 = obfuscateTicketAge(huge_age, add);
    try testing.expectEqual(@as(u32, 42) +% add, obfuscated2);
}

test "age skew observation reports signed drift without rejecting on its own" {
    const add: u32 = 500;
    const obfuscated = obfuscateTicketAge(10_000, add);
    const skew = observeAgeSkew(obfuscated, add, 9_000);
    try testing.expectEqual(@as(u32, 10_000), skew.apparent_age_ms);
    try testing.expectEqual(@as(i64, 1_000), skew.skew_ms);
}

test "ClientPskOfferSet is bounded to eight, move-oriented, and fully wiped on deinit" {
    var set: ClientPskOfferSet = .{};
    var common: session.ResumableSessionCommon = .{};
    try common.init(testing.allocator, .default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0x42} ** 32),
        .auth_binding = .{ .bytes = [_]u8{0} ** session.auth_binding_len },
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 1000,
    });
    var ticket: session.ClientTicketState = .{};
    try ticket.init(testing.allocator, .default, &common, .{
        .ticket = "opaque-ticket",
        .ticket_age_add = 7,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });
    try set.push(&ticket);
    try testing.expectEqual(@as(usize, 0), ticket.ticket.slice().len); // moved out
    try testing.expectEqual(@as(usize, 1), set.len);

    var dest: session.ClientTicketState = .{};
    set.takeSelected(0, &dest);
    try testing.expectEqualStrings("opaque-ticket", dest.ticket.slice());
    try testing.expectEqual(@as(usize, 0), set.len);
    dest.deinit();
}

test "ClientPskOfferSet accepts exactly eight offers and rejects a ninth" {
    var set: ClientPskOfferSet = .{};
    defer set.deinit();
    var common: session.ResumableSessionCommon = .{};
    try common.init(testing.allocator, .default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0x42} ** 32),
        .auth_binding = .{ .bytes = [_]u8{0} ** session.auth_binding_len },
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 1000,
    });
    defer common.deinit();

    var tickets: [max_offered_identities + 1]session.ClientTicketState = undefined;
    for (&tickets, 0..) |*ticket, i| {
        ticket.* = .{};
        var clone: session.ResumableSessionCommon = .{};
        try common.cloneInto(testing.allocator, &clone);
        var id_buf: [1]u8 = .{@intCast(i)};
        try ticket.init(testing.allocator, .default, &clone, .{
            .ticket = &id_buf,
            .ticket_age_add = 0,
            .ticket_nonce = "n",
            .received_at_unix_ms = 0,
        });
    }
    defer for (&tickets) |*ticket| ticket.deinit();

    for (tickets[0..max_offered_identities]) |*ticket| try set.push(ticket);
    try testing.expectEqual(max_offered_identities, set.len);
    try testing.expectError(error.TooManyOffers, set.push(&tickets[max_offered_identities]));
    // A rejected push leaves both the set and the ticket untouched.
    try testing.expectEqual(max_offered_identities, set.len);
    try testing.expectEqualStrings(&[_]u8{max_offered_identities}, tickets[max_offered_identities].ticket.slice());
}

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}
