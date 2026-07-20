//! Provider-neutral stateless TLS ticket protection (#363).
//!
//! The public ticket identity is a small authenticated envelope around the
//! canonical `session.ServerRecoverableState` encoding. Runtime loading,
//! rotation scheduling, metrics export, and TLS PSK binder policy stay outside
//! this module.

const std = @import("std");
const crypto = @import("crypto");
const session = @import("session.zig");

const provider = crypto.provider;
const secrets = crypto.secrets;

pub const magic = [4]u8{ 'T', 'D', 'T', 'K' };
pub const format_version: u8 = 1;
pub const key_id_len = 16;
pub const fixed_header_len = 36;
pub const tag_len = provider.aead_tag_len;
pub const envelope_overhead = fixed_header_len + tag_len;
pub const max_keys = 16;

const aad_prefix = "tardigrade/tls-ticket/v1\x00";

pub const KeyId = [key_id_len]u8;
const TicketKeySecret = secrets.FixedSecret(provider.max_aead_key_len);

pub const ParseError = error{
    MalformedEnvelope,
    UnsupportedVersion,
    UnsupportedAeadId,
    EnvelopeTooLarge,
};

pub const SnapshotError = error{
    TooManyKeys,
    DuplicateKeyId,
    InvalidKeyLength,
    UnsupportedCapability,
    InvalidValidityWindow,
    InvalidNonceLease,
    OverlappingNonceLease,
    AmbiguousEncryptionWindow,
    StaleSnapshotGeneration,
    GenerationOverflow,
    OutOfMemory,
};

pub const SealError = error{
    NoActiveEncryptionKey,
    AmbiguousActiveEncryptionKey,
    TicketOutlivesKey,
    NonceLeaseExhausted,
    SerializedStateTooLarge,
    TicketTooLarge,
    OutputTooSmall,
    UnsupportedCapability,
    InvalidInternalState,
    OutOfMemory,
};

pub const ResolveError = error{
    OutOfMemory,
    UnsupportedCapability,
    InvalidInternalState,
};

pub const SealRejectReason = enum {
    no_active_encryption_key,
    ambiguous_active_encryption_key,
    ticket_outlives_key,
    nonce_lease_exhausted,
    serialized_state_too_large,
    ticket_too_large,
    output_too_small,
    unsupported_capability,
    invalid_internal_state,
    out_of_memory,
};

pub const ResolveRejectReason = enum {
    malformed_envelope,
    unsupported_version,
    unsupported_aead,
    envelope_too_large,
    unknown_key,
    future_key,
    retired_key,
    unsupported_capability,
    authentication_failed,
    invalid_plaintext,
    not_yet_valid,
    expired,
    invalid_internal_state,
};

pub const SnapshotRejectReason = enum {
    too_many_keys,
    duplicate_key_id,
    invalid_key_length,
    unsupported_capability,
    invalid_validity_window,
    invalid_nonce_lease,
    overlapping_nonce_lease,
    ambiguous_encryption_window,
    stale_generation,
    generation_overflow,
    out_of_memory,
};

pub const Event = union(enum) {
    seal_succeeded,
    seal_rejected: SealRejectReason,
    resolve_succeeded,
    resolve_rejected: ResolveRejectReason,
    snapshot_installed: u64,
    snapshot_rejected: SnapshotRejectReason,
    key_retired: u64,
    nonce_lease_exhausted,
};

pub const Observer = struct {
    ctx: *anyopaque,
    recordFn: *const fn (*anyopaque, Event) void,

    pub fn record(self: Observer, event: Event) void {
        self.recordFn(self.ctx, event);
    }
};

pub const NonceLeaseConfig = struct {
    prefix: [4]u8,
    start: u64,
    end_exclusive: u64,
};

pub const KeyConfig = struct {
    id: KeyId,
    aead: provider.Aead,
    key_bytes: []const u8,
    not_before_unix_ms: i64,
    encrypt_until_unix_ms: i64,
    decrypt_until_unix_ms: i64,
    nonce_lease: ?NonceLeaseConfig = null,
};

pub const ParsedEnvelope = struct {
    aead: provider.Aead,
    key_id: KeyId,
    nonce: [provider.aead_nonce_len]u8,
    header: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
};

pub fn encodeAeadId(aead: provider.Aead) u8 {
    return switch (aead) {
        .aes_128_gcm => 1,
        .aes_256_gcm => 2,
        .chacha20_poly1305 => 3,
    };
}

pub fn decodeAeadId(id: u8) ParseError!provider.Aead {
    return switch (id) {
        1 => .aes_128_gcm,
        2 => .aes_256_gcm,
        3 => .chacha20_poly1305,
        else => error.UnsupportedAeadId,
    };
}

pub fn parseEnvelope(identity: []const u8, limits: session.Limits) ParseError!ParsedEnvelope {
    limits.validate() catch return error.EnvelopeTooLarge;
    if (identity.len > limits.max_ticket_len or identity.len > session.absolute_ticket_wire_max)
        return error.EnvelopeTooLarge;
    if (identity.len < fixed_header_len + 1 + tag_len) return error.MalformedEnvelope;
    if (!std.mem.eql(u8, identity[0..4], &magic)) return error.MalformedEnvelope;
    if (identity[4] != format_version) return error.UnsupportedVersion;
    const aead = try decodeAeadId(identity[5]);
    if (std.mem.readInt(u16, identity[6..8], .big) != 0) return error.MalformedEnvelope;

    var key_id: KeyId = undefined;
    @memcpy(&key_id, identity[8..24]);
    var nonce: [provider.aead_nonce_len]u8 = undefined;
    @memcpy(&nonce, identity[24..36]);

    return .{
        .aead = aead,
        .key_id = key_id,
        .nonce = nonce,
        .header = identity[0..fixed_header_len],
        .ciphertext = identity[fixed_header_len .. identity.len - tag_len],
        .tag = identity[identity.len - tag_len ..],
    };
}

const NonceLease = struct {
    prefix: [4]u8,
    next_counter: std.atomic.Value(u64),
    end_exclusive: u64,

    fn init(config: NonceLeaseConfig) SnapshotError!NonceLease {
        if (config.start >= config.end_exclusive) return error.InvalidNonceLease;
        return .{
            .prefix = config.prefix,
            .next_counter = std.atomic.Value(u64).init(config.start),
            .end_exclusive = config.end_exclusive,
        };
    }

    fn reserve(self: *NonceLease) SealError![provider.aead_nonce_len]u8 {
        while (true) {
            const current = self.next_counter.load(.acquire);
            if (current >= self.end_exclusive) return error.NonceLeaseExhausted;
            if (current == std.math.maxInt(u64)) return error.NonceLeaseExhausted;
            if (self.next_counter.cmpxchgWeak(current, current + 1, .acq_rel, .acquire) == null) {
                var nonce: [provider.aead_nonce_len]u8 = undefined;
                @memcpy(nonce[0..4], &self.prefix);
                std.mem.writeInt(u64, nonce[4..12], current, .big);
                return nonce;
            }
            std.atomic.spinLoopHint();
        }
    }

    fn currentEnd(self: *const NonceLease) u64 {
        return self.end_exclusive;
    }
};

const KeyRecord = struct {
    id: KeyId,
    aead: provider.Aead,
    key: TicketKeySecret,
    not_before_unix_ms: i64,
    encrypt_until_unix_ms: i64,
    decrypt_until_unix_ms: i64,
    nonce_lease: ?NonceLease,

    fn build(config: KeyConfig, caps: provider.Capabilities) SnapshotError!KeyRecord {
        if (!caps.supportsAead(config.aead)) return error.UnsupportedCapability;
        if (config.key_bytes.len != config.aead.keyLength()) return error.InvalidKeyLength;
        if (!(config.not_before_unix_ms < config.encrypt_until_unix_ms and
            config.encrypt_until_unix_ms <= config.decrypt_until_unix_ms))
            return error.InvalidValidityWindow;

        var key = TicketKeySecret.init(config.key_bytes) catch return error.InvalidKeyLength;
        errdefer key.deinit();

        const lease = if (config.nonce_lease) |lease_config|
            try NonceLease.init(lease_config)
        else
            null;

        return .{
            .id = config.id,
            .aead = config.aead,
            .key = key,
            .not_before_unix_ms = config.not_before_unix_ms,
            .encrypt_until_unix_ms = config.encrypt_until_unix_ms,
            .decrypt_until_unix_ms = config.decrypt_until_unix_ms,
            .nonce_lease = lease,
        };
    }

    fn deinit(self: *KeyRecord) void {
        self.key.deinit();
    }

    fn canEncryptAt(self: *const KeyRecord, now_unix_ms: i64) bool {
        return self.nonce_lease != null and
            now_unix_ms >= self.not_before_unix_ms and
            now_unix_ms < self.encrypt_until_unix_ms;
    }

    fn decryptWindowAt(self: *const KeyRecord, now_unix_ms: i64) enum { future, active, retained, retired } {
        if (now_unix_ms < self.not_before_unix_ms) return .future;
        if (now_unix_ms < self.encrypt_until_unix_ms) return .active;
        if (now_unix_ms < self.decrypt_until_unix_ms) return .retained;
        return .retired;
    }

    pub fn format(
        _: KeyRecord,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("ticket key records must not be formatted or logged");
    }
};

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    generation: u64,
    keys: []KeyRecord,
    ref_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(1),
    deinit_count: ?*std.atomic.Value(usize) = null,

    pub fn build(
        allocator: std.mem.Allocator,
        configs: []const KeyConfig,
        generation: u64,
        caps: provider.Capabilities,
    ) SnapshotError!*Snapshot {
        if (configs.len == 0 or configs.len > max_keys) return error.TooManyKeys;

        var snapshot = allocator.create(Snapshot) catch return error.OutOfMemory;
        snapshot.* = .{
            .allocator = allocator,
            .generation = generation,
            .keys = &.{},
        };
        errdefer {
            snapshot.deinit();
            allocator.destroy(snapshot);
        }

        var keys = allocator.alloc(KeyRecord, configs.len) catch return error.OutOfMemory;
        var initialized: usize = 0;
        errdefer {
            for (keys[0..initialized]) |*key| key.deinit();
            allocator.free(keys);
        }

        for (configs, 0..) |config, i| {
            for (configs[0..i]) |prior| {
                if (std.mem.eql(u8, &prior.id, &config.id)) return error.DuplicateKeyId;
            }
            keys[i] = try KeyRecord.build(config, caps);
            initialized += 1;
        }

        snapshot.keys = keys;
        return snapshot;
    }

    pub fn retain(self: *Snapshot) void {
        _ = self.ref_count.fetchAdd(1, .acq_rel);
    }

    pub fn release(self: *Snapshot) void {
        const previous = self.ref_count.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
        if (previous == 1) {
            const allocator = self.allocator;
            self.deinit();
            allocator.destroy(self);
        }
    }

    fn deinit(self: *Snapshot) void {
        if (self.deinit_count) |counter| _ = counter.fetchAdd(1, .monotonic);
        for (self.keys) |*key| key.deinit();
        self.allocator.free(self.keys);
        self.keys = &.{};
    }

    fn activeEncryptionKey(self: *Snapshot, now_unix_ms: i64) SealError!*KeyRecord {
        var found: ?*KeyRecord = null;
        for (self.keys) |*key| {
            if (!key.canEncryptAt(now_unix_ms)) continue;
            if (found != null) return error.AmbiguousActiveEncryptionKey;
            found = key;
        }
        return found orelse error.NoActiveEncryptionKey;
    }

    fn findKey(self: *Snapshot, key_id: *const KeyId) ?*KeyRecord {
        for (self.keys) |*key| {
            if (std.mem.eql(u8, &key.id, key_id)) return key;
        }
        return null;
    }

    pub fn format(
        _: Snapshot,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("ticket key snapshots must not be formatted or logged");
    }
};

const LeaseHighWater = struct {
    key_id: KeyId,
    prefix: [4]u8,
    end_exclusive: u64,
};

pub const ReloadableKeyRing = struct {
    allocator: std.mem.Allocator,
    mutex: SpinMutex = .{},
    current: ?*Snapshot = null,
    next_generation: u64 = 1,
    ledger: [max_keys]LeaseHighWater = undefined,
    ledger_len: usize = 0,
    observer: ?Observer = null,

    pub fn init(allocator: std.mem.Allocator) ReloadableKeyRing {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ReloadableKeyRing) void {
        self.mutex.lock();
        const retired = self.current;
        self.current = null;
        self.ledger_len = 0;
        self.mutex.unlock();
        if (retired) |snapshot| snapshot.release();
    }

    pub fn buildSnapshot(self: *ReloadableKeyRing, configs: []const KeyConfig, caps: provider.Capabilities) SnapshotError!*Snapshot {
        self.mutex.lock();
        if (self.next_generation == std.math.maxInt(u64)) {
            self.mutex.unlock();
            return error.GenerationOverflow;
        }
        const generation = self.next_generation;
        self.next_generation += 1;
        self.mutex.unlock();
        return Snapshot.build(self.allocator, configs, generation, caps);
    }

    pub fn install(self: *ReloadableKeyRing, replacement: *Snapshot) SnapshotError!void {
        self.mutex.lock();
        if (self.current) |current| {
            if (current == replacement) {
                if (replacement.generation == std.math.maxInt(u64)) {
                    self.mutex.unlock();
                    self.record(.{ .snapshot_rejected = .generation_overflow });
                    return error.GenerationOverflow;
                }
                self.next_generation = @max(self.next_generation, replacement.generation + 1);
                self.mutex.unlock();
                return;
            }
            if (replacement.generation <= current.generation) {
                self.mutex.unlock();
                replacement.release();
                self.record(.{ .snapshot_rejected = .stale_generation });
                return error.StaleSnapshotGeneration;
            }
        }
        if (replacement.generation == std.math.maxInt(u64)) {
            self.mutex.unlock();
            replacement.release();
            self.record(.{ .snapshot_rejected = .generation_overflow });
            return error.GenerationOverflow;
        }

        self.validateReplacementLocked(replacement) catch |err| {
            self.mutex.unlock();
            replacement.release();
            self.record(.{ .snapshot_rejected = snapshotReason(err) });
            return err;
        };

        const retired = self.current;
        self.current = replacement;
        self.next_generation = @max(self.next_generation, replacement.generation + 1);
        self.rebuildLedgerLocked();
        self.mutex.unlock();

        self.record(.{ .snapshot_installed = replacement.generation });
        if (retired) |snapshot| {
            self.record(.{ .key_retired = snapshot.generation });
            snapshot.release();
        }
    }

    pub fn acquireCurrent(self: *ReloadableKeyRing) ?*Snapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        const snapshot = self.current orelse return null;
        snapshot.retain();
        return snapshot;
    }

    fn validateReplacementLocked(self: *ReloadableKeyRing, replacement: *Snapshot) SnapshotError!void {
        for (replacement.keys, 0..) |*key, i| {
            if (key.nonce_lease) |*lease| {
                for (replacement.keys[0..i]) |*prior| {
                    if (!std.mem.eql(u8, &prior.id, &key.id)) continue;
                    if (prior.nonce_lease) |*prior_lease| {
                        if (std.mem.eql(u8, &prior_lease.prefix, &lease.prefix) and
                            rangesOverlap(prior_lease.next_counter.load(.acquire), prior_lease.currentEnd(), lease.next_counter.load(.acquire), lease.currentEnd()))
                            return error.OverlappingNonceLease;
                    }
                }
                if (self.findLedger(&key.id)) |entry| {
                    if (!std.mem.eql(u8, &entry.prefix, &lease.prefix)) return error.OverlappingNonceLease;
                    if (lease.next_counter.load(.acquire) < entry.end_exclusive) return error.OverlappingNonceLease;
                }
            }

            if (self.current) |current| {
                if (current.findKey(&key.id)) |old| {
                    if (old.aead != key.aead or !old.key.eql(&key.key)) return error.DuplicateKeyId;
                }
            }
        }
    }

    fn rebuildLedgerLocked(self: *ReloadableKeyRing) void {
        self.ledger_len = 0;
        const snapshot = self.current orelse return;
        for (snapshot.keys) |*key| {
            const lease = if (key.nonce_lease) |*lease| lease else continue;
            if (self.findLedgerIndex(&key.id)) |idx| {
                self.ledger[idx].end_exclusive = @max(self.ledger[idx].end_exclusive, lease.currentEnd());
            } else if (self.ledger_len < self.ledger.len) {
                self.ledger[self.ledger_len] = .{
                    .key_id = key.id,
                    .prefix = lease.prefix,
                    .end_exclusive = lease.currentEnd(),
                };
                self.ledger_len += 1;
            }
        }
    }

    fn findLedger(self: *const ReloadableKeyRing, key_id: *const KeyId) ?LeaseHighWater {
        if (self.findLedgerIndex(key_id)) |idx| return self.ledger[idx];
        return null;
    }

    fn findLedgerIndex(self: *const ReloadableKeyRing, key_id: *const KeyId) ?usize {
        for (self.ledger[0..self.ledger_len], 0..) |entry, i| {
            if (std.mem.eql(u8, &entry.key_id, key_id)) return i;
        }
        return null;
    }

    fn record(self: *ReloadableKeyRing, event: Event) void {
        if (self.observer) |observer| observer.record(event);
    }
};

pub const Protector = struct {
    provider: provider.CryptoProvider,
    keyring: *ReloadableKeyRing,
    limits: session.Limits,
    observer: ?Observer = null,

    pub fn protectedLen(
        self: *const Protector,
        state: *const session.ServerRecoverableState,
    ) SealError!usize {
        const plaintext_len = session.serverEncodedLenWithLimits(state, self.limits) catch |err| switch (err) {
            error.StateTooLarge => return error.SerializedStateTooLarge,
            error.InvalidLimits, error.TooManyFields, error.FieldTooLarge, error.InvalidState => return error.SerializedStateTooLarge,
            error.BufferTooSmall => unreachable,
        };
        return checkedProtectedLen(plaintext_len, self.limits);
    }

    pub fn seal(
        self: *Protector,
        allocator: std.mem.Allocator,
        state: *const session.ServerRecoverableState,
        now_unix_ms: i64,
        out: []u8,
    ) SealError![]const u8 {
        const snapshot = self.keyring.acquireCurrent() orelse {
            self.record(.{ .seal_rejected = .no_active_encryption_key });
            return error.NoActiveEncryptionKey;
        };
        defer snapshot.release();

        const key = snapshot.activeEncryptionKey(now_unix_ms) catch |err| {
            self.record(.{ .seal_rejected = sealReason(err) });
            return err;
        };

        if (!self.provider.capabilities().supportsAead(key.aead)) {
            self.record(.{ .seal_rejected = .unsupported_capability });
            return error.UnsupportedCapability;
        }

        if (!ticketExpiresWithinKey(state, key.decrypt_until_unix_ms)) {
            self.record(.{ .seal_rejected = .ticket_outlives_key });
            return error.TicketOutlivesKey;
        }

        const protected_len = try self.protectedLen(state);
        if (out.len < protected_len) {
            self.record(.{ .seal_rejected = .output_too_small });
            return error.OutputTooSmall;
        }

        const plaintext_len = protected_len - envelope_overhead;
        const plaintext = allocator.alloc(u8, plaintext_len) catch {
            self.record(.{ .seal_rejected = .out_of_memory });
            return error.OutOfMemory;
        };
        defer {
            secrets.secureZero(plaintext);
            allocator.free(plaintext);
        }

        const encoded = session.encodeServer(state, self.limits, plaintext) catch |err| switch (err) {
            error.BufferTooSmall, error.InvalidLimits, error.TooManyFields, error.FieldTooLarge, error.InvalidState => return error.InvalidInternalState,
            error.StateTooLarge => return error.SerializedStateTooLarge,
        };
        std.debug.assert(encoded.len == plaintext_len);

        const lease = &(key.nonce_lease orelse {
            self.record(.{ .seal_rejected = .no_active_encryption_key });
            return error.NoActiveEncryptionKey;
        });
        const nonce = lease.reserve() catch |err| {
            self.record(.nonce_lease_exhausted);
            self.record(.{ .seal_rejected = .nonce_lease_exhausted });
            return err;
        };

        writeHeader(out[0..fixed_header_len], key.aead, &key.id, &nonce);
        var aad: [aad_prefix.len + fixed_header_len]u8 = undefined;
        buildAad(out[0..fixed_header_len], &aad);
        const ciphertext = out[fixed_header_len .. fixed_header_len + plaintext_len];
        const tag = out[fixed_header_len + plaintext_len .. protected_len];
        self.provider.aeadSeal(key.aead, key.key.slice(), &nonce, &aad, encoded, ciphertext, tag) catch |err| switch (err) {
            error.UnsupportedCapability => return error.UnsupportedCapability,
            error.InvalidInput => return error.InvalidInternalState,
        };

        self.record(.seal_succeeded);
        return out[0..protected_len];
    }

    pub fn resolve(
        self: *Protector,
        allocator: std.mem.Allocator,
        identity: []const u8,
        now_unix_ms: i64,
        out: *session.ServerRecoverableState,
    ) ResolveError!bool {
        const parsed = parseEnvelope(identity, self.limits) catch |err| {
            self.record(.{ .resolve_rejected = parseReason(err) });
            return false;
        };

        const snapshot = self.keyring.acquireCurrent() orelse {
            self.record(.{ .resolve_rejected = .unknown_key });
            return false;
        };
        defer snapshot.release();

        const key = snapshot.findKey(&parsed.key_id) orelse {
            self.record(.{ .resolve_rejected = .unknown_key });
            return false;
        };
        if (key.aead != parsed.aead) {
            self.record(.{ .resolve_rejected = .authentication_failed });
            return false;
        }
        switch (key.decryptWindowAt(now_unix_ms)) {
            .future => {
                self.record(.{ .resolve_rejected = .future_key });
                return false;
            },
            .active, .retained => {},
            .retired => {
                self.record(.{ .resolve_rejected = .retired_key });
                return false;
            },
        }
        if (!self.provider.capabilities().supportsAead(key.aead)) return error.UnsupportedCapability;

        const plaintext = allocator.alloc(u8, parsed.ciphertext.len) catch return error.OutOfMemory;
        defer {
            secrets.secureZero(plaintext);
            allocator.free(plaintext);
        }

        var aad: [aad_prefix.len + fixed_header_len]u8 = undefined;
        buildAad(parsed.header, &aad);
        self.provider.aeadOpen(key.aead, key.key.slice(), &parsed.nonce, &aad, parsed.ciphertext, parsed.tag, plaintext) catch |err| switch (err) {
            error.AuthenticationFailed => {
                self.record(.{ .resolve_rejected = .authentication_failed });
                return false;
            },
            error.UnsupportedCapability => return error.UnsupportedCapability,
            error.InvalidInput => return error.InvalidInternalState,
        };

        var decoded = session.decode(allocator, self.limits, plaintext) catch {
            self.record(.{ .resolve_rejected = .invalid_plaintext });
            return false;
        };
        defer decoded.deinit();

        var recovered = switch (decoded) {
            .server => |*server_state| server_state,
            .client => {
                self.record(.{ .resolve_rejected = .invalid_plaintext });
                return false;
            },
        };
        if (recovered.common.isNotYetValid(now_unix_ms)) {
            self.record(.{ .resolve_rejected = .not_yet_valid });
            return false;
        }
        if (recovered.common.isExpired(now_unix_ms)) {
            self.record(.{ .resolve_rejected = .expired });
            return false;
        }

        out.moveFrom(recovered);
        self.record(.resolve_succeeded);
        return true;
    }

    fn record(self: *Protector, event: Event) void {
        if (self.observer) |observer| observer.record(event);
    }
};

fn checkedProtectedLen(plaintext_len: usize, limits: session.Limits) SealError!usize {
    if (plaintext_len > limits.max_serialized_len) return error.SerializedStateTooLarge;
    const protected_len = std.math.add(usize, fixed_header_len, plaintext_len) catch return error.TicketTooLarge;
    const total = std.math.add(usize, protected_len, tag_len) catch return error.TicketTooLarge;
    if (total > limits.max_ticket_len) return error.TicketTooLarge;
    if (total > session.absolute_ticket_wire_max) return error.TicketTooLarge;
    return total;
}

fn ticketExpiresWithinKey(state: *const session.ServerRecoverableState, key_decrypt_until_unix_ms: i64) bool {
    const expires: i128 = @as(i128, state.common.issued_at_unix_ms) +
        @as(i128, state.common.lifetime_seconds) * 1000;
    return expires <= @as(i128, key_decrypt_until_unix_ms);
}

fn writeHeader(out: []u8, aead: provider.Aead, key_id: *const KeyId, nonce: *const [provider.aead_nonce_len]u8) void {
    std.debug.assert(out.len == fixed_header_len);
    @memcpy(out[0..4], &magic);
    out[4] = format_version;
    out[5] = encodeAeadId(aead);
    std.mem.writeInt(u16, out[6..8], 0, .big);
    @memcpy(out[8..24], key_id);
    @memcpy(out[24..36], nonce);
}

fn buildAad(header: []const u8, out: *[aad_prefix.len + fixed_header_len]u8) void {
    std.debug.assert(header.len == fixed_header_len);
    @memcpy(out[0..aad_prefix.len], aad_prefix);
    @memcpy(out[aad_prefix.len..], header);
}

fn rangesOverlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) bool {
    return a_start < b_end and b_start < a_end;
}

fn parseReason(err: ParseError) ResolveRejectReason {
    return switch (err) {
        error.MalformedEnvelope => .malformed_envelope,
        error.UnsupportedVersion => .unsupported_version,
        error.UnsupportedAeadId => .unsupported_aead,
        error.EnvelopeTooLarge => .envelope_too_large,
    };
}

fn sealReason(err: SealError) SealRejectReason {
    return switch (err) {
        error.NoActiveEncryptionKey => .no_active_encryption_key,
        error.AmbiguousActiveEncryptionKey => .ambiguous_active_encryption_key,
        error.TicketOutlivesKey => .ticket_outlives_key,
        error.NonceLeaseExhausted => .nonce_lease_exhausted,
        error.SerializedStateTooLarge => .serialized_state_too_large,
        error.TicketTooLarge => .ticket_too_large,
        error.OutputTooSmall => .output_too_small,
        error.UnsupportedCapability => .unsupported_capability,
        error.InvalidInternalState => .invalid_internal_state,
        error.OutOfMemory => .out_of_memory,
    };
}

fn snapshotReason(err: SnapshotError) SnapshotRejectReason {
    return switch (err) {
        error.TooManyKeys => .too_many_keys,
        error.DuplicateKeyId => .duplicate_key_id,
        error.InvalidKeyLength => .invalid_key_length,
        error.UnsupportedCapability => .unsupported_capability,
        error.InvalidValidityWindow => .invalid_validity_window,
        error.InvalidNonceLease => .invalid_nonce_lease,
        error.OverlappingNonceLease => .overlapping_nonce_lease,
        error.AmbiguousEncryptionWindow => .ambiguous_encryption_window,
        error.StaleSnapshotGeneration => .stale_generation,
        error.GenerationOverflow => .generation_overflow,
        error.OutOfMemory => .out_of_memory,
    };
}

const SpinMutex = struct {
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

    fn lock(self: *SpinMutex) void {
        while (self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *SpinMutex) void {
        self.state.store(0, .release);
    }
};

const testing = std.testing;

fn testCapabilities() provider.Capabilities {
    var caps = provider.Capabilities{};
    caps.aeads.insert(.aes_128_gcm);
    caps.aeads.insert(.aes_256_gcm);
    caps.aeads.insert(.chacha20_poly1305);
    return caps;
}

fn testProvider() provider.CryptoProvider {
    const pure_zig = crypto.pure_zig;
    const Static = struct {
        var entropy_buf = [_]u8{0x42} ** 256;
        var entropy = std.Random.DefaultPrng.init(1);
        var provider_state = pure_zig.Provider.init(.{
            .context = &entropy,
            .fillFn = fill,
        });

        fn fill(ctx: *anyopaque, out: []u8) provider.EntropyError!void {
            _ = &entropy_buf;
            const prng: *std.Random.DefaultPrng = @ptrCast(@alignCast(ctx));
            prng.random().bytes(out);
        }
    };
    return Static.provider_state.cryptoProvider();
}

fn keyId(byte: u8) KeyId {
    return [_]u8{byte} ** key_id_len;
}

fn sampleKeyConfig(id: KeyId, aead: provider.Aead, lease: ?NonceLeaseConfig) KeyConfig {
    return .{
        .id = id,
        .aead = aead,
        .key_bytes = switch (aead) {
            .aes_128_gcm => &([_]u8{0x11} ** 16),
            .aes_256_gcm, .chacha20_poly1305 => &([_]u8{0x22} ** 32),
        },
        .not_before_unix_ms = 1_000,
        .encrypt_until_unix_ms = 5_000,
        .decrypt_until_unix_ms = 20_000,
        .nonce_lease = lease,
    };
}

fn sampleServerState(allocator: std.mem.Allocator) !session.ServerRecoverableState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xab} ** 32),
        .server_name = "Example.TEST",
        .application_protocol = "h3",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 1_000,
        .lifetime_seconds = 10,
        .early_data = .resume_only,
    });
    var state: session.ServerRecoverableState = .{};
    state.init(&common);
    return state;
}

test "AEAD id mapping is stable and not enum ordinal dependent" {
    try testing.expectEqual(@as(u8, 1), encodeAeadId(.aes_128_gcm));
    try testing.expectEqual(@as(u8, 2), encodeAeadId(.aes_256_gcm));
    try testing.expectEqual(@as(u8, 3), encodeAeadId(.chacha20_poly1305));
    try testing.expectEqual(provider.Aead.aes_128_gcm, try decodeAeadId(1));
    try testing.expectEqual(provider.Aead.aes_256_gcm, try decodeAeadId(2));
    try testing.expectEqual(provider.Aead.chacha20_poly1305, try decodeAeadId(3));
    try testing.expectError(error.UnsupportedAeadId, decodeAeadId(0));
}

test "parseEnvelope validates public structure without allocation" {
    var identity = [_]u8{0} ** (fixed_header_len + 1 + tag_len);
    writeHeader(identity[0..fixed_header_len], .aes_128_gcm, &keyId(7), &([_]u8{0x33} ** provider.aead_nonce_len));
    identity[fixed_header_len] = 1;
    const parsed = try parseEnvelope(&identity, session.Limits.default);
    try testing.expectEqual(provider.Aead.aes_128_gcm, parsed.aead);
    try testing.expectEqual(@as(usize, 1), parsed.ciphertext.len);
    try testing.expectEqual(@as(usize, tag_len), parsed.tag.len);

    identity[0] = 'x';
    try testing.expectError(error.MalformedEnvelope, parseEnvelope(&identity, session.Limits.default));
    identity[0] = 'T';
    identity[4] = 2;
    try testing.expectError(error.UnsupportedVersion, parseEnvelope(&identity, session.Limits.default));
    identity[4] = format_version;
    identity[5] = 99;
    try testing.expectError(error.UnsupportedAeadId, parseEnvelope(&identity, session.Limits.default));
    identity[5] = encodeAeadId(.aes_128_gcm);
    identity[7] = 1;
    try testing.expectError(error.MalformedEnvelope, parseEnvelope(&identity, session.Limits.default));
}

test "protectedLen reserves envelope overhead exactly" {
    var state = try sampleServerState(testing.allocator);
    defer state.deinit();
    const encoded_len = try session.serverEncodedLenWithLimits(&state, session.Limits.default);
    var limits = session.Limits.default;
    limits.max_ticket_len = encoded_len + envelope_overhead;
    var keyring = ReloadableKeyRing.init(testing.allocator);
    defer keyring.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = limits };
    try testing.expectEqual(encoded_len + envelope_overhead, try protector.protectedLen(&state));

    limits.max_ticket_len = encoded_len + envelope_overhead - 1;
    protector.limits = limits;
    try testing.expectError(error.TicketTooLarge, protector.protectedLen(&state));
}

test "seal and resolve round trip and authenticate header fields" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = sampleKeyConfig(keyId(1), .aes_128_gcm, .{ .prefix = .{ 1, 2, 3, 4 }, .start = 9, .end_exclusive = 11 });
    const snapshot = try keyring.buildSnapshot(&.{config}, testCapabilities());
    try keyring.install(snapshot);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;
    const ticket = try protector.seal(allocator, &state, 2_000, &ticket_buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 9 }, ticket[24..36]);

    var recovered: session.ServerRecoverableState = .{};
    defer recovered.deinit();
    try testing.expect(try protector.resolve(allocator, ticket, 2_000, &recovered));
    try testing.expectEqual(state.common.lifetime_seconds, recovered.common.lifetime_seconds);
    try testing.expectEqualSlices(u8, state.common.resumption_psk.slice(), recovered.common.resumption_psk.slice());

    ticket_buf[8] ^= 1;
    var untouched: session.ServerRecoverableState = .{};
    defer untouched.deinit();
    try testing.expect(!try protector.resolve(allocator, ticket, 2_000, &untouched));
}

test "nonce lease exhaustion fails closed without wraparound" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = sampleKeyConfig(keyId(2), .aes_128_gcm, .{ .prefix = .{ 9, 8, 7, 6 }, .start = 0, .end_exclusive = 1 });
    const snapshot = try keyring.buildSnapshot(&.{config}, testCapabilities());
    try keyring.install(snapshot);

    var state = try sampleServerState(allocator);
    defer state.deinit();
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var ticket_buf = [_]u8{0} ** 512;
    _ = try protector.seal(allocator, &state, 2_000, &ticket_buf);
    try testing.expectError(error.NonceLeaseExhausted, protector.seal(allocator, &state, 2_000, &ticket_buf));
}

test "replacement snapshot rejects overlapping nonce lease and accepts adjacent range" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const first = sampleKeyConfig(keyId(3), .aes_128_gcm, .{ .prefix = .{ 1, 1, 1, 1 }, .start = 0, .end_exclusive = 10 });
    try keyring.install(try keyring.buildSnapshot(&.{first}, testCapabilities()));

    const overlap = sampleKeyConfig(keyId(3), .aes_128_gcm, .{ .prefix = .{ 1, 1, 1, 1 }, .start = 9, .end_exclusive = 20 });
    try testing.expectError(error.OverlappingNonceLease, keyring.install(try keyring.buildSnapshot(&.{overlap}, testCapabilities())));

    const adjacent = sampleKeyConfig(keyId(3), .aes_128_gcm, .{ .prefix = .{ 1, 1, 1, 1 }, .start = 10, .end_exclusive = 20 });
    try keyring.install(try keyring.buildSnapshot(&.{adjacent}, testCapabilities()));

    const changed_prefix = sampleKeyConfig(keyId(3), .aes_128_gcm, .{ .prefix = .{ 2, 1, 1, 1 }, .start = 20, .end_exclusive = 30 });
    try testing.expectError(error.OverlappingNonceLease, keyring.install(try keyring.buildSnapshot(&.{changed_prefix}, testCapabilities())));
}

test "key windows and ticket lifetime are enforced" {
    const allocator = testing.allocator;
    var keyring = ReloadableKeyRing.init(allocator);
    defer keyring.deinit();
    const config = sampleKeyConfig(keyId(4), .aes_128_gcm, .{ .prefix = .{ 4, 4, 4, 4 }, .start = 0, .end_exclusive = 3 });
    try keyring.install(try keyring.buildSnapshot(&.{config}, testCapabilities()));
    var protector = Protector{ .provider = testProvider(), .keyring = &keyring, .limits = session.Limits.default };
    var state = try sampleServerState(allocator);
    defer state.deinit();
    var ticket_buf = [_]u8{0} ** 512;

    try testing.expectError(error.NoActiveEncryptionKey, protector.seal(allocator, &state, 999, &ticket_buf));
    _ = try protector.seal(allocator, &state, 4_999, &ticket_buf);
    try testing.expectError(error.NoActiveEncryptionKey, protector.seal(allocator, &state, 5_000, &ticket_buf));

    state.common.lifetime_seconds = 20;
    try testing.expectError(error.TicketOutlivesKey, protector.seal(allocator, &state, 2_000, &ticket_buf));
}
