//! Optional, disabled-by-default persistence for the bounded session caches
//! in `session_cache.zig` (#364).
//!
//! Persistence is never required for `ClientSessionCache` /
//! `StatefulServerCache` to function: both are complete in-memory stores on
//! their own. This module only adds a versioned snapshot framing plus two
//! small seams a caller wires up for a real backend:
//!
//!   - `Protector` — seals/opens the snapshot's sensitive plaintext (which
//!     contains bearer secrets: resumption PSKs and raw tickets). No
//!     built-in adapter here writes that plaintext to disk directly; a real
//!     deployment must supply a `Protector` backed by an actual AEAD/KMS
//!     integration.
//!   - `Backend` — loads/saves the already-sealed bytes. Atomic replacement
//!     (e.g. write-temp-then-rename) is the backend implementation's
//!     responsibility; this module only guarantees that the in-memory cache
//!     is swapped to the newly-loaded state in one step, and only after
//!     decode/limit/expiry validation has fully succeeded.
//!
//! A persistence failure (protection, backend, or malformed/oversized/
//! unsupported-version/trailing-data snapshot) never invalidates the live
//! in-memory cache and never propagates as a TLS-connection-affecting
//! error — every entry point here returns a plain `SaveResult` / `LoadResult`.
//!
//! Decoding is bounded *before* it allocates anything sized by attacker- or
//! corruption-controlled input: the declared record count is checked
//! against the target cache's own entry limit (and a hard ceiling) before
//! any capacity is reserved, the plaintext itself is checked against a
//! fixed byte ceiling before parsing starts, and a snapshot with any
//! trailing bytes after its declared records is rejected rather than
//! silently accepted.

const std = @import("std");
const crypto = @import("crypto");
const session = @import("session.zig");
const session_cache = @import("session_cache.zig");

const secrets = crypto.secrets;

pub const snapshot_magic = [4]u8{ 'T', 'D', 'P', 'S' };
pub const snapshot_version: u8 = 1;
const header_len: usize = 4 + 1 + 1 + 4;

/// Hard ceiling on total plaintext snapshot size, checked before any
/// header/record parsing begins. Generous relative to the cache byte
/// budgets (`Limits.hard_max_total_bytes`) so a legitimate snapshot never
/// approaches it, while still bounding a corrupted or malicious buffer.
pub const hard_max_snapshot_bytes: usize = 16 * 1024 * 1024;

pub const SnapshotKind = enum(u8) { client = 1, server = 2 };

pub const SnapshotEncodeError = session.EncodeError || error{OutOfMemory};
pub const SnapshotDecodeError = error{
    OutOfMemory,
    SnapshotTooLarge,
    Truncated,
    TrailingData,
    BadMagic,
    UnsupportedVersion,
    UnsupportedKind,
    TooManyRecords,
    MalformedLength,
    InvalidHandle,
    DecodeFailed,
};

// -----------------------------------------------------------------------
// Snapshot framing: `magic(4) | version(1) | kind(1) | count(4) | records`.
//
// Client record:
//   `usage(1) | insertion_sequence(8) | lru_sequence(8) | len(4) |
//    session.encodeClient bytes(len)`.
// Server record:
//   `usage(1) | handle(40) | lru_sequence(8) | len(4) |
//    session.encodeServer bytes(len)`.
//
// Persisting `insertion_sequence`/`lru_sequence` explicitly (rather than
// relying on physical record order) lets restore reproduce the exact
// pre-save offer order and eviction order, since the live caches reorder
// their backing storage on every `swapRemove`-based removal.
// -----------------------------------------------------------------------

fn writeHeader(out: []u8, kind: SnapshotKind, count: u32) void {
    @memcpy(out[0..4], &snapshot_magic);
    out[4] = snapshot_version;
    out[5] = @intFromEnum(kind);
    std.mem.writeInt(u32, out[6..10], count, .big);
}

const Header = struct {
    kind: SnapshotKind,
    count: u32,
    body: []const u8,
};

fn readHeader(bytes: []const u8) SnapshotDecodeError!Header {
    if (bytes.len > hard_max_snapshot_bytes) return error.SnapshotTooLarge;
    if (bytes.len < header_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], &snapshot_magic)) return error.BadMagic;
    if (bytes[4] != snapshot_version) return error.UnsupportedVersion;
    const kind = std.enums.fromInt(SnapshotKind, bytes[5]) orelse return error.UnsupportedKind;
    const count = std.mem.readInt(u32, bytes[6..10], .big);
    return .{ .kind = kind, .count = count, .body = bytes[header_len..] };
}

/// Encodes every live client entry into a single owned plaintext buffer.
/// The returned buffer contains bearer secrets (raw tickets, PSKs): the
/// caller must wipe it (`secrets.secureZero`) before freeing, on every path.
pub fn encodeClientSnapshotAlloc(
    allocator: std.mem.Allocator,
    entries: []const session_cache.PersistedClientEntry,
    limits: session.Limits,
) SnapshotEncodeError![]u8 {
    var total: usize = header_len;
    for (entries) |*e| {
        const encoded_len = try session.clientEncodedLenWithLimits(&e.ticket, limits);
        total += 1 + 8 + 8 + 4 + encoded_len;
    }

    const buf = try allocator.alloc(u8, total);
    errdefer {
        secrets.secureZero(buf);
        allocator.free(buf);
    }

    writeHeader(buf, .client, @intCast(entries.len));
    var pos: usize = header_len;
    for (entries) |*e| {
        buf[pos] = @intFromEnum(e.usage);
        pos += 1;
        std.mem.writeInt(u64, buf[pos..][0..8], e.insertion_sequence, .big);
        pos += 8;
        std.mem.writeInt(u64, buf[pos..][0..8], e.lru_sequence, .big);
        pos += 8;
        const encoded_len = try session.clientEncodedLenWithLimits(&e.ticket, limits);
        std.mem.writeInt(u32, buf[pos..][0..4], @intCast(encoded_len), .big);
        pos += 4;
        _ = try session.encodeClient(&e.ticket, limits, buf[pos .. pos + encoded_len]);
        pos += encoded_len;
    }
    std.debug.assert(pos == total);
    return buf;
}

/// Same framing for the stateful server cache; each record also carries the
/// exact 40-byte `TDSH` handle so a reload can preserve it (a client that
/// still holds the identity must keep working).
pub fn encodeServerSnapshotAlloc(
    allocator: std.mem.Allocator,
    entries: []const session_cache.PersistedServerEntry,
    limits: session.Limits,
) SnapshotEncodeError![]u8 {
    var total: usize = header_len;
    for (entries) |*e| {
        const encoded_len = try session.serverEncodedLenWithLimits(&e.state, limits);
        total += 1 + session_cache.stateful_identity_len + 8 + 4 + encoded_len;
    }

    const buf = try allocator.alloc(u8, total);
    errdefer {
        secrets.secureZero(buf);
        allocator.free(buf);
    }

    writeHeader(buf, .server, @intCast(entries.len));
    var pos: usize = header_len;
    for (entries) |*e| {
        buf[pos] = @intFromEnum(e.usage);
        pos += 1;
        @memcpy(buf[pos .. pos + session_cache.stateful_identity_len], &e.handle);
        pos += session_cache.stateful_identity_len;
        std.mem.writeInt(u64, buf[pos..][0..8], e.lru_sequence, .big);
        pos += 8;
        const encoded_len = try session.serverEncodedLenWithLimits(&e.state, limits);
        std.mem.writeInt(u32, buf[pos..][0..4], @intCast(encoded_len), .big);
        pos += 4;
        _ = try session.encodeServer(&e.state, limits, buf[pos .. pos + encoded_len]);
        pos += encoded_len;
    }
    std.debug.assert(pos == total);
    return buf;
}

/// `max_entries` bounds `header.count` *before* any capacity is reserved
/// for the decoded list, so a corrupted/hostile snapshot claiming an
/// enormous count fails immediately rather than attempting a huge
/// allocation. It is typically the target cache's own `Limits.max_entries`.
pub fn decodeClientSnapshotAlloc(
    allocator: std.mem.Allocator,
    limits: session.Limits,
    max_entries: usize,
    bytes: []const u8,
) SnapshotDecodeError!std.ArrayListUnmanaged(session_cache.PersistedClientEntry) {
    const header = try readHeader(bytes);
    if (header.kind != .client) return error.UnsupportedKind;
    if (header.count > max_entries or header.count > session_cache.hard_max_entries) return error.TooManyRecords;

    var out: std.ArrayListUnmanaged(session_cache.PersistedClientEntry) = .empty;
    errdefer {
        for (out.items) |*p| p.deinit();
        out.deinit(allocator);
    }
    out.ensureTotalCapacityPrecise(allocator, header.count) catch return error.OutOfMemory;

    var rest = header.body;
    var i: u32 = 0;
    while (i < header.count) : (i += 1) {
        if (rest.len < 1 + 8 + 8 + 4) return error.Truncated;
        const usage = std.enums.fromInt(session_cache.UsagePolicy, rest[0]) orelse return error.MalformedLength;
        const insertion_sequence = std.mem.readInt(u64, rest[1..9], .big);
        const lru_sequence = std.mem.readInt(u64, rest[9..17], .big);
        const len = std.mem.readInt(u32, rest[17..21], .big);
        rest = rest[21..];
        if (rest.len < len) return error.Truncated;
        const record_bytes = rest[0..len];
        rest = rest[len..];

        var decoded = session.decode(allocator, limits, record_bytes) catch return error.DecodeFailed;
        switch (decoded) {
            .client => |c| out.appendAssumeCapacity(.{
                .ticket = c,
                .usage = usage,
                .insertion_sequence = insertion_sequence,
                .lru_sequence = lru_sequence,
            }),
            .server => {
                decoded.deinit();
                return error.UnsupportedKind;
            },
        }
    }
    if (rest.len != 0) return error.TrailingData;
    return out;
}

pub fn decodeServerSnapshotAlloc(
    allocator: std.mem.Allocator,
    limits: session.Limits,
    max_entries: usize,
    bytes: []const u8,
) SnapshotDecodeError!std.ArrayListUnmanaged(session_cache.PersistedServerEntry) {
    const header = try readHeader(bytes);
    if (header.kind != .server) return error.UnsupportedKind;
    if (header.count > max_entries or header.count > session_cache.hard_max_entries) return error.TooManyRecords;

    var out: std.ArrayListUnmanaged(session_cache.PersistedServerEntry) = .empty;
    errdefer {
        for (out.items) |*p| p.deinit();
        out.deinit(allocator);
    }
    out.ensureTotalCapacityPrecise(allocator, header.count) catch return error.OutOfMemory;

    var rest = header.body;
    var i: u32 = 0;
    while (i < header.count) : (i += 1) {
        const fixed_len = 1 + session_cache.stateful_identity_len + 8 + 4;
        if (rest.len < fixed_len) return error.Truncated;
        const usage = std.enums.fromInt(session_cache.UsagePolicy, rest[0]) orelse return error.MalformedLength;
        var handle: [session_cache.stateful_identity_len]u8 = undefined;
        @memcpy(&handle, rest[1 .. 1 + session_cache.stateful_identity_len]);
        if (!session_cache.isValidStatefulHandleShape(&handle)) return error.InvalidHandle;
        const lru_offset = 1 + session_cache.stateful_identity_len;
        const lru_sequence = std.mem.readInt(u64, rest[lru_offset..][0..8], .big);
        const len_offset = lru_offset + 8;
        const len = std.mem.readInt(u32, rest[len_offset..][0..4], .big);
        rest = rest[fixed_len..];
        if (rest.len < len) return error.Truncated;
        const record_bytes = rest[0..len];
        rest = rest[len..];

        var decoded = session.decode(allocator, limits, record_bytes) catch return error.DecodeFailed;
        switch (decoded) {
            .server => |s| out.appendAssumeCapacity(.{ .handle = handle, .usage = usage, .state = s, .lru_sequence = lru_sequence }),
            .client => {
                decoded.deinit();
                return error.UnsupportedKind;
            },
        }
    }
    if (rest.len != 0) return error.TrailingData;
    return out;
}

// -----------------------------------------------------------------------
// Protection / backend seams
// -----------------------------------------------------------------------

pub const ProtectError = error{ProtectionFailed};

/// Seals/opens the sensitive snapshot plaintext. `sealedLen`/`openLen` let
/// callers size scratch buffers before calling `seal`/`open`.
pub const Protector = struct {
    ctx: *anyopaque,
    sealedLenFn: *const fn (ctx: *anyopaque, plaintext_len: usize) usize,
    sealFn: *const fn (ctx: *anyopaque, plaintext: []const u8, out: []u8) ProtectError![]const u8,
    openLenFn: *const fn (ctx: *anyopaque, sealed_len: usize) usize,
    openFn: *const fn (ctx: *anyopaque, sealed: []const u8, out: []u8) ProtectError![]const u8,

    pub fn sealedLen(self: Protector, plaintext_len: usize) usize {
        return self.sealedLenFn(self.ctx, plaintext_len);
    }
    pub fn seal(self: Protector, plaintext: []const u8, out: []u8) ProtectError![]const u8 {
        return self.sealFn(self.ctx, plaintext, out);
    }
    pub fn openLen(self: Protector, sealed_len: usize) usize {
        return self.openLenFn(self.ctx, sealed_len);
    }
    pub fn open(self: Protector, sealed: []const u8, out: []u8) ProtectError![]const u8 {
        return self.openFn(self.ctx, sealed, out);
    }
};

pub const BackendError = error{BackendFailed};

/// Loads/saves already-sealed bytes. `save` must be atomic from an external
/// reader's point of view (e.g. write-temp-then-rename); that guarantee is
/// the concrete backend's responsibility, not this module's.
pub const Backend = struct {
    ctx: *anyopaque,
    loadFn: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) BackendError!?[]u8,
    saveFn: *const fn (ctx: *anyopaque, bytes: []const u8) BackendError!void,

    pub fn load(self: Backend, allocator: std.mem.Allocator) BackendError!?[]u8 {
        return self.loadFn(self.ctx, allocator);
    }
    pub fn save(self: Backend, bytes: []const u8) BackendError!void {
        return self.saveFn(self.ctx, bytes);
    }
};

// -----------------------------------------------------------------------
// Save/load orchestration
// -----------------------------------------------------------------------

pub const SaveResult = enum { saved, allocation_failed, cache_busy, protection_failed, backend_failed };
pub const LoadResult = enum {
    loaded,
    absent,
    allocation_failed,
    cache_busy,
    protection_failed,
    corrupted,
    unsupported_version,
    backend_failed,
};

fn mapDecodeError(err: SnapshotDecodeError) LoadResult {
    return switch (err) {
        error.OutOfMemory => .allocation_failed,
        error.UnsupportedVersion => .unsupported_version,
        error.SnapshotTooLarge,
        error.Truncated,
        error.TrailingData,
        error.BadMagic,
        error.UnsupportedKind,
        error.TooManyRecords,
        error.MalformedLength,
        error.InvalidHandle,
        error.DecodeFailed,
        => .corrupted,
    };
}

/// Saves every live, non-expired client entry. Clones are taken outside the
/// cache mutex (`cloneLiveForPersistence` already unlocks before returning);
/// all scratch plaintext is wiped on every path, success or failure.
pub fn saveClientCache(
    cache: *session_cache.ClientSessionCache,
    limits: session.Limits,
    protector: Protector,
    backend: Backend,
    now_unix_ms: i64,
) SaveResult {
    var snapshot = cache.cloneLiveForPersistence(cache.allocator, now_unix_ms) catch return .allocation_failed;
    defer {
        for (snapshot.items) |*p| p.deinit();
        snapshot.deinit(cache.allocator);
    }

    const plaintext = encodeClientSnapshotAlloc(cache.allocator, snapshot.items, limits) catch return .allocation_failed;
    defer {
        secrets.secureZero(plaintext);
        cache.allocator.free(plaintext);
    }

    const sealed_len = protector.sealedLen(plaintext.len);
    const sealed_buf = cache.allocator.alloc(u8, sealed_len) catch return .allocation_failed;
    defer {
        secrets.secureZero(sealed_buf);
        cache.allocator.free(sealed_buf);
    }
    const sealed = protector.seal(plaintext, sealed_buf) catch return .protection_failed;

    backend.save(sealed) catch return .backend_failed;
    return .saved;
}

/// Loads, decrypts, decodes into a temporary cache (enforcing `cache`'s
/// current limits and discarding expired entries), and swaps the live cache
/// to the reloaded state only after every step has fully succeeded. On any
/// failure the live cache is left completely untouched.
pub fn loadClientCache(
    cache: *session_cache.ClientSessionCache,
    limits: session.Limits,
    protector: Protector,
    backend: Backend,
    now_unix_ms: i64,
) LoadResult {
    const sealed = (backend.load(cache.allocator) catch return .backend_failed) orelse return .absent;
    defer {
        secrets.secureZero(sealed);
        cache.allocator.free(sealed);
    }

    const plaintext_len = protector.openLen(sealed.len);
    const plaintext_buf = cache.allocator.alloc(u8, plaintext_len) catch return .allocation_failed;
    defer {
        secrets.secureZero(plaintext_buf);
        cache.allocator.free(plaintext_buf);
    }
    const plaintext = protector.open(sealed, plaintext_buf) catch return .protection_failed;

    var entries = decodeClientSnapshotAlloc(cache.allocator, limits, cache.limits.max_entries, plaintext) catch |err| return mapDecodeError(err);
    defer {
        for (entries.items) |*p| p.deinit();
        entries.deinit(cache.allocator);
    }

    var temp = session_cache.ClientSessionCache.init(cache.allocator, cache.limits) catch return .corrupted;
    defer temp.deinit();
    temp.restoreClones(entries.items, now_unix_ms) catch return .allocation_failed;

    cache.mutex.lock();
    defer cache.mutex.unlock();
    for (cache.entries.items) |*e| e.ticket.deinit();
    cache.entries.deinit(cache.allocator);
    cache.entries = temp.entries;
    cache.total_bytes = temp.total_bytes;
    cache.next_insertion_sequence = temp.next_insertion_sequence;
    cache.next_lru_sequence = temp.next_lru_sequence;
    cache.next_entry_id = temp.next_entry_id;
    temp.entries = .empty;
    temp.total_bytes = 0;
    return .loaded;
}

pub fn saveServerCache(
    cache: *session_cache.StatefulServerCache,
    limits: session.Limits,
    protector: Protector,
    backend: Backend,
    now_unix_ms: i64,
) SaveResult {
    var snapshot = cache.cloneLiveForPersistence(cache.allocator, now_unix_ms) catch |err| return switch (err) {
        error.OutOfMemory => .allocation_failed,
        error.CacheBusy => .cache_busy,
    };
    defer {
        for (snapshot.items) |*p| p.deinit();
        snapshot.deinit(cache.allocator);
    }

    const plaintext = encodeServerSnapshotAlloc(cache.allocator, snapshot.items, limits) catch return .allocation_failed;
    defer {
        secrets.secureZero(plaintext);
        cache.allocator.free(plaintext);
    }

    const sealed_len = protector.sealedLen(plaintext.len);
    const sealed_buf = cache.allocator.alloc(u8, sealed_len) catch return .allocation_failed;
    defer {
        secrets.secureZero(sealed_buf);
        cache.allocator.free(sealed_buf);
    }
    const sealed = protector.seal(plaintext, sealed_buf) catch return .protection_failed;

    backend.save(sealed) catch return .backend_failed;
    return .saved;
}

pub fn loadServerCache(
    cache: *session_cache.StatefulServerCache,
    limits: session.Limits,
    protector: Protector,
    backend: Backend,
    now_unix_ms: i64,
) LoadResult {
    const sealed = (backend.load(cache.allocator) catch return .backend_failed) orelse return .absent;
    defer {
        secrets.secureZero(sealed);
        cache.allocator.free(sealed);
    }

    const plaintext_len = protector.openLen(sealed.len);
    const plaintext_buf = cache.allocator.alloc(u8, plaintext_len) catch return .allocation_failed;
    defer {
        secrets.secureZero(plaintext_buf);
        cache.allocator.free(plaintext_buf);
    }
    const plaintext = protector.open(sealed, plaintext_buf) catch return .protection_failed;

    var entries = decodeServerSnapshotAlloc(cache.allocator, limits, cache.limits.max_entries, plaintext) catch |err| return mapDecodeError(err);
    defer {
        for (entries.items) |*p| p.deinit();
        entries.deinit(cache.allocator);
    }

    var temp = session_cache.StatefulServerCache.init(cache.allocator, cache.limits, cache.random) catch return .corrupted;
    defer temp.deinit();
    temp.restoreEntries(entries.items, now_unix_ms) catch return .allocation_failed;

    cache.mutex.lock();
    defer cache.mutex.unlock();

    // Re-check the *live* cache for outstanding leases immediately before
    // swapping it out: a lease acquired after `cloneLiveForPersistence`'s
    // own check (which only guards the snapshot side, taken during save)
    // must not be silently invalidated by a concurrent reload.
    var it = cache.entries.valueIterator();
    while (it.next()) |e| {
        if (e.usage == .single_use and e.active_lease_epoch != null) return .cache_busy;
    }

    var old_it = cache.entries.valueIterator();
    while (old_it.next()) |e| {
        e.state.deinit();
        secrets.secureZero(&e.handle);
    }
    cache.entries.deinit(cache.allocator);
    cache.handle_index.deinit(cache.allocator);
    var old_bucket_it = cache.origin_index.valueIterator();
    while (old_bucket_it.next()) |b| b.deinit(cache.allocator);
    cache.origin_index.deinit(cache.allocator);

    cache.entries = temp.entries;
    cache.handle_index = temp.handle_index;
    cache.origin_index = temp.origin_index;
    cache.total_bytes = temp.total_bytes;
    cache.next_entry_id = temp.next_entry_id;
    cache.next_lru_sequence = temp.next_lru_sequence;
    cache.next_lease_epoch = temp.next_lease_epoch;

    temp.entries = .empty;
    temp.handle_index = .empty;
    temp.origin_index = .empty;
    temp.total_bytes = 0;
    return .loaded;
}

// -----------------------------------------------------------------------
// Test-only protector/backend fixtures
// -----------------------------------------------------------------------

const testing = std.testing;

/// Identity "protection" — NOT encryption. Exists only so this module's own
/// round-trip tests don't need a real AEAD backend; production callers must
/// supply a `Protector` backed by an actual authenticated-encryption
/// integration.
const passthrough_protector: Protector = .{
    .ctx = @ptrCast(@constCast(&passthrough_dummy)),
    .sealedLenFn = passthroughLen,
    .sealFn = passthroughSeal,
    .openLenFn = passthroughLen,
    .openFn = passthroughOpen,
};
var passthrough_dummy: u8 = 0;

fn passthroughLen(_: *anyopaque, len: usize) usize {
    return len;
}
fn passthroughSeal(_: *anyopaque, plaintext: []const u8, out: []u8) ProtectError![]const u8 {
    if (out.len < plaintext.len) return error.ProtectionFailed;
    @memcpy(out[0..plaintext.len], plaintext);
    return out[0..plaintext.len];
}
fn passthroughOpen(_: *anyopaque, sealed: []const u8, out: []u8) ProtectError![]const u8 {
    return passthroughSeal(undefined, sealed, out);
}

/// Single-slot in-memory backend for tests: `save` replaces the whole
/// buffer, `load` returns an owned copy.
const MemoryBackend = struct {
    allocator: std.mem.Allocator,
    bytes: ?[]u8 = null,

    fn deinit(self: *MemoryBackend) void {
        if (self.bytes) |b| {
            secrets.secureZero(b);
            self.allocator.free(b);
        }
        self.bytes = null;
    }

    fn interface(self: *MemoryBackend) Backend {
        return .{ .ctx = self, .loadFn = load, .saveFn = save };
    }

    fn load(ctx: *anyopaque, allocator: std.mem.Allocator) BackendError!?[]u8 {
        const self: *MemoryBackend = @ptrCast(@alignCast(ctx));
        const existing = self.bytes orelse return null;
        const copy = allocator.alloc(u8, existing.len) catch return error.BackendFailed;
        @memcpy(copy, existing);
        return copy;
    }

    fn save(ctx: *anyopaque, bytes: []const u8) BackendError!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ctx));
        const copy = self.allocator.alloc(u8, bytes.len) catch return error.BackendFailed;
        @memcpy(copy, bytes);
        if (self.bytes) |old| {
            secrets.secureZero(old);
            self.allocator.free(old);
        }
        self.bytes = copy;
    }
};

const FailingBackend = struct {
    fn interface() Backend {
        return .{ .ctx = @ptrCast(@constCast(&failing_dummy)), .loadFn = load, .saveFn = save };
    }
    fn load(_: *anyopaque, _: std.mem.Allocator) BackendError!?[]u8 {
        return error.BackendFailed;
    }
    fn save(_: *anyopaque, _: []const u8) BackendError!void {
        return error.BackendFailed;
    }
};
var failing_dummy: u8 = 0;

fn testCommonParams(psk: []const u8, sni: []const u8) session.ResumableSessionCommon.InitParams {
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

fn testClient(allocator: std.mem.Allocator, ticket: []const u8, sni: []const u8) !session.ClientTicketState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, testCommonParams(&([_]u8{0xab} ** 32), sni));
    var state: session.ClientTicketState = .{};
    try state.init(allocator, session.Limits.default, &common, .{
        .ticket = ticket,
        .ticket_age_add = 1,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });
    return state;
}

fn testServerState(allocator: std.mem.Allocator, sni: []const u8) !session.ServerRecoverableState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(allocator, session.Limits.default, testCommonParams(&([_]u8{0xcd} ** 32), sni));
    var state: session.ServerRecoverableState = .{};
    state.init(&common, 7);
    return state;
}

test "client snapshot round trips through encode/decode, including order metadata" {
    const t1 = try testClient(testing.allocator, "persist-ticket-1", "example.test");
    var entries = [_]session_cache.PersistedClientEntry{.{ .ticket = t1, .usage = .single_use, .insertion_sequence = 7, .lru_sequence = 3 }};
    defer for (&entries) |*e| e.deinit();

    const bytes = try encodeClientSnapshotAlloc(testing.allocator, &entries, session.Limits.default);
    defer {
        secrets.secureZero(bytes);
        testing.allocator.free(bytes);
    }

    var decoded = try decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, session_cache.hard_max_entries, bytes);
    defer {
        for (decoded.items) |*p| p.deinit();
        decoded.deinit(testing.allocator);
    }
    try testing.expectEqual(@as(usize, 1), decoded.items.len);
    try testing.expectEqual(session_cache.UsagePolicy.single_use, decoded.items[0].usage);
    try testing.expectEqual(@as(u64, 7), decoded.items[0].insertion_sequence);
    try testing.expectEqual(@as(u64, 3), decoded.items[0].lru_sequence);
    try testing.expectEqualStrings("persist-ticket-1", decoded.items[0].ticket.ticket.slice());
}

test "server snapshot preserves the exact handle and LRU sequence" {
    const s1 = try testServerState(testing.allocator, "example.test");
    var handle: [session_cache.stateful_identity_len]u8 = undefined;
    @memset(&handle, 0xAB);
    @memcpy(handle[0..4], "TDSH");
    std.mem.writeInt(u16, handle[4..6], 1, .big);
    std.mem.writeInt(u16, handle[6..8], 0, .big);
    var entries = [_]session_cache.PersistedServerEntry{.{ .handle = handle, .usage = .reusable, .state = s1, .lru_sequence = 42 }};
    defer for (&entries) |*e| e.deinit();

    const bytes = try encodeServerSnapshotAlloc(testing.allocator, &entries, session.Limits.default);
    defer {
        secrets.secureZero(bytes);
        testing.allocator.free(bytes);
    }
    var decoded = try decodeServerSnapshotAlloc(testing.allocator, session.Limits.default, session_cache.hard_max_entries, bytes);
    defer {
        for (decoded.items) |*p| p.deinit();
        decoded.deinit(testing.allocator);
    }
    try testing.expectEqual(@as(usize, 1), decoded.items.len);
    try testing.expect(std.mem.eql(u8, &handle, &decoded.items[0].handle));
    try testing.expectEqual(@as(u64, 42), decoded.items[0].lru_sequence);
}

test "decode rejects truncated, bad-magic, and unsupported-version snapshots" {
    const t1 = try testClient(testing.allocator, "t", "example.test");
    var entries = [_]session_cache.PersistedClientEntry{.{ .ticket = t1, .usage = .reusable }};
    defer for (&entries) |*e| e.deinit();
    const bytes = try encodeClientSnapshotAlloc(testing.allocator, &entries, session.Limits.default);
    defer {
        secrets.secureZero(bytes);
        testing.allocator.free(bytes);
    }

    try testing.expectError(error.Truncated, decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, session_cache.hard_max_entries, bytes[0..5]));

    const bad_magic = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(bad_magic);
    bad_magic[0] = 'X';
    try testing.expectError(error.BadMagic, decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, session_cache.hard_max_entries, bad_magic));

    const bad_version = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(bad_version);
    bad_version[4] = 99;
    try testing.expectError(error.UnsupportedVersion, decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, session_cache.hard_max_entries, bad_version));

    const truncated_record = try testing.allocator.dupe(u8, bytes[0 .. bytes.len - 1]);
    defer testing.allocator.free(truncated_record);
    try testing.expectError(error.Truncated, decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, session_cache.hard_max_entries, truncated_record));
}

test "decode rejects a declared record count over the target cache's entry limit before allocating" {
    const t1 = try testClient(testing.allocator, "t", "example.test");
    var entries = [_]session_cache.PersistedClientEntry{.{ .ticket = t1, .usage = .reusable }};
    defer for (&entries) |*e| e.deinit();
    const bytes = try encodeClientSnapshotAlloc(testing.allocator, &entries, session.Limits.default);
    defer {
        secrets.secureZero(bytes);
        testing.allocator.free(bytes);
    }

    // A single real record, but a corrupted count claiming ~4 billion.
    const bombed = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(bombed);
    std.mem.writeInt(u32, bombed[6..10], 0xFFFF_FFF0, .big);
    try testing.expectError(error.TooManyRecords, decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, 8, bombed));
}

test "decode rejects trailing bytes after the declared record count, even with a zero count" {
    var zero_count: [header_len + 4]u8 = undefined;
    writeHeader(&zero_count, .client, 0);
    @memset(zero_count[header_len..], 0xAA);
    try testing.expectError(error.TrailingData, decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, session_cache.hard_max_entries, &zero_count));

    const t1 = try testClient(testing.allocator, "t", "example.test");
    var entries = [_]session_cache.PersistedClientEntry{.{ .ticket = t1, .usage = .reusable }};
    defer for (&entries) |*e| e.deinit();
    const bytes = try encodeClientSnapshotAlloc(testing.allocator, &entries, session.Limits.default);
    defer {
        secrets.secureZero(bytes);
        testing.allocator.free(bytes);
    }
    var with_trailer = try testing.allocator.alloc(u8, bytes.len + 3);
    defer testing.allocator.free(with_trailer);
    @memcpy(with_trailer[0..bytes.len], bytes);
    @memset(with_trailer[bytes.len..], 0x99);
    try testing.expectError(error.TrailingData, decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, session_cache.hard_max_entries, with_trailer));
}

test "decode rejects a server handle with a non-zero reserved field or wrong magic/version" {
    const s1 = try testServerState(testing.allocator, "example.test");
    var handle: [session_cache.stateful_identity_len]u8 = undefined;
    @memcpy(handle[0..4], "TDSH");
    std.mem.writeInt(u16, handle[4..6], 1, .big);
    std.mem.writeInt(u16, handle[6..8], 1, .big); // non-zero reserved
    var entries = [_]session_cache.PersistedServerEntry{.{ .handle = handle, .usage = .reusable, .state = s1 }};
    defer for (&entries) |*e| e.deinit();
    const bytes = try encodeServerSnapshotAlloc(testing.allocator, &entries, session.Limits.default);
    defer {
        secrets.secureZero(bytes);
        testing.allocator.free(bytes);
    }
    try testing.expectError(error.InvalidHandle, decodeServerSnapshotAlloc(testing.allocator, session.Limits.default, session_cache.hard_max_entries, bytes));
}

test "decode rejects a plaintext buffer over the hard snapshot size ceiling before parsing" {
    const oversized = try testing.allocator.alloc(u8, hard_max_snapshot_bytes + 1);
    defer testing.allocator.free(oversized);
    // Header/magic left as zeroed garbage: the size gate must reject this
    // before `readHeader` ever inspects the magic/version/count fields.
    try testing.expectError(
        error.SnapshotTooLarge,
        decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, session_cache.hard_max_entries, oversized),
    );
}

test "client cache and server cache both refuse a corrupted payload without touching the live cache" {
    var cache = try session_cache.ClientSessionCache.init(testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "still-here", "example.test");
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();

    var backend = MemoryBackend{ .allocator = testing.allocator };
    defer backend.deinit();
    backend.bytes = try testing.allocator.dupe(u8, "not a valid snapshot at all");

    try testing.expectEqual(LoadResult.corrupted, loadClientCache(&cache, session.Limits.default, passthrough_protector, backend.interface(), 1));
    try testing.expectEqual(@as(usize, 1), cache.count());
}

test "loadClientCache reports absent without touching the live cache" {
    var cache = try session_cache.ClientSessionCache.init(testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "still-here", "example.test");
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();

    var backend = MemoryBackend{ .allocator = testing.allocator };
    defer backend.deinit();
    try testing.expectEqual(LoadResult.absent, loadClientCache(&cache, session.Limits.default, passthrough_protector, backend.interface(), 1));
    try testing.expectEqual(@as(usize, 1), cache.count());
}

test "loadClientCache backend failure leaves the live cache untouched" {
    var cache = try session_cache.ClientSessionCache.init(testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "still-here", "example.test");
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();

    try testing.expectEqual(LoadResult.backend_failed, loadClientCache(&cache, session.Limits.default, passthrough_protector, FailingBackend.interface(), 1));
    try testing.expectEqual(@as(usize, 1), cache.count());
}

test "saveClientCache and loadClientCache round trip through an in-memory backend" {
    var cache = try session_cache.ClientSessionCache.init(testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "round-trip-ticket", "example.test");
    _ = cache.storeClone(&t1, 0, .single_use);
    t1.deinit();

    var backend = MemoryBackend{ .allocator = testing.allocator };
    defer backend.deinit();

    try testing.expectEqual(SaveResult.saved, saveClientCache(&cache, session.Limits.default, passthrough_protector, backend.interface(), 1));

    var restored = try session_cache.ClientSessionCache.init(testing.allocator, session_cache.Limits.client_default);
    defer restored.deinit();
    try testing.expectEqual(LoadResult.loaded, loadClientCache(&restored, session.Limits.default, passthrough_protector, backend.interface(), 2));
    try testing.expectEqual(@as(usize, 1), restored.count());
}

test "loadClientCache discards expired entries and enforces current limits on reload" {
    var cache = try session_cache.ClientSessionCache.init(testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "expiring-ticket", "example.test");
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();

    var backend = MemoryBackend{ .allocator = testing.allocator };
    defer backend.deinit();
    try testing.expectEqual(SaveResult.saved, saveClientCache(&cache, session.Limits.default, passthrough_protector, backend.interface(), 1));

    var restored = try session_cache.ClientSessionCache.init(testing.allocator, session_cache.Limits.client_default);
    defer restored.deinit();
    // Reload far past the 1000s lifetime used by `testCommonParams`.
    try testing.expectEqual(LoadResult.loaded, loadClientCache(&restored, session.Limits.default, passthrough_protector, backend.interface(), 2_000_000));
    try testing.expectEqual(@as(usize, 0), restored.count());
}

test "saveServerCache refuses a leased single-use entry and succeeds once it is committed" {
    var cache = try session_cache.StatefulServerCache.init(testing.allocator, session_cache.Limits.stateful_server_default, session_cache.system_random_source);
    defer cache.deinit();
    var s1 = try testServerState(testing.allocator, "example.test");
    var handle: [session_cache.stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .single_use, &handle);

    var backend = MemoryBackend{ .allocator = testing.allocator };
    defer backend.deinit();

    var leased = cache.resolveLease(&handle, 1);
    try testing.expectEqual(SaveResult.cache_busy, saveServerCache(&cache, session.Limits.default, passthrough_protector, backend.interface(), 1));
    try testing.expect(backend.bytes == null);

    switch (leased) {
        .hit => |*h| h.lease.commit(),
        else => try testing.expect(false),
    }
    leased.deinit();

    try testing.expectEqual(SaveResult.saved, saveServerCache(&cache, session.Limits.default, passthrough_protector, backend.interface(), 2));
}

test "loadServerCache refuses to replace a live cache with an outstanding lease" {
    var cache = try session_cache.StatefulServerCache.init(testing.allocator, session_cache.Limits.stateful_server_default, session_cache.system_random_source);
    defer cache.deinit();
    var s1 = try testServerState(testing.allocator, "example.test");
    var handle: [session_cache.stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .single_use, &handle);

    var backend = MemoryBackend{ .allocator = testing.allocator };
    defer backend.deinit();
    backend.bytes = try encodeServerSnapshotAlloc(testing.allocator, &.{}, session.Limits.default);
    var header_buf = backend.bytes.?;
    writeHeader(header_buf[0..header_len], .server, 0);

    var leased = cache.resolveLease(&handle, 1);
    try testing.expectEqual(LoadResult.cache_busy, loadServerCache(&cache, session.Limits.default, passthrough_protector, backend.interface(), 2));
    try testing.expectEqual(@as(usize, 1), cache.count());

    switch (leased) {
        .hit => |*h| h.lease.release(),
        else => try testing.expect(false),
    }
    leased.deinit();
}

test "saveServerCache and loadServerCache round trip and preserve the handle" {
    var cache = try session_cache.StatefulServerCache.init(testing.allocator, session_cache.Limits.stateful_server_default, session_cache.system_random_source);
    defer cache.deinit();
    var s1 = try testServerState(testing.allocator, "example.test");
    var handle: [session_cache.stateful_identity_len]u8 = undefined;
    _ = cache.insertMove(&s1, 0, .reusable, &handle);

    var backend = MemoryBackend{ .allocator = testing.allocator };
    defer backend.deinit();
    try testing.expectEqual(SaveResult.saved, saveServerCache(&cache, session.Limits.default, passthrough_protector, backend.interface(), 1));

    var restored = try session_cache.StatefulServerCache.init(testing.allocator, session_cache.Limits.stateful_server_default, session_cache.system_random_source);
    defer restored.deinit();
    try testing.expectEqual(LoadResult.loaded, loadServerCache(&restored, session.Limits.default, passthrough_protector, backend.interface(), 2));

    var hit = restored.resolveLease(&handle, 2);
    defer hit.deinit();
    try testing.expect(hit == .hit);
}

test "restore allocation failure aborts the load atomically, leaving the live cache untouched" {
    var backing: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);

    var cache = try session_cache.ClientSessionCache.init(testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "still-here", "example.test");
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();

    var to_persist = try testClient(testing.allocator, "incoming", "example.test");
    var entries = [_]session_cache.PersistedClientEntry{.{ .ticket = to_persist, .usage = .reusable }};
    const bytes = try encodeClientSnapshotAlloc(testing.allocator, &entries, session.Limits.default);
    defer {
        secrets.secureZero(bytes);
        testing.allocator.free(bytes);
    }
    to_persist.deinit();

    var backend = MemoryBackend{ .allocator = fba.allocator() };
    backend.bytes = try fba.allocator().dupe(u8, bytes);

    var failing = std.testing.FailingAllocator.init(fba.allocator(), .{ .fail_index = 0 });
    var failing_cache = session_cache.ClientSessionCache{ .allocator = failing.allocator(), .limits = session_cache.Limits.client_default };
    defer failing_cache.entries.deinit(fba.allocator());
    const result = loadClientCache(&failing_cache, session.Limits.default, passthrough_protector, backend.interface(), 1);
    // Whichever step the injected allocation failure surfaces at, the load
    // must never report `.loaded` and must never populate the cache.
    try testing.expect(result != .loaded);
    try testing.expectEqual(@as(usize, 0), failing_cache.entries.items.len);

    // The unrelated live `cache` must be untouched regardless.
    try testing.expectEqual(@as(usize, 1), cache.count());
}

test "protection failure during save and load is reported without corrupting state" {
    const FailingProtector = struct {
        fn interface() Protector {
            return .{ .ctx = @ptrCast(@constCast(&dummy)), .sealedLenFn = len, .sealFn = seal, .openLenFn = len, .openFn = open };
        }
        var dummy: u8 = 0;
        fn len(_: *anyopaque, l: usize) usize {
            return l;
        }
        fn seal(_: *anyopaque, _: []const u8, _: []u8) ProtectError![]const u8 {
            return error.ProtectionFailed;
        }
        fn open(_: *anyopaque, _: []const u8, _: []u8) ProtectError![]const u8 {
            return error.ProtectionFailed;
        }
    };

    var cache = try session_cache.ClientSessionCache.init(testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    var t1 = try testClient(testing.allocator, "still-here", "example.test");
    _ = cache.storeClone(&t1, 0, .reusable);
    t1.deinit();

    var backend = MemoryBackend{ .allocator = testing.allocator };
    defer backend.deinit();
    try testing.expectEqual(SaveResult.protection_failed, saveClientCache(&cache, session.Limits.default, FailingProtector.interface(), backend.interface(), 1));
    try testing.expect(backend.bytes == null);

    try testing.expectEqual(SaveResult.saved, saveClientCache(&cache, session.Limits.default, passthrough_protector, backend.interface(), 1));
    try testing.expectEqual(LoadResult.protection_failed, loadClientCache(&cache, session.Limits.default, FailingProtector.interface(), backend.interface(), 2));
    try testing.expectEqual(@as(usize, 1), cache.count());
}
