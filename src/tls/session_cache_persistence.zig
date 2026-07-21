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
//! unsupported-version data) never invalidates the live in-memory cache and
//! never propagates as a TLS-connection-affecting error — every entry point
//! here returns a plain `SaveResult` / `LoadResult`.

const std = @import("std");
const crypto = @import("crypto");
const session = @import("session.zig");
const session_cache = @import("session_cache.zig");

const secrets = crypto.secrets;

pub const snapshot_magic = [4]u8{ 'T', 'D', 'P', 'S' };
pub const snapshot_version: u8 = 1;
const header_len: usize = 4 + 1 + 1 + 4;

pub const SnapshotKind = enum(u8) { client = 1, server = 2 };

pub const SnapshotEncodeError = session.EncodeError || error{OutOfMemory};
pub const SnapshotDecodeError = error{
    OutOfMemory,
    Truncated,
    BadMagic,
    UnsupportedVersion,
    UnsupportedKind,
    MalformedLength,
    DecodeFailed,
};

// -----------------------------------------------------------------------
// Snapshot framing: `magic(4) | version(1) | kind(1) | count(4) | records`.
//
// Client record: `usage(1) | len(4) | session.encodeClient bytes(len)`.
// Server record: `usage(1) | handle(40) | len(4) | session.encodeServer
// bytes(len)`.
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
        total += 1 + 4 + encoded_len;
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
        total += 1 + session_cache.stateful_identity_len + 4 + encoded_len;
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
        const encoded_len = try session.serverEncodedLenWithLimits(&e.state, limits);
        std.mem.writeInt(u32, buf[pos..][0..4], @intCast(encoded_len), .big);
        pos += 4;
        _ = try session.encodeServer(&e.state, limits, buf[pos .. pos + encoded_len]);
        pos += encoded_len;
    }
    std.debug.assert(pos == total);
    return buf;
}

pub fn decodeClientSnapshotAlloc(
    allocator: std.mem.Allocator,
    limits: session.Limits,
    bytes: []const u8,
) SnapshotDecodeError!std.ArrayListUnmanaged(session_cache.PersistedClientEntry) {
    const header = try readHeader(bytes);
    if (header.kind != .client) return error.UnsupportedKind;

    var out: std.ArrayListUnmanaged(session_cache.PersistedClientEntry) = .empty;
    errdefer {
        for (out.items) |*p| p.deinit();
        out.deinit(allocator);
    }
    out.ensureTotalCapacityPrecise(allocator, header.count) catch return error.OutOfMemory;

    var rest = header.body;
    var i: u32 = 0;
    while (i < header.count) : (i += 1) {
        if (rest.len < 1 + 4) return error.Truncated;
        const usage = std.enums.fromInt(session_cache.UsagePolicy, rest[0]) orelse return error.MalformedLength;
        const len = std.mem.readInt(u32, rest[1..5], .big);
        rest = rest[5..];
        if (rest.len < len) return error.Truncated;
        const record_bytes = rest[0..len];
        rest = rest[len..];

        var decoded = session.decode(allocator, limits, record_bytes) catch return error.DecodeFailed;
        switch (decoded) {
            .client => |c| out.appendAssumeCapacity(.{ .ticket = c, .usage = usage }),
            .server => {
                decoded.deinit();
                return error.UnsupportedKind;
            },
        }
    }
    return out;
}

pub fn decodeServerSnapshotAlloc(
    allocator: std.mem.Allocator,
    limits: session.Limits,
    bytes: []const u8,
) SnapshotDecodeError!std.ArrayListUnmanaged(session_cache.PersistedServerEntry) {
    const header = try readHeader(bytes);
    if (header.kind != .server) return error.UnsupportedKind;

    var out: std.ArrayListUnmanaged(session_cache.PersistedServerEntry) = .empty;
    errdefer {
        for (out.items) |*p| p.deinit();
        out.deinit(allocator);
    }
    out.ensureTotalCapacityPrecise(allocator, header.count) catch return error.OutOfMemory;

    var rest = header.body;
    var i: u32 = 0;
    while (i < header.count) : (i += 1) {
        if (rest.len < 1 + session_cache.stateful_identity_len + 4) return error.Truncated;
        const usage = std.enums.fromInt(session_cache.UsagePolicy, rest[0]) orelse return error.MalformedLength;
        var handle: [session_cache.stateful_identity_len]u8 = undefined;
        @memcpy(&handle, rest[1 .. 1 + session_cache.stateful_identity_len]);
        const len_offset = 1 + session_cache.stateful_identity_len;
        const len = std.mem.readInt(u32, rest[len_offset..][0..4], .big);
        rest = rest[len_offset + 4 ..];
        if (rest.len < len) return error.Truncated;
        const record_bytes = rest[0..len];
        rest = rest[len..];

        var decoded = session.decode(allocator, limits, record_bytes) catch return error.DecodeFailed;
        switch (decoded) {
            .server => |s| out.appendAssumeCapacity(.{ .handle = handle, .usage = usage, .state = s }),
            .client => {
                decoded.deinit();
                return error.UnsupportedKind;
            },
        }
    }
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

pub const SaveResult = enum { saved, allocation_failed, protection_failed, backend_failed };
pub const LoadResult = enum {
    loaded,
    absent,
    allocation_failed,
    protection_failed,
    corrupted,
    unsupported_version,
    backend_failed,
};

fn mapDecodeError(err: SnapshotDecodeError) LoadResult {
    return switch (err) {
        error.OutOfMemory => .allocation_failed,
        error.UnsupportedVersion => .unsupported_version,
        error.Truncated, error.BadMagic, error.UnsupportedKind, error.MalformedLength, error.DecodeFailed => .corrupted,
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

    var entries = decodeClientSnapshotAlloc(cache.allocator, limits, plaintext) catch |err| return mapDecodeError(err);
    defer {
        for (entries.items) |*p| p.deinit();
        entries.deinit(cache.allocator);
    }

    var temp = session_cache.ClientSessionCache.init(cache.allocator, cache.limits) catch return .corrupted;
    defer temp.deinit();
    temp.restoreClones(entries.items, now_unix_ms);

    cache.mutex.lock();
    defer cache.mutex.unlock();
    for (cache.entries.items) |*e| e.ticket.deinit();
    cache.entries.deinit(cache.allocator);
    cache.entries = temp.entries;
    cache.total_bytes = temp.total_bytes;
    cache.next_sequence = temp.next_sequence;
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
    var snapshot = cache.cloneLiveForPersistence(cache.allocator, now_unix_ms) catch return .allocation_failed;
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

    var entries = decodeServerSnapshotAlloc(cache.allocator, limits, plaintext) catch |err| return mapDecodeError(err);
    defer {
        for (entries.items) |*p| p.deinit();
        entries.deinit(cache.allocator);
    }

    var temp = session_cache.StatefulServerCache.init(cache.allocator, cache.limits, cache.random) catch return .corrupted;
    defer temp.deinit();
    temp.restoreEntries(entries.items, now_unix_ms);

    cache.mutex.lock();
    defer cache.mutex.unlock();
    for (cache.entries.items) |*e| {
        e.state.deinit();
        secrets.secureZero(&e.handle);
    }
    cache.entries.deinit(cache.allocator);
    cache.entries = temp.entries;
    cache.total_bytes = temp.total_bytes;
    cache.next_sequence = temp.next_sequence;
    cache.next_generation = temp.next_generation;
    temp.entries = .empty;
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

test "client snapshot round trips through encode/decode" {
    const t1 = try testClient(testing.allocator, "persist-ticket-1", "example.test");
    var entries = [_]session_cache.PersistedClientEntry{.{ .ticket = t1, .usage = .single_use }};
    defer for (&entries) |*e| e.deinit();

    const bytes = try encodeClientSnapshotAlloc(testing.allocator, &entries, session.Limits.default);
    defer {
        secrets.secureZero(bytes);
        testing.allocator.free(bytes);
    }

    var decoded = try decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, bytes);
    defer {
        for (decoded.items) |*p| p.deinit();
        decoded.deinit(testing.allocator);
    }
    try testing.expectEqual(@as(usize, 1), decoded.items.len);
    try testing.expectEqual(session_cache.UsagePolicy.single_use, decoded.items[0].usage);
    try testing.expectEqualStrings("persist-ticket-1", decoded.items[0].ticket.ticket.slice());
}

test "server snapshot preserves the exact handle" {
    const s1 = try testServerState(testing.allocator, "example.test");
    var handle: [session_cache.stateful_identity_len]u8 = undefined;
    @memset(&handle, 0xAB);
    var entries = [_]session_cache.PersistedServerEntry{.{ .handle = handle, .usage = .reusable, .state = s1 }};
    defer for (&entries) |*e| e.deinit();

    const bytes = try encodeServerSnapshotAlloc(testing.allocator, &entries, session.Limits.default);
    defer {
        secrets.secureZero(bytes);
        testing.allocator.free(bytes);
    }
    var decoded = try decodeServerSnapshotAlloc(testing.allocator, session.Limits.default, bytes);
    defer {
        for (decoded.items) |*p| p.deinit();
        decoded.deinit(testing.allocator);
    }
    try testing.expectEqual(@as(usize, 1), decoded.items.len);
    try testing.expect(std.mem.eql(u8, &handle, &decoded.items[0].handle));
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

    try testing.expectError(error.Truncated, decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, bytes[0..5]));

    var bad_magic = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(bad_magic);
    bad_magic[0] = 'X';
    try testing.expectError(error.BadMagic, decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, bad_magic));

    var bad_version = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(bad_version);
    bad_version[4] = 99;
    try testing.expectError(error.UnsupportedVersion, decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, bad_version));

    const truncated_record = try testing.allocator.dupe(u8, bytes[0 .. bytes.len - 1]);
    defer testing.allocator.free(truncated_record);
    try testing.expectError(error.Truncated, decodeClientSnapshotAlloc(testing.allocator, session.Limits.default, truncated_record));
}

test "decode rejects a client snapshot presented as a server snapshot" {
    const t1 = try testClient(testing.allocator, "t", "example.test");
    var entries = [_]session_cache.PersistedClientEntry{.{ .ticket = t1, .usage = .reusable }};
    defer for (&entries) |*e| e.deinit();
    const bytes = try encodeClientSnapshotAlloc(testing.allocator, &entries, session.Limits.default);
    defer {
        secrets.secureZero(bytes);
        testing.allocator.free(bytes);
    }
    try testing.expectError(error.UnsupportedKind, decodeServerSnapshotAlloc(testing.allocator, session.Limits.default, bytes));
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

test "loadClientCache corrupted payload leaves the live cache untouched" {
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

    var hit = restored.lookupLease(&handle, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .server_name = "example.test",
        .application_protocol = "h3",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf-der"),
    }, 2);
    defer hit.deinit();
    try testing.expect(hit == .hit);
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
