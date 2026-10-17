const std = @import("std");
const credentials = @import("credentials.zig");
const secrets = @import("crypto_secrets");
const crypto_provider_pkg = @import("crypto").provider;

pub const LoadedIdentity = struct {
    allocator: std.mem.Allocator,
    cert_chain: [][]u8,
    key_der: []u8,
    identity: credentials.Identity,

    pub fn deinit(self: *LoadedIdentity) void {
        secrets.secureZero(std.mem.asBytes(&self.identity.key));
        for (self.cert_chain) |cert_der| {
            if (cert_der.len > 0) self.allocator.free(cert_der);
        }
        if (self.cert_chain.len > 0) self.allocator.free(self.cert_chain);
        secrets.secureZeroAndFree(self.allocator, self.key_der);
        self.* = undefined;
    }
};

/// `entropy` is required for RSA private keys: `credentials.Identity
/// .initPkcs8WithEntropy` draws its `p`/`q` primality-check Miller-Rabin
/// witnesses from it (see that function's doc comment). Ed25519/ECDSA-P256
/// keys never touch it, but the key type isn't known until parsing is
/// underway, so every caller must supply one — production callers pass the
/// real OS entropy source (`production_crypto.OsEntropy`).
pub fn loadIdentity(
    allocator: std.mem.Allocator,
    cert_path: []const u8,
    key_path: []const u8,
    entropy: crypto_provider_pkg.Entropy,
) !LoadedIdentity {
    const cert_raw = try readSmallFile(allocator, cert_path);
    defer secrets.secureZeroAndFree(allocator, cert_raw);
    const key_raw = try readSmallFile(allocator, key_path);
    defer secrets.secureZeroAndFree(allocator, key_raw);

    return loadIdentityFromBytes(allocator, cert_raw, key_raw, entropy);
}

/// Same as `loadIdentity`, but from owned-in-memory PEM or DER bytes rather
/// than file paths — the entry point for credential material a caller has
/// already produced/verified in memory (e.g. an issued ACME chain and leaf
/// key) rather than read from disk. Neither `cert_bytes` nor `key_bytes` is
/// retained or mutated; both may be freed by the caller as soon as this
/// returns.
pub fn loadIdentityFromBytes(
    allocator: std.mem.Allocator,
    cert_bytes: []const u8,
    key_bytes: []const u8,
    entropy: crypto_provider_pkg.Entropy,
) !LoadedIdentity {
    const cert_chain = try certChainFromPemOrDer(allocator, cert_bytes);
    errdefer freeCertChain(allocator, cert_chain);
    const key_der = try keyDerFromPemOrDer(allocator, key_bytes);
    errdefer secrets.secureZeroAndFree(allocator, key_der);

    if (cert_chain.len == 0) return error.PemBlockNotFound;
    const identity = try credentials.Identity.initPkcs8WithEntropy(cert_chain[0], key_der, entropy);
    return .{
        .allocator = allocator,
        .cert_chain = cert_chain,
        .key_der = key_der,
        .identity = identity,
    };
}

const read_small_file_max_len = 256 * 1024;

/// Reads `path` into a freshly allocated, exactly-sized buffer, bounded by
/// `read_small_file_max_len`. The file may contain private-key bytes, so
/// every intermediate allocation this function creates — not just the one it
/// finally returns — must be wiped before it is freed. `std.ArrayList`'s
/// grow-and-copy and `toOwnedSlice`'s final move both free a retired
/// backing allocation through `Allocator.free`, which only `@memset`s it
/// with `undefined` (a no-op in ReleaseFast); using one for accumulation
/// would leave earlier chunks of the file recoverable in freed heap memory.
/// This manages its own growth instead, so every allocation this function
/// retires is explicitly zeroed via `secrets.secureZeroAndFree` first.
pub fn readSmallFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{}, 0);
    defer _ = std.c.close(fd);

    var capacity: usize = 4096;
    var buf = try allocator.alloc(u8, capacity);
    errdefer secrets.secureZeroAndFree(allocator, buf);
    var len: usize = 0;
    while (true) {
        if (len == capacity) {
            if (capacity >= read_small_file_max_len) {
                // Confirm there is really more data before failing: the
                // file may be exactly `read_small_file_max_len` bytes, in
                // which case the next read legitimately returns EOF.
                var probe: [1]u8 = undefined;
                defer secrets.secureZero(&probe);
                if (try std.posix.read(fd, &probe) == 0) break;
                return error.FileTooBig;
            }
            const grown = @min(capacity * 2, read_small_file_max_len);
            buf = try growSecretBuffer(allocator, buf, grown);
            capacity = grown;
        }
        const n = try std.posix.read(fd, buf[len..capacity]);
        if (n == 0) break;
        len += n;
    }
    return shrinkSecretBufferToExact(allocator, buf, len);
}

/// Grows `buf` to `new_capacity`, in place when the allocator permits it, or
/// via copy-then-wipe-then-free of the retired allocation otherwise.
fn growSecretBuffer(allocator: std.mem.Allocator, buf: []u8, new_capacity: usize) ![]u8 {
    if (allocator.resize(buf, new_capacity)) return buf.ptr[0..new_capacity];
    const grown = try allocator.alloc(u8, new_capacity);
    @memcpy(grown[0..buf.len], buf);
    secrets.secureZeroAndFree(allocator, buf);
    return grown;
}

/// Shrinks `buf` down to its live `len` bytes, in place when the allocator
/// permits it, or via copy-then-wipe-then-free of the retired allocation
/// otherwise. This is the buffer's final owner-to-owner transfer, mirroring
/// what `toOwnedSlice` would otherwise do without wiping.
fn shrinkSecretBufferToExact(allocator: std.mem.Allocator, buf: []u8, len: usize) ![]u8 {
    if (buf.len == len) return buf;
    if (len == 0) {
        secrets.secureZeroAndFree(allocator, buf);
        return &.{};
    }
    if (allocator.resize(buf, len)) return buf.ptr[0..len];
    const exact = try allocator.alloc(u8, len);
    @memcpy(exact, buf[0..len]);
    secrets.secureZeroAndFree(allocator, buf);
    return exact;
}

pub fn derFromPemOrDer(allocator: std.mem.Allocator, raw: []const u8, block_name: []const u8) ![]u8 {
    if (raw.len > 0 and raw[0] == 0x30) return allocator.dupe(u8, raw);
    return pemBlockToDer(allocator, raw, block_name);
}

pub fn certChainFromPemOrDer(allocator: std.mem.Allocator, raw: []const u8) ![][]u8 {
    if (raw.len > 0 and raw[0] == 0x30) {
        const chain = try allocator.alloc([]u8, 1);
        errdefer allocator.free(chain);
        chain[0] = try allocator.dupe(u8, raw);
        return chain;
    }
    return pemBlocksToDer(allocator, raw, "CERTIFICATE");
}

pub fn keyDerFromPemOrDer(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (raw.len > 0 and raw[0] == 0x30) return allocator.dupe(u8, raw);
    // Only a genuinely absent "PRIVATE KEY" block justifies retrying as the
    // legacy SEC1 "EC PRIVATE KEY" label -- any other failure (malformed
    // block, bad base64, or a real allocation failure) must propagate as
    // itself rather than being discarded in favor of a doomed second guess.
    return pemBlockToDer(allocator, raw, "PRIVATE KEY") catch |err| switch (err) {
        error.PemBlockNotFound => pemBlockToDer(allocator, raw, "EC PRIVATE KEY"),
        else => err,
    };
}

pub fn pemBlockToDer(allocator: std.mem.Allocator, pem: []const u8, block_name: []const u8) ![]u8 {
    var next: usize = 0;
    return pemBlockToDerFrom(allocator, pem, block_name, &next) catch |err| switch (err) {
        error.NoMorePemBlocks => error.PemBlockNotFound,
        else => err,
    };
}

pub fn pemBlocksToDer(allocator: std.mem.Allocator, pem: []const u8, block_name: []const u8) ![][]u8 {
    var chain: std.ArrayList([]u8) = .empty;
    errdefer {
        for (chain.items) |der| allocator.free(der);
        chain.deinit(allocator);
    }

    var next: usize = 0;
    while (pemBlockToDerFrom(allocator, pem, block_name, &next)) |der| {
        chain.append(allocator, der) catch |err| {
            allocator.free(der);
            return err;
        };
    } else |err| switch (err) {
        error.NoMorePemBlocks => {},
        else => return err,
    }
    if (chain.items.len == 0) return error.PemBlockNotFound;
    return chain.toOwnedSlice(allocator);
}

fn pemBlockToDerFrom(allocator: std.mem.Allocator, pem: []const u8, block_name: []const u8, next: *usize) ![]u8 {
    var begin_buf: [64]u8 = undefined;
    var end_buf: [64]u8 = undefined;
    const begin = try std.fmt.bufPrint(&begin_buf, "-----BEGIN {s}-----", .{block_name});
    const end = try std.fmt.bufPrint(&end_buf, "-----END {s}-----", .{block_name});
    const begin_at = std.mem.findPos(u8, pem, next.*, begin) orelse return error.NoMorePemBlocks;
    const body_start = begin_at + begin.len;
    const end_at = std.mem.findPos(u8, pem, body_start, end) orelse return error.MalformedPemBlock;
    next.* = end_at + end.len;
    const body = pem[body_start..end_at];

    var compact = try allocator.alloc(u8, body.len);
    defer secrets.secureZeroAndFree(allocator, compact);
    var len: usize = 0;
    for (body) |char| {
        if (char == '\n' or char == '\r' or char == ' ' or char == '\t') continue;
        compact[len] = char;
        len += 1;
    }
    const decoder = std.base64.standard.Decoder;
    const der_len = try decoder.calcSizeForSlice(compact[0..len]);
    const der = try allocator.alloc(u8, der_len);
    errdefer secrets.secureZeroAndFree(allocator, der);
    try decoder.decode(der, compact[0..len]);
    return der;
}

fn freeCertChain(allocator: std.mem.Allocator, chain: [][]u8) void {
    for (chain) |cert_der| allocator.free(cert_der);
    allocator.free(chain);
}

test "PEM block decoding extracts DER bytes" {
    const allocator = std.testing.allocator;
    const pem = "junk\n-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n";
    const der = try pemBlockToDer(allocator, pem, "CERTIFICATE");
    defer allocator.free(der);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 }, der);
    try std.testing.expectError(error.PemBlockNotFound, pemBlockToDer(allocator, pem, "PRIVATE KEY"));
}

test "PEM certificate chain decoding preserves every certificate block in order" {
    const allocator = std.testing.allocator;
    const pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "MAMCAQA=\n" ++
        "-----END CERTIFICATE-----\n" ++
        "ignored text\n" ++
        "-----BEGIN CERTIFICATE-----\n" ++
        "MAMCAQE=\n" ++
        "-----END CERTIFICATE-----\n";
    const chain = try certChainFromPemOrDer(allocator, pem);
    defer freeCertChain(allocator, chain);

    try std.testing.expectEqual(@as(usize, 2), chain.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 }, chain[0]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x01 }, chain[1]);
}

/// Test-only allocator wrapper that always refuses in-place `resize`,
/// forcing every grow (and the final shrink-to-exact) through the
/// alloc-copy-free path. Real allocators sometimes resize in place, which
/// would let a broken implementation skip the wipe-before-free step
/// entirely and still pass; this proves the wipe happens even when a move
/// is unavoidable.
const ForceMoveAllocator = struct {
    backing: std.mem.Allocator,
    moved_allocations: usize = 0,
    saw_nonzero_at_free: bool = false,

    fn allocator(self: *ForceMoveAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = vtableAlloc,
        .resize = vtableResize,
        .remap = vtableRemap,
        .free = vtableFree,
    };

    fn vtableAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *ForceMoveAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.rawAlloc(len, alignment, ret_addr);
    }

    fn vtableResize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        const self: *ForceMoveAllocator = @ptrCast(@alignCast(ctx));
        self.moved_allocations += 1;
        return false;
    }

    fn vtableRemap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        _ = ctx;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        return null;
    }

    fn vtableFree(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *ForceMoveAllocator = @ptrCast(@alignCast(ctx));
        for (memory) |b| {
            if (b != 0) {
                self.saw_nonzero_at_free = true;
                break;
            }
        }
        self.backing.rawFree(memory, alignment, ret_addr);
    }
};

test "readSmallFile scrubs every allocation retired during growth, not just the final one" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Larger than the function's initial 4096-byte capacity so at least one
    // grow-and-copy cycle happens; well under the size cap so the read
    // succeeds and the buffer's final shrink-to-exact also moves.
    const data = try std.testing.allocator.alloc(u8, 20 * 1024);
    defer std.testing.allocator.free(data);
    @memset(data, 0xcd);
    try tmp.dir.writeFile(io, .{ .sub_path = "medium.key", .data = data });

    const path = try tmp.dir.realPathFileAlloc(io, "medium.key", std.testing.allocator);
    defer std.testing.allocator.free(path);

    var forced = ForceMoveAllocator{ .backing = std.testing.allocator };
    const out = try readSmallFile(forced.allocator(), path);
    defer std.testing.allocator.free(out);

    try std.testing.expectEqualSlices(u8, data, out);
    // Every grow step and the final shrink asked to resize in place and was
    // refused, so this only passes if the wipe-then-copy-then-free path ran
    // more than once.
    try std.testing.expect(forced.moved_allocations > 1);
    try std.testing.expect(!forced.saw_nonzero_at_free);
}

test "readSmallFile wipes the accumulated buffer when the size limit trips" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const data = try std.testing.allocator.alloc(u8, 256 * 1024 + 4096);
    defer std.testing.allocator.free(data);
    @memset(data, 0xab);
    try tmp.dir.writeFile(io, .{ .sub_path = "big.key", .data = data });

    const path = try tmp.dir.realPathFileAlloc(io, "big.key", std.testing.allocator);
    defer std.testing.allocator.free(path);

    const backing = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(backing);
    var fba = std.heap.FixedBufferAllocator.init(backing);

    try std.testing.expectError(error.FileTooBig, readSmallFile(fba.allocator(), path));
    try std.testing.expect(std.mem.indexOfScalar(u8, backing, 0xab) == null);
}

test "PEM certificate chain decoding rejects truncated trailing certificate" {
    const allocator = std.testing.allocator;
    const pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "MAMCAQA=\n" ++
        "-----END CERTIFICATE-----\n" ++
        "-----BEGIN CERTIFICATE-----\n" ++
        "MAMCAQE=\n";

    try std.testing.expectError(error.MalformedPemBlock, certChainFromPemOrDer(allocator, pem));
}
