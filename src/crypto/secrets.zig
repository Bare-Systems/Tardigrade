//! Secret ownership and zeroization helpers (#372).
//!
//! These containers make secret lifetimes explicit. They copy caller-provided
//! bytes into owned storage, expose only borrowed slices, wipe replaced values
//! before reuse, and require `deinit` before the value is discarded.

const std = @import("std");

pub const Error = error{SecretTooLarge};

/// Overwrite `buffer` with zeros in a way the optimiser may not elide.
///
/// This deliberately does NOT call `std.crypto.secureZero`, which is
/// `@memset` over a `[]volatile T`. LLVM discards the `volatile` qualifier on
/// that memset and lowers it to a plain `memset` libcall; on x86_64-linux
/// that call binds to `compiler_rt.memset`, which in Zig 0.16 is a
/// byte-at-a-time store loop -- and it wins over libc's optimised `memset`
/// even with `link_libc = true`. (`compiler_rt.memcpy` is size-dispatched and
/// fast; only `memset` is naive, so the asymmetry is easy to miss.) On
/// aarch64/macOS the same source binds to libSystem's vectorised `_bzero`,
/// which is why this only ever showed up on the x86_64 fuzz VMs: measured
/// cost of one 265,408-byte wipe was 4.35 us on aarch64 vs 95.9 us on
/// x86_64, and it made the #675 QUIC CRYPTO-reassembly row a >6 h job there
/// versus ~12 min on an aarch64 dev machine.
///
/// Storing through wide *volatile* pointers keeps the "must not be elided"
/// guarantee -- LLVM may not merge, widen, or drop volatile stores, so this
/// can never decay back into a `memset` libcall -- while moving 32 bytes per
/// store instead of one. Targets without 32-byte vector stores split the
/// chunk into whatever native store width they do have, which is still far
/// better than one byte at a time. Measured after this change: 7.6 us for
/// the same 265,408-byte wipe on x86_64, i.e. within the ~2x general
/// CPU-class gap between the two machines rather than 22x off it.
pub fn secureZero(buffer: []u8) void {
    // Coverage instrumentation would put an atomic counter increment inside
    // the chunk loop below. It costs nothing measurable, but it would grow
    // the fuzzer's instrumented-edge count (8509 -> 8511 on the QUIC fuzz
    // build) purely as a side effect of a performance fix, and the coverage
    // it reports is noise: the only thing it varies on is how many bytes
    // were wiped. The `@memset` path this replaces never had it either,
    // because the wipe was a libcall into uninstrumented compiler_rt, so
    // this keeps the coverage surface equivalent to before.
    @disableInstrumentation();

    const Chunk = @Vector(32, u8);
    const chunk_len = @sizeOf(Chunk);

    var index: usize = 0;
    while (index + chunk_len <= buffer.len) : (index += chunk_len) {
        const dest: *align(1) volatile Chunk = @ptrCast(buffer.ptr + index);
        dest.* = @splat(0);
    }
    while (index < buffer.len) : (index += 1) {
        const dest: *volatile u8 = @ptrCast(buffer.ptr + index);
        dest.* = 0;
    }
}

pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    return std.crypto.timing_safe.compare(u8, a, b, .big) == .eq;
}

/// Wipes a secret-bearing heap allocation and returns it to `allocator`,
/// guaranteeing the bytes the backing allocator observes are zero rather
/// than whatever `std.mem.Allocator.free` would otherwise leave behind.
///
/// `Allocator.free` runs `@memset(bytes, undefined)` before dispatching to
/// the backing implementation. In safety builds that fills the buffer with a
/// poison pattern *after* any zeroing we've already done, which trips
/// allocator-level "was this zeroized before free" assertions; in
/// ReleaseFast, "undefined" carries no required bit pattern so the compiler
/// is free to emit no write at all, meaning the plain `free()` path is not
/// actually guaranteed to scrub secrets in a production build. Bypassing the
/// wrapper and calling `rawFree` directly ensures the zeroed bytes are what
/// the allocator (and anything that reuses the memory next) actually sees.
///
/// This is the `[]u8` special case of `secureZeroAndFreeAligned`; use that
/// directly for a typed slice whose element alignment may exceed `u8`.
pub fn secureZeroAndFree(allocator: std.mem.Allocator, buffer: []u8) void {
    secureZeroAndFreeAligned(u8, allocator, buffer);
}

/// Generic form of `secureZeroAndFree` for a secret-bearing `[]T` whose
/// element alignment may be stricter than `u8`. Passing a byte-cast view of
/// such a slice to `secureZeroAndFree` would call `rawFree` with
/// `alignOf(u8)`, understating the alignment the backing allocator was
/// originally told to use for this allocation — some allocators rely on
/// `free`/`rawFree` receiving the same alignment `alloc` received to locate
/// or validate the allocation's bookkeeping.
pub fn secureZeroAndFreeAligned(comptime T: type, allocator: std.mem.Allocator, buffer: []T) void {
    if (buffer.len == 0) return;
    const bytes = std.mem.sliceAsBytes(buffer);
    secureZero(bytes);
    allocator.rawFree(bytes, .fromByteUnits(@alignOf(T)), @returnAddress());
}

pub fn FixedSecret(comptime capacity: usize) type {
    return struct {
        bytes: [capacity]u8 = [_]u8{0} ** capacity,
        len: usize = 0,

        const Self = @This();

        pub fn init(value: []const u8) Error!Self {
            var secret = Self{};
            try secret.replace(value);
            return secret;
        }

        pub fn replace(self: *Self, value: []const u8) Error!void {
            if (value.len > self.bytes.len) return error.SecretTooLarge;
            const old_len = self.len;
            if (overlaps(self.bytes[0..], value)) {
                std.mem.copyForwards(u8, self.bytes[0..value.len], value);
                if (old_len > value.len) secureZero(self.bytes[value.len..old_len]);
            } else {
                self.clear();
                @memcpy(self.bytes[0..value.len], value);
            }
            self.len = value.len;
        }

        pub fn slice(self: *const Self) []const u8 {
            return self.bytes[0..self.len];
        }

        pub fn copy(self: *const Self) Self {
            var out = Self{};
            out.replace(self.slice()) catch unreachable;
            return out;
        }

        pub fn eql(self: *const Self, other: *const Self) bool {
            return constantTimeEqual(self.slice(), other.slice());
        }

        pub fn deinit(self: *Self) void {
            self.clear();
        }

        fn clear(self: *Self) void {
            if (self.len > 0) secureZero(self.bytes[0..self.len]);
            self.len = 0;
        }

        pub fn format(
            _: Self,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            _: anytype,
        ) !void {
            @compileError("secret values must not be formatted or logged");
        }
    };
}

pub const BoundedSecret = struct {
    allocator: ?std.mem.Allocator = null,
    bytes: []u8 = &.{},
    len: usize = 0,

    pub fn initCapacity(self: *BoundedSecret, allocator: std.mem.Allocator, capacity: usize) !void {
        std.debug.assert(self.bytes.len == 0);
        self.bytes = try allocator.alloc(u8, capacity);
        self.allocator = allocator;
        @memset(self.bytes, 0);
    }

    pub fn init(self: *BoundedSecret, allocator: std.mem.Allocator, capacity: usize, value: []const u8) !void {
        try self.initCapacity(allocator, capacity);
        errdefer self.deinit();
        try self.replace(value);
    }

    pub fn replace(self: *BoundedSecret, value: []const u8) Error!void {
        if (value.len > self.bytes.len) return error.SecretTooLarge;
        const old_len = self.len;
        if (overlaps(self.bytes, value)) {
            std.mem.copyForwards(u8, self.bytes[0..value.len], value);
            if (old_len > value.len) secureZero(self.bytes[value.len..old_len]);
        } else {
            self.clear();
            @memcpy(self.bytes[0..value.len], value);
        }
        self.len = value.len;
    }

    pub fn slice(self: *const BoundedSecret) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: *const BoundedSecret, other: *const BoundedSecret) bool {
        return constantTimeEqual(self.slice(), other.slice());
    }

    pub fn deinit(self: *BoundedSecret) void {
        self.len = 0;
        const allocator = self.allocator orelse return;
        // `secureZeroAndFree`, not `clearAll()` + ordinary `allocator.free`:
        // the latter hands the allocator a zeroed-then-poisoned (or, in
        // ReleaseFast, possibly never-actually-zeroed) buffer instead of one
        // it can observe as genuinely zero. See `secureZeroAndFree`'s doc
        // comment for why `Allocator.free` on its own is not sufficient here.
        secureZeroAndFree(allocator, self.bytes);
        self.allocator = null;
        self.bytes = self.bytes[0..0];
    }

    fn clear(self: *BoundedSecret) void {
        if (self.len > 0) secureZero(self.bytes[0..self.len]);
        self.len = 0;
    }

    fn clearAll(self: *BoundedSecret) void {
        secureZero(self.bytes);
        self.len = 0;
    }

    pub fn format(
        _: BoundedSecret,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("secret values must not be formatted or logged");
    }
};

fn overlaps(storage: []const u8, value: []const u8) bool {
    if (storage.len == 0 or value.len == 0) return false;
    const storage_start = @intFromPtr(storage.ptr);
    const storage_end = storage_start + storage.len;
    const value_start = @intFromPtr(value.ptr);
    const value_end = value_start + value.len;
    return value_start < storage_end and storage_start < value_end;
}

/// Test allocator wrapper that observes the contents of specific buffers at the
/// moment they are released, so "this credential is zeroized before release"
/// can be asserted as behavior instead of reviewed by eye.
///
/// Why contents-are-zero rather than plaintext-sniffing: `Allocator.free`
/// scribbles `undefined` (0xaa) over the buffer before the allocator ever sees
/// it whenever runtime safety is on, so an ordinary free never exposes readable
/// plaintext *in a safe build* and a plaintext search would pass either way.
/// `secureZeroAndFree` bypasses that scribble (it calls `rawFree` directly), so
/// a watched buffer arrives all-zero exactly when the canonical wipe was used:
/// an ordinary free shows 0xaa, and an unsafe build with no wipe shows the
/// secret. Both regressions fail this check.
pub const CredentialWipeDetector = struct {
    pub const max_watched = 8;

    backing: std.mem.Allocator,
    watched: [max_watched]?Watch = @splat(null),
    count: usize = 0,

    const Watch = struct {
        ptr: [*]const u8,
        len: usize,
        released: bool = false,
        zeroed_on_release: bool = false,
    };

    pub fn init(backing: std.mem.Allocator) CredentialWipeDetector {
        return .{ .backing = backing };
    }

    pub fn allocator(self: *CredentialWipeDetector) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    /// Track `buffer` and require it to be wiped by the time it is released.
    pub fn watch(self: *CredentialWipeDetector, buffer: []const u8) void {
        if (self.count >= max_watched) @panic("CredentialWipeDetector: too many watched buffers");
        self.watched[self.count] = .{ .ptr = buffer.ptr, .len = buffer.len };
        self.count += 1;
    }

    /// True when every watched buffer was released AND was fully zeroed at that
    /// point. A buffer that is never released fails too: a leaked credential is
    /// not a wiped credential.
    pub fn allWatchedWiped(self: *const CredentialWipeDetector) bool {
        for (self.watched[0..self.count]) |maybe| {
            const entry = maybe orelse return false;
            if (!entry.released or !entry.zeroed_on_release) return false;
        }
        return true;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CredentialWipeDetector = @ptrCast(@alignCast(ctx));
        return self.backing.vtable.alloc(self.backing.ptr, len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CredentialWipeDetector = @ptrCast(@alignCast(ctx));
        return self.backing.vtable.resize(self.backing.ptr, memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CredentialWipeDetector = @ptrCast(@alignCast(ctx));
        return self.backing.vtable.remap(self.backing.ptr, memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CredentialWipeDetector = @ptrCast(@alignCast(ctx));
        for (self.watched[0..self.count]) |*maybe| {
            const entry = &(maybe.* orelse continue);
            if (entry.ptr != memory.ptr or entry.len != memory.len) continue;
            entry.released = true;
            entry.zeroed_on_release = std.mem.allEqual(u8, memory, 0);
        }
        self.backing.vtable.free(self.backing.ptr, memory, alignment, ret_addr);
    }
};

const testing = std.testing;

test "CredentialWipeDetector distinguishes a wiped release from an ordinary free" {
    var detector = CredentialWipeDetector.init(testing.allocator);
    const allocator = detector.allocator();

    const wiped = try allocator.dupe(u8, "s3cret-token");
    detector.watch(wiped);
    secureZeroAndFree(allocator, wiped);
    try testing.expect(detector.allWatchedWiped());

    var ordinary_detector = CredentialWipeDetector.init(testing.allocator);
    const ordinary_allocator = ordinary_detector.allocator();
    const plain = try ordinary_allocator.dupe(u8, "s3cret-token");
    ordinary_detector.watch(plain);
    ordinary_allocator.free(plain);
    try testing.expect(!ordinary_detector.allWatchedWiped());
}

test "fixed secret copies, borrows, compares, and zeroizes" {
    const Secret32 = FixedSecret(32);
    var first = try Secret32.init("secret");
    defer first.deinit();
    var second = try Secret32.init("secret");
    defer second.deinit();

    try testing.expectEqualStrings("secret", first.slice());
    try testing.expect(first.eql(&second));
    first.deinit();
    try testing.expectEqual(@as(usize, 0), first.len);
    for (first.bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "fixed secret replace clears old tail before reuse" {
    const Secret8 = FixedSecret(8);
    var secret = try Secret8.init("abcdef");
    try secret.replace("xy");

    try testing.expectEqualStrings("xy", secret.slice());
    try testing.expectEqual(@as(u8, 0), secret.bytes[2]);
    try testing.expectEqual(@as(u8, 0), secret.bytes[5]);
    secret.deinit();
}

test "fixed secret replace handles self-overlapping input" {
    const Secret8 = FixedSecret(8);
    var secret = try Secret8.init("abcdef");
    try secret.replace(secret.slice()[1..4]);
    try testing.expectEqualStrings("bcd", secret.slice());
    try testing.expectEqual(@as(u8, 0), secret.bytes[3]);
    secret.deinit();
}

test "fixed secret rejects oversized input without clobbering current value" {
    const Secret4 = FixedSecret(4);
    var secret = try Secret4.init("keep");
    try testing.expectError(error.SecretTooLarge, secret.replace("too-large"));
    try testing.expectEqualStrings("keep", secret.slice());
    secret.deinit();
}

test "bounded secret clears allocator backing storage before free" {
    var backing = [_]u8{0xcc} ** 128;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var secret = BoundedSecret{};
    try secret.init(fba.allocator(), 32, &([_]u8{0xab} ** 16));
    try testing.expectEqual(@as(usize, 16), secret.len);

    secret.clearAll();
    try testing.expect(std.mem.indexOfScalar(u8, &backing, 0xab) == null);
    for (backing[0..32]) |byte| try testing.expectEqual(@as(u8, 0), byte);
    secret.deinit();
}

test "bounded secret errdefer cleanup zeroizes early returns" {
    var backing = [_]u8{0xcc} ** 128;
    var fba = std.heap.FixedBufferAllocator.init(&backing);

    const Helper = struct {
        fn failAfterInit(allocator: std.mem.Allocator) !void {
            var secret = BoundedSecret{};
            try secret.init(allocator, 32, &([_]u8{0xdd} ** 16));
            errdefer secret.deinit();
            return error.TestExpectedError;
        }
    };

    try testing.expectError(error.TestExpectedError, Helper.failAfterInit(fba.allocator()));
    try testing.expect(std.mem.indexOfScalar(u8, &backing, 0xdd) == null);
}

test "bounded secret replace handles self-overlapping input" {
    var backing = [_]u8{0xcc} ** 128;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var secret = BoundedSecret{};
    try secret.init(fba.allocator(), 32, "abcdef");
    defer secret.deinit();

    try secret.replace(secret.slice()[1..4]);
    try testing.expectEqualStrings("bcd", secret.slice());
    try testing.expectEqual(@as(u8, 0), secret.bytes[3]);
}

test "bounded secret deinit hands the allocator zeroed bytes, not Allocator.free's undefined-poison" {
    var backing = [_]u8{0xcc} ** 64;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var secret = BoundedSecret{};
    try secret.init(fba.allocator(), 32, &([_]u8{0xab} ** 16));

    secret.deinit();

    try testing.expect(std.mem.indexOfScalar(u8, &backing, 0xab) == null);
    for (backing[0..32]) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "secureZero wipes every length class and respects slice bounds" {
    // `secureZero` wipes in 32-byte chunks with a byte tail (#675), so cover
    // lengths below, at, and above the chunk size, plus an unaligned start
    // offset -- the chunk stores are `align(1)` precisely so a []u8 that does
    // not begin on a 32-byte boundary is still handled.
    var storage: [200]u8 = undefined;
    for ([_]usize{ 0, 1, 7, 31, 32, 33, 63, 64, 65, 127 }) |len| {
        for ([_]usize{ 0, 1, 3, 8 }) |offset| {
            @memset(&storage, 0xAA);
            secureZero(storage[offset..][0..len]);
            for (storage[offset..][0..len]) |byte| try testing.expectEqual(@as(u8, 0), byte);
            // Bytes on either side of the wiped slice must be untouched.
            for (storage[0..offset]) |byte| try testing.expectEqual(@as(u8, 0xAA), byte);
            for (storage[offset + len ..]) |byte| try testing.expectEqual(@as(u8, 0xAA), byte);
        }
    }
}

test "secureZeroAndFree hands the allocator zeroed bytes, not Allocator.free's undefined-poison" {
    var backing = [_]u8{0xcc} ** 64;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const buf = try fba.allocator().alloc(u8, 16);
    @memset(buf, 0xab);

    secureZeroAndFree(fba.allocator(), buf);

    // A plain `allocator.free(buf)` would have run `@memset(buf, undefined)`
    // first in safety builds, leaving poison bytes rather than zeros.
    try testing.expect(std.mem.indexOfScalar(u8, &backing, 0xab) == null);
    for (backing[0..16]) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "secureZeroAndFree tolerates an empty buffer" {
    var backing = [_]u8{0xcc} ** 8;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    secureZeroAndFree(fba.allocator(), &.{});
}

test "secureZeroAndFreeAligned hands the allocator zeroed bytes for a wider-than-u8-aligned element" {
    var backing: [64]u8 align(8) = [_]u8{0xcc} ** 64;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const buf = try fba.allocator().alloc(u64, 4);
    @memset(buf, 0xabab_abab_abab_abab);

    secureZeroAndFreeAligned(u64, fba.allocator(), buf);

    try testing.expect(std.mem.indexOfScalar(u8, &backing, 0xab) == null);
    for (backing[0..32]) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "secureZeroAndFreeAligned tolerates an empty buffer" {
    var backing = [_]u8{0xcc} ** 8;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    secureZeroAndFreeAligned(u64, fba.allocator(), &.{});
}

test "secret helpers expose non-formatting APIs" {
    try testing.expect(@hasDecl(FixedSecret(8), "format"));
    try testing.expect(@hasDecl(BoundedSecret, "format"));
    try testing.expect(constantTimeEqual("same", "same"));
    try testing.expect(!constantTimeEqual("same", "diff"));
    try testing.expect(!constantTimeEqual("short", "shorter"));
}
