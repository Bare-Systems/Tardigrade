//! Secret ownership and zeroization helpers (#372).
//!
//! These containers make secret lifetimes explicit. They copy caller-provided
//! bytes into owned storage, expose only borrowed slices, wipe replaced values
//! before reuse, and require `deinit` before the value is discarded.

const std = @import("std");

pub const Error = error{SecretTooLarge};

pub fn secureZero(buffer: []u8) void {
    std.crypto.secureZero(u8, buffer);
}

pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    return std.crypto.timing_safe.compare(u8, a, b, .big) == .eq;
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
        self.clearAll();
        const allocator = self.allocator orelse return;
        allocator.free(self.bytes);
        self.allocator = null;
        self.bytes = self.bytes[0..0];
        self.len = 0;
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

const testing = std.testing;

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

test "secret helpers expose non-formatting APIs" {
    try testing.expect(@hasDecl(FixedSecret(8), "format"));
    try testing.expect(@hasDecl(BoundedSecret, "format"));
    try testing.expect(constantTimeEqual("same", "same"));
    try testing.expect(!constantTimeEqual("same", "diff"));
    try testing.expect(!constantTimeEqual("short", "shorter"));
}
