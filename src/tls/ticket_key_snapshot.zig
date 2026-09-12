//! Production loader for persistent TLS ticket-protection key snapshots.
//!
//! This module only decodes operator-supplied state into
//! `ticket_protection.KeyConfig`. Rotation, nonce-lease validation, atomic
//! publication, and key wiping remain owned by `ticket_protection.zig`.

const std = @import("std");
const compat = @import("zig_compat");
const crypto = @import("crypto");
const ticket_protection = @import("ticket_protection.zig");

const provider = crypto.provider;
const owner_only_permissions: std.Io.File.Permissions = .fromMode(0o600);

const ZeroingAllocator = struct {
    child: std.mem.Allocator,

    fn allocator(self: *ZeroingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ptr: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *ZeroingAllocator = @ptrCast(@alignCast(ptr));
        return self.child.vtable.alloc(self.child.ptr, len, alignment, ret_addr);
    }

    fn resize(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *ZeroingAllocator = @ptrCast(@alignCast(ptr));
        if (new_len < memory.len) provider.secureZero(memory[new_len..]);
        return self.child.vtable.resize(self.child.ptr, memory, alignment, new_len, ret_addr);
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *ZeroingAllocator = @ptrCast(@alignCast(ptr));
        provider.secureZero(memory);
        self.child.vtable.free(self.child.ptr, memory, alignment, ret_addr);
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };
};

pub const max_snapshot_bytes: usize = 64 * 1024;
pub const format_version: u8 = 1;

pub const LoadError = error{
    SnapshotUnreadable,
    SnapshotTooLarge,
    MalformedEncoding,
    UnsupportedVersion,
    UnsupportedAead,
    InvalidHex,
    InvalidField,
    SnapshotUnwritable,
    OutOfMemory,
};

pub const ReservationValidator = struct {
    ctx: *anyopaque,
    validateFn: *const fn (*anyopaque, u64, []const ticket_protection.KeyConfig) ticket_protection.SnapshotError!void,

    pub fn validate(self: ReservationValidator, generation: u64, configs: []const ticket_protection.KeyConfig) ticket_protection.SnapshotError!void {
        try self.validateFn(self.ctx, generation, configs);
    }
};

pub const OwnedSnapshot = struct {
    allocator: std.mem.Allocator,
    generation: u64,
    configs: []ticket_protection.KeyConfig,
    key_storage: []KeyStorage,

    pub fn deinit(self: *OwnedSnapshot) void {
        // `secureZeroAndFreeAligned`, not a zero loop followed by ordinary
        // `allocator.free`: the latter hands the backing allocator a buffer
        // `Allocator.free`'s own `@memset(bytes, undefined)` may re-poison
        // (safety builds) or never actually clear (ReleaseFast), rather than
        // one it observes as genuinely zero. `configs` holds no secret bytes
        // of its own — `key_bytes` is a view into `key_storage` — so it is
        // freed ordinarily.
        crypto.secrets.secureZeroAndFreeAligned(KeyStorage, self.allocator, self.key_storage);
        self.allocator.free(self.configs);
        self.* = undefined;
    }
};

const KeyStorage = struct {
    bytes: [provider.max_aead_key_len]u8 = [_]u8{0} ** provider.max_aead_key_len,
};

pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) LoadError!OwnedSnapshot {
    const bytes = compat.cwd().readFileAlloc(allocator, path, max_snapshot_bytes) catch |err| switch (err) {
        error.FileTooBig => return error.SnapshotTooLarge,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.SnapshotUnreadable,
    };
    defer crypto.secrets.secureZeroAndFree(allocator, bytes);
    return parse(allocator, bytes);
}

pub fn reserveNonceLeasesInFile(allocator: std.mem.Allocator, path: []const u8, snapshot: *OwnedSnapshot, validator: ReservationValidator) (LoadError || ticket_protection.SnapshotError)!void {
    var lock = try acquireReservationLock(allocator, path);
    defer lock.release();

    const current = try loadFromFile(allocator, path);
    snapshot.deinit();
    snapshot.* = current;

    try validator.validate(snapshot.generation, snapshot.configs);

    var changed = false;
    for (snapshot.configs) |*cfg| {
        if (cfg.nonce_lease) |*lease| {
            const width = lease.end_exclusive -| lease.start;
            if (width == 0) return error.InvalidField;
            const next_end = std.math.add(u64, lease.end_exclusive, width) catch return error.InvalidField;
            lease.start = lease.end_exclusive;
            lease.end_exclusive = next_end;
            changed = true;
        }
    }
    if (!changed) return;

    try validator.validate(snapshot.generation, snapshot.configs);

    var out = std.array_list.Managed(u8).init(allocator);
    // Zero-and-raw-free the whole backing allocation via `allocatedSlice()`
    // (not `out`'s own plain-`Allocator.free`-backed deinit method) so the
    // region handed to `rawFree` matches the region wiped exactly —
    // `out.items` alone would under-cover any unused capacity `serialize`'s
    // growth reserved past the logical length.
    defer crypto.secrets.secureZeroAndFree(allocator, out.allocatedSlice());
    try serialize(&out, snapshot);

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.{d}.tmp", .{ path, std.c.getpid() });
    defer allocator.free(tmp_path);
    compat.cwd().deleteFile(tmp_path) catch {};
    errdefer compat.cwd().deleteFile(tmp_path) catch {};
    const replacement_permissions = try restrictiveReplacementPermissions(path);
    {
        var file = compat.cwd().createFile(tmp_path, .{
            .truncate = true,
            .exclusive = true,
            .permissions = replacement_permissions,
        }) catch return error.SnapshotUnwritable;
        defer file.close();
        file.writeAll(out.items) catch return error.SnapshotUnwritable;
        file.flush() catch return error.SnapshotUnwritable;
    }
    compat.cwd().rename(tmp_path, compat.cwd(), path) catch return error.SnapshotUnwritable;
    syncParentDirectory(path) catch return error.SnapshotUnwritable;
}

const ReservationLock = struct {
    file: compat.FileCompat,
    path: []const u8,
    allocator: std.mem.Allocator,

    fn release(self: *ReservationLock) void {
        self.file.close();
        self.allocator.free(self.path);
    }
};

fn acquireReservationLock(allocator: std.mem.Allocator, path: []const u8) LoadError!ReservationLock {
    const lock_path = std.fmt.allocPrint(allocator, "{s}.lock", .{path}) catch return error.OutOfMemory;
    errdefer allocator.free(lock_path);
    const file = compat.cwd().createFile(lock_path, .{
        .read = true,
        .truncate = false,
        .permissions = owner_only_permissions,
        .lock = .exclusive,
    }) catch return error.SnapshotUnwritable;
    return .{ .file = file, .path = lock_path, .allocator = allocator };
}

fn restrictiveReplacementPermissions(path: []const u8) LoadError!std.Io.File.Permissions {
    if (comptime @hasDecl(std.Io.File.Permissions, "toMode")) {
        const stat = compat.cwd().statFile(path) catch return error.SnapshotUnreadable;
        const mode = stat.permissions.toMode() & 0o777;
        if ((mode & 0o077) != 0) return error.SnapshotUnwritable;
        return .fromMode(mode);
    }
    return owner_only_permissions;
}

fn syncParentDirectory(path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse ".";
    const fd = try std.posix.openat(std.posix.AT.FDCWD, parent, .{
        .ACCMODE = .RDONLY,
        .DIRECTORY = true,
        .CLOEXEC = true,
    }, 0);
    defer _ = std.c.close(fd);
    if (std.c.fsync(fd) != 0) return error.SyncFailed;
}

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) LoadError!OwnedSnapshot {
    var json_allocator = ZeroingAllocator{ .child = allocator };
    var parsed = std.json.parseFromSlice(std.json.Value, json_allocator.allocator(), bytes, .{}) catch return error.MalformedEncoding;
    defer parsed.deinit();
    const root = if (parsed.value == .object) parsed.value.object else return error.MalformedEncoding;
    const version_value = root.get("version") orelse return error.MalformedEncoding;
    const version = try jsonUnsigned(u8, version_value);
    if (version != format_version) return error.UnsupportedVersion;
    const generation = try jsonUnsigned(u64, root.get("generation") orelse return error.MalformedEncoding);
    const keys_value = root.get("keys") orelse return error.MalformedEncoding;
    if (keys_value != .array) return error.MalformedEncoding;
    const keys = keys_value.array.items;
    if (keys.len == 0 or keys.len > ticket_protection.max_keys) return error.InvalidField;

    var configs = allocator.alloc(ticket_protection.KeyConfig, keys.len) catch return error.OutOfMemory;
    errdefer allocator.free(configs);
    var key_storage = allocator.alloc(KeyStorage, keys.len) catch return error.OutOfMemory;
    errdefer crypto.secrets.secureZeroAndFreeAligned(KeyStorage, allocator, key_storage);
    @memset(key_storage, .{});

    for (keys, 0..) |key_value, i| {
        if (key_value != .object) return error.MalformedEncoding;
        const obj = key_value.object;
        const aead = try parseAead(try jsonString(obj.get("aead") orelse return error.MalformedEncoding));
        const key_len = aead.keyLength();
        var id: ticket_protection.KeyId = undefined;
        try decodeFixedHex(ticket_protection.KeyId, try jsonString(obj.get("id") orelse return error.MalformedEncoding), &id);
        try decodeHexSlice(try jsonString(obj.get("key") orelse return error.MalformedEncoding), key_storage[i].bytes[0..key_len]);

        const lease = if (obj.get("nonce_lease")) |lease_value| blk: {
            if (lease_value == .null) break :blk null;
            if (lease_value != .object) return error.MalformedEncoding;
            const lease_obj = lease_value.object;
            var prefix: [4]u8 = undefined;
            try decodeFixedHex([4]u8, try jsonString(lease_obj.get("prefix") orelse return error.MalformedEncoding), &prefix);
            break :blk ticket_protection.NonceLeaseConfig{
                .prefix = prefix,
                .start = try jsonUnsigned(u64, lease_obj.get("start") orelse return error.MalformedEncoding),
                .end_exclusive = try jsonUnsigned(u64, lease_obj.get("end_exclusive") orelse return error.MalformedEncoding),
            };
        } else null;

        configs[i] = .{
            .id = id,
            .aead = aead,
            .key_bytes = key_storage[i].bytes[0..key_len],
            .not_before_unix_ms = try jsonSigned(i64, obj.get("not_before_unix_ms") orelse return error.MalformedEncoding),
            .encrypt_until_unix_ms = try jsonSigned(i64, obj.get("encrypt_until_unix_ms") orelse return error.MalformedEncoding),
            .decrypt_until_unix_ms = try jsonSigned(i64, obj.get("decrypt_until_unix_ms") orelse return error.MalformedEncoding),
            .nonce_lease = lease,
        };
    }

    return .{
        .allocator = allocator,
        .generation = generation,
        .configs = configs,
        .key_storage = key_storage,
    };
}

fn serialize(out: *std.array_list.Managed(u8), snapshot: *const OwnedSnapshot) LoadError!void {
    try out.print("{{\"version\":{d},\"generation\":{d},\"keys\":[", .{ format_version, snapshot.generation });
    for (snapshot.configs, 0..) |cfg, i| {
        if (i > 0) try out.append(',');
        try out.print(
            "{{\"id\":\"",
            .{},
        );
        try appendHexLower(out, &cfg.id);
        try out.print(
            "\",\"aead\":\"{s}\",\"key\":\"",
            .{aeadName(cfg.aead)},
        );
        try appendHexLower(out, cfg.key_bytes);
        try out.print(
            "\",\"not_before_unix_ms\":{d},\"encrypt_until_unix_ms\":{d},\"decrypt_until_unix_ms\":{d}",
            .{
                cfg.not_before_unix_ms,
                cfg.encrypt_until_unix_ms,
                cfg.decrypt_until_unix_ms,
            },
        );
        if (cfg.nonce_lease) |lease| {
            try out.print(
                ",\"nonce_lease\":{{\"prefix\":\"",
                .{},
            );
            try appendHexLower(out, &lease.prefix);
            try out.print(
                "\",\"start\":{d},\"end_exclusive\":{d}}}",
                .{ lease.start, lease.end_exclusive },
            );
        }
        try out.append('}');
    }
    try out.appendSlice("]}");
}

fn appendHexLower(out: *std.array_list.Managed(u8), bytes: []const u8) LoadError!void {
    const alphabet = "0123456789abcdef";
    for (bytes) |b| {
        try out.append(alphabet[b >> 4]);
        try out.append(alphabet[b & 0x0f]);
    }
}

fn aeadName(aead: provider.Aead) []const u8 {
    return switch (aead) {
        .aes_128_gcm => "aes_128_gcm",
        .aes_256_gcm => "aes_256_gcm",
        .chacha20_poly1305 => "chacha20_poly1305",
    };
}

fn parseAead(value: []const u8) LoadError!provider.Aead {
    if (std.mem.eql(u8, value, "aes_128_gcm")) return .aes_128_gcm;
    if (std.mem.eql(u8, value, "aes_256_gcm")) return .aes_256_gcm;
    if (std.mem.eql(u8, value, "chacha20_poly1305")) return .chacha20_poly1305;
    return error.UnsupportedAead;
}

fn jsonString(value: std.json.Value) LoadError![]const u8 {
    if (value != .string) return error.MalformedEncoding;
    return value.string;
}

fn jsonUnsigned(comptime T: type, value: std.json.Value) LoadError!T {
    return switch (value) {
        .integer => |n| if (n >= 0 and n <= std.math.maxInt(T)) @intCast(n) else error.InvalidField,
        else => error.MalformedEncoding,
    };
}

fn jsonSigned(comptime T: type, value: std.json.Value) LoadError!T {
    return switch (value) {
        .integer => |n| if (n >= std.math.minInt(T) and n <= std.math.maxInt(T)) @intCast(n) else error.InvalidField,
        else => error.MalformedEncoding,
    };
}

fn decodeFixedHex(comptime T: type, raw: []const u8, out: *T) LoadError!void {
    const bytes = std.mem.asBytes(out);
    try decodeHexSlice(raw, bytes);
}

fn decodeHexSlice(raw: []const u8, bytes: []u8) LoadError!void {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len != bytes.len * 2) return error.InvalidHex;
    _ = std.fmt.hexToBytes(bytes, trimmed) catch return error.InvalidHex;
}

pub fn fuzzPersistentSnapshot(allocator: std.mem.Allocator, input: []const u8) void {
    var snapshot = parse(allocator, input) catch return;
    defer snapshot.deinit();

    const built = ticket_protection.Snapshot.build(
        allocator,
        snapshot.configs,
        snapshot.generation,
        fuzzCapabilities(),
    ) catch return;
    built.release();
}

fn fuzzCapabilities() provider.Capabilities {
    var caps = provider.Capabilities{};
    caps.aeads.insert(.aes_128_gcm);
    caps.aeads.insert(.aes_256_gcm);
    caps.aeads.insert(.chacha20_poly1305);
    return caps;
}

test "persistent ticket key snapshot parses owned key configs" {
    const json =
        \\{"version":1,"generation":7,"keys":[{"id":"000102030405060708090a0b0c0d0e0f","aead":"aes_128_gcm","key":"101112131415161718191a1b1c1d1e1f","not_before_unix_ms":1000,"encrypt_until_unix_ms":5000,"decrypt_until_unix_ms":9000,"nonce_lease":{"prefix":"aabbccdd","start":10,"end_exclusive":20}}]}
    ;
    var snapshot = try parse(std.testing.allocator, json);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(u64, 7), snapshot.generation);
    try std.testing.expectEqual(@as(usize, 1), snapshot.configs.len);
    try std.testing.expectEqual(ticket_protection.NonceLeaseConfig{ .prefix = .{ 0xaa, 0xbb, 0xcc, 0xdd }, .start = 10, .end_exclusive = 20 }, snapshot.configs[0].nonce_lease.?);
    try std.testing.expectEqual(@as(usize, 16), snapshot.configs[0].key_bytes.len);
}

test "OwnedSnapshot.deinit hands the allocator zeroed key bytes, not Allocator.free's undefined-poison" {
    const json =
        \\{"version":1,"generation":1,"keys":[{"id":"000102030405060708090a0b0c0d0e0f","aead":"aes_128_gcm","key":"101112131415161718191a1b1c1d1e1f","not_before_unix_ms":1000,"encrypt_until_unix_ms":5000,"decrypt_until_unix_ms":9000}]}
    ;
    var backing: [65536]u8 align(8) = [_]u8{0xcc} ** 65536;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var snapshot = try parse(fba.allocator(), json);

    var key_copy: [16]u8 = undefined;
    @memcpy(&key_copy, snapshot.configs[0].key_bytes);
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    }, &key_copy);

    snapshot.deinit();

    // A plain ordinary `Allocator.free` of `key_storage` would leave these
    // bytes intact (or replaced with build-mode-dependent poison, never
    // guaranteed zero); `secureZeroAndFreeAligned` must scrub them before
    // `deinit` returns, anywhere in the shared backing buffer.
    try std.testing.expect(std.mem.indexOf(u8, &backing, &key_copy) == null);
}

test "persistent ticket key snapshot rejects malformed secret lengths" {
    const json =
        \\{"version":1,"generation":1,"keys":[{"id":"000102030405060708090a0b0c0d0e0f","aead":"aes_128_gcm","key":"10","not_before_unix_ms":1000,"encrypt_until_unix_ms":5000,"decrypt_until_unix_ms":9000}]}
    ;
    try std.testing.expectError(error.InvalidHex, parse(std.testing.allocator, json));
}

test "fuzz: persistent ticket key snapshot parser rejects hostile JSON safely" {
    try std.testing.fuzz({}, fuzzPersistentSnapshotInput, .{ .corpus = &.{
        "",
        "{}",
        "[]",
        "{\"version\":1,\"generation\":1,\"keys\":[]}",
        "{\"version\":2,\"generation\":1,\"keys\":[]}",
        "{\"version\":1,\"generation\":1,\"keys\":[{\"id\":\"000102030405060708090a0b0c0d0e0f\",\"aead\":\"aes_128_gcm\",\"key\":\"101112131415161718191a1b1c1d1e1f\",\"not_before_unix_ms\":1000,\"encrypt_until_unix_ms\":5000,\"decrypt_until_unix_ms\":9000}]}",
        "{\"version\":1,\"generation\":1,\"keys\":[{\"id\":\"000102030405060708090a0b0c0d0e0f\",\"aead\":\"chacha20_poly1305\",\"key\":\"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\",\"not_before_unix_ms\":1000,\"encrypt_until_unix_ms\":5000,\"decrypt_until_unix_ms\":9000,\"nonce_lease\":{\"prefix\":\"01020304\",\"start\":0,\"end_exclusive\":1}}]}",
        &([_]u8{0xff} ** 128),
    } });
}

fn fuzzPersistentSnapshotInput(_: void, smith: *std.testing.Smith) !void {
    var input_buf: [4096]u8 = undefined;
    const len = smith.slice(&input_buf);
    fuzzPersistentSnapshot(std.testing.allocator, input_buf[0..len]);
}
