const std = @import("std");
const compat = @import("zig_compat");
const session = @import("session.zig");

const owner_only_permissions: std.Io.File.Permissions = .fromMode(0o600);

pub const StoredSession = struct {
    token: []const u8,
    identity: []const u8,
    client_ip: []const u8,
    device_id: []const u8,
    created_ns: i128,
    last_active_ns: i128,
    revoked: bool,
};

const StoreEnvelope = struct {
    version: u32,
    entries: []const StoredSession,
};

pub fn persist(allocator: std.mem.Allocator, path: []const u8, store: *const session.SessionStore) !void {
    const entries = try snapshot(allocator, store);
    defer freeLoaded(allocator, entries);

    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.{d}.tmp", .{ path, std.c.getpid() });
    defer allocator.free(tmp_path);

    const buf = try compat.stringifyAlloc(allocator, StoreEnvelope{
        .version = 1,
        .entries = entries,
    }, .{});
    defer {
        @memset(buf, 0);
        allocator.free(buf);
    }

    std.Io.Dir.deleteFileAbsolute(compat.io(), tmp_path) catch {};
    errdefer std.Io.Dir.deleteFileAbsolute(compat.io(), tmp_path) catch {};
    {
        const file = try std.Io.Dir.createFileAbsolute(compat.io(), tmp_path, .{
            .truncate = true,
            .exclusive = true,
            .permissions = owner_only_permissions,
        });
        defer file.close(compat.io());
        try file.writeStreamingAll(compat.io(), buf);
        try file.sync(compat.io());
    }
    try std.Io.Dir.renameAbsolute(tmp_path, path, compat.io());
}

pub fn load(allocator: std.mem.Allocator, path: []const u8) ![]StoredSession {
    const file = std.Io.Dir.openFileAbsolute(compat.io(), path, .{}) catch |err| switch (err) {
        error.FileNotFound => return try allocator.alloc(StoredSession, 0),
        else => return err,
    };
    defer file.close(compat.io());
    var file_buf: [8192]u8 = undefined;
    var reader = file.reader(compat.io(), &file_buf);
    const data = try reader.interface.allocRemaining(allocator, .limited(64 * 1024 * 1024));
    defer {
        @memset(data, 0);
        allocator.free(data);
    }

    const parsed = try std.json.parseFromSlice(StoreEnvelope, allocator, data, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    var out = try allocator.alloc(StoredSession, parsed.value.entries.len);
    var i: usize = 0;
    errdefer {
        for (out[0..i]) |entry| freeEntry(allocator, entry);
        allocator.free(out);
    }

    for (parsed.value.entries) |entry| {
        out[i] = .{
            .token = try allocator.dupe(u8, entry.token),
            .identity = try allocator.dupe(u8, entry.identity),
            .client_ip = try allocator.dupe(u8, entry.client_ip),
            .device_id = try allocator.dupe(u8, entry.device_id),
            .created_ns = entry.created_ns,
            .last_active_ns = entry.last_active_ns,
            .revoked = entry.revoked,
        };
        i += 1;
    }
    return out;
}

pub fn restore(allocator: std.mem.Allocator, store: *session.SessionStore, entries: []const StoredSession) !void {
    for (entries) |entry| {
        const token = try allocator.dupe(u8, entry.token);
        errdefer allocator.free(token);
        const identity = try allocator.dupe(u8, entry.identity);
        errdefer allocator.free(identity);
        const client_ip = try allocator.dupe(u8, entry.client_ip);
        errdefer allocator.free(client_ip);
        const device_id = if (entry.device_id.len > 0)
            try allocator.dupe(u8, entry.device_id)
        else
            null;
        errdefer if (device_id) |value| allocator.free(value);

        try store.sessions.put(token, .{
            .token = toFixedToken(entry.token) orelse return error.InvalidSessionToken,
            .identity = identity,
            .client_ip = client_ip,
            .device_id = device_id,
            .created_ns = entry.created_ns,
            .last_active_ns = entry.last_active_ns,
            .revoked = entry.revoked,
        });
    }
}

pub fn freeLoaded(allocator: std.mem.Allocator, entries: []StoredSession) void {
    for (entries) |entry| freeEntry(allocator, entry);
    allocator.free(entries);
}

fn snapshot(allocator: std.mem.Allocator, store: *const session.SessionStore) ![]StoredSession {
    var out = try allocator.alloc(StoredSession, store.sessions.count());
    var i: usize = 0;
    errdefer {
        for (out[0..i]) |entry| freeEntry(allocator, entry);
        allocator.free(out);
    }

    var it = store.sessions.iterator();
    while (it.next()) |kv| {
        const value = kv.value_ptr.*;
        out[i] = .{
            .token = try allocator.dupe(u8, kv.key_ptr.*),
            .identity = try allocator.dupe(u8, value.identity),
            .client_ip = try allocator.dupe(u8, value.client_ip),
            .device_id = if (value.device_id) |device_id| try allocator.dupe(u8, device_id) else try allocator.dupe(u8, ""),
            .created_ns = value.created_ns,
            .last_active_ns = value.last_active_ns,
            .revoked = value.revoked,
        };
        i += 1;
    }

    return out;
}

fn freeEntry(allocator: std.mem.Allocator, entry: StoredSession) void {
    allocator.free(entry.token);
    allocator.free(entry.identity);
    allocator.free(entry.client_ip);
    allocator.free(entry.device_id);
}

fn toFixedToken(raw: []const u8) ?[session.TOKEN_HEX_LEN]u8 {
    if (!session.isValidToken(raw)) return null;
    var out: [session.TOKEN_HEX_LEN]u8 = undefined;
    @memcpy(out[0..], raw);
    return out;
}

test "session store persistence round trips active and revoked entries" {
    const allocator = std.testing.allocator;

    var base = session.SessionStore.init(allocator, 300, 0);
    defer base.deinit();

    const active = try base.create("alpha", "127.0.0.1", null);
    const revoked = try base.create("beta", "127.0.0.2", "device-1");
    _ = base.revoke(revoked);
    _ = base.validate(active);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/sessions.json", .{tmp_abs});
    defer allocator.free(path);

    try persist(allocator, path, &base);

    const persisted = try std.Io.Dir.openFileAbsolute(compat.io(), path, .{});
    defer persisted.close(compat.io());
    const stat = try persisted.stat(compat.io());
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);

    const loaded = try load(allocator, path);
    defer freeLoaded(allocator, loaded);
    try std.testing.expectEqual(@as(usize, 2), loaded.len);

    var restored = session.SessionStore.init(allocator, 300, 0);
    defer restored.deinit();
    try restore(allocator, &restored, loaded);

    try std.testing.expect(restored.validate(active) != null);
    try std.testing.expect(restored.validate(revoked) == null);
}

test "session persistence removes credential temp file when rename fails" {
    const allocator = std.testing.allocator;
    var store = session.SessionStore.init(allocator, 300, 0);
    defer store.deinit();
    _ = try store.create("identity", "127.0.0.1", null);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/destination", .{tmp_abs});
    defer allocator.free(path);
    try std.Io.Dir.createDirAbsolute(compat.io(), path, .default_dir);
    const temp_path = try std.fmt.allocPrint(allocator, "{s}.{d}.tmp", .{ path, std.c.getpid() });
    defer allocator.free(temp_path);

    var failed = false;
    persist(allocator, path, &store) catch {
        failed = true;
    };
    try std.testing.expect(failed);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.openFileAbsolute(compat.io(), temp_path, .{}));
}
