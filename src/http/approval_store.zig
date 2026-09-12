/// approval_store.zig — Persistent storage and escalation webhook for approval entries.
///
/// Provides atomic JSON-file persistence and best-effort HTTP webhook delivery
/// for the approval workflow. All operations that can fail are non-fatal callers
/// log warnings and continue.
const std = @import("std");
const compat = @import("zig_compat");
const secrets = @import("crypto").secrets;

const owner_only_permissions: std.Io.File.Permissions = .fromMode(0o600);

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// One approval entry as persisted on disk.
pub const StoredApproval = struct {
    token: []const u8,
    method: []const u8,
    path: []const u8,
    identity: []const u8,
    command_id: []const u8,
    /// String form of ApprovalStatus: "pending", "approved", "denied", "escalated".
    status: []const u8,
    created_ms: i64,
    expires_ms: i64,
    decided_ms: i64,
    decided_by: []const u8,
    /// True once the escalation webhook has been fired for this entry.
    escalation_fired: bool,
};

// Internal on-disk envelope (versioned for forward compatibility).
const StoreEnvelope = struct {
    version: u32,
    entries: []const StoredApproval,
};

// ---------------------------------------------------------------------------
// Persist
// ---------------------------------------------------------------------------

/// Serialise `entries` to `path` using an atomic write (write to `<path>.tmp`,
/// then rename over `path`). Callers should hold no locks while calling this.
pub fn persist(
    allocator: std.mem.Allocator,
    path: []const u8,
    entries: []const StoredApproval,
) !void {
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.{d}.tmp", .{ path, std.c.getpid() });
    defer allocator.free(tmp_path);

    // The serialized envelope contains bearer-like approval tokens. Use the
    // project's canonical wipe (non-elidable, correct free semantics) rather
    // than `@memset` + ordinary free, which #750 documents as insufficient.
    const json_bytes = try compat.stringifyAlloc(allocator, StoreEnvelope{ .version = 1, .entries = entries }, .{});
    defer secrets.secureZeroAndFree(allocator, json_bytes);

    std.Io.Dir.deleteFileAbsolute(compat.io(), tmp_path) catch {};
    errdefer std.Io.Dir.deleteFileAbsolute(compat.io(), tmp_path) catch {};
    {
        const f = try std.Io.Dir.createFileAbsolute(compat.io(), tmp_path, .{
            .truncate = true,
            .exclusive = true,
            .permissions = owner_only_permissions,
        });
        defer f.close(compat.io());
        try f.writeStreamingAll(compat.io(), json_bytes);
        try f.sync(compat.io());
    }
    try std.Io.Dir.renameAbsolute(tmp_path, path, compat.io());
}

// ---------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------

/// Load entries from `path`. Returns an empty slice when the file does not
/// exist. Caller must free with `freeLoaded`.
pub fn load(
    allocator: std.mem.Allocator,
    path: []const u8,
) ![]StoredApproval {
    const data = blk: {
        const f = std.Io.Dir.openFileAbsolute(compat.io(), path, .{}) catch |e| switch (e) {
            error.FileNotFound => return try allocator.alloc(StoredApproval, 0),
            else => return e,
        };
        defer f.close(compat.io());
        var file_buf: [8192]u8 = undefined;
        var reader = f.reader(compat.io(), &file_buf);
        // `readAlloc` requires EXACTLY the requested length and fails with
        // `EndOfStream` on anything shorter, which made every restore attempt
        // fail. `allocRemaining` reads to EOF under the same size ceiling.
        break :blk try reader.interface.allocRemaining(allocator, .limited(64 * 1024 * 1024));
    };
    defer secrets.secureZeroAndFree(allocator, data);

    const parsed = try std.json.parseFromSlice(
        StoreEnvelope,
        allocator,
        data,
        .{ .ignore_unknown_fields = true },
    );
    defer {
        // The parser's arena may hold its own copies of the token strings. We
        // own that memory until `deinit()`, so wipe the credential fields
        // before releasing it; otherwise the only wiped copy would be `data`.
        for (parsed.value.entries) |e| secrets.secureZero(@constCast(e.token));
        parsed.deinit();
    }

    var out = try allocator.alloc(StoredApproval, parsed.value.entries.len);
    var i: usize = 0;
    errdefer {
        for (out[0..i]) |e| freeEntry(allocator, e);
        allocator.free(out);
    }

    for (parsed.value.entries) |e| {
        out[i] = .{
            .token = try allocator.dupe(u8, e.token),
            .method = try allocator.dupe(u8, e.method),
            .path = try allocator.dupe(u8, e.path),
            .identity = try allocator.dupe(u8, e.identity),
            .command_id = try allocator.dupe(u8, e.command_id),
            .status = try allocator.dupe(u8, e.status),
            .created_ms = e.created_ms,
            .expires_ms = e.expires_ms,
            .decided_ms = e.decided_ms,
            .decided_by = try allocator.dupe(u8, e.decided_by),
            .escalation_fired = e.escalation_fired,
        };
        i += 1;
    }
    return out;
}

/// Free memory returned by `load`.
pub fn freeLoaded(allocator: std.mem.Allocator, entries: []StoredApproval) void {
    for (entries) |e| freeEntry(allocator, e);
    allocator.free(entries);
}

fn freeEntry(allocator: std.mem.Allocator, e: StoredApproval) void {
    // Explicit disposition per field rather than a blanket free: `token` is
    // presented as a bearer credential, so its heap copy is wiped. `identity`
    // and `decided_by` name a principal and are wiped as well, since they are
    // the inputs an attacker would need to replay an approval. The remaining
    // fields (method/path/command_id/status) are routing and state metadata
    // that carry no secret, so an ordinary free is correct for them.
    secrets.secureZeroAndFree(allocator, @constCast(e.token));
    secrets.secureZeroAndFree(allocator, @constCast(e.identity));
    secrets.secureZeroAndFree(allocator, @constCast(e.decided_by));
    allocator.free(e.method);
    allocator.free(e.path);
    allocator.free(e.command_id);
    allocator.free(e.status);
}

// ---------------------------------------------------------------------------
// Escalation webhook
// ---------------------------------------------------------------------------

/// Fire an HTTP POST to `webhook_url` with `body` as the JSON payload.
/// Best-effort: errors are logged as warnings and not propagated.
pub fn fireWebhook(
    allocator: std.mem.Allocator,
    webhook_url: []const u8,
    body: []const u8,
) void {
    if (webhook_url.len == 0) return;
    doFireWebhook(allocator, webhook_url, body) catch |err| {
        std.log.warn("approval escalation webhook failed ({s}): {}", .{ webhook_url, err });
    };
}

fn doFireWebhook(
    allocator: std.mem.Allocator,
    webhook_url: []const u8,
    body: []const u8,
) !void {
    const uri = try std.Uri.parse(webhook_url);
    var client = std.http.Client{ .allocator = allocator, .io = compat.io() };
    defer client.deinit();
    _ = try client.fetch(.{
        .location = .{ .uri = uri },
        .method = .POST,
        .payload = body,
        .keep_alive = false,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
}

test "approval persistence creates owner-only credential storage" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/approvals.json", .{tmp_abs});
    defer allocator.free(path);

    try persist(allocator, path, &.{});
    const file = try std.Io.Dir.openFileAbsolute(compat.io(), path, .{});
    defer file.close(compat.io());
    const stat = try file.stat(compat.io());
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);
}

test "approval persistence removes credential temp file when rename fails" {
    const allocator = std.testing.allocator;
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
    persist(allocator, path, &.{}) catch {
        failed = true;
    };
    try std.testing.expect(failed);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.openFileAbsolute(compat.io(), temp_path, .{}));
}

test "loaded approval credentials are wiped, not merely freed" {
    // Companion to the session-store regression: approval tokens are
    // bearer-like, so the duplicated heap copies must be wiped on release.
    var detector = secrets.CredentialWipeDetector.init(std.testing.allocator);
    const allocator = detector.allocator();

    const entries = try allocator.alloc(StoredApproval, 1);
    const token = try allocator.dupe(u8, "approval-token-9f3c");
    const identity = try allocator.dupe(u8, "alice");
    detector.watch(token);
    detector.watch(identity);
    entries[0] = .{
        .token = token,
        .method = try allocator.dupe(u8, "POST"),
        .path = try allocator.dupe(u8, "/deploy"),
        .identity = identity,
        .command_id = try allocator.dupe(u8, "cmd-1"),
        .status = try allocator.dupe(u8, "pending"),
        .created_ms = 0,
        .expires_ms = 0,
        .decided_ms = 0,
        .decided_by = try allocator.dupe(u8, ""),
        .escalation_fired = false,
    };

    freeLoaded(allocator, entries);
    try std.testing.expect(detector.allWatchedWiped());
}

test "approval store round trips through persist and load" {
    // Regression: `load()` used `readAlloc`, which demands exactly the byte
    // limit it is given, so every restore of a normally sized store failed with
    // `EndOfStream` and persisted approvals were silently dropped on restart.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/approvals.json", .{tmp_abs});
    defer allocator.free(path);

    const entries = [_]StoredApproval{.{
        .token = "apr-1",
        .method = "POST",
        .path = "/deploy",
        .identity = "alice",
        .command_id = "cmd-1",
        .status = "pending",
        .created_ms = 10,
        .expires_ms = 20,
        .decided_ms = 0,
        .decided_by = "",
        .escalation_fired = false,
    }};
    try persist(allocator, path, entries[0..]);

    const loaded = try load(allocator, path);
    defer freeLoaded(allocator, loaded);
    try std.testing.expectEqual(@as(usize, 1), loaded.len);
    try std.testing.expectEqualStrings("apr-1", loaded[0].token);
    try std.testing.expectEqualStrings("/deploy", loaded[0].path);
    try std.testing.expectEqualStrings("pending", loaded[0].status);
    try std.testing.expectEqual(@as(i64, 20), loaded[0].expires_ms);

    // A missing store is an empty store, not an error.
    const missing_path = try std.fmt.allocPrint(allocator, "{s}/absent.json", .{tmp_abs});
    defer allocator.free(missing_path);
    const empty = try load(allocator, missing_path);
    defer freeLoaded(allocator, empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);
}
