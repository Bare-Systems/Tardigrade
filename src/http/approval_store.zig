/// approval_store.zig — Persistent storage and escalation webhook for approval entries.
///
/// Provides atomic JSON-file persistence and best-effort HTTP webhook delivery
/// for the approval workflow. All operations that can fail are non-fatal callers
/// log warnings and continue.
const std = @import("std");
const compat = @import("zig_compat");

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
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp", .{path});
    defer allocator.free(tmp_path);

    const json_bytes = try compat.stringifyAlloc(allocator, StoreEnvelope{ .version = 1, .entries = entries }, .{});
    defer allocator.free(json_bytes);

    {
        const f = try std.Io.Dir.createFileAbsolute(compat.io(), tmp_path, .{ .truncate = true });
        defer f.close(compat.io());
        try f.writeStreamingAll(compat.io(), json_bytes);
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
        break :blk try reader.interface.readAlloc(allocator, 64 * 1024 * 1024);
    };
    defer allocator.free(data);

    const parsed = try std.json.parseFromSlice(
        StoreEnvelope,
        allocator,
        data,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

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
    allocator.free(e.token);
    allocator.free(e.method);
    allocator.free(e.path);
    allocator.free(e.identity);
    allocator.free(e.command_id);
    allocator.free(e.status);
    allocator.free(e.decided_by);
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
