//! Durable per-group renewal retry state (#835, A5 of epic #759, design
//! `docs/ACME_AUTOMATIC_HTTPS.md` §5.4, §5.5, §9.2).
//!
//! One `renewal.json` per group, stored alongside (never inside) that
//! group's `current`/`generations/` layout (`acme/activate.zig`) under
//! `groups/<group-id>/`: it tracks *attempts*, while `activate.zig` tracks
//! *committed credential generations*. The two are written by different
//! calls and neither rewrite ever touches the other's file, so a renewal
//! worker can record a failed attempt without risking the still-valid
//! generation it left completely alone, and a corrupt `renewal.json` can
//! never be mistaken for a corrupt certificate.
//!
//! Same atomic-replace/strict-read discipline as every other ACME state
//! file (`state.zig`): `0600`, same-directory temp + fsync + rename. A
//! record that fails to parse is never repaired or deleted in place; the
//! caller (the renewal worker) is expected to apply a conservative
//! synthetic cooldown instead of treating unreadable history as "never
//! attempted" (design: "malformed ... state must preserve the last valid
//! generation and apply a conservative cooldown rather than trigger a
//! renewal storm").

const std = @import("std");
const state_mod = @import("state.zig");
const json_limits = @import("json_limits.zig");
const client_mod = @import("client.zig");

pub const Error = state_mod.Error;

/// Reuses `client.FailureClass` (transport/protocol/persistence/resource)
/// rather than inventing a second taxonomy: it is already the closed,
/// low-cardinality classification every ACME call failure maps to.
pub const FailureClass = client_mod.FailureClass;

pub const file_name = "renewal.json";
pub const version: u32 = 1;
/// Comfortably larger than the fixed-shape JSON this ever produces.
pub const max_file_len = 512;

pub const Record = struct {
    /// Unix seconds of the most recent attempt; `0` means "never attempted"
    /// (not a valid attempt time, so it doubles as the absent sentinel).
    last_attempt_at: i64 = 0,
    /// Consecutive failures since the last successful publish; `0` after a
    /// success or before the first attempt.
    failures: u32 = 0,
    last_failure_class: ?FailureClass = null,
    /// Unix seconds; `null` when the CA gave no (or no usable) `Retry-After`.
    retry_after_at: ?i64 = null,
};

const RecordJson = struct {
    version: u32,
    last_attempt_at: i64,
    failures: u32,
    last_failure_class: []const u8,
    retry_after_at: i64,
};

// `max_string` must cover the longest JSON *key* too (e.g.
// `"last_failure_class"`, 19 bytes), not just the longest value.
const record_limits = json_limits.Limits{ .max_bytes = max_file_len, .max_depth = 2, .max_string = 32, .max_keys = 8, .max_array = 1 };

/// Load the durable record for a group, or `null` if none has ever been
/// written. `error.CorruptState` propagates rather than silently resetting
/// to "never attempted" -- the caller decides the safe fallback.
pub fn load(allocator: std.mem.Allocator, group: *state_mod.SubDir) Error!?Record {
    const bytes = group.readFileAllocExactMode(allocator, file_name, max_file_len, 0o600) catch |err| switch (err) {
        error.NotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);
    var parsed = json_limits.parseBounded(RecordJson, allocator, bytes, record_limits) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CorruptState,
    };
    defer parsed.deinit();
    const v = parsed.value;
    if (v.version != version) return error.CorruptState;
    if (v.last_attempt_at < 0 or v.retry_after_at < 0 or v.failures > 1_000_000) return error.CorruptState;
    const class = parseFailureClass(v.last_failure_class) catch return error.CorruptState;
    return Record{
        .last_attempt_at = v.last_attempt_at,
        .failures = v.failures,
        .last_failure_class = class,
        .retry_after_at = if (v.retry_after_at == 0) null else v.retry_after_at,
    };
}

/// Load the durable record, converting a missing record into the empty
/// default (no prior attempt -- never applies a floor) and a corrupt one
/// into a conservative one-failure record (applies the normal failure floor
/// rather than permitting an immediate retry). Hard errors (permissions,
/// ownership, I/O, memory) still propagate.
///
/// `corrupt_since` anchors the synthetic failure's `last_attempt_at` to the
/// *first* call that observed corruption, not to each call's own `now`: a
/// still-corrupt file read repeatedly (the worker wakes every pass) must
/// count down to its retry floor from one fixed point, or the floor would
/// recompute as `now + retry_floor_seconds` forever and never arrive — a
/// cooldown that never expires is indistinguishable from "never retry at
/// all" (design: "a conservative cooldown rather than ... a renewal
/// storm", not a permanent stall). Cleared back to `null` the moment the
/// file reads clean (repaired by an operator, or replaced by a fresh
/// `save`), so a later unrelated corruption gets its own fresh anchor.
pub fn loadOrConservativeDefault(allocator: std.mem.Allocator, group: *state_mod.SubDir, now: i64, corrupt_since: *?i64) Error!Record {
    const loaded = load(allocator, group) catch |err| switch (err) {
        error.CorruptState => {
            if (corrupt_since.* == null) corrupt_since.* = now;
            return Record{ .last_attempt_at = corrupt_since.*.?, .failures = 1 };
        },
        else => return err,
    };
    corrupt_since.* = null;
    return loaded orelse Record{};
}

/// Persist `record` atomically (`0600`). Never touches `current` or any
/// generation directory.
pub fn save(allocator: std.mem.Allocator, group: *state_mod.SubDir, record: Record) Error!void {
    const class_name = if (record.last_failure_class) |c| @tagName(c) else "";
    const json = std.fmt.allocPrint(
        allocator,
        "{{\"version\":{d},\"last_attempt_at\":{d},\"failures\":{d},\"last_failure_class\":{f},\"retry_after_at\":{d}}}\n",
        .{ version, record.last_attempt_at, record.failures, std.json.fmt(class_name, .{}), record.retry_after_at orelse 0 },
    ) catch return error.OutOfMemory;
    defer allocator.free(json);
    try group.writeFileAtomic(file_name, json, 0o600);
}

fn parseFailureClass(name: []const u8) error{CorruptState}!?FailureClass {
    if (name.len == 0) return null;
    return std.meta.stringToEnum(FailureClass, name) orelse error.CorruptState;
}

// ---------------------------------------------------------------------------

const testing = std.testing;

fn openTestGroupDir(state: *state_mod.StateDir) !state_mod.SubDir {
    var groups = try state.openOrCreateSubdir("groups");
    defer groups.close();
    return try groups.openOrCreateSubdir("g1");
}

test "ACME renewal state: absent record loads as null and the conservative default is empty" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(@import("zig_compat").io(), &buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/state", .{buf[0..n]});
    defer testing.allocator.free(path);

    var state = try state_mod.StateDir.open(path);
    defer state.close();
    var group = try openTestGroupDir(&state);
    defer group.close();

    try testing.expect((try load(testing.allocator, &group)) == null);
    var anchor: ?i64 = null;
    const default = try loadOrConservativeDefault(testing.allocator, &group, 1_700_000_000, &anchor);
    try testing.expectEqual(@as(i64, 0), default.last_attempt_at);
    try testing.expectEqual(@as(u32, 0), default.failures);
    try testing.expect(default.last_failure_class == null);
    try testing.expect(default.retry_after_at == null);
}

test "ACME renewal state: round trips a failure and a success" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(@import("zig_compat").io(), &buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/state", .{buf[0..n]});
    defer testing.allocator.free(path);

    var state = try state_mod.StateDir.open(path);
    defer state.close();
    var group = try openTestGroupDir(&state);
    defer group.close();

    try save(testing.allocator, &group, .{
        .last_attempt_at = 1_700_000_000,
        .failures = 3,
        .last_failure_class = .transport,
        .retry_after_at = 1_700_000_300,
    });
    const loaded = (try load(testing.allocator, &group)).?;
    try testing.expectEqual(@as(i64, 1_700_000_000), loaded.last_attempt_at);
    try testing.expectEqual(@as(u32, 3), loaded.failures);
    try testing.expectEqual(FailureClass.transport, loaded.last_failure_class.?);
    try testing.expectEqual(@as(i64, 1_700_000_300), loaded.retry_after_at.?);

    // A success resets everything, including the Retry-After hint.
    try save(testing.allocator, &group, .{ .last_attempt_at = 1_700_000_500, .failures = 0, .last_failure_class = null, .retry_after_at = null });
    const reset = (try load(testing.allocator, &group)).?;
    try testing.expectEqual(@as(u32, 0), reset.failures);
    try testing.expect(reset.last_failure_class == null);
    try testing.expect(reset.retry_after_at == null);
}

test "ACME renewal state: a malformed record is corrupt, never silently treated as clean" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(@import("zig_compat").io(), &buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/state", .{buf[0..n]});
    defer testing.allocator.free(path);

    var state = try state_mod.StateDir.open(path);
    defer state.close();
    var group = try openTestGroupDir(&state);
    defer group.close();

    var anchor: ?i64 = null;
    for ([_][]const u8{
        "not json",
        "{}",
        "{\"version\":2,\"last_attempt_at\":1,\"failures\":1,\"last_failure_class\":\"\",\"retry_after_at\":0}",
        "{\"version\":1,\"last_attempt_at\":-1,\"failures\":1,\"last_failure_class\":\"\",\"retry_after_at\":0}",
        "{\"version\":1,\"last_attempt_at\":1,\"failures\":1,\"last_failure_class\":\"bogus\",\"retry_after_at\":0}",
    }) |content| {
        try group.writeFileAtomic(file_name, content, 0o600);
        try testing.expectError(error.CorruptState, load(testing.allocator, &group));
        const fallback = try loadOrConservativeDefault(testing.allocator, &group, 1_700_000_000, &anchor);
        try testing.expectEqual(@as(i64, 1_700_000_000), fallback.last_attempt_at);
        try testing.expectEqual(@as(u32, 1), fallback.failures);
    }

    try group.writeFileAtomic(file_name, "{\"version\":1,\"last_attempt_at\":1,\"failures\":1,\"last_failure_class\":\"\",\"retry_after_at\":0}", 0o640);
    try testing.expectError(error.InsecurePermissions, load(testing.allocator, &group));
}

test "ACME renewal state: a corrupt record's cooldown anchor is stable across repeated reads, not reset to each call's own now" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(@import("zig_compat").io(), &buf);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/state", .{buf[0..n]});
    defer testing.allocator.free(path);

    var state = try state_mod.StateDir.open(path);
    defer state.close();
    var group = try openTestGroupDir(&state);
    defer group.close();
    try group.writeFileAtomic(file_name, "not json", 0o600);

    var anchor: ?i64 = null;
    const first = try loadOrConservativeDefault(testing.allocator, &group, 1_700_000_000, &anchor);
    try testing.expectEqual(@as(i64, 1_700_000_000), first.last_attempt_at);

    // The file is still corrupt an hour later; without a stable anchor this
    // would synthesize a fresh `last_attempt_at` every call and the
    // computed retry floor would recompute as "now + floor" forever,
    // perpetually postponing renewal rather than ever expiring.
    const second = try loadOrConservativeDefault(testing.allocator, &group, 1_700_003_600, &anchor);
    try testing.expectEqual(@as(i64, 1_700_000_000), second.last_attempt_at);
    try testing.expectEqual(@as(u32, 1), second.failures);

    // Once the file reads clean again, the anchor clears: a later, distinct
    // corruption must get its own fresh anchor rather than reusing this one.
    try save(testing.allocator, &group, .{ .last_attempt_at = 1_700_003_600, .failures = 0 });
    const clean = try loadOrConservativeDefault(testing.allocator, &group, 1_700_003_600, &anchor);
    try testing.expectEqual(@as(i64, 1_700_003_600), clean.last_attempt_at);
    try testing.expectEqual(@as(u32, 0), clean.failures);

    try group.writeFileAtomic(file_name, "not json", 0o600);
    const fresh = try loadOrConservativeDefault(testing.allocator, &group, 1_700_010_000, &anchor);
    try testing.expectEqual(@as(i64, 1_700_010_000), fresh.last_attempt_at);
}

test {
    std.testing.refAllDecls(@This());
}
