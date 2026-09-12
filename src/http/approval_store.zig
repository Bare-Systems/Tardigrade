/// approval_store.zig — Persistent storage and escalation webhook for approval entries.
///
/// Provides atomic JSON-file persistence and best-effort HTTP webhook delivery
/// for the approval workflow. All operations that can fail are non-fatal callers
/// log warnings and continue.
const std = @import("std");
const compat = @import("zig_compat");
const secrets = @import("crypto").secrets;
const upstream_tls = @import("upstream_tls.zig");

const owner_only_permissions: std.Io.File.Permissions = .fromMode(0o600);
const webhook_timeout_ms: u32 = 5_000;
const webhook_max_payload_bytes: usize = 64 * 1024;
const webhook_max_response_head_bytes: usize = 64 * 1024;

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
    if (body.len > webhook_max_payload_bytes) return error.WebhookPayloadTooLarge;
    const uri = try std.Uri.parse(webhook_url);
    const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    if (!is_https and !std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.UnsupportedUriScheme;
    if (uri.user != null or uri.password != null or uri.fragment != null) return error.UnsupportedWebhookUrl;

    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host_name = try uri.getHost(&host_buf);
    const host = unbracketUriHost(host_name.bytes);
    if (!httpFieldSafe(host)) return error.UnsafeWebhookUrl;
    const port = uri.port orelse if (is_https) @as(u16, 443) else @as(u16, 80);
    const fd = try compat.connectBoundedTcp(host, port, webhook_timeout_ms);
    defer _ = std.c.close(fd);
    compat.setSocketTimeoutsMs(fd, webhook_timeout_ms, webhook_timeout_ms);

    var request: std.Io.Writer.Allocating = .init(allocator);
    defer request.deinit();
    try request.writer.writeAll("POST ");
    try writeUriComponent(&request.writer, uri.path);
    if (uri.query) |query| {
        try request.writer.writeByte('?');
        try writeUriComponent(&request.writer, query);
    }
    try request.writer.writeAll(" HTTP/1.1\r\nHost: ");
    if (std.mem.findScalar(u8, host, ':') != null) {
        try request.writer.print("[{s}]", .{host});
    } else {
        try request.writer.writeAll(host);
    }
    const default_port: u16 = if (is_https) 443 else 80;
    if (port != default_port) try request.writer.print(":{d}", .{port});
    try request.writer.print(
        "\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ body.len, body },
    );

    if (is_https) {
        var tls = try upstream_tls.UpstreamTlsConn.connect(fd, host, .{});
        defer tls.deinit();
        try tls.writeAll(request.written());
        try readWebhookResponseHead(&tls, fd, webhook_timeout_ms);
    } else {
        const stream = compat.netStreamFromFd(fd);
        try stream.writeAll(request.written());
        try readWebhookResponseHead(stream, fd, webhook_timeout_ms);
    }
}

fn httpFieldSafe(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0) return false;
    }
    return true;
}

fn unbracketUriHost(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') return host[1 .. host.len - 1];
    return host;
}

fn writeUriComponent(writer: *std.Io.Writer, component: std.Uri.Component) !void {
    const bytes = switch (component) {
        .raw, .percent_encoded => |value| value,
    };
    if (!httpFieldSafe(if (bytes.len == 0) "/" else bytes)) return error.UnsafeWebhookUrl;
    if (bytes.len == 0) {
        try writer.writeByte('/');
    } else {
        try writer.writeAll(bytes);
    }
}

fn readWebhookResponseHead(transport: anytype, fd: std.posix.fd_t, timeout_ms: u32) !void {
    const start_ms = compat.milliTimestamp();
    var response_head: [webhook_max_response_head_bytes]u8 = undefined;
    var used: usize = 0;
    while (std.mem.find(u8, response_head[0..used], "\r\n\r\n") == null) {
        const elapsed: u64 = @intCast(@max(0, compat.milliTimestamp() - start_ms));
        if (elapsed >= timeout_ms) return error.Timeout;
        const remaining: u32 = @intCast(timeout_ms - elapsed);
        if (!transportReadReady(transport) and !try pollReadable(fd, remaining)) return error.Timeout;
        const n = try transport.read(response_head[used..]);
        if (n == 0) return error.UpstreamConnectionClosed;
        used += n;
        if (used == response_head.len and std.mem.find(u8, response_head[0..used], "\r\n\r\n") == null) {
            return error.WebhookResponseHeadTooLarge;
        }
    }
}

fn transportReadReady(transport: anytype) bool {
    const T = @TypeOf(transport);
    const info = @typeInfo(T);
    const Target = if (info == .pointer) info.pointer.child else T;
    if (@hasDecl(Target, "readReady")) return transport.readReady();
    if (@hasDecl(Target, "pending")) return transport.pending() > 0;
    return false;
}

fn pollReadable(fd: std.posix.fd_t, timeout_ms: u32) !bool {
    var poll_fds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR,
        .revents = 0,
    }};
    const ready = std.posix.poll(&poll_fds, @intCast(@min(timeout_ms, std.math.maxInt(i32)))) catch return error.Timeout;
    return ready != 0;
}

test "approval webhook response head read has an absolute timeout" {
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) {
        return error.SocketPairFailed;
    }
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    const start_ms = compat.milliTimestamp();
    try std.testing.expectError(
        error.Timeout,
        readWebhookResponseHead(compat.netStreamFromFd(fds[0]), fds[0], 25),
    );
    const elapsed_ms = compat.milliTimestamp() - start_ms;
    try std.testing.expect(elapsed_ms >= 15);
    try std.testing.expect(elapsed_ms < 2_000);
}

test "approval webhook response head accepts a complete bounded response" {
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) {
        return error.SocketPairFailed;
    }
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);
    const response = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
    try compat.netStreamFromFd(fds[1]).writeAll(response);
    try readWebhookResponseHead(compat.netStreamFromFd(fds[0]), fds[0], 250);
}

test "approval webhook rejects header delimiters in URL-derived fields" {
    try std.testing.expect(httpFieldSafe("example.test"));
    try std.testing.expect(!httpFieldSafe(""));
    try std.testing.expect(!httpFieldSafe("example.test\r\nHost: attacker"));
    try std.testing.expect(!httpFieldSafe("example\x00test"));
    try std.testing.expectEqualStrings("::1", unbracketUriHost("[::1]"));
    try std.testing.expectEqualStrings("example.test", unbracketUriHost("example.test"));
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
