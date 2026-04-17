const builtin = @import("builtin");
const std = @import("std");

pub const Entry = struct {
    ts_ms: i64,
    scope: []const u8,
    route: []const u8,
    correlation_id: []const u8,
    identity: []const u8,
    client_ip: []const u8,
    upstream_url: []const u8,
    request_body: []const u8,
    response_status: u16,
    response_content_type: []const u8,
    response_body: []const u8,
};

pub const Summary = struct {
    id: usize,
    ts_ms: i64,
    scope: []u8,
    route: []u8,
    correlation_id: []u8,
    identity: []u8,
    client_ip: []u8,
    response_status: u16,

    pub fn deinit(self: *Summary, allocator: std.mem.Allocator) void {
        allocator.free(self.scope);
        allocator.free(self.route);
        allocator.free(self.correlation_id);
        allocator.free(self.identity);
        allocator.free(self.client_ip);
        self.* = undefined;
    }
};

pub const StoredEntry = struct {
    id: usize,
    ts_ms: i64,
    scope: []u8,
    route: []u8,
    correlation_id: []u8,
    identity: []u8,
    client_ip: []u8,
    upstream_url: []u8,
    request_body: []u8,
    response_status: u16,
    response_content_type: []u8,
    response_body: []u8,

    pub fn deinit(self: *StoredEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.scope);
        allocator.free(self.route);
        allocator.free(self.correlation_id);
        allocator.free(self.identity);
        allocator.free(self.client_ip);
        allocator.free(self.upstream_url);
        allocator.free(self.request_body);
        allocator.free(self.response_content_type);
        allocator.free(self.response_body);
        self.* = undefined;
    }

    fn fromEntry(allocator: std.mem.Allocator, id: usize, entry: Entry) !StoredEntry {
        return .{
            .id = id,
            .ts_ms = entry.ts_ms,
            .scope = try allocator.dupe(u8, entry.scope),
            .route = try allocator.dupe(u8, entry.route),
            .correlation_id = try allocator.dupe(u8, entry.correlation_id),
            .identity = try allocator.dupe(u8, entry.identity),
            .client_ip = try allocator.dupe(u8, entry.client_ip),
            .upstream_url = try allocator.dupe(u8, entry.upstream_url),
            .request_body = try allocator.dupe(u8, entry.request_body),
            .response_status = entry.response_status,
            .response_content_type = try allocator.dupe(u8, entry.response_content_type),
            .response_body = try allocator.dupe(u8, entry.response_body),
        };
    }
};

pub fn append(allocator: std.mem.Allocator, path: []const u8, entry: Entry, redacted_values: []const []const u8) !void {
    if (path.len == 0) return;

    if (std.fs.path.dirname(path)) |dir_name| {
        std.fs.makeDirAbsolute(dir_name) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
    }

    const file = try std.fs.createFileAbsolute(path, .{ .read = true, .truncate = false });
    defer file.close();
    try ensureOwnerOnlyPermissions(file);
    try file.seekFromEnd(0);

    var sanitized = try sanitizeEntry(allocator, entry, redacted_values);
    defer sanitized.deinit(allocator);

    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try std.json.stringify(sanitized, .{}, buf.writer());
    try file.writeAll(buf.items);
    try file.writeAll("\n");
}

pub fn listRecent(allocator: std.mem.Allocator, path: []const u8, limit: usize) ![]Summary {
    if (path.len == 0 or limit == 0) return allocator.alloc(Summary, 0);

    const contents = readFileOrEmpty(allocator, path) catch |err| switch (err) {
        error.FileNotFound => return allocator.alloc(Summary, 0),
        else => return err,
    };
    defer allocator.free(contents);

    var window = std.ArrayList(Summary).init(allocator);
    errdefer {
        for (window.items) |*summary| summary.deinit(allocator);
        window.deinit();
    }

    var line_id: usize = 0;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        line_id += 1;
        var entry = try parseStoredEntryLine(allocator, line_id, line);
        defer entry.deinit(allocator);

        if (window.items.len == limit) {
            var oldest = window.orderedRemove(0);
            oldest.deinit(allocator);
        }
        try window.append(.{
            .id = entry.id,
            .ts_ms = entry.ts_ms,
            .scope = try allocator.dupe(u8, entry.scope),
            .route = try allocator.dupe(u8, entry.route),
            .correlation_id = try allocator.dupe(u8, entry.correlation_id),
            .identity = try allocator.dupe(u8, entry.identity),
            .client_ip = try allocator.dupe(u8, entry.client_ip),
            .response_status = entry.response_status,
        });
    }

    std.mem.reverse(Summary, window.items);
    return window.toOwnedSlice();
}

pub fn getById(allocator: std.mem.Allocator, path: []const u8, id: usize) !?StoredEntry {
    if (path.len == 0 or id == 0) return null;

    const contents = readFileOrEmpty(allocator, path) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(contents);

    var line_id: usize = 0;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        line_id += 1;
        if (line_id != id) continue;
        return try parseStoredEntryLine(allocator, id, line);
    }

    return null;
}

fn readFileOrEmpty(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return allocator.alloc(u8, 0),
        else => return err,
    };
    defer file.close();
    const stat = try file.stat();
    const max_bytes: usize = 8 * 1024 * 1024;
    const size: usize = @intCast(@min(stat.size, max_bytes));
    return try file.readToEndAlloc(allocator, size);
}

fn parseStoredEntryLine(allocator: std.mem.Allocator, id: usize, line: []const u8) !StoredEntry {
    var parsed = try std.json.parseFromSlice(Entry, allocator, line, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return StoredEntry.fromEntry(allocator, id, parsed.value);
}

fn sanitizeEntry(allocator: std.mem.Allocator, entry: Entry, redacted_values: []const []const u8) !StoredEntry {
    var out = StoredEntry{
        .id = 0,
        .ts_ms = entry.ts_ms,
        .scope = try redactText(allocator, entry.scope, redacted_values),
        .route = try redactText(allocator, entry.route, redacted_values),
        .correlation_id = try redactText(allocator, entry.correlation_id, redacted_values),
        .identity = try redactText(allocator, entry.identity, redacted_values),
        .client_ip = try redactText(allocator, entry.client_ip, redacted_values),
        .upstream_url = try redactText(allocator, entry.upstream_url, redacted_values),
        .request_body = try redactText(allocator, entry.request_body, redacted_values),
        .response_status = entry.response_status,
        .response_content_type = try redactText(allocator, entry.response_content_type, redacted_values),
        .response_body = try redactText(allocator, entry.response_body, redacted_values),
    };
    errdefer out.deinit(allocator);
    return out;
}

fn redactText(allocator: std.mem.Allocator, value: []const u8, redacted_values: []const []const u8) ![]u8 {
    var out = try allocator.dupe(u8, value);
    errdefer allocator.free(out);

    for (redacted_values) |secret| {
        if (secret.len == 0) continue;
        if (std.mem.indexOf(u8, out, secret) == null) continue;
        const replaced = try std.mem.replaceOwned(u8, allocator, out, secret, "[REDACTED]");
        allocator.free(out);
        out = replaced;
    }

    var changed = true;
    while (changed) {
        changed = false;
        const start = findJwtLikeToken(out) orelse break;
        const end = start + jwtLikeTokenLength(out[start..]);
        const prefix = out[0..start];
        const suffix = out[end..];
        const replaced = try std.fmt.allocPrint(allocator, "{s}[REDACTED]{s}", .{ prefix, suffix });
        allocator.free(out);
        out = replaced;
        changed = true;
    }

    return out;
}

fn findJwtLikeToken(value: []const u8) ?usize {
    var idx: usize = 0;
    while (idx < value.len) : (idx += 1) {
        if (!isJwtTokenChar(value[idx])) continue;
        const len = jwtLikeTokenLength(value[idx..]);
        if (len > 0) return idx;
    }
    return null;
}

fn jwtLikeTokenLength(value: []const u8) usize {
    var idx: usize = 0;
    var segments: usize = 0;
    while (idx < value.len) {
        const start = idx;
        while (idx < value.len and isJwtTokenChar(value[idx])) : (idx += 1) {}
        if (idx == start) break;
        if (idx - start < 4) return 0;
        segments += 1;
        if (segments == 3) {
            return if (idx == value.len or !isJwtTokenChar(value[idx])) idx else 0;
        }
        if (idx >= value.len or value[idx] != '.') return 0;
        idx += 1;
    }
    return 0;
}

fn isJwtTokenChar(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_';
}

fn ensureOwnerOnlyPermissions(file: std.fs.File) !void {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return;
    try file.chmod(0o600);
}

test "transcript store appends ndjson records" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/transcripts.ndjson", .{tmp_abs});
    defer allocator.free(path);

    try append(allocator, path, .{
        .ts_ms = 1,
        .scope = "chat",
        .route = "/v1/chat",
        .correlation_id = "corr-1",
        .identity = "user-1",
        .client_ip = "127.0.0.1",
        .upstream_url = "http://127.0.0.1:8080/v1/chat",
        .request_body = "{\"message\":\"hello\"}",
        .response_status = 200,
        .response_content_type = "application/json",
        .response_body = "{\"ok\":true}",
    }, &.{});

    const contents = try std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
    defer allocator.free(contents);
    try std.testing.expect(std.mem.indexOf(u8, contents, "\"scope\":\"chat\"") != null);
    try std.testing.expect(std.mem.endsWith(u8, contents, "\n"));
}

test "transcript store redacts explicit bearer values and jwt-looking tokens" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/transcripts.ndjson", .{tmp_abs});
    defer allocator.free(path);
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTQyIn0.c2lnbmF0dXJl";

    try append(allocator, path, .{
        .ts_ms = 1,
        .scope = "chat",
        .route = "/v1/chat",
        .correlation_id = "corr-1",
        .identity = "user-42",
        .client_ip = "127.0.0.1",
        .upstream_url = "http://127.0.0.1:8080/v1/chat?token=opaque-secret",
        .request_body = "{\"Authorization\":\"Bearer opaque-secret\",\"jwt\":\"" ++ jwt ++ "\"}",
        .response_status = 200,
        .response_content_type = "application/json",
        .response_body = "{\"echo\":\"opaque-secret\",\"jwt\":\"" ++ jwt ++ "\"}",
    }, &.{ "opaque-secret", jwt });

    const contents = try std.fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
    defer allocator.free(contents);
    try std.testing.expect(std.mem.indexOf(u8, contents, "opaque-secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, contents, jwt) == null);
    try std.testing.expect(std.mem.indexOf(u8, contents, "[REDACTED]") != null);
}

test "transcript store writes owner-only file permissions when supported" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/transcripts.ndjson", .{tmp_abs});
    defer allocator.free(path);

    try append(allocator, path, .{
        .ts_ms = 1,
        .scope = "chat",
        .route = "/v1/chat",
        .correlation_id = "corr-1",
        .identity = "user-1",
        .client_ip = "127.0.0.1",
        .upstream_url = "http://127.0.0.1:8080/v1/chat",
        .request_body = "{}",
        .response_status = 200,
        .response_content_type = "application/json",
        .response_body = "{\"ok\":true}",
    }, &.{});

    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    try std.testing.expectEqual(@as(u32, 0o600), stat.mode & 0o777);
}

test "transcript store lists recent entries and loads details by id" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/transcripts.ndjson", .{tmp_abs});
    defer allocator.free(path);

    try append(allocator, path, .{
        .ts_ms = 1,
        .scope = "chat",
        .route = "/v1/chat",
        .correlation_id = "corr-1",
        .identity = "user-1",
        .client_ip = "127.0.0.1",
        .upstream_url = "http://127.0.0.1:8080/v1/chat",
        .request_body = "{\"message\":\"one\"}",
        .response_status = 200,
        .response_content_type = "application/json",
        .response_body = "{\"ok\":1}",
    }, &.{});
    try append(allocator, path, .{
        .ts_ms = 2,
        .scope = "commands",
        .route = "/v1/commands",
        .correlation_id = "corr-2",
        .identity = "user-2",
        .client_ip = "127.0.0.2",
        .upstream_url = "http://127.0.0.1:8080/v1/commands",
        .request_body = "{\"command\":\"status\"}",
        .response_status = 202,
        .response_content_type = "application/json",
        .response_body = "{\"queued\":true}",
    }, &.{});

    const summaries = try listRecent(allocator, path, 10);
    defer {
        for (summaries) |*summary| summary.deinit(allocator);
        allocator.free(summaries);
    }
    try std.testing.expectEqual(@as(usize, 2), summaries.len);
    try std.testing.expectEqual(@as(usize, 2), summaries[0].id);
    try std.testing.expectEqualStrings("/v1/commands", summaries[0].route);

    var entry = (try getById(allocator, path, 1)).?;
    defer entry.deinit(allocator);
    try std.testing.expectEqualStrings("/v1/chat", entry.route);
    try std.testing.expectEqualStrings("{\"message\":\"one\"}", entry.request_body);
}
