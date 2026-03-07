const std = @import("std");
const Allocator = std.mem.Allocator;
const Headers = @import("headers.zig").Headers;

pub const HEADER_NAME = "Idempotency-Key";
pub const MAX_KEY_LEN: usize = 256;

/// Stored result for a previously-seen idempotency key.
pub const CachedResponse = struct {
    status: u16,
    body: []const u8,
    content_type: []const u8,
    created_ns: i128,
};

/// In-memory idempotency key store.
///
/// Tracks previously-processed request keys and their responses so
/// duplicate requests receive the same result without re-execution.
pub const IdempotencyStore = struct {
    allocator: Allocator,
    entries: std.StringHashMap(CachedResponse),
    ttl_ns: i128, // how long entries live

    pub fn init(allocator: Allocator, ttl_seconds: u32) IdempotencyStore {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap(CachedResponse).init(allocator),
            .ttl_ns = @as(i128, ttl_seconds) * std.time.ns_per_s,
        };
    }

    pub fn deinit(self: *IdempotencyStore) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.body);
            self.allocator.free(entry.value_ptr.content_type);
        }
        self.entries.deinit();
    }

    /// Look up a cached response for the given idempotency key.
    /// Returns null if not found or expired.
    pub fn get(self: *IdempotencyStore, key: []const u8) ?CachedResponse {
        const entry = self.entries.get(key) orelse return null;
        const now = std.time.nanoTimestamp();
        if (now - entry.created_ns > self.ttl_ns) {
            // Expired - remove it
            self.remove(key);
            return null;
        }
        return entry;
    }

    /// Store a response for an idempotency key.
    pub fn put(self: *IdempotencyStore, key: []const u8, status: u16, body: []const u8, content_type: []const u8) !void {
        // Periodic cleanup before adding new entries
        self.cleanupExpired();

        const owned_key = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned_key);

        const owned_body = try self.allocator.dupe(u8, body);
        errdefer self.allocator.free(owned_body);

        const owned_ct = try self.allocator.dupe(u8, content_type);
        errdefer self.allocator.free(owned_ct);

        // Remove old entry if exists
        if (self.entries.fetchRemove(owned_key)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value.body);
            self.allocator.free(old.value.content_type);
        }

        try self.entries.put(owned_key, .{
            .status = status,
            .body = owned_body,
            .content_type = owned_ct,
            .created_ns = std.time.nanoTimestamp(),
        });
    }

    fn remove(self: *IdempotencyStore, key: []const u8) void {
        if (self.entries.fetchRemove(key)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value.body);
            self.allocator.free(old.value.content_type);
        }
    }

    fn cleanupExpired(self: *IdempotencyStore) void {
        const now = std.time.nanoTimestamp();
        var keys_to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer keys_to_remove.deinit();

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.created_ns > self.ttl_ns) {
                keys_to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (keys_to_remove.items) |key| {
            self.remove(key);
        }
    }
};

/// Validate an idempotency key from headers.
pub fn isValidKey(key: []const u8) bool {
    if (key.len == 0 or key.len > MAX_KEY_LEN) return false;
    for (key) |c| {
        // Allow printable ASCII minus control chars and spaces at edges
        if (c < 0x21 or c > 0x7e) return false;
    }
    return true;
}

/// Extract and validate idempotency key from request headers.
pub fn fromHeaders(headers: *const Headers) ?[]const u8 {
    const key = headers.get("idempotency-key") orelse return null;
    if (!isValidKey(key)) return null;
    return key;
}

// Tests

test "isValidKey accepts printable ASCII" {
    try std.testing.expect(isValidKey("abc-123-def"));
    try std.testing.expect(isValidKey("550e8400-e29b-41d4-a716-446655440000"));
    try std.testing.expect(!isValidKey(""));
    try std.testing.expect(!isValidKey("has space"));
    try std.testing.expect(!isValidKey("has\ttab"));
}

test "fromHeaders extracts valid key" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try headers.append("Idempotency-Key", "my-unique-key-123");
    const key = fromHeaders(&headers);
    try std.testing.expectEqualStrings("my-unique-key-123", key.?);
}

test "fromHeaders returns null when missing" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try std.testing.expect(fromHeaders(&headers) == null);
}

test "IdempotencyStore put and get" {
    const allocator = std.testing.allocator;
    var store = IdempotencyStore.init(allocator, 300);
    defer store.deinit();

    try store.put("key-1", 200, "{\"ok\":true}", "application/json");

    const cached = store.get("key-1").?;
    try std.testing.expectEqual(@as(u16, 200), cached.status);
    try std.testing.expectEqualStrings("{\"ok\":true}", cached.body);
    try std.testing.expectEqualStrings("application/json", cached.content_type);
}

test "IdempotencyStore returns null for unknown key" {
    const allocator = std.testing.allocator;
    var store = IdempotencyStore.init(allocator, 300);
    defer store.deinit();

    try std.testing.expect(store.get("nonexistent") == null);
}
