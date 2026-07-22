//! HTTP-01 ACME challenge token store (pure Zig, no OpenSSL).
//!
//! Extracted from `acme_client.zig` (#379) so both the OpenSSL-backed ACME
//! client (general profile) and the no-OpenSSL stub (appliance profile) share
//! one implementation, and so the store can be referenced without pulling the
//! ACME client's `@cImport` into the appliance link graph. The edge gateway
//! reads from this store to serve `/.well-known/acme-challenge/<token>`.

const std = @import("std");
const compat = @import("zig_compat");

/// Thread-safe store for HTTP-01 ACME challenge tokens.
pub const ChallengeStore = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    tokens: std.StringHashMap([]u8),

    pub fn init(allocator: std.mem.Allocator) ChallengeStore {
        return .{
            .allocator = allocator,
            .tokens = std.StringHashMap([]u8).init(allocator),
        };
    }

    pub fn deinit(self: *ChallengeStore) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.tokens.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.tokens.deinit();
    }

    pub fn put(self: *ChallengeStore, token: []const u8, key_auth: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const owned_token = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(owned_token);
        const owned_auth = try self.allocator.dupe(u8, key_auth);
        errdefer self.allocator.free(owned_auth);
        const gop = try self.tokens.getOrPut(owned_token);
        if (gop.found_existing) {
            self.allocator.free(gop.key_ptr.*);
            self.allocator.free(gop.value_ptr.*);
            gop.key_ptr.* = owned_token;
        }
        gop.value_ptr.* = owned_auth;
    }

    /// Returns an owned copy of the key authorization for the token, or null.
    /// Caller must free the returned slice.
    pub fn getCopy(self: *ChallengeStore, allocator: std.mem.Allocator, token: []const u8) ?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const val = self.tokens.get(token) orelse return null;
        return allocator.dupe(u8, val) catch null;
    }

    pub fn remove(self: *ChallengeStore, token: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.tokens.fetchRemove(token)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value);
        }
    }
};

test "ChallengeStore put/getCopy/remove" {
    const allocator = std.testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();

    try store.put("abc123", "abc123.thumbprint");
    const val = store.getCopy(allocator, "abc123").?;
    defer allocator.free(val);
    try std.testing.expectEqualStrings("abc123.thumbprint", val);

    store.remove("abc123");
    try std.testing.expect(store.getCopy(allocator, "abc123") == null);
}
