const std = @import("std");
const Allocator = std.mem.Allocator;
const Headers = @import("headers.zig").Headers;

/// Session token length in bytes (32 bytes = 256 bits of entropy).
pub const TOKEN_BYTES: usize = 32;
/// Hex-encoded token length.
pub const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;

pub const SESSION_HEADER = "X-Session-Token";

/// A single session record.
pub const Session = struct {
    token: [TOKEN_HEX_LEN]u8,
    /// Identity that created this session (e.g. bearer token hash).
    identity: []const u8,
    /// Client IP at session creation.
    client_ip: []const u8,
    /// Optional device identifier.
    device_id: ?[]const u8,
    /// Nanosecond timestamp when session was created.
    created_ns: i128,
    /// Nanosecond timestamp of last activity.
    last_active_ns: i128,
    /// Whether the session has been explicitly revoked.
    revoked: bool,
};

/// In-memory session store.
///
/// Provides token issuance, lookup, touch (extend), revocation,
/// and automatic expiry of idle sessions.
pub const SessionStore = struct {
    allocator: Allocator,
    sessions: std.StringHashMap(Session),
    /// Session TTL in nanoseconds (idle timeout).
    ttl_ns: i128,
    /// Maximum concurrent sessions (0 = unlimited).
    max_sessions: u32,

    pub fn init(allocator: Allocator, ttl_seconds: u32, max_sessions: u32) SessionStore {
        return .{
            .allocator = allocator,
            .sessions = std.StringHashMap(Session).init(allocator),
            .ttl_ns = @as(i128, ttl_seconds) * std.time.ns_per_s,
            .max_sessions = max_sessions,
        };
    }

    pub fn deinit(self: *SessionStore) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.freeSessionData(entry.value_ptr);
            self.allocator.free(entry.key_ptr.*);
        }
        self.sessions.deinit();
    }

    /// Create a new session for the given identity.
    /// Returns the hex-encoded session token.
    pub fn create(self: *SessionStore, identity: []const u8, client_ip: []const u8, device_id: ?[]const u8) ![]const u8 {
        // Cleanup expired before creating
        self.cleanupExpired();

        // Enforce max sessions
        if (self.max_sessions > 0 and self.sessions.count() >= self.max_sessions) {
            return error.TooManySessions;
        }

        const now = std.time.nanoTimestamp();

        // Generate cryptographically random token
        var token_bytes: [TOKEN_BYTES]u8 = undefined;
        std.crypto.random.bytes(&token_bytes);

        var token_hex: [TOKEN_HEX_LEN]u8 = undefined;
        _ = std.fmt.bufPrint(&token_hex, "{s}", .{std.fmt.fmtSliceHexLower(&token_bytes)}) catch unreachable;

        const owned_identity = try self.allocator.dupe(u8, identity);
        errdefer self.allocator.free(owned_identity);

        const owned_ip = try self.allocator.dupe(u8, client_ip);
        errdefer self.allocator.free(owned_ip);

        var owned_device: ?[]const u8 = null;
        if (device_id) |did| {
            owned_device = try self.allocator.dupe(u8, did);
        }
        errdefer if (owned_device) |d| self.allocator.free(d);

        const key = try self.allocator.dupe(u8, &token_hex);
        errdefer self.allocator.free(key);

        try self.sessions.put(key, .{
            .token = token_hex,
            .identity = owned_identity,
            .client_ip = owned_ip,
            .device_id = owned_device,
            .created_ns = now,
            .last_active_ns = now,
            .revoked = false,
        });

        return key;
    }

    /// Validate and return a session if the token is valid and not expired.
    /// Also updates last_active_ns (touch).
    pub fn validate(self: *SessionStore, token: []const u8) ?*const Session {
        const entry = self.sessions.getPtr(token) orelse return null;
        if (entry.revoked) return null;

        const now = std.time.nanoTimestamp();
        if (now - entry.last_active_ns > self.ttl_ns) {
            // Expired — remove it
            self.removeByToken(token);
            return null;
        }

        // Touch: extend session
        entry.last_active_ns = now;
        return entry;
    }

    /// Revoke a session (mark as invalid without deleting for audit).
    pub fn revoke(self: *SessionStore, token: []const u8) bool {
        if (self.sessions.getPtr(token)) |entry| {
            entry.revoked = true;
            return true;
        }
        return false;
    }

    /// Revoke all sessions for a given identity.
    pub fn revokeByIdentity(self: *SessionStore, identity: []const u8) u32 {
        var count: u32 = 0;
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.revoked and std.mem.eql(u8, entry.value_ptr.identity, identity)) {
                entry.value_ptr.revoked = true;
                count += 1;
            }
        }
        return count;
    }

    /// List active sessions for a given identity.
    pub fn listByIdentity(self: *const SessionStore, allocator: Allocator, identity: []const u8) ![]const Session {
        var result = std.ArrayList(Session).init(allocator);
        errdefer result.deinit();

        const now = std.time.nanoTimestamp();
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr;
            if (!s.revoked and
                std.mem.eql(u8, s.identity, identity) and
                now - s.last_active_ns <= self.ttl_ns)
            {
                try result.append(s.*);
            }
        }
        return result.toOwnedSlice();
    }

    /// Count active (non-revoked, non-expired) sessions.
    pub fn activeCount(self: *const SessionStore) u32 {
        var count: u32 = 0;
        const now = std.time.nanoTimestamp();
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.revoked and now - entry.value_ptr.last_active_ns <= self.ttl_ns) {
                count += 1;
            }
        }
        return count;
    }

    fn removeByToken(self: *SessionStore, token: []const u8) void {
        if (self.sessions.fetchRemove(token)) |kv| {
            var session = kv.value;
            self.freeSessionData(&session);
            self.allocator.free(kv.key);
        }
    }

    fn freeSessionData(self: *SessionStore, session: *Session) void {
        self.allocator.free(session.identity);
        self.allocator.free(session.client_ip);
        if (session.device_id) |d| self.allocator.free(d);
    }

    fn cleanupExpired(self: *SessionStore) void {
        const now = std.time.nanoTimestamp();
        var keys_to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer keys_to_remove.deinit();

        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            const s = entry.value_ptr;
            // Remove expired sessions or revoked sessions (cleaned up at next cycle)
            if (now - s.last_active_ns > self.ttl_ns or s.revoked) {
                keys_to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (keys_to_remove.items) |key| {
            self.removeByToken(key);
        }
    }
};

/// Extract session token from request headers.
pub fn fromHeaders(headers: *const Headers) ?[]const u8 {
    const token = headers.get("x-session-token") orelse return null;
    if (!isValidToken(token)) return null;
    return token;
}

/// Validate a session token format (must be hex, correct length).
pub fn isValidToken(token: []const u8) bool {
    if (token.len != TOKEN_HEX_LEN) return false;
    for (token) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

// Tests

test "SessionStore create and validate" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator, 300, 0);
    defer store.deinit();

    const token = try store.create("user-abc", "10.0.0.1", null);

    try std.testing.expectEqual(@as(usize, TOKEN_HEX_LEN), token.len);
    try std.testing.expect(isValidToken(token));

    const session = store.validate(token).?;
    try std.testing.expectEqualStrings("user-abc", session.identity);
    try std.testing.expectEqualStrings("10.0.0.1", session.client_ip);
    try std.testing.expect(session.device_id == null);
    try std.testing.expect(!session.revoked);
}

test "SessionStore create with device_id" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator, 300, 0);
    defer store.deinit();

    const token = try store.create("user-abc", "10.0.0.1", "iphone-14-xyz");
    const session = store.validate(token).?;
    try std.testing.expectEqualStrings("iphone-14-xyz", session.device_id.?);
}

test "SessionStore revoke" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator, 300, 0);
    defer store.deinit();

    const token = try store.create("user-abc", "10.0.0.1", null);
    try std.testing.expect(store.validate(token) != null);

    try std.testing.expect(store.revoke(token));

    // Revoked session returns null
    try std.testing.expect(store.validate(token) == null);
}

test "SessionStore revokeByIdentity" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator, 300, 0);
    defer store.deinit();

    _ = try store.create("user-abc", "10.0.0.1", null);
    _ = try store.create("user-abc", "10.0.0.2", null);
    _ = try store.create("user-xyz", "10.0.0.3", null);

    const revoked = store.revokeByIdentity("user-abc");
    try std.testing.expectEqual(@as(u32, 2), revoked);
    try std.testing.expectEqual(@as(u32, 1), store.activeCount());
}

test "SessionStore max_sessions limit" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator, 300, 2);
    defer store.deinit();

    _ = try store.create("a", "1.1.1.1", null);
    _ = try store.create("b", "2.2.2.2", null);

    try std.testing.expectError(error.TooManySessions, store.create("c", "3.3.3.3", null));
}

test "SessionStore validate returns null for unknown token" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator, 300, 0);
    defer store.deinit();

    try std.testing.expect(store.validate("0000000000000000000000000000000000000000000000000000000000000000") == null);
}

test "SessionStore listByIdentity" {
    const allocator = std.testing.allocator;
    var store = SessionStore.init(allocator, 300, 0);
    defer store.deinit();

    _ = try store.create("user-abc", "10.0.0.1", "device-1");
    _ = try store.create("user-abc", "10.0.0.2", "device-2");
    _ = try store.create("user-xyz", "10.0.0.3", null);

    const sessions = try store.listByIdentity(allocator, "user-abc");
    defer allocator.free(sessions);

    try std.testing.expectEqual(@as(usize, 2), sessions.len);
}

test "isValidToken validates format" {
    // Valid: 64 hex chars
    try std.testing.expect(isValidToken("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"));
    // Wrong length
    try std.testing.expect(!isValidToken("abcdef"));
    // Non-hex chars
    try std.testing.expect(!isValidToken("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
}

test "fromHeaders extracts valid token" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try headers.append("X-Session-Token", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    const token = fromHeaders(&headers);
    try std.testing.expect(token != null);
    try std.testing.expectEqual(@as(usize, TOKEN_HEX_LEN), token.?.len);
}

test "fromHeaders returns null when missing" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try std.testing.expect(fromHeaders(&headers) == null);
}

test "fromHeaders returns null for invalid token" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try headers.append("X-Session-Token", "too-short");
    try std.testing.expect(fromHeaders(&headers) == null);
}
