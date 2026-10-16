//! HTTP-01 ACME challenge token store (pure Zig, no OpenSSL).
//!
//! Host-scoped, bounded, TTL'd store for native ACME HTTP-01 challenges
//! (#877, design doc §8.2/§9.1). The key is `(managed host, token)`, not
//! token alone: a token minted for one host cannot be replayed to retrieve
//! the key authorization for a different host. `matchManagedHost` performs
//! that host scoping against the operator's configured managed-hostname
//! set; callers must run it on the request Host before calling into the
//! store so an unmatched or hostile Host header never reaches a lookup.
//!
//! Extracted from `acme_client.zig` (#379) so both the OpenSSL-backed ACME
//! client (general profile) and the no-OpenSSL stub (appliance profile) share
//! one implementation, and so the store can be referenced without pulling the
//! ACME client's C-interop import into the appliance link graph. The edge
//! gateway reads from this store to serve `/.well-known/acme-challenge/<token>`.
//!
//! Time is caller-supplied (`now`/`expires_at` are Unix seconds), never read
//! from the system clock internally, so expiry and capacity behavior are
//! deterministic under a fake clock in tests.

const std = @import("std");
const compat = @import("zig_compat");
const crypto = @import("crypto");
const secrets = crypto.secrets;

/// Store-wide caps (design §9.1).
pub const max_entries: usize = 128;
pub const max_host_len: usize = 253; // RFC 1035 full-name limit.
pub const min_token_len: usize = 16;
pub const max_token_len: usize = 128;
pub const max_key_authorization_len: usize = 256;
/// Default live window for an entry; callers pass the smaller of this and
/// the CA's own authorization deadline as `expires_at` (design §8.2/§9.1).
pub const default_ttl_s: i64 = 10 * 60;

pub const PutError = error{
    OutOfMemory,
    InvalidHost,
    InvalidToken,
    InvalidKeyAuthorization,
    StoreFull,
};

/// Whether an explicit cleanup (rejected authorization, canceled order)
/// actually closed out a live entry, so the caller can tell a real
/// cancellation from a no-op one.
pub const CloseOutcome = enum { closed, not_found };

const Slot = struct {
    host: []u8,
    token: []u8,
    value: []u8,
    expires_at: i64,
};

/// Thread-safe, bounded, host-scoped store for HTTP-01 ACME challenge tokens.
pub const ChallengeStore = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    slots: std.ArrayList(Slot) = .empty,

    pub fn init(allocator: std.mem.Allocator) ChallengeStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ChallengeStore) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.slots.items) |*slot| self.freeSlot(slot);
        self.slots.deinit(self.allocator);
    }

    fn freeSlot(self: *ChallengeStore, slot: *Slot) void {
        self.allocator.free(slot.host);
        secrets.secureZeroAndFree(self.allocator, slot.token);
        secrets.secureZeroAndFree(self.allocator, slot.value);
    }

    fn findIndex(self: *ChallengeStore, host: []const u8, token: []const u8) ?usize {
        for (self.slots.items, 0..) |slot, i| {
            if (std.mem.eql(u8, slot.host, host) and std.mem.eql(u8, slot.token, token)) return i;
        }
        return null;
    }

    /// Removes every slot whose `expires_at` is at or before `now`. Run on
    /// every lookup, not only a periodic sweep (design §8.2), and before
    /// admission in `put` so capacity is never held by stale challenges.
    pub fn expire(self: *ChallengeStore, now: i64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.expireLocked(now);
    }

    fn expireLocked(self: *ChallengeStore, now: i64) void {
        var i: usize = 0;
        while (i < self.slots.items.len) {
            if (self.slots.items[i].expires_at <= now) {
                var removed = self.slots.swapRemove(i);
                self.freeSlot(&removed);
            } else {
                i += 1;
            }
        }
    }

    /// Admits a challenge keyed by `(host, token)`. `token` and
    /// `key_authorization` are validated and rejected *before* any byte is
    /// retained. A `put` for an already-present `(host, token)` replaces the
    /// stored value (duplicate-key replacement, e.g. a retried challenge
    /// POST); otherwise capacity exhaustion fails the new challenge and never
    /// evicts another live one.
    pub fn put(
        self: *ChallengeStore,
        now: i64,
        host: []const u8,
        token: []const u8,
        key_authorization: []const u8,
        expires_at: i64,
    ) PutError!void {
        if (host.len == 0 or host.len > max_host_len) return error.InvalidHost;
        if (!isValidToken(token)) return error.InvalidToken;
        if (key_authorization.len == 0 or key_authorization.len > max_key_authorization_len) {
            return error.InvalidKeyAuthorization;
        }

        self.mutex.lock();
        defer self.mutex.unlock();
        self.expireLocked(now);

        if (self.findIndex(host, token)) |i| {
            const owned_value = try self.allocator.dupe(u8, key_authorization);
            secrets.secureZeroAndFree(self.allocator, self.slots.items[i].value);
            self.slots.items[i].value = owned_value;
            self.slots.items[i].expires_at = expires_at;
            return;
        }

        if (self.slots.items.len >= max_entries) return error.StoreFull;

        const owned_host = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(owned_host);
        const owned_token = try self.allocator.dupe(u8, token);
        errdefer secrets.secureZeroAndFree(self.allocator, owned_token);
        const owned_value = try self.allocator.dupe(u8, key_authorization);
        errdefer secrets.secureZeroAndFree(self.allocator, owned_value);
        try self.slots.append(self.allocator, .{
            .host = owned_host,
            .token = owned_token,
            .value = owned_value,
            .expires_at = expires_at,
        });
    }

    /// Returns an owned copy of the key authorization for `(host, token)`,
    /// or null if absent, expired, or closed. Caller must free the returned
    /// slice. Expiry is enforced here, not only by `expire`'s sweep, so a
    /// stale entry can never be served even if the sweep has not run yet.
    pub fn getCopy(self: *ChallengeStore, allocator: std.mem.Allocator, now: i64, host: []const u8, token: []const u8) ?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.expireLocked(now);
        const i = self.findIndex(host, token) orelse return null;
        return allocator.dupe(u8, self.slots.items[i].value) catch null;
    }

    /// Explicit cleanup for a rejected authorization or a canceled order:
    /// closes out a live entry so it can never be served again, even before
    /// its TTL elapses.
    pub fn remove(self: *ChallengeStore, host: []const u8, token: []const u8) CloseOutcome {
        self.mutex.lock();
        defer self.mutex.unlock();
        const i = self.findIndex(host, token) orelse return .not_found;
        var removed = self.slots.swapRemove(i);
        self.freeSlot(&removed);
        return .closed;
    }

    /// Token charset/length gate: `^[A-Za-z0-9_-]{16,128}$` (design §6.3,
    /// §8.2). RFC 8555 §8.3 base64url challenge tokens are well inside this
    /// range.
    fn isValidToken(token: []const u8) bool {
        if (token.len < min_token_len or token.len > max_token_len) return false;
        for (token) |c| {
            const ok = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '_' or c == '-';
            if (!ok) return false;
        }
        return true;
    }
};

/// Host-scopes a request Host header against the operator's configured
/// managed-hostname set (design §8.0/§8.2): the request must name one of the
/// exact managed hosts, not a prefix/suffix/pattern match, since ACME names
/// admit no wildcards (`acme/names.zig`). Rejects anything that is not a
/// bare DNS authority -- userinfo (`user@host`), empty input, or a Host that
/// fails to parse -- rather than trying to normalize it, since those are
/// exactly the shapes default-port and authority-confusion tricks rely on.
/// Returns the matching entry from `managed_hosts` (stable, so it can key
/// the store without an extra copy) or null on any mismatch. `managed_hosts`
/// is assumed already-canonical lowercase, which `acme/names.zig` enforces
/// at config-validation time.
pub fn matchManagedHost(managed_hosts: []const []const u8, raw_host: ?[]const u8) ?[]const u8 {
    const host = raw_host orelse return null;
    const trimmed = std.mem.trim(u8, host, " \t\r\n");
    if (trimmed.len == 0) return null;
    if (std.mem.indexOfScalar(u8, trimmed, '@') != null) return null;
    const without_port = stripPort(trimmed);
    if (without_port.len == 0) return null;
    for (managed_hosts) |candidate| {
        if (std.ascii.eqlIgnoreCase(candidate, without_port)) return candidate;
    }
    return null;
}

/// Strips an optional `:port` suffix from a Host/authority value, honoring
/// `[...]` IPv6 literals. Deliberately re-implemented rather than imported
/// from `edge_config.stripHostPort` so this file keeps its original #379
/// zero-dependency property (no `edge_config`/`http` import graph), which is
/// what lets it be reached from both the OpenSSL and no-OpenSSL profiles.
fn stripPort(host: []const u8) []const u8 {
    if (host[0] == '[') {
        const end = std.mem.findScalar(u8, host, ']') orelse return host;
        return host[1..end];
    }
    const colon = std.mem.findScalarLast(u8, host, ':') orelse return host;
    const head = host[0..colon];
    if (std.mem.findScalar(u8, head, ':') != null) return host;
    return head;
}

const testing = std.testing;

test "ChallengeStore put/getCopy/remove are host-scoped" {
    var store = ChallengeStore.init(testing.allocator);
    defer store.deinit();

    try store.put(0, "a.example.com", "abcdefghijklmnop", "abcdefghijklmnop.thumb", 600);

    const val = store.getCopy(testing.allocator, 0, "a.example.com", "abcdefghijklmnop").?;
    defer testing.allocator.free(val);
    try testing.expectEqualStrings("abcdefghijklmnop.thumb", val);

    // Same token, different host: not retrievable.
    try testing.expect(store.getCopy(testing.allocator, 0, "b.example.com", "abcdefghijklmnop") == null);
    // Wrong token on the right host: not retrievable.
    try testing.expect(store.getCopy(testing.allocator, 0, "a.example.com", "zzzzzzzzzzzzzzzz") == null);

    try testing.expectEqual(CloseOutcome.closed, store.remove("a.example.com", "abcdefghijklmnop"));
    try testing.expect(store.getCopy(testing.allocator, 0, "a.example.com", "abcdefghijklmnop") == null);
    try testing.expectEqual(CloseOutcome.not_found, store.remove("a.example.com", "abcdefghijklmnop"));
}

test "ChallengeStore expiry is enforced on every lookup, not only a sweep" {
    var store = ChallengeStore.init(testing.allocator);
    defer store.deinit();

    try store.put(0, "a.example.com", "abcdefghijklmnop", "value", 100);
    const live = store.getCopy(testing.allocator, 50, "a.example.com", "abcdefghijklmnop").?;
    testing.allocator.free(live);

    // At the expiry boundary the entry is already gone (<=, not <).
    try testing.expect(store.getCopy(testing.allocator, 100, "a.example.com", "abcdefghijklmnop") == null);
    try testing.expectEqual(@as(usize, 0), store.slots.items.len);
}

test "ChallengeStore.expire sweeps stale entries without touching live ones" {
    var store = ChallengeStore.init(testing.allocator);
    defer store.deinit();

    try store.put(0, "a.example.com", "abcdefghijklmnop", "stale-value", 50);
    try store.put(0, "a.example.com", "qrstuvwxyzabcdef", "live-value", 5000);

    store.expire(100);
    try testing.expectEqual(@as(usize, 1), store.slots.items.len);
    const v = store.getCopy(testing.allocator, 100, "a.example.com", "qrstuvwxyzabcdef").?;
    defer testing.allocator.free(v);
    try testing.expectEqualStrings("live-value", v);
}

test "ChallengeStore duplicate (host, token) replaces the value in place" {
    var store = ChallengeStore.init(testing.allocator);
    defer store.deinit();

    try store.put(0, "a.example.com", "abcdefghijklmnop", "first", 600);
    try store.put(0, "a.example.com", "abcdefghijklmnop", "second", 900);

    try testing.expectEqual(@as(usize, 1), store.slots.items.len);
    const v = store.getCopy(testing.allocator, 0, "a.example.com", "abcdefghijklmnop").?;
    defer testing.allocator.free(v);
    try testing.expectEqualStrings("second", v);
}

test "ChallengeStore rejects invalid token and oversize key authorization before retaining bytes" {
    var store = ChallengeStore.init(testing.allocator);
    defer store.deinit();

    try testing.expectError(error.InvalidToken, store.put(0, "a.example.com", "short", "value", 600));
    try testing.expectError(error.InvalidToken, store.put(0, "a.example.com", "has a space!!!!!", "value", 600));
    try testing.expectError(error.InvalidToken, store.put(0, "a.example.com", "a" ** 129, "value", 600));
    try testing.expectError(error.InvalidKeyAuthorization, store.put(0, "a.example.com", "abcdefghijklmnop", "a" ** 257, 600));
    try testing.expectError(error.InvalidKeyAuthorization, store.put(0, "a.example.com", "abcdefghijklmnop", "", 600));
    try testing.expectError(error.InvalidHost, store.put(0, "", "abcdefghijklmnop", "value", 600));

    try testing.expectEqual(@as(usize, 0), store.slots.items.len);
}

test "ChallengeStore caps at 128 entries and never evicts a live challenge for a new one" {
    var store = ChallengeStore.init(testing.allocator);
    defer store.deinit();

    var buf: [20]u8 = undefined;
    for (0..max_entries) |i| {
        const token = std.fmt.bufPrint(&buf, "tok-{d:0>12}", .{i}) catch unreachable;
        try store.put(0, "a.example.com", token, "value", 600);
    }
    try testing.expectEqual(max_entries, store.slots.items.len);

    const overflow_token = std.fmt.bufPrint(&buf, "tok-{d:0>12}", .{max_entries}) catch unreachable;
    try testing.expectError(error.StoreFull, store.put(0, "a.example.com", overflow_token, "value", 600));

    // Every original entry is still live.
    const first_token = std.fmt.bufPrint(&buf, "tok-{d:0>12}", .{0}) catch unreachable;
    const v = store.getCopy(testing.allocator, 0, "a.example.com", first_token).?;
    testing.allocator.free(v);
}

test "ChallengeStore put rolls back cleanly on allocator failure" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 2 });
    var store = ChallengeStore.init(failing.allocator());
    defer store.deinit();

    try testing.expectError(error.OutOfMemory, store.put(0, "a.example.com", "abcdefghijklmnop", "value", 600));
    try testing.expectEqual(@as(usize, 0), store.slots.items.len);
}

test "ChallengeStore concurrent put/getCopy/remove stays within bounds" {
    var store = ChallengeStore.init(testing.allocator);
    defer store.deinit();

    const Worker = struct {
        fn run(s: *ChallengeStore, id: usize) void {
            var buf: [20]u8 = undefined;
            for (0..64) |i| {
                const token = std.fmt.bufPrint(&buf, "w{d:0>2}-tok{d:0>10}", .{ id, i }) catch unreachable;
                s.put(0, "a.example.com", token, "value", 600) catch {};
                if (s.getCopy(testing.allocator, 0, "a.example.com", token)) |v| testing.allocator.free(v);
                _ = s.remove("a.example.com", token);
            }
        }
    };

    var threads: [4]std.Thread = undefined;
    for (0..threads.len) |i| threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ &store, i });
    for (threads) |t| t.join();

    try testing.expect(store.slots.items.len <= max_entries);
}

test "matchManagedHost scopes by exact managed hostname and rejects userinfo/default-port tricks" {
    const managed = [_][]const u8{ "a.example.com", "b.example.com" };

    try testing.expect(matchManagedHost(&managed, "a.example.com") != null);
    try testing.expectEqualStrings("a.example.com", matchManagedHost(&managed, "A.Example.Com").?);
    try testing.expectEqualStrings("a.example.com", matchManagedHost(&managed, "a.example.com:443").?);
    try testing.expectEqualStrings("a.example.com", matchManagedHost(&managed, "a.example.com:80").?);

    try testing.expect(matchManagedHost(&managed, "c.example.com") == null);
    try testing.expect(matchManagedHost(&managed, "evil.com@a.example.com") == null);
    try testing.expect(matchManagedHost(&managed, "a.example.com@evil.com") == null);
    try testing.expect(matchManagedHost(&managed, "") == null);
    try testing.expect(matchManagedHost(&managed, null) == null);
    try testing.expect(matchManagedHost(&managed, "sub.a.example.com") == null);
}
