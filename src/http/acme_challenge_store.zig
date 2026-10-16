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
const dns_name = @import("tls_core").dns_name;

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
    /// `expires_at` (after the ten-minute cap is applied) is at or before
    /// `now`: there is no live window left to admit, so nothing is retained.
    InvalidExpiry,
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
        if (!isValidManagedHost(host)) return error.InvalidHost;
        if (!isValidToken(token)) return error.InvalidToken;
        if (key_authorization.len == 0 or key_authorization.len > max_key_authorization_len) {
            return error.InvalidKeyAuthorization;
        }

        // Ten minutes or the CA's own (shorter) authorization deadline,
        // whichever ends first (design §8.2/§9.1) -- applied once here so
        // neither admission path can retain material past the policy
        // window, however large a deadline a caller passes.
        const ttl_end = std.math.add(i64, now, default_ttl_s) catch std.math.maxInt(i64);
        const effective_expiry = @min(expires_at, ttl_end);
        if (effective_expiry <= now) return error.InvalidExpiry;

        self.mutex.lock();
        defer self.mutex.unlock();
        self.expireLocked(now);

        if (self.findIndex(host, token)) |i| {
            const owned_value = try self.allocator.dupe(u8, key_authorization);
            secrets.secureZeroAndFree(self.allocator, self.slots.items[i].value);
            self.slots.items[i].value = owned_value;
            self.slots.items[i].expires_at = effective_expiry;
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
            .expires_at = effective_expiry,
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

    /// Store-key gate for `host`: a single, already-canonical-lowercase DNS
    /// name, the same shape `acme/names.zig` requires for a managed
    /// hostname (#877). `dns_name.validateHostName` alone already rejects
    /// userinfo, ports, wildcards, and brackets -- none of those characters
    /// are valid DNS label bytes -- so this only adds the canonical-case and
    /// non-IP-literal checks `matchManagedHost`'s configured `managed_hosts`
    /// set doesn't need (it is validated once at config time instead).
    /// Rejecting rather than normalizing here keeps `findIndex`'s
    /// case-sensitive comparison safe: two spellings of the same host can
    /// never both be admitted into separate slots.
    fn isValidManagedHost(host: []const u8) bool {
        dns_name.validateHostName(host) catch return false;
        for (host) |c| if (c >= 'A' and c <= 'Z') return false;
        if (isAllDigitLabels(host)) return false;
        return true;
    }

    /// Every label purely numeric: covers dotted-quad IPv4 literals, which
    /// are not valid ACME managed-hostname identifiers.
    fn isAllDigitLabels(host: []const u8) bool {
        var it = std.mem.splitScalar(u8, host, '.');
        while (it.next()) |label| {
            for (label) |c| if (c < '0' or c > '9') return false;
        }
        return true;
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
    // `[]@/\?#` and raw control bytes are rejected outright rather than
    // parsed: brackets are an IPv6-literal marker, never valid around a DNS
    // name, and this matcher is DNS-names-only (`acme/names.zig` forbids IP
    // literals for managed hosts), so a bracketed authority is malformed
    // input, not a literal to unwrap. `Request.parseAuthority` (a general
    // HTTP authority parser) accepts bracket content it never validates as
    // an IP literal, so this check -- not that parser -- is this matcher's
    // only defense against a bracketed DNS name.
    for (trimmed) |c| {
        if (c < 0x20 or std.mem.indexOfScalar(u8, "[]@/\\?#", c) != null) return null;
    }
    const without_port = stripPort(trimmed) orelse return null;
    if (without_port.len == 0) return null;
    for (managed_hosts) |candidate| {
        if (std.ascii.eqlIgnoreCase(candidate, without_port)) return candidate;
    }
    return null;
}

/// Strips an optional `:port` suffix from an already-bracket/control-byte-free
/// Host/authority value. At most one colon is permitted, and the port (if
/// present) must be a nonempty run of digits that fits in a `u16`; anything
/// else is a malformed authority, not a value to pass through unstripped.
/// Deliberately re-implemented rather than imported from
/// `edge_config.stripHostPort` so this file keeps its original #379
/// zero-dependency property (no `edge_config`/`http` import graph), which is
/// what lets it be reached from both the OpenSSL and no-OpenSSL profiles.
fn stripPort(host: []const u8) ?[]const u8 {
    const colon = std.mem.indexOfScalar(u8, host, ':') orelse return host;
    if (std.mem.indexOfScalar(u8, host[colon + 1 ..], ':') != null) return null;
    const head = host[0..colon];
    const port = host[colon + 1 ..];
    if (port.len == 0) return null;
    for (port) |c| if (c < '0' or c > '9') return null;
    _ = std.fmt.parseInt(u16, port, 10) catch return null;
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

test "ChallengeStore put rejects a non-canonical or malformed host before allocating anything (#877 review)" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var store = ChallengeStore.init(failing.allocator());
    defer store.deinit();

    // Userinfo, mixed case, wildcard, port, IPv4 literal, and a bracketed
    // name are all rejected -- none of them is the canonical managed-DNS
    // key `matchManagedHost` would hand this API.
    try testing.expectError(error.InvalidHost, store.put(0, "user@a.example.com", "abcdefghijklmnop", "value", 600));
    try testing.expectError(error.InvalidHost, store.put(0, "A.Example.Com", "abcdefghijklmnop", "value", 600));
    try testing.expectError(error.InvalidHost, store.put(0, "*.example.com", "abcdefghijklmnop", "value", 600));
    try testing.expectError(error.InvalidHost, store.put(0, "a.example.com:443", "abcdefghijklmnop", "value", 600));
    try testing.expectError(error.InvalidHost, store.put(0, "192.168.1.1", "abcdefghijklmnop", "value", 600));
    try testing.expectError(error.InvalidHost, store.put(0, "[a.example.com]", "abcdefghijklmnop", "value", 600));

    // `fail_index = 0` means the very first allocation attempt fails, so
    // these rejections happening without error.OutOfMemory proves they were
    // caught before any allocation was attempted.
    try testing.expectEqual(@as(usize, 0), store.slots.items.len);
}

test "ChallengeStore never admits two case spellings of the same host into separate slots (#877 review)" {
    var store = ChallengeStore.init(testing.allocator);
    defer store.deinit();

    try store.put(0, "a.example.com", "abcdefghijklmnop", "value", 600);
    // A non-canonical spelling of the same name is rejected outright, not
    // normalized into (and so never collides with) the existing slot.
    try testing.expectError(error.InvalidHost, store.put(0, "A.Example.Com", "abcdefghijklmnop", "other-value", 600));
    try testing.expectEqual(@as(usize, 1), store.slots.items.len);
    try testing.expect(store.getCopy(testing.allocator, 0, "A.Example.Com", "abcdefghijklmnop") == null);
}

test "ChallengeStore put caps a CA deadline far beyond the default ten-minute window (#877 review)" {
    var store = ChallengeStore.init(testing.allocator);
    defer store.deinit();

    try store.put(0, "a.example.com", "abcdefghijklmnop", "value", 86400);

    const still_live = store.getCopy(testing.allocator, default_ttl_s - 1, "a.example.com", "abcdefghijklmnop").?;
    testing.allocator.free(still_live);
    // At and beyond the ten-minute boundary the entry is gone, regardless of
    // the far-future deadline the caller originally asked for.
    try testing.expect(store.getCopy(testing.allocator, default_ttl_s, "a.example.com", "abcdefghijklmnop") == null);
    try testing.expect(store.getCopy(testing.allocator, default_ttl_s + 1, "a.example.com", "abcdefghijklmnop") == null);
}

test "ChallengeStore put honors a CA deadline shorter than the default window (#877 review)" {
    var store = ChallengeStore.init(testing.allocator);
    defer store.deinit();

    try store.put(0, "a.example.com", "abcdefghijklmnop", "value", 120);

    const still_live = store.getCopy(testing.allocator, 119, "a.example.com", "abcdefghijklmnop").?;
    testing.allocator.free(still_live);
    try testing.expect(store.getCopy(testing.allocator, 120, "a.example.com", "abcdefghijklmnop") == null);
}

test "ChallengeStore duplicate replacement re-applies the ten-minute cap against the new now (#877 review)" {
    var store = ChallengeStore.init(testing.allocator);
    defer store.deinit();

    // First insertion: still live when the replacement below runs, so the
    // second `put` genuinely replaces it in place rather than re-inserting
    // into an already-expired slot.
    try store.put(0, "a.example.com", "abcdefghijklmnop", "first", 86400);
    // Replacing at a later `now` re-derives the cap from that `now`, not
    // from the original insertion time or the first deadline.
    try store.put(50, "a.example.com", "abcdefghijklmnop", "second", 86400);

    try testing.expectEqual(@as(usize, 1), store.slots.items.len);
    const still_live = store.getCopy(testing.allocator, 50 + default_ttl_s - 1, "a.example.com", "abcdefghijklmnop").?;
    defer testing.allocator.free(still_live);
    try testing.expectEqualStrings("second", still_live);
    try testing.expect(store.getCopy(testing.allocator, 50 + default_ttl_s, "a.example.com", "abcdefghijklmnop") == null);
}

test "ChallengeStore put rejects a deadline at or before now without retaining bytes (#877 review)" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var store = ChallengeStore.init(failing.allocator());
    defer store.deinit();

    try testing.expectError(error.InvalidExpiry, store.put(100, "a.example.com", "abcdefghijklmnop", "value", 100));
    try testing.expectError(error.InvalidExpiry, store.put(100, "a.example.com", "abcdefghijklmnop", "value", 50));
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

test "matchManagedHost rejects malformed authorities rather than unbracketing or truncating them (#877 review)" {
    const managed = [_][]const u8{"a.example.com"};

    // Brackets are an IPv6-literal marker; this matcher is DNS-names-only,
    // so a bracketed DNS name is rejected outright, never unwrapped.
    try testing.expect(matchManagedHost(&managed, "[a.example.com]") == null);
    try testing.expect(matchManagedHost(&managed, "[a.example.com]garbage") == null);
    // A non-numeric or out-of-range port, a dangling colon, and a second
    // colon are all malformed rather than a value to pass through.
    try testing.expect(matchManagedHost(&managed, "a.example.com:garbage") == null);
    try testing.expect(matchManagedHost(&managed, "a.example.com:") == null);
    try testing.expect(matchManagedHost(&managed, "a.example.com:1:2") == null);
    try testing.expect(matchManagedHost(&managed, "a.example.com:99999") == null);

    // `Request.parseAuthority` (`http/request.zig`, a general HTTP
    // authority parser this file deliberately does not import -- see the
    // module doc comment) accepts any nonempty bracket content as a host
    // without validating it is actually an IP literal, so a parsed
    // request's Host header can still carry this shape at the production
    // boundary. `edge_gateway.zig`'s own test suite covers that boundary
    // with an actual parsed request, since it already imports both sides.
}
