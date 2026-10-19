//! Bounded TLS-ALPN-01 authorization selection state (#932, A6 of #759).
//!
//! This is deliberately a small seam between ACME order ownership and a
//! future native TLS ClientHello hook. It neither constructs the RFC 8737
//! validation certificate nor knows about a TLS credential provider. Instead,
//! it retains a short-lived, host-bound opaque material blob and returns an
//! owned snapshot only when the ClientHello is unambiguously a TLS-ALPN-01
//! validation attempt. A returned `Lease` is independent of the registry, so
//! cancellation or reload can never invalidate material an in-flight
//! handshake has already selected.

const std = @import("std");
const compat = @import("zig_compat");
const crypto = @import("crypto");
const names = @import("names.zig");

pub const protocol = "acme-tls/1";
pub const max_entries: usize = 64;
pub const max_material_len: usize = 64 * 1024;
pub const default_ttl_s: i64 = 10 * 60;

pub const Binding = [32]u8;

pub const PutError = error{
    OutOfMemory,
    InvalidHost,
    InvalidMaterial,
    InvalidExpiry,
    DuplicateHost,
    StoreFull,
};

pub const LookupError = error{OutOfMemory};

pub const CloseOutcome = enum { closed, not_found };

/// An owned, immutable handshake selection. `material` is challenge-private
/// and must be deinitialized after the handshake consumes it.
pub const Lease = struct {
    allocator: std.mem.Allocator,
    host: []u8,
    binding: Binding,
    material: []u8,
    expires_at: i64,

    pub fn deinit(self: *Lease) void {
        self.allocator.free(self.host);
        crypto.secrets.secureZeroAndFree(self.allocator, self.material);
        self.* = undefined;
    }
};

const Slot = struct {
    host: []u8,
    binding: Binding,
    material: []u8,
    expires_at: i64,
};

/// Fixed-capacity registry of live TLS-ALPN-01 authorizations. It accepts
/// only canonical ACME managed names, which makes exact byte equality a safe
/// SNI identity check rather than a case-folding or suffix-match policy.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    slots: std.ArrayList(Slot) = .empty,

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Registry) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.slots.items) |*slot| self.freeSlot(slot);
        self.slots.deinit(self.allocator);
    }

    /// Activates one authorization. A host may have only one live challenge;
    /// rejecting a replacement is intentional: an order retry must cancel its
    /// old authorization before it can publish new validation material.
    pub fn put(
        self: *Registry,
        now: i64,
        host: []const u8,
        binding: Binding,
        material: []const u8,
        expires_at: i64,
    ) PutError!void {
        names.validateName(host, true) catch return error.InvalidHost;
        if (material.len == 0 or material.len > max_material_len) return error.InvalidMaterial;

        const ttl_end = std.math.add(i64, now, default_ttl_s) catch std.math.maxInt(i64);
        const effective_expiry = @min(expires_at, ttl_end);
        if (effective_expiry <= now) return error.InvalidExpiry;

        self.mutex.lock();
        defer self.mutex.unlock();
        self.expireLocked(now);
        if (self.findIndex(host) != null) return error.DuplicateHost;
        if (self.slots.items.len >= max_entries) return error.StoreFull;

        const owned_host = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(owned_host);
        const owned_material = try self.allocator.dupe(u8, material);
        errdefer crypto.secrets.secureZeroAndFree(self.allocator, owned_material);
        try self.slots.append(self.allocator, .{
            .host = owned_host,
            .binding = binding,
            .material = owned_material,
            .expires_at = effective_expiry,
        });
    }

    /// Returns an independent, owned lease only for a ClientHello that offers
    /// precisely `acme-tls/1`. The RFC 8737 validation client must not offer
    /// ordinary HTTP ALPNs alongside it; enforcing that here prevents a
    /// normal HTTPS ClientHello from accidentally receiving a validation
    /// credential merely because it appended the special protocol.
    pub fn lookup(
        self: *Registry,
        allocator: std.mem.Allocator,
        now: i64,
        server_name: ?[]const u8,
        offered_alpn: []const []const u8,
    ) LookupError!?Lease {
        const host = server_name orelse return null;
        if (!isChallengeAlpnOffer(offered_alpn)) return null;

        self.mutex.lock();
        defer self.mutex.unlock();
        self.expireLocked(now);
        const index = self.findIndex(host) orelse return null;
        const slot = self.slots.items[index];
        const owned_host = try allocator.dupe(u8, slot.host);
        errdefer allocator.free(owned_host);
        const owned_material = try allocator.dupe(u8, slot.material);
        return .{
            .allocator = allocator,
            .host = owned_host,
            .binding = slot.binding,
            .material = owned_material,
            .expires_at = slot.expires_at,
        };
    }

    /// Cancels a pending authorization, but only if it is still owned by
    /// `expected_binding`. The comparison happens under the same lock as the
    /// removal, so a delayed cancellation from a retired order can never
    /// destroy a replacement order's live challenge for the same host. A
    /// previously returned lease remains valid because it owns a copy, while
    /// every later lookup fails closed.
    pub fn remove(self: *Registry, host: []const u8, expected_binding: Binding) CloseOutcome {
        self.mutex.lock();
        defer self.mutex.unlock();
        const index = self.findIndex(host) orelse return .not_found;
        if (!std.mem.eql(u8, self.slots.items[index].binding[0..], expected_binding[0..]))
            return .not_found;
        var removed = self.slots.swapRemove(index);
        self.freeSlot(&removed);
        return .closed;
    }

    pub fn expire(self: *Registry, now: i64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.expireLocked(now);
    }

    fn freeSlot(self: *Registry, slot: *Slot) void {
        self.allocator.free(slot.host);
        crypto.secrets.secureZeroAndFree(self.allocator, slot.material);
    }

    fn findIndex(self: *Registry, host: []const u8) ?usize {
        for (self.slots.items, 0..) |slot, index| {
            if (std.mem.eql(u8, slot.host, host)) return index;
        }
        return null;
    }

    fn expireLocked(self: *Registry, now: i64) void {
        var index: usize = 0;
        while (index < self.slots.items.len) {
            if (self.slots.items[index].expires_at <= now) {
                var removed = self.slots.swapRemove(index);
                self.freeSlot(&removed);
            } else {
                index += 1;
            }
        }
    }
};

fn isChallengeAlpnOffer(offered_alpn: []const []const u8) bool {
    return offered_alpn.len == 1 and std.mem.eql(u8, offered_alpn[0], protocol);
}

const testing = std.testing;

const binding_a: Binding = [_]u8{0xA5} ** 32;
const binding_b: Binding = [_]u8{0x5A} ** 32;

test "TLS-ALPN registry selects only exact SNI and exclusive acme ALPN" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.put(100, "a.example.test", binding_a, "validation-cert-and-key", 200);

    const challenge_alpn = [_][]const u8{protocol};
    var lease = (try registry.lookup(testing.allocator, 101, "a.example.test", &challenge_alpn)).?;
    defer lease.deinit();
    try testing.expectEqualStrings("a.example.test", lease.host);
    try testing.expectEqual(binding_a, lease.binding);
    try testing.expectEqualStrings("validation-cert-and-key", lease.material);

    try testing.expect((try registry.lookup(testing.allocator, 101, "b.example.test", &challenge_alpn)) == null);
    try testing.expect((try registry.lookup(testing.allocator, 101, null, &challenge_alpn)) == null);
    const h2 = [_][]const u8{"h2"};
    try testing.expect((try registry.lookup(testing.allocator, 101, "a.example.test", &h2)) == null);
    const mixed = [_][]const u8{ "h2", protocol };
    try testing.expect((try registry.lookup(testing.allocator, 101, "a.example.test", &mixed)) == null);
}

test "TLS-ALPN registry expiry, cancellation, and leases are independent" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    const challenge_alpn = [_][]const u8{protocol};

    try registry.put(0, "a.example.test", binding_a, "first", 600);
    var lease = (try registry.lookup(testing.allocator, 1, "a.example.test", &challenge_alpn)).?;
    defer lease.deinit();
    try testing.expectEqual(.closed, registry.remove("a.example.test", binding_a));
    try testing.expect((try registry.lookup(testing.allocator, 1, "a.example.test", &challenge_alpn)) == null);
    try testing.expectEqualStrings("first", lease.material);

    try registry.put(0, "a.example.test", binding_b, "second", 2);
    try testing.expect((try registry.lookup(testing.allocator, 2, "a.example.test", &challenge_alpn)) == null);
    try testing.expectEqual(.not_found, registry.remove("a.example.test", binding_b));
}

test "TLS-ALPN registry rejects conflicting, malformed, and excessive challenges" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    try testing.expectError(error.InvalidHost, registry.put(0, "A.example.test", binding_a, "value", 1));
    try testing.expectError(error.InvalidMaterial, registry.put(0, "a.example.test", binding_a, "", 1));
    try testing.expectError(error.InvalidExpiry, registry.put(0, "a.example.test", binding_a, "value", 0));
    try registry.put(0, "a.example.test", binding_a, "value", 1);
    try testing.expectError(error.DuplicateHost, registry.put(0, "a.example.test", binding_b, "other", 1));

    _ = registry.remove("a.example.test", binding_a);
    var host_buf: [64]u8 = undefined;
    for (0..max_entries) |index| {
        const host = try std.fmt.bufPrint(&host_buf, "h{d}.example.test", .{index});
        try registry.put(0, host, binding_a, "value", 1);
    }
    try testing.expectError(error.StoreFull, registry.put(0, "overflow.example.test", binding_a, "value", 1));
}

test "TLS-ALPN registry cancellation is scoped to the owning binding" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    const challenge_alpn = [_][]const u8{protocol};

    // A mismatched binding cannot cancel an active challenge.
    try registry.put(0, "a.example.test", binding_a, "first", 600);
    try testing.expectEqual(.not_found, registry.remove("a.example.test", binding_b));
    {
        var lease = (try registry.lookup(testing.allocator, 1, "a.example.test", &challenge_alpn)).?;
        defer lease.deinit();
        try testing.expectEqual(binding_a, lease.binding);
        try testing.expectEqualStrings("first", lease.material);
    }

    // The owning binding cancels it.
    try testing.expectEqual(.closed, registry.remove("a.example.test", binding_a));

    // Stale cancellation from the retired order cannot retire its replacement.
    try registry.put(0, "a.example.test", binding_b, "second", 600);
    try testing.expectEqual(.not_found, registry.remove("a.example.test", binding_a));
    var lease = (try registry.lookup(testing.allocator, 1, "a.example.test", &challenge_alpn)).?;
    defer lease.deinit();
    try testing.expectEqual(binding_b, lease.binding);
    try testing.expectEqualStrings("second", lease.material);
}

test "TLS-ALPN registry wipes secret material on remove, expire, deinit, and lease release" {
    var detector = crypto.secrets.CredentialWipeDetector.init(testing.allocator);
    const allocator = detector.allocator();
    const challenge_alpn = [_][]const u8{protocol};

    var registry = Registry.init(allocator);
    try registry.put(0, "a.example.test", binding_a, "remove-secret", 600);
    try registry.put(0, "b.example.test", binding_a, "expire-secret", 5);
    try registry.put(0, "c.example.test", binding_a, "deinit-secret", 600);
    for (registry.slots.items) |slot| detector.watch(slot.material);

    var lease = (try registry.lookup(allocator, 1, "c.example.test", &challenge_alpn)).?;
    detector.watch(lease.material);

    try testing.expectEqual(.closed, registry.remove("a.example.test", binding_a));
    registry.expire(5);
    try testing.expectEqual(@as(usize, 1), registry.slots.items.len);
    registry.deinit();
    lease.deinit();
    try testing.expect(detector.allWatchedWiped());
}

test "TLS-ALPN registry rolls back cleanly on allocator failure" {
    const challenge_alpn = [_][]const u8{protocol};

    // put allocates host, material, then the slot list entry.
    for (0..3) |fail_index| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        var registry = Registry.init(failing.allocator());
        defer registry.deinit();
        try testing.expectError(error.OutOfMemory, registry.put(0, "a.example.test", binding_a, "value", 600));
        try testing.expectEqual(@as(usize, 0), registry.slots.items.len);
    }

    // lookup allocates host then material; neither failure leaks or mutates.
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.put(0, "a.example.test", binding_a, "value", 600);
    for (0..2) |fail_index| {
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        try testing.expectError(
            error.OutOfMemory,
            registry.lookup(failing.allocator(), 1, "a.example.test", &challenge_alpn),
        );
        try testing.expectEqual(@as(usize, 1), registry.slots.items.len);
    }
}

test "TLS-ALPN registry concurrent lookup, retirement, and reactivation stay generation-consistent" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();

    const generations: u8 = 200;

    // Each generation's binding and material are the same repeated byte, so a
    // lease mixing two generations is detectable.
    const Shared = struct {
        registry: *Registry,
        failures: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        fn fail(self: *@This()) void {
            _ = self.failures.fetchAdd(1, .monotonic);
        }

        fn reader(self: *@This(), host: []const u8) void {
            const challenge_alpn = [_][]const u8{protocol};
            while (!self.done.load(.acquire)) {
                const maybe = self.registry.lookup(testing.allocator, 1, host, &challenge_alpn) catch {
                    self.fail();
                    return;
                };
                var lease = maybe orelse continue;
                defer lease.deinit();
                const gen = lease.binding[0];
                for (lease.binding) |byte| if (byte != gen) self.fail();
                if (lease.material.len != 32) self.fail();
                for (lease.material) |byte| if (byte != gen) self.fail();
                if (!std.mem.eql(u8, lease.host, host)) self.fail();
            }
        }

        // Sole owner of host a: retire/replace generations, and issue stale
        // cancellations from the previous generation after each replacement.
        fn owner(self: *@This()) void {
            var previous: Binding = @splat(0);
            var gen: u8 = 1;
            while (gen <= generations) : (gen += 1) {
                const binding: Binding = @splat(gen);
                const material: [32]u8 = @splat(gen);
                self.registry.put(0, "a.example.test", binding, &material, 600) catch {
                    self.fail();
                    return;
                };
                if (gen > 1 and self.registry.remove("a.example.test", previous) != .not_found) self.fail();
                if (self.registry.remove("a.example.test", @as(Binding, @splat(0))) != .not_found) self.fail();
                const challenge_alpn = [_][]const u8{protocol};
                const check = self.registry.lookup(testing.allocator, 1, "a.example.test", &challenge_alpn) catch {
                    self.fail();
                    return;
                };
                if (check) |c| {
                    var lease = c;
                    defer lease.deinit();
                    if (!std.mem.eql(u8, &lease.binding, &binding)) self.fail();
                } else self.fail();
                if (self.registry.remove("a.example.test", binding) != .closed) self.fail();
                previous = binding;
            }
        }

        // Host b challenges are retired by expiry rather than cancellation.
        fn expirer(self: *@This()) void {
            var now: i64 = 0;
            while (now < generations) : (now += 1) {
                const gen: u8 = @intCast(now + 1);
                const material: [32]u8 = @splat(gen);
                self.registry.put(now, "b.example.test", @as(Binding, @splat(gen)), &material, now + 1) catch {
                    self.fail();
                    return;
                };
                self.registry.expire(now + 1);
            }
        }
    };

    var shared = Shared{ .registry = &registry };
    var readers: [3]std.Thread = undefined;
    readers[0] = try std.Thread.spawn(.{}, Shared.reader, .{ &shared, "a.example.test" });
    readers[1] = try std.Thread.spawn(.{}, Shared.reader, .{ &shared, "a.example.test" });
    readers[2] = try std.Thread.spawn(.{}, Shared.reader, .{ &shared, "b.example.test" });
    const owner = try std.Thread.spawn(.{}, Shared.owner, .{&shared});
    const expirer = try std.Thread.spawn(.{}, Shared.expirer, .{&shared});
    owner.join();
    expirer.join();
    shared.done.store(true, .release);
    for (readers) |t| t.join();

    try testing.expectEqual(@as(u32, 0), shared.failures.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), registry.slots.items.len);
}
