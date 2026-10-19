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

    /// Cancels a pending authorization. A previously returned lease remains
    /// valid because it owns a copy, while every later lookup fails closed.
    pub fn remove(self: *Registry, host: []const u8) CloseOutcome {
        self.mutex.lock();
        defer self.mutex.unlock();
        const index = self.findIndex(host) orelse return .not_found;
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
    try testing.expectEqual(.closed, registry.remove("a.example.test"));
    try testing.expect((try registry.lookup(testing.allocator, 1, "a.example.test", &challenge_alpn)) == null);
    try testing.expectEqualStrings("first", lease.material);

    try registry.put(0, "a.example.test", binding_b, "second", 2);
    try testing.expect((try registry.lookup(testing.allocator, 2, "a.example.test", &challenge_alpn)) == null);
    try testing.expectEqual(.not_found, registry.remove("a.example.test"));
}

test "TLS-ALPN registry rejects conflicting, malformed, and excessive challenges" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    try testing.expectError(error.InvalidHost, registry.put(0, "A.example.test", binding_a, "value", 1));
    try testing.expectError(error.InvalidMaterial, registry.put(0, "a.example.test", binding_a, "", 1));
    try testing.expectError(error.InvalidExpiry, registry.put(0, "a.example.test", binding_a, "value", 0));
    try registry.put(0, "a.example.test", binding_a, "value", 1);
    try testing.expectError(error.DuplicateHost, registry.put(0, "a.example.test", binding_b, "other", 1));

    _ = registry.remove("a.example.test");
    var host_buf: [64]u8 = undefined;
    for (0..max_entries) |index| {
        const host = try std.fmt.bufPrint(&host_buf, "h{d}.example.test", .{index});
        try registry.put(0, host, binding_a, "value", 1);
    }
    try testing.expectError(error.StoreFull, registry.put(0, "overflow.example.test", binding_a, "value", 1));
}
