const std = @import("std");
const Allocator = std.mem.Allocator;

/// Represents an IPv4 or IPv6 address as raw bytes.
pub const IpAddress = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

    pub fn eql(self: IpAddress, other: IpAddress) bool {
        return switch (self) {
            .v4 => |a| switch (other) {
                .v4 => |b| std.mem.eql(u8, &a, &b),
                .v6 => false,
            },
            .v6 => |a| switch (other) {
                .v4 => false,
                .v6 => |b| std.mem.eql(u8, &a, &b),
            },
        };
    }
};

/// A CIDR block for matching IP ranges.
pub const CidrBlock = struct {
    address: IpAddress,
    prefix_len: u8,

    /// Check if a given IP address falls within this CIDR block.
    pub fn contains(self: CidrBlock, ip: IpAddress) bool {
        return switch (self.address) {
            .v4 => |net_bytes| switch (ip) {
                .v4 => |ip_bytes| matchPrefix(&net_bytes, &ip_bytes, self.prefix_len),
                .v6 => false,
            },
            .v6 => |net_bytes| switch (ip) {
                .v4 => false,
                .v6 => |ip_bytes| matchPrefix(&net_bytes, &ip_bytes, self.prefix_len),
            },
        };
    }
};

/// Bit-level prefix comparison.
fn matchPrefix(net: []const u8, ip: []const u8, prefix_len: u8) bool {
    if (net.len != ip.len) return false;

    const full_bytes = prefix_len / 8;
    if (full_bytes > net.len) return false;

    // Compare full bytes
    if (!std.mem.eql(u8, net[0..full_bytes], ip[0..full_bytes])) return false;

    // Compare remaining bits
    const remaining_bits = prefix_len % 8;
    if (remaining_bits > 0 and full_bytes < net.len) {
        const mask: u8 = @as(u8, 0xFF) << @intCast(8 - remaining_bits);
        if ((net[full_bytes] & mask) != (ip[full_bytes] & mask)) return false;
    }

    return true;
}

/// An access control rule: allow or deny an IP/CIDR.
pub const Rule = struct {
    cidr: CidrBlock,
    action: Action,
};

pub const Action = enum {
    allow,
    deny,
};

/// Result of an access check.
pub const AccessResult = enum {
    allowed,
    denied,
    no_match,
};

/// IP-based access control list.
///
/// Rules are evaluated in order (first match wins), similar to
/// nginx's allow/deny directives. If no rule matches, the
/// default_action applies.
pub const AccessControl = struct {
    rules: []const Rule,
    default_action: Action,
    allocator: Allocator,

    pub fn init(allocator: Allocator, default_action: Action) AccessControl {
        return .{
            .rules = &[_]Rule{},
            .default_action = default_action,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AccessControl) void {
        if (self.rules.len > 0) {
            self.allocator.free(self.rules);
        }
    }

    /// Build the access control list from a configuration string.
    ///
    /// Format: comma-separated rules, each is "allow <CIDR>" or "deny <CIDR>".
    /// Example: "allow 10.0.0.0/8, deny 192.168.1.0/24, allow 0.0.0.0/0"
    pub fn fromConfig(allocator: Allocator, config: []const u8, default_action: Action) !AccessControl {
        var rules = std.ArrayList(Rule).empty;
        errdefer rules.deinit(allocator);

        var it = std.mem.splitScalar(u8, config, ',');
        while (it.next()) |part| {
            const trimmed = std.mem.trim(u8, part, " \t\r\n");
            if (trimmed.len == 0) continue;

            const rule = try parseRule(trimmed);
            try rules.append(allocator, rule);
        }

        return .{
            .rules = try rules.toOwnedSlice(allocator),
            .default_action = default_action,
            .allocator = allocator,
        };
    }

    /// Check if the given IP string is allowed.
    pub fn check(self: *const AccessControl, ip_str: []const u8) AccessResult {
        const ip = parseIp(ip_str) orelse return switch (self.default_action) {
            .allow => .allowed,
            .deny => .denied,
        };

        for (self.rules) |rule| {
            if (rule.cidr.contains(ip)) {
                return switch (rule.action) {
                    .allow => .allowed,
                    .deny => .denied,
                };
            }
        }

        return switch (self.default_action) {
            .allow => .allowed,
            .deny => .denied,
        };
    }
};

/// Parse a single rule like "allow 10.0.0.0/8" or "deny 192.168.1.100".
fn parseRule(s: []const u8) !Rule {
    // Find the space between action and CIDR
    const space = std.mem.findScalar(u8, s, ' ') orelse return error.InvalidRule;
    const action_str = s[0..space];
    const cidr_str = std.mem.trim(u8, s[space + 1 ..], " \t");

    const action: Action = if (std.mem.eql(u8, action_str, "allow"))
        .allow
    else if (std.mem.eql(u8, action_str, "deny"))
        .deny
    else
        return error.InvalidAction;

    const cidr = parseCidr(cidr_str) orelse return error.InvalidCidr;

    return .{ .cidr = cidr, .action = action };
}

/// Parse a CIDR string like "10.0.0.0/8" or a plain IP like "192.168.1.1".
/// Plain IPs get /32 (IPv4) or /128 (IPv6) prefix.
pub fn parseCidr(s: []const u8) ?CidrBlock {
    if (std.mem.findScalar(u8, s, '/')) |slash| {
        const ip_part = s[0..slash];
        const prefix_str = s[slash + 1 ..];
        const prefix_len = std.fmt.parseInt(u8, prefix_str, 10) catch return null;

        const ip = parseIp(ip_part) orelse return null;

        // Validate prefix length
        switch (ip) {
            .v4 => if (prefix_len > 32) return null,
            .v6 => if (prefix_len > 128) return null,
        }

        return .{ .address = ip, .prefix_len = prefix_len };
    } else {
        // Plain IP — treat as single host
        const ip = parseIp(s) orelse return null;
        return .{
            .address = ip,
            .prefix_len = switch (ip) {
                .v4 => 32,
                .v6 => 128,
            },
        };
    }
}

/// Parse an IPv4 or IPv6 address string into raw bytes.
pub fn parseIp(s: []const u8) ?IpAddress {
    // Try IPv4 first
    if (parseIpv4(s)) |bytes| return .{ .v4 = bytes };
    // Try IPv6
    if (parseIpv6(s)) |bytes| return .{ .v6 = bytes };
    return null;
}

fn parseIpv4(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |part| {
        if (octet_idx >= 4) return null;
        const val = std.fmt.parseInt(u8, part, 10) catch return null;
        result[octet_idx] = val;
        octet_idx += 1;
    }
    if (octet_idx != 4) return null;
    return result;
}

fn parseIpv6(s: []const u8) ?[16]u8 {
    // Simplified IPv6 parsing: support full form and :: shorthand
    var result: [16]u8 = .{0} ** 16;

    // Handle :: expansion
    if (std.mem.find(u8, s, "::")) |dcolon_pos| {
        // Parse before ::
        var before_count: usize = 0;
        if (dcolon_pos > 0) {
            var it = std.mem.splitScalar(u8, s[0..dcolon_pos], ':');
            while (it.next()) |part| {
                if (before_count >= 8) return null;
                const val = std.fmt.parseInt(u16, part, 16) catch return null;
                result[before_count * 2] = @intCast(val >> 8);
                result[before_count * 2 + 1] = @intCast(val & 0xFF);
                before_count += 1;
            }
        }

        // Parse after ::
        const after_start = dcolon_pos + 2;
        if (after_start < s.len) {
            var after_groups: [8]u16 = .{0} ** 8;
            var after_count: usize = 0;
            var it = std.mem.splitScalar(u8, s[after_start..], ':');
            while (it.next()) |part| {
                if (after_count >= 8) return null;
                after_groups[after_count] = std.fmt.parseInt(u16, part, 16) catch return null;
                after_count += 1;
            }

            if (before_count + after_count > 8) return null;

            // Place after groups at the end
            const offset = 8 - after_count;
            for (0..after_count) |i| {
                result[(offset + i) * 2] = @intCast(after_groups[i] >> 8);
                result[(offset + i) * 2 + 1] = @intCast(after_groups[i] & 0xFF);
            }
        }

        return result;
    }

    // Full form: 8 groups
    var group_idx: usize = 0;
    var it = std.mem.splitScalar(u8, s, ':');
    while (it.next()) |part| {
        if (group_idx >= 8) return null;
        const val = std.fmt.parseInt(u16, part, 16) catch return null;
        result[group_idx * 2] = @intCast(val >> 8);
        result[group_idx * 2 + 1] = @intCast(val & 0xFF);
        group_idx += 1;
    }
    if (group_idx != 8) return null;
    return result;
}

// Tests

test "parseIp valid IPv4" {
    const ip = parseIp("192.168.1.100").?;
    try std.testing.expectEqual(IpAddress{ .v4 = .{ 192, 168, 1, 100 } }, ip);
}

test "parseIp valid IPv6 full" {
    const ip = parseIp("2001:0db8:0000:0000:0000:0000:0000:0001").?;
    switch (ip) {
        .v6 => |bytes| {
            try std.testing.expectEqual(@as(u8, 0x20), bytes[0]);
            try std.testing.expectEqual(@as(u8, 0x01), bytes[1]);
            try std.testing.expectEqual(@as(u8, 0x01), bytes[15]);
        },
        .v4 => return error.TestUnexpectedResult,
    }
}

test "parseIp valid IPv6 shorthand" {
    const ip = parseIp("::1").?;
    switch (ip) {
        .v6 => |bytes| {
            // All zeros except last byte
            for (bytes[0..15]) |b| try std.testing.expectEqual(@as(u8, 0), b);
            try std.testing.expectEqual(@as(u8, 1), bytes[15]);
        },
        .v4 => return error.TestUnexpectedResult,
    }
}

test "parseIp invalid" {
    try std.testing.expect(parseIp("not-an-ip") == null);
    try std.testing.expect(parseIp("999.999.999.999") == null);
    try std.testing.expect(parseIp("") == null);
}

test "parseCidr IPv4 with prefix" {
    const cidr = parseCidr("10.0.0.0/8").?;
    try std.testing.expectEqual(@as(u8, 8), cidr.prefix_len);
    switch (cidr.address) {
        .v4 => |bytes| try std.testing.expectEqual(@as(u8, 10), bytes[0]),
        .v6 => return error.TestUnexpectedResult,
    }
}

test "parseCidr plain IPv4 gets /32" {
    const cidr = parseCidr("192.168.1.1").?;
    try std.testing.expectEqual(@as(u8, 32), cidr.prefix_len);
}

test "parseCidr invalid prefix" {
    try std.testing.expect(parseCidr("10.0.0.0/33") == null);
}

test "CidrBlock contains matching IP" {
    const cidr = parseCidr("10.0.0.0/8").?;
    try std.testing.expect(cidr.contains(parseIp("10.1.2.3").?));
    try std.testing.expect(cidr.contains(parseIp("10.255.255.255").?));
    try std.testing.expect(!cidr.contains(parseIp("11.0.0.1").?));
    try std.testing.expect(!cidr.contains(parseIp("192.168.1.1").?));
}

test "CidrBlock /24 subnet" {
    const cidr = parseCidr("192.168.1.0/24").?;
    try std.testing.expect(cidr.contains(parseIp("192.168.1.0").?));
    try std.testing.expect(cidr.contains(parseIp("192.168.1.255").?));
    try std.testing.expect(!cidr.contains(parseIp("192.168.2.0").?));
}

test "CidrBlock /32 exact match" {
    const cidr = parseCidr("1.2.3.4/32").?;
    try std.testing.expect(cidr.contains(parseIp("1.2.3.4").?));
    try std.testing.expect(!cidr.contains(parseIp("1.2.3.5").?));
}

test "CidrBlock /0 matches all" {
    const cidr = parseCidr("0.0.0.0/0").?;
    try std.testing.expect(cidr.contains(parseIp("1.2.3.4").?));
    try std.testing.expect(cidr.contains(parseIp("255.255.255.255").?));
}

test "CidrBlock IPv4 does not match IPv6" {
    const cidr = parseCidr("10.0.0.0/8").?;
    try std.testing.expect(!cidr.contains(parseIp("::1").?));
}

test "AccessControl allow by default" {
    const allocator = std.testing.allocator;
    var acl = AccessControl.init(allocator, .allow);
    defer acl.deinit();

    try std.testing.expectEqual(AccessResult.allowed, acl.check("1.2.3.4"));
}

test "AccessControl deny by default" {
    const allocator = std.testing.allocator;
    var acl = AccessControl.init(allocator, .deny);
    defer acl.deinit();

    try std.testing.expectEqual(AccessResult.denied, acl.check("1.2.3.4"));
}

test "AccessControl fromConfig allow then deny" {
    const allocator = std.testing.allocator;
    var acl = try AccessControl.fromConfig(allocator, "allow 10.0.0.0/8, deny 0.0.0.0/0", .deny);
    defer acl.deinit();

    try std.testing.expectEqual(AccessResult.allowed, acl.check("10.1.2.3"));
    try std.testing.expectEqual(AccessResult.denied, acl.check("192.168.1.1"));
}

test "AccessControl fromConfig deny specific" {
    const allocator = std.testing.allocator;
    var acl = try AccessControl.fromConfig(allocator, "deny 192.168.1.0/24", .allow);
    defer acl.deinit();

    try std.testing.expectEqual(AccessResult.denied, acl.check("192.168.1.50"));
    try std.testing.expectEqual(AccessResult.allowed, acl.check("10.0.0.1"));
}

test "AccessControl first match wins" {
    const allocator = std.testing.allocator;
    var acl = try AccessControl.fromConfig(allocator, "allow 10.0.0.1, deny 10.0.0.0/8", .allow);
    defer acl.deinit();

    // 10.0.0.1 matches "allow" first
    try std.testing.expectEqual(AccessResult.allowed, acl.check("10.0.0.1"));
    // 10.0.0.2 matches "deny 10.0.0.0/8"
    try std.testing.expectEqual(AccessResult.denied, acl.check("10.0.0.2"));
}

test "AccessControl handles unparseable IP" {
    const allocator = std.testing.allocator;
    var acl = try AccessControl.fromConfig(allocator, "deny 10.0.0.0/8", .allow);
    defer acl.deinit();

    // Unparseable IP falls through to default
    try std.testing.expectEqual(AccessResult.allowed, acl.check("not-an-ip"));
}
