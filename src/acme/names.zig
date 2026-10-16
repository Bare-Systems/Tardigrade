//! Managed-hostname grammar for automatic HTTPS (#832, design §4.2).
//!
//! `acme_domains` is a comma list of DNS names; `;` separates order groups
//! (one certificate per group). This module validates the grammar and the
//! bounds and reports counts; it allocates nothing and never resolves names.
//! Host-name syntax itself is `tls/dns_name.zig`, the validator the SNI
//! provider already uses, so an accepted name is always a valid SNI pattern.

const std = @import("std");
const dns_name = @import("tls_core").dns_name;

pub const max_names = 100;
pub const max_groups = 64;
pub const max_names_per_group = 16;

pub const Error = error{
    Empty,
    EmptyGroup,
    InvalidName,
    /// Wildcards need DNS-01, which is out of scope.
    WildcardUnsupported,
    IpLiteral,
    Duplicate,
    /// Names must already be canonical lowercase so order-group identity
    /// never depends on spelling case.
    NotLowercase,
    TooManyNames,
    TooManyGroups,
    GroupTooLarge,
    /// `localhost`, single-label, `.local`/`.internal`/`.test`/`.invalid`
    /// names are only meaningful against a private/test CA.
    PrivateNameForPublicCa,
};

pub const Summary = struct {
    names: usize,
    groups: usize,
};

/// `private_ca`: the directory URL is non-default *and* an explicit CA bundle
/// is configured (design §4.2), so test names are meaningful.
pub fn validate(raw: []const u8, private_ca: bool) Error!Summary {
    if (std.mem.trim(u8, raw, " \t\r\n").len == 0) return error.Empty;

    var seen: [max_names][dns_name.max_name_len]u8 = undefined;
    var seen_len: [max_names]u8 = undefined;
    var names: usize = 0;
    var groups: usize = 0;

    var group_it = std.mem.splitScalar(u8, raw, ';');
    while (group_it.next()) |group_text| {
        const trimmed_group = std.mem.trim(u8, group_text, " \t\r\n");
        // A trailing `;` is tolerated; an empty group in the middle is not.
        if (trimmed_group.len == 0) {
            if (group_it.peek() == null) break;
            return error.EmptyGroup;
        }
        groups += 1;
        if (groups > max_groups) return error.TooManyGroups;

        var in_group: usize = 0;
        var name_it = std.mem.splitScalar(u8, trimmed_group, ',');
        while (name_it.next()) |name_text| {
            const name = std.mem.trim(u8, name_text, " \t\r\n");
            if (name.len == 0) continue;
            try validateName(name, private_ca);

            names += 1;
            if (names > max_names) return error.TooManyNames;
            in_group += 1;
            if (in_group > max_names_per_group) return error.GroupTooLarge;

            // Names are canonical lowercase here, so equality is identity.
            for (0..names - 1) |i| {
                if (std.mem.eql(u8, seen[i][0..seen_len[i]], name)) return error.Duplicate;
            }
            @memcpy(seen[names - 1][0..name.len], name);
            seen_len[names - 1] = @intCast(name.len);
        }
        if (in_group == 0) return error.EmptyGroup;
    }
    if (names == 0) return error.Empty;
    return .{ .names = names, .groups = groups };
}

/// Per-name syntax, case, and IP-literal rules shared by `validate` and by
/// direct per-name callers (`csr.zig`) that need the same canonical-identity
/// guarantees without the grouping/count bookkeeping `validate` also does.
pub fn validateName(name: []const u8, private_ca: bool) Error!void {
    if (std.mem.indexOfScalar(u8, name, '*') != null) return error.WildcardUnsupported;
    dns_name.validateHostName(name) catch return error.InvalidName;
    for (name) |c| if (c >= 'A' and c <= 'Z') return error.NotLowercase;
    if (isIpv4Literal(name)) return error.IpLiteral;
    if (!private_ca and isPrivateName(name)) return error.PrivateNameForPublicCa;
}

/// Every label purely numeric (covers dotted quads and decimal forms).
fn isIpv4Literal(name: []const u8) bool {
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        for (label) |c| if (c < '0' or c > '9') return false;
    }
    return true;
}

fn isPrivateName(name: []const u8) bool {
    if (std.mem.indexOfScalar(u8, name, '.') == null) return true; // single label, incl. localhost
    const suffixes = [_][]const u8{ ".localhost", ".local", ".internal", ".test", ".invalid", ".example", ".lan", ".home.arpa" };
    for (suffixes) |suffix| {
        if (name.len > suffix.len and std.ascii.eqlIgnoreCase(name[name.len - suffix.len ..], suffix)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------

const testing = std.testing;

test "ACME names: accepts names and order groups" {
    const one = try validate("example.com", false);
    try testing.expectEqual(@as(usize, 1), one.names);
    try testing.expectEqual(@as(usize, 1), one.groups);
    const two = try validate("a.example.com, www.a.example.com ; b.example.com;", false);
    try testing.expectEqual(@as(usize, 3), two.names);
    try testing.expectEqual(@as(usize, 2), two.groups);
    try testing.expectError(error.NotLowercase, validate("Example.COM", false));
}

test "ACME names: rejects each invalid shape deterministically" {
    const cases = [_]struct { raw: []const u8, err: Error }{
        .{ .raw = "", .err = error.Empty },
        .{ .raw = "  ;  ", .err = error.EmptyGroup },
        .{ .raw = "a.example.com;;b.example.com", .err = error.EmptyGroup },
        .{ .raw = "*.example.com", .err = error.WildcardUnsupported },
        .{ .raw = "a.*.example.com", .err = error.WildcardUnsupported },
        .{ .raw = "example.com.", .err = error.InvalidName },
        .{ .raw = ".example.com", .err = error.InvalidName },
        .{ .raw = "exa mple.com", .err = error.InvalidName },
        .{ .raw = "ex_ample.com", .err = error.InvalidName },
        .{ .raw = "-a.example.com", .err = error.InvalidName },
        .{ .raw = "a..example.com", .err = error.InvalidName },
        .{ .raw = "xn--é.example.com", .err = error.InvalidName },
        .{ .raw = "192.168.1.1", .err = error.IpLiteral },
        .{ .raw = "8.8.8.8", .err = error.IpLiteral },
        .{ .raw = "[::1]", .err = error.InvalidName },
        .{ .raw = "localhost", .err = error.PrivateNameForPublicCa },
        .{ .raw = "intranet", .err = error.PrivateNameForPublicCa },
        .{ .raw = "host.local", .err = error.PrivateNameForPublicCa },
        .{ .raw = "host.internal", .err = error.PrivateNameForPublicCa },
        .{ .raw = "host.test", .err = error.PrivateNameForPublicCa },
        .{ .raw = "host.invalid", .err = error.PrivateNameForPublicCa },
        .{ .raw = "a.example.com,A.EXAMPLE.COM", .err = error.NotLowercase },
        .{ .raw = "a.example.com,a.example.com", .err = error.Duplicate },
        .{ .raw = "a.example.com;b.example.com;a.example.com", .err = error.Duplicate },
    };
    for (cases) |case| try testing.expectError(case.err, validate(case.raw, false));
}

test "ACME names: private names are allowed only with a private CA" {
    _ = try validate("localhost,host.test,intranet", true);
    // Syntax rules still apply.
    try testing.expectError(error.WildcardUnsupported, validate("*.test", true));
    try testing.expectError(error.IpLiteral, validate("10.0.0.1", true));
}

test "ACME names: count and group bounds are exact" {
    var buf: [8192]u8 = undefined;
    var len: usize = 0;
    for (0..max_names) |i| {
        // One group per 16 names.
        const sep: []const u8 = if (i == 0) "" else if (i % max_names_per_group == 0) ";" else ",";
        len += (try std.fmt.bufPrint(buf[len..], "{s}h{d}.example.com", .{ sep, i })).len;
    }
    const full = try validate(buf[0..len], false);
    try testing.expectEqual(@as(usize, max_names), full.names);

    len += (try std.fmt.bufPrint(buf[len..], ",extra.example.com", .{})).len;
    try testing.expectError(error.TooManyNames, validate(buf[0..len], false));

    // 101 names in groups of one: too many names (not too many groups).
    len = 0;
    for (0..max_names + 1) |i| {
        const sep: []const u8 = if (i == 0) "" else ";";
        len += (try std.fmt.bufPrint(buf[len..], "{s}h{d}.example.com", .{ sep, i })).len;
    }
    try testing.expectError(error.TooManyGroups, validate(buf[0..len], false));

    // 17 in one group.
    len = 0;
    for (0..max_names_per_group + 1) |i| {
        const sep: []const u8 = if (i == 0) "" else ",";
        len += (try std.fmt.bufPrint(buf[len..], "{s}h{d}.example.com", .{ sep, i })).len;
    }
    try testing.expectError(error.GroupTooLarge, validate(buf[0..len], false));
}

fn fuzzNames(_: void, smith: *testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    const summary = validate(buf[0..len], smith.index(2) == 0) catch return;
    try testing.expect(summary.names >= 1 and summary.names <= max_names);
    try testing.expect(summary.groups >= 1 and summary.groups <= max_groups);
}

test "fuzz: ACME: managed hostname grammar is bounded" {
    try testing.fuzz({}, fuzzNames, .{ .corpus = &.{
        "",
        "example.com",
        "a.example.com,b.example.com;c.example.com",
        "*.example.com",
        "a;b;c;d;e;f;g",
        &([_]u8{';'} ** 100),
        &([_]u8{','} ** 100),
        "A.example.com,a.EXAMPLE.com",
    } });
}
