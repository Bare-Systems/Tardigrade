//! Order-group parsing and stable identifiers for automatic HTTPS (#884, A4
//! of epic #759, design `docs/ACME_AUTOMATIC_HTTPS.md` §4.4).
//!
//! `tls_acme_domains_spec` has already passed `acme/names.zig`'s grammar
//! check (bounds, DNS syntax, no wildcards/IPs, dedup, per-group caps) by
//! the time anything here runs; `names.validate` reports only counts, not
//! the `;`/`,` boundaries themselves, so this module re-splits the same
//! grammar to recover the actual order groups, and derives each group's
//! durable on-disk identifier.

const std = @import("std");
const names_mod = @import("names.zig");

pub const max_groups = names_mod.max_groups;
pub const max_names_per_group = names_mod.max_names_per_group;
/// 16 bytes of SHA-256, hex-encoded (design §4.4).
pub const group_id_len = 32;

pub const Group = struct {
    names: [max_names_per_group][]const u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const Group) []const []const u8 {
        return self.names[0..self.len];
    }
};

pub const GroupList = struct {
    groups: [max_groups]Group = undefined,
    len: usize = 0,

    pub fn slice(self: *const GroupList) []const Group {
        return self.groups[0..self.len];
    }
};

/// Re-splits an already-`names.validate`d `domains_spec` into its
/// `;`-delimited order groups and `,`-delimited names (borrowed slices into
/// `domains_spec`, valid for as long as it is). A caller that skips
/// `names.validate` first still cannot read out of bounds here -- the same
/// structural checks (non-empty groups/names, caps) are re-applied and fail
/// closed with `error.Invalid` -- but this function trusts (and does not
/// re-check) DNS syntax, casing, wildcard/IP rejection, or duplicates.
pub fn parse(domains_spec: []const u8) error{Invalid}!GroupList {
    var out = GroupList{};
    var group_it = std.mem.splitScalar(u8, domains_spec, ';');
    while (group_it.next()) |group_text| {
        const trimmed_group = std.mem.trim(u8, group_text, " \t\r\n");
        if (trimmed_group.len == 0) {
            // A trailing `;` is tolerated (mirrors `names.validate`); an
            // empty group in the middle is not.
            if (group_it.peek() == null) break;
            return error.Invalid;
        }
        if (out.len >= max_groups) return error.Invalid;
        var group = Group{};
        var name_it = std.mem.splitScalar(u8, trimmed_group, ',');
        while (name_it.next()) |name_text| {
            const name = std.mem.trim(u8, name_text, " \t\r\n");
            if (name.len == 0) continue;
            if (group.len >= max_names_per_group) return error.Invalid;
            group.names[group.len] = name;
            group.len += 1;
        }
        if (group.len == 0) return error.Invalid;
        out.groups[out.len] = group;
        out.len += 1;
    }
    if (out.len == 0) return error.Invalid;
    return out;
}

/// Design §4.4: "lowercase hex SHA-256 of the sorted name list truncated to
/// 16 bytes". Sorting makes the id independent of the order names were
/// written in the config; names are already canonical lowercase
/// (`names.validateName`), so this is a plain byte-order sort, not a
/// case-folding one. Names are joined with `,` (never a valid DNS-name
/// byte) before hashing so `{"ab","c"}` and `{"a","bc"}` cannot collide.
pub fn groupId(buf: *[group_id_len]u8, group_names: []const []const u8) []const u8 {
    var sorted_buf: [max_names_per_group][]const u8 = undefined;
    const sorted = sorted_buf[0..group_names.len];
    @memcpy(sorted, group_names);
    std.mem.sort([]const u8, sorted, {}, lessThanBytes);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (sorted, 0..) |name, i| {
        if (i > 0) hasher.update(",");
        hasher.update(name);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bufPrint(buf, "{x}", .{digest[0..16]}) catch unreachable;
}

fn lessThanBytes(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

// ---------------------------------------------------------------------------

const testing = std.testing;

test "parse splits `;` order groups and `,` names, tolerating a trailing `;`" {
    const list = try parse("a.example.com,www.a.example.com;b.example.com;");
    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expectEqual(@as(usize, 2), list.groups[0].len);
    try testing.expectEqualStrings("a.example.com", list.groups[0].names[0]);
    try testing.expectEqualStrings("www.a.example.com", list.groups[0].names[1]);
    try testing.expectEqual(@as(usize, 1), list.groups[1].len);
    try testing.expectEqualStrings("b.example.com", list.groups[1].names[0]);
}

test "parse rejects an empty group in the middle, an all-empty spec, or an oversize group" {
    try testing.expectError(error.Invalid, parse("a.example.com;;b.example.com"));
    try testing.expectError(error.Invalid, parse(""));
    try testing.expectError(error.Invalid, parse(";"));

    var spec_buf: [512]u8 = undefined;
    var spec_len: usize = 0;
    for (0..max_names_per_group + 1) |i| {
        if (i > 0) {
            spec_buf[spec_len] = ',';
            spec_len += 1;
        }
        const written = std.fmt.bufPrint(spec_buf[spec_len..], "n{d}.example.com", .{i}) catch unreachable;
        spec_len += written.len;
    }
    try testing.expectError(error.Invalid, parse(spec_buf[0..spec_len]));
}

test "groupId is stable under reordering and distinguishes name sets" {
    var buf_a: [group_id_len]u8 = undefined;
    var buf_b: [group_id_len]u8 = undefined;
    const a = groupId(&buf_a, &.{ "a.example.com", "b.example.com" });
    const b = groupId(&buf_b, &.{ "b.example.com", "a.example.com" });
    try testing.expectEqualStrings(a, b);

    var buf_c: [group_id_len]u8 = undefined;
    const c = groupId(&buf_c, &.{"a.example.com"});
    try testing.expect(!std.mem.eql(u8, a, c));

    // Separator-aware: {"ab","c"} must not collide with {"a","bc"}.
    var buf_d: [group_id_len]u8 = undefined;
    var buf_e: [group_id_len]u8 = undefined;
    const d = groupId(&buf_d, &.{ "ab.example.com", "c.example.com" });
    const e = groupId(&buf_e, &.{ "a.example.com", "bc.example.com" });
    try testing.expect(!std.mem.eql(u8, d, e));

    try testing.expectEqual(@as(usize, group_id_len), a.len);
    for (a) |ch| try testing.expect((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'));
}

test {
    std.testing.refAllDecls(@This());
}
