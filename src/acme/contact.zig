//! Account contact validation (#832). Shared by config validation and the
//! protocol client so both reject exactly the same addresses.

const std = @import("std");

/// Conservative address check: it only has to be safe to embed in JSON and a
/// `mailto:` URI without escaping, and plausibly an address. The CA is the
/// authority on whether it is deliverable.
pub fn isPlausibleEmail(email: []const u8) bool {
    if (email.len < 3 or email.len > 254) return false;
    const at = std.mem.indexOfScalar(u8, email, '@') orelse return false;
    if (at == 0 or at == email.len - 1) return false;
    if (std.mem.indexOfScalarPos(u8, email, at + 1, '@') != null) return false;
    for (email) |c| {
        if (c <= 0x20 or c >= 0x7f) return false;
        if (std.mem.indexOfScalar(u8, "\"\\<>,;?#%&=/", c) != null) return false;
    }
    return true;
}

test "ACME contact: plausible addresses only" {
    try std.testing.expect(isPlausibleEmail("ops@example.com"));
    for ([_][]const u8{ "", "a", "no-at", "a@", "@b", "a@b@c", "a b@c", "a\"@c", "a@c,d@e", "a@c\n" }) |bad| {
        try std.testing.expect(!isPlausibleEmail(bad));
    }
}
