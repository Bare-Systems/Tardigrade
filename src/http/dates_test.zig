const std = @import("std");
const dates = @import("dates.zig");

test "parse RFC1123 date" {
    const s = "Sun, 06 Nov 1994 08:49:37 GMT";
    const res = dates.parseHttpDate(s) orelse unreachable;
    try std.testing.expect(res != 0);
}

test "parse RFC850 date" {
    const s = "Sunday, 06-Nov-94 08:49:37 GMT";
    const res = dates.parseHttpDate(s) orelse unreachable;
    try std.testing.expect(res != 0);
}

test "parse asctime date" {
    const s = "Sun Nov  6 08:49:37 1994";
    const res = dates.parseHttpDate(s) orelse unreachable;
    try std.testing.expect(res != 0);
}

test "reject invalid date" {
    const s = "Not a date";
    const res = dates.parseHttpDate(s);
    try std.testing.expect(res == null);
}
