const std = @import("std");

test "keep-alive integration (disabled)" {
    try std.testing.skip("disabled: socket-level keep-alive integration deferred due to std.net portability issues");
}
// no server thread to join
