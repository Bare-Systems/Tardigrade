//! Native ACME account, JWS transport and durable state (#832, epic #759).
//! Phase A2: nothing here issues or activates a certificate (A3/A4 own that).

pub const account = @import("account.zig");
pub const json_limits = @import("json_limits.zig");
pub const state = @import("state.zig");
pub const url = @import("url.zig");
pub const contact = @import("contact.zig");
pub const transport = @import("transport.zig");
pub const client = @import("client.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("fake_ca.zig");
        _ = @import("client_tests.zig");
    }
}

test {
    @import("std").testing.refAllDecls(@This());
}
