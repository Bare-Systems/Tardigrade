//! Native ACME account, JWS transport and durable state (#832, epic #759).
//! Phase A2: nothing here issues or activates a certificate (A3/A4 own that).

pub const account = @import("account.zig");
pub const csr = @import("csr.zig");
pub const json_limits = @import("json_limits.zig");
pub const state = @import("state.zig");
pub const url = @import("url.zig");
pub const contact = @import("contact.zig");
pub const names = @import("names.zig");
pub const transport = @import("transport.zig");
pub const client = @import("client.zig");

/// Test-only fake CA (see `fake_ca.zig`); absent from non-test builds.
pub const fake_ca = if (@import("builtin").is_test) @import("fake_ca.zig") else struct {};

comptime {
    if (@import("builtin").is_test) _ = @import("client_tests.zig");
}

test {
    @import("std").testing.refAllDecls(@This());
}
