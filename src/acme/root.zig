//! Native ACME account, JWS transport and durable state (#832, epic #759).
//! Phase A2 landed the account/state foundation; #879 (A4) adds
//! pre-activation verification and durable generation storage in
//! `activate.zig`. Nothing here publishes a live TLS identity yet (#880/#884
//! own that).

pub const account = @import("account.zig");
pub const csr = @import("csr.zig");
pub const json_limits = @import("json_limits.zig");
pub const state = @import("state.zig");
pub const url = @import("url.zig");
pub const contact = @import("contact.zig");
pub const names = @import("names.zig");
pub const transport = @import("transport.zig");
pub const client = @import("client.zig");
pub const activate = @import("activate.zig");
pub const orders = @import("orders.zig");
pub const groups = @import("groups.zig");
/// Pure A5 renewal deadlines and bounded retry policy (#835).
pub const renewal_policy = @import("renewal_policy.zig");
/// Durable per-group renewal retry state (#835).
pub const renewal_state = @import("renewal_state.zig");

/// Test-only fake CA (see `fake_ca.zig`); absent from non-test builds.
pub const fake_ca = if (@import("builtin").is_test) @import("fake_ca.zig") else struct {};
/// Test-only real-crypto certificate builder (see `test_cert_builder.zig`);
/// absent from non-test builds.
pub const test_cert_builder = if (@import("builtin").is_test) @import("test_cert_builder.zig") else struct {};

comptime {
    if (@import("builtin").is_test) {
        _ = @import("client_tests.zig");
        _ = @import("activate_tests.zig");
        _ = @import("orders_tests.zig");
        _ = @import("live_http01_tests.zig");
    }
}

test {
    @import("std").testing.refAllDecls(@This());
}
