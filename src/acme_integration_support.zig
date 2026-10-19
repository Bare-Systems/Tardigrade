//! Test-only bridge for the real-process automatic-HTTPS acceptance test.
//!
//! Keeping these imports in one module guarantees that the loopback ACME
//! server and its caller share the same `FakeCa` type and state.

pub const fake = @import("acme/fake_ca.zig");
pub const live_ca = @import("acme/live_ca_server.zig");
pub const test_ca = @import("acme/test_cert_builder.zig");
