//! Test-only bridge for the real-process automatic-HTTPS acceptance test.
//!
//! Keeping these imports in one module guarantees that the loopback ACME
//! server and its caller share the same `FakeCa` type and state.

pub const fake = @import("acme/fake_ca.zig");
pub const live_ca = @import("acme/live_ca_server.zig");
pub const test_ca = @import("acme/test_cert_builder.zig");
// The live-process acceptance test owns the external gateway process, so it
// needs these narrowly-scoped durable-state helpers to publish a controlled
// second generation and exercise the real SIGHUP recovery path.
pub const activate = @import("acme/activate.zig");
pub const csr = @import("acme/csr.zig");
pub const groups = @import("acme/groups.zig");
pub const state = @import("acme/state.zig");
