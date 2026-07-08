//! QUIC path management (#250, #251): Retry / address validation, the
//! anti-amplification limit, PATH_CHALLENGE/PATH_RESPONSE path validation, NAT
//! rebinding detection, and connection migration policy.
//!
//! Gates how many bytes `connection.zig` may send to an unvalidated peer
//! address (anti-amplification), validates new paths before migrating, and
//! implements the Retry-token issue/verify used for downstream address
//! validation. Stateless reset detection pairs with `cid.zig`.
//!
//! Status: skeleton — Retry/anti-amplification in #250, migration in #251.

const std = @import("std");

// TODO(#250/#251): Retry tokens, anti-amplification, path validation, migration.

test {
    std.testing.refAllDecls(@This());
}
