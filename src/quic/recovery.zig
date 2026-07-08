//! QUIC loss detection and congestion control (#244, RFC 9002): ACK manager,
//! RTT estimator, loss detection, PTO, and a NewReno-baseline congestion
//! controller with pacing hooks.
//!
//! Consumes ACK frames decoded by `packet.zig` and the sent-packet metadata
//! recorded by `connection.zig`; drives retransmission and the send-allowance
//! that gates `stream.zig` output. Deliberately starts on a correct RFC 9002 /
//! NewReno baseline — BBR and aggressive optimizer work are explicitly deferred
//! (see the #240 non-goals).
//!
//! Status: skeleton — implemented in #244.

const std = @import("std");

// TODO(#244): ACK range processing, RTT/PTO, loss detection, NewReno window +
// pacing.

test {
    std.testing.refAllDecls(@This());
}
