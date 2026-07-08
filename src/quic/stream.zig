//! QUIC streams (#245, RFC 9000 §2–§4, §19.8–§19.13): per-stream send/receive
//! state, stream- and connection-level flow control, RESET_STREAM /
//! STOP_SENDING, and the backpressure integration that HTTP/3 relies on.
//!
//! Reassembles STREAM frames decoded by `packet.zig`, enforces the MAX_DATA /
//! MAX_STREAM_DATA windows from `config.zig`, and exposes the bounded
//! read/write surface that `../http3/session.zig` maps onto the shared
//! `stream_transport` contract — mirroring the bounded-buffer, explicit-cancel,
//! no-hidden-full-body model already used by the h1/h2 proxy paths.
//!
//! Status: skeleton — implemented in #245.

const std = @import("std");

// TODO(#245): stream state machines, flow control, resets, STOP_SENDING,
// backpressure.

test {
    std.testing.refAllDecls(@This());
}
