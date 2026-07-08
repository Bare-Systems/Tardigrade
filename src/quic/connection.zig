//! QUIC connection state machine (RFC 9000): packet number spaces (Initial,
//! Handshake, Application), transport-parameter negotiation, and the
//! connection close/draining lifecycle.
//!
//! Drives the packet layer (`packet.zig`) and the TLS adapter
//! (`tls_adapter.zig`), owns per-space packet-number issuance and the ACK
//! eliciting/acked bookkeeping handed to `recovery.zig`, and multiplexes
//! `stream.zig` streams. Depends on `config.zig` for transport parameters and
//! `udp.zig` for datagram I/O.
//!
//! Status: skeleton — implemented after #243 (packet) + #249 (crypto).

const std = @import("std");

// TODO: connection state machine, packet-number spaces, transport-parameter
// application, and close/drain handling.

test {
    std.testing.refAllDecls(@This());
}
