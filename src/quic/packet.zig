//! QUIC packet layer (#243): varint codec, long/short packet headers, packet
//! number encoding/reconstruction, and the frame codec.
//!
//! Owns the wire format only — no connection state, no crypto (packet/header
//! protection lives with the TLS adapter, #249). Long-header types: Initial,
//! 0-RTT, Handshake, Retry; short header for the 1-RTT application space.
//! Frame set starts with PADDING/PING/ACK/CRYPTO/CONNECTION_CLOSE and the
//! STREAM/flow-control/CID/path frame skeletons (RFC 9000 §12, §17, §19).
//!
//! Status: skeleton — implemented in #243. Compiles and is covered by
//! `zig build test-quic`; carries no behavior yet.

const std = @import("std");

// TODO(#243): varint encode/decode, packet header parse/serialize, packet
// number reconstruction, and the initial frame codec set.

test {
    std.testing.refAllDecls(@This());
}
