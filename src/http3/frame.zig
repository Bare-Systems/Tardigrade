//! HTTP/3 framing layer (#246, RFC 9114 §7): the frame codec (DATA, HEADERS,
//! SETTINGS, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH), the unidirectional control
//! stream, and stream-type identification.
//!
//! Runs over QUIC streams (`../quic/stream.zig`); HEADERS payloads are encoded
//! and decoded via QPACK (`qpack.zig`). No transport/connection state here —
//! only the HTTP/3 wire format.
//!
//! Status: skeleton — implemented in #246.

const std = @import("std");

// TODO(#246): frame parse/serialize, control-stream + SETTINGS handling, stream
// type identification.

test {
    std.testing.refAllDecls(@This());
}
