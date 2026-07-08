//! QUIC connection ID management (#251, RFC 9000 §5.1): CID generation,
//! lookup/routing, retirement, and stateless-reset token derivation.
//!
//! The UDP endpoint (`udp.zig`) demultiplexes incoming datagrams to a
//! connection by destination CID via the lookup table owned here; NEW/RETIRE
//! CONNECTION_ID frame handling and the active-CID limit from `config.zig` also
//! live here. Deeper migration/path lifecycle is `path.zig`.
//!
//! Status: skeleton — basic generation/lookup scaffolding for #243, full
//! lifecycle in #251.

const std = @import("std");

// TODO(#251): CID generation/lookup/retirement and stateless-reset tokens.

test {
    std.testing.refAllDecls(@This());
}
