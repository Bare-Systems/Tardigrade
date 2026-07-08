//! QUIC TLS 1.3 adapter (#249, RFC 9001): the boundary between the QUIC
//! connection and the TLS handshake. Carries CRYPTO frame data in/out of the
//! TLS state machine, installs read/write secrets per encryption level, and
//! provides packet-protection and header-protection keys to `packet.zig`.
//!
//! This is the one seam that may temporarily wrap an external TLS 1.3
//! implementation behind a no-leak interface (see the #242 design); no TLS
//! library type escapes this module. Initial-secret derivation and key updates
//! also live here.
//!
//! Status: skeleton — implemented in #249.

const std = @import("std");

// TODO(#249): CRYPTO reassembly, per-level secret installation, packet/header
// protection key provision, and key updates.

test {
    std.testing.refAllDecls(@This());
}
