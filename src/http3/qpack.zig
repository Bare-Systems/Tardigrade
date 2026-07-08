//! QPACK header compression (#252 static-only first, then #253 dynamic table,
//! RFC 9204): static table, Huffman coding, and later the dynamic table with
//! encoder/decoder streams and blocked-stream accounting.
//!
//! Encodes/decodes the HEADERS payloads carried by `frame.zig`. The initial
//! milestone is static-table-only (no dynamic insertions, `SETTINGS`
//! capacity 0) to unblock #246; the dynamic table and blocked-stream limits
//! from `../quic/config.zig` follow in #253.
//!
//! Status: skeleton — static mode #252, dynamic #253.

const std = @import("std");

// TODO(#252/#253): static table + Huffman, then dynamic table + encoder/decoder
// streams + blocked-stream accounting.

test {
    std.testing.refAllDecls(@This());
}
