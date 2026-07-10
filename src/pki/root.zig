//! Pure-Zig PKI foundation (#324, #339): bounded ASN.1 DER decoding for X.509.
//!
//! This package is the DER foundation for the Web PKI epic (#324). It does not
//! parse complete certificates (#341), load PEM (#340), or verify signatures.
//!
//! ## Modules
//!
//! - `der` — TLV cursor, typed decoders, limits, fuzz entrypoint
//! - `oid` — OBJECT IDENTIFIER component decoding
//! - `time` — UTCTime and GeneralizedTime validation
//!
//! ## Policy summary
//!
//! Definite-length DER only; reject BER indefinite lengths and non-minimal
//! encodings. Zero-copy views into caller-owned input; call `expectEnd` to
//! enforce complete consumption. See `der.Limits` for default bounds.
//!
//! ## Downstream usage
//!
//! #340 should base64-decode PEM blocks and hand DER bytes to `der.Reader`.
//! #341 should map TBSCertificate, Name, and Extension sequences using child
//! readers and the typed decoders exported here.

pub const der = @import("der.zig");
pub const oid = @import("oid.zig");
pub const time = @import("time.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("der_tests.zig");
}
