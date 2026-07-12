//! Pure-Zig PKI foundation (#324, #339, #340): bounded ASN.1 DER decoding and
//! PEM/certificate-chain loading for X.509.
//!
//! This package is the DER and PEM foundation for the Web PKI epic (#324). It
//! does not parse complete certificates (#341) or verify signatures.
//!
//! ## Modules
//!
//! - `der` — TLV cursor, typed decoders, limits, fuzz entrypoint
//! - `oid` — OBJECT IDENTIFIER component decoding
//! - `time` — UTCTime and GeneralizedTime validation
//! - `pem` — strict PEM decoding and DER certificate-chain loading
//!
//! ## Policy summary
//!
//! Definite-length DER only; reject BER indefinite lengths and non-minimal
//! encodings. Zero-copy views into caller-owned input; call `expectEnd` to
//! enforce complete consumption. See `der.Limits` for default bounds. PEM
//! loading is strict (RFC 7468 profile) and returns owned DER copies; see
//! `pem.Limits` for input, size, and count bounds.
//!
//! ## Downstream usage
//!
//! #341 should map TBSCertificate, Name, and Extension sequences using child
//! readers and the typed decoders exported here, consuming exact DER bytes
//! from `pem.CertificateChain`.

pub const der = @import("der.zig");
pub const oid = @import("oid.zig");
pub const time = @import("time.zig");
pub const pem = @import("pem.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("der_tests.zig");
    _ = @import("pem_tests.zig");
}
