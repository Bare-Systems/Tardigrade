//! Pure-Zig PKI foundation (#324, #339, #340, #341): bounded ASN.1 DER
//! decoding, PEM/certificate-chain loading, and the typed X.509 model.
//!
//! This package is the parsing foundation for the Web PKI epic (#324). It
//! does not verify signatures or apply validation policy (#324-D onward).
//!
//! ## Modules
//!
//! - `der` — TLV cursor, typed decoders, limits, fuzz entrypoint
//! - `oid` — OBJECT IDENTIFIER component decoding
//! - `time` — UTCTime and GeneralizedTime validation
//! - `pem` — strict PEM decoding and DER certificate-chain loading
//! - `x509` — policy-neutral certificate model with typed extensions
//! - `identity` — SAN-only DNS/IP service identity matching (RFC 9525)
//! - `verify` — certificate signature verification via the crypto provider
//! - `path_builder` — deterministic candidate certification-path construction
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
//! #324-D through #324-G consume `x509.Certificate` views: `tbs_raw` and
//! `signature_value` for signature verification, `Name.raw` for byte-exact
//! chain building, and typed extensions for RFC 5280 validation. DER input
//! comes from `pem.CertificateChain`, which owns the backing bytes.

pub const der = @import("der.zig");
pub const oid = @import("oid.zig");
pub const time = @import("time.zig");
pub const pem = @import("pem.zig");
pub const x509 = @import("x509.zig");
pub const identity = @import("identity.zig");
pub const verify = @import("verify.zig");
pub const path_builder = @import("path_builder.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("der_tests.zig");
    _ = @import("pem_tests.zig");
    _ = @import("x509_tests.zig");
    _ = @import("identity_tests.zig");
    _ = @import("verify_tests.zig");
    _ = @import("path_builder_tests.zig");
}
