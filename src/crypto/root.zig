//! Pure-Zig cryptographic-provider package (#370, epic #327).
//!
//! `provider` is the stable boundary every TLS/QUIC/PKI module depends on;
//! `pure_zig` is the first concrete backend behind it. An OpenSSL adapter will
//! join as a second implementation of the same `provider.CryptoProvider`
//! interface. See `docs/CRYPTO_PROVIDER.md`.

pub const provider = @import("provider.zig");
pub const profile = @import("profile.zig");
pub const pure_zig = @import("pure_zig.zig");
pub const rsa = @import("rsa.zig");
pub const secrets = @import("crypto_secrets");

test {
    @import("std").testing.refAllDecls(@This());
}
