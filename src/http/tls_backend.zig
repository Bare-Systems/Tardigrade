//! TLS termination backend selector (#379, epic #327).
//!
//! Every consumer of TLS termination — `http.zig`'s public alias and the
//! direct importers inside `src/http/` — goes through this file, so exactly
//! one backend type set exists per build. `-Dtls-profile=general` selects
//! the approved OpenSSL adapter; `-Dtls-profile=appliance` selects the
//! no-OpenSSL stub, in which case `tls_termination.zig` is never analyzed,
//! `@cImport("openssl/...")` never runs, and no `libssl`/`libcrypto`
//! linkage exists. The selection is a build-graph decision with no runtime
//! fallback; see docs/TLS_DEPENDENCY_POLICY.md.

const selected = if (@import("build_options").tls_openssl_adapter)
    @import("tls_termination.zig")
else
    @import("tls_termination_stub.zig");

pub const TlsError = selected.TlsError;
pub const SniCertSpec = selected.SniCertSpec;
pub const TlsOptions = selected.TlsOptions;
pub const NegotiatedProtocol = selected.NegotiatedProtocol;
pub const TlsTerminator = selected.TlsTerminator;
pub const TlsConnection = selected.TlsConnection;
pub const UpstreamTlsOptions = selected.UpstreamTlsOptions;
pub const UpstreamAlpnPolicy = selected.UpstreamAlpnPolicy;
pub const UpstreamTlsConn = selected.UpstreamTlsConn;
pub const lastOpenSslError = selected.lastOpenSslError;

test {
    _ = selected;
}
