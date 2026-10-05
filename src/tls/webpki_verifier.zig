//! Native Web-PKI peer verification for the TLS client role (#634).
//!
//! Adapts the pure-Zig PKI chain builder/validator (`src/pki/`) to the
//! engine's `credentials.PeerVerifier` contract, for a TLS client that must
//! authenticate a server certificate chain against a trust-anchor set —
//! today the native upstream HTTPS client (`http/upstream_tls.zig`),
//! and any future native TLS client role — rather than a fixed pin or
//! insecure passthrough (both already covered by `credentials.FixedVerifier`
//! via `Trust.insecure_no_verification` / `.pinned_certificate`).
//!
//! No cryptographic primitive or ASN.1 decoder is implemented here: this file
//! only wires the existing chain builder (`pki.path_builder`), validator
//! (`pki.path_validator`, which itself calls `pki.identity.verifyHost` for
//! RFC 9525 hostname/SAN matching), and trust-anchor store (`pki.trust_store`)
//! together behind the engine's verifier seam. Verification is entirely
//! synchronous — no network or filesystem access happens during a handshake —
//! so `verifyPeer` always completes with `.complete`, never `.pending`.

const std = @import("std");
const crypto = @import("crypto");
const pki = @import("pki");
const zig_compat = @import("zig_compat");
const credentials = @import("credentials.zig");

pub const Error = pki.trust_store.FileError || error{NoSystemTrustAnchors};

/// Ordered, well-known CA bundle file locations consulted when no explicit
/// upstream CA bundle path is configured — the native-profile analogue of
/// OpenSSL's compiled-in default verify path
/// (`SSL_CTX_set_default_verify_paths`, see `upstream_tls.zig`). This is
/// plain filesystem access via the pure-Zig PEM/X.509 loader, not a foreign
/// TLS/crypto library — see the #634 comment clarifying that "pure Zig"
/// bounds external *protocol/crypto* implementations, not ordinary OS/kernel
/// facilities. The first candidate that exists and loads is used.
const system_ca_bundle_candidates = [_][]const u8{
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Arch
    "/etc/pki/tls/certs/ca-bundle.crt", // Fedora/RHEL/CentOS
    "/etc/ssl/cert.pem", // Alpine, macOS/Homebrew OpenSSL layout, *BSD
    "/etc/ssl/ca-bundle.pem", // openSUSE
    "/etc/pki/tls/cacert.pem", // older RHEL
    "/etc/certs/ca-certificates.crt", // Solaris/illumos
};

/// An owned trust-anchor snapshot ready for repeated `WebPkiVerifier` use.
/// Caller-owned; free with `deinit` once no in-flight verifier needs it.
pub const TrustAnchors = struct {
    snapshot: pki.trust_store.Snapshot,

    pub fn deinit(self: *TrustAnchors, allocator: std.mem.Allocator) void {
        self.snapshot.deinit(allocator);
        self.* = undefined;
    }

    pub fn anchors(self: *const TrustAnchors) []const pki.x509.Certificate {
        return self.snapshot.anchors();
    }
};

/// Load trust anchors from an explicit PEM CA bundle path, or — when empty —
/// the first well-known system CA bundle location that exists and parses.
/// Mirrors the OpenSSL upstream adapter's choice between
/// `SSL_CTX_load_verify_locations` and `SSL_CTX_set_default_verify_paths`
/// (`upstream_tls.zig`'s `UpstreamTlsConn.connect`), without linking
/// OpenSSL: both paths go through the same pure-Zig PEM/X.509 loader.
/// Deterministic failure (`error.NoSystemTrustAnchors`) when neither an
/// explicit bundle nor any well-known system location is usable — this never
/// silently falls back to an empty, always-failing trust store.
pub fn loadTrustAnchors(
    allocator: std.mem.Allocator,
    ca_bundle_path: []const u8,
) Error!TrustAnchors {
    const io = zig_compat.io();
    const dir = std.Io.Dir.cwd();
    if (ca_bundle_path.len > 0) {
        const snapshot = try pki.trust_store.Snapshot.loadFiles(allocator, io, dir, &.{.{ .pem = ca_bundle_path }}, .{});
        return .{ .snapshot = snapshot };
    }
    for (system_ca_bundle_candidates) |candidate| {
        const snapshot = pki.trust_store.Snapshot.loadFiles(allocator, io, dir, &.{.{ .pem = candidate }}, .{}) catch |err| {
            if (err == error.OutOfMemory) return err;
            continue;
        };
        return .{ .snapshot = snapshot };
    }
    return error.NoSystemTrustAnchors;
}

/// A `credentials.PeerVerifier` backed by RFC 5280 path validation against a
/// borrowed trust-anchor set. The anchors, and the `WebPkiVerifier` itself,
/// must outlive every handshake that uses `verifier()`.
pub const WebPkiVerifier = struct {
    allocator: std.mem.Allocator,
    trust_anchors: []const pki.x509.Certificate,
    crypto_provider: crypto.provider.CryptoProvider,
    /// Which TLS certificate purpose the peer chain is validated for. A
    /// `.client` verifier (downstream mTLS, #763) requires `id-kp-clientAuth`
    /// rather than `id-kp-serverAuth` and applies no hostname policy.
    purpose: Purpose = .server,
    /// Longest certification path accepted, counting the leaf and
    /// intermediates but not the trust anchor.
    maximum_path_length: usize = default_maximum_path_length,

    pub const Purpose = enum { server, client };
    pub const default_maximum_path_length: usize = 8;

    pub fn init(
        allocator: std.mem.Allocator,
        trust_anchors: []const pki.x509.Certificate,
        crypto_provider: crypto.provider.CryptoProvider,
    ) WebPkiVerifier {
        return .{ .allocator = allocator, .trust_anchors = trust_anchors, .crypto_provider = crypto_provider };
    }

    /// A verifier for downstream client certificates (#763).
    pub fn initClientAuth(
        allocator: std.mem.Allocator,
        trust_anchors: []const pki.x509.Certificate,
        crypto_provider: crypto.provider.CryptoProvider,
        maximum_path_length: usize,
    ) WebPkiVerifier {
        var self = init(allocator, trust_anchors, crypto_provider);
        self.purpose = .client;
        self.maximum_path_length = maximum_path_length;
        return self;
    }

    pub fn verifier(self: *WebPkiVerifier) credentials.PeerVerifier {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable = credentials.PeerVerifier.VTable{ .verify = verifyImpl };

    fn verifyImpl(
        ctx: *anyopaque,
        context: *const credentials.VerificationContext,
    ) credentials.VerifyError!credentials.Progress(credentials.Verdict) {
        const self: *WebPkiVerifier = @ptrCast(@alignCast(ctx));
        return .{ .complete = self.verify(context) };
    }

    /// Parse the presented DER chain, build candidate certification paths to
    /// `trust_anchors`, and validate the first one that satisfies RFC 5280 —
    /// including, when `context.server_name` is set, RFC 9525 hostname/SAN
    /// matching against the leaf (`pki.path_validator` calls
    /// `pki.identity.verifyHost` internally). All scratch state (parsed
    /// certificate views, candidate paths, validation output) lives in a
    /// per-call arena freed before returning — nothing here outlives the
    /// verdict.
    fn verify(self: *WebPkiVerifier, context: *const credentials.VerificationContext) credentials.Verdict {
        if (context.chain.count() == 0) return .rejected;

        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var parsed: [credentials.max_chain_entries]pki.x509.Certificate = undefined;
        var parsed_len: usize = 0;
        for (context.chain.entries) |der| {
            if (parsed_len >= parsed.len) break;
            parsed[parsed_len] = pki.x509.Certificate.parse(arena, der, .{}) catch return .rejected;
            parsed_len += 1;
        }
        if (parsed_len == 0) return .rejected;

        const leaf = &parsed[0];
        const intermediates = parsed[1..parsed_len];

        const candidates = pki.path_builder.build(arena, leaf, intermediates, self.trust_anchors, .{}) catch return .rejected;

        const now_unix_s = zig_compat.unixTimestamp();
        const result = pki.path_validator.validateCandidates(arena, candidates, .{
            .validation_time = now_unix_s,
            // The SNI a client sent names *our* server, not the client
            // certificate's identity: never a hostname policy for `.client`.
            .expected_dns_name = if (self.purpose == .server) context.server_name else null,
            .require_server_auth_eku = self.purpose == .server,
            .require_client_auth_eku = self.purpose == .client,
            .maximum_path_length = self.maximum_path_length,
            .trust_anchors = self.trust_anchors,
        }, self.crypto_provider);
        return switch (result) {
            .accepted => .accepted,
            .rejected => .rejected,
        };
    }
};

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
