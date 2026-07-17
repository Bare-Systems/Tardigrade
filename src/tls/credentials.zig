//! Provider-neutral TLS 1.3 credential and verification contracts.
//!
//! This module is the seam through which the handshake engine
//! (`tls13_backend.zig`) obtains a *local* authentication credential and
//! delegates *peer* certificate verification, without embedding X.509 policy,
//! private-key byte handling, or provider lifecycle in the state machine.
//! Nothing here imports OpenSSL, a concrete X.509 validator, QUIC, or HTTP,
//! and no private-key bytes cross any interface: a selected credential exposes
//! its public certificate chain and a signing *capability* only (#334).
//!
//! The three contracts are deliberately minimal vtables so a future
//! production SNI selector (#347), an external/asynchronous signer, or a
//! Web-PKI verifier (#324) can be dropped in without touching the engine:
//!
//!   - `CredentialProvider`  — selects a local credential for a handshake,
//!                             given immutable selection context.
//!   - `SelectedCredential`  — an opaque handle exposing (a) the public
//!                             certificate chain and (b) a bounded signing
//!                             callback; released exactly once by the engine.
//!   - `PeerVerifier`        — inspects immutable peer DER views and returns a
//!                             verdict; the engine performs proof-of-possession
//!                             separately (transcript crypto is not PKI policy).
//!
//! ## Ownership and lifetime rules (normative)
//!
//! Certificate chains are surfaced as `CertificateChain`: an immutable view
//! over a slice of DER byte slices.
//!
//! over a slice of DER byte slices. The `entries` collection and every inner
//! DER slice are borrowed; `CertificateChain` never owns or frees them. Three
//! distinct lifetime rules apply depending on which chain it is:
//!
//!   - **Selection-context inputs** (`SelectionContext.server_name`,
//!     `.peer_signature_schemes`) are valid ONLY during the `select` call. A
//!     provider that suspends (returns `pending`) or wants to keep any of them
//!     MUST copy into its own storage first.
//!   - **Peer-chain views** (`VerificationContext.chain`) are valid ONLY during
//!     the `verify` call. A verifier MUST NOT retain a slice past its return;
//!     the engine may reuse or wipe the reassembly buffer immediately after,
//!     and any pending verify operation owns its own snapshot.
//!   - **A selected local credential's chain** (`SelectedCredential.chain`) is
//!     immutable and valid until `SelectedCredential.release()`. The engine
//!     calls `chain()`, then serializes those slices into the flight, so the
//!     provider MUST keep them stable for the whole selected lifetime — a
//!     reloadable provider snapshots them at selection, not per-call.
//!
//! A `SelectedCredential` handle is released exactly once, via `release`, after
//! the local flight has been signed and emitted, or immediately on any failure
//! after selection (cancellation included). After `release` the handle and
//! every slice it produced are invalid.
//!
//! ## Non-blocking / event-driven compatibility
//!
//! `select`, `sign`, and `verify` each return a progress value: `complete`
//! now, or `pending` with a `PendingOperation` the engine drives via
//! `poll`/`cancel`/`release`. An HSM, remote signer, or asynchronous verifier
//! returns `pending`, wakes the driver later, and the engine resumes without
//! recording any handshake message twice; a pending operation snapshots any
//! input it needs (the transcript-derived signing bytes, the peer chain) so the
//! caller-owned stack buffers may disappear. Synchronous providers return
//! `complete` and never allocate a `PendingOperation`. Every operation is
//! cancelled and released exactly once, including on handshake teardown.

const std = @import("std");
const crypto = std.crypto;
const alerts = @import("alerts.zig");
const events = @import("events.zig");
const tls_state = @import("state.zig");

const Ed25519 = crypto.sign.Ed25519;
const EcdsaP256 = crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Role = tls_state.Role;

/// TLS SignatureScheme code points (RFC 8446 §4.2.3) for the schemes this
/// profile can sign and verify. Non-exhaustive: peers may offer others, which
/// selection treats as simply unsupported rather than illegal.
pub const SignatureScheme = enum(u16) {
    ed25519 = 0x0807,
    ecdsa_secp256r1_sha256 = 0x0403,
    _,

    pub fn code(self: SignatureScheme) u16 {
        return @intFromEnum(self);
    }
};

/// Largest local or peer certificate chain (entry count) any contract here
/// surfaces. A single-certificate flight is the common case; the bound leaves
/// room for a short intermediate chain without unbounded growth.
pub const max_chain_entries = 8;

/// Immutable view over a DER certificate chain. See the module-level ownership
/// and lifetime rules: `entries` and every slice within are borrowed and valid
/// only for the lifetime of the call that produced the view.
pub const CertificateChain = struct {
    entries: []const []const u8,

    pub fn count(self: CertificateChain) usize {
        return self.entries.len;
    }

    /// The end-entity certificate (first in the chain), or null when empty.
    pub fn leaf(self: CertificateChain) ?[]const u8 {
        return if (self.entries.len == 0) null else self.entries[0];
    }
};

/// Local authentication policy relevant to selection and verification. Kept
/// deliberately small; a production selector (#347) reads whatever richer
/// policy it owns and only needs these transport-visible bits here.
pub const AuthPolicy = struct {
    /// The verifying side requires the peer to present a valid certificate.
    require_peer_authentication: bool = false,
    /// An unauthenticated peer certificate is acceptable (explicit opt-in).
    allow_unverified_peer: bool = false,
};

/// Immutable context passed to `CredentialProvider.selectCredential`. Carries
/// enough for a future SNI selector (#347) to choose among multiple hosts and
/// key types without the engine changing: role, the SNI the peer requested (or
/// this side intends), the peer's offered signature schemes, the negotiated
/// version/cipher/ALPN, and applicable local policy. Every slice is borrowed
/// for the duration of the selection call only.
pub const SelectionContext = struct {
    role: Role,
    /// Server: the SNI host_name from ClientHello, preserved as received (may
    /// be null when the peer sent none). Client: the intended host, if any.
    server_name: ?[]const u8,
    /// The peer's offered SignatureScheme code points, in offer order.
    peer_signature_schemes: []const u16,
    negotiated_version: u16,
    cipher_suite: u16,
    /// The negotiated application protocol, when ALPN selected one.
    application_protocol: ?[]const u8,
    auth_policy: AuthPolicy,

    /// True when the peer offered `scheme`.
    pub fn offersScheme(self: SelectionContext, scheme: SignatureScheme) bool {
        for (self.peer_signature_schemes) |offered| {
            if (offered == scheme.code()) return true;
        }
        return false;
    }
};

/// Errors a `SelectedCredential.sign` callback may report. `SignatureOutput
/// Overflow` means the requested output buffer is too small for the scheme's
/// signature; the provider must report it rather than write past the bound.
pub const SignError = error{
    SigningProviderFailure,
    SignatureOutputOverflow,
    InvalidCallbackBehavior,
};

/// An opaque, provider-owned handle to a selected local credential. It exposes
/// the public certificate chain and a bounded signing capability; it never
/// exposes private-key bytes. The engine calls `release` exactly once.
pub const SelectedCredential = struct {
    handle: *anyopaque,
    /// The SignatureScheme this credential signs CertificateVerify with. The
    /// provider guarantees it is compatible with the selection context.
    scheme: SignatureScheme,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Return the credential's public DER chain as a borrowed view valid
        /// only until `release` (or the end of the current engine call).
        chain: *const fn (handle: *anyopaque) CertificateChain,
        /// Sign `input` with `scheme`, writing the signature into `out` and
        /// returning its length. Must not write past `out`; report
        /// `SignatureOutputOverflow` when it would not fit.
        sign: *const fn (handle: *anyopaque, scheme: SignatureScheme, input: []const u8, out: []u8) SignError!usize,
        /// Release the handle and any storage it produced. Called exactly once.
        release: *const fn (handle: *anyopaque) void,
    };

    pub fn certificateChain(self: SelectedCredential) CertificateChain {
        return self.vtable.chain(self.handle);
    }

    /// Sign through the provider, defensively enforcing the output bound: a
    /// provider that reports writing more than `out.len` has violated the
    /// contract and is reported as such rather than trusted.
    pub fn sign(self: SelectedCredential, input: []const u8, out: []u8) SignError!usize {
        const written = try self.vtable.sign(self.handle, self.scheme, input, out);
        if (written > out.len) return error.InvalidCallbackBehavior;
        return written;
    }

    pub fn release(self: SelectedCredential) void {
        self.vtable.release(self.handle);
    }
};

/// Errors `CredentialProvider.selectCredential` may report.
pub const SelectError = error{
    /// No credential is configured for this handshake (e.g. no cert for SNI).
    NoCredentialAvailable,
    /// A credential exists but none of its schemes match the peer's offers.
    NoCompatibleSignatureAlgorithm,
    /// The configured credential's certificate chain is malformed or empty.
    MalformedCredentialChain,
    /// The provider itself failed deterministically (local fault).
    ProviderInternalFailure,
    /// The provider returned a handle that violates the contract.
    InvalidCallbackBehavior,
};

/// Selects a local credential for one handshake. Implementations are the fixed
/// provider (below), test mocks, and future SNI/external-key providers.
pub const CredentialProvider = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        select: *const fn (ctx: *anyopaque, selection: *const SelectionContext, out: *SelectedCredential) SelectError!void,
    };

    pub fn selectCredential(self: CredentialProvider, selection: *const SelectionContext, out: *SelectedCredential) SelectError!void {
        return self.vtable.select(self.ctx, selection, out);
    }
};

/// A peer verifier's decision about a presented certificate chain. `accepted`
/// and `rejected` are authoritative trust decisions; `not_checked` records
/// that the verifier deliberately did not evaluate trust (insecure opt-in).
pub const Verdict = enum { accepted, rejected, not_checked };

/// Errors `PeerVerifier.verifyPeer` may report, distinct from a `rejected`
/// verdict: these are verifier/provider faults, not a peer-authentication
/// failure. `InvalidPeerCertificateChain` covers a malformed or empty chain
/// the verifier cannot even evaluate.
pub const VerifyError = error{
    InvalidPeerCertificateChain,
    VerifierInternalFailure,
    InvalidCallbackBehavior,
};

/// Immutable context passed to `PeerVerifier.verifyPeer`. `role` is the side
/// performing verification: a client verifying the server, or (handshake-time
/// client authentication, at the interface level) a server verifying a client.
/// Post-handshake client authentication is explicitly deferred (#334); this
/// contract does not model it. Every slice is borrowed for the call only.
pub const VerificationContext = struct {
    role: Role,
    server_name: ?[]const u8,
    chain: CertificateChain,
    negotiated_version: u16,
    cipher_suite: u16,
    application_protocol: ?[]const u8,
    auth_policy: AuthPolicy,
};

/// Delegated peer certificate verification. The engine supplies immutable DER
/// views and the authentication context; the verifier applies whatever policy
/// it owns (pinning, Web-PKI via #324, insecure passthrough) and returns a
/// verdict. It must not retain the views past the call.
pub const PeerVerifier = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        verify: *const fn (ctx: *anyopaque, context: *const VerificationContext) VerifyError!Verdict,
    };

    pub fn verifyPeer(self: PeerVerifier, context: *const VerificationContext) VerifyError!Verdict {
        return self.vtable.verify(self.ctx, context);
    }
};

// ===========================================================================
// Typed failures and deterministic alert mapping.
// ===========================================================================

/// Whether an authentication failure originated with the peer (its credential
/// or signature is unacceptable) or locally (this side's provider, verifier,
/// or configuration failed). The distinction drives the alert: a peer fault is
/// `bad_certificate`; a local fault is `internal_error`/`handshake_failure`,
/// never blaming the peer for our own misconfiguration.
pub const Origin = enum { peer, local };

/// The complete taxonomy of credential/verification failure classes and their
/// deterministic TLS alert mapping (RFC 8446 §6). Each class maps to exactly
/// one alert and one origin, so a transport emits a stable, correctly-attributed
/// fatal alert (at most once) for every way authentication can fail.
pub const FailureClass = enum {
    no_credential_available,
    no_compatible_signature_algorithm,
    malformed_credential_chain,
    signing_provider_failure,
    signature_output_overflow,
    /// The local credential provider itself failed (distinct from a *verifier*
    /// failure, so diagnostics name the right subsystem).
    provider_internal_failure,
    invalid_peer_certificate_chain,
    /// The peer's CertificateVerify signature did not check out against its
    /// presented leaf (proof-of-possession failure). Peer-originated, but a
    /// distinct reason from a structurally invalid chain.
    certificate_verify_invalid,
    peer_verification_rejected,
    verifier_internal_failure,
    invalid_callback_behavior,

    pub fn origin(self: FailureClass) Origin {
        return switch (self) {
            .invalid_peer_certificate_chain,
            .certificate_verify_invalid,
            .peer_verification_rejected,
            => .peer,
            .no_credential_available,
            .no_compatible_signature_algorithm,
            .malformed_credential_chain,
            .signing_provider_failure,
            .signature_output_overflow,
            .provider_internal_failure,
            .verifier_internal_failure,
            .invalid_callback_behavior,
            => .local,
        };
    }

    /// The fatal alert a peer must be sent for this failure class.
    pub fn alert(self: FailureClass) alerts.AlertDescription {
        return switch (self) {
            // Local: we cannot authenticate ourselves to the peer. RFC 8446
            // §4.4.2.2 uses handshake_failure when the server cannot produce an
            // acceptable certificate/signature for the offered parameters.
            .no_credential_available,
            .no_compatible_signature_algorithm,
            => .handshake_failure,
            // Local provider/verifier faults are our internal errors, not the
            // peer's fault.
            .malformed_credential_chain,
            .signing_provider_failure,
            .signature_output_overflow,
            .provider_internal_failure,
            .verifier_internal_failure,
            .invalid_callback_behavior,
            => .internal_error,
            // Peer-originated authentication failure.
            .invalid_peer_certificate_chain,
            .certificate_verify_invalid,
            .peer_verification_rejected,
            => .bad_certificate,
        };
    }

    /// The engine-level `HandshakeError` this failure surfaces as. Peer faults
    /// reuse `CertificateInvalid` (bad_certificate); local faults use the two
    /// credential-specific errors so the wire alert stays correctly attributed.
    pub fn engineError(self: FailureClass) events.HandshakeError {
        return switch (self) {
            .invalid_peer_certificate_chain,
            .certificate_verify_invalid,
            .peer_verification_rejected,
            => error.CertificateInvalid,
            .no_credential_available,
            .no_compatible_signature_algorithm,
            => error.NoApplicableCredential,
            .malformed_credential_chain,
            .signing_provider_failure,
            .signature_output_overflow,
            .provider_internal_failure,
            .verifier_internal_failure,
            .invalid_callback_behavior,
            => error.CredentialProviderFailed,
        };
    }
};

/// Map a `SelectError` to its failure class.
pub fn classifySelectError(err: SelectError) FailureClass {
    return switch (err) {
        error.NoCredentialAvailable => .no_credential_available,
        error.NoCompatibleSignatureAlgorithm => .no_compatible_signature_algorithm,
        error.MalformedCredentialChain => .malformed_credential_chain,
        error.ProviderInternalFailure => .provider_internal_failure,
        error.InvalidCallbackBehavior => .invalid_callback_behavior,
    };
}

/// Map a `SignError` to its failure class.
pub fn classifySignError(err: SignError) FailureClass {
    return switch (err) {
        error.SigningProviderFailure => .signing_provider_failure,
        error.SignatureOutputOverflow => .signature_output_overflow,
        error.InvalidCallbackBehavior => .invalid_callback_behavior,
    };
}

/// Map a `VerifyError` to its failure class.
pub fn classifyVerifyError(err: VerifyError) FailureClass {
    return switch (err) {
        error.InvalidPeerCertificateChain => .invalid_peer_certificate_chain,
        error.VerifierInternalFailure => .verifier_internal_failure,
        error.InvalidCallbackBehavior => .invalid_callback_behavior,
    };
}

// ===========================================================================
// Fixed identity: the migrated hard-coded server credential, now expressed as
// a production `CredentialProvider`.
// ===========================================================================

/// The server's certificate and signing key: Ed25519 (RFC 8410) or ECDSA
/// P-256 (RFC 5915/5480). `initPkcs8` loads standard PKCS#8 DER as produced by
/// `openssl genpkey -algorithm ed25519` or
/// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`. Two key
/// types because deployed TLS stacks disagree on defaults: GnuTLS/OpenSSL
/// accept Ed25519 out of the box while BoringSSL's default verifier
/// (quiche/Chromium) requires ECDSA/RSA — P-256 is the interoperable floor.
///
/// This is the credential a `FixedCredentialProvider` serves. Private-key
/// bytes live only inside this value and its provider; the handshake engine
/// receives a `SelectedCredential` handle, never the key.
pub const Identity = struct {
    certificate_der: []const u8,
    key: Key,

    pub const Key = union(enum) {
        ed25519: Ed25519.KeyPair,
        ecdsa_p256: EcdsaP256.KeyPair,
    };

    pub const InitError = error{InvalidPrivateKey};

    pub fn initPkcs8(certificate_der: []const u8, pkcs8_key_der: []const u8) InitError!Identity {
        if (ed25519SeedFromPkcs8(pkcs8_key_der)) |seed| {
            const key_pair = Ed25519.KeyPair.generateDeterministic(seed) catch return error.InvalidPrivateKey;
            return .{ .certificate_der = certificate_der, .key = .{ .ed25519 = key_pair } };
        } else |_| {}
        const scalar = try ecdsaP256KeyFromPkcs8(pkcs8_key_der);
        const secret = EcdsaP256.SecretKey.fromBytes(scalar) catch return error.InvalidPrivateKey;
        const key_pair = EcdsaP256.KeyPair.fromSecretKey(secret) catch return error.InvalidPrivateKey;
        return .{ .certificate_der = certificate_der, .key = .{ .ecdsa_p256 = key_pair } };
    }

    /// The TLS SignatureScheme this identity signs CertificateVerify with.
    pub fn signatureScheme(self: *const Identity) SignatureScheme {
        return switch (self.key) {
            .ed25519 => .ed25519,
            .ecdsa_p256 => .ecdsa_secp256r1_sha256,
        };
    }

    /// Legacy accessor returning the raw SignatureScheme code point.
    pub fn signatureAlgorithm(self: *const Identity) u16 {
        return self.signatureScheme().code();
    }

    /// Sign `input` into `out`, returning the signature length. Bounded: never
    /// writes past `out`; reports `SignatureOutputOverflow` when it would.
    /// This is the single place the fixed private key is used for signing.
    pub fn sign(self: *const Identity, input: []const u8, out: []u8) SignError!usize {
        switch (self.key) {
            .ed25519 => |*key_pair| {
                if (out.len < Ed25519.Signature.encoded_length) return error.SignatureOutputOverflow;
                const signature = key_pair.sign(input, null) catch return error.SigningProviderFailure;
                const bytes = signature.toBytes();
                @memcpy(out[0..bytes.len], &bytes);
                return bytes.len;
            },
            .ecdsa_p256 => |*key_pair| {
                const signature = key_pair.sign(input, null) catch return error.SigningProviderFailure;
                var der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
                const der = signature.toDer(&der_buf);
                if (out.len < der.len) return error.SignatureOutputOverflow;
                @memcpy(out[0..der.len], der);
                return der.len;
            },
        }
    }

    /// Extract the P-256 private scalar from PKCS#8 DER (RFC 5915 inside
    /// RFC 5958): SEQUENCE { INTEGER 0, SEQUENCE { OID id-ecPublicKey, OID
    /// prime256v1 }, OCTET STRING { SEQUENCE { INTEGER 1, OCTET STRING(32)
    /// privateKey, ... } } }. Bounded, no allocation.
    fn ecdsaP256KeyFromPkcs8(der: []const u8) InitError![32]u8 {
        const oid_ec_public_key = [_]u8{ 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
        const oid_prime256v1 = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
        var walker = DerWalker{ .bytes = der };
        var outer = try walker.sequence();
        // Both encodings openssl produces: PKCS#8 (RFC 5958, version 0)
        // wrapping ECPrivateKey, or a bare SEC1/RFC 5915 ECPrivateKey
        // (version 1) as written by `openssl pkey -outform DER`.
        var probe = outer;
        const version = try probe.integer();
        if (version == 1) {
            return ecPrivateKeyScalar(&outer);
        }
        try outer.expectInteger(0);
        var alg = try outer.sequence();
        try alg.expectBytes(&oid_ec_public_key);
        try alg.expectBytes(&oid_prime256v1);
        const key_octets = try outer.octetString();
        var inner_walker = DerWalker{ .bytes = key_octets };
        var ec_key = try inner_walker.sequence();
        return ecPrivateKeyScalar(&ec_key);
    }

    /// RFC 5915 ECPrivateKey body: INTEGER 1, OCTET STRING privateKey, ...
    fn ecPrivateKeyScalar(ec_key: *DerWalker) InitError![32]u8 {
        try ec_key.expectInteger(1);
        const scalar = try ec_key.octetString();
        if (scalar.len != 32) return error.InvalidPrivateKey;
        return scalar[0..32].*;
    }

    const DerWalker = struct {
        bytes: []const u8,
        pos: usize = 0,

        fn tagged(self: *DerWalker, tag: u8) InitError![]const u8 {
            if (self.pos + 2 > self.bytes.len) return error.InvalidPrivateKey;
            if (self.bytes[self.pos] != tag) return error.InvalidPrivateKey;
            var len: usize = self.bytes[self.pos + 1];
            var header: usize = 2;
            if (len == 0x81) {
                if (self.pos + 3 > self.bytes.len) return error.InvalidPrivateKey;
                len = self.bytes[self.pos + 2];
                header = 3;
            } else if (len == 0x82) {
                if (self.pos + 4 > self.bytes.len) return error.InvalidPrivateKey;
                len = (@as(usize, self.bytes[self.pos + 2]) << 8) | self.bytes[self.pos + 3];
                header = 4;
            } else if (len > 0x80) {
                return error.InvalidPrivateKey;
            }
            if (self.pos + header + len > self.bytes.len) return error.InvalidPrivateKey;
            const content = self.bytes[self.pos + header ..][0..len];
            self.pos += header + len;
            return content;
        }

        fn sequence(self: *DerWalker) InitError!DerWalker {
            return .{ .bytes = try self.tagged(0x30) };
        }

        fn octetString(self: *DerWalker) InitError![]const u8 {
            return self.tagged(0x04);
        }

        fn integer(self: *DerWalker) InitError!u8 {
            const content = try self.tagged(0x02);
            if (content.len != 1) return error.InvalidPrivateKey;
            return content[0];
        }

        fn expectInteger(self: *DerWalker, value: u8) InitError!void {
            if (try self.integer() != value) return error.InvalidPrivateKey;
        }

        fn expectBytes(self: *DerWalker, expected: []const u8) InitError!void {
            if (self.pos + expected.len > self.bytes.len) return error.InvalidPrivateKey;
            if (!std.mem.eql(u8, self.bytes[self.pos..][0..expected.len], expected)) return error.InvalidPrivateKey;
            self.pos += expected.len;
        }
    };

    /// Extract the 32-byte Ed25519 seed from a PKCS#8 `OneAsymmetricKey` DER
    /// (RFC 8410 §7): SEQUENCE { version 0, AlgorithmIdentifier id-Ed25519,
    /// privateKey OCTET STRING { OCTET STRING(32) } }.
    fn ed25519SeedFromPkcs8(der: []const u8) InitError![Ed25519.KeyPair.seed_length]u8 {
        const prefix = [_]u8{
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // INTEGER version 0
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier { 1.3.101.112 }
            0x04, 0x22, 0x04, 0x20, // OCTET STRING { OCTET STRING (32 bytes) }
        };
        if (der.len != prefix.len + Ed25519.KeyPair.seed_length) return error.InvalidPrivateKey;
        if (!std.mem.eql(u8, der[0..prefix.len], &prefix)) return error.InvalidPrivateKey;
        return der[prefix.len..][0..Ed25519.KeyPair.seed_length].*;
    }
};

/// A `CredentialProvider` backed by a single fixed `Identity`. This is the
/// migration target for the previously hard-coded server credential: the fixed
/// server path and any future SNI/external-key provider serve credentials
/// through the *same* contract, so there is only one authentication path.
///
/// Stored by value so the engine can embed it; obtain the vtable via
/// `provider()` from a stable pointer at point of use. The single held DER
/// chain slice `self.chain_entry` is what `SelectedCredential.chain` returns.
pub const FixedCredentialProvider = struct {
    identity: Identity,
    chain_entry: [1][]const u8,

    pub fn init(identity: Identity) FixedCredentialProvider {
        return .{ .identity = identity, .chain_entry = .{identity.certificate_der} };
    }

    pub fn provider(self: *FixedCredentialProvider) CredentialProvider {
        return .{ .ctx = self, .vtable = &vtable };
    }

    /// Securely clear the private key material.
    pub fn deinit(self: *FixedCredentialProvider) void {
        crypto.secureZero(u8, std.mem.asBytes(&self.identity.key));
    }

    const vtable = CredentialProvider.VTable{ .select = select };

    fn select(ctx: *anyopaque, selection: *const SelectionContext, out: *SelectedCredential) SelectError!void {
        const self: *FixedCredentialProvider = @ptrCast(@alignCast(ctx));
        if (self.identity.certificate_der.len == 0) return error.MalformedCredentialChain;
        const scheme = self.identity.signatureScheme();
        // Honor the peer's advertised signature algorithms: a fixed credential
        // whose one scheme the peer did not offer is not usable here (#347's
        // richer selection would try alternate credentials; a fixed provider
        // has only this one).
        if (!selection.offersScheme(scheme)) return error.NoCompatibleSignatureAlgorithm;
        out.* = .{ .handle = self, .scheme = scheme, .vtable = &credential_vtable };
    }

    const credential_vtable = SelectedCredential.VTable{
        .chain = credentialChain,
        .sign = credentialSign,
        .release = credentialRelease,
    };

    fn credentialChain(handle: *anyopaque) CertificateChain {
        const self: *FixedCredentialProvider = @ptrCast(@alignCast(handle));
        return .{ .entries = self.chain_entry[0..] };
    }

    fn credentialSign(handle: *anyopaque, scheme: SignatureScheme, input: []const u8, out: []u8) SignError!usize {
        const self: *FixedCredentialProvider = @ptrCast(@alignCast(handle));
        // The engine signs with the scheme the credential reported; a mismatch
        // would be an engine bug, guarded here defensively.
        if (scheme != self.identity.signatureScheme()) return error.InvalidCallbackBehavior;
        return self.identity.sign(input, out);
    }

    fn credentialRelease(handle: *anyopaque) void {
        // The fixed credential owns no per-selection scratch; releasing is a
        // no-op beyond marking the (engine-owned) handle done. Key material is
        // wiped by `deinit`, tied to the provider's own lifetime.
        _ = handle;
    }
};

/// How a client decides a server certificate's validity (or a server a
/// client's, at the interface level). Web-PKI chain building is delegated to a
/// #324 verifier; these deterministic modes cover local handshakes, tests, and
/// deployment pinning, and are served through the same `PeerVerifier` contract.
pub const Trust = union(enum) {
    /// The presented leaf must byte-equal this DER certificate.
    pinned_certificate: []const u8,
    /// Report `not_checked`; the driver completes only when it explicitly opts
    /// into an unverified peer.
    insecure_no_verification,
};

/// A `PeerVerifier` backed by a fixed `Trust` policy — the migration target
/// for the previously inline pin/insecure verification. Stored by value;
/// obtain the vtable via `verifier()` from a stable pointer at point of use.
pub const FixedVerifier = struct {
    trust: Trust,

    pub fn init(trust: Trust) FixedVerifier {
        return .{ .trust = trust };
    }

    pub fn verifier(self: *FixedVerifier) PeerVerifier {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable = PeerVerifier.VTable{ .verify = verify };

    fn verify(ctx: *anyopaque, context: *const VerificationContext) VerifyError!Verdict {
        const self: *FixedVerifier = @ptrCast(@alignCast(ctx));
        const leaf = context.chain.leaf() orelse return error.InvalidPeerCertificateChain;
        return switch (self.trust) {
            .pinned_certificate => |pin| if (std.mem.eql(u8, leaf, pin)) .accepted else .rejected,
            .insecure_no_verification => .not_checked,
        };
    }
};

// ===========================================================================
// Deterministic test fixtures.
// ===========================================================================

/// Deterministic local server identity (self-signed Ed25519,
/// CN=tardigrade.test, valid to 2036; generated with openssl, see
/// src/quic/testdata/). For unit tests and local smoke harnesses only — never
/// a production identity.
pub const testdata = struct {
    const certificate_bytes = hexBytes(
        "308201483081fba00302010202146c8bf2251dd4fceda024f44e82cbfaeaa9da082a300506032b6570031a3118301606035504030c0f746172646967726164652e74657374301e170d3236303731303033303535325a170d3336303730373033303535325a301a3118301606035504030c0f746172646967726164652e74657374302a300506032b65700321007487dbf1f35e41d63ee2c907330660439af5fa63ca7f70a9f1484c12f8d4666fa3533051301d0603551d0e0416041494fd70298293687f12c2f46d00fba451fd3c6143301f0603551d2304183016801494fd70298293687f12c2f46d00fba451fd3c6143300f0603551d130101ff040530030101ff300506032b657003410070eb127814436ca43322b688fd6643507d5c2346f7c176a155ddf5350db941acccefceb29f0ea66e9842159f2fece42b67d935b255f2a4224df68182b646e201",
    );
    const private_key_bytes = hexBytes(
        "302e020100300506032b65700422042099132d0957fdbc8235285b25bd8dd5101d7941408adb068ded6de7ada191251f",
    );

    pub const certificate_der: []const u8 = &certificate_bytes;
    pub const private_key_pkcs8_der: []const u8 = &private_key_bytes;

    pub fn identity() Identity {
        return Identity.initPkcs8(certificate_der, private_key_pkcs8_der) catch unreachable;
    }
};

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

// ===========================================================================
// Reusable test mocks: a scriptable provider and verifier that count
// invocations and assert exact lifetime transitions.
// ===========================================================================

/// A `CredentialProvider` whose behavior is scripted and whose selection,
/// signing, and release invocations are counted. Used to prove selection
/// context, sigalg filtering, signing/overflow contracts, and exactly-once
/// handle teardown without a real key. Stored by value; obtain the vtable via
/// `provider()`.
pub const MockCredentialProvider = struct {
    identity: Identity,
    chain_entry: [1][]const u8,
    /// Force selection to fail with this class, ignoring the sigalg check.
    force_select_error: ?SelectError = null,
    /// Report this many bytes written on sign, regardless of the real length,
    /// to model a provider that overflows the caller's bound.
    force_sign_len: ?usize = null,
    force_sign_error: ?SignError = null,
    /// Return an empty certificate chain from selection, to model a malformed
    /// local credential the engine must reject before signing.
    empty_chain: bool = false,
    /// Return the leaf repeated this many times, to model a provider whose
    /// chain exceeds the engine's entry/size bounds.
    chain_repeat: usize = 1,
    /// Skip the peer-offer compatibility check and return the credential's
    /// scheme regardless, to model a provider that hands back an algorithm the
    /// peer never advertised.
    ignore_offer: bool = false,
    /// Sign normally, then flip a signature byte, to model a peer whose
    /// CertificateVerify does not check out (proof-of-possession failure).
    flip_signature: bool = false,
    chain_storage: [16][]const u8 = undefined,

    select_count: usize = 0,
    sign_count: usize = 0,
    release_count: usize = 0,
    /// The last SNI selection saw, copied into mock-owned storage — the
    /// `SelectionContext.server_name` slice is only valid during `select`, so a
    /// mock that wants to remember it MUST NOT retain the borrowed slice.
    last_server_name_buf: [256]u8 = undefined,
    last_server_name_len: usize = 0,
    last_server_name_present: bool = false,
    last_offered_scheme_count: usize = 0,
    last_role: ?Role = null,

    pub fn init(identity: Identity) MockCredentialProvider {
        return .{ .identity = identity, .chain_entry = .{identity.certificate_der} };
    }

    pub fn provider(self: *MockCredentialProvider) CredentialProvider {
        return .{ .ctx = self, .vtable = &vtable };
    }

    /// The remembered SNI as a slice into mock-owned storage (valid for the
    /// mock's lifetime), or null when the last selection carried no SNI.
    pub fn lastServerName(self: *const MockCredentialProvider) ?[]const u8 {
        return if (self.last_server_name_present) self.last_server_name_buf[0..self.last_server_name_len] else null;
    }

    const vtable = CredentialProvider.VTable{ .select = select };

    fn select(ctx: *anyopaque, selection: *const SelectionContext, out: *SelectedCredential) SelectError!void {
        const self: *MockCredentialProvider = @ptrCast(@alignCast(ctx));
        self.select_count += 1;
        self.last_role = selection.role;
        if (selection.server_name) |name| {
            const n = @min(name.len, self.last_server_name_buf.len);
            @memcpy(self.last_server_name_buf[0..n], name[0..n]);
            self.last_server_name_len = n;
            self.last_server_name_present = true;
        } else {
            self.last_server_name_present = false;
            self.last_server_name_len = 0;
        }
        self.last_offered_scheme_count = selection.peer_signature_schemes.len;
        if (self.force_select_error) |err| return err;
        const scheme = self.identity.signatureScheme();
        if (!self.ignore_offer and !selection.offersScheme(scheme)) return error.NoCompatibleSignatureAlgorithm;
        out.* = .{ .handle = self, .scheme = scheme, .vtable = &credential_vtable };
    }

    const credential_vtable = SelectedCredential.VTable{
        .chain = credentialChain,
        .sign = credentialSign,
        .release = credentialRelease,
    };

    fn credentialChain(handle: *anyopaque) CertificateChain {
        const self: *MockCredentialProvider = @ptrCast(@alignCast(handle));
        if (self.empty_chain) return .{ .entries = self.chain_entry[0..0] };
        if (self.chain_repeat == 1) return .{ .entries = self.chain_entry[0..] };
        const n = @min(self.chain_repeat, self.chain_storage.len);
        for (0..n) |i| self.chain_storage[i] = self.identity.certificate_der;
        return .{ .entries = self.chain_storage[0..n] };
    }

    fn credentialSign(handle: *anyopaque, scheme: SignatureScheme, input: []const u8, out: []u8) SignError!usize {
        const self: *MockCredentialProvider = @ptrCast(@alignCast(handle));
        self.sign_count += 1;
        if (self.force_sign_error) |err| return err;
        if (self.force_sign_len) |forced| return forced; // may exceed out.len on purpose
        _ = scheme;
        const written = try self.identity.sign(input, out);
        if (self.flip_signature and written > 0) out[0] ^= 0xff;
        return written;
    }

    fn credentialRelease(handle: *anyopaque) void {
        const self: *MockCredentialProvider = @ptrCast(@alignCast(handle));
        self.release_count += 1;
    }
};

/// A `PeerVerifier` returning a scripted verdict or error, counting calls and
/// recording the last chain length it saw.
pub const MockVerifier = struct {
    result: VerifyError!Verdict,
    verify_count: usize = 0,
    last_chain_len: usize = 0,
    last_role: ?Role = null,
    last_policy: AuthPolicy = .{},
    /// The server name the verifier last observed, copied into mock-owned
    /// storage — the `VerificationContext.server_name` slice is only valid
    /// during the `verify` call.
    last_server_name_buf: [256]u8 = undefined,
    last_server_name_len: usize = 0,
    last_server_name_present: bool = false,

    pub fn init(result: VerifyError!Verdict) MockVerifier {
        return .{ .result = result };
    }

    pub fn verifier(self: *MockVerifier) PeerVerifier {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn lastServerName(self: *const MockVerifier) ?[]const u8 {
        return if (self.last_server_name_present) self.last_server_name_buf[0..self.last_server_name_len] else null;
    }

    const vtable = PeerVerifier.VTable{ .verify = verify };

    fn verify(ctx: *anyopaque, context: *const VerificationContext) VerifyError!Verdict {
        const self: *MockVerifier = @ptrCast(@alignCast(ctx));
        self.verify_count += 1;
        self.last_chain_len = context.chain.count();
        self.last_role = context.role;
        self.last_policy = context.auth_policy;
        if (context.server_name) |name| {
            const n = @min(name.len, self.last_server_name_buf.len);
            @memcpy(self.last_server_name_buf[0..n], name[0..n]);
            self.last_server_name_len = n;
            self.last_server_name_present = true;
        } else {
            self.last_server_name_present = false;
            self.last_server_name_len = 0;
        }
        return self.result;
    }
};

// ===========================================================================
// Contract-level tests. Real-handshake integration lives in
// tls13_backend_tests.zig; these pin the contract's own guarantees.
// ===========================================================================

const testing = std.testing;

fn testSelection(schemes: []const u16) SelectionContext {
    return .{
        .role = .server,
        .server_name = "tardigrade.test",
        .peer_signature_schemes = schemes,
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = "h2",
        .auth_policy = .{},
    };
}

test "fixed provider selects and exposes its public chain without private-key bytes" {
    var fixed = FixedCredentialProvider.init(testdata.identity());
    defer fixed.deinit();
    const provider = fixed.provider();

    const selection = testSelection(&.{ 0x0807, 0x0403 });
    var credential: SelectedCredential = undefined;
    try provider.selectCredential(&selection, &credential);
    try testing.expectEqual(SignatureScheme.ed25519, credential.scheme);

    const chain = credential.certificateChain();
    try testing.expectEqual(@as(usize, 1), chain.count());
    try testing.expectEqualSlices(u8, testdata.certificate_der, chain.leaf().?);
    credential.release();
}

test "fixed provider signs a bounded output the certificate can verify" {
    var fixed = FixedCredentialProvider.init(testdata.identity());
    defer fixed.deinit();
    const provider = fixed.provider();
    const selection = testSelection(&.{0x0807});
    var credential: SelectedCredential = undefined;
    try provider.selectCredential(&selection, &credential);
    defer credential.release();

    const message = "TLS 1.3 CertificateVerify transcript-derived signing input";
    var sig_buf: [128]u8 = undefined;
    const written = try credential.sign(message, &sig_buf);
    try testing.expectEqual(Ed25519.Signature.encoded_length, written);

    // The signature verifies against the certificate's Ed25519 public key.
    const parsed = try (crypto.Certificate{ .buffer = testdata.certificate_der, .index = 0 }).parse();
    const public_key = try Ed25519.PublicKey.fromBytes(parsed.pubKey()[0..Ed25519.PublicKey.encoded_length].*);
    const sig = Ed25519.Signature.fromBytes(sig_buf[0..Ed25519.Signature.encoded_length].*);
    try sig.verify(message, public_key);
}

test "fixed provider rejects an output buffer too small for the signature" {
    var fixed = FixedCredentialProvider.init(testdata.identity());
    defer fixed.deinit();
    const provider = fixed.provider();
    const selection = testSelection(&.{0x0807});
    var credential: SelectedCredential = undefined;
    try provider.selectCredential(&selection, &credential);
    defer credential.release();

    var tiny: [16]u8 = undefined;
    try testing.expectError(error.SignatureOutputOverflow, credential.sign("input", &tiny));
}

test "fixed provider filters on the peer's offered signature algorithms" {
    var fixed = FixedCredentialProvider.init(testdata.identity()); // Ed25519 identity
    defer fixed.deinit();
    const provider = fixed.provider();

    // Peer offers only ECDSA P-256; the Ed25519 credential is not compatible.
    const ecdsa_only = testSelection(&.{0x0403});
    var credential: SelectedCredential = undefined;
    try testing.expectError(error.NoCompatibleSignatureAlgorithm, provider.selectCredential(&ecdsa_only, &credential));

    // With no schemes offered at all, still no compatible scheme.
    const none = testSelection(&.{});
    try testing.expectError(error.NoCompatibleSignatureAlgorithm, provider.selectCredential(&none, &credential));
}

test "selection context preserves the exact SNI and absent SNI deterministically" {
    var present = testSelection(&.{0x0807});
    present.server_name = "exact.example.test";
    try testing.expectEqualStrings("exact.example.test", present.server_name.?);

    var absent = testSelection(&.{0x0807});
    absent.server_name = null;
    try testing.expect(absent.server_name == null);
}

test "mock provider selects the compatible preferred scheme among several offers" {
    var mock = MockCredentialProvider.init(testdata.identity()); // Ed25519
    const provider = mock.provider();
    // Peer offers ECDSA first, then Ed25519; the Ed25519 credential still binds.
    const selection = testSelection(&.{ 0x0403, 0x0807 });
    var credential: SelectedCredential = undefined;
    try provider.selectCredential(&selection, &credential);
    try testing.expectEqual(SignatureScheme.ed25519, credential.scheme);
    try testing.expectEqual(@as(usize, 1), mock.select_count);
    try testing.expectEqual(@as(usize, 2), mock.last_offered_scheme_count);
    credential.release();
    try testing.expectEqual(@as(usize, 1), mock.release_count);
}

test "SelectedCredential.sign catches a provider that overreports its length" {
    var mock = MockCredentialProvider.init(testdata.identity());
    mock.force_sign_len = 999; // claim a write far past the buffer
    const provider = mock.provider();
    const selection = testSelection(&.{0x0807});
    var credential: SelectedCredential = undefined;
    try provider.selectCredential(&selection, &credential);
    defer credential.release();

    var out: [128]u8 = undefined;
    try testing.expectError(error.InvalidCallbackBehavior, credential.sign("input", &out));
}

test "mock provider reports a scripted signing failure" {
    var mock = MockCredentialProvider.init(testdata.identity());
    mock.force_sign_error = error.SigningProviderFailure;
    const provider = mock.provider();
    const selection = testSelection(&.{0x0807});
    var credential: SelectedCredential = undefined;
    try provider.selectCredential(&selection, &credential);
    defer credential.release();
    var out: [128]u8 = undefined;
    try testing.expectError(error.SigningProviderFailure, credential.sign("input", &out));
}

test "fixed verifier accepts a matching pin and rejects a mismatch" {
    const chain_entries = [_][]const u8{testdata.certificate_der};
    const context = VerificationContext{
        .role = .client,
        .server_name = "tardigrade.test",
        .chain = .{ .entries = chain_entries[0..] },
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = "h2",
        .auth_policy = .{ .require_peer_authentication = true },
    };

    var pinned = FixedVerifier.init(.{ .pinned_certificate = testdata.certificate_der });
    try testing.expectEqual(Verdict.accepted, try pinned.verifier().verifyPeer(&context));

    var wrong = [_]u8{0} ** 4;
    var mismatched = FixedVerifier.init(.{ .pinned_certificate = &wrong });
    try testing.expectEqual(Verdict.rejected, try mismatched.verifier().verifyPeer(&context));

    var insecure = FixedVerifier.init(.insecure_no_verification);
    try testing.expectEqual(Verdict.not_checked, try insecure.verifier().verifyPeer(&context));
}

test "fixed verifier reports an empty chain as an invalid peer chain" {
    const empty = [_][]const u8{};
    const context = VerificationContext{
        .role = .client,
        .server_name = null,
        .chain = .{ .entries = empty[0..] },
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };
    var pinned = FixedVerifier.init(.{ .pinned_certificate = testdata.certificate_der });
    try testing.expectError(error.InvalidPeerCertificateChain, pinned.verifier().verifyPeer(&context));
}

test "mock verifier can reject, error, and report a scripted verdict with call counts" {
    const chain_entries = [_][]const u8{testdata.certificate_der};
    const context = VerificationContext{
        .role = .client,
        .server_name = null,
        .chain = .{ .entries = chain_entries[0..] },
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };

    var rejecting = MockVerifier.init(.rejected);
    try testing.expectEqual(Verdict.rejected, try rejecting.verifier().verifyPeer(&context));
    try testing.expectEqual(@as(usize, 1), rejecting.verify_count);
    try testing.expectEqual(@as(usize, 1), rejecting.last_chain_len);
    try testing.expectEqual(Role.client, rejecting.last_role.?);

    var failing = MockVerifier.init(error.VerifierInternalFailure);
    try testing.expectError(error.VerifierInternalFailure, failing.verifier().verifyPeer(&context));
}

test "every failure class maps to a deterministic alert, origin, and engine error" {
    // Peer-originated authentication failures blame the peer's certificate.
    for ([_]FailureClass{ .invalid_peer_certificate_chain, .certificate_verify_invalid, .peer_verification_rejected }) |class| {
        try testing.expectEqual(Origin.peer, class.origin());
        try testing.expectEqual(alerts.AlertDescription.bad_certificate, class.alert());
        try testing.expectEqual(@as(events.HandshakeError, error.CertificateInvalid), class.engineError());
    }
    // Local "cannot authenticate ourselves" failures use handshake_failure.
    for ([_]FailureClass{ .no_credential_available, .no_compatible_signature_algorithm }) |class| {
        try testing.expectEqual(Origin.local, class.origin());
        try testing.expectEqual(alerts.AlertDescription.handshake_failure, class.alert());
        try testing.expectEqual(@as(events.HandshakeError, error.NoApplicableCredential), class.engineError());
    }
    // Local provider/verifier faults are our internal errors. `provider` and
    // `verifier` internal failures are distinct classes so diagnostics name the
    // right subsystem, even though both map to the same wire alert.
    for ([_]FailureClass{
        .malformed_credential_chain,
        .signing_provider_failure,
        .signature_output_overflow,
        .provider_internal_failure,
        .verifier_internal_failure,
        .invalid_callback_behavior,
    }) |class| {
        try testing.expectEqual(Origin.local, class.origin());
        try testing.expectEqual(alerts.AlertDescription.internal_error, class.alert());
        try testing.expectEqual(@as(events.HandshakeError, error.CredentialProviderFailed), class.engineError());
    }
    try testing.expect(FailureClass.provider_internal_failure != FailureClass.verifier_internal_failure);
    try testing.expect(FailureClass.certificate_verify_invalid != FailureClass.invalid_peer_certificate_chain);
    try testing.expectEqual(FailureClass.provider_internal_failure, classifySelectError(error.ProviderInternalFailure));
}

test "error classifiers cover every select, sign, and verify error" {
    try testing.expectEqual(FailureClass.no_credential_available, classifySelectError(error.NoCredentialAvailable));
    try testing.expectEqual(FailureClass.no_compatible_signature_algorithm, classifySelectError(error.NoCompatibleSignatureAlgorithm));
    try testing.expectEqual(FailureClass.malformed_credential_chain, classifySelectError(error.MalformedCredentialChain));
    try testing.expectEqual(FailureClass.provider_internal_failure, classifySelectError(error.ProviderInternalFailure));
    try testing.expectEqual(FailureClass.invalid_callback_behavior, classifySelectError(error.InvalidCallbackBehavior));

    try testing.expectEqual(FailureClass.signing_provider_failure, classifySignError(error.SigningProviderFailure));
    try testing.expectEqual(FailureClass.signature_output_overflow, classifySignError(error.SignatureOutputOverflow));
    try testing.expectEqual(FailureClass.invalid_callback_behavior, classifySignError(error.InvalidCallbackBehavior));

    try testing.expectEqual(FailureClass.invalid_peer_certificate_chain, classifyVerifyError(error.InvalidPeerCertificateChain));
    try testing.expectEqual(FailureClass.verifier_internal_failure, classifyVerifyError(error.VerifierInternalFailure));
    try testing.expectEqual(FailureClass.invalid_callback_behavior, classifyVerifyError(error.InvalidCallbackBehavior));
}

test "fixed provider teardown zeroes the private key exactly once" {
    var fixed = FixedCredentialProvider.init(testdata.identity());
    fixed.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&fixed.identity.key), 0));
}

test "identity parser loads and rejects malformed PKCS#8" {
    const identity = try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der);
    const parsed = try (crypto.Certificate{ .buffer = testdata.certificate_der, .index = 0 }).parse();
    try testing.expect(parsed.pub_key_algo == .curveEd25519);
    try testing.expectEqualSlices(u8, parsed.pubKey(), &identity.key.ed25519.public_key.toBytes());
    try testing.expectError(
        error.InvalidPrivateKey,
        Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der[0 .. testdata.private_key_pkcs8_der.len - 1]),
    );
}
