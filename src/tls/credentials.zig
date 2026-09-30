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
const crypto_pkg = @import("crypto");
const pure_zig = crypto_pkg.pure_zig;
const crypto_provider_pkg = crypto_pkg.provider;

const Ed25519 = crypto.sign.Ed25519;

pub const Role = tls_state.Role;

/// TLS SignatureScheme code points (RFC 8446 §4.2.3) for the schemes this
/// profile can sign and verify. Non-exhaustive: peers may offer others, which
/// selection treats as simply unsupported rather than illegal.
pub const SignatureScheme = enum(u16) {
    ed25519 = 0x0807,
    ecdsa_secp256r1_sha256 = 0x0403,
    rsa_pss_rsae_sha256 = 0x0804,
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
        /// completing with its length. Must not write past `out`; report
        /// `SignatureOutputOverflow` when it would not fit. May return `pending`
        /// (an async signer); the pending operation must keep `out` and a
        /// snapshot of `input` until it completes.
        sign: *const fn (handle: *anyopaque, scheme: SignatureScheme, input: []const u8, out: []u8) SignError!Progress(usize),
        /// Release the handle and any storage it produced. Called exactly once.
        release: *const fn (handle: *anyopaque) void,
    };

    pub fn certificateChain(self: SelectedCredential) CertificateChain {
        return self.vtable.chain(self.handle);
    }

    /// Sign through the provider, defensively enforcing the output bound on a
    /// synchronous completion: a provider that reports writing more than
    /// `out.len` has violated the contract and is reported as such.
    pub fn sign(self: SelectedCredential, input: []const u8, out: []u8) SignError!Progress(usize) {
        const progress = try self.vtable.sign(self.handle, self.scheme, input, out);
        switch (progress) {
            .complete => |written| if (written > out.len) return error.InvalidCallbackBehavior,
            .pending => {},
        }
        return progress;
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
    /// The provider could not allocate a selected-handle or operation.
    OutOfMemory,
};

/// Selects a local credential for one handshake. Implementations are the fixed
/// provider (below), test mocks, and future SNI/external-key providers.
pub const CredentialProvider = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Select a credential, completing with it synchronously or returning a
        /// pending operation (e.g. an SNI lookup that must go async).
        select: *const fn (ctx: *anyopaque, selection: *const SelectionContext) SelectError!Progress(SelectedCredential),
    };

    pub fn selectCredential(self: CredentialProvider, selection: *const SelectionContext) SelectError!Progress(SelectedCredential) {
        return self.vtable.select(self.ctx, selection);
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
        verify: *const fn (ctx: *anyopaque, context: *const VerificationContext) VerifyError!Progress(Verdict),
    };

    pub fn verifyPeer(self: PeerVerifier, context: *const VerificationContext) VerifyError!Progress(Verdict) {
        return self.vtable.verify(self.ctx, context);
    }
};

// ===========================================================================
// Asynchronous / event-driven progression.
// ===========================================================================

/// Errors a pending authentication operation may report while resolving.
pub const OperationError = error{
    /// The underlying async operation failed (signer/verifier/selector fault).
    OperationFailed,
    /// The operation violated its contract (completed with an out-of-range or
    /// wrong-kind result).
    InvalidCallbackBehavior,
};

/// The value an in-flight `PendingOperation` yields on completion, tagged by
/// the operation kind it resolves.
pub const Completion = union(enum) {
    credential: SelectedCredential,
    /// A credential selection that deterministically resolved to "no suitable
    /// credential" (#334). For a client answering a CertificateRequest this is a
    /// normal decline — the engine sends an empty Certificate — not a failure,
    /// so an asynchronous selector can report it faithfully rather than being
    /// forced into a provider-internal error.
    no_credential,
    signature_len: usize,
    verdict: Verdict,
};

/// A handle to an authentication operation that did not complete synchronously
/// — an HSM round-trip, a remote signer, an async verifier. The engine parks it
/// and drives `poll` when the caller signals progress, `cancel` if the
/// handshake is abandoned before it resolves, and `release` exactly once at the
/// end (after completion or cancellation). While pending, the operation owns a
/// snapshot of whatever input it needs; the engine's stack buffers may vanish.
pub const PendingOperation = struct {
    handle: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Poll for completion: returns true and fills `out` when done, false
        /// while still pending. An error terminates the operation.
        poll: *const fn (handle: *anyopaque, out: *Completion) OperationError!bool,
        /// Abandon an in-flight operation (handshake cancelled or failed).
        cancel: *const fn (handle: *anyopaque) void,
        /// Release operation resources. Called exactly once.
        release: *const fn (handle: *anyopaque) void,
    };

    pub fn poll(self: PendingOperation, out: *Completion) OperationError!bool {
        return self.vtable.poll(self.handle, out);
    }
    pub fn cancel(self: PendingOperation) void {
        self.vtable.cancel(self.handle);
    }
    pub fn release(self: PendingOperation) void {
        self.vtable.release(self.handle);
    }
};

/// The result of an authentication callback: `complete` synchronously with a
/// value, or `pending` with an operation the engine resumes later. A
/// synchronous provider always returns `complete` and never allocates a
/// `PendingOperation`; the contract does not force private-key work to block.
pub fn Progress(comptime T: type) type {
    return union(enum) {
        complete: T,
        pending: PendingOperation,
    };
}

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
    unsupported_peer_certificate,
    /// The peer's CertificateVerify signature did not check out against its
    /// presented leaf (proof-of-possession failure). Peer-originated, but a
    /// distinct reason from a structurally invalid chain.
    certificate_verify_invalid,
    peer_verification_rejected,
    verifier_internal_failure,
    invalid_callback_behavior,
    /// The server requires handshake-time client authentication and the client
    /// presented no certificate. Peer-attributed (certificate_required).
    client_certificate_required,

    pub fn origin(self: FailureClass) Origin {
        return switch (self) {
            .invalid_peer_certificate_chain,
            .unsupported_peer_certificate,
            .certificate_verify_invalid,
            .peer_verification_rejected,
            .client_certificate_required,
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
            .peer_verification_rejected,
            => .bad_certificate,
            .unsupported_peer_certificate => .unsupported_certificate,
            // A CertificateVerify signature that fails proof of possession is a
            // decrypt_error, not a trust rejection (RFC 8446 §4.4.3).
            .certificate_verify_invalid => .decrypt_error,
            // The client declined mandatory authentication.
            .client_certificate_required => .certificate_required,
        };
    }

    /// The engine-level `HandshakeError` this failure surfaces as. Peer faults
    /// reuse `CertificateInvalid` (bad_certificate); local faults use the two
    /// credential-specific errors so the wire alert stays correctly attributed.
    pub fn engineError(self: FailureClass) events.HandshakeError {
        return switch (self) {
            .invalid_peer_certificate_chain,
            .peer_verification_rejected,
            => error.CertificateInvalid,
            .unsupported_peer_certificate => error.UnsupportedCertificate,
            .certificate_verify_invalid => error.DecryptError,
            .client_certificate_required => error.ClientCertificateRequired,
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
        error.OutOfMemory => .provider_internal_failure,
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

    /// The private-key material behind each supported scheme, held as the
    /// pure-Zig software implementation of the opaque `provider.SigningKey`
    /// handle rather than a raw `std.crypto` key pair (#490): `sign` below
    /// calls through `SigningKey.sign`, so `Identity` never exposes private
    /// bytes to a caller, and this is the single place they are constructed
    /// or read directly. A future HSM/remote signer would present the same
    /// `provider.SigningKey` shape without `Identity`'s public API changing.
    pub const Key = union(enum) {
        ed25519: pure_zig.SoftwareSigningKey,
        ecdsa_p256: pure_zig.SoftwareEcdsaP256SigningKey,
        rsa: pure_zig.SoftwareRsaSigningKey,
    };

    /// Pre-existing public error type for `initPkcs8`, unchanged by RSA
    /// support: callers that reference `Identity.InitError` directly stay
    /// source-compatible. `initPkcs8` never returns `EntropyFailure` (see
    /// its body), so it does not belong in this set — that case lives only
    /// on `InitWithEntropyError`, the wider type `initPkcs8WithEntropy`
    /// actually needs.
    pub const InitError = error{InvalidPrivateKey};

    /// Error type for `initPkcs8WithEntropy`. `EntropyFailure` is distinct
    /// from `InvalidPrivateKey`: it means the key itself may well be fine
    /// but the injected entropy source failed mid-RSA-import (drawing
    /// Miller-Rabin witnesses), a transient/local provider fault, not
    /// malformed credential data — callers that log or alert on these should
    /// not conflate "bad key on disk" with "entropy source is unhealthy."
    pub const InitWithEntropyError = error{ InvalidPrivateKey, EntropyFailure };

    /// Load an Ed25519 or ECDSA-P256 PKCS#8 private key. Returns
    /// `error.InvalidPrivateKey` for an RSA key — RSA's `p`/`q` primality
    /// check needs an injected entropy source for its random Miller-Rabin
    /// witnesses (a fixed/public witness set is not sound against an
    /// adversarially chosen key; see `rsa.isProbablePrime`'s doc comment),
    /// which this entry point has none of. Use `initPkcs8WithEntropy` for
    /// RSA support.
    pub fn initPkcs8(certificate_der: []const u8, pkcs8_key_der: []const u8) InitError!Identity {
        return initPkcs8Impl(certificate_der, pkcs8_key_der, null) catch |err| switch (err) {
            error.InvalidPrivateKey => error.InvalidPrivateKey,
            // Unreachable: with `entropy = null`, `initPkcs8Impl`'s RSA
            // branch takes `entropy orelse return error.InvalidPrivateKey`
            // immediately, never reaching `SoftwareRsaSigningKey.fromDer`
            // (the only source of `EntropyFailure`).
            error.EntropyFailure => unreachable,
        };
    }

    /// Load an Ed25519, ECDSA-P256, or RSA PKCS#8 private key. `entropy` is
    /// required only for RSA — Ed25519/ECDSA-P256 parsing never touches it —
    /// but every caller must supply one since the key type isn't known until
    /// parsing is underway.
    pub fn initPkcs8WithEntropy(certificate_der: []const u8, pkcs8_key_der: []const u8, entropy: crypto_provider_pkg.Entropy) InitWithEntropyError!Identity {
        return initPkcs8Impl(certificate_der, pkcs8_key_der, entropy);
    }

    fn initPkcs8Impl(certificate_der: []const u8, pkcs8_key_der: []const u8, entropy: ?crypto_provider_pkg.Entropy) InitWithEntropyError!Identity {
        if (ed25519SeedFromPkcs8(pkcs8_key_der)) |seed| {
            const software_key = pure_zig.SoftwareSigningKey.fromSeed(seed) catch return error.InvalidPrivateKey;
            return .{ .certificate_der = certificate_der, .key = .{ .ed25519 = software_key } };
        } else |_| {}
        if (ecdsaP256KeyFromPkcs8(pkcs8_key_der)) |scalar_local| {
            var scalar = scalar_local;
            defer crypto_pkg.secrets.secureZero(&scalar);
            var scalar_secret = crypto_pkg.secrets.FixedSecret(32).init(&scalar) catch return error.InvalidPrivateKey;
            defer scalar_secret.deinit();
            const software_key = pure_zig.SoftwareEcdsaP256SigningKey.fromScalarSecret(&scalar_secret) catch return error.InvalidPrivateKey;
            return .{ .certificate_der = certificate_der, .key = .{ .ecdsa_p256 = software_key } };
        } else |_| {}
        const rsa_key_der = try rsaKeyDerFromPkcs8(pkcs8_key_der);
        const rsa_entropy = entropy orelse return error.InvalidPrivateKey;
        var software_key = pure_zig.SoftwareRsaSigningKey.fromDer(rsa_key_der, rsa_entropy) catch |err| return switch (err) {
            error.EntropyFailure => error.EntropyFailure,
            error.InvalidInput, error.UnsupportedCapability, error.ProviderFailure => error.InvalidPrivateKey,
        };
        errdefer software_key.deinit();

        // A structurally valid RSA private key is not necessarily *this*
        // certificate's key — advertise a credential only when the leaf's
        // own RSAPublicKey (modulus and exponent) matches what the private
        // key can actually sign for. Without this check, an unrelated RSA
        // certificate/key pairing would be selected and only fail once the
        // peer rejects the CertificateVerify signature.
        const leaf = (crypto.Certificate{ .buffer = certificate_der, .index = 0 }).parse() catch
            return error.InvalidPrivateKey;
        if (leaf.pub_key_algo != .rsaEncryption or !software_key.matchesPublicKeyDer(leaf.pubKey()))
            return error.InvalidPrivateKey;

        return .{ .certificate_der = certificate_der, .key = .{ .rsa = software_key } };
    }

    /// The TLS SignatureScheme this identity signs CertificateVerify with.
    pub fn signatureScheme(self: *const Identity) SignatureScheme {
        return switch (self.key) {
            .ed25519 => .ed25519,
            .ecdsa_p256 => .ecdsa_secp256r1_sha256,
            .rsa => .rsa_pss_rsae_sha256,
        };
    }

    /// Legacy accessor returning the raw SignatureScheme code point.
    pub fn signatureAlgorithm(self: *const Identity) u16 {
        return self.signatureScheme().code();
    }

    pub fn format(
        _: Identity,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("TLS identities must not be formatted or logged");
    }

    /// Sign `input` into `out`, returning the signature length. Bounded: never
    /// writes past `out`; reports `SignatureOutputOverflow` when it would.
    /// This is the single place the fixed private key is used for signing —
    /// through the opaque `provider.SigningKey` handle, never a named
    /// `std.crypto.sign` primitive directly (#490).
    pub fn sign(self: *const Identity, input: []const u8, entropy: crypto_provider_pkg.Entropy, out: []u8) SignError!usize {
        // `signingKey()` takes a mutable receiver purely for vtable-context
        // shape; neither supported scheme's `sign` mutates key state, so
        // reborrowing the const union payload as mutable here is sound —
        // `Identity.sign` itself stays a read-only operation from its
        // caller's point of view, matching its `*const Identity` signature.
        const signer: crypto_provider_pkg.SigningKey = switch (self.key) {
            .ed25519 => |*key| @constCast(key).signingKey(),
            .ecdsa_p256 => |*key| @constCast(key).signingKey(),
            .rsa => |*key| @constCast(key).signingKey(),
        };
        return signer.sign(input, entropy, out) catch |err| switch (err) {
            error.InvalidInput => error.SignatureOutputOverflow,
            error.UnsupportedCapability, error.EntropyFailure, error.ProviderFailure => error.SigningProviderFailure,
        };
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

    /// Unwrap a PKCS#8 `PrivateKeyInfo` for `rsaEncryption` (RFC 8017 §A.1.1
    /// inside RFC 5958): SEQUENCE { INTEGER 0, SEQUENCE { OID
    /// 1.2.840.113549.1.1.1, NULL }, OCTET STRING { RSAPrivateKey } }, and
    /// return the borrowed `RSAPrivateKey` DER `pure_zig.SoftwareRsaSigningKey
    /// .fromDer` parses directly. Every structural expectation is enforced,
    /// not just the leading OID: the mandatory NULL parameters, that the
    /// AlgorithmIdentifier and outer SEQUENCE each stop exactly where their
    /// known fields end (no unparsed RFC 5958 attributes silently ignored),
    /// and that the top-level input carries no trailing bytes.
    fn rsaKeyDerFromPkcs8(der: []const u8) InitError![]const u8 {
        const oid_rsa_encryption = [_]u8{ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
        const null_params = [_]u8{ 0x05, 0x00 };
        var walker = DerWalker{ .bytes = der };
        var outer = try walker.sequence();
        try outer.expectInteger(0);
        var alg = try outer.sequence();
        try alg.expectBytes(&oid_rsa_encryption);
        try alg.expectBytes(&null_params);
        if (alg.pos != alg.bytes.len) return error.InvalidPrivateKey;
        const key_der = try outer.octetString();
        if (outer.pos != outer.bytes.len) return error.InvalidPrivateKey;
        if (walker.pos != walker.bytes.len) return error.InvalidPrivateKey;
        return key_der;
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
    entropy: crypto_provider_pkg.Entropy,

    pub fn init(identity: Identity, entropy: crypto_provider_pkg.Entropy) FixedCredentialProvider {
        return .{ .identity = identity, .chain_entry = .{identity.certificate_der}, .entropy = entropy };
    }

    pub fn provider(self: *FixedCredentialProvider) CredentialProvider {
        return .{ .ctx = self, .vtable = &vtable };
    }

    /// Securely clear the private key material.
    pub fn deinit(self: *FixedCredentialProvider) void {
        crypto_pkg.secrets.secureZero(std.mem.asBytes(&self.identity.key));
    }

    const vtable = CredentialProvider.VTable{ .select = select };

    fn select(ctx: *anyopaque, selection: *const SelectionContext) SelectError!Progress(SelectedCredential) {
        const self: *FixedCredentialProvider = @ptrCast(@alignCast(ctx));
        if (self.identity.certificate_der.len == 0) return error.MalformedCredentialChain;
        const scheme = self.identity.signatureScheme();
        // Honor the peer's advertised signature algorithms: a fixed credential
        // whose one scheme the peer did not offer is not usable here (#347's
        // richer selection would try alternate credentials; a fixed provider
        // has only this one).
        if (!selection.offersScheme(scheme)) return error.NoCompatibleSignatureAlgorithm;
        return .{ .complete = .{ .handle = self, .scheme = scheme, .vtable = &credential_vtable } };
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

    fn credentialSign(handle: *anyopaque, scheme: SignatureScheme, input: []const u8, out: []u8) SignError!Progress(usize) {
        const self: *FixedCredentialProvider = @ptrCast(@alignCast(handle));
        // The engine signs with the scheme the credential reported; a mismatch
        // would be an engine bug, guarded here defensively.
        if (scheme != self.identity.signatureScheme()) return error.InvalidCallbackBehavior;
        return .{ .complete = try self.identity.sign(input, self.entropy, out) };
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

    fn verify(ctx: *anyopaque, context: *const VerificationContext) VerifyError!Progress(Verdict) {
        const self: *FixedVerifier = @ptrCast(@alignCast(ctx));
        const leaf = context.chain.leaf() orelse return error.InvalidPeerCertificateChain;
        const verdict: Verdict = switch (self.trust) {
            .pinned_certificate => |pin| if (std.mem.eql(u8, leaf, pin)) .accepted else .rejected,
            .insecure_no_verification => .not_checked,
        };
        return .{ .complete = verdict };
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

    const p256_certificate_bytes = hexBytes(
        "308201b030820156a003020102021440bf2f15168b53a2f36de45a8fe10f2a0dc90eab300a06082a8648ce3d04030230143112301006035504030c093132372e302e302e31301e170d3236303731393137313834355a170d3237303731393137313834355a30143112301006035504030c093132372e302e302e313059301306072a8648ce3d020106082a8648ce3d030107034200047815574399f47ac6876fc8889dd4258cb451d7caa5293b3619800f018f02085861a5ae3a35bb3547d5b4f5c9aae142884961d39722778bfbc07223723afe2386a38185308182301d0603551d0e041604149b4daf99d1f484024795bf2e133c15c7614ec6af301f0603551d230418301680149b4daf99d1f484024795bf2e133c15c7614ec6af300f0603551d130101ff040530030101ff301a0603551d110413301187047f00000182096c6f63616c686f737430130603551d25040c300a06082b06010505070301300a06082a8648ce3d04030203480030450220675306f8aa6f9d82bf45acfbc4c273f4dc52bd60f49115dad4f0bc26e3e1cd29022100cad745d5dbcdf7f910dfc5afcdaf4a0dad09222842fbee61436fc90bc004ffdc",
    );
    const p256_private_key_bytes = hexBytes(
        "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420f017bbb44ed9ea2263b59c0c04fe83433f432014a80782af0710384ef5452234a144034200047815574399f47ac6876fc8889dd4258cb451d7caa5293b3619800f018f02085861a5ae3a35bb3547d5b4f5c9aae142884961d39722778bfbc07223723afe2386",
    );

    pub const p256_certificate_der: []const u8 = &p256_certificate_bytes;
    pub const p256_private_key_pkcs8_der: []const u8 = &p256_private_key_bytes;

    // Self-signed RSA-2048 fixture, CN=tardigrade.test, generated with
    // openssl (`openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`
    // + `openssl req -new -x509`). `rsa_private_key_bytes` is the PKCS#8
    // `PrivateKeyInfo` wrapping form `Identity.initPkcs8` unwraps via
    // `rsaKeyDerFromPkcs8` — matches `rsa.zig`'s own `testdata`, which holds
    // the same key's bare PKCS#1 `RSAPrivateKey`/`RSAPublicKey` DER for
    // lower-level provider tests.
    const rsa_certificate_bytes = hexBytes(
        "30820315308201fda00302010202145b36622ef1cd21d37cd907d98f391f900653d212300d06092a864886f70d01010b0500301a3118301606035504030c0f746172646967726164652e74657374301e170d3236303830333032313833375a170d3336303733313032313833375a301a3118301606035504030c0f746172646967726164652e7465737430820122300d06092a864886f70d01010105000382010f003082010a028201010092af7ce98c5ada061925562b8ad51c91242589053bc4d81283fb8b7f32ad27b1c0bbeff24e7126ec5d9956fd36c6621459cf5d99f8a6b7790d77a0a7480cb490db649a1882d89876c4eacf39aeef0dab58174dba46abcc948e4755b3f41aa045be5ce6382fefe7c7e0e6ad1c5f59d2c76ed2cbf5daff65d567609eb4daec1058c20ffa7c45db67146c95d36632ce793687b577003589ecafb8ab176d47781ac11d4434d56889d52b86bf3f87bc5893dbebde97dbdf58e57242a4cf4fbec148c0ede4faed1ebad450da2272bab56c48a7eacff3bd62e8685a00de2db458ed2b91f2453139c90dd3724ed82aa825f4dd4885f85ec0e09e1c72682db6fdd1b921e90203010001a3533051301d0603551d0e04160414afadb2110af59c4b5c8e27f14436afab0e22e25f301f0603551d23041830168014afadb2110af59c4b5c8e27f14436afab0e22e25f300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000382010100925514498cccec0fec872db5b8e1472080cce1d5e197d7c359f644b732a682ec2ca8d6318c61914d099e490bae8bf104f6d114770865398144554acfddf2d8538ec6930b2ce1dacc432d0098d5fcd366fe63555e2ef59df65fc801ae475b4565983cc012c3a160042f7b4b47ab743f255f6da3e2ee3ed572e608e4312e615a915c3a92eb6c95a2e3391e9ec3b9dbb50fb4150b0f9224c0b4142e9371c7704e5c92415f7a46960499e04ae7cbd43f7f83ac683aa50f0d4ff78aaf6460c8881d37416e1009433c00b131181beb2dbd1062d2d03d7e79f32d33a935b8bdc7146b648661e4b2b042fd73df221e512e227b4e587160c032988ba27296f07987d66b47",
    );
    const rsa_private_key_bytes = hexBytes(
        "308204be020100300d06092a864886f70d0101010500048204a8308204a4020100028201010092af7ce98c5ada061925562b8ad51c91242589053bc4d81283fb8b7f32ad27b1c0bbeff24e7126ec5d9956fd36c6621459cf5d99f8a6b7790d77a0a7480cb490db649a1882d89876c4eacf39aeef0dab58174dba46abcc948e4755b3f41aa045be5ce6382fefe7c7e0e6ad1c5f59d2c76ed2cbf5daff65d567609eb4daec1058c20ffa7c45db67146c95d36632ce793687b577003589ecafb8ab176d47781ac11d4434d56889d52b86bf3f87bc5893dbebde97dbdf58e57242a4cf4fbec148c0ede4faed1ebad450da2272bab56c48a7eacff3bd62e8685a00de2db458ed2b91f2453139c90dd3724ed82aa825f4dd4885f85ec0e09e1c72682db6fdd1b921e9020301000102820100225b8d680cd288e7cdc3038c7e5fcd69a7ac4d0c574413923eacd02f5278e167ceab9697cc4ccf9fa48ad2a7cbc92ad6f6744e49cec68a0a06200396bb1712c22d494298c42924890935b0a523b6e59e412b702ed5f7ce9aeb3a8535f9d2b4c0b146843c1bea570167c9d039699219ff51937967944ca71715b839644634eddce9700cde13717d98963cb2a4a2808c3b4add40a44df95f576500f3d82de9d25fe5e69ee08a0dc1599bbc7ae7681061126dc172427bbe22111c9faf2d0ca74728cdc3502b6aef8ecb26dccf0768055cece8079e516f15819c9d5ad056c6e8302d17d781392102dc09fbf8f813964a54646631e8fe3c27405f344c99505d539fa902818100cb8d33ac351529071f695efd67c9d3a5f3cfa76e42cee65a29b8a32f6b79b07679ecf138f82c3dfdb58cbf4609751b5b17478a60888503b4ebe61b3d459d00c933836d4271a7c8feff058c3667ce33f2236344e69c30b64cfdfcf59fdaabca6f2463d89ab842e44f0288f8e318d9c1250b9a57aa95db61134de7f129a44e9edd02818100b87b400d63d31ba7864de2bf3e7c8ce2af6c1c46620138a2c8a2a3fc52a687f2a991c549e3971c6e29f3605498268d35fecf5653f91e25c71112689474d9abe2eee2f7c74ac172c156c3d8e139fbf4de85888b5dbc810005a3fd2a9ca3d446f931e1d427633e702530d393521fbe6a8cc88915a2a49ff39faa2a320bde2ad07d02818100a95f00d41607597037cef1df61712acf37a45de8fd66337e6aa0dc082521c8978cb47fb3abad04980b6ce5eb5d0b388bff3ee401971737126007c43aa3a61475568bd16a2c3034ab1980803ef4f93b780bc21a1ed9701f00c986a6cb30a52978798b2b3cf27d9683b7d449648dd50345d3f5c56487f5573d3ce1f66573f687710281810089dba07be1130ae15f5da88a1d59d9b6343ce7cc38c48cdc286e5178e7128718f15a7b41c20f543186abd65aa0f07e29d166832e7144f41a1449db58c5113c7f72e0ad24825a99349d6ff10c2dd678a028cd66c7ff6baee6882b51c28832c36ec8b5e7621fa9b30837ba83a6a50e1875680df8daf78687f9d2a1819098cf09c902818043160afb78cc14e9b0b9ac88f83d72fbf75f9594c77d1dd0ecd98b4af5255d362bb74c0e7f0f9ed7fbc65aae99606326653afa099f7d4bbe039d45e5ceaacbab4bf4c21354e616aae47ad1032261a9abe0600c6f2687ff0235893b91513366867e99d21a80d3b16fffab975e99fd18645698bc104bfe206e0b11e45cbf729f11",
    );

    pub const rsa_certificate_der: []const u8 = &rsa_certificate_bytes;
    pub const rsa_private_key_pkcs8_der: []const u8 = &rsa_private_key_bytes;

    // A second, unrelated RSA-2048 key (different modulus/exponents), used
    // only to prove `rsa_certificate_der` paired with the *wrong* private
    // key is rejected rather than silently accepted as a usable credential.
    const other_rsa_private_key_bytes = hexBytes(
        "308204be020100300d06092a864886f70d0101010500048204a8308204a40201000282010100f15415a9a76266a3fa82a83f6dd5e12645ab9a716f8a53589428c630ff9cbe7a0c797f140657ccda65d113102274b13cea73ec8e8a19d490312745dec15f42cd8c04ecec80ae32afaa4c0d1f91408a33a9a74c1c1543d070a5a469e3fb0c8d91406526d40e1a38d5262aeeed2c64e5e908996cf0a6674a033037751c0b798e43c0704ae2a50e2c77302179c2e910bcb484c15f59c2a0e3bde01061fe4b36d56ab60cb84592526e53f2d616f0e13afc94b9319572b12c12db3a9f3682c181be40ef6adf4549b79ebf17b7d3ffa61a243e2c891df46122f7d3f24a7d2cfa416af411a798908fb1284dad1b2e8e90cf62970d367a0653de2388c3b1a740c05ae5090203010001028201000b6fb66a188c557c6260043ca3461e3a1bd59ec74ee7a17d02626f47fda90e2ec6fe0ffb61349278ec17cd1d37e0cb506d74ea6a33d9b704d14b80e866460f2aa1fecec283739de3ccc07763be54ae67f5db7f841a2ee14721566a0d3b85b404c4e6364198dc7dc27e214d3ad09e8475b76a5beb089bbefa6933cb993563008e9656463bb6568facc694f8dec58df7706e3c992fdd2b35c37ec89268f42e0031332ecc3b72a282b722606bbf4b4c5447869fbc93db8da3375858720c485a182fd1f03456ba48f70b867b9a4724f121a7e3bebe22e2f3caaeda1b1a40e6f09388b286933dbd1f86e5c5f08a2ceae4b41d2cbbe740572b97404a4ba836d086331d02818100fa434d920e8ba5cafd03616d47029311cfec89055ca4d537e093845977b53d5c150a60fc81c50fa3390b6134484813ab4a0bdcf58a69d7807ebe0b879ef62ceade43cba98ab00fe6818147c20ac9281f851d4243f99cc84950b469c821d7f61bd5f752931ee23fedaead680bc5963bf684b3a889bed61ce3ecf14cde9943d87d02818100f6dc5948e0034c3965da1de0d6cf5fb23033e74046fc54876537fb40ffb0f59353cb8dda5ac2e0ba917ae8dd8b51487faff483e9ad67a463b15dde87f34db91d58ad63f0986ab64495df70ff9f9efea1ce01d8619de42466e5435f001a4b4a3f87e423c1b114799bc9bb4f52eb1253a9cc5cfc34913ece40a4e30de9d469f07d02818061e902e82998a8fc8990510597ca820f6df1748a0c7cd08e53e662d93de442654c360b4bbed9820cb1bcaa02f264808d7b22b907b76741509c456ded595ba6a71cde1947f3627e560844b3f64e91f488a0639a114e0ef0acfe4e17349d4908984b55bf909f7c94d64088c73413d17b142f46baa169700b4d80ddc6dd2fc9436102818100b2c9ca1c7ea9c4c5f95f6cae4fc5a7705d7ae9ec62bd13d76fd688b17dbe434dedad8a526fd39e8161261c8b800061baa0cc3dd1bb5649f82e1867381d5dd84949d562817952282a2a45c7084c2a120f4c2d87f2c330ddb06c314c17bdf37395e9acb0bcf2ac7a9afb131f1355cf532ab229523c1c49d985762640086f603edd02818100d52656918165d006ef10fe005b9f309efee2daca8fbaee0098590e23aa869e694773e3e0fac39988254ed54789a9dd5b4f73a3d473d98059d3583f08b4c7899609afe32235d2d421063da1200dd154fe0781cf9d3dc63de90c51a99f01a0ca1af02bd68a01a86e2e13c8d2b7ca777e1db5d6579020552954ac47ec1bdc780dcd",
    );
    pub const other_rsa_private_key_pkcs8_der: []const u8 = &other_rsa_private_key_bytes;

    pub fn identity() Identity {
        return Identity.initPkcs8(certificate_der, private_key_pkcs8_der) catch unreachable;
    }

    pub fn p256Identity() Identity {
        return Identity.initPkcs8(p256_certificate_der, p256_private_key_pkcs8_der) catch unreachable;
    }

    pub fn rsaIdentity() Identity {
        var det = pure_zig.DeterministicEntropy.init(0x8511);
        return Identity.initPkcs8WithEntropy(rsa_certificate_der, rsa_private_key_pkcs8_der, det.entropy()) catch unreachable;
    }

    const ignored_entropy_context: u8 = 0;

    fn ignoredEntropyFill(_: *anyopaque, out: []u8) crypto_provider_pkg.EntropyError!void {
        @memset(out, 0);
    }

    pub fn ignoredEntropy() crypto_provider_pkg.Entropy {
        return .{ .context = @ptrCast(@constCast(&ignored_entropy_context)), .fillFn = ignoredEntropyFill };
    }
};

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(4096);
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
    /// Test-only scheme override for modelling a provider that advertises an
    /// algorithm inconsistent with the certificate's public key.
    scheme_override: ?SignatureScheme = null,
    /// Sign normally, then flip a signature byte, to model a peer whose
    /// CertificateVerify does not check out (proof-of-possession failure).
    flip_signature: bool = false,
    chain_storage: [16][]const u8 = undefined,
    /// Async modelling: when set, `select`/`sign` return `pending`, and the
    /// pending operation reports `pending` for `pending_polls` polls before
    /// completing (or failing, when `pending_fails`).
    async_select: bool = false,
    async_sign: bool = false,
    /// When set, an asynchronous selection resolves to the "no suitable
    /// credential" completion rather than a credential, modelling a selector
    /// that decides to decline (empty Certificate) only after suspending.
    async_no_credential: bool = false,
    /// When set, an asynchronous signature completes with the wrong Completion
    /// kind (a credential instead of a signature length), modelling a provider
    /// that violates the callback contract, to prove the engine releases every
    /// owned handle exactly once.
    sign_returns_credential: bool = false,
    /// When set alongside `pending_fails`, the poll error is
    /// `InvalidCallbackBehavior` rather than `OperationFailed`, modelling a
    /// provider that violates the callback contract rather than merely failing.
    pending_fail_invalid_callback: bool = false,
    pending_polls: usize = 1,
    pending_fails: bool = false,
    poll_count: usize = 0,
    cancel_count: usize = 0,
    op_release_count: usize = 0,
    // Snapshot of the signing job captured when a pending sign is issued.
    pending_kind: enum { none, select, sign } = .none,
    pending_out: []u8 = &.{},
    pending_input: [256]u8 = undefined,
    pending_input_len: usize = 0,
    remaining_polls: usize = 0,

    select_count: usize = 0,
    sign_count: usize = 0,
    release_count: usize = 0,
    /// The last SNI selection saw, copied into mock-owned storage — the
    /// `SelectionContext.server_name` slice is only valid during `select`, so a
    /// mock that wants to remember it MUST NOT retain the borrowed slice.
    last_server_name_buf: [256]u8 = undefined,
    last_server_name_len: usize = 0,
    last_server_name_present: bool = false,
    last_application_protocol_buf: [255]u8 = undefined,
    last_application_protocol_len: usize = 0,
    last_application_protocol_present: bool = false,
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

    pub fn lastApplicationProtocol(self: *const MockCredentialProvider) ?[]const u8 {
        return if (self.last_application_protocol_present) self.last_application_protocol_buf[0..self.last_application_protocol_len] else null;
    }

    pub fn selectedCredential(self: *MockCredentialProvider) SelectedCredential {
        return .{ .handle = self, .scheme = self.selectedScheme(), .vtable = &credential_vtable };
    }

    fn selectedScheme(self: *const MockCredentialProvider) SignatureScheme {
        return self.scheme_override orelse self.identity.signatureScheme();
    }

    const vtable = CredentialProvider.VTable{ .select = select };

    fn select(ctx: *anyopaque, selection: *const SelectionContext) SelectError!Progress(SelectedCredential) {
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
        if (selection.application_protocol) |protocol| {
            const n = @min(protocol.len, self.last_application_protocol_buf.len);
            @memcpy(self.last_application_protocol_buf[0..n], protocol[0..n]);
            self.last_application_protocol_len = n;
            self.last_application_protocol_present = true;
        } else {
            self.last_application_protocol_present = false;
            self.last_application_protocol_len = 0;
        }
        self.last_offered_scheme_count = selection.peer_signature_schemes.len;
        if (self.force_select_error) |err| return err;
        const scheme = self.selectedScheme();
        if (!self.ignore_offer and !selection.offersScheme(scheme)) return error.NoCompatibleSignatureAlgorithm;
        if (self.async_select) {
            self.pending_kind = .select;
            self.remaining_polls = self.pending_polls;
            return .{ .pending = self.pendingOp() };
        }
        return .{ .complete = self.selectedCredential() };
    }

    fn pendingOp(self: *MockCredentialProvider) PendingOperation {
        return .{ .handle = self, .vtable = &op_vtable };
    }

    const op_vtable = PendingOperation.VTable{ .poll = opPoll, .cancel = opCancel, .release = opRelease };

    fn opPoll(handle: *anyopaque, out: *Completion) OperationError!bool {
        const self: *MockCredentialProvider = @ptrCast(@alignCast(handle));
        self.poll_count += 1;
        if (self.remaining_polls > 0) {
            self.remaining_polls -= 1;
            return false;
        }
        if (self.pending_fails) return if (self.pending_fail_invalid_callback) error.InvalidCallbackBehavior else error.OperationFailed;
        switch (self.pending_kind) {
            .select => out.* = if (self.async_no_credential) .no_credential else .{ .credential = self.selectedCredential() },
            .sign => {
                if (self.sign_returns_credential) {
                    // Contract violation: hand back a credential where a
                    // signature length is required.
                    out.* = .{ .credential = self.selectedCredential() };
                    return true;
                }
                self.sign_count += 1;
                const written = self.identity.sign(self.pending_input[0..self.pending_input_len], mockSignEntropy(), self.pending_out) catch
                    return error.OperationFailed;
                out.* = .{ .signature_len = written };
            },
            .none => return error.InvalidCallbackBehavior,
        }
        return true;
    }

    fn opCancel(handle: *anyopaque) void {
        const self: *MockCredentialProvider = @ptrCast(@alignCast(handle));
        self.cancel_count += 1;
    }

    fn opRelease(handle: *anyopaque) void {
        const self: *MockCredentialProvider = @ptrCast(@alignCast(handle));
        self.op_release_count += 1;
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

    fn credentialSign(handle: *anyopaque, scheme: SignatureScheme, input: []const u8, out: []u8) SignError!Progress(usize) {
        const self: *MockCredentialProvider = @ptrCast(@alignCast(handle));
        _ = scheme;
        if (self.async_sign) {
            // Snapshot the transcript-derived input and capture the (stable,
            // engine-owned) output buffer; complete on a later poll.
            self.pending_kind = .sign;
            self.remaining_polls = self.pending_polls;
            const n = @min(input.len, self.pending_input.len);
            @memcpy(self.pending_input[0..n], input[0..n]);
            self.pending_input_len = n;
            self.pending_out = out;
            return .{ .pending = self.pendingOp() };
        }
        self.sign_count += 1;
        if (self.force_sign_error) |err| return err;
        if (self.force_sign_len) |forced| return .{ .complete = forced }; // may exceed out.len on purpose
        const written = try self.identity.sign(input, mockSignEntropy(), out);
        if (self.flip_signature and written > 0) out[0] ^= 0xff;
        return .{ .complete = written };
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
    last_application_protocol_buf: [255]u8 = undefined,
    last_application_protocol_len: usize = 0,
    last_application_protocol_present: bool = false,
    /// Async modelling: return `pending`, resolving to `result` after
    /// `pending_polls` polls.
    async_mode: bool = false,
    pending_polls: usize = 1,
    remaining_polls: usize = 0,
    poll_count: usize = 0,
    cancel_count: usize = 0,
    op_release_count: usize = 0,

    pub fn init(result: VerifyError!Verdict) MockVerifier {
        return .{ .result = result };
    }

    pub fn verifier(self: *MockVerifier) PeerVerifier {
        return .{ .ctx = self, .vtable = &vtable };
    }

    pub fn lastServerName(self: *const MockVerifier) ?[]const u8 {
        return if (self.last_server_name_present) self.last_server_name_buf[0..self.last_server_name_len] else null;
    }

    pub fn lastApplicationProtocol(self: *const MockVerifier) ?[]const u8 {
        return if (self.last_application_protocol_present) self.last_application_protocol_buf[0..self.last_application_protocol_len] else null;
    }

    const vtable = PeerVerifier.VTable{ .verify = verify };

    fn verify(ctx: *anyopaque, context: *const VerificationContext) VerifyError!Progress(Verdict) {
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
        if (context.application_protocol) |protocol| {
            const n = @min(protocol.len, self.last_application_protocol_buf.len);
            @memcpy(self.last_application_protocol_buf[0..n], protocol[0..n]);
            self.last_application_protocol_len = n;
            self.last_application_protocol_present = true;
        } else {
            self.last_application_protocol_present = false;
            self.last_application_protocol_len = 0;
        }
        if (self.async_mode) {
            self.remaining_polls = self.pending_polls;
            return .{ .pending = .{ .handle = self, .vtable = &op_vtable } };
        }
        return .{ .complete = try self.result };
    }

    const op_vtable = PendingOperation.VTable{ .poll = opPoll, .cancel = opCancel, .release = opRelease };

    fn opPoll(handle: *anyopaque, out: *Completion) OperationError!bool {
        const self: *MockVerifier = @ptrCast(@alignCast(handle));
        self.poll_count += 1;
        if (self.remaining_polls > 0) {
            self.remaining_polls -= 1;
            return false;
        }
        const verdict = self.result catch return error.OperationFailed;
        out.* = .{ .verdict = verdict };
        return true;
    }

    fn opCancel(handle: *anyopaque) void {
        const self: *MockVerifier = @ptrCast(@alignCast(handle));
        self.cancel_count += 1;
    }

    fn opRelease(handle: *anyopaque) void {
        const self: *MockVerifier = @ptrCast(@alignCast(handle));
        self.op_release_count += 1;
    }
};

// ===========================================================================
// Contract-level tests. Real-handshake integration lives in
// tls13_backend_tests.zig; these pin the contract's own guarantees.
// ===========================================================================

const testing = std.testing;

fn mockSignEntropy() crypto_provider_pkg.Entropy {
    return testdata.ignoredEntropy();
}

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

// Synchronous unwrap helpers for the contract tests: assert the callback
// completed rather than returning `pending`.
fn syncSelect(provider: CredentialProvider, selection: *const SelectionContext) !SelectedCredential {
    return switch (try provider.selectCredential(selection)) {
        .complete => |credential| credential,
        .pending => error.TestUnexpectedPending,
    };
}
fn syncSign(credential: SelectedCredential, input: []const u8, out: []u8) !usize {
    return switch (try credential.sign(input, out)) {
        .complete => |written| written,
        .pending => error.TestUnexpectedPending,
    };
}
fn syncVerify(v: PeerVerifier, context: *const VerificationContext) !Verdict {
    return switch (try v.verifyPeer(context)) {
        .complete => |verdict| verdict,
        .pending => error.TestUnexpectedPending,
    };
}

test "fixed provider selects and exposes its public chain without private-key bytes" {
    var fixed = FixedCredentialProvider.init(testdata.identity(), testdata.ignoredEntropy());
    defer fixed.deinit();
    const provider = fixed.provider();

    const selection = testSelection(&.{ 0x0807, 0x0403 });
    const credential = try syncSelect(provider, &selection);
    try testing.expectEqual(SignatureScheme.ed25519, credential.scheme);

    const chain = credential.certificateChain();
    try testing.expectEqual(@as(usize, 1), chain.count());
    try testing.expectEqualSlices(u8, testdata.certificate_der, chain.leaf().?);
    credential.release();
}

test "fixed provider signs a bounded output the certificate can verify" {
    var fixed = FixedCredentialProvider.init(testdata.identity(), testdata.ignoredEntropy());
    defer fixed.deinit();
    const provider = fixed.provider();
    const selection = testSelection(&.{0x0807});
    const credential = try syncSelect(provider, &selection);
    defer credential.release();

    const message = "TLS 1.3 CertificateVerify transcript-derived signing input";
    var sig_buf: [128]u8 = undefined;
    const written = try syncSign(credential, message, &sig_buf);
    try testing.expectEqual(Ed25519.Signature.encoded_length, written);

    // The signature verifies against the certificate's Ed25519 public key.
    const parsed = try (crypto.Certificate{ .buffer = testdata.certificate_der, .index = 0 }).parse();
    const public_key = try Ed25519.PublicKey.fromBytes(parsed.pubKey()[0..Ed25519.PublicKey.encoded_length].*);
    const sig = Ed25519.Signature.fromBytes(sig_buf[0..Ed25519.Signature.encoded_length].*);
    try sig.verify(message, public_key);
}

test "fixed provider selects and signs ECDSA only for compatible offers" {
    var det = pure_zig.DeterministicEntropy.init(0x4326);
    var fixed = FixedCredentialProvider.init(testdata.p256Identity(), det.entropy());
    defer fixed.deinit();
    const provider_view = fixed.provider();

    const incompatible = testSelection(&.{0x0807});
    try testing.expectError(error.NoCompatibleSignatureAlgorithm, provider_view.selectCredential(&incompatible));

    const selection = testSelection(&.{0x0403});
    const credential = try syncSelect(provider_view, &selection);
    defer credential.release();
    try testing.expectEqual(SignatureScheme.ecdsa_secp256r1_sha256, credential.scheme);

    const message = "ECDSA CertificateVerify credential path";
    var sig_buf: [128]u8 = undefined;
    const written = try syncSign(credential, message, &sig_buf);

    var verify_entropy = pure_zig.DeterministicEntropy.init(0x4327);
    var verify_provider = pure_zig.Provider.init(verify_entropy.entropy());
    const cp = verify_provider.cryptoProvider();
    const parsed = try (crypto.Certificate{ .buffer = testdata.p256_certificate_der, .index = 0 }).parse();
    try cp.verify(.ecdsa_secp256r1_sha256, parsed.pubKey(), message, sig_buf[0..written]);
}

test "fixed provider selects and signs RSA-PSS only for compatible offers" {
    var det = pure_zig.DeterministicEntropy.init(0x5926);
    var fixed = FixedCredentialProvider.init(testdata.rsaIdentity(), det.entropy());
    defer fixed.deinit();
    const provider_view = fixed.provider();

    const incompatible = testSelection(&.{0x0807});
    try testing.expectError(error.NoCompatibleSignatureAlgorithm, provider_view.selectCredential(&incompatible));

    const selection = testSelection(&.{0x0804});
    const credential = try syncSelect(provider_view, &selection);
    defer credential.release();
    try testing.expectEqual(SignatureScheme.rsa_pss_rsae_sha256, credential.scheme);

    const message = "RSA-PSS CertificateVerify credential path";
    var sig_buf: [512]u8 = undefined;
    const written = try syncSign(credential, message, &sig_buf);
    try testing.expectEqual(@as(usize, 256), written);

    var verify_entropy = pure_zig.DeterministicEntropy.init(0x5927);
    var verify_provider = pure_zig.Provider.init(verify_entropy.entropy());
    const cp = verify_provider.cryptoProvider();
    const parsed = try (crypto.Certificate{ .buffer = testdata.rsa_certificate_der, .index = 0 }).parse();
    try testing.expect(parsed.pub_key_algo == .rsaEncryption);
    try cp.verify(.rsa_pss_rsae_sha256, parsed.pubKey(), message, sig_buf[0..written]);
}

test "fixed provider rejects an output buffer too small for the signature" {
    var fixed = FixedCredentialProvider.init(testdata.identity(), testdata.ignoredEntropy());
    defer fixed.deinit();
    const provider = fixed.provider();
    const selection = testSelection(&.{0x0807});
    const credential = try syncSelect(provider, &selection);
    defer credential.release();

    var tiny: [16]u8 = undefined;
    try testing.expectError(error.SignatureOutputOverflow, credential.sign("input", &tiny));
}

test "fixed provider filters on the peer's offered signature algorithms" {
    var fixed = FixedCredentialProvider.init(testdata.identity(), testdata.ignoredEntropy()); // Ed25519 identity
    defer fixed.deinit();
    const provider = fixed.provider();

    // Peer offers only ECDSA P-256; the Ed25519 credential is not compatible.
    const ecdsa_only = testSelection(&.{0x0403});
    try testing.expectError(error.NoCompatibleSignatureAlgorithm, provider.selectCredential(&ecdsa_only));

    // With no schemes offered at all, still no compatible scheme.
    const none = testSelection(&.{});
    try testing.expectError(error.NoCompatibleSignatureAlgorithm, provider.selectCredential(&none));
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
    const credential = try syncSelect(provider, &selection);
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
    const credential = try syncSelect(provider, &selection);
    defer credential.release();

    var out: [128]u8 = undefined;
    try testing.expectError(error.InvalidCallbackBehavior, credential.sign("input", &out));
}

test "mock provider reports a scripted signing failure" {
    var mock = MockCredentialProvider.init(testdata.identity());
    mock.force_sign_error = error.SigningProviderFailure;
    const provider = mock.provider();
    const selection = testSelection(&.{0x0807});
    const credential = try syncSelect(provider, &selection);
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
    try testing.expectEqual(Verdict.accepted, try syncVerify(pinned.verifier(), &context));

    var wrong = [_]u8{0} ** 4;
    var mismatched = FixedVerifier.init(.{ .pinned_certificate = &wrong });
    try testing.expectEqual(Verdict.rejected, try syncVerify(mismatched.verifier(), &context));

    var insecure = FixedVerifier.init(.insecure_no_verification);
    try testing.expectEqual(Verdict.not_checked, try syncVerify(insecure.verifier(), &context));
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
    try testing.expectEqual(Verdict.rejected, try syncVerify(rejecting.verifier(), &context));
    try testing.expectEqual(@as(usize, 1), rejecting.verify_count);
    try testing.expectEqual(@as(usize, 1), rejecting.last_chain_len);
    try testing.expectEqual(Role.client, rejecting.last_role.?);

    var failing = MockVerifier.init(error.VerifierInternalFailure);
    try testing.expectError(error.VerifierInternalFailure, failing.verifier().verifyPeer(&context));
}

test "every failure class maps to a deterministic alert, origin, and engine error" {
    // Peer-originated authentication failures blame the peer's certificate.
    for ([_]FailureClass{ .invalid_peer_certificate_chain, .peer_verification_rejected }) |class| {
        try testing.expectEqual(Origin.peer, class.origin());
        try testing.expectEqual(alerts.AlertDescription.bad_certificate, class.alert());
        try testing.expectEqual(@as(events.HandshakeError, error.CertificateInvalid), class.engineError());
    }
    try testing.expectEqual(Origin.peer, FailureClass.unsupported_peer_certificate.origin());
    try testing.expectEqual(alerts.AlertDescription.unsupported_certificate, FailureClass.unsupported_peer_certificate.alert());
    try testing.expectEqual(@as(events.HandshakeError, error.UnsupportedCertificate), FailureClass.unsupported_peer_certificate.engineError());
    // A CertificateVerify proof-of-possession failure is peer-originated but
    // carries the distinct decrypt_error alert (RFC 8446 §4.4.3).
    try testing.expectEqual(Origin.peer, FailureClass.certificate_verify_invalid.origin());
    try testing.expectEqual(alerts.AlertDescription.decrypt_error, FailureClass.certificate_verify_invalid.alert());
    try testing.expectEqual(@as(events.HandshakeError, error.DecryptError), FailureClass.certificate_verify_invalid.engineError());
    // A client that declines mandatory authentication is peer-attributed but
    // carries the distinct certificate_required alert (RFC 8446 §4.4.2.4).
    try testing.expectEqual(Origin.peer, FailureClass.client_certificate_required.origin());
    try testing.expectEqual(alerts.AlertDescription.certificate_required, FailureClass.client_certificate_required.alert());
    try testing.expectEqual(@as(events.HandshakeError, error.ClientCertificateRequired), FailureClass.client_certificate_required.engineError());
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
    var fixed = FixedCredentialProvider.init(testdata.identity(), testdata.ignoredEntropy());
    fixed.deinit();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&fixed.identity.key), 0));
}

test "identity parser loads and rejects malformed PKCS#8" {
    try testing.expect(@hasDecl(Identity, "format"));
    const identity = try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der);
    const parsed = try (crypto.Certificate{ .buffer = testdata.certificate_der, .index = 0 }).parse();
    try testing.expect(parsed.pub_key_algo == .curveEd25519);
    try testing.expectEqualSlices(u8, parsed.pubKey(), &identity.key.ed25519.publicKey());
    try testing.expectError(
        error.InvalidPrivateKey,
        Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der[0 .. testdata.private_key_pkcs8_der.len - 1]),
    );
}

test "identity parser loads a PKCS#8 RSA key and rejects a truncated one" {
    var det = pure_zig.DeterministicEntropy.init(0x8512);
    const identity = try Identity.initPkcs8WithEntropy(testdata.rsa_certificate_der, testdata.rsa_private_key_pkcs8_der, det.entropy());
    try testing.expectEqual(SignatureScheme.rsa_pss_rsae_sha256, identity.signatureScheme());
    try testing.expectEqual(@as(usize, 256), identity.key.rsa.key.modulusLen());
    try testing.expectError(
        error.InvalidPrivateKey,
        Identity.initPkcs8WithEntropy(testdata.rsa_certificate_der, testdata.rsa_private_key_pkcs8_der[0 .. testdata.rsa_private_key_pkcs8_der.len - 1], det.entropy()),
    );
}

test "identity parser without an entropy source rejects an RSA key" {
    // `initPkcs8` (no entropy) must fail closed for RSA rather than silently
    // skip the primality check `initPkcs8WithEntropy` performs.
    try testing.expectError(
        error.InvalidPrivateKey,
        Identity.initPkcs8(testdata.rsa_certificate_der, testdata.rsa_private_key_pkcs8_der),
    );
}

test "identity parser preserves EntropyFailure distinctly from InvalidPrivateKey for RSA" {
    // A failing entropy source is a local/transient provider fault, not
    // malformed credential data — initPkcs8WithEntropy must not collapse it
    // into the same error a caller would otherwise read as "bad key on
    // disk."
    const FailingEntropy = struct {
        fn fill(_: *anyopaque, _: []u8) crypto_provider_pkg.EntropyError!void {
            return error.EntropyFailure;
        }
    };
    var context: u8 = 0;
    const failing_entropy = crypto_provider_pkg.Entropy{ .context = &context, .fillFn = FailingEntropy.fill };
    try testing.expectError(
        error.EntropyFailure,
        Identity.initPkcs8WithEntropy(testdata.rsa_certificate_der, testdata.rsa_private_key_pkcs8_der, failing_entropy),
    );
}

test "identity parser rejects an RSA certificate paired with an unrelated RSA private key" {
    // Both keys are individually well-formed, mathematically valid RSA-2048
    // private keys; only their pairing with `rsa_certificate_der` is wrong.
    // The mismatch must be caught here, at construction, not discovered only
    // when a peer rejects the resulting CertificateVerify signature.
    var det = pure_zig.DeterministicEntropy.init(0x8513);
    try testing.expectError(
        error.InvalidPrivateKey,
        Identity.initPkcs8WithEntropy(testdata.rsa_certificate_der, testdata.other_rsa_private_key_pkcs8_der, det.entropy()),
    );
}

test "RSA PKCS#8 wrapper rejects missing NULL parameters, extra fields, and trailing bytes" {
    var det = pure_zig.DeterministicEntropy.init(0x8514);
    const valid = testdata.rsa_private_key_pkcs8_der;

    // Corrupt the two-byte NULL (0x05 0x00) immediately following the OID:
    // flipping its tag byte to something else breaks `expectBytes`.
    const null_offset = std.mem.indexOf(u8, valid, &[_]u8{ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 }).? + 11;
    var missing_null = try testing.allocator.dupe(u8, valid);
    defer testing.allocator.free(missing_null);
    missing_null[null_offset] = 0x04; // NULL tag (0x05) replaced with OCTET STRING tag
    try testing.expectError(error.InvalidPrivateKey, Identity.initPkcs8WithEntropy(testdata.rsa_certificate_der, missing_null, det.entropy()));

    // Trailing bytes after the top-level SEQUENCE.
    var with_trailer = try testing.allocator.alloc(u8, valid.len + 1);
    defer testing.allocator.free(with_trailer);
    @memcpy(with_trailer[0..valid.len], valid);
    with_trailer[valid.len] = 0x00;
    try testing.expectError(error.InvalidPrivateKey, Identity.initPkcs8WithEntropy(testdata.rsa_certificate_der, with_trailer, det.entropy()));

    // Extra bytes appended inside the AlgorithmIdentifier SEQUENCE, after its
    // NULL parameters but still inside the SEQUENCE's declared length —
    // exercises the `alg.pos != alg.bytes.len` exhaustion check specifically
    // (distinct from the top-level trailing-bytes case above).
    const alg_seq_start = std.mem.indexOf(u8, valid, &[_]u8{ 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 }).?;
    var extra_alg_field = try testing.allocator.alloc(u8, valid.len + 2);
    defer testing.allocator.free(extra_alg_field);
    @memcpy(extra_alg_field[0 .. alg_seq_start + 15], valid[0 .. alg_seq_start + 15]);
    extra_alg_field[alg_seq_start + 1] = 0x0f; // grow the AlgorithmIdentifier SEQUENCE length by 2
    extra_alg_field[alg_seq_start + 15] = 0x05; // an extra (bogus) NULL element
    extra_alg_field[alg_seq_start + 16] = 0x00;
    @memcpy(extra_alg_field[alg_seq_start + 17 ..], valid[alg_seq_start + 15 ..]);
    // Growing the AlgorithmIdentifier SEQUENCE's own length also grows the
    // outer PrivateKeyInfo SEQUENCE's declared length by the same 2 bytes,
    // and the outer length is encoded 2 bytes into the buffer as a 0x82
    // long-form u16.
    const outer_len_before = std.mem.readInt(u16, extra_alg_field[2..4], .big);
    std.mem.writeInt(u16, extra_alg_field[2..4], outer_len_before + 2, .big);
    try testing.expectError(error.InvalidPrivateKey, Identity.initPkcs8WithEntropy(testdata.rsa_certificate_der, extra_alg_field, det.entropy()));
}
