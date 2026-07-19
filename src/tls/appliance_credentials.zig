//! Bare Systems appliance TLS credential provisioning (#392).
//!
//! Strict loader and lifecycle owner for the fixed v0.5 appliance identity:
//! exactly one Ed25519 key, one leaf-first certificate chain, one configured
//! server name. The loader enforces the exact provisioning byte format (strict
//! RFC 7468 PEM, unencrypted RFC 5958/8410 PKCS#8), proves the leaf public key
//! equals the configured private key, preflights the encoded TLS Certificate
//! flight against the handshake writer's bounds, and publishes exactly one
//! bundle into the existing `sni_provider.ReloadableProvider`. The TLS engine
//! continues to see only the provider-neutral `credentials.CredentialProvider`;
//! private-key bytes never cross that seam.
//!
//! This module deliberately adds no new provider, signer, selector, or X.509
//! parser: it composes `pki.pem`, `pki.x509`, `crypto.pure_zig`
//! `SoftwareSigningKey`, `crypto.secrets`, and `sni_provider`.

const std = @import("std");
const crypto = @import("crypto");
const pki = @import("pki");
const credentials = @import("credentials.zig");
const sni_provider = @import("sni_provider.zig");
const dns_name = @import("dns_name.zig");
const tls13_backend = @import("tls13_backend.zig");
const production_crypto = @import("production_crypto.zig");

const secrets = crypto.secrets;
const Ed25519 = std.crypto.sign.Ed25519;

/// Fixed framing the TLS Certificate message adds around the raw chain: 1-byte
/// msg_type + 3-byte length + 1-byte certificate_request_context length +
/// 3-byte CertificateList length. Mirrors `tls13_backend`.
const certificate_message_overhead = 1 + 3 + 1 + 3;
/// Per-CertificateEntry framing: 3-byte cert_data length + 2-byte extensions
/// length. Mirrors `tls13_backend`.
const certificate_entry_overhead = 3 + 2;
/// Headroom reserved for the other messages sharing the server's one flight
/// buffer (EncryptedExtensions with ALPN and the optional CertificateRequest
/// are each well under this).
const flight_headroom = 512;

pub const default_max_certificate_flight_bytes =
    tls13_backend.max_message_len - flight_headroom;

pub const Limits = struct {
    max_certificate_file_bytes: usize = 256 * 1024,
    max_private_key_file_bytes: usize = 64 * 1024,
    max_chain_entries: usize = credentials.max_chain_entries,
    max_certificate_der_bytes: usize = tls13_backend.max_certificate_len,
    max_certificate_flight_bytes: usize = default_max_certificate_flight_bytes,
};

pub const Options = struct {
    /// The one exact DNS host name the appliance identity serves. Also the
    /// default identity for clients that omit SNI; any other non-empty SNI
    /// fails the handshake before HTTP parsing.
    server_name: []const u8,
    limits: Limits = .{},
};

pub const Error = error{
    MissingCertificateChain,
    MissingPrivateKey,
    CertificateFileTooLarge,
    PrivateKeyFileTooLarge,
    EmptyCertificateChain,
    TooManyCertificates,
    MalformedCertificatePem,
    AmbiguousCertificateInput,
    CertificateTooLarge,
    MalformedCertificateDer,
    MalformedPrivateKeyPem,
    AmbiguousPrivateKeyInput,
    MalformedPrivateKeyDer,
    UnsupportedPrivateKeyAlgorithm,
    UnsupportedPrivateKeyParameters,
    InvalidPrivateKeySize,
    InvalidPrivateKey,
    UnsupportedLeafKeyAlgorithm,
    KeyCertificateMismatch,
    CertificateFlightTooLarge,
    InvalidServerName,
    UnsupportedApplianceConfiguration,
    ProviderPublicationFailed,
    AccessDenied,
    FileNotFound,
    OutOfMemory,
};

var os_entropy_state: production_crypto.OsEntropy = .{};

/// The long-lived Ed25519 signer owned by a published snapshot. Retirement of
/// the snapshot (reload or provider deinit) runs `release` exactly once, which
/// securely erases the private key before freeing the allocation.
const OwnedSigner = struct {
    allocator: std.mem.Allocator,
    key: crypto.pure_zig.SoftwareSigningKey,

    fn release(ctx: *anyopaque) void {
        const self: *OwnedSigner = @ptrCast(@alignCast(ctx));
        const allocator = self.allocator;
        self.key.deinit();
        allocator.destroy(self);
    }
};

/// Owner of the one provisioned appliance identity. Construct once at the
/// composition root, borrow `provider()` for every native TCP TLS connection
/// and the HTTP/3 runtime, and keep the owner alive until every borrower is
/// torn down. All parsing/validation happens off-path; a failed reload leaves
/// the previously published credential fully usable.
pub const ApplianceCredentials = struct {
    allocator: std.mem.Allocator,
    provider_state: sni_provider.ReloadableProvider,

    pub fn initFromBytes(
        allocator: std.mem.Allocator,
        certificate_pem: []const u8,
        private_key_pem: []const u8,
        options: Options,
    ) Error!ApplianceCredentials {
        var self = ApplianceCredentials{
            .allocator = allocator,
            .provider_state = sni_provider.ReloadableProvider.init(allocator),
        };
        errdefer self.provider_state.deinit();
        try self.reloadFromBytes(certificate_pem, private_key_pem, options);
        return self;
    }

    pub fn initFromFiles(
        allocator: std.mem.Allocator,
        certificate_path: []const u8,
        private_key_path: []const u8,
        options: Options,
    ) Error!ApplianceCredentials {
        var self = ApplianceCredentials{
            .allocator = allocator,
            .provider_state = sni_provider.ReloadableProvider.init(allocator),
        };
        errdefer self.provider_state.deinit();
        try self.reloadFromFiles(certificate_path, private_key_path, options);
        return self;
    }

    /// Parse, validate, and atomically publish a replacement credential. On
    /// any error nothing is published and the current snapshot (if any)
    /// remains selectable; in-flight handshakes keep their pinned generation
    /// either way.
    pub fn reloadFromBytes(
        self: *ApplianceCredentials,
        certificate_pem: []const u8,
        private_key_pem: []const u8,
        options: Options,
    ) Error!void {
        try validateServerName(options.server_name);
        const limits = options.limits;

        // Certificate chain: strict whole-input PEM contract, then the shared
        // #340 loader for base64/DER decoding and ownership.
        try scanStrictCertificatePem(certificate_pem, limits);
        var chain = pki.pem.loadChainPem(self.allocator, certificate_pem, pemLimits(limits)) catch |err|
            return mapChainPemError(err);
        defer chain.deinit(self.allocator);
        try preflightChain(&chain, limits);

        // Leaf certificate: must carry a canonical RFC 8410 Ed25519 SPKI.
        var leaf_public: [Ed25519.PublicKey.encoded_length]u8 = undefined;
        try extractEd25519LeafPublicKey(self.allocator, chain.certificates[0].der, &leaf_public);

        // Private key: strict single PKCS#8 PEM block, Ed25519 only. Every
        // intermediate secret buffer is wiped on all paths.
        const signer_owner = try self.loadPrivateKey(private_key_pem, limits);
        var signer_owned = true;
        errdefer if (signer_owned) OwnedSigner.release(signer_owner);

        // Exact key/certificate binding: the leaf public key must equal the
        // key derived from the provisioned seed, then a fixed sign/verify
        // probe guards the signer wiring as defense in depth.
        const derived_public = signer_owner.key.publicKey();
        if (!secrets.constantTimeEqual(&leaf_public, &derived_public))
            return error.KeyCertificateMismatch;
        try proofOfPossession(&signer_owner.key, leaf_public);

        // Publish exactly one bundle through the existing reloadable provider.
        const entries = self.allocator.alloc([]const u8, chain.certificates.len) catch
            return error.OutOfMemory;
        defer self.allocator.free(entries);
        for (chain.certificates, 0..) |cert, i| entries[i] = cert.der;

        const patterns = [_][]const u8{options.server_name};
        const schemes = [_]credentials.SignatureScheme{.ed25519};
        const bundle = sni_provider.CredentialBundleConfig{
            .chain = entries,
            .patterns = &patterns,
            .signer = sni_provider.SignAdapter.fromSigningKey(
                signer_owner.key.signingKey(),
                os_entropy_state.entropy(),
                signer_owner,
                OwnedSigner.release,
            ),
            .key_kind = .ed25519,
            .supported_schemes = &schemes,
            .is_default = true,
        };
        // From here the provider owns the signer: reload releases it on every
        // failure path and the published snapshot releases it on retirement.
        signer_owned = false;
        self.provider_state.reload(&.{bundle}, .{
            .absent_sni_policy = .use_default,
            .unknown_sni_policy = .fail_handshake,
        }) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.EmptyHostPattern,
            error.InvalidHostPattern,
            error.InvalidWildcardPattern,
            error.DuplicateHostPattern,
            => error.InvalidServerName,
            else => error.ProviderPublicationFailed,
        };
    }

    pub fn reloadFromFiles(
        self: *ApplianceCredentials,
        certificate_path: []const u8,
        private_key_path: []const u8,
        options: Options,
    ) Error!void {
        if (certificate_path.len == 0) return error.MissingCertificateChain;
        if (private_key_path.len == 0) return error.MissingPrivateKey;
        const limits = options.limits;

        const certificate_pem = readFileBounded(
            self.allocator,
            certificate_path,
            limits.max_certificate_file_bytes,
            error.CertificateFileTooLarge,
        ) catch |err| return err;
        defer self.allocator.free(certificate_pem);

        // Key-file bytes are secret material: bounded, typed, and wiped on
        // every return path.
        var key_bytes = secrets.BoundedSecret{};
        key_bytes.initCapacity(self.allocator, limits.max_private_key_file_bytes) catch
            return error.OutOfMemory;
        defer key_bytes.deinit();
        try readFileIntoSecret(&key_bytes, private_key_path, error.PrivateKeyFileTooLarge);

        return self.reloadFromBytes(certificate_pem, key_bytes.slice(), options);
    }

    /// The borrowed provider view. `self` must outlive every connection and
    /// runtime that can select from it.
    pub fn provider(self: *ApplianceCredentials) credentials.CredentialProvider {
        return self.provider_state.provider();
    }

    pub fn deinit(self: *ApplianceCredentials) void {
        self.provider_state.deinit();
        self.* = undefined;
    }

    fn loadPrivateKey(
        self: *ApplianceCredentials,
        private_key_pem: []const u8,
        limits: Limits,
    ) Error!*OwnedSigner {
        if (private_key_pem.len > limits.max_private_key_file_bytes)
            return error.PrivateKeyFileTooLarge;

        // Decoded DER and compacted base64 are both no longer than the PEM
        // text itself, so the wiped scratch capacity is bounded by the input.
        var key_der = secrets.BoundedSecret{};
        key_der.initCapacity(self.allocator, private_key_pem.len) catch
            return error.OutOfMemory;
        defer key_der.deinit();
        try decodeStrictPrivateKeyPem(self.allocator, private_key_pem, &key_der);

        var seed = secrets.FixedSecret(Ed25519.KeyPair.seed_length){};
        defer seed.deinit();
        try parseEd25519Pkcs8(key_der.slice(), &seed);

        const owner = self.allocator.create(OwnedSigner) catch return error.OutOfMemory;
        errdefer self.allocator.destroy(owner);
        owner.* = .{
            .allocator = self.allocator,
            .key = crypto.pure_zig.SoftwareSigningKey.fromSeed(
                seed.bytes[0..Ed25519.KeyPair.seed_length].*,
            ) catch return error.InvalidPrivateKey,
        };
        return owner;
    }
};

/// Full appliance credential preflight without publishing anything or opening
/// any socket: used by `tardi check`. Builds and immediately retires a
/// complete provider snapshot so the check exercises the exact startup path.
pub fn validateFiles(
    allocator: std.mem.Allocator,
    certificate_path: []const u8,
    private_key_path: []const u8,
    options: Options,
) Error!void {
    var owner = try ApplianceCredentials.initFromFiles(
        allocator,
        certificate_path,
        private_key_path,
        options,
    );
    owner.deinit();
}

pub fn validateBytes(
    allocator: std.mem.Allocator,
    certificate_pem: []const u8,
    private_key_pem: []const u8,
    options: Options,
) Error!void {
    var owner = try ApplianceCredentials.initFromBytes(
        allocator,
        certificate_pem,
        private_key_pem,
        options,
    );
    owner.deinit();
}

pub fn validateServerName(name: []const u8) Error!void {
    if (name.len == 0) return error.InvalidServerName;
    if (std.mem.indexOfScalar(u8, name, '*') != null) return error.InvalidServerName;
    dns_name.validateHostName(name) catch return error.InvalidServerName;
}

fn pemLimits(limits: Limits) pki.pem.Limits {
    return .{
        .max_input_len = limits.max_certificate_file_bytes,
        .max_certificate_len = limits.max_certificate_der_bytes,
        .max_certificates = limits.max_chain_entries,
    };
}

fn mapChainPemError(err: pki.pem.Error) Error {
    return switch (err) {
        error.InputTooLarge => error.CertificateFileTooLarge,
        error.CertificateTooLarge => error.CertificateTooLarge,
        error.TooManyCertificates => error.TooManyCertificates,
        error.NoCertificates => error.EmptyCertificateChain,
        error.MalformedPemBoundary,
        error.MismatchedPemLabel,
        error.UnterminatedPemBlock,
        error.InvalidPemBase64,
        error.EmptyPemBlock,
        => error.MalformedCertificatePem,
        error.MalformedCertificateDer => error.MalformedCertificateDer,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn preflightChain(chain: *const pki.pem.CertificateChain, limits: Limits) Error!void {
    const count = chain.certificates.len;
    if (count == 0) return error.EmptyCertificateChain;
    if (count > limits.max_chain_entries or count > credentials.max_chain_entries)
        return error.TooManyCertificates;

    var flight: usize = certificate_message_overhead;
    for (chain.certificates) |cert| {
        if (cert.der.len == 0) return error.MalformedCertificateDer;
        if (cert.der.len > limits.max_certificate_der_bytes) return error.CertificateTooLarge;
        flight = std.math.add(usize, flight, cert.der.len + certificate_entry_overhead) catch
            return error.CertificateFlightTooLarge;
        if (flight > limits.max_certificate_flight_bytes) return error.CertificateFlightTooLarge;
    }
}

/// Parse the leaf with the shared pure-Zig X.509 parser and require the
/// canonical RFC 8410 Ed25519 SubjectPublicKeyInfo: Ed25519 algorithm, zero
/// BIT STRING unused bits, exactly 32 public-key bytes.
fn extractEd25519LeafPublicKey(
    allocator: std.mem.Allocator,
    leaf_der: []const u8,
    out: *[Ed25519.PublicKey.encoded_length]u8,
) Error!void {
    var leaf = pki.x509.Certificate.parse(allocator, leaf_der, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedCertificateDer,
    };
    defer leaf.deinit(allocator);
    if (leaf.subject_public_key_info.key_type != .ed25519)
        return error.UnsupportedLeafKeyAlgorithm;
    const public_key = leaf.subject_public_key_info.subject_public_key;
    if (public_key.unused_bits != 0 or public_key.data.len != Ed25519.PublicKey.encoded_length)
        return error.MalformedCertificateDer;
    @memcpy(out, public_key.data);
}

/// Fixed sign-and-verify probe: defends against future signer-adapter wiring
/// errors. Never replaces the exact public-key comparison performed first.
fn proofOfPossession(
    key: *const crypto.pure_zig.SoftwareSigningKey,
    leaf_public: [Ed25519.PublicKey.encoded_length]u8,
) Error!void {
    const probe = "Tardigrade appliance credential preflight v1";
    const signature = key.key_pair.sign(probe, null) catch return error.InvalidPrivateKey;
    const public_key = Ed25519.PublicKey.fromBytes(leaf_public) catch
        return error.MalformedCertificateDer;
    signature.verify(probe, public_key) catch return error.KeyCertificateMismatch;
}

// ---------------------------------------------------------------------------
// Strict provisioning PEM contract
// ---------------------------------------------------------------------------

const begin_certificate = "-----BEGIN CERTIFICATE-----";
const end_certificate = "-----END CERTIFICATE-----";
const begin_private_key = "-----BEGIN PRIVATE KEY-----";
const end_private_key = "-----END PRIVATE KEY-----";

fn isWhitespaceLine(line: []const u8) bool {
    for (line) |ch| {
        if (ch != ' ' and ch != '\t') return false;
    }
    return true;
}

fn isBase64Line(line: []const u8) bool {
    if (line.len == 0) return false;
    for (line) |ch| {
        const valid = (ch >= 'A' and ch <= 'Z') or (ch >= 'a' and ch <= 'z') or
            (ch >= '0' and ch <= '9') or ch == '+' or ch == '/' or ch == '=';
        if (!valid) return false;
    }
    return true;
}

const LineIterator = struct {
    inner: std.mem.SplitIterator(u8, .scalar),

    fn init(text: []const u8) LineIterator {
        return .{ .inner = std.mem.splitScalar(u8, text, '\n') };
    }

    fn next(self: *LineIterator) ?[]const u8 {
        const raw = self.inner.next() orelse return null;
        // Strip exactly one CR from a CRLF terminator.
        return if (raw.len > 0 and raw[raw.len - 1] == '\r') raw[0 .. raw.len - 1] else raw;
    }
};

/// The certificate file must contain only `CERTIFICATE` blocks and ASCII
/// whitespace: no prose, comments, unrelated PEM labels, or trailing
/// non-whitespace material. Base64/DER decoding is delegated to `pki.pem`.
fn scanStrictCertificatePem(text: []const u8, limits: Limits) Error!void {
    if (text.len == 0) return error.MissingCertificateChain;
    if (text.len > limits.max_certificate_file_bytes) return error.CertificateFileTooLarge;

    var blocks: usize = 0;
    var in_block = false;
    var lines = LineIterator.init(text);
    while (lines.next()) |line| {
        if (!in_block) {
            if (isWhitespaceLine(line)) continue;
            if (std.mem.eql(u8, line, begin_certificate)) {
                in_block = true;
                continue;
            }
            if (std.mem.startsWith(u8, line, "-----BEGIN ")) return error.AmbiguousCertificateInput;
            if (std.mem.startsWith(u8, line, "-----")) return error.MalformedCertificatePem;
            return error.AmbiguousCertificateInput;
        }
        if (std.mem.eql(u8, line, end_certificate)) {
            in_block = false;
            blocks += 1;
            continue;
        }
        if (!isBase64Line(line)) return error.MalformedCertificatePem;
    }
    if (in_block) return error.MalformedCertificatePem;
    if (blocks == 0) return error.EmptyCertificateChain;
}

/// The key file must contain exactly one `PRIVATE KEY` block surrounded only
/// by ASCII whitespace. The base64 body is decoded into `out` (a wiped,
/// bounded secret). Known non-appliance key encodings are classified as
/// unsupported algorithms; anything else outside the contract is ambiguous or
/// malformed input.
fn decodeStrictPrivateKeyPem(
    allocator: std.mem.Allocator,
    text: []const u8,
    out: *secrets.BoundedSecret,
) Error!void {
    if (text.len == 0) return error.MissingPrivateKey;

    var body = secrets.BoundedSecret{};
    body.initCapacity(allocator, out.bytes.len) catch return error.OutOfMemory;
    defer body.deinit();
    var body_len: usize = 0;

    var blocks: usize = 0;
    var in_block = false;
    var lines = LineIterator.init(text);
    while (lines.next()) |line| {
        if (!in_block) {
            if (isWhitespaceLine(line)) continue;
            if (std.mem.eql(u8, line, begin_private_key)) {
                if (blocks > 0) return error.MalformedPrivateKeyPem;
                in_block = true;
                continue;
            }
            if (std.mem.startsWith(u8, line, "-----BEGIN ")) {
                const unsupported_labels = [_][]const u8{
                    "-----BEGIN EC PRIVATE KEY-----",
                    "-----BEGIN RSA PRIVATE KEY-----",
                    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                    "-----BEGIN OPENSSH PRIVATE KEY-----",
                };
                for (unsupported_labels) |label| {
                    if (std.mem.eql(u8, line, label)) return error.UnsupportedPrivateKeyAlgorithm;
                }
                return error.AmbiguousPrivateKeyInput;
            }
            if (std.mem.startsWith(u8, line, "-----")) return error.MalformedPrivateKeyPem;
            return error.AmbiguousPrivateKeyInput;
        }
        if (std.mem.eql(u8, line, end_private_key)) {
            in_block = false;
            blocks += 1;
            continue;
        }
        if (!isBase64Line(line)) return error.MalformedPrivateKeyPem;
        if (line.len > body.bytes.len - body_len) return error.PrivateKeyFileTooLarge;
        @memcpy(body.bytes[body_len..][0..line.len], line);
        body_len += line.len;
        body.len = body_len;
    }
    if (in_block) return error.MalformedPrivateKeyPem;
    if (blocks == 0) return error.MissingPrivateKey;
    if (body_len == 0) return error.MalformedPrivateKeyPem;

    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(body.bytes[0..body_len]) catch
        return error.MalformedPrivateKeyPem;
    if (decoded_len > out.bytes.len) return error.PrivateKeyFileTooLarge;
    decoder.decode(out.bytes[0..decoded_len], body.bytes[0..body_len]) catch {
        secrets.secureZero(out.bytes);
        return error.MalformedPrivateKeyPem;
    };
    out.len = decoded_len;
}

// ---------------------------------------------------------------------------
// Strict Ed25519 PKCS#8 (RFC 5958 / RFC 8410)
// ---------------------------------------------------------------------------

const StrictDer = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn remaining(self: *const StrictDer) usize {
        return self.bytes.len - self.pos;
    }

    fn element(self: *StrictDer, tag: u8) Error![]const u8 {
        if (self.remaining() < 2) return error.MalformedPrivateKeyDer;
        if (self.bytes[self.pos] != tag) return error.MalformedPrivateKeyDer;
        var len: usize = self.bytes[self.pos + 1];
        var header: usize = 2;
        if (len == 0x81) {
            if (self.remaining() < 3) return error.MalformedPrivateKeyDer;
            len = self.bytes[self.pos + 2];
            if (len < 0x80) return error.MalformedPrivateKeyDer;
            header = 3;
        } else if (len == 0x82) {
            if (self.remaining() < 4) return error.MalformedPrivateKeyDer;
            len = (@as(usize, self.bytes[self.pos + 2]) << 8) | self.bytes[self.pos + 3];
            if (len < 0x100) return error.MalformedPrivateKeyDer;
            header = 4;
        } else if (len > 0x80) {
            return error.MalformedPrivateKeyDer;
        } else if (len == 0x80) {
            return error.MalformedPrivateKeyDer;
        }
        if (self.remaining() < header + len) return error.MalformedPrivateKeyDer;
        const content = self.bytes[self.pos + header ..][0..len];
        self.pos += header + len;
        return content;
    }

    fn peekTag(self: *const StrictDer) ?u8 {
        if (self.remaining() == 0) return null;
        return self.bytes[self.pos];
    }
};

const oid_ed25519 = [_]u8{ 0x06, 0x03, 0x2b, 0x65, 0x70 };

/// Strict Ed25519-only PKCS#8 entry point with a typed error surface:
/// distinguishes malformed DER, unsupported algorithms, illegal Ed25519
/// AlgorithmIdentifier parameters, wrong seed sizes, and trailing material.
/// The extracted seed lands only in the caller's `FixedSecret`.
pub fn parseEd25519Pkcs8(
    der: []const u8,
    seed_out: *secrets.FixedSecret(Ed25519.KeyPair.seed_length),
) Error!void {
    if (der.len == 0) return error.MissingPrivateKey;
    var outer_walker = StrictDer{ .bytes = der };
    const outer_content = try outer_walker.element(0x30);
    if (outer_walker.remaining() != 0) return error.MalformedPrivateKeyDer;

    var body = StrictDer{ .bytes = outer_content };
    const version = try body.element(0x02);
    if (version.len != 1 or version[0] != 0) return error.MalformedPrivateKeyDer;

    const algorithm = try body.element(0x30);
    if (algorithm.len < oid_ed25519.len) return error.MalformedPrivateKeyDer;
    var algorithm_walker = StrictDer{ .bytes = algorithm };
    const oid = try algorithm_walker.element(0x06);
    if (!std.mem.eql(u8, oid, oid_ed25519[2..])) return error.UnsupportedPrivateKeyAlgorithm;
    if (algorithm_walker.remaining() != 0) return error.UnsupportedPrivateKeyParameters;

    const private_key = try body.element(0x04);
    // RFC 8410: privateKey OCTET STRING wraps CurvePrivateKey ::= OCTET
    // STRING carrying exactly the 32-byte seed.
    var curve_walker = StrictDer{ .bytes = private_key };
    const inner = curve_walker.element(0x04) catch return error.MalformedPrivateKeyDer;
    if (curve_walker.remaining() != 0) return error.MalformedPrivateKeyDer;
    if (inner.len != Ed25519.KeyPair.seed_length) return error.InvalidPrivateKeySize;

    // Attributes or an appended public key are outside the provisioning
    // contract.
    if (body.remaining() != 0) return error.UnsupportedPrivateKeyParameters;

    seed_out.replace(inner) catch return error.InvalidPrivateKeySize;
}

// ---------------------------------------------------------------------------
// Bounded file access
// ---------------------------------------------------------------------------

fn openBounded(path: []const u8) Error!std.posix.fd_t {
    return std.posix.openat(std.posix.AT.FDCWD, path, .{}, 0) catch |err| switch (err) {
        error.AccessDenied => error.AccessDenied,
        else => error.FileNotFound,
    };
}

fn readFileBounded(
    allocator: std.mem.Allocator,
    path: []const u8,
    limit: usize,
    comptime too_large: Error,
) Error![]u8 {
    const fd = try openBounded(path);
    defer _ = std.c.close(fd);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = std.posix.read(fd, &buf) catch return error.FileNotFound;
        if (n == 0) break;
        if (out.items.len + n > limit) return too_large;
        out.appendSlice(allocator, buf[0..n]) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice(allocator) catch error.OutOfMemory;
}

fn readFileIntoSecret(
    secret: *secrets.BoundedSecret,
    path: []const u8,
    comptime too_large: Error,
) Error!void {
    const fd = try openBounded(path);
    defer _ = std.c.close(fd);

    var used: usize = 0;
    while (true) {
        if (used == secret.bytes.len) {
            // Probe for one extra byte: a file exactly at the limit is fine,
            // anything longer is rejected without buffering it.
            var probe: [1]u8 = undefined;
            const extra = std.posix.read(fd, &probe) catch return error.FileNotFound;
            if (extra != 0) return too_large;
            break;
        }
        const n = std.posix.read(fd, secret.bytes[used..]) catch return error.FileNotFound;
        if (n == 0) break;
        used += n;
    }
    secret.len = used;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(8000);
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

// Deterministic self-signed Ed25519 test identity (CN=tardigrade.test,
// SAN DNS:tardigrade.test). Matches tests/fixtures/tls/native_ed25519.{crt,key}.
// Test-only material — never a production credential. The tls_core
// `credentials.testdata` certificate is unusable here: its issuer Name is
// mis-encoded and the strict pki.x509 parser correctly rejects it.
const test_certificate_bytes = hexBytes(
    "3082016230820114a00302010202140d25d9bad95fdf952191eca5b90b4fba4f44d871300506032b6570301a3118301606035504030c0f746172646967726164652e74657374301e170d3236303731393138353935365a170d3436303731343138353935365a301a3118301606035504030c0f746172646967726164652e74657374302a300506032b6570032100d496b9d3f3dcd0b56e18654498312633ea922faff390e6ce0b5fdf9a8acd3b1ca36c306a301d0603551d0e041604140c6407b86ac0dde833bb1bc6295091048b50dc8e301f0603551d230418301680140c6407b86ac0dde833bb1bc6295091048b50dc8e301a0603551d1104133011820f746172646967726164652e74657374300c0603551d130101ff04023000300506032b6570034100a6ae237ee3f1420b5685da59f0a01e392f7a318b567069c57ab202476d29859c619b6c230d2fdc0ca947d3d2752178f03b42199951787c9c64ea73bcf743170b",
);
const test_key_pkcs8_bytes = hexBytes(
    "302e020100300506032b657004220420bfa19b67713278fd5be2639dd1bec0a1cfebae6ef671304f3b2c7df4fd894f23",
);
const test_seed_hex = "bfa19b67713278fd5be2639dd1bec0a1cfebae6ef671304f3b2c7df4fd894f23";
const test_certificate_der: []const u8 = &test_certificate_bytes;
const test_key_pkcs8_der: []const u8 = &test_key_pkcs8_bytes;

fn pemEncode(allocator: std.mem.Allocator, label: []const u8, der: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const encoder = std.base64.standard.Encoder;
    const body = try allocator.alloc(u8, encoder.calcSize(der.len));
    defer allocator.free(body);
    _ = encoder.encode(body, der);

    try out.appendSlice(allocator, "-----BEGIN ");
    try out.appendSlice(allocator, label);
    try out.appendSlice(allocator, "-----\n");
    var offset: usize = 0;
    while (offset < body.len) {
        const take = @min(64, body.len - offset);
        try out.appendSlice(allocator, body[offset..][0..take]);
        try out.appendSlice(allocator, "\n");
        offset += take;
    }
    try out.appendSlice(allocator, "-----END ");
    try out.appendSlice(allocator, label);
    try out.appendSlice(allocator, "-----\n");
    return out.toOwnedSlice(allocator);
}

fn testCertificatePem(allocator: std.mem.Allocator) ![]u8 {
    return pemEncode(allocator, "CERTIFICATE", test_certificate_der);
}

fn testPrivateKeyPem(allocator: std.mem.Allocator) ![]u8 {
    return pemEncode(allocator, "PRIVATE KEY", test_key_pkcs8_der);
}

/// PKCS#8 DER for an arbitrary 32-byte Ed25519 seed.
fn pkcs8FromSeed(seed: [32]u8) [48]u8 {
    const prefix = [_]u8{
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    };
    var out: [48]u8 = undefined;
    @memcpy(out[0..16], &prefix);
    @memcpy(out[16..], &seed);
    return out;
}

const test_options = Options{ .server_name = "tardigrade.test" };

fn testSelection(name: ?[]const u8, schemes: []const u16) credentials.SelectionContext {
    return .{
        .role = .server,
        .server_name = name,
        .peer_signature_schemes = schemes,
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = "h2",
        .auth_policy = .{},
    };
}

fn syncSelect(
    p: credentials.CredentialProvider,
    selection: *const credentials.SelectionContext,
) !credentials.SelectedCredential {
    return switch (try p.selectCredential(selection)) {
        .complete => |credential| credential,
        .pending => error.TestUnexpectedPending,
    };
}

test "valid Ed25519 chain and key publish a selectable default identity" {
    const cert_pem = try testCertificatePem(testing.allocator);
    defer testing.allocator.free(cert_pem);
    const key_pem = try testPrivateKeyPem(testing.allocator);
    defer testing.allocator.free(key_pem);

    var owner = try ApplianceCredentials.initFromBytes(
        testing.allocator,
        cert_pem,
        key_pem,
        test_options,
    );
    defer owner.deinit();

    // Exact configured SNI.
    var exact = testSelection("tardigrade.test", &.{0x0807});
    const selected = try syncSelect(owner.provider(), &exact);
    try testing.expectEqual(credentials.SignatureScheme.ed25519, selected.scheme);
    try testing.expectEqualSlices(
        u8,
        test_certificate_der,
        selected.certificateChain().leaf().?,
    );

    // The selected credential signs and the leaf's public key verifies it.
    var signature: [128]u8 = undefined;
    const written = switch (try selected.sign("appliance handshake probe", &signature)) {
        .complete => |len| len,
        .pending => return error.TestUnexpectedPending,
    };
    try testing.expectEqual(@as(usize, Ed25519.Signature.encoded_length), written);
    selected.release();

    // Absent SNI selects the default; unknown SNI and a peer without Ed25519
    // fail before any HTTP parsing could begin.
    var absent = testSelection(null, &.{0x0807});
    const defaulted = try syncSelect(owner.provider(), &absent);
    defaulted.release();

    var unknown = testSelection("unknown.example.test", &.{0x0807});
    try testing.expectError(
        error.NoCredentialAvailable,
        owner.provider().selectCredential(&unknown),
    );

    var no_ed25519 = testSelection("tardigrade.test", &.{0x0403});
    try testing.expectError(
        error.NoCompatibleSignatureAlgorithm,
        owner.provider().selectCredential(&no_ed25519),
    );
}

test "byte and file APIs produce equivalent provider behavior" {
    const allocator = testing.allocator;
    const cert_pem = try testCertificatePem(allocator);
    defer allocator.free(cert_pem);
    const key_pem = try testPrivateKeyPem(allocator);
    defer allocator.free(key_pem);

    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "appliance.crt", .data = cert_pem });
    try tmp.dir.writeFile(io, .{ .sub_path = "appliance.key", .data = key_pem });

    const cert_path = try tmp.dir.realPathFileAlloc(io, "appliance.crt", allocator);
    defer allocator.free(cert_path);
    const key_path = try tmp.dir.realPathFileAlloc(io, "appliance.key", allocator);
    defer allocator.free(key_path);

    var owner = try ApplianceCredentials.initFromFiles(allocator, cert_path, key_path, test_options);
    defer owner.deinit();

    var exact = testSelection("TARDIGRADE.TEST", &.{ 0xffff, 0x0807 });
    const selected = try syncSelect(owner.provider(), &exact);
    defer selected.release();
    try testing.expectEqualSlices(
        u8,
        test_certificate_der,
        selected.certificateChain().leaf().?,
    );

    // The file API surfaces the same taxonomy as the byte API.
    try testing.expectError(
        error.FileNotFound,
        ApplianceCredentials.initFromFiles(allocator, cert_path, "does-not-exist.key", test_options),
    );
    try testing.expectError(
        error.MissingCertificateChain,
        ApplianceCredentials.initFromFiles(allocator, "", key_path, test_options),
    );
    try testing.expectError(
        error.MissingPrivateKey,
        ApplianceCredentials.initFromFiles(allocator, cert_path, "", test_options),
    );
}

test "leaf plus intermediate chain preserves transmission order" {
    const allocator = testing.allocator;
    const single = try testCertificatePem(allocator);
    defer allocator.free(single);
    const chain_pem = try std.mem.concat(allocator, u8, &.{ single, single });
    defer allocator.free(chain_pem);
    const key_pem = try testPrivateKeyPem(allocator);
    defer allocator.free(key_pem);

    var owner = try ApplianceCredentials.initFromBytes(allocator, chain_pem, key_pem, test_options);
    defer owner.deinit();

    var exact = testSelection("tardigrade.test", &.{0x0807});
    const selected = try syncSelect(owner.provider(), &exact);
    defer selected.release();
    try testing.expectEqual(@as(usize, 2), selected.certificateChain().count());
}

test "certificate contract rejections are deterministic" {
    const allocator = testing.allocator;
    const key_pem = try testPrivateKeyPem(allocator);
    defer allocator.free(key_pem);
    const cert_pem = try testCertificatePem(allocator);
    defer allocator.free(cert_pem);

    const Case = struct { input: []const u8, expected: Error };
    const prose_then_cert = try std.mem.concat(allocator, u8, &.{ "subject=CN=x\n", cert_pem });
    defer allocator.free(prose_then_cert);
    const cert_then_prose = try std.mem.concat(allocator, u8, &.{ cert_pem, "trailing prose\n" });
    defer allocator.free(cert_then_prose);
    const cert_then_key = try std.mem.concat(allocator, u8, &.{ cert_pem, key_pem });
    defer allocator.free(cert_then_key);

    const cases = [_]Case{
        .{ .input = "", .expected = error.MissingCertificateChain },
        .{ .input = "   \n\t\n", .expected = error.EmptyCertificateChain },
        .{ .input = "-----BEGIN CERTIFICATE-----\nAAAA\n", .expected = error.MalformedCertificatePem },
        .{ .input = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n", .expected = error.MalformedCertificatePem },
        .{ .input = "-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n", .expected = error.MalformedCertificatePem },
        .{ .input = "-----BEGINCERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", .expected = error.MalformedCertificatePem },
        .{ .input = prose_then_cert, .expected = error.AmbiguousCertificateInput },
        .{ .input = cert_then_prose, .expected = error.AmbiguousCertificateInput },
        .{ .input = cert_then_key, .expected = error.AmbiguousCertificateInput },
        .{ .input = "raw der bytes", .expected = error.AmbiguousCertificateInput },
    };
    for (cases) |case| {
        try testing.expectError(
            case.expected,
            ApplianceCredentials.initFromBytes(allocator, case.input, key_pem, test_options),
        );
    }

    // Truncated DER inside a well-formed block.
    const truncated = try pemEncode(
        allocator,
        "CERTIFICATE",
        test_certificate_der[0 .. test_certificate_der.len - 4],
    );
    defer allocator.free(truncated);
    try testing.expectError(
        error.MalformedCertificateDer,
        ApplianceCredentials.initFromBytes(allocator, truncated, key_pem, test_options),
    );

    // Trailing DER bytes appended to a valid certificate.
    const padded_der = try std.mem.concat(allocator, u8, &.{
        test_certificate_der,
        &[_]u8{ 0x00, 0x00 },
    });
    defer allocator.free(padded_der);
    const padded = try pemEncode(allocator, "CERTIFICATE", padded_der);
    defer allocator.free(padded);
    try testing.expectError(
        error.MalformedCertificateDer,
        ApplianceCredentials.initFromBytes(allocator, padded, key_pem, test_options),
    );

    // Too many chain entries.
    var many: std.ArrayList(u8) = .empty;
    defer many.deinit(allocator);
    for (0..credentials.max_chain_entries + 1) |_| try many.appendSlice(allocator, cert_pem);
    try testing.expectError(
        error.TooManyCertificates,
        ApplianceCredentials.initFromBytes(allocator, many.items, key_pem, test_options),
    );

    // Oversized single certificate and oversized aggregate flight.
    var tight = test_options;
    tight.limits.max_certificate_der_bytes = test_certificate_der.len - 1;
    try testing.expectError(
        error.CertificateTooLarge,
        ApplianceCredentials.initFromBytes(allocator, cert_pem, key_pem, tight),
    );
    var tight_flight = test_options;
    tight_flight.limits.max_certificate_flight_bytes = test_certificate_der.len;
    try testing.expectError(
        error.CertificateFlightTooLarge,
        ApplianceCredentials.initFromBytes(allocator, cert_pem, key_pem, tight_flight),
    );
}

test "private-key contract rejections are deterministic" {
    const allocator = testing.allocator;
    const cert_pem = try testCertificatePem(allocator);
    defer allocator.free(cert_pem);
    const key_pem = try testPrivateKeyPem(allocator);
    defer allocator.free(key_pem);

    const Case = struct { input: []const u8, expected: Error };
    const two_keys = try std.mem.concat(allocator, u8, &.{ key_pem, key_pem });
    defer allocator.free(two_keys);
    const key_then_prose = try std.mem.concat(allocator, u8, &.{ key_pem, "trailing prose\n" });
    defer allocator.free(key_then_prose);
    const key_then_cert = try std.mem.concat(allocator, u8, &.{ key_pem, cert_pem });
    defer allocator.free(key_then_cert);

    const cases = [_]Case{
        .{ .input = "", .expected = error.MissingPrivateKey },
        .{ .input = " \n\t \n", .expected = error.MissingPrivateKey },
        .{ .input = "\x30\x2e\x02\x01\x00", .expected = error.AmbiguousPrivateKeyInput },
        .{ .input = two_keys, .expected = error.MalformedPrivateKeyPem },
        .{ .input = key_then_prose, .expected = error.AmbiguousPrivateKeyInput },
        .{ .input = key_then_cert, .expected = error.AmbiguousPrivateKeyInput },
        .{ .input = "-----BEGIN PRIVATE KEY-----\nAAAA\n", .expected = error.MalformedPrivateKeyPem },
        .{ .input = "-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----\n", .expected = error.MalformedPrivateKeyPem },
        .{ .input = "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n", .expected = error.MalformedPrivateKeyPem },
        .{ .input = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n", .expected = error.UnsupportedPrivateKeyAlgorithm },
        .{ .input = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n", .expected = error.UnsupportedPrivateKeyAlgorithm },
        .{ .input = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n", .expected = error.UnsupportedPrivateKeyAlgorithm },
        .{ .input = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", .expected = error.UnsupportedPrivateKeyAlgorithm },
    };
    for (cases) |case| {
        try testing.expectError(
            case.expected,
            ApplianceCredentials.initFromBytes(allocator, cert_pem, case.input, test_options),
        );
    }
}

test "strict PKCS#8 parser classifies malformed and unsupported keys" {
    const allocator = testing.allocator;
    const cert_pem = try testCertificatePem(allocator);
    defer allocator.free(cert_pem);

    const Case = struct { der: []const u8, expected: Error };

    // Well-formed PKCS#8 carrying a P-256 (id-ecPublicKey) algorithm.
    const p256_pkcs8 = [_]u8{
        0x30, 0x1a, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06,
        0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
        0x01, 0x07, 0x04, 0x00,
    };
    // Ed25519 OID with an illegal NULL parameter.
    const ed25519_null_params = [_]u8{
        0x30, 0x14, 0x02, 0x01, 0x00, 0x30, 0x07, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x04, 0x06,
        0x04, 0x04, 0xaa, 0xbb, 0xcc, 0xdd,
    };
    // Unknown algorithm OID.
    const unknown_oid = [_]u8{
        0x30, 0x10, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x71, 0x04, 0x04, 0x04, 0x02,
        0xaa, 0xbb,
    };
    // Ed25519 with a 16-byte seed.
    const short_seed = [_]u8{
        0x30, 0x1e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x12, 0x04, 0x10,
    } ++ [_]u8{0x11} ** 16;
    // Valid key with trailing bytes after the outer SEQUENCE.
    const valid = comptime pkcs8FromSeed([_]u8{0x22} ** 32);
    const trailing = valid ++ [_]u8{0x00};

    const cases = [_]Case{
        .{ .der = &p256_pkcs8, .expected = error.UnsupportedPrivateKeyAlgorithm },
        .{ .der = &ed25519_null_params, .expected = error.UnsupportedPrivateKeyParameters },
        .{ .der = &unknown_oid, .expected = error.UnsupportedPrivateKeyAlgorithm },
        .{ .der = &short_seed, .expected = error.InvalidPrivateKeySize },
        .{ .der = &trailing, .expected = error.MalformedPrivateKeyDer },
        .{ .der = valid[0 .. valid.len - 8], .expected = error.MalformedPrivateKeyDer },
    };
    for (cases) |case| {
        var seed = secrets.FixedSecret(32){};
        defer seed.deinit();
        try testing.expectError(case.expected, parseEd25519Pkcs8(case.der, &seed));

        const pem = try pemEncode(allocator, "PRIVATE KEY", case.der);
        defer allocator.free(pem);
        try testing.expectError(
            case.expected,
            ApplianceCredentials.initFromBytes(allocator, cert_pem, pem, test_options),
        );
    }
}

test "certificate and key must be the same Ed25519 key pair" {
    const allocator = testing.allocator;
    const cert_pem = try testCertificatePem(allocator);
    defer allocator.free(cert_pem);

    // A perfectly valid but unrelated Ed25519 key.
    const unrelated = pkcs8FromSeed([_]u8{0x42} ** 32);
    const unrelated_pem = try pemEncode(allocator, "PRIVATE KEY", &unrelated);
    defer allocator.free(unrelated_pem);
    try testing.expectError(
        error.KeyCertificateMismatch,
        ApplianceCredentials.initFromBytes(allocator, cert_pem, unrelated_pem, test_options),
    );
}

test "server-name policy rejects wildcards and invalid names" {
    const allocator = testing.allocator;
    const cert_pem = try testCertificatePem(allocator);
    defer allocator.free(cert_pem);
    const key_pem = try testPrivateKeyPem(allocator);
    defer allocator.free(key_pem);

    const invalid_names = [_][]const u8{ "", "*", "*.example.test", "bad host", ".leading.dot", "-x.test" };
    for (invalid_names) |name| {
        try testing.expectError(
            error.InvalidServerName,
            ApplianceCredentials.initFromBytes(allocator, cert_pem, key_pem, .{ .server_name = name }),
        );
    }
}

test "failed reload leaves the previous identity selectable" {
    const allocator = testing.allocator;
    const cert_pem = try testCertificatePem(allocator);
    defer allocator.free(cert_pem);
    const key_pem = try testPrivateKeyPem(allocator);
    defer allocator.free(key_pem);

    var owner = try ApplianceCredentials.initFromBytes(allocator, cert_pem, key_pem, test_options);
    defer owner.deinit();

    // Selected handle pinned to the current generation before the reload.
    var exact = testSelection("tardigrade.test", &.{0x0807});
    const pinned = try syncSelect(owner.provider(), &exact);

    const unrelated = pkcs8FromSeed([_]u8{0x42} ** 32);
    const unrelated_pem = try pemEncode(allocator, "PRIVATE KEY", &unrelated);
    defer allocator.free(unrelated_pem);
    try testing.expectError(
        error.KeyCertificateMismatch,
        owner.reloadFromBytes(cert_pem, unrelated_pem, test_options),
    );

    // Old identity still selectable, pinned handle still signs.
    var signature: [128]u8 = undefined;
    _ = switch (try pinned.sign("still generation 1", &signature)) {
        .complete => |len| len,
        .pending => return error.TestUnexpectedPending,
    };
    pinned.release();

    const selected = try syncSelect(owner.provider(), &exact);
    selected.release();

    // A successful reload republishes atomically.
    try owner.reloadFromBytes(cert_pem, key_pem, test_options);
    const reloaded = try syncSelect(owner.provider(), &exact);
    reloaded.release();
}

test "temporary key material is wiped on success and on parse failure" {
    var backing: [64 * 1024]u8 = undefined;
    @memset(&backing, 0xcc);
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const allocator = fba.allocator();

    const cert_pem = try testCertificatePem(allocator);
    const key_pem = try testPrivateKeyPem(allocator);

    // Success path: after deinit, neither the PKCS#8 DER nor the raw seed may
    // remain anywhere in the arena.
    {
        var owner = try ApplianceCredentials.initFromBytes(allocator, cert_pem, key_pem, test_options);
        owner.deinit();
    }
    const seed_hex = test_seed_hex;
    var seed_bytes: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed_bytes, seed_hex);
    try testing.expect(std.mem.indexOf(u8, &backing, &seed_bytes) == null);
    try testing.expect(std.mem.indexOf(u8, &backing, test_key_pkcs8_der) == null);

    // Failure path: a mismatched key must also be wiped.
    const unrelated_seed = [_]u8{0x42} ** 32;
    const unrelated = pkcs8FromSeed(unrelated_seed);
    const unrelated_pem = try pemEncode(allocator, "PRIVATE KEY", &unrelated);
    try testing.expectError(
        error.KeyCertificateMismatch,
        ApplianceCredentials.initFromBytes(allocator, cert_pem, unrelated_pem, test_options),
    );
    try testing.expect(std.mem.indexOf(u8, &backing, &unrelated_seed) == null);
}

test "allocation failure during construction does not leak or publish" {
    const cert_pem = try testCertificatePem(testing.allocator);
    defer testing.allocator.free(cert_pem);
    const key_pem = try testPrivateKeyPem(testing.allocator);
    defer testing.allocator.free(key_pem);

    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, cert: []const u8, key: []const u8) !void {
            var owner = try ApplianceCredentials.initFromBytes(allocator, cert, key, test_options);
            owner.deinit();
        }
    }.run, .{ cert_pem, key_pem });
}

test "validateBytes performs the full preflight without publishing" {
    const allocator = testing.allocator;
    const cert_pem = try testCertificatePem(allocator);
    defer allocator.free(cert_pem);
    const key_pem = try testPrivateKeyPem(allocator);
    defer allocator.free(key_pem);

    try validateBytes(allocator, cert_pem, key_pem, test_options);

    const unrelated = pkcs8FromSeed([_]u8{0x42} ** 32);
    const unrelated_pem = try pemEncode(allocator, "PRIVATE KEY", &unrelated);
    defer allocator.free(unrelated_pem);
    try testing.expectError(
        error.KeyCertificateMismatch,
        validateBytes(allocator, cert_pem, unrelated_pem, test_options),
    );
}

test "oversized inputs are rejected before parsing" {
    const allocator = testing.allocator;
    const key_pem = try testPrivateKeyPem(allocator);
    defer allocator.free(key_pem);
    const cert_pem = try testCertificatePem(allocator);
    defer allocator.free(cert_pem);

    var small = test_options;
    small.limits.max_certificate_file_bytes = 16;
    try testing.expectError(
        error.CertificateFileTooLarge,
        ApplianceCredentials.initFromBytes(allocator, cert_pem, key_pem, small),
    );

    var small_key = test_options;
    small_key.limits.max_private_key_file_bytes = 16;
    try testing.expectError(
        error.PrivateKeyFileTooLarge,
        ApplianceCredentials.initFromBytes(allocator, cert_pem, key_pem, small_key),
    );
}
