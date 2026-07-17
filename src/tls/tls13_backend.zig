//! Shared pure-Zig TLS 1.3 handshake engine for QUIC and record transports.
//! It consumes and produces TLS 1.3 handshake messages, exports traffic
//! secrets, negotiates ALPN, and authenticates the server certificate. The
//! explicit transport profile decides whether a bounded opaque extension is
//! carried. QUIC owns the contents of that extension; record mode carries no
//! transport extension at all. This module imports neither QUIC nor OpenSSL.
//!
//! Deliberately narrow first profile, one interoperable code path per choice:
//!   - cipher suite: TLS_AES_128_GCM_SHA256 (the adapter's suite)
//!   - key exchange: X25519
//!   - signature: Ed25519 (server CertificateVerify)
//!   - server-only authentication; client certificates are not offered
//!   - trust: an explicitly pinned certificate (deterministic fixture /
//!     deployment pin) or an explicit insecure mode reporting `not_checked`
//! Session resumption, 0-RTT, HelloRetryRequest, and web-PKI chain validation
//! are follow-ups (see docs/QUIC_TLS.md). Entropy is caller-supplied like the
//! rest of the native transport stack — no ambient RNG.

const std = @import("std");
const encrypted_stream = @import("encrypted_stream.zig");
const events = @import("events.zig");
const tls_handshake_codec = @import("handshake.zig");
const tls_key_schedule = @import("key_schedule.zig");
const tls_state = @import("state.zig");

const crypto = std.crypto;
const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;
const EcdsaP256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const Certificate = crypto.Certificate;

const EncryptionLevel = events.EncryptionEpoch;
const CertificateState = events.CertificateState;
const HandshakeError = encrypted_stream.RecordHandshakeError;
const EventSink = encrypted_stream.RecordTransport.EventSink;
const TlsBackend = encrypted_stream.RecordHandshakeBackend;
const Role = tls_state.Role;
const MessageType = tls_handshake_codec.MessageType;
const Reader = tls_handshake_codec.Reader;
const Writer = tls_handshake_codec.Writer;

pub const hash_len = tls_key_schedule.hash_len;
/// Largest handshake message body we accept (u24 wire limit is 16 MiB; a
/// single-certificate Ed25519 flight is far below this).
pub const max_message_len = 8 * 1024;
pub const max_certificate_len = 2048;

const tls13_version: u16 = 0x0304;
const legacy_version: u16 = 0x0303;
const cipher_tls_aes_128_gcm_sha256: u16 = 0x1301;
const group_x25519: u16 = 0x001d;
const sigalg_ed25519: u16 = 0x0807;
const sigalg_ecdsa_secp256r1_sha256: u16 = 0x0403;

const ext_supported_groups: u16 = 10;
const ext_signature_algorithms: u16 = 13;
const ext_alpn: u16 = 16;
const ext_supported_versions: u16 = 43;
const ext_key_share: u16 = 51;
pub const max_transport_extension_len = 512;

/// Transport differences are explicit production configuration, never a
/// mutable test-only switch. The TLS engine treats the extension payload as
/// opaque; the owning transport adapter is responsible for its codec and
/// policy. Record mode carries no transport-specific extension.
pub const TransportProfile = union(enum) {
    record: RecordOptions,
    extension: ExtensionOptions,

    pub const RecordOptions = struct {
        alpn: []const u8,
    };

    pub const ExtensionOptions = struct {
        alpn: []const u8,
        extension_type: u16,
        /// Borrowed from the transport adapter. It must remain valid until the
        /// local ClientHello or EncryptedExtensions flight has been emitted.
        local: []const u8,
    };

    fn alpn(self: TransportProfile) []const u8 {
        return switch (self) {
            .record => |options| options.alpn,
            .extension => |options| options.alpn,
        };
    }

    fn extensionType(self: TransportProfile) ?u16 {
        return switch (self) {
            .record => null,
            .extension => |options| options.extension_type,
        };
    }

    fn localExtension(self: TransportProfile) ?[]const u8 {
        return switch (self) {
            .record => null,
            .extension => |options| options.local,
        };
    }
};

/// RFC 8446 §4.1.3: a ServerHello whose random equals this value is a
/// HelloRetryRequest. This backend offers exactly the parameters it supports,
/// so a compliant peer never needs one; receiving it is a deterministic error.
const hello_retry_request_random = [32]u8{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

// ===========================================================================
// TLS 1.3 key schedule (protocol-neutral core).
// ===========================================================================

pub const KeySchedule = tls_key_schedule.KeySchedule;

const ExtensionGuard = struct {
    pub const max_extensions = 64;

    ids: [max_extensions]u16 = undefined,
    len: usize = 0,

    fn check(self: *ExtensionGuard, ext_id: u16) HandshakeError!void {
        for (self.ids[0..self.len]) |seen| {
            // A repeated extension type is well-formed but illegal
            // (RFC 8446 §4.2: abort with illegal_parameter).
            if (seen == ext_id) return error.IllegalParameter;
        }
        // Exceeding the bounded tracker is a resource/parse limit, not a
        // semantic field error, so it stays a decode failure.
        if (self.len == self.ids.len) return error.MalformedHandshake;
        self.ids[self.len] = ext_id;
        self.len += 1;
    }
};

// ===========================================================================
// Server identity and client trust.
// ===========================================================================

/// The server's certificate and signing key: Ed25519 (RFC 8410) or ECDSA
/// P-256 (RFC 5915/5480). `initPkcs8` loads standard PKCS#8 DER as produced
/// by `openssl genpkey -algorithm ed25519` or
/// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`. Two key
/// types because deployed TLS stacks disagree on defaults: GnuTLS/OpenSSL
/// accept Ed25519 out of the box while BoringSSL's default verifier
/// (quiche/Chromium) requires ECDSA/RSA — P-256 is the interoperable floor.
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
    pub fn signatureAlgorithm(self: *const Identity) u16 {
        return switch (self.key) {
            .ed25519 => sigalg_ed25519,
            .ecdsa_p256 => sigalg_ecdsa_secp256r1_sha256,
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

/// How the client decides the server certificate's validity. Web-PKI chain
/// building is a follow-up; the deterministic modes below cover local
/// handshakes, tests, and deployment pinning.
pub const Trust = union(enum) {
    /// The presented leaf must byte-equal this DER certificate.
    pinned_certificate: []const u8,
    /// Report `not_checked`; completes only when the driver explicitly opts
    /// into `allow_unverified_certificate`.
    insecure_no_verification,
};

/// Caller-supplied entropy for one handshake, consistent with the rest of
/// `src/quic/` where unpredictable bytes always come from the caller.
pub const Entropy = struct {
    hello_random: [32]u8,
    key_share_seed: [X25519.seed_length]u8,
};

// ===========================================================================
// The backend.
// ===========================================================================

pub const Tls13Backend = struct {
    role: Role,
    profile: TransportProfile,
    entropy: Entropy,
    identity: ?Identity = null,
    trust: Trust = .insecure_no_verification,
    peer_transport_extension: [max_transport_extension_len]u8 = undefined,
    peer_transport_extension_len: usize = 0,
    peer_transport_extension_pending: bool = false,
    key_pair: ?X25519.KeyPair = null,
    core: tls_handshake_codec.Core,
    schedule: ?KeySchedule = null,
    /// The client Finished verify_data the server expects (computed when its
    /// own flight is sent).
    expected_client_verify: [hash_len]u8 = undefined,
    /// Reassembled-but-unparsed handshake bytes per transport epoch; a message
    /// may arrive split across TLS records or QUIC CRYPTO frames. The
    /// application-level
    /// buffer exists because post-handshake messages (NewSessionTicket) may be
    /// fragmented across application-epoch transport chunks like any other
    /// handshake message.
    initial_input: tls_handshake_codec.Reassembler(max_message_len + 4) = .{},
    handshake_input: tls_handshake_codec.Reassembler(max_message_len + 4) = .{},
    application_input: tls_handshake_codec.Reassembler(max_message_len + 4) = .{},
    /// The peer's leaf certificate (client role), kept for CertificateVerify.
    peer_certificate: [max_certificate_len]u8 = undefined,
    peer_certificate_len: usize = 0,

    pub fn initClient(entropy: Entropy, trust: Trust, profile: TransportProfile) Tls13Backend {
        return .{ .role = .client, .profile = profile, .entropy = entropy, .trust = trust, .core = tls_handshake_codec.Core.init(.client) };
    }

    pub fn initServer(entropy: Entropy, identity: Identity, profile: TransportProfile) Tls13Backend {
        return .{ .role = .server, .profile = profile, .entropy = entropy, .identity = identity, .core = tls_handshake_codec.Core.init(.server) };
    }

    pub fn backend(self: *Tls13Backend) TlsBackend {
        return .{
            .ptr = self,
            .startFn = startImpl,
            .receiveFn = receiveImpl,
            .deinitFn = deinitImpl,
        };
    }

    pub fn alpn(self: *const Tls13Backend) []const u8 {
        return self.profile.alpn();
    }

    pub fn setExtensionProfile(self: *Tls13Backend, extension_type: u16, local: []const u8) HandshakeError!void {
        if (local.len > max_transport_extension_len) return error.TransportBufferOverflow;
        self.profile = .{ .extension = .{
            .alpn = self.profile.alpn(),
            .extension_type = extension_type,
            .local = local,
        } };
    }

    /// Returns a newly received opaque transport extension once. The caller
    /// must consume/copy it before the next backend call.
    pub fn takePeerTransportExtension(self: *Tls13Backend) ?[]const u8 {
        if (!self.peer_transport_extension_pending) return null;
        self.peer_transport_extension_pending = false;
        return self.peer_transport_extension[0..self.peer_transport_extension_len];
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    pub fn deinit(self: *Tls13Backend) void {
        if (self.schedule) |*schedule| schedule.wipe();
        self.schedule = null;
        crypto.secureZero(u8, &self.expected_client_verify);
        if (self.key_pair) |*key_pair| {
            crypto.secureZero(u8, &key_pair.secret_key);
            crypto.secureZero(u8, &key_pair.public_key);
        }
        self.key_pair = null;
        crypto.secureZero(u8, &self.peer_certificate);
        self.peer_certificate_len = 0;
        crypto.secureZero(u8, &self.peer_transport_extension);
        self.peer_transport_extension_len = 0;
        self.peer_transport_extension_pending = false;
        crypto.secureZero(u8, std.mem.asBytes(&self.initial_input));
        crypto.secureZero(u8, std.mem.asBytes(&self.handshake_input));
        crypto.secureZero(u8, std.mem.asBytes(&self.application_input));
        self.initial_input = .{};
        self.handshake_input = .{};
        self.application_input = .{};
        crypto.secureZero(u8, std.mem.asBytes(&self.core));
        self.core = tls_handshake_codec.Core.init(self.role);
        self.core.handshake_lifecycle = .failed;
    }

    fn startImpl(ptr: *anyopaque, role: Role, _: void, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        // The driver's role comes from Handshake.initClient/initServer and must
        // match how this backend was constructed; a mismatch is a wiring bug.
        std.debug.assert(role == self.role);
        std.debug.assert(self.core.handshake_lifecycle == .idle);
        self.core.start() catch |err| return mapCoreError(err);
        switch (self.role) {
            .client => {
                try self.sendClientHello(sink);
            },
            .server => {},
        }
    }

    fn receiveImpl(ptr: *anyopaque, level: EncryptionLevel, bytes: []const u8, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        const input = switch (level) {
            .initial => &self.initial_input,
            .handshake => &self.handshake_input,
            // This deliberately narrow TLS profile does not implement 0-RTT.
            .zero_rtt => return error.UnexpectedTransportEpoch,
            // Application-epoch handshake input carries post-handshake messages.
            .application => blk: {
                if (self.core.handshake_lifecycle != .complete) return error.UnexpectedTransportEpoch;
                break :blk &self.application_input;
            },
        };
        input.append(bytes) catch |err| return mapCoreError(err);

        while (input.peek() catch |err| return mapCoreError(err)) |message| {
            if (level != try expectedLevel(message.kind)) return error.UnexpectedTransportEpoch;
            const transcript_before = self.core.transcriptHash();
            _ = self.core.acceptReceived(message.raw) catch |err| return mapCoreError(err);
            try self.onMessage(message, level, transcript_before, sink);
            input.discard(message.raw.len) catch |err| return mapCoreError(err);
            // A failed or freshly completed handshake stops consuming its own
            // epochs; post-handshake application input keeps draining (a peer
            // may batch several NewSessionTickets).
            if ((self.core.handshake_lifecycle == .complete or self.core.handshake_lifecycle == .failed) and level != .application) break;
        }
    }

    fn expectedLevel(kind: MessageType) HandshakeError!EncryptionLevel {
        return switch (kind) {
            .client_hello, .server_hello => .initial,
            .encrypted_extensions, .certificate, .certificate_verify, .finished => .handshake,
            .new_session_ticket => .application,
            else => error.UnexpectedHandshakeMessage,
        };
    }

    fn mapCoreError(err: tls_handshake_codec.Error) HandshakeError {
        return switch (err) {
            error.MalformedHandshake,
            error.IncompleteHandshake,
            error.MessageTooLarge,
            error.DuplicateExtension,
            error.TooManyExtensions,
            => error.MalformedHandshake,
            error.HandshakeBufferOverflow => error.HandshakeBufferOverflow,
            error.IllegalParameter => error.IllegalParameter,
            error.UnexpectedHandshakeMessage => error.UnexpectedHandshakeMessage,
            error.AlpnMismatch => error.AlpnMismatch,
            error.CertificateInvalid => error.CertificateInvalid,
            error.SecretExportFailed => error.SecretExportFailed,
            error.InvalidHandshakeState => error.InvalidHandshakeState,
        };
    }

    fn onMessage(
        self: *Tls13Backend,
        message: tls_handshake_codec.Message,
        level: EncryptionLevel,
        transcript_before: [hash_len]u8,
        sink: *EventSink,
    ) HandshakeError!void {
        // Enforce the transport epoch each message belongs to before anything
        // else, so carrier routing mistakes surface as epoch errors rather
        // than parse errors.
        const kind = message.kind;
        const body = message.body;
        const expected_level = try expectedLevel(kind);
        if (level != expected_level) return error.UnexpectedTransportEpoch;

        if (kind == .new_session_ticket) {
            // NewSessionTicket travels server->client only (RFC 8446 §4.6.1); a
            // server that receives one has been sent a message it must never
            // get, which is an ordering violation, not malformed bytes.
            if (self.role != .client) return error.UnexpectedHandshakeMessage;
            // This backend does not implement resumption, so the ticket is
            // ignored — but a compliant peer must still send a structurally
            // valid one. Validate the framing so malformed wire data is
            // rejected as `decode_error` rather than silently accepted.
            try validateNewSessionTicket(body);
            return;
        }

        // Message ordering has already been enforced by `core.acceptReceived`.
        // Dispatch the shared TLS semantics; transport extension contents stay
        // opaque and are consumed by the owning adapter.
        switch (kind) {
            .client_hello => try self.onClientHello(body, sink),
            .server_hello => try self.onServerHello(body, sink),
            .encrypted_extensions => try self.onEncryptedExtensions(body, sink),
            .certificate => try self.onCertificate(body),
            .certificate_verify => try self.onCertificateVerify(transcript_before, body, sink),
            .finished => switch (self.role) {
                .client => try self.onServerFinished(transcript_before, body, sink),
                .server => try self.onClientFinished(body, sink),
            },
            else => return error.UnexpectedHandshakeMessage,
        }
    }

    /// Minimally validate a NewSessionTicket's framing (RFC 8446 §4.6.1):
    ///
    ///   struct {
    ///     uint32 ticket_lifetime;
    ///     uint32 ticket_age_add;
    ///     opaque ticket_nonce<0..255>;
    ///     opaque ticket<1..2^16-1>;
    ///     Extension extensions<0..2^16-2>;
    ///   } NewSessionTicket;
    ///
    /// This backend does not implement resumption and ignores the ticket, but a
    /// structurally invalid one is still malformed wire data. Any framing error
    /// (including an empty `ticket`, which the spec forbids, or trailing bytes)
    /// is a `MalformedHandshake` / `decode_error`.
    fn validateNewSessionTicket(body: []const u8) HandshakeError!void {
        var r = Reader{ .bytes = body };
        _ = try r.slice(4); // ticket_lifetime
        _ = try r.slice(4); // ticket_age_add
        _ = try r.slice(try r.u8_()); // ticket_nonce
        if ((try r.slice(try r.u16_())).len == 0) return error.MalformedHandshake; // ticket<1..>
        _ = try r.slice(try r.u16_()); // extensions
        try r.expectEnd();
    }

    // -----------------------------------------------------------------------
    // Client flight.
    // -----------------------------------------------------------------------

    fn sendClientHello(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        const key_pair = X25519.KeyPair.generateDeterministic(self.entropy.key_share_seed) catch
            return error.SecretExportFailed;
        self.key_pair = key_pair;

        var buf: [1024]u8 = undefined;
        var w = Writer{ .buf = &buf };
        try w.u8_(@intFromEnum(MessageType.client_hello));
        const message_len = try w.reserve(3);
        try w.u16_(legacy_version);
        try w.bytes(&self.entropy.hello_random);
        try w.u8_(0); // legacy_session_id: this profile does not use compatibility mode
        try w.u16_(2); // cipher_suites
        try w.u16_(cipher_tls_aes_128_gcm_sha256);
        try w.u8_(1); // legacy_compression_methods
        try w.u8_(0);

        const extensions_len = try w.reserve(2);
        try w.u16_(ext_supported_versions);
        try w.u16_(3);
        try w.u8_(2);
        try w.u16_(tls13_version);

        try w.u16_(ext_supported_groups);
        try w.u16_(4);
        try w.u16_(2);
        try w.u16_(group_x25519);

        try w.u16_(ext_signature_algorithms);
        try w.u16_(6);
        try w.u16_(4);
        try w.u16_(sigalg_ed25519);
        try w.u16_(sigalg_ecdsa_secp256r1_sha256);

        try w.u16_(ext_key_share);
        try w.u16_(2 + 2 + 2 + X25519.public_length);
        try w.u16_(2 + 2 + X25519.public_length); // client_shares
        try w.u16_(group_x25519);
        try w.u16_(X25519.public_length);
        try w.bytes(&key_pair.public_key);

        const negotiated_alpn = self.alpn();
        try w.u16_(ext_alpn);
        const alpn_ext_len = try w.reserve(2);
        const alpn_list_len = try w.reserve(2);
        try w.u8_(@intCast(negotiated_alpn.len));
        try w.bytes(negotiated_alpn);
        w.patch(2, alpn_list_len);
        w.patch(2, alpn_ext_len);

        if (self.profile.extensionType()) |extension_type| {
            const payload = self.profile.localExtension() orelse return error.MissingTransportExtension;
            try w.u16_(extension_type);
            try w.u16_(@intCast(payload.len));
            try w.bytes(payload);
        }

        w.patch(2, extensions_len);
        w.patch(3, message_len);

        const message = buf[0..w.len];
        self.core.recordSent(message) catch |err| return mapCoreError(err);
        try sink.emitCrypto(.initial, message);
    }

    fn onServerHello(self: *Tls13Backend, body: []const u8, sink: *EventSink) HandshakeError!void {
        var r = Reader{ .bytes = body };
        if (try r.u16_() != legacy_version) return error.IllegalParameter;
        const random = try r.slice(32);
        if (std.mem.eql(u8, random, &hello_retry_request_random)) return error.IllegalParameter;
        const session_id_len = try r.u8_();
        _ = try r.slice(session_id_len);
        if (try r.u16_() != cipher_tls_aes_128_gcm_sha256) return error.IllegalParameter;
        if (try r.u8_() != 0) return error.IllegalParameter;

        var selected_version: ?u16 = null;
        var peer_share: ?[X25519.public_length]u8 = null;
        var guard = ExtensionGuard{};
        var extensions = Reader{ .bytes = try r.slice(try r.u16_()) };
        try r.expectEnd();
        while (extensions.remaining() > 0) {
            const ext_id = try extensions.u16_();
            try guard.check(ext_id);
            var ext = Reader{ .bytes = try extensions.slice(try extensions.u16_()) };
            switch (ext_id) {
                ext_supported_versions => selected_version = try ext.u16_(),
                ext_key_share => {
                    if (try ext.u16_() != group_x25519) return error.IllegalParameter;
                    if (try ext.u16_() != X25519.public_length) return error.IllegalParameter;
                    peer_share = (try ext.slice(X25519.public_length))[0..X25519.public_length].*;
                    try ext.expectEnd();
                },
                else => {},
            }
        }
        if (selected_version != tls13_version) return error.IllegalParameter;
        const share = peer_share orelse return error.MalformedHandshake;

        // A low-order/identity peer share is a well-formed 32-byte field with an
        // illegal value (predictable all-zero shared secret), not malformed wire
        // data.
        const shared = X25519.scalarmult(self.key_pair.?.secret_key, share) catch
            return error.IllegalParameter;
        self.schedule = KeySchedule.init(shared, self.core.transcriptHash());
        try self.emitHandshakeSecrets(sink);
        try sink.emitDiscardKeys(.initial);
    }

    fn onEncryptedExtensions(self: *Tls13Backend, body: []const u8, sink: *EventSink) HandshakeError!void {
        var r = Reader{ .bytes = body };
        var guard = ExtensionGuard{};
        var transport_extension_seen = false;
        var extensions = Reader{ .bytes = try r.slice(try r.u16_()) };
        try r.expectEnd();
        while (extensions.remaining() > 0) {
            const ext_id = try extensions.u16_();
            try guard.check(ext_id);
            var ext = Reader{ .bytes = try extensions.slice(try extensions.u16_()) };
            switch (ext_id) {
                ext_alpn => {
                    var list = Reader{ .bytes = try ext.slice(try ext.u16_()) };
                    const name = try list.slice(try list.u8_());
                    // The server selects exactly one protocol (RFC 7301 §3.1).
                    try list.expectEnd();
                    try sink.emitAlpn(name);
                },
                else => {
                    if (self.profile.extensionType()) |expected_type| {
                        if (expected_type == ext_id) {
                            try self.capturePeerTransportExtension(ext.bytes);
                            transport_extension_seen = true;
                        }
                    }
                },
            }
        }
        if (self.profile.extensionType() != null and !transport_extension_seen) return error.MissingTransportExtension;
    }

    fn onCertificate(self: *Tls13Backend, body: []const u8) HandshakeError!void {
        var r = Reader{ .bytes = body };
        if (try r.u8_() != 0) return error.MalformedHandshake; // certificate_request_context
        var list = Reader{ .bytes = try r.slice(try r.u24_()) };
        try r.expectEnd();

        const leaf_len = try list.u24_();
        if (leaf_len == 0 or leaf_len > max_certificate_len) return error.CertificateInvalid;
        const leaf = try list.slice(leaf_len);
        _ = try list.slice(try list.u16_()); // leaf extensions
        // Validate the framing of any additional chain certificates; the trust
        // decision here is pin-based, so only the leaf is retained.
        while (list.remaining() > 0) {
            _ = try list.slice(try list.u24_());
            _ = try list.slice(try list.u16_());
        }

        @memcpy(self.peer_certificate[0..leaf.len], leaf);
        self.peer_certificate_len = leaf.len;
    }

    fn onCertificateVerify(self: *Tls13Backend, transcript_before: [hash_len]u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        var r = Reader{ .bytes = body };
        const algorithm = try r.u16_();
        const signature = try r.slice(try r.u16_());
        try r.expectEnd();

        // The signature covers the transcript through Certificate (RFC 8446
        // §4.4.3) — before this message is added.
        const content = certificateVerifyContent(.server, transcript_before);
        const state = self.verifyServerCertificate(algorithm, signature, content.slice());
        try sink.emitCertificate(state);
        if (state == .invalid) {
            self.core.handshake_lifecycle = .failed;
            return error.CertificateInvalid;
        }
    }

    fn verifyServerCertificate(self: *Tls13Backend, algorithm: u16, signature: []const u8, content: []const u8) CertificateState {
        const leaf = self.peer_certificate[0..self.peer_certificate_len];

        // Proof of key possession: the CertificateVerify signature must check
        // out against the certificate's public key in every trust mode.
        const parsed = (Certificate{ .buffer = leaf, .index = 0 }).parse() catch return .invalid;
        switch (algorithm) {
            sigalg_ed25519 => {
                if (signature.len != Ed25519.Signature.encoded_length) return .invalid;
                if (parsed.pub_key_algo != .curveEd25519) return .invalid;
                const pub_key_bytes = parsed.pubKey();
                if (pub_key_bytes.len != Ed25519.PublicKey.encoded_length) return .invalid;
                const public_key = Ed25519.PublicKey.fromBytes(pub_key_bytes[0..Ed25519.PublicKey.encoded_length].*) catch return .invalid;
                const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
                sig.verify(content, public_key) catch return .invalid;
            },
            sigalg_ecdsa_secp256r1_sha256 => {
                switch (parsed.pub_key_algo) {
                    .X9_62_id_ecPublicKey => |curve| if (curve != .X9_62_prime256v1) return .invalid,
                    else => return .invalid,
                }
                const public_key = EcdsaP256.PublicKey.fromSec1(parsed.pubKey()) catch return .invalid;
                const sig = EcdsaP256.Signature.fromDer(signature) catch return .invalid;
                sig.verify(content, public_key) catch return .invalid;
            },
            else => return .invalid,
        }

        return switch (self.trust) {
            .pinned_certificate => |pin| if (std.mem.eql(u8, leaf, pin)) .valid else .invalid,
            .insecure_no_verification => .not_checked,
        };
    }

    fn onServerFinished(self: *Tls13Backend, transcript_before: [hash_len]u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        const schedule = &self.schedule.?;
        if (body.len != hash_len) return error.MalformedHandshake;
        const expected = KeySchedule.verifyData(schedule.server_handshake_traffic, transcript_before);
        if (!crypto.timing_safe.eql([hash_len]u8, expected, body[0..hash_len].*)) {
            return error.MalformedHandshake;
        }

        // 1-RTT secrets exist from the transcript through server Finished.
        const finished_hash = self.core.transcriptHash();
        const app = schedule.applicationSecrets(finished_hash);
        try self.emitSecret(sink, .application, .write, &app.client);
        try self.emitSecret(sink, .application, .read, &app.server);

        // Client Finished covers the transcript including server Finished.
        var buf: [4 + hash_len]u8 = undefined;
        var w = Writer{ .buf = &buf };
        try w.u8_(@intFromEnum(MessageType.finished));
        const message_len = try w.reserve(3);
        try w.bytes(&KeySchedule.verifyData(schedule.client_handshake_traffic, finished_hash));
        w.patch(3, message_len);
        const message = buf[0..w.len];
        self.core.recordSent(message) catch |err| return mapCoreError(err);
        try sink.emitCrypto(.handshake, message);

        try self.emitDiscardKeys(sink, .handshake);
        try sink.emitHandshakeComplete();
        self.finish();
    }

    // -----------------------------------------------------------------------
    // Server flight.
    // -----------------------------------------------------------------------

    fn onClientHello(self: *Tls13Backend, body: []const u8, sink: *EventSink) HandshakeError!void {
        var r = Reader{ .bytes = body };
        if (try r.u16_() != legacy_version) return error.IllegalParameter;
        _ = try r.slice(32); // client random (already covered by the transcript)
        const session_id = try r.slice(try r.u8_());

        var offers_cipher = false;
        var ciphers = Reader{ .bytes = try r.slice(try r.u16_()) };
        while (ciphers.remaining() > 0) {
            if (try ciphers.u16_() == cipher_tls_aes_128_gcm_sha256) offers_cipher = true;
        }
        var offers_null_compression = false;
        var compressions = Reader{ .bytes = try r.slice(try r.u8_()) };
        while (compressions.remaining() > 0) {
            if (try compressions.u8_() == 0) offers_null_compression = true;
        }
        if (!offers_cipher or !offers_null_compression) return error.MalformedHandshake;

        const required_sigalg = self.identity.?.signatureAlgorithm();
        var offers_tls13 = false;
        var offers_x25519_group = false;
        var offers_our_sigalg = false;
        var peer_share: ?[X25519.public_length]u8 = null;
        var alpn_match = false;
        var first_alpn: []const u8 = "";
        var alpn_offered = false;
        var transport_params: ?[]const u8 = null;

        var guard = ExtensionGuard{};
        var extensions = Reader{ .bytes = try r.slice(try r.u16_()) };
        try r.expectEnd();
        while (extensions.remaining() > 0) {
            const ext_id = try extensions.u16_();
            try guard.check(ext_id);
            var ext = Reader{ .bytes = try extensions.slice(try extensions.u16_()) };
            switch (ext_id) {
                ext_supported_versions => {
                    var versions = Reader{ .bytes = try ext.slice(try ext.u8_()) };
                    while (versions.remaining() > 0) {
                        if (try versions.u16_() == tls13_version) offers_tls13 = true;
                    }
                },
                ext_supported_groups => {
                    var groups = Reader{ .bytes = try ext.slice(try ext.u16_()) };
                    while (groups.remaining() > 0) {
                        if (try groups.u16_() == group_x25519) offers_x25519_group = true;
                    }
                },
                ext_signature_algorithms => {
                    var algorithms = Reader{ .bytes = try ext.slice(try ext.u16_()) };
                    while (algorithms.remaining() > 0) {
                        if (try algorithms.u16_() == required_sigalg) offers_our_sigalg = true;
                    }
                },
                ext_key_share => {
                    var shares = Reader{ .bytes = try ext.slice(try ext.u16_()) };
                    while (shares.remaining() > 0) {
                        const group = try shares.u16_();
                        const share = try shares.slice(try shares.u16_());
                        if (group == group_x25519 and share.len == X25519.public_length) {
                            peer_share = share[0..X25519.public_length].*;
                        }
                    }
                },
                ext_alpn => {
                    var list = Reader{ .bytes = try ext.slice(try ext.u16_()) };
                    while (list.remaining() > 0) {
                        const name = try list.slice(try list.u8_());
                        if (!alpn_offered) first_alpn = name;
                        alpn_offered = true;
                        if (std.mem.eql(u8, name, self.alpn())) alpn_match = true;
                    }
                },
                else => {
                    if (self.profile.extensionType()) |expected_type| {
                        if (expected_type == ext_id) transport_params = ext.bytes;
                    }
                },
            }
        }
        if (!offers_tls13 or !offers_x25519_group or !offers_our_sigalg) return error.MalformedHandshake;
        const client_share = peer_share orelse return error.MalformedHandshake;

        // Validate the peer share before emitting anything: X25519.scalarmult
        // rejects low-order/identity public keys (all-zero shared secret)
        // rather than deriving a predictable secret.
        const key_pair = X25519.KeyPair.generateDeterministic(self.entropy.key_share_seed) catch
            return error.SecretExportFailed;
        self.key_pair = key_pair;
        const shared = X25519.scalarmult(key_pair.secret_key, client_share) catch
            return error.IllegalParameter;

        if (!alpn_match) {
            // Report what the client offered instead of silently downgrading;
            // the driver fails with AlpnMismatch before any flight is sent.
            try sink.emitAlpn(first_alpn);
            self.core.handshake_lifecycle = .failed;
            return error.AlpnMismatch;
        }
        if (self.profile.extensionType() != null) {
            const extension = transport_params orelse return error.MissingTransportExtension;
            try self.capturePeerTransportExtension(extension);
        }

        // ServerHello (Initial level).
        var hello_buf: [256]u8 = undefined;
        var hello = Writer{ .buf = &hello_buf };
        try hello.u8_(@intFromEnum(MessageType.server_hello));
        const hello_len = try hello.reserve(3);
        try hello.u16_(legacy_version);
        try hello.bytes(&self.entropy.hello_random);
        try hello.u8_(@intCast(session_id.len)); // echo legacy_session_id
        try hello.bytes(session_id);
        try hello.u16_(cipher_tls_aes_128_gcm_sha256);
        try hello.u8_(0);
        const hello_extensions = try hello.reserve(2);
        try hello.u16_(ext_supported_versions);
        try hello.u16_(2);
        try hello.u16_(tls13_version);
        try hello.u16_(ext_key_share);
        try hello.u16_(2 + 2 + X25519.public_length);
        try hello.u16_(group_x25519);
        try hello.u16_(X25519.public_length);
        try hello.bytes(&key_pair.public_key);
        hello.patch(2, hello_extensions);
        hello.patch(3, hello_len);
        const server_hello = hello_buf[0..hello.len];
        self.core.recordSent(server_hello) catch |err| return mapCoreError(err);
        try sink.emitCrypto(.initial, server_hello);
        try sink.emitAlpn(self.alpn());

        self.schedule = KeySchedule.init(shared, self.core.transcriptHash());
        try self.emitHandshakeSecrets(sink);
        try sink.emitDiscardKeys(.initial);

        try self.sendServerFlight(sink);
    }

    /// EncryptedExtensions + Certificate + CertificateVerify + Finished at the
    /// Handshake level, followed by the 1-RTT secrets.
    fn sendServerFlight(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        const identity = self.identity.?;
        const schedule = &self.schedule.?;
        var buf: [max_message_len]u8 = undefined;
        var w = Writer{ .buf = &buf };

        // EncryptedExtensions: selected ALPN plus the profile's opaque
        // transport extension, when one is configured.
        try w.u8_(@intFromEnum(MessageType.encrypted_extensions));
        const ee_len = try w.reserve(3);
        const ee_extensions = try w.reserve(2);
        const negotiated_alpn = self.alpn();
        try w.u16_(ext_alpn);
        const alpn_ext_len = try w.reserve(2);
        const alpn_list_len = try w.reserve(2);
        try w.u8_(@intCast(negotiated_alpn.len));
        try w.bytes(negotiated_alpn);
        w.patch(2, alpn_list_len);
        w.patch(2, alpn_ext_len);
        if (self.profile.extensionType()) |extension_type| {
            const payload = self.profile.localExtension() orelse return error.MissingTransportExtension;
            try w.u16_(extension_type);
            try w.u16_(@intCast(payload.len));
            try w.bytes(payload);
        }
        w.patch(2, ee_extensions);
        w.patch(3, ee_len);
        const encrypted_extensions = buf[0..w.len];

        // Certificate.
        const cert_start = w.len;
        try w.u8_(@intFromEnum(MessageType.certificate));
        const cert_len = try w.reserve(3);
        try w.u8_(0); // certificate_request_context
        const list_len = try w.reserve(3);
        const entry_len = try w.reserve(3);
        try w.bytes(identity.certificate_der);
        w.patch(3, entry_len);
        try w.u16_(0); // per-certificate extensions
        w.patch(3, list_len);
        w.patch(3, cert_len);
        const certificate = buf[cert_start..w.len];

        // CertificateVerify signs the transcript through Certificate.
        self.core.recordSent(encrypted_extensions) catch |err| return mapCoreError(err);
        self.core.recordSent(certificate) catch |err| return mapCoreError(err);
        const content = certificateVerifyContent(.server, self.core.transcriptHash());
        const verify_start = w.len;
        try w.u8_(@intFromEnum(MessageType.certificate_verify));
        const verify_len = try w.reserve(3);
        try w.u16_(identity.signatureAlgorithm());
        switch (identity.key) {
            .ed25519 => |key_pair| {
                const signature = key_pair.sign(content.slice(), null) catch
                    return error.SecretExportFailed;
                try w.u16_(Ed25519.Signature.encoded_length);
                try w.bytes(&signature.toBytes());
            },
            .ecdsa_p256 => |key_pair| {
                const signature = key_pair.sign(content.slice(), null) catch
                    return error.SecretExportFailed;
                var der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
                const der = signature.toDer(&der_buf);
                try w.u16_(@intCast(der.len));
                try w.bytes(der);
            },
        }
        w.patch(3, verify_len);
        const certificate_verify = buf[verify_start..w.len];
        self.core.recordSent(certificate_verify) catch |err| return mapCoreError(err);

        // Finished covers the transcript through CertificateVerify.
        const finished_start = w.len;
        try w.u8_(@intFromEnum(MessageType.finished));
        const finished_len = try w.reserve(3);
        try w.bytes(&KeySchedule.verifyData(schedule.server_handshake_traffic, self.core.transcriptHash()));
        w.patch(3, finished_len);
        const finished = buf[finished_start..w.len];
        self.core.recordSent(finished) catch |err| return mapCoreError(err);
        try sink.emitCrypto(.handshake, buf[0..w.len]);

        // 1-RTT secrets from the transcript through server Finished; the
        // client Finished we will require is fixed by the same hash.
        const finished_hash = self.core.transcriptHash();
        const app = schedule.applicationSecrets(finished_hash);
        try self.emitSecret(sink, .application, .read, &app.client);
        try self.emitSecret(sink, .application, .write, &app.server);
        self.expected_client_verify = KeySchedule.verifyData(schedule.client_handshake_traffic, finished_hash);
    }

    fn onClientFinished(self: *Tls13Backend, body: []const u8, sink: *EventSink) HandshakeError!void {
        if (body.len != hash_len) return error.MalformedHandshake;
        if (!crypto.timing_safe.eql([hash_len]u8, self.expected_client_verify, body[0..hash_len].*)) {
            return error.MalformedHandshake;
        }
        // Client Finished confirms the handshake for the server (RFC 8446 §4.4.4).
        try self.emitDiscardKeys(sink, .handshake);
        try sink.emitHandshakeComplete();
        self.finish();
    }

    // -----------------------------------------------------------------------
    // Shared helpers.
    // -----------------------------------------------------------------------

    fn emitHandshakeSecrets(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        const schedule = &self.schedule.?;
        switch (self.role) {
            .client => {
                try self.emitSecret(sink, .handshake, .write, &schedule.client_handshake_traffic);
                try self.emitSecret(sink, .handshake, .read, &schedule.server_handshake_traffic);
            },
            .server => {
                try self.emitSecret(sink, .handshake, .read, &schedule.client_handshake_traffic);
                try self.emitSecret(sink, .handshake, .write, &schedule.server_handshake_traffic);
            },
        }
    }

    fn emitSecret(
        self: *Tls13Backend,
        sink: *EventSink,
        epoch: EncryptionLevel,
        direction: events.SecretDirection,
        data: []const u8,
    ) HandshakeError!void {
        self.core.secrets.install(toCoreEpoch(epoch), direction) catch return error.SecretExportFailed;
        try sink.emitSecret(epoch, direction, data);
    }

    fn emitDiscardKeys(self: *Tls13Backend, sink: *EventSink, epoch: EncryptionLevel) HandshakeError!void {
        self.core.secrets.discardEpoch(toCoreEpoch(epoch)) catch return error.SecretExportFailed;
        try sink.emitDiscardKeys(epoch);
    }

    fn toCoreEpoch(epoch: EncryptionLevel) events.EncryptionEpoch {
        return epoch;
    }

    fn capturePeerTransportExtension(self: *Tls13Backend, payload: []const u8) HandshakeError!void {
        if (payload.len > self.peer_transport_extension.len) return error.TransportBufferOverflow;
        @memcpy(self.peer_transport_extension[0..payload.len], payload);
        self.peer_transport_extension_len = payload.len;
        self.peer_transport_extension_pending = true;
    }

    /// The handshake is over: the transport sink owns every exported live
    /// secret, so wipe the engine's key schedule immediately.
    fn finish(self: *Tls13Backend) void {
        if (self.schedule) |*schedule| schedule.wipe();
        self.schedule = null;
        crypto.secureZero(u8, &self.expected_client_verify);
    }
};

/// RFC 8446 §4.4.3 CertificateVerify content: 64 spaces, context string,
/// separator, transcript hash.
const CertificateVerifyContent = struct {
    buf: [64 + 64 + 1 + hash_len]u8,
    len: usize,

    fn slice(self: *const CertificateVerifyContent) []const u8 {
        return self.buf[0..self.len];
    }
};

fn certificateVerifyContent(signer: Role, transcript_hash: [hash_len]u8) CertificateVerifyContent {
    const context = switch (signer) {
        .server => "TLS 1.3, server CertificateVerify",
        .client => "TLS 1.3, client CertificateVerify",
    };
    var content: CertificateVerifyContent = undefined;
    var len: usize = 0;
    @memset(content.buf[0..64], 0x20);
    len += 64;
    @memcpy(content.buf[len..][0..context.len], context);
    len += context.len;
    content.buf[len] = 0x00;
    len += 1;
    @memcpy(content.buf[len..][0..hash_len], &transcript_hash);
    len += hash_len;
    content.len = len;
    return content;
}

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
};

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

test "TLS-owned identity fixture loads without QUIC or OpenSSL" {
    const identity = try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der);
    const parsed = try (Certificate{ .buffer = testdata.certificate_der, .index = 0 }).parse();
    try std.testing.expect(parsed.pub_key_algo == .curveEd25519);
    try std.testing.expectEqualSlices(u8, parsed.pubKey(), &identity.key.ed25519.public_key.toBytes());
}

test "TLS-owned identity parser rejects malformed PKCS#8" {
    try std.testing.expectError(
        error.InvalidPrivateKey,
        Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der[0 .. testdata.private_key_pkcs8_der.len - 1]),
    );
}

test "TLS-owned backend teardown clears transcript-adjacent and peer scratch" {
    var backend = Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0x41} ** 32, .key_share_seed = [_]u8{0x42} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .{ .record = .{ .alpn = "h2" } },
    );
    backend.core.transcript.update("transcript-adjacent state");
    @memset(&backend.expected_client_verify, 0xa5);
    @memset(&backend.peer_certificate, 0x5a);
    backend.peer_certificate_len = 32;
    backend.deinit();

    try std.testing.expect(std.mem.allEqual(u8, &backend.expected_client_verify, 0));
    try std.testing.expect(std.mem.allEqual(u8, &backend.peer_certificate, 0));
    try std.testing.expectEqual(@as(usize, 0), backend.peer_certificate_len);
    try std.testing.expectEqual(tls_handshake_codec.HandshakeLifecycle.failed, backend.core.handshake_lifecycle);
}
