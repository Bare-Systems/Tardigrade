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
const events = @import("events.zig");
const credentials = @import("credentials.zig");
const tls_handshake_codec = @import("handshake.zig");
const tls_key_schedule = @import("key_schedule.zig");
const tls_state = @import("state.zig");
const tls13_transport = @import("tls13_transport.zig");

const crypto = std.crypto;
const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;
const EcdsaP256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const Certificate = crypto.Certificate;

const EncryptionLevel = events.EncryptionEpoch;
const CertificateState = events.CertificateState;
const HandshakeError = tls13_transport.Error;
const EventSink = tls13_transport.EventSink;
const TlsBackend = tls13_transport.Backend;
const Role = tls_state.Role;
const MessageType = tls_handshake_codec.MessageType;
const Reader = tls_handshake_codec.Reader;
const Writer = tls_handshake_codec.Writer;

pub const hash_len = tls_key_schedule.hash_len;
/// Largest handshake message body we accept (u24 wire limit is 16 MiB; a
/// single-certificate Ed25519 flight is far below this).
pub const max_message_len = 8 * 1024;
pub const max_certificate_len = 2048;
/// Caller-owned bound on a CertificateVerify signature. The engine hands the
/// signing provider a buffer this size; a provider whose signature would not
/// fit reports overflow rather than exceeding the bound (#334). Comfortably
/// above Ed25519 (64) and DER-encoded ECDSA P-256 (~72).
pub const max_signature_len = 256;

const tls13_version: u16 = 0x0304;
const legacy_version: u16 = 0x0303;
const cipher_tls_aes_128_gcm_sha256: u16 = 0x1301;
const group_x25519: u16 = 0x001d;
const sigalg_ed25519: u16 = 0x0807;
const sigalg_ecdsa_secp256r1_sha256: u16 = 0x0403;

const ext_server_name: u16 = 0;
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

    fn validate(self: TransportProfile) HandshakeError!void {
        const negotiated_alpn = self.alpn();
        if (negotiated_alpn.len == 0 or negotiated_alpn.len > std.math.maxInt(u8)) {
            return error.InvalidTransportProfile;
        }
        if (self == .extension) {
            const options = self.extension;
            if (options.local.len > max_transport_extension_len) return error.InvalidTransportProfile;
            switch (options.extension_type) {
                ext_supported_groups,
                ext_signature_algorithms,
                ext_alpn,
                ext_supported_versions,
                ext_key_share,
                => return error.InvalidTransportProfile,
                else => {},
            }
        }
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

/// The provider-neutral credential and verification contracts live in
/// `credentials.zig` (#334). The fixed server identity and pin/insecure trust
/// are re-exported here for callers and served through the same contract the
/// engine uses for any provider — there is a single authentication path.
pub const Identity = credentials.Identity;
pub const Trust = credentials.Trust;
pub const CredentialProvider = credentials.CredentialProvider;
pub const PeerVerifier = credentials.PeerVerifier;
pub const SelectionContext = credentials.SelectionContext;
pub const VerificationContext = credentials.VerificationContext;
pub const CredentialFailure = credentials.FailureClass;

/// Whether a server requests handshake-time client authentication (#334).
/// `optional` accepts an empty client Certificate; `required` fails closed with
/// `certificate_required` when the client presents none. Post-handshake client
/// authentication is explicitly deferred.
pub const ClientAuthMode = enum { disabled, optional, required };

/// Largest peer certificate chain (total DER bytes and entry count) the engine
/// reassembles and surfaces to a `PeerVerifier` as immutable views. A chain
/// exceeding either bound fails closed (peer-attributed) rather than being
/// truncated, so a verifier never sees a partial chain.
pub const max_peer_chain_bytes = 16 * 1024;
pub const max_peer_chain_entries = credentials.max_chain_entries;
/// Largest set of peer-offered signature schemes captured for selection.
/// Generous versus real ClientHellos (~a dozen); a larger offer fails closed
/// rather than being silently truncated.
const max_peer_sig_schemes = 64;
/// Largest SNI host_name captured for selection (RFC 6066 caps names well
/// under this).
const max_server_name_len = 256;

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
    identity: Identity = undefined,
    identity_present: bool = false,
    trust: Trust = .insecure_no_verification,
    /// An externally supplied credential provider (server) / peer verifier
    /// (client or server). When set, it overrides the fixed identity/trust; the
    /// vtable's `ctx` points to caller-owned storage that must outlive the
    /// handshake. When null, the engine wraps the fixed identity/trust in the
    /// same production contract, so there is one authentication path.
    /// The local credential provider — my own certificate. Server: the server
    /// cert (or the fixed identity). Client: the client cert for handshake-time
    /// client authentication, when configured.
    external_provider: ?CredentialProvider = null,
    /// How I verify the peer. Client: verify the server. Server: verify the
    /// client's certificate during handshake-time client authentication.
    external_verifier: ?PeerVerifier = null,
    /// Server: whether to request client authentication.
    client_auth: ClientAuthMode = .disabled,
    /// Explicit local authentication policy, passed to selection and
    /// verification. Set at construction from the caller's intent, never
    /// re-derived from a defaulted field (an external verifier must not silently
    /// inherit the insecure default).
    auth_policy: credentials.AuthPolicy = .{},
    /// The last typed credential/verification failure. Set on failure and
    /// deliberately preserved across `deinit` (it is diagnostic, not secret) so
    /// terminal cleanup does not erase the underlying reason (#334).
    credential_failure: ?CredentialFailure = null,
    /// Peer-offered signature schemes captured from ClientHello, passed
    /// immutably into credential selection.
    peer_sig_schemes: [max_peer_sig_schemes]u16 = undefined,
    peer_sig_scheme_count: usize = 0,
    /// SNI host_name. Server: the value parsed from ClientHello. Client: the
    /// intended server name, configured at construction, emitted as ClientHello
    /// SNI and passed to the verifier so a Web-PKI verifier can check hostname.
    server_name: [max_server_name_len]u8 = undefined,
    server_name_len: usize = 0,
    server_name_present: bool = false,
    peer_transport_extension: [max_transport_extension_len]u8 = undefined,
    peer_transport_extension_len: usize = 0,
    peer_transport_extension_pending: bool = false,
    key_pair: X25519.KeyPair = undefined,
    key_pair_present: bool = false,
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
    /// The peer's reassembled certificate chain (immutable DER, surfaced to the
    /// verifier as views). `entries` index into `peer_chain`.
    peer_chain: [max_peer_chain_bytes]u8 = undefined,
    peer_chain_entries: [max_peer_chain_entries]Slice = undefined,
    peer_chain_count: usize = 0,
    peer_chain_len: usize = 0,
    /// A parked asynchronous authentication operation (an external signer,
    /// verifier, or async selector that returned `pending`). While set, the
    /// handshake is suspended: the receive loop stops consuming and the driver
    /// must call `resumeAuth` when the operation signals progress.
    pending_op: ?credentials.PendingOperation = null,
    pending_stage: PendingStage = undefined,
    /// The selected credential held across a pending signature (released when
    /// the signature completes, or cancelled at teardown).
    pending_credential: ?credentials.SelectedCredential = null,
    /// Stable, engine-owned signature output buffer. An async signer keeps a
    /// pointer to this across the suspend; the engine reads it on completion.
    pending_signature: [max_signature_len]u8 = undefined,

    const Slice = struct { start: usize, len: usize };
    const PendingStage = enum { server_select, server_sign, client_verify };

    /// Options for a client that verifies its peer through an external verifier:
    /// the exact intended server name (emitted as SNI and handed to the
    /// verifier) and the explicit authentication policy.
    pub const ClientOptions = struct {
        server_name: ?[]const u8 = null,
        /// Defaults to strict: an external verifier is assumed to require a
        /// valid peer certificate unless the caller opts out.
        policy: credentials.AuthPolicy = .{ .require_peer_authentication = true },
    };

    /// The authentication policy implied by a fixed `Trust`: insecure mode
    /// explicitly allows an unverified peer, pinning requires a match.
    fn policyFromTrust(trust: Trust) credentials.AuthPolicy {
        return switch (trust) {
            .insecure_no_verification => .{ .allow_unverified_peer = true },
            .pinned_certificate => .{ .require_peer_authentication = true },
        };
    }

    /// Allocation-free. The returned backend owns its copied entropy until
    /// `deinit`, which securely clears all private material.
    pub fn initClient(entropy: Entropy, trust: Trust, profile: TransportProfile) Tls13Backend {
        return .{
            .role = .client,
            .profile = profile,
            .entropy = entropy,
            .trust = trust,
            .auth_policy = policyFromTrust(trust),
            .core = tls_handshake_codec.Core.init(.client),
        };
    }

    /// Allocation-free. The returned backend owns its copy of `identity` and
    /// securely clears the private signing key in `deinit`. The fixed identity
    /// is served to the engine through the production `CredentialProvider`
    /// contract, identical to an external provider.
    pub fn initServer(entropy: Entropy, identity: Identity, profile: TransportProfile) Tls13Backend {
        return .{
            .role = .server,
            .profile = profile,
            .entropy = entropy,
            .identity = identity,
            .identity_present = true,
            .core = tls_handshake_codec.Core.init(.server),
        };
    }

    /// Server construction against an external credential provider (SNI
    /// selector, external/asynchronous signer, ...). The provider's storage
    /// must outlive the handshake. No fixed identity is held.
    pub fn initServerWithProvider(entropy: Entropy, provider: CredentialProvider, profile: TransportProfile) Tls13Backend {
        return .{
            .role = .server,
            .profile = profile,
            .entropy = entropy,
            .external_provider = provider,
            .core = tls_handshake_codec.Core.init(.server),
        };
    }

    /// Client construction against an external peer verifier (#324 Web-PKI, a
    /// custom trust store, ...). The verifier's storage must outlive the
    /// handshake. `options` carries the intended server name (emitted as SNI and
    /// passed to the verifier for hostname verification) and the explicit
    /// policy — the verifier never inherits the insecure trust default.
    pub fn initClientWithVerifier(entropy: Entropy, verifier: PeerVerifier, profile: TransportProfile, options: ClientOptions) Tls13Backend {
        var self: Tls13Backend = .{
            .role = .client,
            .profile = profile,
            .entropy = entropy,
            .external_verifier = verifier,
            .auth_policy = options.policy,
            .core = tls_handshake_codec.Core.init(.client),
        };
        if (options.server_name) |name| {
            // A name too long for the bounded buffer is a caller error; clamp
            // defensively (callers pass real hostnames, well under the bound).
            const n = @min(name.len, self.server_name.len);
            @memcpy(self.server_name[0..n], name[0..n]);
            self.server_name_len = n;
            self.server_name_present = true;
        }
        return self;
    }

    /// Server: request handshake-time client authentication, verifying the
    /// client's certificate through `verifier` (role `.server`). Must be called
    /// before `start`. `optional` accepts an empty client Certificate;
    /// `required` fails closed when the client presents none.
    pub fn requestClientAuthentication(self: *Tls13Backend, mode: ClientAuthMode, verifier: PeerVerifier) void {
        std.debug.assert(self.role == .server);
        self.client_auth = mode;
        self.external_verifier = verifier;
    }

    /// Client: supply the credential provider for the client's own certificate,
    /// used to authenticate when the server sends a CertificateRequest. Must be
    /// called before `start`.
    pub fn setLocalCredentialProvider(self: *Tls13Backend, provider: CredentialProvider) void {
        std.debug.assert(self.role == .client);
        self.external_provider = provider;
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
        const profile: TransportProfile = .{ .extension = .{
            .alpn = self.profile.alpn(),
            .extension_type = extension_type,
            .local = local,
        } };
        try profile.validate();
        self.profile = profile;
    }

    /// The typed credential/verification failure this handshake latched, if
    /// any. Survives `deinit` so a failed handshake's reason stays queryable.
    pub fn credentialFailure(self: *const Tls13Backend) ?CredentialFailure {
        return self.credential_failure;
    }

    /// Record a typed failure, mark the core failed, and return the engine-level
    /// error whose alert mapping matches the failure's origin (#334).
    fn failCredential(self: *Tls13Backend, class: CredentialFailure) HandshakeError {
        self.credential_failure = class;
        self.core.handshake_lifecycle = .failed;
        return class.engineError();
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
        // Cancel and release any parked async operation (and held credential)
        // exactly once before tearing down the rest.
        self.cancelPendingAuth();
        crypto.secureZero(u8, &self.pending_signature);
        if (self.schedule) |*schedule| schedule.wipe();
        self.schedule = null;
        crypto.secureZero(u8, &self.expected_client_verify);
        self.wipeEphemeral();
        self.wipeIdentity();
        crypto.secureZero(u8, &self.peer_chain);
        self.peer_chain_count = 0;
        self.peer_chain_len = 0;
        crypto.secureZero(u8, std.mem.asBytes(&self.peer_sig_schemes));
        self.peer_sig_scheme_count = 0;
        crypto.secureZero(u8, &self.server_name);
        self.server_name_len = 0;
        self.server_name_present = false;
        // `credential_failure` is intentionally *not* cleared: terminal cleanup
        // must preserve the underlying typed failure (#334). The external
        // provider/verifier vtables borrow caller storage; drop the references.
        self.external_provider = null;
        self.external_verifier = null;
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

    fn wipeEphemeral(self: *Tls13Backend) void {
        crypto.secureZero(u8, &self.entropy.key_share_seed);
        crypto.secureZero(u8, std.mem.asBytes(&self.key_pair));
        self.key_pair_present = false;
    }

    fn wipeIdentity(self: *Tls13Backend) void {
        crypto.secureZero(u8, std.mem.asBytes(&self.identity));
        self.identity_present = false;
    }

    fn startImpl(ptr: *anyopaque, role: Role, _: void, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        // The driver's role comes from Handshake.initClient/initServer and must
        // match how this backend was constructed; a mismatch is a wiring bug.
        std.debug.assert(role == self.role);
        std.debug.assert(self.core.handshake_lifecycle == .idle);
        try self.profile.validate();
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
            // A parked async authentication operation suspends the handshake:
            // stop consuming buffered messages until the driver resumes it (any
            // remaining bytes stay buffered and are drained on the next drive).
            if (self.pending_op != null) break;
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
            // Surfaced only by this backend's credential/verification path, not
            // the codec core, but they are part of the shared error set.
            error.NoApplicableCredential => error.NoApplicableCredential,
            error.CredentialProviderFailed => error.CredentialProviderFailed,
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
        var key_pair = X25519.KeyPair.generateDeterministic(self.entropy.key_share_seed) catch
            return error.SecretExportFailed;
        defer crypto.secureZero(u8, &key_pair.secret_key);
        self.key_pair = key_pair;
        self.key_pair_present = true;

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

        // server_name (RFC 6066): the configured intended host, so the server
        // can select on SNI and the same value reaches this side's verifier.
        if (self.serverNameSlice()) |name| {
            try w.u16_(ext_server_name);
            const sni_ext_len = try w.reserve(2);
            const sni_list_len = try w.reserve(2);
            try w.u8_(0); // name_type host_name
            try w.u16_(@intCast(name.len));
            try w.bytes(name);
            w.patch(2, sni_list_len);
            w.patch(2, sni_ext_len);
        }

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
        if (!self.key_pair_present) return error.InvalidHandshakeState;
        var shared = X25519.scalarmult(self.key_pair.secret_key, share) catch
            return error.IllegalParameter;
        defer crypto.secureZero(u8, &shared);
        self.wipeEphemeral();
        self.schedule = KeySchedule.init(&shared, self.core.transcriptHash());
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

        // Reassemble the *complete* chain into engine-owned storage. A verifier
        // (especially a #324 path builder) must decide trust over exactly what
        // the peer sent, never a prefix that happened to fit — so a chain that
        // exceeds our bounds fails closed with a peer-attributed error rather
        // than being silently truncated. Every CertificateEntry, leaf and
        // intermediate, must be non-empty and within `max_certificate_len`.
        self.peer_chain_count = 0;
        self.peer_chain_len = 0;
        var first = true;
        while (list.remaining() > 0) {
            const entry_len = try list.u24_();
            if (entry_len == 0 or entry_len > max_certificate_len) return self.failCredential(.invalid_peer_certificate_chain);
            const entry = try list.slice(entry_len);
            _ = try list.slice(try list.u16_()); // per-certificate extensions
            self.appendPeerCertificate(entry) catch return self.failCredential(.invalid_peer_certificate_chain);
            first = false;
        }
        // An empty CertificateList is only legal for client auth (an empty
        // client Certificate); a server that presents none is malformed here.
        if (first and self.role == .client) return self.failCredential(.invalid_peer_certificate_chain);
    }

    /// Copy one peer DER certificate into the bounded chain storage, recording
    /// its view. Returns `CertificateInvalid` when the entry or the aggregate
    /// chain would exceed the engine's bounds — the caller fails closed.
    fn appendPeerCertificate(self: *Tls13Backend, der: []const u8) error{CertificateInvalid}!void {
        if (self.peer_chain_count >= self.peer_chain_entries.len) return error.CertificateInvalid;
        if (self.peer_chain_len + der.len > self.peer_chain.len) return error.CertificateInvalid;
        const start = self.peer_chain_len;
        @memcpy(self.peer_chain[start..][0..der.len], der);
        self.peer_chain_entries[self.peer_chain_count] = .{ .start = start, .len = der.len };
        self.peer_chain_count += 1;
        self.peer_chain_len += der.len;
    }

    /// Build the immutable peer chain view over engine storage into `out`. The
    /// returned slices are valid only until `peer_chain` is next mutated or the
    /// backend is torn down; a verifier must not retain them.
    fn peerChainView(self: *const Tls13Backend, out: *[max_peer_chain_entries][]const u8) credentials.CertificateChain {
        for (0..self.peer_chain_count) |i| {
            const e = self.peer_chain_entries[i];
            out[i] = self.peer_chain[e.start..][0..e.len];
        }
        return .{ .entries = out[0..self.peer_chain_count] };
    }

    fn serverSelectionContext(self: *const Tls13Backend) credentials.SelectionContext {
        return .{
            .role = .server,
            .server_name = self.serverNameSlice(),
            .peer_signature_schemes = self.peer_sig_schemes[0..self.peer_sig_scheme_count],
            .negotiated_version = tls13_version,
            .cipher_suite = cipher_tls_aes_128_gcm_sha256,
            .application_protocol = self.alpn(),
            .auth_policy = self.auth_policy,
        };
    }

    /// The intended/parsed SNI as a borrowed slice, or null when absent.
    fn serverNameSlice(self: *const Tls13Backend) ?[]const u8 {
        return if (self.server_name_present) self.server_name[0..self.server_name_len] else null;
    }

    fn onCertificateVerify(self: *Tls13Backend, transcript_before: [hash_len]u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        var r = Reader{ .bytes = body };
        const algorithm = try r.u16_();
        const signature = try r.slice(try r.u16_());
        try r.expectEnd();

        // The signature covers the transcript through Certificate (RFC 8446
        // §4.4.3) — before this message is added. Proof of key possession is
        // transcript crypto, not PKI policy, so it stays in the engine; a
        // failure is peer-originated (bad_certificate).
        const content = certificateVerifyContent(.server, transcript_before);
        if (!self.checkProofOfPossession(algorithm, signature, content.slice())) {
            try sink.emitCertificate(.invalid);
            return self.failCredential(.certificate_verify_invalid);
        }

        // Delegate the trust verdict to the peer verifier — the fixed pin/
        // insecure policy or an external #324 Web-PKI verifier — over immutable
        // DER views it must not retain.
        var views: [max_peer_chain_entries][]const u8 = undefined;
        var verifier_storage: credentials.FixedVerifier = undefined;
        const verifier = if (self.external_verifier) |v| v else blk: {
            verifier_storage = credentials.FixedVerifier.init(self.trust);
            break :blk verifier_storage.verifier();
        };
        const context = credentials.VerificationContext{
            .role = .client,
            .server_name = self.serverNameSlice(),
            .chain = self.peerChainView(&views),
            .negotiated_version = tls13_version,
            .cipher_suite = cipher_tls_aes_128_gcm_sha256,
            .application_protocol = self.alpn(),
            .auth_policy = self.auth_policy,
        };
        // The verifier may resolve synchronously or return a pending operation
        // (an async Web-PKI/OCSP lookup); park the latter and resume later.
        switch (verifier.verifyPeer(&context) catch |err|
            return self.failCredential(credentials.classifyVerifyError(err))) {
            .complete => |verdict| return self.applyClientVerdict(verdict, sink),
            .pending => |op| return self.parkAuth(op, .client_verify),
        }
    }

    /// Apply a peer-verification verdict: emit the certificate state and fail
    /// closed on rejection. Reachable synchronously and after resume.
    fn applyClientVerdict(self: *Tls13Backend, verdict: credentials.Verdict, sink: *EventSink) HandshakeError!void {
        const state: CertificateState = switch (verdict) {
            .accepted => .valid,
            .not_checked => .not_checked,
            .rejected => .invalid,
        };
        try sink.emitCertificate(state);
        if (state == .invalid) return self.failCredential(.peer_verification_rejected);
    }

    /// Verify the CertificateVerify signature against the peer leaf's public
    /// key: proof that the peer holds the private key for the presented
    /// certificate. Returns false on any mismatch. This is not a trust decision
    /// — that is the verifier's job.
    fn checkProofOfPossession(self: *const Tls13Backend, algorithm: u16, signature: []const u8, content: []const u8) bool {
        if (self.peer_chain_count == 0) return false;
        const e = self.peer_chain_entries[0];
        const leaf = self.peer_chain[e.start..][0..e.len];
        const parsed = (Certificate{ .buffer = leaf, .index = 0 }).parse() catch return false;
        switch (algorithm) {
            sigalg_ed25519 => {
                if (signature.len != Ed25519.Signature.encoded_length) return false;
                if (parsed.pub_key_algo != .curveEd25519) return false;
                const pub_key_bytes = parsed.pubKey();
                if (pub_key_bytes.len != Ed25519.PublicKey.encoded_length) return false;
                const public_key = Ed25519.PublicKey.fromBytes(pub_key_bytes[0..Ed25519.PublicKey.encoded_length].*) catch return false;
                const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
                sig.verify(content, public_key) catch return false;
            },
            sigalg_ecdsa_secp256r1_sha256 => {
                switch (parsed.pub_key_algo) {
                    .X9_62_id_ecPublicKey => |curve| if (curve != .X9_62_prime256v1) return false,
                    else => return false,
                }
                const public_key = EcdsaP256.PublicKey.fromSec1(parsed.pubKey()) catch return false;
                const sig = EcdsaP256.Signature.fromDer(signature) catch return false;
                sig.verify(content, public_key) catch return false;
            },
            else => return false,
        }
        return true;
    }

    fn onServerFinished(self: *Tls13Backend, transcript_before: [hash_len]u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        const schedule = &self.schedule.?;
        if (body.len != hash_len) return error.MalformedHandshake;
        var expected = KeySchedule.verifyData(&schedule.server_handshake_traffic, transcript_before);
        defer crypto.secureZero(u8, &expected);
        if (!crypto.timing_safe.eql([hash_len]u8, expected, body[0..hash_len].*)) {
            return error.MalformedHandshake;
        }

        // 1-RTT secrets exist from the transcript through server Finished.
        const finished_hash = self.core.transcriptHash();
        var app = schedule.applicationSecrets(finished_hash);
        defer app.wipe();
        try self.emitSecret(sink, .application, .write, &app.client);
        try self.emitSecret(sink, .application, .read, &app.server);

        // Client Finished covers the transcript including server Finished.
        var buf: [4 + hash_len]u8 = undefined;
        var w = Writer{ .buf = &buf };
        try w.u8_(@intFromEnum(MessageType.finished));
        const message_len = try w.reserve(3);
        var client_verify = KeySchedule.verifyData(&schedule.client_handshake_traffic, finished_hash);
        defer crypto.secureZero(u8, &client_verify);
        try w.bytes(&client_verify);
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

        // A server needs a credential source: the fixed identity or an external
        // provider. Which signature scheme is usable is decided later by
        // credential selection against the peer's advertised algorithms.
        if (!self.identity_present and self.external_provider == null) return error.InvalidHandshakeState;
        self.peer_sig_scheme_count = 0;
        self.server_name_present = false;
        self.server_name_len = 0;
        var offers_tls13 = false;
        var offers_x25519_group = false;
        var saw_signature_algorithms = false;
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
                    saw_signature_algorithms = true;
                    var algorithms = Reader{ .bytes = try ext.slice(try ext.u16_()) };
                    // Preserve the peer's *complete* offer in order — truncating
                    // it would silently turn a compatible scheme in a high slot
                    // into a false local "no compatible credential". If the offer
                    // is larger than our bounded vector, fail rather than lie to
                    // the selector about what the peer supports.
                    while (algorithms.remaining() > 0) {
                        const scheme = try algorithms.u16_();
                        if (self.peer_sig_scheme_count >= self.peer_sig_schemes.len) return error.MalformedHandshake;
                        self.peer_sig_schemes[self.peer_sig_scheme_count] = scheme;
                        self.peer_sig_scheme_count += 1;
                    }
                    try ext.expectEnd();
                },
                ext_server_name => {
                    // RFC 6066 §3: ServerNameList<1..>, each { name_type, name<..> }.
                    // Distinguish absent (no extension / no host_name) from valid
                    // and from malformed: an empty, over-bound, or duplicated
                    // host_name is rejected deterministically rather than being
                    // collapsed into the default-certificate path, so a selector
                    // never serves the default cert for an invalid SNI.
                    var names = Reader{ .bytes = try ext.slice(try ext.u16_()) };
                    while (names.remaining() > 0) {
                        const name_type = try names.u8_();
                        const name = try names.slice(try names.u16_());
                        if (name_type != 0) continue; // only host_name is defined
                        // RFC 6066: a given name_type must appear at most once.
                        if (self.server_name_present) return error.IllegalParameter;
                        if (name.len == 0 or name.len > self.server_name.len) return error.IllegalParameter;
                        @memcpy(self.server_name[0..name.len], name);
                        self.server_name_len = name.len;
                        self.server_name_present = true;
                    }
                    try ext.expectEnd();
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
        if (!offers_tls13 or !offers_x25519_group) return error.MalformedHandshake;
        // signature_algorithms is required whenever the server authenticates
        // with a certificate (RFC 8446 §9.2). A missing or empty list is a
        // malformed/missing required *peer* extension — attribute it to the
        // peer (decode_error), not to local credential configuration.
        if (!saw_signature_algorithms or self.peer_sig_scheme_count == 0) return error.MalformedHandshake;
        const client_share = peer_share orelse return error.MalformedHandshake;

        // Validate the peer share before emitting anything: X25519.scalarmult
        // rejects low-order/identity public keys (all-zero shared secret)
        // rather than deriving a predictable secret.
        var key_pair = X25519.KeyPair.generateDeterministic(self.entropy.key_share_seed) catch
            return error.SecretExportFailed;
        defer crypto.secureZero(u8, &key_pair.secret_key);
        self.key_pair = key_pair;
        self.key_pair_present = true;
        var shared = X25519.scalarmult(key_pair.secret_key, client_share) catch
            return error.IllegalParameter;
        defer crypto.secureZero(u8, &shared);
        crypto.secureZero(u8, &key_pair.secret_key);
        self.wipeEphemeral();

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

        self.schedule = KeySchedule.init(&shared, self.core.transcriptHash());
        try self.emitHandshakeSecrets(sink);
        try sink.emitDiscardKeys(.initial);

        try self.sendServerFlight(sink);
    }

    /// EncryptedExtensions + Certificate + CertificateVerify + Finished at the
    /// Handshake level, followed by the 1-RTT secrets.
    fn sendServerFlight(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        // Resolve the credential provider — an external one, or the fixed
        // identity wrapped in the identical production contract — and select a
        // credential for the negotiated parameters. There is one path.
        var fixed_provider: credentials.FixedCredentialProvider = undefined;
        var using_fixed = false;
        const provider = if (self.external_provider) |p| p else blk: {
            if (!self.identity_present) return self.failCredential(.no_credential_available);
            fixed_provider = credentials.FixedCredentialProvider.init(self.identity);
            using_fixed = true;
            break :blk fixed_provider.provider();
        };
        // Wipe the fixed key material (stack copy and stored identity) on the
        // way out, whatever the outcome.
        defer if (using_fixed) {
            fixed_provider.deinit();
            self.wipeIdentity();
        };

        var selection = self.serverSelectionContext();
        // Selection may complete synchronously or return a pending operation
        // (e.g. an async SNI lookup); park the latter and resume later.
        switch (provider.selectCredential(&selection) catch |err|
            return self.failCredential(credentials.classifySelectError(err))) {
            .complete => |credential| return self.emitServerAuthFlight(credential, sink),
            .pending => |op| return self.parkAuth(op, .server_select),
        }
    }

    /// Validate the selected credential, emit EncryptedExtensions+Certificate,
    /// then sign CertificateVerify — synchronously, or by parking a pending
    /// signer. On any failure the handle is released exactly once.
    fn emitServerAuthFlight(self: *Tls13Backend, credential: credentials.SelectedCredential, sink: *EventSink) HandshakeError!void {
        var owned = true;
        errdefer if (owned) credential.release();

        // Validate provider output before trusting it: the returned scheme must
        // have been offered (else the CertificateVerify carries an algorithm the
        // client never advertised), and the chain must fit the flight bounds. A
        // violation is a local provider fault; signing never happens.
        const selection = self.serverSelectionContext();
        if (!selection.offersScheme(credential.scheme))
            return self.failCredential(.invalid_callback_behavior);
        const chain = credential.certificateChain();
        if (chain.count() == 0 or chain.count() > credentials.max_chain_entries)
            return self.failCredential(.malformed_credential_chain);
        var encoded_len: usize = 0;
        for (chain.entries) |entry| {
            if (entry.len == 0 or entry.len > max_certificate_len)
                return self.failCredential(.malformed_credential_chain);
            // CertificateEntry framing overhead: 3-byte cert_data length +
            // 2-byte extensions length.
            encoded_len = std.math.add(usize, encoded_len, entry.len + 5) catch
                return self.failCredential(.malformed_credential_chain);
            if (encoded_len > max_message_len)
                return self.failCredential(.malformed_credential_chain);
        }

        // Ask the client to authenticate (handshake-time client auth, #334)
        // before recording the flight, so the Core inserts CertificateRequest
        // after EncryptedExtensions and expects the client certificate flight
        // after the server Finished.
        if (self.client_auth != .disabled) self.core.requestClientCertificate();

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

        // CertificateRequest (RFC 8446 §4.3.2), when requesting client auth:
        // empty context, a signature_algorithms extension listing accepted
        // client-auth schemes.
        var certificate_request: []const u8 = &.{};
        if (self.client_auth != .disabled) {
            const cr_start = w.len;
            try w.u8_(@intFromEnum(MessageType.certificate_request));
            const cr_len = try w.reserve(3);
            try w.u8_(0); // certificate_request_context<0..255>: empty
            const cr_exts = try w.reserve(2);
            try w.u16_(ext_signature_algorithms);
            try w.u16_(2 + 2 * 2); // extension_data length
            try w.u16_(2 * 2); // supported_signature_algorithms list length
            try w.u16_(sigalg_ed25519);
            try w.u16_(sigalg_ecdsa_secp256r1_sha256);
            w.patch(2, cr_exts);
            w.patch(3, cr_len);
            certificate_request = buf[cr_start..w.len];
        }

        // Certificate: the selected credential's validated public DER chain,
        // valid until `release`.
        const cert_start = w.len;
        try w.u8_(@intFromEnum(MessageType.certificate));
        const cert_len = try w.reserve(3);
        try w.u8_(0); // certificate_request_context
        const list_len = try w.reserve(3);
        for (chain.entries) |entry| {
            const entry_len = try w.reserve(3);
            try w.bytes(entry);
            w.patch(3, entry_len);
            try w.u16_(0); // per-certificate extensions
        }
        w.patch(3, list_len);
        w.patch(3, cert_len);
        const certificate = buf[cert_start..w.len];

        self.core.recordSent(encrypted_extensions) catch |err| return mapCoreError(err);
        if (certificate_request.len > 0)
            self.core.recordSent(certificate_request) catch |err| return mapCoreError(err);
        self.core.recordSent(certificate) catch |err| return mapCoreError(err);
        try sink.emitCrypto(.handshake, buf[0..w.len]);

        // CertificateVerify signs the transcript through Certificate, into the
        // engine-owned buffer. Signing goes through the opaque handle; the
        // private key never enters the engine. An async signer parks here.
        const content = certificateVerifyContent(.server, self.core.transcriptHash());
        switch (credential.sign(content.slice(), &self.pending_signature) catch |err|
            return self.failCredential(credentials.classifySignError(err))) {
            .complete => |len| {
                owned = false; // ownership passes to serverFinishFlight
                return self.serverFinishFlight(credential, len, sink);
            },
            .pending => |op| {
                owned = false; // ownership passes to the parked operation
                self.pending_credential = credential;
                return self.parkAuth(op, .server_sign);
            },
        }
    }

    /// Emit CertificateVerify (with the completed signature) and Finished, then
    /// the 1-RTT secrets. Releases the credential exactly once. Reachable both
    /// synchronously and after resuming a pending signature.
    fn serverFinishFlight(self: *Tls13Backend, credential: credentials.SelectedCredential, sig_len: usize, sink: *EventSink) HandshakeError!void {
        defer credential.release();
        const schedule = &self.schedule.?;
        if (sig_len > self.pending_signature.len) return self.failCredential(.signature_output_overflow);

        var buf: [max_message_len]u8 = undefined;
        var w = Writer{ .buf = &buf };
        try w.u8_(@intFromEnum(MessageType.certificate_verify));
        const verify_len = try w.reserve(3);
        try w.u16_(credential.scheme.code());
        const sig_len_slot = try w.reserve(2);
        try w.bytes(self.pending_signature[0..sig_len]);
        w.patch(2, sig_len_slot);
        w.patch(3, verify_len);
        const certificate_verify = buf[0..w.len];
        crypto.secureZero(u8, &self.pending_signature);
        self.core.recordSent(certificate_verify) catch |err| return mapCoreError(err);

        // Finished covers the transcript through CertificateVerify.
        const finished_start = w.len;
        try w.u8_(@intFromEnum(MessageType.finished));
        const finished_len = try w.reserve(3);
        var server_verify = KeySchedule.verifyData(&schedule.server_handshake_traffic, self.core.transcriptHash());
        defer crypto.secureZero(u8, &server_verify);
        try w.bytes(&server_verify);
        w.patch(3, finished_len);
        const finished = buf[finished_start..w.len];
        self.core.recordSent(finished) catch |err| return mapCoreError(err);
        // Emit CertificateVerify and Finished together (the second half of the
        // flight; EncryptedExtensions+Certificate were emitted before signing).
        try sink.emitCrypto(.handshake, buf[0..w.len]);

        // 1-RTT secrets from the transcript through server Finished; the
        // client Finished we will require is fixed by the same hash.
        const finished_hash = self.core.transcriptHash();
        var app = schedule.applicationSecrets(finished_hash);
        defer app.wipe();
        try self.emitSecret(sink, .application, .read, &app.client);
        try self.emitSecret(sink, .application, .write, &app.server);
        var client_verify = KeySchedule.verifyData(&schedule.client_handshake_traffic, finished_hash);
        defer crypto.secureZero(u8, &client_verify);
        self.expected_client_verify = client_verify;
    }

    // -----------------------------------------------------------------------
    // Asynchronous authentication (parking / resume / cancel).
    // -----------------------------------------------------------------------

    /// True while an authentication operation is parked; the driver must call
    /// `resumeAuth` when it signals progress, and stop feeding new bytes.
    pub fn authPending(self: *const Tls13Backend) bool {
        return self.pending_op != null;
    }

    fn parkAuth(self: *Tls13Backend, op: credentials.PendingOperation, stage: PendingStage) void {
        self.pending_op = op;
        self.pending_stage = stage;
    }

    /// Poll a parked authentication operation. When it is still pending this is
    /// a no-op; when it completes the handshake resumes exactly where it
    /// suspended, recording no handshake message twice; when it fails the typed
    /// failure is latched.
    pub fn resumeAuth(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        const op = self.pending_op orelse return error.InvalidHandshakeState;
        const stage = self.pending_stage;
        var completion: credentials.Completion = undefined;
        const done = op.poll(&completion) catch {
            self.cancelPendingAuth();
            return self.failCredential(pendingFailureClass(stage));
        };
        if (!done) return; // still pending; the driver polls again later
        op.release();
        self.pending_op = null;
        switch (stage) {
            .server_select => {
                if (completion != .credential) return self.failCredential(.provider_internal_failure);
                return self.emitServerAuthFlight(completion.credential, sink);
            },
            .server_sign => {
                if (completion != .signature_len) return self.failCredential(.invalid_callback_behavior);
                const credential = self.pending_credential orelse return error.InvalidHandshakeState;
                self.pending_credential = null;
                return self.serverFinishFlight(credential, completion.signature_len, sink);
            },
            .client_verify => {
                if (completion != .verdict) return self.failCredential(.verifier_internal_failure);
                return self.applyClientVerdict(completion.verdict, sink);
            },
        }
    }

    /// The failure class for a pending operation that reported an error, by
    /// the stage it was resolving.
    fn pendingFailureClass(stage: PendingStage) CredentialFailure {
        return switch (stage) {
            .server_select => .provider_internal_failure,
            .server_sign => .signing_provider_failure,
            .client_verify => .verifier_internal_failure,
        };
    }

    /// Cancel and release a parked operation (and any held credential) exactly
    /// once, on handshake teardown or failure.
    fn cancelPendingAuth(self: *Tls13Backend) void {
        if (self.pending_op) |op| {
            op.cancel();
            op.release();
            self.pending_op = null;
        }
        if (self.pending_credential) |credential| {
            credential.release();
            self.pending_credential = null;
        }
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

/// Deterministic local server identity fixture — see `credentials.testdata`.
/// Re-exported here so existing callers and tests keep their spelling.
pub const testdata = credentials.testdata;

test "TLS-owned backend teardown clears transcript-adjacent and peer scratch" {
    var backend = Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0x41} ** 32, .key_share_seed = [_]u8{0x42} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .{ .record = .{ .alpn = "h2" } },
    );
    backend.core.transcript.update("transcript-adjacent state");
    @memset(&backend.expected_client_verify, 0xa5);
    @memset(&backend.peer_chain, 0x5a);
    backend.peer_chain_entries[0] = .{ .start = 0, .len = 32 };
    backend.peer_chain_count = 1;
    backend.peer_chain_len = 32;
    backend.deinit();

    try std.testing.expect(std.mem.allEqual(u8, &backend.expected_client_verify, 0));
    try std.testing.expect(std.mem.allEqual(u8, &backend.peer_chain, 0));
    try std.testing.expect(std.mem.allEqual(u8, &backend.entropy.key_share_seed, 0));
    try std.testing.expect(!backend.key_pair_present);
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&backend.key_pair), 0));
    try std.testing.expectEqual(@as(usize, 0), backend.peer_chain_count);
    try std.testing.expectEqual(@as(usize, 0), backend.peer_chain_len);
    try std.testing.expectEqual(tls_handshake_codec.HandshakeLifecycle.failed, backend.core.handshake_lifecycle);
}

test "transport profile validation fails before lifecycle or transcript advance" {
    const entropy = Entropy{ .hello_random = [_]u8{0x41} ** 32, .key_share_seed = [_]u8{0x42} ** 32 };
    const invalid_alpns = [_][]const u8{ "", &([_]u8{'a'} ** 256) };
    for (invalid_alpns) |alpn_value| {
        var backend = Tls13Backend.initClient(
            entropy,
            .{ .pinned_certificate = testdata.certificate_der },
            .{ .record = .{ .alpn = alpn_value } },
        );
        var sink = EventSink{};
        defer sink.deinit();
        try std.testing.expectError(error.InvalidTransportProfile, backend.backend().start(.client, {}, &sink));
        try std.testing.expectEqual(tls_handshake_codec.HandshakeLifecycle.idle, backend.core.handshake_lifecycle);
        try std.testing.expectEqual(@as(usize, 0), sink.len);
        try std.testing.expect(!backend.key_pair_present);
        try std.testing.expectEqualSlices(u8, &entropy.key_share_seed, &backend.entropy.key_share_seed);
        backend.deinit();
    }

    var oversized = [_]u8{0xa5} ** (max_transport_extension_len + 1);
    var extension_backend = Tls13Backend.initClient(
        entropy,
        .{ .pinned_certificate = testdata.certificate_der },
        .{ .extension = .{ .alpn = "h3", .extension_type = 57, .local = &oversized } },
    );
    var extension_sink = EventSink{};
    defer extension_sink.deinit();
    try std.testing.expectError(error.InvalidTransportProfile, extension_backend.backend().start(.client, {}, &extension_sink));
    try std.testing.expectEqual(tls_handshake_codec.HandshakeLifecycle.idle, extension_backend.core.handshake_lifecycle);
    try std.testing.expectEqual(@as(usize, 0), extension_sink.len);
    try std.testing.expectError(error.InvalidTransportProfile, extension_backend.setExtensionProfile(ext_alpn, "valid"));
    extension_backend.deinit();

    var collision_backend = Tls13Backend.initClient(
        entropy,
        .{ .pinned_certificate = testdata.certificate_der },
        .{ .extension = .{ .alpn = "h3", .extension_type = ext_supported_versions, .local = "valid" } },
    );
    var collision_sink = EventSink{};
    defer collision_sink.deinit();
    try std.testing.expectError(error.InvalidTransportProfile, collision_backend.backend().start(.client, {}, &collision_sink));
    try std.testing.expectEqual(tls_handshake_codec.HandshakeLifecycle.idle, collision_backend.core.handshake_lifecycle);
    try std.testing.expectEqual(@as(usize, 0), collision_sink.len);
    collision_backend.deinit();
}

test "abandoned backend teardown wipes ephemeral and server identity storage" {
    const entropy = Entropy{ .hello_random = [_]u8{0x31} ** 32, .key_share_seed = [_]u8{0x32} ** 32 };
    var client = Tls13Backend.initClient(
        entropy,
        .{ .pinned_certificate = testdata.certificate_der },
        .{ .record = .{ .alpn = "h2" } },
    );
    var sink = EventSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);
    try std.testing.expect(client.key_pair_present);
    client.deinit();
    try std.testing.expect(std.mem.allEqual(u8, &client.entropy.key_share_seed, 0));
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&client.key_pair), 0));
    try std.testing.expect(!client.key_pair_present);

    var server = Tls13Backend.initServer(
        entropy,
        try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
        .{ .record = .{ .alpn = "h2" } },
    );
    server.deinit();
    try std.testing.expect(!server.identity_present);
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&server.identity), 0));
    try std.testing.expect(std.mem.allEqual(u8, &server.entropy.key_share_seed, 0));
}
