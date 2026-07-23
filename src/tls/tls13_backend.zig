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
const dns_name = @import("dns_name.zig");
const events = @import("events.zig");
const credentials = @import("credentials.zig");
const tls_algorithms = @import("algorithms.zig");
const tls_negotiation = @import("negotiation.zig");
const tls_policy = @import("policy.zig");
const crypto_pkg = @import("crypto");
const tls_handshake_codec = @import("handshake.zig");
const tls_key_schedule = @import("key_schedule.zig");
const new_session_ticket = @import("new_session_ticket.zig");
const pre_shared_key = @import("pre_shared_key.zig");
const session = @import("session.zig");
const tls_state = @import("state.zig");
const tls13_transport = @import("tls13_transport.zig");

const crypto = std.crypto;
const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;
const EcdsaP256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const Certificate = crypto.Certificate;
const Sha256 = crypto.hash.sha2.Sha256;

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
/// Largest framed handshake message we accept during the main handshake.
pub const max_message_len = 8 * 1024;
/// Largest framed post-handshake NewSessionTicket message: a 65535-byte opaque
/// ticket identity plus its handshake header and small fixed/vector fields.
pub const max_new_session_ticket_message_len = tls13_transport.max_new_session_ticket_message_len;
const handshake_header_len = 4;
var empty_observer_dummy: u8 = 0;

const PostHandshakeInput = struct {
    allocator: ?std.mem.Allocator = null,
    buf_allocator: ?std.mem.Allocator = null,
    header: [handshake_header_len]u8 = undefined,
    header_len: usize = 0,
    buf: []u8 = &.{},
    len: usize = 0,

    fn setAllocator(self: *PostHandshakeInput, allocator: std.mem.Allocator) HandshakeError!void {
        if (self.buf.len > 0 and !sameAllocator(self.buf_allocator.?, allocator)) return error.InvalidHandshakeState;
        self.allocator = allocator;
    }

    fn deinit(self: *PostHandshakeInput) void {
        if (self.buf.len > 0) {
            crypto.secureZero(u8, self.buf);
            self.buf_allocator.?.free(self.buf);
        }
        if (self.header_len > 0) crypto.secureZero(u8, self.header[0..self.header_len]);
        self.* = .{};
    }

    fn append(self: *PostHandshakeInput, bytes: []const u8) HandshakeError!usize {
        if (self.buf.len > 0 and self.len == self.buf.len) return 0;
        var rest = bytes;
        const original_len = bytes.len;
        while (rest.len > 0) {
            if (self.buf.len == 0) {
                if (self.header_len < handshake_header_len) {
                    const take = @min(handshake_header_len - self.header_len, rest.len);
                    @memcpy(self.header[self.header_len..][0..take], rest[0..take]);
                    self.header_len += take;
                    rest = rest[take..];
                    if (self.header_len < handshake_header_len) return original_len - rest.len;
                }
                const body_len: usize = @intCast(std.mem.readInt(u24, self.header[1..4], .big));
                const frame_len = handshake_header_len + body_len;
                if (frame_len > max_new_session_ticket_message_len) return error.HandshakeBufferOverflow;
                const allocator = self.allocator orelse return error.InvalidHandshakeState;
                self.buf = allocator.alloc(u8, frame_len) catch return error.CredentialProviderFailed;
                self.buf_allocator = allocator;
                @memcpy(self.buf[0..handshake_header_len], &self.header);
                self.len = handshake_header_len;
                crypto.secureZero(u8, &self.header);
                self.header_len = 0;
            }
            const take = @min(self.buf.len - self.len, rest.len);
            @memcpy(self.buf[self.len..][0..take], rest[0..take]);
            self.len += take;
            rest = rest[take..];
            if (self.len == self.buf.len) break;
        }
        return original_len - rest.len;
    }

    fn peek(self: *PostHandshakeInput) tls_handshake_codec.Error!?tls_handshake_codec.Message {
        if (self.buf.len == 0 or self.len < self.buf.len) return null;
        return try tls_handshake_codec.decode(self.buf[0..self.len]);
    }

    fn discard(self: *PostHandshakeInput, len: usize) tls_handshake_codec.Error!void {
        if (self.buf.len == 0 or len != self.buf.len) return error.MalformedHandshake;
        crypto.secureZero(u8, self.buf);
        self.buf_allocator.?.free(self.buf);
        self.buf_allocator = null;
        self.buf = &.{};
        self.len = 0;
    }
};

fn sameAllocator(a: std.mem.Allocator, b: std.mem.Allocator) bool {
    return a.ptr == b.ptr and a.vtable == b.vtable;
}
pub const max_certificate_len = 2048;
/// The Certificate handshake message's fixed framing overhead, counted in the
/// flight-size preflight so a chain cannot pass validation and then overflow the
/// writer once the message header is added: 1-byte msg_type + 3-byte length +
/// 1-byte certificate_request_context length + 3-byte CertificateList length.
pub const certificate_message_overhead = 1 + 3 + 1 + 3;
/// Per-CertificateEntry framing the writer adds around each raw DER
/// certificate: 3-byte cert_data length + 2-byte per-certificate extensions
/// length (RFC 8446 §4.4.2). Exported so a caller preflighting a chain (#392)
/// sums the exact same per-entry cost the writer below does, rather than
/// duplicating this literal.
pub const certificate_entry_overhead = 3 + 2;
/// Caller-owned bound on a CertificateVerify signature. The engine hands the
/// signing provider a buffer this size; a provider whose signature would not
/// fit reports overflow rather than exceeding the bound (#334). Comfortably
/// above Ed25519 (64) and DER-encoded ECDSA P-256 (~72).
pub const max_signature_len = 256;

/// Worst-case size of everything the server flight buffer carries *besides*
/// the Certificate message, so a caller can preflight how much of
/// `max_message_len` a certificate chain may actually occupy without
/// duplicating the writer's own arithmetic (#392). Conservatively sums, for
/// any transport profile and any client-auth policy this engine supports:
///
///   - EncryptedExtensions framing: 1-byte msg_type + 3-byte length +
///     2-byte extensions-vector length = 6 bytes.
///   - The ALPN extension at its legal maximum: 2-byte extension type +
///     2-byte extension length + 2-byte protocol-list length + 1-byte
///     protocol length + up to 255 protocol bytes (`Policy`'s ALPN validation
///     bound) = 262 bytes.
///   - The opaque transport extension (QUIC/H3 profile only; record mode
///     carries none): 2-byte type + 2-byte length + `max_transport_extension_len`
///     payload = 516 bytes.
///   - CertificateRequest, for a profile that requests client
///     authentication: 1-byte msg_type + 3-byte length + 1-byte empty
///     context + 2-byte extensions length + 2-byte ext type + 2-byte ext
///     length + 2-byte sigalg-list length + 4 bytes for the two advertised
///     signature algorithms = 17 bytes.
///
/// The appliance profile (#392) never requests client authentication and
/// uses at most one short ALPN protocol name, so this bound has headroom to
/// spare; it is deliberately not narrowed to that specific configuration so
/// it stays correct if either changes.
pub const max_non_certificate_server_flight_bytes: usize = 6 + 262 + (4 + max_transport_extension_len) + 17;

fn checkedAdd(a: usize, b: usize) HandshakeError!usize {
    return std.math.add(usize, a, b) catch return error.InvalidTransportProfile;
}

const tls13_version: u16 = @intFromEnum(tls_algorithms.ProtocolVersion.tls13);
const legacy_version: u16 = tls_algorithms.legacy_version;
const cipher_tls_aes_128_gcm_sha256: u16 = @intFromEnum(tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256);
const group_x25519: u16 = @intFromEnum(tls_algorithms.NamedGroup.x25519);
const sigalg_ed25519: u16 = @intFromEnum(tls_algorithms.SignatureScheme.ed25519);
const sigalg_ecdsa_secp256r1_sha256: u16 = @intFromEnum(tls_algorithms.SignatureScheme.ecdsa_secp256r1_sha256);

const ext_server_name: u16 = @intFromEnum(tls_algorithms.ExtensionType.server_name);
const ext_supported_groups: u16 = @intFromEnum(tls_algorithms.ExtensionType.supported_groups);
const ext_signature_algorithms: u16 = @intFromEnum(tls_algorithms.ExtensionType.signature_algorithms);
const ext_alpn: u16 = @intFromEnum(tls_algorithms.ExtensionType.application_layer_protocol_negotiation);
const ext_supported_versions: u16 = @intFromEnum(tls_algorithms.ExtensionType.supported_versions);
const ext_key_share: u16 = @intFromEnum(tls_algorithms.ExtensionType.key_share);
const ext_early_data: u16 = @intFromEnum(tls_algorithms.ExtensionType.early_data);
pub const max_transport_extension_len = 512;

const native_protocol_versions = [_]tls_algorithms.ProtocolVersion{.tls13};
const native_cipher_suites = [_]tls_algorithms.CipherSuite{.tls_aes_128_gcm_sha256};
const native_named_groups = [_]tls_algorithms.NamedGroup{.x25519};
const native_signature_schemes = [_]tls_algorithms.SignatureScheme{ .ed25519, .ecdsa_secp256r1_sha256 };

pub const native_capabilities = tls_policy.Capabilities{
    .protocol_versions = &native_protocol_versions,
    .cipher_suites = &native_cipher_suites,
    .named_groups = &native_named_groups,
    .signature_schemes = &native_signature_schemes,
};

pub const BackendConfig = struct {
    policy: tls_policy.Policy,
    transport: TransportProfile,
};

pub fn recordConfig(policy: tls_policy.Policy) BackendConfig {
    return .{ .policy = policy, .transport = .record };
}

fn defaultConfigForTransport(transport: TransportProfile) BackendConfig {
    return switch (transport) {
        .record => recordConfig(tls_policy.Policy.recordH2Only()),
        .extension => .{ .policy = tls_policy.Policy.quicDefault(), .transport = transport },
    };
}

/// Transport differences are explicit production configuration, never a
/// mutable test-only switch. The TLS engine treats the extension payload as
/// opaque; the owning transport adapter is responsible for its codec and
/// policy. Record mode carries no transport-specific extension.
pub const TransportProfile = union(enum) {
    record,
    extension: ExtensionOptions,

    pub const ExtensionOptions = struct {
        extension_type: u16,
        /// Borrowed from the transport adapter. It must remain valid until the
        /// local ClientHello or EncryptedExtensions flight has been emitted.
        local: []const u8,
    };

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
        if (self == .extension) {
            const options = self.extension;
            if (options.local.len > max_transport_extension_len) return error.InvalidTransportProfile;
            switch (options.extension_type) {
                ext_server_name,
                ext_supported_groups,
                ext_signature_algorithms,
                ext_alpn,
                ext_supported_versions,
                ext_key_share,
                @intFromEnum(tls_algorithms.ExtensionType.padding),
                @intFromEnum(tls_algorithms.ExtensionType.early_data),
                @intFromEnum(tls_algorithms.ExtensionType.cookie),
                // #362: reserve the TLS-owned PSK extension IDs too — a
                // caller configuring a transport extension with either of
                // these types would otherwise collide with (and be
                // misparsed as) the PSK negotiation extensions.
                pre_shared_key.ext_pre_shared_key,
                pre_shared_key.ext_psk_key_exchange_modes,
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

// ===========================================================================
// 0-RTT / early-data vocabulary (#366).
//
// Native TLS 1.3/QUIC 0-RTT mechanics: explicit client opt-in, a server-side
// identity-0/skew/replay decision made inside the existing `selectPsk`
// selection, and EncryptedExtensions acceptance signaling. Ticket
// advertisement, record/QUIC key installation, and HTTP-level request-safety
// gating are separate follow-up slices (#366's own suggested PR breakdown);
// this backend owns only the TLS-layer negotiation and secret derivation.
// ===========================================================================

/// Client: explicit application opt-in to attempt 0-RTT on this connection.
/// Disabled by default — configured before `start` via
/// `setClientEarlyDataIntent`.
pub const ClientEarlyDataIntent = struct {
    enabled: bool = false,
    max_bytes: u32 = 0,
};

/// Why (or whether) 0-RTT was accepted for this connection. Distinct from
/// the boolean `earlyDataAccepted()`/`earlyDataAttempted()` accessors: this
/// is the closed set of reasons a caller can log/meter without ever
/// exposing secret or attacker-controlled values.
pub const EarlyDataDecision = enum {
    not_attempted,
    accepted,
    disabled,
    ticket_not_capable,
    selected_identity_not_zero,
    age_skew,
    transport_incompatible,
    application_incompatible,
    replay_rejected,
    replay_unavailable,
    resource_limited,
};

/// Server: enablement/tolerance for accepting 0-RTT. Disabled by default;
/// configured before `start` via `setServerEarlyDataPolicy`. Resource
/// admission (`EarlyDataDecision.resource_limited`) is a composition-root
/// concern (concurrent-request/byte caps) layered on top of this backend,
/// not decided here.
pub const ServerEarlyDataPolicy = struct {
    enabled: bool = false,
    age_skew_tolerance_ms: u64 = 60_000,
};

pub const EarlyDataReplayDecision = enum { allow, replay, unavailable };

/// Bounded, non-secret metadata about an early-data attempt handed to the
/// anti-replay gate — never the raw ticket, PSK, or binder. #368 owns the
/// actual replay store; this is only the seam.
pub const EarlyDataReplayCandidate = struct {
    selected_identity: u16 = 0,
};

/// Server (#366/#368 seam): injectable anti-replay decision for an
/// otherwise-acceptable 0-RTT attempt. The default (`decideFn == null`)
/// reports `.unavailable`, which rejects only early data and preserves
/// ordinary 1-RTT resumption — production is safe with no replay store
/// configured at all.
pub const EarlyDataReplayGate = struct {
    ctx: *anyopaque = @ptrCast(@constCast(&empty_observer_dummy)),
    decideFn: ?*const fn (*anyopaque, EarlyDataReplayCandidate) EarlyDataReplayDecision = null,

    fn decide(self: EarlyDataReplayGate, candidate: EarlyDataReplayCandidate) EarlyDataReplayDecision {
        const f = self.decideFn orelse return .unavailable;
        return f(self.ctx, candidate);
    }
};

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
    policy: tls_policy.Policy,
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
    /// A configured (client) server name that did not fit the bounded buffer.
    /// Rather than truncate it — which would emit SNI for a different host and
    /// hand the wrong name to the verifier — construction records the overflow
    /// and `start` fails closed before any ClientHello is emitted.
    server_name_overflow: bool = false,
    selected_alpn: [255]u8 = undefined,
    selected_alpn_len: usize = 0,
    selected_alpn_present: bool = false,
    negotiated_version: tls_algorithms.ProtocolVersion = .tls13,
    negotiated_cipher_suite: tls_algorithms.CipherSuite = .tls_aes_128_gcm_sha256,
    negotiated_named_group: tls_algorithms.NamedGroup = .x25519,
    peer_transport_extension: [max_transport_extension_len]u8 = undefined,
    peer_transport_extension_len: usize = 0,
    peer_transport_extension_pending: bool = false,
    key_pair: X25519.KeyPair = undefined,
    key_pair_present: bool = false,
    core: tls_handshake_codec.Core,
    schedule: ?KeySchedule = null,
    resumption_master_secret: crypto_pkg.secrets.FixedSecret(session.max_psk_len) = .{},
    session_ticket_consumer: ?ConfiguredSessionTicketConsumer = null,
    /// The client Finished verify_data the server expects (computed when its
    /// own flight is sent).
    expected_client_verify: [hash_len]u8 = undefined,
    /// Reassembled-but-unparsed handshake bytes per transport epoch; a message
    /// may arrive split across TLS records or QUIC CRYPTO frames.
    initial_input: tls_handshake_codec.Reassembler(max_message_len + 4) = .{},
    handshake_input: tls_handshake_codec.Reassembler(max_message_len + 4) = .{},
    /// Post-handshake messages can be much larger than main-handshake flights,
    /// so their storage is allocated lazily after the declared length is known.
    application_input: PostHandshakeInput = .{},
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
    pending_client_session_id: [32]u8 = undefined,
    pending_client_session_id_len: usize = 0,
    pending_client_share: [X25519.public_length]u8 = undefined,
    pending_client_hello_ready: bool = false,
    /// Client (#362): resumption tickets this backend may offer, owned until
    /// moved out at ClientHello emission or wiped after ServerHello selects
    /// (or does not select) one.
    client_offer_lease: pre_shared_key.ClientOfferLease = .{},
    psk_now_ctx: ?*anyopaque = null,
    psk_now_fn: ?*const fn (*anyopaque) i64 = null,
    /// Client (#362): the ticket state named by the server's
    /// `selected_identity`, retained (moved out of `client_offer_lease.offers`)
    /// until EncryptedExtensions has been checked against its stored
    /// context and its `auth_binding` has been carried forward into
    /// `connection_auth_binding`. Deinitialized once that has happened, on
    /// every path (success, mismatch/fallback-is-not-possible-here-so-
    /// fatal, or teardown).
    selected_client_psk: session.ClientTicketState = .{},
    selected_client_psk_present: bool = false,
    /// Server (#362): the accepted session a successful PSK selection moved
    /// into ownership — see `SelectedServerPsk`. Available to the caller
    /// via `takeSelectedServerPsk` once the resumed handshake completes;
    /// wiped on every fallback/error/teardown path along with the rest of
    /// this connection's PSK state.
    selected_server_psk: SelectedServerPsk = .{},
    selected_server_psk_present: bool = false,
    /// True only once the terminal handshake-completion sequence
    /// (Finished-MAC verification, resumption-master-secret capture, and
    /// the completion event) has fully succeeded — distinct from
    /// `core.handshake_lifecycle == .complete`, which `Core` sets as soon
    /// as a Finished message's *ordering* is accepted, before any of that
    /// has happened. See `clearFailedHandshakeState`.
    handshake_committed: bool = false,
    /// Server (#362): the configured stateful/stateless identity resolver.
    /// `null` means this server never offers PSK resumption.
    psk_resolver: ?pre_shared_key.ServerPskResolver = null,
    resume_compat: ResumeCompatibilityPolicy = .{},
    resumption_decision_observer: ResumptionDecisionObserver = .{},
    offered_psk_modes_seen: bool = false,
    offered_psk_dhe_ke: bool = false,
    /// Server: a captured copy of the just-parsed ClientHello, kept only
    /// long enough (within the synchronous credential-selection path) to
    /// verify the selected identity's binder over the exact received bytes.
    /// Cleared once selection has run, on every path.
    client_hello_psk: ?ClientHelloPskCapture = null,
    /// #362: the authenticated identity binding for this connection, when it
    /// differs from `peerAuthBinding()`'s peer-certificate-chain default —
    /// see `effectiveAuthBinding`.
    connection_auth_binding: ?session.AuthBinding = null,
    /// #362/#365 seam: the application-layer compatibility snapshot this
    /// connection is configured with, compared against a candidate PSK's
    /// stored `application_compat` (server) and used to recheck an offered
    /// ticket (client) — and, symmetrically, stamped into any ticket this
    /// connection itself issues/receives. Copied into owned, bounded
    /// storage by `setApplicationCompat` (not borrowed): it is read again
    /// during *post-handshake* ticket issuance/ingestion, well past when a
    /// merely-handshake-scoped borrow would be safe to assume live.
    application_compat_format_id: u16 = 0,
    application_compat_format_version: u16 = 0,
    /// Sized to `session.hard_max_compat_len` — the actual ceiling the
    /// shared session model allows for an application-compatibility
    /// snapshot (`session.Limits.default.max_application_compat_len` is
    /// 1024 of that 8192-byte hard maximum) — not
    /// `max_transport_extension_len` (512), which bounds an unrelated
    /// QUIC/H3 transport-extension payload and would silently reject a
    /// snapshot the session model itself accepts.
    application_compat_bytes: [session.hard_max_compat_len]u8 = undefined,
    application_compat_len: usize = 0,
    application_compat_present: bool = false,
    /// #362: the most recent successful PSK selection's ticket-age skew
    /// observation (apparent vs. actual elapsed time since issuance), taken
    /// exactly once by `takePskAgeSkew`. Informational only — skew alone
    /// never rejects ordinary 1-RTT resumption; #366 is the intended
    /// consumer (e.g. to gate early-data acceptance).
    last_psk_age_skew: ?pre_shared_key.AgeSkew = null,
    /// Client (#366): explicit opt-in to attempt 0-RTT, configured via
    /// `setClientEarlyDataIntent` before `start`.
    client_early_data_intent: ClientEarlyDataIntent = .{},
    /// Client: whether the ClientHello just sent actually carried the
    /// `early_data` extension (decided by `planEarlyDataAttempt` from the
    /// first surviving PSK offer — #487's wire-index/lease semantics are
    /// never reordered to find an early-capable ticket).
    client_early_data_attempted: bool = false,
    /// Client: the wire index of the identity ServerHello selected (if
    /// any), retained so `onEncryptedExtensions` can check an accepted
    /// `early_data` extension applies only to identity 0.
    selected_client_psk_index: ?u16 = null,
    /// Server: whether the just-parsed ClientHello carried the (empty)
    /// `early_data` extension.
    client_hello_early_data_seen: bool = false,
    /// Server (#366): enablement/tolerance for accepting 0-RTT, configured
    /// via `setServerEarlyDataPolicy` before `start`.
    server_early_data_policy: ServerEarlyDataPolicy = .{},
    /// Server (#366/#368 seam): injectable anti-replay decision, configured
    /// via `setEarlyDataReplayGate` before `start`. Defaults to
    /// `.unavailable`, which rejects only early data.
    early_data_replay_gate: EarlyDataReplayGate = .{},
    /// Whether 0-RTT was accepted for this connection — mirrors
    /// `early_data_decision == .accepted`, kept separately for cheap
    /// boolean access from record/QUIC carriers.
    early_data_accepted: bool = false,
    /// Server: authoritative reason `decideServerEarlyData` reached for the
    /// selected candidate. Client: only ever observes `.accepted` (RFC 8446
    /// does not tell a client *why* the server omitted the extension), so
    /// this stays `.not_attempted` on the client except when accepted.
    early_data_decision: EarlyDataDecision = .not_attempted,

    const Slice = struct { start: usize, len: usize };
    const PendingStage = enum { server_select, server_sign, client_select, client_sign, peer_verify };
    const PskSelected = struct { index: usize, psk: [hash_len]u8, early_data: EarlyDataDecision = .not_attempted };
    pub const ResumptionDecision = enum { accepted, miss, incompatible, full_handshake, fatal };

    pub const ResumptionDecisionObserver = struct {
        ctx: *anyopaque = @ptrCast(@constCast(&empty_observer_dummy)),
        onDecisionFn: ?*const fn (*anyopaque, ResumptionDecision) void = null,

        pub fn notify(self: ResumptionDecisionObserver, decision: ResumptionDecision) void {
            if (self.onDecisionFn) |f| f(self.ctx, decision);
        }
    };

    /// Server (#362): the accepted `ServerRecoverableState` a successful PSK
    /// selection moves into backend ownership — not only the derived PSK
    /// bytes — so #365/#366 can consume the authenticated selection
    /// (early-data policy, compatibility metadata, ...) without resolving
    /// the bearer identity a second time.
    const SelectedServerPsk = struct {
        index: u16 = 0,
        state: session.ServerRecoverableState = .{},

        fn deinit(self: *SelectedServerPsk) void {
            self.state.deinit();
            self.index = 0;
        }
    };

    /// Reassembler capacity is `max_message_len + 4` (see `initial_input`),
    /// so the capture buffer matches that bound exactly.
    pub const ClientHelloPskCapture = struct {
        message: [max_message_len + handshake_header_len]u8 = undefined,
        message_len: usize = 0,
        /// Offset of the `pre_shared_key` extension's `extension_data`
        /// within `message`.
        ext_data_offset: usize = 0,
        ext_data_len: usize = 0,

        /// Zeroizes the captured bytes in place. Exposed (`pub`) so its
        /// zeroing behavior can be proven directly, on a plain value, in
        /// isolation from the `?ClientHelloPskCapture = null` transition
        /// `clearClientHelloPsk` performs right after calling this —
        /// reading the backend's own field after that transition would
        /// observe whatever Zig's debug-safety instrumentation does to an
        /// invalidated optional's payload, not necessarily this method's
        /// effect.
        pub fn wipe(self: *ClientHelloPskCapture) void {
            crypto.secureZero(u8, self.message[0..self.message_len]);
            self.message_len = 0;
        }
    };

    pub const SessionTicketConsumer = struct {
        ctx: *anyopaque,
        nowUnixMsFn: *const fn (*anyopaque) i64,
        onTicketFn: *const fn (*anyopaque, *const session.ClientTicketState) void,
    };

    const ConfiguredSessionTicketConsumer = struct {
        allocator: std.mem.Allocator,
        limits: session.Limits,
        consumer: SessionTicketConsumer,
    };

    pub const EmitNewSessionTicketParams = struct {
        ticket_lifetime: u32,
        ticket_age_add: u32,
        ticket_nonce: []const u8,
        opaque_ticket: []const u8,
        max_early_data_size: ?u32 = null,
        issued_at_unix_ms: i64,
    };

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
        return initClientConfigured(entropy, trust, defaultConfigForTransport(profile), .{});
    }

    pub fn initClientConfigured(entropy: Entropy, trust: Trust, config: BackendConfig, options: ClientOptions) Tls13Backend {
        var self: Tls13Backend = .{
            .role = .client,
            .profile = config.transport,
            .policy = config.policy,
            .entropy = entropy,
            .trust = trust,
            .auth_policy = policyFromTrust(trust),
            .core = tls_handshake_codec.Core.init(.client),
        };
        self.applyClientOptions(options);
        return self;
    }

    /// Client construction with the built-in fixed trust policy plus explicit
    /// client options such as intended SNI.
    pub fn initClientWithOptions(entropy: Entropy, trust: Trust, profile: TransportProfile, options: ClientOptions) Tls13Backend {
        return initClientConfigured(entropy, trust, defaultConfigForTransport(profile), options);
    }

    fn applyClientOptions(self: *Tls13Backend, options: ClientOptions) void {
        if (options.server_name) |name| {
            // Invalid configured SNI is a caller error. Record it and reject at
            // `start` rather than emitting malformed or truncated host_name.
            if (dns_name.validateHostName(name)) |_| {
                @memcpy(self.server_name[0..name.len], name);
                self.server_name_len = name.len;
                self.server_name_present = true;
            } else |_| {
                self.server_name_overflow = true;
            }
        }
    }

    /// Allocation-free. The returned backend owns its copy of `identity` and
    /// securely clears the private signing key in `deinit`. The fixed identity
    /// is served to the engine through the production `CredentialProvider`
    /// contract, identical to an external provider.
    pub fn initServer(entropy: Entropy, identity: Identity, profile: TransportProfile) Tls13Backend {
        return initServerConfigured(entropy, identity, defaultConfigForTransport(profile));
    }

    pub fn initServerConfigured(entropy: Entropy, identity: Identity, config: BackendConfig) Tls13Backend {
        return .{
            .role = .server,
            .profile = config.transport,
            .policy = config.policy,
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
        return initServerWithProviderConfigured(entropy, provider, defaultConfigForTransport(profile));
    }

    pub fn initServerWithProviderConfigured(entropy: Entropy, provider: CredentialProvider, config: BackendConfig) Tls13Backend {
        return .{
            .role = .server,
            .profile = config.transport,
            .policy = config.policy,
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
        return initClientWithVerifierConfigured(entropy, verifier, defaultConfigForTransport(profile), options);
    }

    pub fn initClientWithVerifierConfigured(entropy: Entropy, verifier: PeerVerifier, config: BackendConfig, options: ClientOptions) Tls13Backend {
        var self: Tls13Backend = .{
            .role = .client,
            .profile = config.transport,
            .policy = config.policy,
            .entropy = entropy,
            .external_verifier = verifier,
            .auth_policy = options.policy,
            .core = tls_handshake_codec.Core.init(.client),
        };
        self.applyClientOptions(options);
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
        // The policy handed to the client-certificate verifier. `required`
        // demands the client present a certificate. `optional` permits an
        // *absent* certificate (an empty Certificate, handled in `onCertificate`)
        // — but a certificate that IS presented must still verify, so neither
        // mode allows an unverified peer. A `.not_checked` verdict on a presented
        // chain is rejected in `applyPeerVerdict` for both modes.
        self.auth_policy = switch (mode) {
            .disabled => self.auth_policy,
            .required => .{ .require_peer_authentication = true },
            .optional => .{},
        };
    }

    /// Client: supply the credential provider for the client's own certificate,
    /// used to authenticate when the server sends a CertificateRequest. Must be
    /// called before `start`.
    pub fn setLocalCredentialProvider(self: *Tls13Backend, provider: CredentialProvider) void {
        std.debug.assert(self.role == .client);
        self.external_provider = provider;
    }

    /// Client (#362): configure the resumption tickets to offer at the next
    /// ClientHello and the clock used to check their expiry and compute
    /// their obfuscated age. Takes ownership of `offers` (moved out; the
    /// caller's set is left empty) only on success. Must be called before
    /// `start` — replacing the offer set after ClientHello emission would
    /// desync `onServerHello`'s `selected_identity` from the array it
    /// actually indexes.
    pub fn setClientPskOffers(
        self: *Tls13Backend,
        offers: *pre_shared_key.ClientPskOfferSet,
        now_ctx: *anyopaque,
        nowUnixMsFn: *const fn (*anyopaque) i64,
    ) HandshakeError!void {
        if (self.role != .client) return error.InvalidHandshakeState;
        if (self.core.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        self.clearClientPskOffersAborted();
        self.client_offer_lease.offers.moveFrom(offers);
        self.psk_now_ctx = now_ctx;
        self.psk_now_fn = nowUnixMsFn;
    }

    /// Client (#487): configure cache-owned offers with their single-use
    /// lease. The backend owns exactly-once completion from this point.
    pub fn setClientPskOfferLease(
        self: *Tls13Backend,
        lease: *pre_shared_key.ClientOfferLease,
        now_ctx: *anyopaque,
        nowUnixMsFn: *const fn (*anyopaque) i64,
    ) HandshakeError!void {
        if (self.role != .client) return error.InvalidHandshakeState;
        if (self.core.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        self.clearClientPskOffersAborted();
        self.client_offer_lease = lease.*;
        lease.* = .{};
        self.psk_now_ctx = now_ctx;
        self.psk_now_fn = nowUnixMsFn;
    }

    /// Server (#362): configure the stateful/stateless identity resolver
    /// used to select and verify an offered resumption PSK. Without one, the
    /// server never offers or accepts PSK resumption (full handshake only).
    /// Must be called before `start` — swapping the resolver mid-handshake
    /// (e.g. while an async credential selection is pending) would change
    /// the selection policy applied to an already-captured ClientHello.
    pub fn setServerPskResolver(self: *Tls13Backend, resolver: pre_shared_key.ServerPskResolver) HandshakeError!void {
        if (self.role != .server) return error.InvalidHandshakeState;
        if (self.core.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        self.psk_resolver = resolver;
    }

    pub const SnapshotResumePolicy = enum { exact, ignore };

    pub const ResumeCompatibilityPolicy = struct {
        transport: SnapshotResumePolicy = .exact,
        application: SnapshotResumePolicy = .exact,
    };

    pub fn setResumeCompatibilityPolicy(self: *Tls13Backend, policy: ResumeCompatibilityPolicy) HandshakeError!void {
        if (self.core.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        self.resume_compat = policy;
    }

    pub fn setResumptionDecisionObserver(self: *Tls13Backend, observer: ResumptionDecisionObserver) HandshakeError!void {
        if (self.core.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        self.resumption_decision_observer = observer;
    }

    /// Client (#366): opt in to attempting 0-RTT on this connection. Must
    /// be called before `start`; disabled (the default) means the client
    /// never emits `early_data` even when an early-capable ticket is
    /// offered.
    pub fn setClientEarlyDataIntent(self: *Tls13Backend, intent: ClientEarlyDataIntent) HandshakeError!void {
        if (self.role != .client) return error.InvalidHandshakeState;
        if (self.core.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        self.client_early_data_intent = intent;
    }

    /// Server (#366): configure whether/how tolerantly this connection
    /// accepts 0-RTT. Must be called before `start`; disabled (the
    /// default) means this connection never accepts early data even from
    /// an early-capable ticket.
    pub fn setServerEarlyDataPolicy(self: *Tls13Backend, policy: ServerEarlyDataPolicy) HandshakeError!void {
        if (self.role != .server) return error.InvalidHandshakeState;
        if (self.core.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        self.server_early_data_policy = policy;
    }

    /// Server (#366/#368 seam): configure the anti-replay decision hook
    /// consulted for an otherwise-acceptable 0-RTT attempt. Must be called
    /// before `start`; the default gate reports `.unavailable`.
    pub fn setEarlyDataReplayGate(self: *Tls13Backend, gate: EarlyDataReplayGate) HandshakeError!void {
        if (self.role != .server) return error.InvalidHandshakeState;
        if (self.core.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        self.early_data_replay_gate = gate;
    }

    /// Client: whether the ClientHello just sent actually attempted 0-RTT.
    /// Independent of acceptance — see `earlyDataAccepted`.
    pub fn earlyDataAttempted(self: *const Tls13Backend) bool {
        return self.client_early_data_attempted;
    }

    /// Whether 0-RTT was accepted for this connection.
    pub fn earlyDataAccepted(self: *const Tls13Backend) bool {
        return self.early_data_accepted;
    }

    /// The authoritative server-side reason 0-RTT was or was not accepted
    /// (see `EarlyDataDecision`). On the client this only ever reaches
    /// `.accepted`; a client-observed rejection carries no reason
    /// (RFC 8446 EncryptedExtensions simply omits the extension).
    pub fn earlyDataDecision(self: *const Tls13Backend) EarlyDataDecision {
        return self.early_data_decision;
    }

    /// #362/#365: configure this connection's application-layer
    /// compatibility snapshot (e.g. HTTP/3 settings), compared against a
    /// candidate PSK's stored value on the server and used to recheck an
    /// offered ticket on the client. Copies `blob.bytes` into owned,
    /// bounded storage — the caller's slice need not outlive this call —
    /// because this value is read again during post-handshake ticket
    /// issuance/ingestion, not only during the handshake itself. Must be
    /// called before `start`, for the same reason as `setServerPskResolver`.
    pub fn setApplicationCompat(self: *Tls13Backend, blob: ?new_session_ticket.CompatBlob) HandshakeError!void {
        if (self.core.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        if (blob) |b| {
            if (b.bytes.len > self.application_compat_bytes.len) return error.TransportBufferOverflow;
            self.application_compat_format_id = b.format_id;
            self.application_compat_format_version = b.format_version;
            @memcpy(self.application_compat_bytes[0..b.bytes.len], b.bytes);
            self.application_compat_len = b.bytes.len;
            self.application_compat_present = true;
        } else {
            self.application_compat_present = false;
            self.application_compat_len = 0;
        }
    }

    /// The owned `application_compat` snapshot configured via
    /// `setApplicationCompat`, in the wire-neutral `CompatBlob` shape both
    /// `resumptionContext()` (ticket issuance/ingestion) and
    /// `candidateApplicationCompat()` (PSK compatibility evaluation) need.
    pub fn ownedApplicationCompat(self: *const Tls13Backend) ?new_session_ticket.CompatBlob {
        if (!self.application_compat_present) return null;
        return .{
            .format_id = self.application_compat_format_id,
            .format_version = self.application_compat_format_version,
            .bytes = self.application_compat_bytes[0..self.application_compat_len],
        };
    }

    /// #362: takes (clears) the most recent successful PSK selection's
    /// ticket-age skew observation, if any — a one-shot accessor for #366.
    pub fn takePskAgeSkew(self: *Tls13Backend) ?pre_shared_key.AgeSkew {
        defer self.last_psk_age_skew = null;
        return self.last_psk_age_skew;
    }

    /// Server (#362): moves the session accepted by the most recent
    /// successful PSK selection into `out` (which must be zero-valued or a
    /// previously-initialized, live value — never `undefined`), returning
    /// its selected identity index. A one-shot accessor for #365/#366:
    /// returns `null` (leaving `out` untouched) when no PSK has been
    /// selected on this connection, once already taken, or — critically —
    /// before the resumed handshake has actually `handshake_committed`.
    ///
    /// The binder succeeding only proves the *client* authenticated; the
    /// server's own handshake is not authenticated until the client's
    /// Finished verifies (`onClientFinished`). Handing ownership of this
    /// secret-bearing session out any earlier would let a caller retain it
    /// past a subsequent bad-Finished failure — `clearFailedHandshakeState`
    /// can only wipe state the backend still owns.
    pub fn takeSelectedServerPsk(self: *Tls13Backend, out: *session.ServerRecoverableState) ?u16 {
        if (!self.handshake_committed or !self.selected_server_psk_present) return null;
        out.moveFrom(&self.selected_server_psk.state);
        self.selected_server_psk_present = false;
        const index = self.selected_server_psk.index;
        self.selected_server_psk.index = 0;
        return index;
    }

    fn mutableClientPskOffers(self: *Tls13Backend) *pre_shared_key.ClientPskOfferSet {
        return &self.client_offer_lease.offers;
    }

    fn constClientPskOffers(self: *const Tls13Backend) *const pre_shared_key.ClientPskOfferSet {
        return &self.client_offer_lease.offers;
    }

    fn clearClientPskOffersAborted(self: *Tls13Backend) void {
        self.client_offer_lease.deinit();
    }

    pub fn setSessionTicketConsumer(
        self: *Tls13Backend,
        allocator: std.mem.Allocator,
        limits: session.Limits,
        consumer: SessionTicketConsumer,
    ) HandshakeError!void {
        if (self.role != .client) return error.InvalidHandshakeState;
        if (self.core.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        limits.validate() catch return error.InvalidTransportProfile;
        try self.application_input.setAllocator(allocator);
        self.session_ticket_consumer = .{
            .allocator = allocator,
            .limits = limits,
            .consumer = consumer,
        };
    }

    pub fn setPostHandshakeAllocator(self: *Tls13Backend, allocator: std.mem.Allocator) HandshakeError!void {
        if (self.role != .client) return error.InvalidHandshakeState;
        if (self.core.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        if (self.application_input.allocator != null) return;
        try self.application_input.setAllocator(allocator);
    }

    pub fn backend(self: *Tls13Backend) TlsBackend {
        return .{
            .ptr = self,
            .startFn = startImpl,
            .receiveFn = receiveImpl,
            .deinitFn = deinitImpl,
            .authPendingFn = authPendingImpl,
            .resumeFn = resumeImpl,
            .setPostHandshakeAllocatorFn = setPostHandshakeAllocatorImpl,
        };
    }

    fn authPendingImpl(ptr: *anyopaque) bool {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return self.authPending();
    }

    fn resumeImpl(ptr: *anyopaque, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return self.resumeAuth(sink);
    }

    fn setPostHandshakeAllocatorImpl(ptr: *anyopaque, allocator: std.mem.Allocator) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return self.setPostHandshakeAllocator(allocator);
    }

    pub fn alpn(self: *const Tls13Backend) []const u8 {
        return self.policy.firstAlpn();
    }

    fn setSelectedAlpn(self: *Tls13Backend, name: []const u8) void {
        std.debug.assert(name.len <= self.selected_alpn.len);
        if (self.selected_alpn_len > 0) @memset(self.selected_alpn[0..self.selected_alpn_len], 0);
        @memcpy(self.selected_alpn[0..name.len], name);
        self.selected_alpn_len = name.len;
        self.selected_alpn_present = true;
    }

    pub fn selectedAlpn(self: *const Tls13Backend) ?[]const u8 {
        return if (self.selected_alpn_present) self.selected_alpn[0..self.selected_alpn_len] else null;
    }

    fn negotiatedVersionCode(self: *const Tls13Backend) u16 {
        return @intFromEnum(self.negotiated_version);
    }

    fn negotiatedCipherCode(self: *const Tls13Backend) u16 {
        return @intFromEnum(self.negotiated_cipher_suite);
    }

    fn negotiatedGroupCode(self: *const Tls13Backend) u16 {
        return @intFromEnum(self.negotiated_named_group);
    }

    pub fn setExtensionProfile(self: *Tls13Backend, extension_type: u16, local: []const u8) HandshakeError!void {
        const profile: TransportProfile = .{ .extension = .{
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
        crypto.secureZero(u8, &self.pending_client_session_id);
        self.pending_client_session_id_len = 0;
        crypto.secureZero(u8, &self.pending_client_share);
        self.pending_client_hello_ready = false;
        if (self.schedule) |*schedule| schedule.wipe();
        self.schedule = null;
        self.resumption_master_secret.deinit();
        self.session_ticket_consumer = null;
        self.clearClientPskOffersAborted();
        self.psk_now_ctx = null;
        self.psk_now_fn = null;
        self.psk_resolver = null;
        self.connection_auth_binding = null;
        crypto.secureZero(u8, &self.application_compat_bytes);
        self.application_compat_present = false;
        self.application_compat_len = 0;
        self.last_psk_age_skew = null;
        self.client_early_data_intent = .{};
        self.client_early_data_attempted = false;
        self.selected_client_psk_index = null;
        self.client_hello_early_data_seen = false;
        self.server_early_data_policy = .{};
        self.early_data_replay_gate = .{};
        self.early_data_accepted = false;
        self.early_data_decision = .not_attempted;
        self.selected_client_psk.deinit();
        self.selected_client_psk_present = false;
        self.selected_server_psk.deinit();
        self.selected_server_psk_present = false;
        self.handshake_committed = false;
        self.clearClientHelloPsk();
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
        crypto.secureZero(u8, &self.selected_alpn);
        self.selected_alpn_len = 0;
        self.selected_alpn_present = false;
        self.negotiated_version = .tls13;
        self.negotiated_cipher_suite = .tls_aes_128_gcm_sha256;
        self.negotiated_named_group = .x25519;
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
        self.application_input.deinit();
        self.initial_input = .{};
        self.handshake_input = .{};
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

    /// Clears the captured ClientHello PSK state (#362): on every path once
    /// selection has run (success, fallback, error, or no PSK offered at
    /// all). The framed ClientHello bytes are transcript-public wire data,
    /// not secret, but this still wipes the whole capture (rather than only
    /// nulling the optional) so no scratch copy of a peer-supplied opaque
    /// ticket identity lingers in backend storage past the connection that
    /// captured it.
    fn clearClientHelloPsk(self: *Tls13Backend) void {
        if (self.client_hello_psk) |*capture| {
            capture.wipe();
        }
        self.client_hello_psk = null;
        self.offered_psk_modes_seen = false;
        self.offered_psk_dhe_ke = false;
    }

    /// Wipes owned PSK/schedule/RMS state on any handshake-phase failure —
    /// installed via `errdefer` at the `receiveImpl`/`startImpl`/
    /// `resumeAuth` call boundary (not only inside the individual message
    /// handlers), so a terminal failure that occurs before or between
    /// handler dispatch (message-order rejection, wrong transport epoch, a
    /// malformed frame, an async operation's own failure) cannot leave this
    /// state resident in a backend that will not be torn down until some
    /// later, unrelated `deinit()`.
    ///
    /// Gated on `handshake_committed`, **not** `core.handshake_lifecycle ==
    /// .complete`: `Core` transitions to `.complete` as soon as the
    /// Finished message's *ordering* is accepted — before this backend has
    /// verified its MAC (`onClientFinished`/`onServerFinished`), captured
    /// the resumption master secret, or emitted the completion event. A bad
    /// Finished, or any failure in that terminal sequence, would otherwise
    /// see `.complete` and skip cleanup entirely, leaving
    /// `selected_server_psk`/`last_psk_age_skew`/the schedule/the RMS
    /// exposed on a backend that never actually finished authenticating.
    /// `handshake_committed` is set `true` only once every one of those
    /// terminal fallible steps has actually succeeded (see
    /// `completeClientHandshake` and `onClientFinished`), so this remains a
    /// no-op only for a *genuinely* committed handshake — deliberately,
    /// since `selected_server_psk`/`last_psk_age_skew` are meant to outlive
    /// a real success for #365/#366's one-shot accessors, and an unrelated
    /// post-handshake failure (a malformed `NewSessionTicket`, say) must
    /// not destroy them before the caller has had a chance to read them.
    fn clearFailedHandshakeState(self: *Tls13Backend) void {
        if (self.handshake_committed) return;
        self.clearClientPskOffersAborted();
        self.selected_client_psk.deinit();
        self.selected_client_psk_present = false;
        self.selected_server_psk.deinit();
        self.selected_server_psk_present = false;
        self.last_psk_age_skew = null;
        // #366: a failed handshake must never leave a stale 0-RTT
        // acceptance bit visible to a carrier.
        self.client_early_data_attempted = false;
        self.selected_client_psk_index = null;
        self.client_hello_early_data_seen = false;
        self.early_data_accepted = false;
        self.early_data_decision = .not_attempted;
        self.clearClientHelloPsk();
        if (self.schedule) |*schedule| schedule.wipe();
        self.schedule = null;
        self.resumption_master_secret.deinit();
        self.core.psk_authenticated = false;
        // `Core` may already have (incorrectly, from this backend's
        // perspective) advanced to `.complete` on message ordering alone;
        // correct that externally-visible state to match reality.
        if (self.core.handshake_lifecycle != .idle) self.core.handshake_lifecycle = .failed;
    }

    fn startImpl(ptr: *anyopaque, role: Role, _: void, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        errdefer self.clearFailedHandshakeState();
        // The driver's role comes from Handshake.initClient/initServer and must
        // match how this backend was constructed; a mismatch is a wiring bug.
        std.debug.assert(role == self.role);
        std.debug.assert(self.core.handshake_lifecycle == .idle);
        try self.profile.validate();
        try self.validateNativePolicy();
        // A configured client server name that overflowed the bound is a caller
        // configuration error; fail closed before any lifecycle or transcript
        // advance rather than emitting SNI for a truncated (wrong) host.
        if (self.server_name_overflow) return error.InvalidHandshakeState;
        if (self.role == .client) {
            const base_len = try self.clientHelloEncodedLen();
            if (base_len > max_message_len) return error.InvalidTransportProfile;
            // #362: decide which offered tickets fit — and in what wire
            // order — before any lifecycle/key-pair state is mutated below,
            // so a too-large offer never partially advances the handshake.
            _ = try self.planPskOffer(base_len);
            // #366: decide whether to attempt 0-RTT from the (now final)
            // first surviving offer, after offer planning but still before
            // any lifecycle/key-pair state is mutated.
            self.planEarlyDataAttempt();
        }
        self.core.start() catch |err| return mapCoreError(err);
        switch (self.role) {
            .client => {
                try self.sendClientHello(sink);
            },
            .server => {},
        }
    }

    fn validateNativePolicy(self: *const Tls13Backend) HandshakeError!void {
        switch (self.policy.transport_mode) {
            .record => if (self.profile != .record) return error.InvalidTransportProfile,
            .quic => if (self.profile != .extension) return error.InvalidTransportProfile,
        }
        if (self.policy.protocol_versions.len == 0 or
            self.policy.cipher_suites.len == 0 or
            self.policy.named_groups.len == 0 or
            self.policy.signature_schemes.len == 0)
            return error.InvalidTransportProfile;

        if (self.policy.protocol_versions.len > std.math.maxInt(u8) / 2) return error.InvalidTransportProfile;
        if (self.policy.cipher_suites.len > std.math.maxInt(u16) / 2) return error.InvalidTransportProfile;
        if (self.policy.named_groups.len > std.math.maxInt(u16) / 2) return error.InvalidTransportProfile;
        if (self.policy.signature_schemes.len > std.math.maxInt(u16) / 2) return error.InvalidTransportProfile;

        for (self.policy.protocol_versions, 0..) |version, i| {
            if (version != .tls13) return error.InvalidTransportProfile;
            if (containsEnum(tls_algorithms.ProtocolVersion, self.policy.protocol_versions[0..i], version)) return error.InvalidTransportProfile;
        }
        for (self.policy.cipher_suites, 0..) |cipher, i| {
            if (cipher != .tls_aes_128_gcm_sha256) return error.InvalidTransportProfile;
            if (containsEnum(tls_algorithms.CipherSuite, self.policy.cipher_suites[0..i], cipher)) return error.InvalidTransportProfile;
        }
        for (self.policy.named_groups, 0..) |group, i| {
            if (group != .x25519) return error.InvalidTransportProfile;
            if (containsEnum(tls_algorithms.NamedGroup, self.policy.named_groups[0..i], group)) return error.InvalidTransportProfile;
        }
        for (self.policy.signature_schemes, 0..) |scheme, i| {
            switch (scheme) {
                .ed25519, .ecdsa_secp256r1_sha256 => {},
                else => return error.InvalidTransportProfile,
            }
            if (containsEnum(tls_algorithms.SignatureScheme, self.policy.signature_schemes[0..i], scheme)) return error.InvalidTransportProfile;
        }
        if (self.policy.alpn_protocols.len == 0 and !self.policy.allow_absent_alpn) return error.InvalidTransportProfile;
        var alpn_total: usize = 0;
        for (self.policy.alpn_protocols, 0..) |protocol, i| {
            const name = protocol.bytes;
            if (name.len == 0 or name.len > std.math.maxInt(u8)) return error.InvalidTransportProfile;
            alpn_total = checkedAdd(alpn_total, 1 + name.len) catch return error.InvalidTransportProfile;
            if (alpn_total > std.math.maxInt(u16) or alpn_total + 6 > max_message_len) return error.InvalidTransportProfile;
            for (self.policy.alpn_protocols[0..i]) |prior| {
                if (prior.eql(protocol)) return error.InvalidTransportProfile;
            }
        }
        _ = try self.maxServerFlightPreflightLen();
    }

    fn containsEnum(comptime T: type, haystack: []const T, needle: T) bool {
        for (haystack) |item| {
            if (item == needle) return true;
        }
        return false;
    }

    fn maxServerFlightPreflightLen(self: *const Tls13Backend) HandshakeError!usize {
        var len: usize = 0;
        len = try checkedAdd(len, 1 + 3 + 2); // EncryptedExtensions header + extension vector length
        if (self.policy.alpn_protocols.len > 0) {
            len = try checkedAdd(len, try self.policyAlpnOfferEncodedLen());
        }
        if (self.profile.localExtension()) |payload| {
            len = try checkedAdd(len, 2 + 2 + payload.len);
        }
        if (self.client_auth != .disabled) {
            len = try checkedAdd(len, 1 + 3 + 1 + 2); // CertificateRequest header, empty context, extensions vector
            len = try checkedAdd(len, 2 + 2 + 2 + 2 * self.policy.signature_schemes.len);
        }
        if (len > max_message_len) return error.InvalidTransportProfile;
        return len;
    }

    fn receiveImpl(ptr: *anyopaque, level: EncryptionLevel, bytes: []const u8, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        // Covers every terminal failure below — including those raised by
        // `drainInput` itself (message ordering, transport epoch, framing)
        // before any per-message handler ever runs — not only the ones the
        // individual handlers already guard locally. See
        // `clearFailedHandshakeState` for why this is a no-op once the
        // handshake has completed.
        errdefer self.clearFailedHandshakeState();
        switch (level) {
            .zero_rtt => return error.UnexpectedTransportEpoch,
            .application => {
                if (self.core.handshake_lifecycle != .complete) return error.UnexpectedTransportEpoch;
                if (self.pending_op != null) return;
                return self.receivePostHandshake(bytes, sink);
            },
            .initial, .handshake => {},
        }
        if (self.core.handshake_lifecycle == .complete) {
            return error.UnexpectedHandshakeMessage;
        }
        if (self.rejectPeerHandshakeWhileClientAuthPending(level, bytes.len)) {
            self.cancelPendingAuth();
            return error.UnexpectedHandshakeMessage;
        }
        const input = switch (level) {
            .initial => &self.initial_input,
            .handshake => &self.handshake_input,
            .zero_rtt, .application => unreachable,
        };
        input.append(bytes) catch |err| return mapCoreError(err);
        // Never begin dispatching while an authentication operation is parked:
        // buffer the freshly received bytes and wait for `resumeAuth`. Without
        // this, a Finished arriving in a separate transport read while a peer
        // verification is still pending would be processed here — completing the
        // handshake before the verdict resolves.
        if (self.pending_op != null) return;
        try self.drainInput(input, level, sink);
    }

    fn receivePostHandshake(self: *Tls13Backend, bytes: []const u8, sink: *EventSink) HandshakeError!void {
        var rest = bytes;
        while (rest.len > 0) {
            const consumed = try self.application_input.append(rest);
            rest = rest[consumed..];
            try self.drainInput(&self.application_input, .application, sink);
            if (consumed == 0) break;
            if (self.pending_op != null) break;
        }
    }

    /// Consume whole handshake messages from a reassembly buffer, dispatching
    /// each. Stops early when an async authentication operation parks (so the
    /// suspend point is never crossed) or when the handshake completes or fails.
    /// Shared by `receiveImpl` and `resumeAuth`, so buffered messages behind a
    /// suspend point are drained automatically once the operation resolves.
    fn drainInput(
        self: *Tls13Backend,
        input: anytype,
        level: EncryptionLevel,
        sink: *EventSink,
    ) HandshakeError!void {
        while (input.peek() catch |err| return mapCoreError(err)) |message| {
            // Defensive: never dispatch a message while an operation is parked,
            // even if this loop is somehow re-entered mid-suspend.
            if (self.pending_op != null) break;
            if (level != try expectedLevel(message.kind)) return error.UnexpectedTransportEpoch;
            if (level == .handshake and message.kind == .finished and input.len != message.raw.len) {
                return error.UnexpectedHandshakeMessage;
            }
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
            .encrypted_extensions,
            .certificate_request,
            .certificate,
            .certificate_verify,
            .finished,
            => .handshake,
            .new_session_ticket => .application,
            else => error.UnexpectedHandshakeMessage,
        };
    }

    fn rejectPeerHandshakeWhileClientAuthPending(self: *const Tls13Backend, level: EncryptionLevel, byte_len: usize) bool {
        if (byte_len == 0 or self.pending_op == null or self.role != .client or level == .application) return false;
        return self.pending_stage == .client_select or self.pending_stage == .client_sign;
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
            error.MissingExtension => error.MissingExtension,
            error.UnsupportedExtension => error.UnsupportedExtension,
            error.AlpnMismatch => error.AlpnMismatch,
            error.UnsupportedCertificate => error.UnsupportedCertificate,
            error.CertificateInvalid => error.CertificateInvalid,
            error.SecretExportFailed => error.SecretExportFailed,
            error.InvalidHandshakeState => error.InvalidHandshakeState,
            error.TicketTooLarge => error.TicketTooLarge,
            // Surfaced only by this backend's credential/verification path, not
            // the codec core, but they are part of the shared error set.
            error.NoApplicableCredential => error.NoApplicableCredential,
            error.CredentialProviderFailed => error.CredentialProviderFailed,
            error.ClientCertificateRequired => error.ClientCertificateRequired,
            error.DecryptError => error.DecryptError,
        };
    }

    fn mapNegotiationError(err: tls_negotiation.Error) HandshakeError {
        return switch (err) {
            error.MalformedHandshake,
            error.MalformedExtension,
            error.MissingCipherSuites,
            error.OfferVectorTooLarge,
            error.TooManyExtensions,
            => error.MalformedHandshake,
            error.HandshakeBufferOverflow => error.HandshakeBufferOverflow,
            error.MissingSupportedVersions,
            error.MissingExtension,
            => error.MissingExtension,
            error.UnsupportedProtocolVersion,
            error.NoMutualCipherSuite,
            error.NoMutualNamedGroup,
            error.MissingKeyShare,
            error.NoMutualSignatureScheme,
            error.IllegalParameter,
            error.DuplicateExtension,
            => error.IllegalParameter,
            error.NoMutualAlpn => error.AlpnMismatch,
            error.MissingServerName => error.MissingExtension,
            error.IncompleteHandshake,
            error.MessageTooLarge,
            => error.MalformedHandshake,
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
            try self.onNewSessionTicket(body);
            return;
        }

        // Message ordering has already been enforced by `core.acceptReceived`.
        // Dispatch the shared TLS semantics; transport extension contents stay
        // opaque and are consumed by the owning adapter.
        switch (kind) {
            .client_hello => try self.onClientHello(message.raw, sink),
            .server_hello => try self.onServerHello(body, sink),
            .encrypted_extensions => try self.onEncryptedExtensions(body, sink),
            .certificate_request => try self.onCertificateRequest(body),
            .certificate => try self.onCertificate(body),
            .certificate_verify => try self.onCertificateVerify(transcript_before, body, sink),
            .finished => switch (self.role) {
                .client => try self.onServerFinished(transcript_before, body, sink),
                .server => try self.onClientFinished(transcript_before, body, sink),
            },
            else => return error.UnexpectedHandshakeMessage,
        }
    }

    fn onNewSessionTicket(self: *Tls13Backend, body: []const u8) HandshakeError!void {
        const parsed = new_session_ticket.decode(body) catch |err| return mapTicketDecodeError(err);
        const configured = self.session_ticket_consumer orelse return;
        if (self.resumption_master_secret.slice().len == 0) return error.InvalidHandshakeState;
        const received_at = configured.consumer.nowUnixMsFn(configured.consumer.ctx);
        var state = new_session_ticket.buildClientTicketState(
            configured.allocator,
            parsed,
            self.resumptionContext(),
            self.resumption_master_secret.slice(),
            received_at,
            configured.limits,
        ) catch |err| return mapTicketBuildClientError(err);
        if (state) |*ticket| {
            defer ticket.deinit();
            configured.consumer.onTicketFn(configured.consumer.ctx, ticket);
        }
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

        // Sized for the worst case, not the common one: maximum ALPN (255,
        // bounded by `TransportProfile.validate`), maximum SNI
        // (`max_server_name_len` = 256), and a maximum transport extension
        // (`max_transport_extension_len` = 512) together encode to roughly
        // 1.15 KiB — a 1024-byte buffer could overflow for a legitimate
        // configuration, and by the time the writer reported that, `start` had
        // already advanced the core and generated/stored the key pair. Using
        // the same bound as every other flight buffer makes that structurally
        // impossible rather than requiring a separate exact-size preflight.
        var buf: [max_message_len]u8 = undefined;
        // #362: this buffer carries opaque bearer ticket identities and
        // their binders once patched in below — wiped after the sink and
        // transcript have their own copies, regardless of how the function
        // returns.
        defer crypto.secureZero(u8, &buf);
        var w = Writer{ .buf = &buf };
        try w.u8_(@intFromEnum(MessageType.client_hello));
        const message_len = try w.reserve(3);
        try w.u16_(legacy_version);
        try w.bytes(&self.entropy.hello_random);
        try w.u8_(0); // legacy_session_id: this profile does not use compatibility mode
        try w.u16_(@intCast(2 * self.policy.cipher_suites.len)); // cipher_suites
        for (self.policy.cipher_suites) |cipher_suite| {
            try w.u16_(@intFromEnum(cipher_suite));
        }
        try w.u8_(1); // legacy_compression_methods
        try w.u8_(0);

        const extensions_len = try w.reserve(2);
        try w.u16_(ext_supported_versions);
        try w.u16_(@intCast(1 + 2 * self.policy.protocol_versions.len));
        try w.u8_(@intCast(2 * self.policy.protocol_versions.len));
        for (self.policy.protocol_versions) |version| {
            try w.u16_(@intFromEnum(version));
        }

        try w.u16_(ext_supported_groups);
        try w.u16_(@intCast(2 + 2 * self.policy.named_groups.len));
        try w.u16_(@intCast(2 * self.policy.named_groups.len));
        for (self.policy.named_groups) |group| {
            try w.u16_(@intFromEnum(group));
        }

        try w.u16_(ext_signature_algorithms);
        try w.u16_(@intCast(2 + 2 * self.policy.signature_schemes.len));
        try w.u16_(@intCast(2 * self.policy.signature_schemes.len));
        for (self.policy.signature_schemes) |scheme| {
            try w.u16_(@intFromEnum(scheme));
        }

        try w.u16_(ext_key_share);
        try w.u16_(2 + 2 + 2 + X25519.public_length);
        try w.u16_(2 + 2 + X25519.public_length); // client_shares
        try w.u16_(group_x25519);
        try w.u16_(X25519.public_length);
        try w.bytes(&key_pair.public_key);

        try self.writePolicyAlpnOffer(&w);

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

        // early_data (#366): an empty extension announcing a 0-RTT attempt.
        // Order relative to `pre_shared_key` doesn't matter under RFC
        // 8446 §4.2.11 (only `pre_shared_key` itself must be last), so this
        // is placed before the PSK block below for wire-format stability.
        if (self.client_early_data_attempted) {
            try w.u16_(ext_early_data);
            try w.u16_(0);
        }

        // pre_shared_key (#362/#487): `self.client_offer_lease.offers` was already
        // compacted to exactly the eligible, size-fitting, wire-ordered
        // subset by `planPskOffer` (called from `startImpl` before
        // `core.start()`), so this block only needs to emit it verbatim —
        // no further filtering here, which is what keeps the transmitted
        // wire index aligned with `onServerHello`'s `selected_identity`.
        // RFC 8446 §4.2.11's "last extension" rule is what puts this block
        // after every other extension above and before the length patches.
        var psk_secrets: [pre_shared_key.max_offered_identities][hash_len]u8 = undefined;
        defer crypto.secureZero(u8, std.mem.asBytes(&psk_secrets));
        var psk_count: usize = 0;
        var psk_offer_write: ?pre_shared_key.ClientOfferWrite = null;
        const active_offers = self.constClientPskOffers();
        if (!active_offers.isEmpty()) {
            const now_ms = self.psk_now_fn.?(self.psk_now_ctx.?);
            var psk_items: [pre_shared_key.max_offered_identities]pre_shared_key.OfferItem = undefined;
            for (active_offers.constSlice()) |*ticket| {
                @memcpy(&psk_secrets[psk_count], ticket.common.resumption_psk.slice());
                psk_items[psk_count] = .{
                    .identity = ticket.ticket.slice(),
                    .obfuscated_ticket_age = pre_shared_key.obfuscateTicketAge(ticket.ageMillis(now_ms), ticket.ticket_age_add),
                    .digest_len = hash_len,
                };
                psk_count += 1;
            }
            try w.u16_(pre_shared_key.ext_psk_key_exchange_modes);
            const modes_ext_len = try w.reserve(2);
            pre_shared_key.writeModes(&w, &.{.psk_dhe_ke}) catch |err| switch (err) {
                // Exactly one mode, always: never empty, never over 255.
                error.EmptyModes, error.TooManyModes => unreachable,
                error.HandshakeBufferOverflow => return error.HandshakeBufferOverflow,
            };
            w.patch(2, modes_ext_len);
            psk_offer_write = pre_shared_key.writeOffer(&w, psk_items[0..psk_count]) catch |err| switch (err) {
                error.TooManyIdentities => unreachable, // bounded by ClientPskOfferSet's own capacity
                // `max_message_len` (8 KiB) is far below the u16 (65535)
                // vector limits these guard, and `planPskOffer` already
                // rejected any ticket with a zero/oversized identity before
                // it ever reached `self.client_offer_lease.offers` — so none of
                // these are reachable through this concrete backend.
                error.EmptyIdentity,
                error.IdentityTooLarge,
                error.IdentitiesVectorTooLarge,
                error.InvalidBinderLength,
                error.BindersVectorTooLarge,
                error.ExtensionTooLarge,
                => unreachable,
                error.HandshakeBufferOverflow => return error.HandshakeBufferOverflow,
            };
        }

        w.patch(2, extensions_len);
        w.patch(3, message_len);

        // Every enclosing length field (message, extensions block, the PSK
        // extension itself, identities, binders) is now patched to its
        // final value, so the truncated prefix below is exactly what RFC
        // 8446 §4.2.11.2 requires each binder to be computed over.
        if (psk_offer_write) |offer| {
            const prefix = buf[0..offer.truncated_len];
            for (0..psk_count) |i| {
                var binder: [hash_len]u8 = undefined;
                defer crypto.secureZero(u8, &binder);
                pre_shared_key.deriveBinder(.sha256, &psk_secrets[i], prefix, &binder) catch return error.SecretExportFailed;
                const slot = offer.slots[i];
                @memcpy(buf[slot.offset..][0..slot.len], &binder);
            }
        }

        const message = buf[0..w.len];

        // #366: the client 0-RTT traffic secret is derived from the hash of
        // this *complete* ClientHello (patched lengths, real binders) —
        // never the binder-truncated prefix used just above. `psk_secrets[0]`
        // is identity 0's PSK (the only identity 0-RTT may use), matching
        // `planEarlyDataAttempt`'s "first surviving offer only" rule.
        if (self.client_early_data_attempted) {
            var client_hello_hash: [hash_len]u8 = undefined;
            Sha256.hash(message, &client_hello_hash, .{});

            var early = KeySchedule.clientEarlyTrafficSecret(&psk_secrets[0], client_hello_hash);
            defer crypto.secureZero(u8, &early);

            try self.emitSecret(sink, .zero_rtt, .write, &early);
        }

        self.core.recordSent(message) catch |err| return mapCoreError(err);
        try sink.emitCrypto(.initial, message);
    }

    /// #362: decide, before `core.start()` mutates any lifecycle/key-pair
    /// state, exactly which offered tickets will fit in the ClientHello and
    /// in what wire order — compacting `self.client_offer_lease.offers` in place to
    /// exactly that subset (wiping whatever did not fit/qualify), so
    /// `sendClientHello`'s later, unfiltered write and `onServerHello`'s
    /// `selected_identity` interpretation can never disagree about wire
    /// order. `base_len` is the ordinary (non-PSK) ClientHello length
    /// already checked against `max_message_len` by the caller.
    fn planPskOffer(self: *Tls13Backend, base_len: usize) HandshakeError!void {
        if (self.mutableClientPskOffers().isEmpty()) return;
        const now_fn = self.psk_now_fn orelse {
            self.clearClientPskOffersAborted();
            return;
        };
        const now_ms = now_fn(self.psk_now_ctx.?);

        if (self.client_offer_lease.active) {
            var total = try checkedAdd(base_len, 6 + 8);
            var i: usize = 0;
            while (i < self.client_offer_lease.offers.len) {
                const ticket = &self.client_offer_lease.offers.tickets[i];
                var keep = self.ticketEligibleToOffer(ticket, now_ms);
                var stop = false;
                if (keep) {
                    const identity_len = ticket.ticket.slice().len;
                    if (identity_len == 0 or identity_len > std.math.maxInt(u16)) {
                        keep = false;
                    } else {
                        const entry_len = try checkedAdd(try checkedAdd(2, identity_len), 4);
                        const candidate_total = try checkedAdd(try checkedAdd(total, entry_len), 1 + hash_len);
                        if (candidate_total > max_message_len) {
                            keep = false;
                            stop = true;
                        } else total = candidate_total;
                    }
                }
                if (!keep) {
                    self.client_offer_lease.dropOffer(i);
                    if (stop) {
                        while (i < self.client_offer_lease.offers.len) self.client_offer_lease.dropOffer(i);
                        break;
                    }
                    continue;
                }
                i += 1;
            }
            if (self.client_offer_lease.offers.isEmpty()) self.client_offer_lease.finish(.not_selected);
            return;
        }

        var emitted: pre_shared_key.ClientPskOfferSet = .{};
        errdefer emitted.deinit();
        // psk_key_exchange_modes: 2 type + 2 ext_len + 1 vector_len + 1 mode.
        // pre_shared_key: 2 type + 2 ext_len + 2 identities_len + 2 binders_len.
        var total = try checkedAdd(base_len, 6 + 8);

        const raw_offers = self.mutableClientPskOffers();
        for (raw_offers.slice()) |*ticket| {
            if (emitted.len >= pre_shared_key.max_offered_identities) break;
            if (!self.ticketEligibleToOffer(ticket, now_ms)) continue;
            const identity_len = ticket.ticket.slice().len;
            if (identity_len == 0 or identity_len > std.math.maxInt(u16)) continue;
            // identity: 2 len + bytes + 4 age; binder: 1 len + digest.
            const entry_len = try checkedAdd(try checkedAdd(2, identity_len), 4);
            const candidate_total = try checkedAdd(try checkedAdd(total, entry_len), 1 + hash_len);
            if (candidate_total > max_message_len) break; // does not fit: stop, in offer order
            total = candidate_total;
            emitted.push(ticket) catch break; // bounded by the loop guard above
        }

        raw_offers.deinit(); // whatever was ineligible or did not fit
        raw_offers.moveFrom(&emitted);
    }

    /// #366: decide whether to attempt 0-RTT, from the first surviving wire
    /// offer only — tickets are never reordered to find an early-capable
    /// one, which both preserves #487's wire-index/lease semantics and
    /// naturally enforces the TLS "selected identity must be 0" requirement
    /// for early data. Called after `planPskOffer` has already compacted
    /// `self.client_offer_lease.offers` to exactly the wire-emitted subset.
    fn planEarlyDataAttempt(self: *Tls13Backend) void {
        self.client_early_data_attempted = false;
        if (!self.client_early_data_intent.enabled) return;

        const offers = self.constClientPskOffers();
        if (offers.isEmpty()) return;

        const max = switch (offers.constSlice()[0].common.early_data) {
            .resume_only => return,
            .early_data_capable => |n| n,
        };
        if (max == 0 or self.client_early_data_intent.max_bytes == 0) return;

        self.client_early_data_attempted = true;
    }

    /// Whether `ticket` is still safe and compatible to offer *now*: not
    /// expired/not-yet-valid, matching cipher suite, and — #362's "SNI,
    /// ALPN, transport, and application context" recheck — matching the
    /// currently intended SNI, an ALPN this connection is actually
    /// offering, and the transport/application compatibility snapshots this
    /// connection is configured with.
    fn ticketEligibleToOffer(self: *const Tls13Backend, ticket: *const session.ClientTicketState, now_ms: i64) bool {
        const common = &ticket.common;
        if (common.isExpired(now_ms) or common.isNotYetValid(now_ms)) return false;
        if (!self.policy.containsCipherSuite(common.cipher_suite)) return false;
        if (common.resumption_psk.slice().len != hash_len) return false;
        if (common.server_name) |*stored| {
            const intended = self.serverNameSlice() orelse return false;
            if (!stored.eqlIgnoreCase(intended)) return false;
        } else if (self.serverNameSlice() != null) return false;
        if (common.application_protocol) |*stored| {
            if (!self.policy.containsAlpn(stored.slice())) return false;
        }
        // `common.transport_compat` is the *server's* transport snapshot
        // (stamped via `peerTransportCompat()` at issuance, from the
        // server's EncryptedExtensions) — there is no local value to
        // prefilter it against here; comparing it to this client's own
        // outbound extension (`profile.localExtension()`) would compare the
        // wrong direction and could silently filter out every ticket
        // whenever the two peers' payloads differ, which is the ordinary
        // case for opaque transport parameters. The one correct-direction
        // check — the stored peer snapshot against the newly *received*
        // server extension — happens after ServerHello, in
        // `onEncryptedExtensions`, once there is a value to compare it
        // against; that failure is fatal there rather than a
        // pre-offer fallback, since a PSK-selected ServerHello cannot be
        // un-sent.
        if (!compatCompatible(common.application_compat, self.candidateApplicationCompat())) return false;
        return true;
    }

    /// The application-compatibility candidate view of the owned
    /// `application_compat` snapshot (see `setApplicationCompat`), for both
    /// the client's eligibility recheck and the server's candidate
    /// compatibility evaluation.
    fn candidateApplicationCompat(self: *const Tls13Backend) ?session.CandidateCompat {
        const blob = self.ownedApplicationCompat() orelse return null;
        return .{ .format_id = blob.format_id, .format_version = blob.format_version, .bytes = blob.bytes };
    }

    fn clientHelloEncodedLen(self: *const Tls13Backend) HandshakeError!usize {
        var len: usize = 0;
        len = try checkedAdd(len, 1 + 3); // handshake header
        len = try checkedAdd(len, 2); // legacy_version
        len = try checkedAdd(len, 32); // random
        len = try checkedAdd(len, 1); // legacy_session_id
        len = try checkedAdd(len, 2 + 2 * self.policy.cipher_suites.len); // cipher_suites vector
        len = try checkedAdd(len, 1 + 1); // compression_methods vector + null
        len = try checkedAdd(len, 2); // extensions vector length
        len = try checkedAdd(len, 2 + 2 + 1 + 2 * self.policy.protocol_versions.len); // supported_versions
        len = try checkedAdd(len, 2 + 2 + 2 + 2 * self.policy.named_groups.len); // supported_groups
        len = try checkedAdd(len, 2 + 2 + 2 + 2 * self.policy.signature_schemes.len); // signature_algorithms
        len = try checkedAdd(len, 2 + 2 + 2 + 2 + 2 + X25519.public_length); // key_share
        len = try checkedAdd(len, try self.policyAlpnOfferEncodedLen());
        if (self.serverNameSlice()) |name| {
            len = try checkedAdd(len, 2 + 2 + 2 + 1 + 2 + name.len);
        }
        if (self.profile.extensionType() != null) {
            const payload = self.profile.localExtension() orelse return error.MissingTransportExtension;
            len = try checkedAdd(len, 2 + 2 + payload.len);
        }
        return len;
    }

    fn writePolicyAlpnOffer(self: *const Tls13Backend, w: *Writer) HandshakeError!void {
        if (self.policy.alpn_protocols.len == 0) return;
        try w.u16_(ext_alpn);
        const alpn_ext_len = try w.reserve(2);
        const alpn_list_len = try w.reserve(2);
        for (self.policy.alpn_protocols) |protocol| {
            try w.u8_(@intCast(protocol.bytes.len));
            try w.bytes(protocol.bytes);
        }
        w.patch(2, alpn_list_len);
        w.patch(2, alpn_ext_len);
    }

    fn policyAlpnOfferEncodedLen(self: *const Tls13Backend) HandshakeError!usize {
        if (self.policy.alpn_protocols.len == 0) return 0;
        var list_len: usize = 0;
        for (self.policy.alpn_protocols) |protocol| {
            list_len = try checkedAdd(list_len, 1 + protocol.bytes.len);
        }
        return try checkedAdd(6, list_len);
    }

    fn onServerHello(self: *Tls13Backend, body: []const u8, sink: *EventSink) HandshakeError!void {
        // #362: any failure below — malformed framing, an out-of-range
        // `selected_identity`, or anything else — must not leave owned PSK
        // offer/selected-ticket state sitting in a now-failed backend past
        // this call.
        errdefer {
            self.clearClientPskOffersAborted();
            self.selected_client_psk.deinit();
            self.selected_client_psk_present = false;
        }
        var r = Reader{ .bytes = body };
        if (try r.u16_() != legacy_version) return error.IllegalParameter;
        const random = try r.slice(32);
        if (std.mem.eql(u8, random, &hello_retry_request_random)) return error.IllegalParameter;
        const session_id_len = try r.u8_();
        _ = try r.slice(session_id_len);
        const selected_cipher = tls_algorithms.fromInt(tls_algorithms.CipherSuite, try r.u16_()) orelse return error.IllegalParameter;
        if (try r.u8_() != 0) return error.IllegalParameter;

        var selected_version: ?tls_algorithms.ProtocolVersion = null;
        var selected_group: ?tls_algorithms.NamedGroup = null;
        var peer_share: ?[X25519.public_length]u8 = null;
        var selected_identity: ?u16 = null;
        var guard = ExtensionGuard{};
        var extensions = Reader{ .bytes = try r.slice(try r.u16_()) };
        try r.expectEnd();
        while (extensions.remaining() > 0) {
            const ext_id = try extensions.u16_();
            try guard.check(ext_id);
            var ext = Reader{ .bytes = try extensions.slice(try extensions.u16_()) };
            switch (ext_id) {
                ext_supported_versions => {
                    selected_version = tls_algorithms.fromInt(tls_algorithms.ProtocolVersion, try ext.u16_()) orelse return error.IllegalParameter;
                    try ext.expectEnd();
                },
                ext_key_share => {
                    const group = tls_algorithms.fromInt(tls_algorithms.NamedGroup, try ext.u16_()) orelse return error.IllegalParameter;
                    if (try ext.u16_() != X25519.public_length) return error.IllegalParameter;
                    peer_share = (try ext.slice(X25519.public_length))[0..X25519.public_length].*;
                    selected_group = group;
                    try ext.expectEnd();
                },
                pre_shared_key.ext_pre_shared_key => {
                    selected_identity = try ext.u16_();
                    try ext.expectEnd();
                },
                else => {},
            }
        }
        const protocol_version = selected_version orelse return error.MissingExtension;
        const named_group = selected_group orelse return error.MalformedHandshake;
        tls_negotiation.validateServerHelloTuple(self.policy, .{
            .version = protocol_version,
            .cipher_suite = selected_cipher,
            .named_group = named_group,
            .alpn = null,
        }) catch |err| return mapNegotiationError(err);
        if (selected_cipher != .tls_aes_128_gcm_sha256 or named_group != .x25519 or protocol_version != .tls13) return error.IllegalParameter;
        self.negotiated_version = protocol_version;
        self.negotiated_cipher_suite = selected_cipher;
        self.negotiated_named_group = named_group;
        const share = peer_share orelse return error.MalformedHandshake;

        // A low-order/identity peer share is a well-formed 32-byte field with an
        // illegal value (predictable all-zero shared secret), not malformed wire
        // data.
        if (!self.key_pair_present) return error.InvalidHandshakeState;
        var shared = X25519.scalarmult(self.key_pair.secret_key, share) catch
            return error.IllegalParameter;
        defer crypto.secureZero(u8, &shared);

        // #362: consistency-check the server's selected_identity (if any)
        // against our own offers — `self.client_offer_lease.offers` was already
        // compacted to exactly the wire-emitted, wire-ordered subset by
        // `planPskOffer`, so `idx` names an actual offer, never a value the
        // server invented, and never a stale/filtered-out one. On success,
        // move the selected ticket into `selected_client_psk` — retained
        // (not deinitialized yet) until `onEncryptedExtensions` has checked
        // it against the negotiated context and carried its `auth_binding`
        // forward. Every other offer is wiped here, on every path (selected
        // or not, malformed or not).
        var psk_secret: ?[hash_len]u8 = null;
        const active_offers = self.mutableClientPskOffers();
        // #366: retained regardless of `idx`'s value so
        // `onEncryptedExtensions` can check an accepted `early_data`
        // extension applies only to identity 0.
        self.selected_client_psk_index = selected_identity;
        if (selected_identity) |idx| {
            if (idx >= active_offers.len) return error.IllegalParameter;
            if (self.client_offer_lease.active) self.client_offer_lease.finishPins(.{ .selected = idx });
            active_offers.takeSelected(idx, &self.selected_client_psk);
            self.client_offer_lease = .{};
            self.selected_client_psk_present = true;
            const psk_slice = self.selected_client_psk.common.resumption_psk.slice();
            if (psk_slice.len != hash_len) return error.IllegalParameter;
            var buf: [hash_len]u8 = undefined;
            defer crypto.secureZero(u8, &buf);
            @memcpy(&buf, psk_slice);
            psk_secret = buf;
        } else {
            if (self.client_offer_lease.active) {
                self.client_offer_lease.finish(.not_selected);
            } else {
                self.client_offer_lease.offers.deinit();
            }
        }

        self.wipeEphemeral();
        if (psk_secret) |*psk| {
            self.core.enterPskAuthenticated();
            // #488: a PSK-resumed handshake never sends a Certificate
            // message (RFC 8446 SS4.2.11), so `certificate_state` would
            // otherwise stay `.not_checked` forever — which every transport
            // completion policy (record `completionPolicyError`, QUIC
            // `Handshake.complete`) treats as a fatal `CertificateInvalid`
            // for the client role. The resumed identity's trust is not
            // reestablished here: it was already proven once, at the
            // original full handshake that issued this ticket, and the
            // binder just confirmed the client and server share that same
            // ticket's PSK — so the client may treat the peer as
            // equivalently authenticated without a fresh Certificate flight.
            try sink.emitCertificate(.valid);
            self.schedule = KeySchedule.initWithPsk(psk, &shared, self.core.transcriptHash());
            crypto.secureZero(u8, psk);
        } else {
            self.schedule = KeySchedule.init(&shared, self.core.transcriptHash());
        }
        try self.emitHandshakeSecrets(sink);
        try sink.emitDiscardKeys(.initial);
    }

    fn onEncryptedExtensions(self: *Tls13Backend, body: []const u8, sink: *EventSink) HandshakeError!void {
        // #362: a parse/ALPN/transport failure here — before the retained
        // selected ticket is ever reached below — must not leave it alive
        // in a now-failed backend.
        errdefer if (self.selected_client_psk_present) {
            self.selected_client_psk.deinit();
            self.selected_client_psk_present = false;
        };
        var r = Reader{ .bytes = body };
        var guard = ExtensionGuard{};
        var transport_extension_seen = false;
        var alpn_seen = false;
        var early_data_seen = false;
        var extensions = Reader{ .bytes = try r.slice(try r.u16_()) };
        try r.expectEnd();
        while (extensions.remaining() > 0) {
            const ext_id = try extensions.u16_();
            try guard.check(ext_id);
            var ext = Reader{ .bytes = try extensions.slice(try extensions.u16_()) };
            switch (ext_id) {
                ext_alpn => {
                    const list_len = try ext.u16_();
                    if (list_len == 0) return error.MalformedHandshake;
                    var list = Reader{ .bytes = try ext.slice(list_len) };
                    try ext.expectEnd();
                    const name_len = try list.u8_();
                    if (name_len == 0) return error.MalformedHandshake;
                    const name = try list.slice(name_len);
                    // The server selects exactly one protocol (RFC 7301 §3.1).
                    try list.expectEnd();
                    if (!self.policy.containsAlpn(name)) return error.AlpnMismatch;
                    self.setSelectedAlpn(name);
                    alpn_seen = true;
                    try sink.emitAlpn(name);
                },
                // #366: RFC 8446 §4.2.10 defines this extension's
                // EncryptedExtensions form as empty too.
                ext_early_data => {
                    try ext.expectEnd();
                    early_data_seen = true;
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
        if (!alpn_seen and !self.policy.allow_absent_alpn) return error.AlpnMismatch;
        // #366: an EncryptedExtensions `early_data` the client never
        // attempted, or applying to a non-zero selected identity, is a
        // protocol violation — not merely "not accepted".
        if (early_data_seen) {
            if (!self.client_early_data_attempted) return error.IllegalParameter;
            if ((self.selected_client_psk_index orelse return error.IllegalParameter) != 0) return error.IllegalParameter;
        }
        tls_negotiation.validateServerSelection(self.policy, .{
            .version = self.negotiated_version,
            .cipher_suite = self.negotiated_cipher_suite,
            .named_group = self.negotiated_named_group,
            .alpn = if (self.selectedAlpn()) |protocol| .{ .bytes = protocol } else null,
        }) catch |err| return mapNegotiationError(err);
        if (self.profile.extensionType() != null and !transport_extension_seen) return error.MissingTransportExtension;

        // #362: a PSK-resumed connection has no Certificate message from
        // which to (re)derive `connection_auth_binding`, so this is the one
        // point the client can check the negotiated context against the
        // selected ticket's stored one — and the only source for carrying
        // its `auth_binding` forward (e.g. for a later NewSessionTicket on
        // this same resumed connection). A mismatch here is fatal, not a
        // fallback: the PSK was already selected and ServerHello already
        // sent.
        if (self.selected_client_psk_present) {
            defer {
                self.selected_client_psk.deinit();
                self.selected_client_psk_present = false;
            }
            const stored = &self.selected_client_psk.common;
            const negotiated_alpn = self.selectedAlpn();
            const alpn_matches = if (stored.application_protocol) |*proto|
                (negotiated_alpn != null and proto.eql(negotiated_alpn.?))
            else
                negotiated_alpn == null;
            if (!alpn_matches) return error.IllegalParameter;

            const received_transport: ?session.CandidateCompat = if (self.peerTransportCompat()) |blob|
                .{ .format_id = blob.format_id, .format_version = blob.format_version, .bytes = blob.bytes }
            else
                null;
            if (self.resume_compat.transport == .exact and !compatCompatible(stored.transport_compat, received_transport)) return error.IllegalParameter;
            if (self.resume_compat.application == .exact and !compatCompatible(stored.application_compat, self.candidateApplicationCompat())) return error.IllegalParameter;

            // #366: a resume-only ticket can never be the basis for an
            // accepted `early_data` extension, regardless of what the
            // client attempted.
            if (early_data_seen and stored.early_data == .resume_only) return error.IllegalParameter;
            if (early_data_seen) self.early_data_accepted = true;

            self.connection_auth_binding = stored.auth_binding;
        }
    }

    /// Client: a server CertificateRequest (RFC 8446 §4.3.2) asking us to
    /// authenticate at handshake time. `core.acceptReceived` already recorded
    /// that a request arrived and updated the transcript; here we validate the
    /// framing and capture the server's accepted signature schemes so the client
    /// credential provider can select a compatible credential. In a handshake
    /// (not post-handshake) CertificateRequest the context is zero length.
    fn onCertificateRequest(self: *Tls13Backend, body: []const u8) HandshakeError!void {
        std.debug.assert(self.role == .client);
        var r = Reader{ .bytes = body };
        if ((try r.slice(try r.u8_())).len != 0) return error.IllegalParameter; // context must be empty

        // Reuse the peer-signature-scheme vector (unused on the client until
        // now) to remember the schemes the server will accept from us.
        self.peer_sig_scheme_count = 0;
        var saw_signature_algorithms = false;
        var guard = ExtensionGuard{};
        var extensions = Reader{ .bytes = try r.slice(try r.u16_()) };
        try r.expectEnd();
        while (extensions.remaining() > 0) {
            const ext_id = try extensions.u16_();
            try guard.check(ext_id);
            var ext = Reader{ .bytes = try extensions.slice(try extensions.u16_()) };
            switch (ext_id) {
                ext_signature_algorithms => {
                    saw_signature_algorithms = true;
                    var algorithms = Reader{ .bytes = try ext.slice(try ext.u16_()) };
                    while (algorithms.remaining() > 0) {
                        const scheme = try algorithms.u16_();
                        if (self.peer_sig_scheme_count >= self.peer_sig_schemes.len) return error.MalformedHandshake;
                        self.peer_sig_schemes[self.peer_sig_scheme_count] = scheme;
                        self.peer_sig_scheme_count += 1;
                    }
                    try ext.expectEnd();
                },
                else => {},
            }
        }
        // signature_algorithms is mandatory in a CertificateRequest
        // (RFC 8446 §4.3.2); its absence is a malformed/missing peer extension.
        if (!saw_signature_algorithms) return error.MissingExtension;
        if (self.peer_sig_scheme_count == 0) return error.MalformedHandshake;
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
        var empty = true;
        while (list.remaining() > 0) {
            const entry_len = try list.u24_();
            if (entry_len == 0 or entry_len > max_certificate_len) return self.failCredential(.invalid_peer_certificate_chain);
            const entry = try list.slice(entry_len);
            _ = try list.slice(try list.u16_()); // per-certificate extensions
            self.appendPeerCertificate(entry) catch return self.failCredential(.invalid_peer_certificate_chain);
            empty = false;
        }

        // Role-aware: this is the *client's* Certificate when we are the server
        // (handshake-time client authentication, #334), otherwise the server's.
        switch (self.role) {
            .server => {
                // An empty client Certificate declines authentication. In
                // `required` mode that fails closed (certificate_required);
                // in `optional` mode the server proceeds expecting the client
                // Finished (no CertificateVerify follows an empty certificate).
                if (empty) {
                    if (self.client_auth == .required) return self.failCredential(.client_certificate_required);
                    self.core.clientCertificateWasEmpty(true);
                    return;
                }
                self.core.clientCertificateWasEmpty(false);
            },
            .client => {
                // A server that presents no certificate is malformed: server
                // authentication is mandatory in this profile.
                if (empty) return self.failCredential(.invalid_peer_certificate_chain);
            },
        }
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
            .negotiated_version = self.negotiatedVersionCode(),
            .cipher_suite = self.negotiatedCipherCode(),
            .application_protocol = self.selectedAlpn(),
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

        // Role-aware: verifying the *server's* CertificateVerify (we are the
        // client) or the *client's* (we are the server, handshake-time client
        // authentication, #334). The signer is always the peer, so the context
        // string names the peer's role, and the verification context's `role`
        // is our own.
        const signer_role: Role = if (self.role == .client) .server else .client;

        // The signature covers the transcript through Certificate (RFC 8446
        // §4.4.3) — before this message is added. Keep structural certificate
        // failures, unsupported key material, unoffered algorithms, and actual
        // signature mismatches distinct so alert mapping remains faithful.
        const content = certificateVerifyContent(signer_role, transcript_before);
        switch (self.checkProofOfPossession(algorithm, signature, content.slice())) {
            .valid => {},
            .invalid_certificate => return self.failCredential(.invalid_peer_certificate_chain),
            .unsupported_certificate => return self.failCredential(.unsupported_peer_certificate),
            .unoffered_algorithm => return error.IllegalParameter,
            .invalid_signature => return self.failCredential(.certificate_verify_invalid),
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
            .role = self.role,
            .server_name = self.serverNameSlice(),
            .chain = self.peerChainView(&views),
            .negotiated_version = self.negotiatedVersionCode(),
            .cipher_suite = self.negotiatedCipherCode(),
            .application_protocol = self.selectedAlpn(),
            .auth_policy = self.auth_policy,
        };
        // The verifier may resolve synchronously or return a pending operation
        // (an async Web-PKI/OCSP lookup); park the latter and resume later.
        switch (verifier.verifyPeer(&context) catch |err|
            return self.failCredential(credentials.classifyVerifyError(err))) {
            .complete => |verdict| return self.applyPeerVerdict(verdict, sink),
            .pending => |op| return self.parkAuth(op, .peer_verify),
        }
    }

    /// Apply a peer-verification verdict: emit the certificate state and fail
    /// closed on rejection. Reachable synchronously and after resume.
    ///
    /// A `.not_checked` verdict — the verifier deliberately did not evaluate
    /// trust — is only acceptable when policy explicitly permits an unverified
    /// peer (the insecure client opt-in). Every other case, including any server
    /// verifying a client certificate under optional or required authentication,
    /// treats it as a verification failure: policy that requires authentication
    /// must not be satisfied by "no trust decision was made".
    fn applyPeerVerdict(self: *Tls13Backend, verdict: credentials.Verdict, sink: *EventSink) HandshakeError!void {
        switch (verdict) {
            .accepted => try sink.emitCertificate(.valid),
            .rejected => {
                try sink.emitCertificate(.invalid);
                return self.failCredential(.peer_verification_rejected);
            },
            .not_checked => {
                if (!self.auth_policy.allow_unverified_peer) {
                    try sink.emitCertificate(.invalid);
                    return self.failCredential(.peer_verification_rejected);
                }
                try sink.emitCertificate(.not_checked);
            },
        }
    }

    const ProofResult = enum {
        valid,
        invalid_signature,
        invalid_certificate,
        unsupported_certificate,
        unoffered_algorithm,
    };

    fn locallyOfferedSignatureAlgorithm(self: *const Tls13Backend, algorithm: u16) bool {
        const scheme = tls_algorithms.fromInt(tls_algorithms.SignatureScheme, algorithm) orelse return false;
        return self.policy.containsSignatureScheme(scheme);
    }

    /// Verify the CertificateVerify signature against the peer leaf's public
    /// key: proof that the peer holds the private key for the presented
    /// certificate. This is not a trust decision — that is the verifier's job.
    fn checkProofOfPossession(self: *const Tls13Backend, algorithm: u16, signature: []const u8, content: []const u8) ProofResult {
        if (!self.locallyOfferedSignatureAlgorithm(algorithm)) return .unoffered_algorithm;
        if (self.peer_chain_count == 0) return .invalid_certificate;
        const e = self.peer_chain_entries[0];
        const leaf = self.peer_chain[e.start..][0..e.len];
        const parsed = (Certificate{ .buffer = leaf, .index = 0 }).parse() catch return .invalid_certificate;
        switch (algorithm) {
            sigalg_ed25519 => {
                if (signature.len != Ed25519.Signature.encoded_length) return .invalid_signature;
                if (parsed.pub_key_algo != .curveEd25519) {
                    return switch (parsed.pub_key_algo) {
                        .X9_62_id_ecPublicKey => |curve| if (curve == .X9_62_prime256v1) .invalid_signature else .unsupported_certificate,
                        else => .unsupported_certificate,
                    };
                }
                const pub_key_bytes = parsed.pubKey();
                if (pub_key_bytes.len != Ed25519.PublicKey.encoded_length) return .invalid_certificate;
                const public_key = Ed25519.PublicKey.fromBytes(pub_key_bytes[0..Ed25519.PublicKey.encoded_length].*) catch return .invalid_certificate;
                const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
                sig.verify(content, public_key) catch return .invalid_signature;
            },
            sigalg_ecdsa_secp256r1_sha256 => {
                switch (parsed.pub_key_algo) {
                    .X9_62_id_ecPublicKey => |curve| if (curve != .X9_62_prime256v1) return .unsupported_certificate,
                    .curveEd25519 => return .invalid_signature,
                    else => return .unsupported_certificate,
                }
                const public_key = EcdsaP256.PublicKey.fromSec1(parsed.pubKey()) catch return .invalid_certificate;
                const sig = EcdsaP256.Signature.fromDer(signature) catch return .invalid_signature;
                sig.verify(content, public_key) catch return .invalid_signature;
            },
            else => unreachable,
        }
        return .valid;
    }

    fn onServerFinished(self: *Tls13Backend, transcript_before: [hash_len]u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        const schedule = &self.schedule.?;
        if (body.len != hash_len) return error.MalformedHandshake;
        var expected = KeySchedule.verifyData(&schedule.server_handshake_traffic, transcript_before);
        defer crypto.secureZero(u8, &expected);
        if (!crypto.timing_safe.eql([hash_len]u8, expected, body[0..hash_len].*)) return error.DecryptError;

        // 1-RTT secrets exist from the transcript through server Finished,
        // independent of any client certificate flight that follows.
        const finished_hash = self.core.transcriptHash();
        var app = schedule.applicationSecrets(finished_hash);
        defer app.wipe();
        try self.emitSecret(sink, .application, .write, &app.client);
        try self.emitSecret(sink, .application, .read, &app.server);

        // When the server requested handshake-time client authentication
        // (#334) the client answers with Certificate, an optional
        // CertificateVerify, and Finished. That flight owns its own completion
        // because asynchronous credential selection or signing may suspend it
        // mid-way; on resume it finishes and completes the handshake.
        if (self.core.client_certificate_requested) {
            return self.beginClientAuthFlight(sink);
        }

        try self.sendClientFinished(finished_hash, sink);
        try self.completeClientHandshake(sink);
    }

    /// Emit a lone client Finished (no client authentication) covering the
    /// transcript through the server Finished.
    fn sendClientFinished(self: *Tls13Backend, transcript_hash: [hash_len]u8, sink: *EventSink) HandshakeError!void {
        const schedule = &self.schedule.?;
        var buf: [4 + hash_len]u8 = undefined;
        var w = Writer{ .buf = &buf };
        try w.u8_(@intFromEnum(MessageType.finished));
        const message_len = try w.reserve(3);
        var client_verify = KeySchedule.verifyData(&schedule.client_handshake_traffic, transcript_hash);
        defer crypto.secureZero(u8, &client_verify);
        try w.bytes(&client_verify);
        w.patch(3, message_len);
        const message = buf[0..w.len];
        self.core.recordSent(message) catch |err| return mapCoreError(err);
        try sink.emitCrypto(.handshake, message);
    }

    /// Terminal steps shared by every client completion path: discard the
    /// handshake epoch, signal completion, and wipe the key schedule.
    fn completeClientHandshake(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        try self.captureResumptionMasterSecret();
        try self.emitDiscardKeys(sink, .handshake);
        try sink.emitHandshakeComplete();
        self.finish();
        // Only now — every terminal fallible step above has succeeded — is
        // this handshake actually committed. See `clearFailedHandshakeState`.
        self.handshake_committed = true;
    }

    /// The immutable selection context for choosing the client's own
    /// credential, honoring the schemes the server offered in its
    /// CertificateRequest and the intended server name.
    fn clientSelectionContext(self: *const Tls13Backend) credentials.SelectionContext {
        return .{
            .role = .client,
            .server_name = self.serverNameSlice(),
            .peer_signature_schemes = self.peer_sig_schemes[0..self.peer_sig_scheme_count],
            .negotiated_version = self.negotiatedVersionCode(),
            .cipher_suite = self.negotiatedCipherCode(),
            .application_protocol = self.selectedAlpn(),
            .auth_policy = self.auth_policy,
        };
    }

    /// Begin the handshake-time client authentication flight (#334):
    /// Certificate, an optional CertificateVerify, and Finished. With no
    /// provider the client declines with an empty Certificate. A configured
    /// provider selects against the schemes the server advertised in its
    /// CertificateRequest; selection may complete synchronously or suspend
    /// (`client_select`), in which case the flight resumes from `resumeAuth`.
    fn beginClientAuthFlight(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        self.core.beginClientCertificateFlight();
        const provider = self.external_provider orelse
            return self.emitClientCertificate(null, certificate_message_overhead, sink);
        var selection = self.clientSelectionContext();
        // A provider that deterministically has no usable credential is not a
        // failure: TLS 1.3 requires the client to answer a CertificateRequest
        // with an empty Certificate (RFC 8446 §4.4.2). That is how optional auth
        // succeeds and how required auth yields the peer-attributed
        // certificate_required outcome on the server.
        const progress = provider.selectCredential(&selection) catch |err| switch (err) {
            error.NoCredentialAvailable,
            error.NoCompatibleSignatureAlgorithm,
            => return self.emitClientCertificate(null, certificate_message_overhead, sink),
            else => return self.failCredential(credentials.classifySelectError(err)),
        };
        switch (progress) {
            .complete => |credential| return self.emitSelectedClientCertificate(credential, sink),
            .pending => |op| return self.parkAuth(op, .client_select),
        }
    }

    /// Validate a freshly selected client credential (synchronously or after a
    /// resumed `client_select`) and continue emitting its Certificate.
    fn emitSelectedClientCertificate(self: *Tls13Backend, credential: credentials.SelectedCredential, sink: *EventSink) HandshakeError!void {
        var owned = true;
        errdefer if (owned) credential.release();
        const credential_info = try self.inspectSelectedCredential(credential);
        owned = false; // ownership passes to emitClientCertificate
        return self.emitClientCertificate(credential, credential_info.certificate_message_len, sink);
    }

    /// Emit the client Certificate (the credential's validated chain, or an
    /// empty list when declining) and record it, then sign CertificateVerify —
    /// synchronously, or by parking a pending signer (`client_sign`). Owns the
    /// credential handle and releases it exactly once on any failure before
    /// ownership passes on.
    fn emitClientCertificate(
        self: *Tls13Backend,
        credential: ?credentials.SelectedCredential,
        certificate_message_len: usize,
        sink: *EventSink,
    ) HandshakeError!void {
        var owned = credential != null;
        errdefer if (owned) if (credential) |c| c.release();
        if (certificate_message_len > max_message_len) return self.failCredential(.malformed_credential_chain);

        var buf: [max_message_len]u8 = undefined;
        var w = Writer{ .buf = &buf };
        try w.u8_(@intFromEnum(MessageType.certificate));
        const cert_len = try w.reserve(3);
        try w.u8_(0); // certificate_request_context: empty (echoes the request)
        const list_len = try w.reserve(3);
        if (credential) |c| {
            for (c.certificateChain().entries) |entry| {
                const entry_len = try w.reserve(3);
                try w.bytes(entry);
                w.patch(3, entry_len);
                try w.u16_(0); // per-certificate extensions
            }
        }
        w.patch(3, list_len);
        w.patch(3, cert_len);
        self.core.recordSent(buf[0..w.len]) catch |err| return mapCoreError(err);
        try sink.emitCrypto(.handshake, buf[0..w.len]);

        // Declining (empty Certificate) skips CertificateVerify entirely.
        const c = credential orelse return self.finishClientAuthFlight(null, 0, sink);

        // CertificateVerify signs the transcript through the client Certificate
        // (RFC 8446 §4.4.3) with the client context string, into the engine's
        // stable signature buffer. An async signer parks here.
        const content = certificateVerifyContent(.client, self.core.transcriptHash());
        switch (c.sign(content.slice(), &self.pending_signature) catch |err|
            return self.failCredential(credentials.classifySignError(err))) {
            .complete => |len| {
                owned = false; // ownership passes to finishClientAuthFlight
                return self.finishClientAuthFlight(c, len, sink);
            },
            .pending => |op| {
                owned = false; // ownership passes to the parked operation
                self.pending_credential = c;
                return self.parkAuth(op, .client_sign);
            },
        }
    }

    /// Emit CertificateVerify (when a certificate was presented) and the client
    /// Finished, then complete the handshake. Releases the credential exactly
    /// once. Reachable synchronously and after a resumed `client_sign`.
    fn finishClientAuthFlight(self: *Tls13Backend, credential: ?credentials.SelectedCredential, sig_len: usize, sink: *EventSink) HandshakeError!void {
        defer if (credential) |c| c.release();
        const schedule = &self.schedule.?;

        var buf: [max_message_len]u8 = undefined;
        var w = Writer{ .buf = &buf };
        if (credential) |c| {
            if (sig_len > self.pending_signature.len) return self.failCredential(.signature_output_overflow);
            try w.u8_(@intFromEnum(MessageType.certificate_verify));
            const verify_len = try w.reserve(3);
            try w.u16_(c.scheme.code());
            const sig_slot = try w.reserve(2);
            try w.bytes(self.pending_signature[0..sig_len]);
            w.patch(2, sig_slot);
            w.patch(3, verify_len);
            crypto.secureZero(u8, &self.pending_signature);
            self.core.recordSent(buf[0..w.len]) catch |err| return mapCoreError(err);
        }

        // Finished over the transcript through the last message above.
        const finished_start = w.len;
        try w.u8_(@intFromEnum(MessageType.finished));
        const finished_len = try w.reserve(3);
        var client_verify = KeySchedule.verifyData(&schedule.client_handshake_traffic, self.core.transcriptHash());
        defer crypto.secureZero(u8, &client_verify);
        try w.bytes(&client_verify);
        w.patch(3, finished_len);
        self.core.recordSent(buf[finished_start..w.len]) catch |err| return mapCoreError(err);
        // Emit CertificateVerify (when present) and Finished together; the
        // Certificate was already emitted before signing.
        try sink.emitCrypto(.handshake, buf[0..w.len]);

        try self.completeClientHandshake(sink);
    }

    // -----------------------------------------------------------------------
    // Server flight.
    // -----------------------------------------------------------------------

    fn onClientHello(self: *Tls13Backend, raw: []const u8, sink: *EventSink) HandshakeError!void {
        const body = raw[handshake_header_len..];
        // A server needs a credential source: the fixed identity or an external
        // provider. Which signature scheme is usable is decided later by
        // credential selection against the peer's advertised algorithms.
        if (!self.identity_present and self.external_provider == null) return error.InvalidHandshakeState;
        self.peer_sig_scheme_count = 0;
        self.server_name_present = false;
        self.server_name_len = 0;
        self.client_hello_early_data_seen = false;

        const ClientHelloObserver = struct {
            transport_extension_type: ?u16,
            transport_params: ?[]const u8 = null,
            psk_modes_seen: bool = false,
            psk_dhe_ke_offered: bool = false,
            psk_ext: ?struct { body_offset: usize, len: usize } = null,
            early_data_seen: bool = false,

            fn observe(ctx: *anyopaque, observation: tls_negotiation.ExtensionObservation) tls_negotiation.Error!void {
                const self_obs: *@This() = @ptrCast(@alignCast(ctx));
                switch (observation.id) {
                    pre_shared_key.ext_psk_key_exchange_modes => {
                        self_obs.psk_dhe_ke_offered = pre_shared_key.hasMode(observation.data, .psk_dhe_ke) catch
                            return error.MalformedExtension;
                        self_obs.psk_modes_seen = true;
                    },
                    pre_shared_key.ext_pre_shared_key => {
                        if (!observation.is_last) return error.IllegalParameter;
                        _ = pre_shared_key.OfferedPsks.parse(observation.data) catch |err| switch (err) {
                            error.CountMismatch => return error.IllegalParameter,
                            else => return error.MalformedExtension,
                        };
                        self_obs.psk_ext = .{
                            .body_offset = observation.data_offset_in_body,
                            .len = observation.data.len,
                        };
                    },
                    // #366: RFC 8446 §4.2.10 defines this extension's
                    // ClientHello form as empty; anything else is malformed.
                    ext_early_data => {
                        if (observation.data.len != 0) return error.MalformedExtension;
                        self_obs.early_data_seen = true;
                    },
                    else => if (self_obs.transport_extension_type) |expected_type| {
                        if (expected_type == observation.id) self_obs.transport_params = observation.data;
                    },
                }
            }
        };

        var observer = ClientHelloObserver{ .transport_extension_type = self.profile.extensionType() };
        const parsed = tls_negotiation.parseClientHelloObserved(body, .{
            .ctx = &observer,
            .observeFn = ClientHelloObserver.observe,
        }) catch |err| return mapNegotiationError(err);
        const offers = parsed.offers;
        const hello_selection = tls_negotiation.negotiateServerHello(self.policy, &offers) catch |err| return mapNegotiationError(err);
        if (observer.psk_ext != null and !observer.psk_modes_seen) return error.MissingExtension;
        // #366: early_data without an accompanying PSK offer is malformed —
        // 0-RTT is only meaningful alongside a resumption attempt.
        if (observer.early_data_seen and observer.psk_ext == null) return error.MissingExtension;
        self.client_hello_early_data_seen = observer.early_data_seen;
        // signature_algorithms is required whenever the server authenticates
        // with a certificate (RFC 8446 §9.2). A missing or empty list is a
        // malformed/missing required *peer* extension — attribute it to the
        // peer (decode_error), not to local credential configuration.
        if (offers.raw_signature_schemes_len == 0) return error.MissingExtension;
        if (offers.raw_signature_schemes_len > self.peer_sig_schemes.len) return error.MalformedHandshake;
        @memcpy(self.peer_sig_schemes[0..offers.raw_signature_schemes_len], offers.raw_signature_schemes[0..offers.raw_signature_schemes_len]);
        self.peer_sig_scheme_count = offers.raw_signature_schemes_len;
        const selected_key_share = switch (hello_selection.key_share) {
            .use => |share| share.key_exchange,
            .retry => return error.IllegalParameter,
        };
        if (selected_key_share.len != X25519.public_length) return error.MalformedHandshake;
        const client_share = selected_key_share[0..X25519.public_length].*;
        if (hello_selection.cipher_suite != .tls_aes_128_gcm_sha256 or
            hello_selection.named_group != .x25519 or
            hello_selection.version != .tls13)
            return error.IllegalParameter;
        self.negotiated_version = hello_selection.version;
        self.negotiated_cipher_suite = hello_selection.cipher_suite;
        self.negotiated_named_group = hello_selection.named_group;

        if (hello_selection.alpn) |protocol| {
            self.setSelectedAlpn(protocol.bytes);
        } else if (!self.policy.allow_absent_alpn) {
            self.core.handshake_lifecycle = .failed;
            return error.AlpnMismatch;
        }
        if (self.profile.extensionType() != null) {
            const extension = observer.transport_params orelse return error.MissingTransportExtension;
            try self.capturePeerTransportExtension(extension);
        }
        if (hello_selection.server_name) |name| {
            if (name.len > self.server_name.len) return error.IllegalParameter;
            @memcpy(self.server_name[0..name.len], name);
            self.server_name_len = name.len;
            self.server_name_present = true;
        }

        // #362: the PSK-bearing ClientHello is captured only once every
        // other semantic check above has already succeeded — not eagerly
        // as soon as it's parsed — so a later unrelated failure (missing
        // signature_algorithms, ALPN mismatch, missing transport extension)
        // can never leave a captured bearer ticket identity sitting in
        // `client_hello_psk` past this call.
        self.clearClientHelloPsk();
        if (observer.psk_ext) |info| {
            var capture: ClientHelloPskCapture = .{};
            if (raw.len > capture.message.len) return error.MalformedHandshake;
            @memcpy(capture.message[0..raw.len], raw);
            capture.message_len = raw.len;
            capture.ext_data_offset = handshake_header_len + info.body_offset;
            capture.ext_data_len = info.len;
            self.client_hello_psk = capture;
            self.offered_psk_modes_seen = true;
            self.offered_psk_dhe_ke = observer.psk_dhe_ke_offered;
        }
        // Covers every synchronous failure from here on (a bad session_id,
        // a synchronous credential-selection failure); a no-op once
        // `emitServerHelloAndAuthFlight` has already cleared it on its own
        // path, and correctly does *not* fire when selection instead parks
        // — the capture must survive for the async resume.
        errdefer self.clearClientHelloPsk();

        try self.beginServerSelection(parsed.legacy_session_id, client_share, sink);
    }

    fn beginServerSelection(
        self: *Tls13Backend,
        session_id: []const u8,
        client_share: [X25519.public_length]u8,
        sink: *EventSink,
    ) HandshakeError!void {
        if (session_id.len > self.pending_client_session_id.len) return error.IllegalParameter;
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
            .complete => |credential| return self.emitServerHelloAndAuthFlight(session_id, client_share, credential, sink),
            .pending => |op| {
                @memcpy(self.pending_client_session_id[0..session_id.len], session_id);
                self.pending_client_session_id_len = session_id.len;
                self.pending_client_share = client_share;
                self.pending_client_hello_ready = true;
                return self.parkAuth(op, .server_select);
            },
        }
    }

    fn emitServerHelloAndAuthFlight(
        self: *Tls13Backend,
        session_id: []const u8,
        client_share: [X25519.public_length]u8,
        credential: credentials.SelectedCredential,
        sink: *EventSink,
    ) HandshakeError!void {
        var owned = true;
        errdefer if (owned) credential.release();

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

        // #362: credential selection (above, by the caller) happens before
        // this. Validate it and derive the binding for *this server's own*
        // leaf certificate — not the (normally empty, client-only)
        // peer-chain default `peerAuthBinding()` returns — so a candidate
        // ticket's stored `auth_binding` is compared against the identity
        // this connection actually authenticates with, and PSK
        // selection/binder verification happens before any ServerHello byte
        // is written, since a selected identity must be named in it.
        // Installed before any fallible PSK step below, so a resolver or
        // binder failure still clears the captured ClientHello.
        defer self.clearClientHelloPsk();
        const credential_info = try self.inspectSelectedServerCredential(credential);
        self.connection_auth_binding = credential_info.binding;
        var psk_selected = try self.selectPsk(credential_info.binding, sink);
        defer if (psk_selected) |*sel| crypto.secureZero(u8, &sel.psk);

        // ServerHello (Initial level).
        var hello_buf: [256]u8 = undefined;
        defer crypto.secureZero(u8, &hello_buf);
        var hello = Writer{ .buf = &hello_buf };
        try hello.u8_(@intFromEnum(MessageType.server_hello));
        const hello_len = try hello.reserve(3);
        try hello.u16_(legacy_version);
        try hello.bytes(&self.entropy.hello_random);
        try hello.u8_(@intCast(session_id.len)); // echo legacy_session_id
        try hello.bytes(session_id);
        try hello.u16_(self.negotiatedCipherCode());
        try hello.u8_(0);
        const hello_extensions = try hello.reserve(2);
        try hello.u16_(ext_supported_versions);
        try hello.u16_(2);
        try hello.u16_(self.negotiatedVersionCode());
        try hello.u16_(ext_key_share);
        try hello.u16_(2 + 2 + X25519.public_length);
        try hello.u16_(self.negotiatedGroupCode());
        try hello.u16_(X25519.public_length);
        try hello.bytes(&key_pair.public_key);
        if (psk_selected) |sel| {
            try hello.u16_(pre_shared_key.ext_pre_shared_key);
            try hello.u16_(2);
            try hello.u16_(@intCast(sel.index));
        }
        hello.patch(2, hello_extensions);
        hello.patch(3, hello_len);
        const server_hello = hello_buf[0..hello.len];
        self.core.recordSent(server_hello) catch |err| return mapCoreError(err);
        try sink.emitCrypto(.initial, server_hello);
        if (self.selectedAlpn()) |protocol| try sink.emitAlpn(protocol);

        if (psk_selected) |*sel| {
            self.schedule = KeySchedule.initWithPsk(&sel.psk, &shared, self.core.transcriptHash());
        } else {
            self.schedule = KeySchedule.init(&shared, self.core.transcriptHash());
        }
        try self.emitHandshakeSecrets(sink);
        try sink.emitDiscardKeys(.initial);

        if (psk_selected != null) {
            // PSK-resumed: no Certificate/CertificateVerify flight, so the
            // selected credential (already validated by the caller) is
            // never consumed — release it here, on the one success path
            // that reaches this branch.
            credential.release();
            owned = false;
            self.core.enterPskAuthenticated();
            return self.emitPskFinishFlight(sink);
        }

        owned = false;
        try self.emitServerAuthFlight(credential, credential_info.certificate_message_len, sink);
    }

    /// #362 server selection algorithm: iterate the client's offered
    /// identities in order (bounded to `pre_shared_key.max_offered_identities`
    /// attempts), resolve each via the configured resolver, evaluate #360
    /// compatibility against the *current* connection context, and verify
    /// only the first compatible candidate's binder. A binder mismatch on
    /// that candidate is fatal (`DecryptError`) and never probes a later
    /// identity; an incompatible/unknown/undecryptable candidate simply
    /// continues to the next offered identity. Returns `null` — meaning
    /// "continue with the existing full-certificate flow" — whenever PSK is
    /// not configured/offered/eligible, or no candidate is acceptable.
    fn selectPsk(self: *Tls13Backend, current_binding: session.AuthBinding, sink: *EventSink) HandshakeError!?PskSelected {
        const resolver = self.psk_resolver orelse return null;
        const capture = self.client_hello_psk orelse return null;
        if (self.client_auth != .disabled) {
            self.resumption_decision_observer.notify(.full_handshake);
            return null;
        }
        if (!self.offered_psk_modes_seen or !self.offered_psk_dhe_ke) {
            self.resumption_decision_observer.notify(.full_handshake);
            return null;
        }
        const ext_data = capture.message[capture.ext_data_offset..][0..capture.ext_data_len];
        // Already validated once in `onClientHello`; re-parsing the same
        // captured bytes cannot fail.
        const offered = pre_shared_key.OfferedPsks.parse(ext_data) catch {
            self.resumption_decision_observer.notify(.fatal);
            return null;
        };
        const truncated_len = capture.ext_data_offset + offered.binder_vector_offset;
        const truncated_prefix = capture.message[0..truncated_len];
        const now = resolver.nowUnixMs();

        var it = offered.pairs();
        var attempts: usize = 0;
        var saw_resolved = false;
        var saw_incompatible = false;
        while (attempts < pre_shared_key.max_offered_identities) : (attempts += 1) {
            const pair = (it.next() catch return null) orelse break;
            var resolved = resolver.resolve(pair.identity.identity) catch {
                self.resumption_decision_observer.notify(.fatal);
                return self.failCredential(.provider_internal_failure);
            };
            defer resolved.deinit();
            if (resolved == .miss) continue;
            saw_resolved = true;
            var hit = &resolved.hit;

            // #366: 0-RTT may only be attempted against the first offered
            // identity (wire index 0) — never reordered/probed for a later
            // early-capable identity.
            const wants_early = self.client_hello_early_data_seen and attempts == 0;
            const candidate_ctx: session.CandidateContext = .{
                .cipher_suite = self.negotiated_cipher_suite,
                .server_name = self.serverNameSlice(),
                .application_protocol = self.selectedAlpn(),
                .auth_binding = current_binding,
                .transport_compat = if (self.resume_compat.transport == .exact) self.candidateTransportCompat() else null,
                .application_compat = if (self.resume_compat.application == .exact) self.candidateApplicationCompat() else null,
                .want_early_data = wants_early,
            };
            const decision = session.evaluateCompatibility(&hit.state.common, candidate_ctx, now);
            if (decision.resumption != .eligible) {
                saw_incompatible = true;
                continue;
            }

            const psk_slice = hit.state.common.resumption_psk.slice();
            if (psk_slice.len != hash_len) return error.InvalidHandshakeState;
            var psk_buf: [hash_len]u8 = undefined;
            defer crypto.secureZero(u8, &psk_buf);
            @memcpy(&psk_buf, psk_slice);

            const ok = pre_shared_key.verifyBinder(.sha256, &psk_buf, truncated_prefix, pair.binder) catch
                return error.InvalidHandshakeState;
            if (!ok) {
                self.resumption_decision_observer.notify(.fatal);
                return error.DecryptError; // fatal: never probe a later identity
            }

            // #362: surface the ticket-age skew observation for #366 — skew
            // alone never rejects this 1-RTT resumption.
            const age_skew = pre_shared_key.observeAgeSkew(
                pair.identity.obfuscated_ticket_age,
                hit.state.ticket_age_add,
                elapsedMillis(now, hit.state.common.issued_at_unix_ms),
            );
            self.last_psk_age_skew = age_skew;

            // #366: the live 0-RTT decision, made here (not from
            // `takePskAgeSkew`/`takeSelectedServerPsk`, which intentionally
            // release state only after handshake commit — too late for
            // first-flight data) and only after binder verification, so an
            // early-data rejection never rejects an otherwise-valid PSK
            // resumption.
            const early_decision = self.decideServerEarlyData(.{
                .selected_index = attempts,
                .compatibility = decision.early_data,
                .age_skew = age_skew,
            });
            self.early_data_decision = early_decision;
            self.early_data_accepted = early_decision == .accepted;
            if (early_decision == .accepted) {
                var client_hello_hash: [hash_len]u8 = undefined;
                Sha256.hash(capture.message[0..capture.message_len], &client_hello_hash, .{});

                var early = KeySchedule.clientEarlyTrafficSecret(&psk_buf, client_hello_hash);
                defer crypto.secureZero(u8, &early);

                // The server never emits a 0-RTT *write* key; server
                // responses always use 1-RTT keys.
                try self.emitSecret(sink, .zero_rtt, .read, &early);
            }

            if (hit.on_selected) |hook| hook.complete();
            hit.lease.commit();
            self.selected_server_psk.state.moveFrom(&hit.state);
            self.selected_server_psk.index = @intCast(attempts);
            self.selected_server_psk_present = true;
            self.resumption_decision_observer.notify(.accepted);
            return .{ .index = attempts, .psk = psk_buf, .early_data = early_decision };
        }
        if (attempts > 0) {
            self.resumption_decision_observer.notify(if (saw_incompatible)
                .incompatible
            else if (saw_resolved)
                .full_handshake
            else
                .miss);
        }
        return null;
    }

    const ServerEarlyDataInputs = struct {
        selected_index: usize,
        compatibility: session.EarlyDataEligibility,
        age_skew: pre_shared_key.AgeSkew,
    };

    /// #366: the server's live 0-RTT decision for the just-selected,
    /// binder-verified candidate. `inputs.compatibility` already reflects
    /// `client_hello_early_data_seen`/identity-0/ticket-capability via
    /// `session.evaluateCompatibility`'s `want_early_data`; resource
    /// admission (byte/request caps) is a composition-root concern layered
    /// on top of this backend and is never produced here.
    fn decideServerEarlyData(self: *Tls13Backend, inputs: ServerEarlyDataInputs) EarlyDataDecision {
        if (!self.client_hello_early_data_seen) return .not_attempted;
        if (!self.server_early_data_policy.enabled) return .disabled;
        if (inputs.selected_index != 0) return .selected_identity_not_zero;
        switch (inputs.compatibility) {
            // Reached only for the selected (already resumption-eligible)
            // candidate, so `.incompatible` (which `evaluateCompatibility`
            // only produces when resumption itself is ineligible) cannot
            // actually occur here; `.disabled` is the real "ticket is
            // resume-only" case for an identity-0, early_data-requesting
            // candidate.
            .disabled, .incompatible => return .ticket_not_capable,
            .allowed => {},
        }
        if (!skewWithinTolerance(inputs.age_skew.skew_ms, self.server_early_data_policy.age_skew_tolerance_ms))
            return .age_skew;
        return switch (self.early_data_replay_gate.decide(.{ .selected_identity = @intCast(inputs.selected_index) })) {
            .allow => .accepted,
            .replay => .replay_rejected,
            .unavailable => .replay_unavailable,
        };
    }

    fn candidateTransportCompat(self: *const Tls13Backend) ?session.CandidateCompat {
        if (self.peer_transport_extension_len == 0) return null;
        const ext_type = self.profile.extensionType() orelse return null;
        return .{
            .format_id = ext_type,
            .format_version = 1,
            .bytes = self.peer_transport_extension[0..self.peer_transport_extension_len],
        };
    }

    /// PSK-resumed server flight: EncryptedExtensions straight to Finished —
    /// no CertificateRequest, Certificate, or CertificateVerify (RFC 8446
    /// §4.2.11, resumption-PSK-only profile).
    fn emitPskFinishFlight(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        var buf: [max_message_len]u8 = undefined;
        var w = Writer{ .buf = &buf };
        try w.u8_(@intFromEnum(MessageType.encrypted_extensions));
        const ee_len = try w.reserve(3);
        const ee_extensions = try w.reserve(2);
        if (self.selectedAlpn()) |negotiated_alpn| {
            try w.u16_(ext_alpn);
            const alpn_ext_len = try w.reserve(2);
            const alpn_list_len = try w.reserve(2);
            try w.u8_(@intCast(negotiated_alpn.len));
            try w.bytes(negotiated_alpn);
            w.patch(2, alpn_list_len);
            w.patch(2, alpn_ext_len);
        }
        if (self.profile.extensionType()) |extension_type| {
            const payload = self.profile.localExtension() orelse return error.MissingTransportExtension;
            try w.u16_(extension_type);
            try w.u16_(@intCast(payload.len));
            try w.bytes(payload);
        }
        // #366: signal 0-RTT acceptance with an empty `early_data`
        // extension — omitted (not merely absent-with-a-flag) for a
        // PSK-resumed but early-rejected connection, so the client's
        // omission-based rejection check has something concrete to check.
        if (self.early_data_decision == .accepted) {
            try w.u16_(ext_early_data);
            try w.u16_(0);
        }
        w.patch(2, ee_extensions);
        w.patch(3, ee_len);
        self.core.recordSent(buf[0..w.len]) catch |err| return mapCoreError(err);
        try sink.emitCrypto(.handshake, buf[0..w.len]);

        const schedule = &self.schedule.?;
        var fbuf: [handshake_header_len + hash_len]u8 = undefined;
        var fw = Writer{ .buf = &fbuf };
        try fw.u8_(@intFromEnum(MessageType.finished));
        const finished_len = try fw.reserve(3);
        var server_verify = KeySchedule.verifyData(&schedule.server_handshake_traffic, self.core.transcriptHash());
        defer crypto.secureZero(u8, &server_verify);
        try fw.bytes(&server_verify);
        fw.patch(3, finished_len);
        const finished = fbuf[0..fw.len];
        self.core.recordSent(finished) catch |err| return mapCoreError(err);
        try sink.emitCrypto(.handshake, finished);

        const finished_hash = self.core.transcriptHash();
        var app = schedule.applicationSecrets(finished_hash);
        defer app.wipe();
        try self.emitSecret(sink, .application, .read, &app.client);
        try self.emitSecret(sink, .application, .write, &app.server);
    }

    /// Validate the selected credential, emit EncryptedExtensions+Certificate,
    /// then sign CertificateVerify — synchronously, or by parking a pending
    /// signer. On any failure the handle is released exactly once.
    /// `certificate_message_len` is `inspectSelectedServerCredential`'s
    /// already-complete validation of `credential` (every chain entry, not
    /// only the leaf, and the aggregate encoded size) — the single source
    /// of truth for whether this credential is acceptable at all, shared
    /// with the PSK path so neither validates it more weakly than the
    /// other.
    fn emitServerAuthFlight(
        self: *Tls13Backend,
        credential: credentials.SelectedCredential,
        certificate_message_len: usize,
        sink: *EventSink,
    ) HandshakeError!void {
        var owned = true;
        errdefer if (owned) credential.release();

        const chain = credential.certificateChain();
        var buf: [max_message_len]u8 = undefined;
        var w = Writer{ .buf = &buf };

        // EncryptedExtensions: selected ALPN plus the profile's opaque
        // transport extension, when one is configured.
        try w.u8_(@intFromEnum(MessageType.encrypted_extensions));
        const ee_len = try w.reserve(3);
        const ee_extensions = try w.reserve(2);
        if (self.selectedAlpn()) |negotiated_alpn| {
            try w.u16_(ext_alpn);
            const alpn_ext_len = try w.reserve(2);
            const alpn_list_len = try w.reserve(2);
            try w.u8_(@intCast(negotiated_alpn.len));
            try w.bytes(negotiated_alpn);
            w.patch(2, alpn_list_len);
            w.patch(2, alpn_ext_len);
        }
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
            try w.u16_(@intCast(2 + 2 * self.policy.signature_schemes.len)); // extension_data length
            try w.u16_(@intCast(2 * self.policy.signature_schemes.len)); // supported_signature_algorithms list length
            for (self.policy.signature_schemes) |scheme| {
                try w.u16_(@intFromEnum(scheme));
            }
            w.patch(2, cr_exts);
            w.patch(3, cr_len);
            certificate_request = buf[cr_start..w.len];
        }

        // Exact whole-flight preflight: EncryptedExtensions and the optional
        // CertificateRequest are now serialized (`w.len`); confirm the remaining
        // Certificate message also fits before any state mutation, so a provider
        // chain can never overflow the writer after `requestClientCertificate`,
        // a `recordSent`, output emission, or signing. A provider-caused
        // overflow is a malformed local chain.
        const flight_len = std.math.add(usize, w.len, certificate_message_len) catch
            return self.failCredential(.malformed_credential_chain);
        if (flight_len > max_message_len)
            return self.failCredential(.malformed_credential_chain);

        // Ask the client to authenticate (handshake-time client auth, #334)
        // before recording the flight, so the Core inserts CertificateRequest
        // after EncryptedExtensions and expects the client certificate flight
        // after the server Finished.
        if (self.client_auth != .disabled) self.core.requestClientCertificate();

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
        // The client Finished MAC is (re)computed when the client Finished
        // arrives, over the transcript actually preceding it — which, under
        // handshake-time client authentication, includes the client's own
        // Certificate and CertificateVerify. See `onClientFinished`.
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

    /// Poll a parked authentication operation. When nothing is parked this is a
    /// safe no-op (the documented `transport.Backend.resumeAuth` contract: a
    /// caller may call it opportunistically). When it is still pending this is
    /// also a no-op; when it completes the handshake resumes exactly where it
    /// suspended, recording no handshake message twice; when it fails the typed
    /// failure is latched.
    pub fn resumeAuth(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        // A no-op when nothing is parked or the operation is still pending
        // (both ordinary, non-error returns below); fires on the operation's
        // own failure and on any terminal error from resuming into
        // `dispatchResume`/`drainInput`.
        errdefer self.clearFailedHandshakeState();
        const op = self.pending_op orelse return;
        const stage = self.pending_stage;
        var completion: credentials.Completion = undefined;
        const done = op.poll(&completion) catch |err| {
            // `poll` returning an error means the operation has already
            // terminated (per its documented contract), so it must not be
            // cancelled — `cancel` is for abandoning an operation that has not
            // yet resolved. Release it (and any held signing credential)
            // exactly once, then classify the typed callback failure: an
            // `InvalidCallbackBehavior` is a distinct, stage-independent
            // contract violation, never conflated with an ordinary operation
            // failure.
            op.release();
            self.pending_op = null;
            if (self.pending_credential) |credential| {
                credential.release();
                self.pending_credential = null;
            }
            // #362: a pending operation's own failure never reaches
            // `emitServerHelloAndAuthFlight` (whose `defer` would otherwise
            // clear this), so any captured server-side PSK offer state is
            // wiped here explicitly. A no-op for every non-`server_select`
            // stage, and for a connection that never offered PSK.
            self.clearClientHelloPsk();
            return self.failCredential(switch (err) {
                error.InvalidCallbackBehavior => .invalid_callback_behavior,
                error.OperationFailed => pendingFailureClass(stage),
            });
        };
        if (!done) return; // still pending; the driver polls again later
        op.release();
        self.pending_op = null;
        try self.dispatchResume(stage, completion, sink);

        // Drain buffered input in protocol order once the resume itself did not
        // re-park or fail. A parked operation may have suspended while draining
        // either buffer — server credential selection/signing while processing
        // the ClientHello in `initial_input`, or client selection/signing and
        // peer verification while processing the handshake flight in
        // `handshake_input` — and further bytes for either epoch may have
        // arrived and been buffered (not just coalesced within the same
        // message) while it was pending. Draining both, in protocol order,
        // guarantees every accepted transport byte is eventually parsed or
        // deterministically rejected rather than silently ignored.
        if (self.pending_op == null and self.core.handshake_lifecycle == .running)
            try self.drainInput(&self.initial_input, .initial, sink);
        if (self.pending_op == null and self.core.handshake_lifecycle == .running)
            try self.drainInput(&self.handshake_input, .handshake, sink);
    }

    /// Continue the suspended stage from its completion value. Each arm resumes
    /// exactly where the synchronous path would have continued, recording no
    /// handshake message twice.
    fn dispatchResume(self: *Tls13Backend, stage: PendingStage, completion: credentials.Completion, sink: *EventSink) HandshakeError!void {
        switch (stage) {
            .server_select => switch (completion) {
                .credential => |c| {
                    if (!self.pending_client_hello_ready) {
                        c.release();
                        self.clearClientHelloPsk();
                        return error.InvalidHandshakeState;
                    }
                    const session_id = self.pending_client_session_id[0..self.pending_client_session_id_len];
                    const client_share = self.pending_client_share;
                    self.pending_client_hello_ready = false;
                    self.pending_client_session_id_len = 0;
                    // `emitServerHelloAndAuthFlight` itself clears the PSK
                    // capture (on every path) before returning, so this is
                    // the exact same #362 selection this stage would have
                    // reached synchronously — the captured ClientHello
                    // (`client_hello_psk`) is backend-owned state, not tied
                    // to the transient reassembly buffer that already
                    // discarded the raw bytes when `onClientHello` returned.
                    return self.emitServerHelloAndAuthFlight(session_id, client_share, c, sink);
                },
                // Unlike the client, the server MUST authenticate itself in
                // this profile: "no credential" from an async selector is the
                // same normal-but-unusable outcome the synchronous path reports
                // via `NoCredentialAvailable`/`NoCompatibleSignatureAlgorithm`
                // (`NoApplicableCredential`/handshake_failure), not a provider
                // fault. `Completion.no_credential` does not distinguish
                // "unavailable" from "incompatible", so both collapse to the
                // single canonical class here; the wire alert is unaffected.
                .no_credential => {
                    self.clearClientHelloPsk();
                    return self.failCredential(.no_credential_available);
                },
                else => {
                    releaseCompletionCredentials(completion, null);
                    self.clearClientHelloPsk();
                    return self.failCredential(.invalid_callback_behavior);
                },
            },
            .client_select => switch (completion) {
                .credential => |c| return self.emitSelectedClientCertificate(c, sink),
                // A selector that resolved to "no credential" declines with an
                // empty Certificate, exactly like the synchronous path.
                .no_credential => return self.emitClientCertificate(null, certificate_message_overhead, sink),
                else => {
                    releaseCompletionCredentials(completion, null);
                    return self.failCredential(.invalid_callback_behavior);
                },
            },
            .server_sign, .client_sign => {
                // Take the signing credential now so it is released on every
                // path — including a malformed (wrong-kind) completion.
                const held = self.pending_credential;
                self.pending_credential = null;
                if (completion != .signature_len) {
                    releaseCompletionCredentials(completion, held);
                    return self.failCredential(.invalid_callback_behavior);
                }
                const credential = held orelse return error.InvalidHandshakeState;
                return switch (stage) {
                    .server_sign => self.serverFinishFlight(credential, completion.signature_len, sink),
                    .client_sign => self.finishClientAuthFlight(credential, completion.signature_len, sink),
                    else => unreachable,
                };
            },
            .peer_verify => switch (completion) {
                .verdict => |v| return self.applyPeerVerdict(v, sink),
                else => {
                    releaseCompletionCredentials(completion, null);
                    return self.failCredential(.invalid_callback_behavior);
                },
            },
        }
    }

    /// Release the credential handles owned by a rejected completion and/or a
    /// held signing credential exactly once each, deduping when both aliases
    /// refer to the same provider handle (a malformed callback may hand back the
    /// very credential the engine already holds).
    fn releaseCompletionCredentials(completion: credentials.Completion, held: ?credentials.SelectedCredential) void {
        var from_completion: ?credentials.SelectedCredential = switch (completion) {
            .credential => |c| c,
            else => null,
        };
        if (held) |h| {
            h.release();
            if (from_completion) |c| {
                if (c.handle == h.handle) from_completion = null;
            }
        }
        if (from_completion) |c| c.release();
    }

    /// The failure class for a pending operation that reported an error, by
    /// the stage it was resolving.
    fn pendingFailureClass(stage: PendingStage) CredentialFailure {
        return switch (stage) {
            .server_select, .client_select => .provider_internal_failure,
            .server_sign, .client_sign => .signing_provider_failure,
            .peer_verify => .verifier_internal_failure,
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

    fn onClientFinished(self: *Tls13Backend, transcript_before: [hash_len]u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        const schedule = &self.schedule.?;
        if (body.len != hash_len) return error.MalformedHandshake;
        // Recompute over the transcript that actually precedes this Finished:
        // with handshake-time client authentication it includes the client's
        // Certificate and CertificateVerify, so the MAC cannot be fixed when the
        // server flight was sent.
        var expected = KeySchedule.verifyData(&schedule.client_handshake_traffic, transcript_before);
        defer crypto.secureZero(u8, &expected);
        if (!crypto.timing_safe.eql([hash_len]u8, expected, body[0..hash_len].*)) return error.DecryptError;
        // Client Finished confirms the handshake for the server (RFC 8446 §4.4.4).
        try self.captureResumptionMasterSecret();
        try self.emitDiscardKeys(sink, .handshake);
        try sink.emitHandshakeComplete();
        self.finish();
        // Only now — every terminal fallible step above has succeeded — is
        // this handshake actually committed. See `clearFailedHandshakeState`.
        self.handshake_committed = true;
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

    fn captureResumptionMasterSecret(self: *Tls13Backend) HandshakeError!void {
        if (self.resumption_master_secret.slice().len != 0) return error.InvalidHandshakeState;
        const schedule = &(self.schedule orelse return error.InvalidHandshakeState);
        var rms: [hash_len]u8 = undefined;
        defer crypto.secureZero(u8, &rms);
        schedule.resumptionMasterSecret(&self.core.transcriptHash(), &rms) catch return error.SecretExportFailed;
        self.resumption_master_secret.replace(&rms) catch return error.SecretExportFailed;
    }

    fn resumptionContext(self: *const Tls13Backend) new_session_ticket.ConnectionResumptionContext {
        return .{
            .cipher_suite = self.negotiated_cipher_suite,
            .server_name = if (self.server_name_present) self.server_name[0..self.server_name_len] else null,
            .application_protocol = self.selectedAlpn(),
            .auth_binding = self.effectiveAuthBinding(),
            .transport_compat = if (self.resume_compat.transport == .exact) self.peerTransportCompat() else null,
            .application_compat = if (self.resume_compat.application == .exact) self.ownedApplicationCompat() else null,
        };
    }

    fn peerAuthBinding(self: *const Tls13Backend) session.AuthBinding {
        if (self.peer_chain_count == 0) return session.AuthBinding.fromLeafCertificateDer("");
        const leaf = self.peer_chain_entries[0];
        return session.AuthBinding.fromLeafCertificateDer(self.peer_chain[leaf.start..][0..leaf.len]);
    }

    /// #362: the authenticated identity binding for *this* connection, used
    /// both to compare a candidate PSK's stored binding and to stamp any
    /// ticket this connection itself issues/receives.
    ///
    /// For an ordinary full handshake this is exactly `peerAuthBinding()`
    /// (client: the server certificate it verified; server: the client
    /// certificate, if any, from handshake-time client authentication).
    /// A PSK-resumed connection has no Certificate message on either side to
    /// derive that from, so both roles instead stamp
    /// `connection_auth_binding` explicitly: the server from the credential
    /// it validated before PSK selection (`inspectSelectedServerCredential`
    /// — the server's *own* leaf, not the client's), the client from the
    /// selected ticket's stored binding — so a later ticket issued on a
    /// resumed connection still carries the original server-certificate
    /// binding forward instead of silently degrading to the empty sentinel.
    fn effectiveAuthBinding(self: *const Tls13Backend) session.AuthBinding {
        return self.connection_auth_binding orelse self.peerAuthBinding();
    }

    pub const SelectedCredentialInfo = struct {
        /// The exact encoded Certificate message length this chain would
        /// produce (`certificate_message_overhead` + each entry's
        /// `certificate_entry_overhead`-framed size) — reused by
        /// flight emission preflight instead of recomputing it.
        certificate_message_len: usize,
    };

    /// Server (#362): validates the credential selection already performed
    /// for this ClientHello — the same checks `emitServerAuthFlight` applies
    /// before signing — and returns the binding for the server's *own*
    /// leaf certificate. Called unconditionally before PSK selection so a
    /// candidate ticket is compared against the identity this connection
    /// actually authenticates with, not the (normally empty, client-side)
    /// peer chain.
    pub const SelectedServerCredentialInfo = struct {
        binding: session.AuthBinding,
        certificate_message_len: usize,
    };

    fn leafSupportsSignatureScheme(der: []const u8, scheme: credentials.SignatureScheme) HandshakeError!bool {
        const parsed = (Certificate{ .buffer = der, .index = 0 }).parse() catch
            return error.MalformedHandshake;
        return switch (scheme) {
            .ed25519 => parsed.pub_key_algo == .curveEd25519,
            .ecdsa_secp256r1_sha256 => switch (parsed.pub_key_algo) {
                .X9_62_id_ecPublicKey => |curve| curve == .X9_62_prime256v1,
                else => false,
            },
            else => false,
        };
    }

    /// Complete local-provider contract validation for a selected credential,
    /// shared by server authentication and handshake-time client authentication.
    /// This runs before transcript mutation or output emission so callback
    /// violations fail locally without sending a Certificate flight.
    fn inspectSelectedCredential(
        self: *Tls13Backend,
        credential: credentials.SelectedCredential,
    ) HandshakeError!SelectedCredentialInfo {
        const selected = tls_algorithms.fromInt(tls_algorithms.SignatureScheme, credential.scheme.code()) orelse
            return self.failCredential(.invalid_callback_behavior);
        tls_negotiation.validateCredentialSignature(
            self.policy,
            self.peer_sig_schemes[0..self.peer_sig_scheme_count],
            selected,
        ) catch return self.failCredential(.invalid_callback_behavior);

        const chain = credential.certificateChain();
        if (chain.count() == 0 or chain.count() > credentials.max_chain_entries)
            return self.failCredential(.malformed_credential_chain);
        if (!(leafSupportsSignatureScheme(chain.entries[0], credential.scheme) catch
            return self.failCredential(.malformed_credential_chain)))
            return self.failCredential(.invalid_callback_behavior);

        var certificate_message_len: usize = certificate_message_overhead;
        for (chain.entries) |entry| {
            if (entry.len == 0 or entry.len > max_certificate_len)
                return self.failCredential(.malformed_credential_chain);
            certificate_message_len = std.math.add(usize, certificate_message_len, entry.len + certificate_entry_overhead) catch
                return self.failCredential(.malformed_credential_chain);
            if (certificate_message_len > max_message_len)
                return self.failCredential(.malformed_credential_chain);
        }

        return .{ .certificate_message_len = certificate_message_len };
    }

    /// Complete validation of the credential selection already performed
    /// for this ClientHello — every chain entry, not just the leaf, and the
    /// aggregate encoded size, exactly as `emitServerAuthFlight` requires
    /// before ever signing. Called unconditionally before PSK selection —
    /// not only along the full-certificate path — so a malformed remaining
    /// chain entry can never be accepted merely because PSK selection later
    /// succeeds and skips the certificate flight entirely.
    fn inspectSelectedServerCredential(
        self: *Tls13Backend,
        credential: credentials.SelectedCredential,
    ) HandshakeError!SelectedServerCredentialInfo {
        const credential_info = try self.inspectSelectedCredential(credential);
        const chain = credential.certificateChain();
        return .{
            .binding = session.AuthBinding.fromLeafCertificateDer(chain.entries[0]),
            .certificate_message_len = credential_info.certificate_message_len,
        };
    }

    fn peerTransportCompat(self: *const Tls13Backend) ?new_session_ticket.CompatBlob {
        if (self.peer_transport_extension_len == 0) return null;
        const ext_type = self.profile.extensionType() orelse return null;
        return .{
            .format_id = ext_type,
            .format_version = 1,
            .bytes = self.peer_transport_extension[0..self.peer_transport_extension_len],
        };
    }

    /// #488 two-phase issuance, step 1: derives the RMS-bound PSK and the
    /// exact `ServerRecoverableState` a stateful insertion or stateless seal
    /// will consume, without requiring the opaque bearer identity that only
    /// exists once one of those two issuance paths has actually run.
    /// Runtime code must not rederive the PSK from this connection a second
    /// time — call `emitPreparedNewSessionTicket` with the resulting
    /// identity to finish issuance, then `prepared.deinit()` unconditionally.
    pub const PreparedNewSessionTicket = struct {
        state: session.ServerRecoverableState = .{},
        ticket_lifetime: u32 = 0,
        ticket_age_add: u32 = 0,
        ticket_nonce_buf: [new_session_ticket.max_ticket_nonce_len]u8 = undefined,
        ticket_nonce_len: u8 = 0,
        max_early_data_size: ?u32 = null,

        pub fn ticketNonce(self: *const PreparedNewSessionTicket) []const u8 {
            return self.ticket_nonce_buf[0..self.ticket_nonce_len];
        }

        /// Safe to call unconditionally, including after a successful
        /// `emitPreparedNewSessionTicket` whose stateful path already moved
        /// `state` away (leaving it zero-valued and this a no-op).
        pub fn deinit(self: *PreparedNewSessionTicket) void {
            self.state.deinit();
            crypto.secureZero(u8, &self.ticket_nonce_buf);
            self.* = undefined;
        }
    };

    pub const PrepareNewSessionTicketParams = struct {
        ticket_lifetime: u32,
        ticket_age_add: u32,
        ticket_nonce: []const u8,
        max_early_data_size: ?u32 = null,
        issued_at_unix_ms: i64,
    };

    pub fn prepareNewSessionTicket(
        self: *Tls13Backend,
        allocator: std.mem.Allocator,
        params: PrepareNewSessionTicketParams,
        limits: session.Limits,
    ) HandshakeError!PreparedNewSessionTicket {
        if (self.role != .server or self.core.handshake_lifecycle != .complete)
            return error.InvalidHandshakeState;
        if (self.resumption_master_secret.slice().len == 0)
            return error.InvalidHandshakeState;
        limits.validate() catch return error.InvalidTransportProfile;
        if (params.ticket_nonce.len > new_session_ticket.max_ticket_nonce_len)
            return error.IllegalParameter;

        const state = new_session_ticket.buildServerRecoverableStateNoIdentity(
            allocator,
            .{
                .ticket_lifetime = params.ticket_lifetime,
                .ticket_age_add = params.ticket_age_add,
                .ticket_nonce = params.ticket_nonce,
                .max_early_data_size = params.max_early_data_size,
            },
            self.resumptionContext(),
            self.resumption_master_secret.slice(),
            params.issued_at_unix_ms,
            limits,
        ) catch |err| return mapTicketBuildServerError(err);

        var prepared: PreparedNewSessionTicket = .{
            .state = state,
            .ticket_lifetime = params.ticket_lifetime,
            .ticket_age_add = params.ticket_age_add,
            .max_early_data_size = params.max_early_data_size,
        };
        prepared.ticket_nonce_len = @intCast(params.ticket_nonce.len);
        @memcpy(prepared.ticket_nonce_buf[0..prepared.ticket_nonce_len], params.ticket_nonce);
        return prepared;
    }

    /// #488 two-phase issuance, step 2: encodes and emits the
    /// `NewSessionTicket` message carrying `identity` — the exact bearer
    /// identity (stateful handle or stateless envelope) produced from
    /// `prepared.state` — through the existing application-epoch record
    /// path. Does not consume or clear `prepared`; the caller still owns it
    /// and must `deinit` it afterward regardless of outcome.
    pub fn emitPreparedNewSessionTicket(
        self: *Tls13Backend,
        allocator: std.mem.Allocator,
        sink: *EventSink,
        prepared: *const PreparedNewSessionTicket,
        identity: []const u8,
        limits: session.Limits,
    ) HandshakeError!void {
        if (self.role != .server or self.core.handshake_lifecycle != .complete)
            return error.InvalidHandshakeState;
        if (identity.len == 0 or identity.len > limits.max_ticket_len) return error.TicketTooLarge;

        const emit_params: new_session_ticket.EmitParams = .{
            .ticket_lifetime = prepared.ticket_lifetime,
            .ticket_age_add = prepared.ticket_age_add,
            .ticket_nonce = prepared.ticketNonce(),
            .ticket = identity,
            .max_early_data_size = prepared.max_early_data_size,
        };
        const body_len = new_session_ticket.encodedLen(emit_params) catch |err| return mapTicketEncodeError(err);
        if (body_len > max_new_session_ticket_message_len - 4) return error.TransportBufferOverflow;
        const message_len = handshake_header_len + body_len;

        const buf = allocator.alloc(u8, message_len) catch return error.CredentialProviderFailed;
        errdefer {
            crypto.secureZero(u8, buf);
            allocator.free(buf);
        }
        var w = Writer{ .buf = buf };
        try w.u8_(@intFromEnum(MessageType.new_session_ticket));
        const body_len_index = try w.reserve(3);
        const body = new_session_ticket.encode(emit_params, buf[w.len..]) catch |err| return mapTicketEncodeError(err);
        w.len += body.len;
        w.patch(3, body_len_index);
        const message = buf[0..w.len];
        try sink.emitOwnedCrypto(allocator, .application, message);
        self.core.transcript.update(message);
    }

    /// Single-phase issuance, retained for callers (and tests) that already
    /// know the final bearer identity before deriving connection state.
    /// New production issuance paths should prefer `prepareNewSessionTicket`
    /// / `emitPreparedNewSessionTicket` (#488) so the identity can be
    /// derived from the exact state this produces.
    pub fn emitNewSessionTicket(
        self: *Tls13Backend,
        allocator: std.mem.Allocator,
        sink: *EventSink,
        params: EmitNewSessionTicketParams,
        limits: session.Limits,
    ) HandshakeError!session.ServerRecoverableState {
        var prepared = try self.prepareNewSessionTicket(allocator, .{
            .ticket_lifetime = params.ticket_lifetime,
            .ticket_age_add = params.ticket_age_add,
            .ticket_nonce = params.ticket_nonce,
            .max_early_data_size = params.max_early_data_size,
            .issued_at_unix_ms = params.issued_at_unix_ms,
        }, limits);
        errdefer prepared.deinit();
        try self.emitPreparedNewSessionTicket(allocator, sink, &prepared, params.opaque_ticket, limits);
        return prepared.state;
    }

    /// The handshake is over: the transport sink owns every exported live
    /// secret, so wipe the engine's key schedule immediately.
    fn finish(self: *Tls13Backend) void {
        if (self.schedule) |*schedule| schedule.wipe();
        self.schedule = null;
        crypto.secureZero(u8, &self.expected_client_verify);
    }
};

/// Overflow-safe elapsed time in milliseconds since `issued_ms`, saturating
/// to zero for a not-yet-valid/clock-skewed candidate rather than trapping
/// or wrapping, computed in `i128` regardless of how close either input is
/// to the `i64` extremes.
fn elapsedMillis(now_ms: i64, issued_ms: i64) u64 {
    const delta: i128 = @as(i128, now_ms) - @as(i128, issued_ms);
    if (delta <= 0) return 0;
    return @intCast(@min(delta, @as(i128, std.math.maxInt(u64))));
}

/// #366: overflow-safe `|skew_ms| <= tolerance_ms`. The `i128` promotion is
/// deliberate: `-minInt(i64)` must not trap.
fn skewWithinTolerance(skew_ms: i64, tolerance_ms: u64) bool {
    const magnitude: u64 = if (skew_ms < 0)
        @intCast(-@as(i128, skew_ms))
    else
        @intCast(skew_ms);
    return magnitude <= tolerance_ms;
}

/// Symmetric optional equality for a stored `CompatSnapshot` against a
/// candidate `CandidateCompat`, mirroring `session.zig`'s own (private)
/// `compatSnapshotMatches`: a snapshot with none stored only matches a
/// candidate that also supplies none.
fn compatCompatible(stored: ?session.CompatSnapshot, candidate: ?session.CandidateCompat) bool {
    if (stored) |*s| {
        const c = candidate orelse return false;
        return s.format_id == c.format_id and s.format_version == c.format_version and std.mem.eql(u8, s.slice(), c.bytes);
    }
    return candidate == null;
}

fn mapPskReadError(err: pre_shared_key.ReadError) HandshakeError {
    return switch (err) {
        error.MalformedHandshake, error.EmptyIdentity, error.InvalidBinderLength, error.EmptyVector => error.MalformedHandshake,
        error.CountMismatch => error.IllegalParameter,
    };
}

fn mapTicketDecodeError(err: new_session_ticket.DecodeError) HandshakeError {
    return switch (err) {
        error.MalformedHandshake => error.MalformedHandshake,
        error.IllegalParameter => error.IllegalParameter,
    };
}

fn mapTicketEncodeError(err: new_session_ticket.EncodeError) HandshakeError {
    return switch (err) {
        error.IllegalParameter => error.IllegalParameter,
        error.OutputTooSmall, error.LengthOverflow => error.TransportBufferOverflow,
    };
}

fn mapTicketBuildServerError(err: new_session_ticket.BuildServerError) HandshakeError {
    return switch (err) {
        error.IllegalParameter => error.IllegalParameter,
        error.InvalidSecretLength => error.SecretExportFailed,
        error.TicketTooLarge => error.TicketTooLarge,
        error.InvalidLimits => error.InvalidTransportProfile,
        error.OutOfMemory => error.CredentialProviderFailed,
        error.InvalidDnsName,
        error.EmptyServerName,
        error.AlpnProtocolTooLarge,
        error.EmptyApplicationProtocol,
        error.InvalidPskLength,
        error.InvalidLifetime,
        error.InvalidEarlyDataPolicy,
        error.CompatSnapshotTooLarge,
        => error.InvalidTransportProfile,
    };
}

fn mapTicketBuildClientError(err: new_session_ticket.BuildError) HandshakeError!void {
    return switch (err) {
        error.OutOfMemory,
        error.TicketTooLarge,
        error.CompatSnapshotTooLarge,
        => {},
        error.InvalidSecretLength,
        error.InvalidPskLength,
        => error.SecretExportFailed,
        error.InvalidLimits,
        error.InvalidDnsName,
        error.EmptyServerName,
        error.AlpnProtocolTooLarge,
        error.EmptyApplicationProtocol,
        error.NonceTooLarge,
        error.InvalidLifetime,
        error.InvalidEarlyDataPolicy,
        => error.InvalidTransportProfile,
    };
}

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

fn buildMaxNewSessionTicketMessage(allocator: std.mem.Allocator) ![]u8 {
    const body_len = max_new_session_ticket_message_len - 4;
    var message = try allocator.alloc(u8, max_new_session_ticket_message_len);
    errdefer allocator.free(message);
    var pos: usize = 0;
    message[pos] = @intFromEnum(MessageType.new_session_ticket);
    pos += 1;
    std.mem.writeInt(u24, message[pos..][0..3], @intCast(body_len), .big);
    pos += 3;
    std.mem.writeInt(u32, message[pos..][0..4], 1, .big);
    pos += 4;
    std.mem.writeInt(u32, message[pos..][0..4], 0, .big);
    pos += 4;
    message[pos] = session.max_ticket_nonce_len;
    pos += 1;
    @memset(message[pos..][0..session.max_ticket_nonce_len], 0x01);
    pos += session.max_ticket_nonce_len;
    std.mem.writeInt(u16, message[pos..][0..2], @intCast(session.absolute_ticket_wire_max), .big);
    pos += 2;
    @memset(message[pos..][0..session.absolute_ticket_wire_max], 0xa5);
    pos += session.absolute_ticket_wire_max;
    std.mem.writeInt(u16, message[pos..][0..2], std.math.maxInt(u16) - 1, .big);
    pos += 2;

    var written: usize = 0;
    var ext_id: u16 = 1000;
    while (written + 4 <= (std.math.maxInt(u16) - 1) - 6) : ({
        written += 4;
        ext_id += 1;
    }) {
        std.mem.writeInt(u16, message[pos..][0..2], ext_id, .big);
        pos += 2;
        std.mem.writeInt(u16, message[pos..][0..2], 0, .big);
        pos += 2;
    }
    std.mem.writeInt(u16, message[pos..][0..2], ext_id, .big);
    pos += 2;
    std.mem.writeInt(u16, message[pos..][0..2], 2, .big);
    pos += 2;
    message[pos] = 0xaa;
    message[pos + 1] = 0xbb;
    pos += 2;
    written += 6;
    std.debug.assert(written == std.math.maxInt(u16) - 1);
    std.debug.assert(pos == message.len);
    return message;
}

/// Deterministic local server identity fixture — see `credentials.testdata`.
/// Re-exported here so existing callers and tests keep their spelling.
pub const testdata = credentials.testdata;

test "TLS-owned backend does not embed maximum ticket storage" {
    try std.testing.expect(@sizeOf(Tls13Backend) < 64 * 1024);
    try std.testing.expect(@sizeOf(Tls13Backend) + EventSink.max_bytes < max_new_session_ticket_message_len);
}

test "TLS-owned backend teardown clears transcript-adjacent and peer scratch" {
    var backend = Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0x41} ** 32, .key_share_seed = [_]u8{0x42} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .record,
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
    const oversized_alpn = [_]u8{'a'} ** 256;
    const invalid_alpn_sets = [_][]const tls_algorithms.ProtocolName{
        &.{.{ .bytes = "" }},
        &.{.{ .bytes = &oversized_alpn }},
        &.{ .{ .bytes = "h2" }, .{ .bytes = "h2" } },
        &.{},
    };
    for (invalid_alpn_sets) |alpns| {
        var policy = tls_policy.Policy.recordH2Only();
        policy.alpn_protocols = alpns;
        var backend = Tls13Backend.initClientConfigured(
            entropy,
            .{ .pinned_certificate = testdata.certificate_der },
            recordConfig(policy),
            .{},
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

    var names_storage: [40][255]u8 = undefined;
    var names: [40][]const u8 = undefined;
    for (&names_storage, 0..) |*name, i| {
        @memset(name[0..], 'a');
        name[0] = @intCast(i);
        names[i] = name[0..];
    }
    var too_large_policy = tls_policy.Policy.recordDefault();
    var too_large_alpns: [names.len]tls_algorithms.ProtocolName = undefined;
    for (names, 0..) |name, i| too_large_alpns[i] = .{ .bytes = name };
    too_large_policy.alpn_protocols = &too_large_alpns;
    var too_large_backend = Tls13Backend.initClientConfigured(
        entropy,
        .{ .pinned_certificate = testdata.certificate_der },
        recordConfig(too_large_policy),
        .{},
    );
    var too_large_sink = EventSink{};
    defer too_large_sink.deinit();
    try std.testing.expectError(error.InvalidTransportProfile, too_large_backend.backend().start(.client, {}, &too_large_sink));

    var near_storage: [32][255]u8 = undefined;
    var near_names: [32][]const u8 = undefined;
    for (near_storage[0..31], 0..) |*name, i| {
        @memset(name[0..], 'a');
        name[0] = @intCast('A' + i);
        near_names[i] = name[0..];
    }
    @memset(near_storage[31][0..], 'b');
    near_storage[31][0] = 'z';
    near_names[31] = near_storage[31][0..139];
    var near_policy = tls_policy.Policy.recordDefault();
    var near_alpns: [near_names.len]tls_algorithms.ProtocolName = undefined;
    for (near_names, 0..) |name, i| near_alpns[i] = .{ .bytes = name };
    near_policy.alpn_protocols = &near_alpns;
    var near_backend = Tls13Backend.initClientConfigured(
        entropy,
        .{ .pinned_certificate = testdata.certificate_der },
        recordConfig(near_policy),
        .{},
    );
    var near_sink = EventSink{};
    defer near_sink.deinit();
    try std.testing.expectError(error.InvalidTransportProfile, near_backend.backend().start(.client, {}, &near_sink));
    try std.testing.expectEqual(tls_handshake_codec.HandshakeLifecycle.idle, near_backend.core.handshake_lifecycle);
    try std.testing.expect(!near_backend.key_pair_present);
    near_backend.deinit();

    var oversized = [_]u8{0xa5} ** (max_transport_extension_len + 1);
    var extension_backend = Tls13Backend.initClient(
        entropy,
        .{ .pinned_certificate = testdata.certificate_der },
        .{ .extension = .{ .extension_type = 57, .local = &oversized } },
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
        .{ .extension = .{ .extension_type = ext_supported_versions, .local = "valid" } },
    );
    var collision_sink = EventSink{};
    defer collision_sink.deinit();
    try std.testing.expectError(error.InvalidTransportProfile, collision_backend.backend().start(.client, {}, &collision_sink));
    try std.testing.expectEqual(tls_handshake_codec.HandshakeLifecycle.idle, collision_backend.core.handshake_lifecycle);
    try std.testing.expectEqual(@as(usize, 0), collision_sink.len);
    collision_backend.deinit();
}

test "client rejects malformed encrypted extensions ALPN framing" {
    var backend = Tls13Backend.initClient(
        Entropy{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x52} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .record,
    );
    defer backend.deinit();

    var sink = EventSink{};
    defer sink.deinit();

    const empty_list = [_]u8{
        0x00, 0x06, // extensions length
        0x00, ext_alpn, // extension type
        0x00, 0x02, // extension length
        0x00, 0x00, // empty ProtocolNameList
    };
    try std.testing.expectError(error.MalformedHandshake, backend.onEncryptedExtensions(&empty_list, &sink));

    const trailing_extension_byte = [_]u8{
        0x00, 0x0a, // extensions length
        0x00, ext_alpn, // extension type
        0x00, 0x06, // extension length
        0x00, 0x03, // ProtocolNameList length
        0x02, 'h',
        '2',
        0x00, // trailing byte outside the declared list
    };
    try std.testing.expectError(error.MalformedHandshake, backend.onEncryptedExtensions(&trailing_extension_byte, &sink));
}

test "client NewSessionTicket callback receives owned state and lifetime zero is dropped" {
    const TicketCapture = struct {
        count: usize = 0,
        received_at: i64 = 123_456,
        last_lifetime: u32 = 0,
        last_age_add: u32 = 0,
        last_ticket: [16]u8 = undefined,
        last_ticket_len: usize = 0,
        last_psk: [hash_len]u8 = undefined,

        fn now(ctx: *anyopaque) i64 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.received_at;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            self.last_lifetime = ticket.common.lifetime_seconds;
            self.last_age_add = ticket.ticket_age_add;
            const raw_ticket = ticket.ticket.slice();
            self.last_ticket_len = raw_ticket.len;
            @memcpy(self.last_ticket[0..raw_ticket.len], raw_ticket);
            @memcpy(&self.last_psk, ticket.common.resumption_psk.slice());
        }
    };

    var capture = TicketCapture{};
    var backend = Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0x41} ** 32, .key_share_seed = [_]u8{0x42} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .record,
    );
    defer backend.deinit();
    try backend.setSessionTicketConsumer(std.testing.allocator, session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = TicketCapture.now,
        .onTicketFn = TicketCapture.onTicket,
    });
    backend.core.handshake_lifecycle = .complete;
    try backend.resumption_master_secret.replace(&([_]u8{0x42} ** hash_len));

    var body_buf: [128]u8 = undefined;
    const body = try new_session_ticket.encode(.{
        .ticket_lifetime = 120,
        .ticket_age_add = 0xaabbccdd,
        .ticket_nonce = "\x01",
        .ticket = "opaque",
    }, &body_buf);
    try backend.onNewSessionTicket(body);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(@as(u32, 120), capture.last_lifetime);
    try std.testing.expectEqual(@as(u32, 0xaabbccdd), capture.last_age_add);
    try std.testing.expectEqualSlices(u8, "opaque", capture.last_ticket[0..capture.last_ticket_len]);
    try std.testing.expect(!std.mem.allEqual(u8, &capture.last_psk, 0));

    const discard_body = try new_session_ticket.encode(.{
        .ticket_lifetime = 0,
        .ticket_age_add = 0,
        .ticket_nonce = "",
        .ticket = "discard",
    }, &body_buf);
    try backend.onNewSessionTicket(discard_body);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
}

test "client parses and drops NewSessionTicket when no consumer is configured" {
    var backend = Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0x45} ** 32, .key_share_seed = [_]u8{0x46} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .record,
    );
    defer backend.deinit();
    try backend.setPostHandshakeAllocator(std.testing.allocator);
    backend.core.handshake_lifecycle = .complete;

    var body_buf: [128]u8 = undefined;
    const body = try new_session_ticket.encode(.{
        .ticket_lifetime = 120,
        .ticket_age_add = 0,
        .ticket_nonce = "\x01",
        .ticket = "drop-me",
    }, &body_buf);
    var msg_buf: [132]u8 = undefined;
    var w = Writer{ .buf = &msg_buf };
    try w.u8_(@intFromEnum(MessageType.new_session_ticket));
    const body_len = try w.reserve(3);
    try w.bytes(body);
    w.patch(3, body_len);
    const message = w.written();
    var sink = EventSink{};
    defer sink.deinit();
    try backend.backend().receive(.application, message[0..5], &sink);
    try backend.backend().receive(.application, message[5..], &sink);
    try std.testing.expectEqual(@as(usize, 0), backend.application_input.len);
    try std.testing.expectEqual(@as(usize, 0), backend.application_input.buf.len);
}

test "post-handshake input rejects allocator replacement while a frame is active" {
    var backing_a: [64]u8 = undefined;
    var backing_b: [64]u8 = undefined;
    var fba_a = std.heap.FixedBufferAllocator.init(&backing_a);
    var fba_b = std.heap.FixedBufferAllocator.init(&backing_b);
    var input = PostHandshakeInput{};
    defer input.deinit();
    try input.setAllocator(fba_a.allocator());

    const prefix = [_]u8{
        @intFromEnum(MessageType.new_session_ticket),
        0,
        0,
        4,
        1,
    };
    try std.testing.expectEqual(prefix.len, try input.append(&prefix));
    try std.testing.expect(input.buf.len > 0);
    try std.testing.expectError(error.InvalidHandshakeState, input.setAllocator(fba_b.allocator()));
    try std.testing.expectEqual(@as(usize, 3), try input.append(&.{ 2, 3, 4 }));
    try input.discard(input.buf.len);
}

test "server explicitly emits NewSessionTicket and returns recoverable state" {
    var server = Tls13Backend.initServer(
        .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x52} ** 32 },
        try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
        .record,
    );
    defer server.deinit();

    var sink = EventSink{};
    defer sink.deinit();
    try std.testing.expectError(error.InvalidHandshakeState, server.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "ticket",
        .issued_at_unix_ms = 10,
    }, session.Limits.default));

    server.core.handshake_lifecycle = .complete;
    try server.resumption_master_secret.replace(&([_]u8{0x33} ** hash_len));
    var state = try server.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "ticket",
        .max_early_data_size = 32,
        .issued_at_unix_ms = 10,
    }, session.Limits.default);
    defer state.deinit();

    try std.testing.expectEqual(@as(usize, 1), sink.len);
    try std.testing.expectEqual(EncryptionLevel.application, sink.items[0].handshake_bytes.epoch);
    const message = try tls_handshake_codec.decode(sink.items[0].handshake_bytes.data);
    try std.testing.expectEqual(MessageType.new_session_ticket, message.kind);
    const parsed = try new_session_ticket.decode(message.body);
    try std.testing.expectEqual(@as(u32, 60), parsed.ticket_lifetime);
    try std.testing.expectEqualSlices(u8, "ticket", parsed.ticket);
    try std.testing.expectEqual(@as(?u32, 32), parsed.max_early_data_size);
    try std.testing.expectEqual(@as(u32, 60), state.common.lifetime_seconds);
    try std.testing.expectEqual(session.EarlyDataPolicy{ .early_data_capable = 32 }, state.common.early_data);
    try std.testing.expect(!std.mem.allEqual(u8, state.common.resumption_psk.slice(), 0));
}

test "prepare/emit two-phase ticket issuance matches single-phase wire output" {
    var server = Tls13Backend.initServer(
        .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x52} ** 32 },
        try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
        .record,
    );
    defer server.deinit();
    server.core.handshake_lifecycle = .complete;
    try server.resumption_master_secret.replace(&([_]u8{0x33} ** hash_len));

    var sink = EventSink{};
    defer sink.deinit();
    var prepared = try server.prepareNewSessionTicket(std.testing.allocator, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .max_early_data_size = 32,
        .issued_at_unix_ms = 10,
    }, session.Limits.default);
    defer prepared.deinit();

    try std.testing.expect(!std.mem.allEqual(u8, prepared.state.common.resumption_psk.slice(), 0));
    try std.testing.expectEqual(@as(usize, 0), sink.len);

    try server.emitPreparedNewSessionTicket(std.testing.allocator, &sink, &prepared, "identity-bytes", session.Limits.default);

    try std.testing.expectEqual(@as(usize, 1), sink.len);
    const message = try tls_handshake_codec.decode(sink.items[0].handshake_bytes.data);
    try std.testing.expectEqual(MessageType.new_session_ticket, message.kind);
    const parsed = try new_session_ticket.decode(message.body);
    try std.testing.expectEqual(@as(u32, 60), parsed.ticket_lifetime);
    try std.testing.expectEqualSlices(u8, "identity-bytes", parsed.ticket);
    try std.testing.expectEqual(@as(?u32, 32), parsed.max_early_data_size);
}

test "emitPreparedNewSessionTicket rejects an empty or oversized identity" {
    var server = Tls13Backend.initServer(
        .{ .hello_random = [_]u8{0x53} ** 32, .key_share_seed = [_]u8{0x54} ** 32 },
        try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
        .record,
    );
    defer server.deinit();
    server.core.handshake_lifecycle = .complete;
    try server.resumption_master_secret.replace(&([_]u8{0x33} ** hash_len));

    var sink = EventSink{};
    defer sink.deinit();
    var prepared = try server.prepareNewSessionTicket(std.testing.allocator, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .issued_at_unix_ms = 10,
    }, session.Limits.default);
    defer prepared.deinit();

    try std.testing.expectError(error.TicketTooLarge, server.emitPreparedNewSessionTicket(std.testing.allocator, &sink, &prepared, "", session.Limits.default));
    var too_large: [session.Limits.default.max_ticket_len + 1]u8 = undefined;
    @memset(&too_large, 0xa5);
    try std.testing.expectError(error.TicketTooLarge, server.emitPreparedNewSessionTicket(std.testing.allocator, &sink, &prepared, &too_large, session.Limits.default));
    try std.testing.expectEqual(@as(usize, 0), sink.len);
}

test "server ticket output failure is atomic and retryable" {
    var server = Tls13Backend.initServer(
        .{ .hello_random = [_]u8{0x61} ** 32, .key_share_seed = [_]u8{0x62} ** 32 },
        try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
        .record,
    );
    defer server.deinit();
    server.core.handshake_lifecycle = .complete;
    try server.resumption_master_secret.replace(&([_]u8{0x33} ** hash_len));

    var full_sink = EventSink{};
    defer full_sink.deinit();
    for (0..EventSink.max_events) |_| try full_sink.emitHandshakeComplete();
    const before = server.core.transcriptHash();
    try std.testing.expectError(error.TransportBufferOverflow, server.emitNewSessionTicket(std.testing.allocator, &full_sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "ticket",
        .issued_at_unix_ms = 10,
    }, session.Limits.default));
    try std.testing.expectEqualSlices(u8, &before, &server.core.transcriptHash());

    full_sink.reset();
    var state = try server.emitNewSessionTicket(std.testing.allocator, &full_sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "ticket",
        .issued_at_unix_ms = 10,
    }, session.Limits.default);
    defer state.deinit();
    try std.testing.expectEqual(@as(usize, 1), full_sink.len);
}

test "server ticket emission allocation failures leave transcript and sink clean" {
    var saw_injected_failure = false;
    var saw_success = false;

    for (0..16) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var server = Tls13Backend.initServer(
            .{ .hello_random = [_]u8{0x63} ** 32, .key_share_seed = [_]u8{0x64} ** 32 },
            try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
            .record,
        );
        server.core.handshake_lifecycle = .complete;
        try server.resumption_master_secret.replace(&([_]u8{0x33} ** hash_len));
        var sink = EventSink{};
        const before = server.core.transcriptHash();

        var state = server.emitNewSessionTicket(failing.allocator(), &sink, .{
            .ticket_lifetime = 60,
            .ticket_age_add = 1,
            .ticket_nonce = "\x01",
            .opaque_ticket = "ticket",
            .max_early_data_size = 32,
            .issued_at_unix_ms = 10,
        }, session.Limits.default) catch |err| {
            if (!failing.has_induced_failure) return err;
            saw_injected_failure = true;
            try std.testing.expectEqual(error.CredentialProviderFailed, err);
            try std.testing.expectEqualSlices(u8, &before, &server.core.transcriptHash());
            try std.testing.expectEqual(@as(usize, 0), sink.len);
            sink.deinit();
            server.deinit();
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            continue;
        };
        saw_success = true;
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(@as(usize, 1), sink.len);
        state.deinit();
        sink.deinit();
        server.deinit();
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
        break;
    }

    try std.testing.expect(saw_injected_failure);
    try std.testing.expect(saw_success);
}

test "large emitted ticket is delivered once after fragmented application receives" {
    const Capture = struct {
        count: usize = 0,
        psk: [hash_len]u8 = undefined,
        ticket_len: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 10;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            @memcpy(&self.psk, ticket.common.resumption_psk.slice());
            self.ticket_len = ticket.ticket.slice().len;
        }
    };

    const limits = session.Limits{ .max_ticket_len = session.absolute_ticket_wire_max, .max_serialized_len = 128 * 1024 };
    const opaque_ticket = try std.testing.allocator.alloc(u8, session.absolute_ticket_wire_max);
    defer std.testing.allocator.free(opaque_ticket);
    @memset(opaque_ticket, 0xa5);

    var server = Tls13Backend.initServer(
        .{ .hello_random = [_]u8{0x71} ** 32, .key_share_seed = [_]u8{0x72} ** 32 },
        try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
        .record,
    );
    defer server.deinit();
    server.core.handshake_lifecycle = .complete;
    try server.resumption_master_secret.replace(&([_]u8{0x44} ** hash_len));

    var client = Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0x73} ** 32, .key_share_seed = [_]u8{0x74} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .record,
    );
    defer client.deinit();
    var capture = Capture{};
    try client.setSessionTicketConsumer(std.testing.allocator, limits, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });
    client.core.handshake_lifecycle = .complete;
    try client.resumption_master_secret.replace(&([_]u8{0x44} ** hash_len));

    var sink = EventSink{};
    defer sink.deinit();
    var server_state = try server.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = opaque_ticket,
        .issued_at_unix_ms = 10,
    }, limits);
    defer server_state.deinit();
    const emitted = sink.items[0].handshake_bytes.data;
    try std.testing.expect(emitted.len > 16 * 1024);

    var client_sink = EventSink{};
    defer client_sink.deinit();
    try client.backend().receive(.application, emitted[0..17], &client_sink);
    try client.backend().receive(.application, emitted[17..8191], &client_sink);
    try client.backend().receive(.application, emitted[8191..], &client_sink);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(opaque_ticket.len, capture.ticket_len);
    try std.testing.expectEqualSlices(u8, server_state.common.resumption_psk.slice(), &capture.psk);
}

test "application reassembler accepts exact maximum ticket and rejects one byte over" {
    var client = Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0x81} ** 32, .key_share_seed = [_]u8{0x82} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .record,
    );
    defer client.deinit();
    try client.setPostHandshakeAllocator(std.testing.allocator);
    client.core.handshake_lifecycle = .complete;

    const max_message = try buildMaxNewSessionTicketMessage(std.testing.allocator);
    defer std.testing.allocator.free(max_message);
    try std.testing.expectEqual(max_new_session_ticket_message_len, max_message.len);
    var sink = EventSink{};
    defer sink.deinit();
    try client.backend().receive(.application, max_message[0..3], &sink);
    try client.backend().receive(.application, max_message[3..4099], &sink);
    try client.backend().receive(.application, max_message[4099..], &sink);

    var over_client = Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0x83} ** 32, .key_share_seed = [_]u8{0x84} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .record,
    );
    defer over_client.deinit();
    try over_client.setPostHandshakeAllocator(std.testing.allocator);
    over_client.core.handshake_lifecycle = .complete;
    const over = try std.testing.allocator.alloc(u8, max_new_session_ticket_message_len + 1);
    defer std.testing.allocator.free(over);
    @memset(over, 0);
    over[0] = @intFromEnum(MessageType.new_session_ticket);
    std.mem.writeInt(u24, over[1..4], max_new_session_ticket_message_len - 3, .big);
    try std.testing.expectError(error.HandshakeBufferOverflow, over_client.backend().receive(.application, over, &sink));
}

test "client cannot emit NewSessionTicket" {
    var client = Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0x91} ** 32, .key_share_seed = [_]u8{0x92} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .record,
    );
    defer client.deinit();
    client.core.handshake_lifecycle = .complete;
    try client.resumption_master_secret.replace(&([_]u8{0x44} ** hash_len));
    var sink = EventSink{};
    defer sink.deinit();
    try std.testing.expectError(error.InvalidHandshakeState, client.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "ticket",
        .issued_at_unix_ms = 10,
    }, session.Limits.default));
}

test "abandoned backend teardown wipes ephemeral and server identity storage" {
    const entropy = Entropy{ .hello_random = [_]u8{0x31} ** 32, .key_share_seed = [_]u8{0x32} ** 32 };
    var client = Tls13Backend.initClient(
        entropy,
        .{ .pinned_certificate = testdata.certificate_der },
        .record,
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
        .record,
    );
    server.deinit();
    try std.testing.expect(!server.identity_present);
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&server.identity), 0));
    try std.testing.expect(std.mem.allEqual(u8, &server.entropy.key_share_seed, 0));
}
