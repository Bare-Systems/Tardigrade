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
const crypto_pkg = @import("crypto");
const tls_handshake_codec = @import("handshake.zig");
const tls_key_schedule = @import("key_schedule.zig");
const new_session_ticket = @import("new_session_ticket.zig");
const session = @import("session.zig");
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
/// Largest framed handshake message we accept during the main handshake.
pub const max_message_len = 8 * 1024;
/// Largest framed post-handshake NewSessionTicket message: a 65535-byte opaque
/// ticket identity plus its handshake header and small fixed/vector fields.
pub const max_new_session_ticket_message_len = tls13_transport.max_new_session_ticket_message_len;
const handshake_header_len = 4;

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
///     protocol length + up to 255 protocol bytes (`AlpnPolicy.validate`'s
///     own `name.len > std.math.maxInt(u8)` bound) = 262 bytes.
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

pub const AlpnPolicy = struct {
    protocols: []const []const u8,
    allow_absent: bool = false,

    pub fn validate(self: AlpnPolicy) HandshakeError!void {
        if (self.protocols.len == 0 and !self.allow_absent) return error.InvalidTransportProfile;
        var total: usize = 0;
        for (self.protocols, 0..) |name, i| {
            if (name.len == 0 or name.len > std.math.maxInt(u8)) return error.InvalidTransportProfile;
            total = std.math.add(usize, total, 1 + name.len) catch return error.InvalidTransportProfile;
            if (total > std.math.maxInt(u16)) return error.InvalidTransportProfile;
            if (total + 6 > max_message_len) return error.InvalidTransportProfile;
            for (self.protocols[0..i]) |prior| {
                if (std.mem.eql(u8, prior, name)) return error.InvalidTransportProfile;
            }
        }
    }

    pub fn contains(self: AlpnPolicy, name: []const u8) bool {
        for (self.protocols) |protocol| {
            if (std.mem.eql(u8, protocol, name)) return true;
        }
        return false;
    }
};

pub fn recordAlpnPolicy(comptime protocol: []const u8) AlpnPolicy {
    return .{ .protocols = &.{protocol} };
}

/// Transport differences are explicit production configuration, never a
/// mutable test-only switch. The TLS engine treats the extension payload as
/// opaque; the owning transport adapter is responsible for its codec and
/// policy. Record mode carries no transport-specific extension.
pub const TransportProfile = union(enum) {
    record: RecordOptions,
    extension: ExtensionOptions,

    pub const RecordOptions = struct {
        alpn: AlpnPolicy,
    };

    pub const ExtensionOptions = struct {
        alpn: []const u8,
        extension_type: u16,
        /// Borrowed from the transport adapter. It must remain valid until the
        /// local ClientHello or EncryptedExtensions flight has been emitted.
        local: []const u8,
    };

    fn firstConfiguredAlpn(self: TransportProfile) []const u8 {
        return switch (self) {
            .record => |options| if (options.alpn.protocols.len > 0) options.alpn.protocols[0] else "",
            .extension => |options| options.alpn,
        };
    }

    fn allowAbsentAlpn(self: TransportProfile) bool {
        return switch (self) {
            .record => |options| options.alpn.allow_absent,
            .extension => false,
        };
    }

    fn containsAlpn(self: TransportProfile, name: []const u8) bool {
        return switch (self) {
            .record => |options| options.alpn.contains(name),
            .extension => |options| std.mem.eql(u8, options.alpn, name),
        };
    }

    fn alpnPreference(self: TransportProfile, name: []const u8) ?usize {
        return switch (self) {
            .record => |options| blk: {
                for (options.alpn.protocols, 0..) |protocol, index| {
                    if (std.mem.eql(u8, protocol, name)) break :blk index;
                }
                break :blk null;
            },
            .extension => |options| if (std.mem.eql(u8, options.alpn, name)) 0 else null,
        };
    }

    fn writeAlpnOffer(self: TransportProfile, w: *Writer) HandshakeError!void {
        switch (self) {
            .record => |options| {
                if (options.alpn.protocols.len == 0) return;
                try w.u16_(ext_alpn);
                const alpn_ext_len = try w.reserve(2);
                const alpn_list_len = try w.reserve(2);
                for (options.alpn.protocols) |protocol| {
                    try w.u8_(@intCast(protocol.len));
                    try w.bytes(protocol);
                }
                w.patch(2, alpn_list_len);
                w.patch(2, alpn_ext_len);
            },
            .extension => |options| {
                try w.u16_(ext_alpn);
                const alpn_ext_len = try w.reserve(2);
                const alpn_list_len = try w.reserve(2);
                try w.u8_(@intCast(options.alpn.len));
                try w.bytes(options.alpn);
                w.patch(2, alpn_list_len);
                w.patch(2, alpn_ext_len);
            },
        }
    }

    fn alpnOfferEncodedLen(self: TransportProfile) HandshakeError!usize {
        return switch (self) {
            .record => |options| blk: {
                if (options.alpn.protocols.len == 0) break :blk 0;
                var list_len: usize = 0;
                for (options.alpn.protocols) |protocol| {
                    list_len = try checkedAdd(list_len, 1 + protocol.len);
                }
                break :blk try checkedAdd(6, list_len);
            },
            .extension => |options| try checkedAdd(7, options.alpn.len),
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
        switch (self) {
            .record => |options| try options.alpn.validate(),
            .extension => |options| if (options.alpn.len == 0 or options.alpn.len > std.math.maxInt(u8)) return error.InvalidTransportProfile,
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
    /// A configured (client) server name that did not fit the bounded buffer.
    /// Rather than truncate it — which would emit SNI for a different host and
    /// hand the wrong name to the verifier — construction records the overflow
    /// and `start` fails closed before any ClientHello is emitted.
    server_name_overflow: bool = false,
    selected_alpn: [255]u8 = undefined,
    selected_alpn_len: usize = 0,
    selected_alpn_present: bool = false,
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

    const Slice = struct { start: usize, len: usize };
    const PendingStage = enum { server_select, server_sign, client_select, client_sign, peer_verify };

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
        return initClientWithOptions(entropy, trust, profile, .{});
    }

    /// Client construction with the built-in fixed trust policy plus explicit
    /// client options such as intended SNI.
    pub fn initClientWithOptions(entropy: Entropy, trust: Trust, profile: TransportProfile, options: ClientOptions) Tls13Backend {
        var self: Tls13Backend = .{
            .role = .client,
            .profile = profile,
            .entropy = entropy,
            .trust = trust,
            .auth_policy = policyFromTrust(trust),
            .core = tls_handshake_codec.Core.init(.client),
        };
        self.applyClientOptions(options);
        return self;
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
        return self.profile.firstConfiguredAlpn();
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

    fn selectedAlpnForAuth(self: *const Tls13Backend) []const u8 {
        return self.selectedAlpn() orelse "";
    }

    pub fn setExtensionProfile(self: *Tls13Backend, extension_type: u16, local: []const u8) HandshakeError!void {
        const profile: TransportProfile = .{ .extension = .{
            .alpn = self.profile.firstConfiguredAlpn(),
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

    fn startImpl(ptr: *anyopaque, role: Role, _: void, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        // The driver's role comes from Handshake.initClient/initServer and must
        // match how this backend was constructed; a mismatch is a wiring bug.
        std.debug.assert(role == self.role);
        std.debug.assert(self.core.handshake_lifecycle == .idle);
        try self.profile.validate();
        // A configured client server name that overflowed the bound is a caller
        // configuration error; fail closed before any lifecycle or transcript
        // advance rather than emitting SNI for a truncated (wrong) host.
        if (self.server_name_overflow) return error.InvalidHandshakeState;
        if (self.role == .client and try self.clientHelloEncodedLen() > max_message_len)
            return error.InvalidTransportProfile;
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
            .client_hello => try self.onClientHello(body, sink),
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

        try self.profile.writeAlpnOffer(&w);

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

    fn clientHelloEncodedLen(self: *const Tls13Backend) HandshakeError!usize {
        var len: usize = 0;
        len = try checkedAdd(len, 1 + 3); // handshake header
        len = try checkedAdd(len, 2); // legacy_version
        len = try checkedAdd(len, 32); // random
        len = try checkedAdd(len, 1); // legacy_session_id
        len = try checkedAdd(len, 2 + 2); // cipher_suites vector + one suite
        len = try checkedAdd(len, 1 + 1); // compression_methods vector + null
        len = try checkedAdd(len, 2); // extensions vector length
        len = try checkedAdd(len, 2 + 2 + 3); // supported_versions
        len = try checkedAdd(len, 2 + 2 + 4); // supported_groups
        len = try checkedAdd(len, 2 + 2 + 6); // signature_algorithms
        len = try checkedAdd(len, 2 + 2 + 2 + 2 + 2 + X25519.public_length); // key_share
        len = try checkedAdd(len, try self.profile.alpnOfferEncodedLen());
        if (self.serverNameSlice()) |name| {
            len = try checkedAdd(len, 2 + 2 + 2 + 1 + 2 + name.len);
        }
        if (self.profile.extensionType() != null) {
            const payload = self.profile.localExtension() orelse return error.MissingTransportExtension;
            len = try checkedAdd(len, 2 + 2 + payload.len);
        }
        return len;
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
        var alpn_seen = false;
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
                    if (!self.profile.containsAlpn(name)) return error.AlpnMismatch;
                    self.setSelectedAlpn(name);
                    alpn_seen = true;
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
        if (!alpn_seen and !self.profile.allowAbsentAlpn()) return error.AlpnMismatch;
        if (self.profile.extensionType() != null and !transport_extension_seen) return error.MissingTransportExtension;
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
            .negotiated_version = tls13_version,
            .cipher_suite = cipher_tls_aes_128_gcm_sha256,
            .application_protocol = self.selectedAlpnForAuth(),
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
            .negotiated_version = tls13_version,
            .cipher_suite = cipher_tls_aes_128_gcm_sha256,
            .application_protocol = self.selectedAlpnForAuth(),
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

    fn locallyOfferedSignatureAlgorithm(algorithm: u16) bool {
        return algorithm == sigalg_ed25519 or algorithm == sigalg_ecdsa_secp256r1_sha256;
    }

    /// Verify the CertificateVerify signature against the peer leaf's public
    /// key: proof that the peer holds the private key for the presented
    /// certificate. This is not a trust decision — that is the verifier's job.
    fn checkProofOfPossession(self: *const Tls13Backend, algorithm: u16, signature: []const u8, content: []const u8) ProofResult {
        if (!locallyOfferedSignatureAlgorithm(algorithm)) return .unoffered_algorithm;
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
    }

    /// The immutable selection context for choosing the client's own
    /// credential, honoring the schemes the server offered in its
    /// CertificateRequest and the intended server name.
    fn clientSelectionContext(self: *const Tls13Backend) credentials.SelectionContext {
        return .{
            .role = .client,
            .server_name = self.serverNameSlice(),
            .peer_signature_schemes = self.peer_sig_schemes[0..self.peer_sig_scheme_count],
            .negotiated_version = tls13_version,
            .cipher_suite = cipher_tls_aes_128_gcm_sha256,
            .application_protocol = self.selectedAlpnForAuth(),
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
            return self.emitClientCertificate(null, sink);
        var selection = self.clientSelectionContext();
        // A provider that deterministically has no usable credential is not a
        // failure: TLS 1.3 requires the client to answer a CertificateRequest
        // with an empty Certificate (RFC 8446 §4.4.2). That is how optional auth
        // succeeds and how required auth yields the peer-attributed
        // certificate_required outcome on the server.
        const progress = provider.selectCredential(&selection) catch |err| switch (err) {
            error.NoCredentialAvailable,
            error.NoCompatibleSignatureAlgorithm,
            => return self.emitClientCertificate(null, sink),
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
        // The provider must return a scheme the server actually offered, else
        // the CertificateVerify would carry an unadvertised algorithm.
        const selection = self.clientSelectionContext();
        if (!selection.offersScheme(credential.scheme))
            return self.failCredential(.invalid_callback_behavior);
        owned = false; // ownership passes to emitClientCertificate
        return self.emitClientCertificate(credential, sink);
    }

    /// Emit the client Certificate (the credential's validated chain, or an
    /// empty list when declining) and record it, then sign CertificateVerify —
    /// synchronously, or by parking a pending signer (`client_sign`). Owns the
    /// credential handle and releases it exactly once on any failure before
    /// ownership passes on.
    fn emitClientCertificate(self: *Tls13Backend, credential: ?credentials.SelectedCredential, sink: *EventSink) HandshakeError!void {
        var owned = credential != null;
        errdefer if (owned) if (credential) |c| c.release();

        // Validate the credential's chain and its exact encoded size up front,
        // before any transcript mutation (`recordSent`) or output emission, so a
        // credential that cannot be serialized within bounds fails closed rather
        // than being partially recorded or emitted.
        if (credential) |c| {
            const chain = c.certificateChain();
            if (chain.count() == 0 or chain.count() > credentials.max_chain_entries)
                return self.failCredential(.malformed_credential_chain);
            // The Certificate message's own framing must be counted too:
            // 1-byte type + 3-byte length + 1-byte request context + 3-byte
            // CertificateList length. Omitting it lets a chain that fits the
            // entry sum overflow the writer after the message header is added.
            var encoded_len: usize = certificate_message_overhead;
            for (chain.entries) |entry| {
                if (entry.len == 0 or entry.len > max_certificate_len)
                    return self.failCredential(.malformed_credential_chain);
                // CertificateEntry overhead: 3-byte cert_data length + 2-byte
                // extensions length.
                encoded_len = std.math.add(usize, encoded_len, entry.len + 5) catch
                    return self.failCredential(.malformed_credential_chain);
                if (encoded_len > max_message_len)
                    return self.failCredential(.malformed_credential_chain);
            }
        }

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
        var alpn_offered = false;
        var selected_alpn: ?[]const u8 = null;
        var selected_alpn_preference: usize = std.math.maxInt(usize);
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
                    const list_len = try ext.u16_();
                    // RFC 6066 §3: ServerNameList<1..2^16-1> — an empty list is
                    // malformed, not "no host_name present"; accepting it would
                    // silently route to the default credential exactly like the
                    // metadata-collapse behavior this parser otherwise rejects.
                    if (list_len == 0) return error.IllegalParameter;
                    var names = Reader{ .bytes = try ext.slice(list_len) };
                    while (names.remaining() > 0) {
                        const name_type = try names.u8_();
                        const name = try names.slice(try names.u16_());
                        if (name_type != 0) continue; // only host_name is defined
                        // RFC 6066: a given name_type must appear at most once.
                        if (self.server_name_present) return error.IllegalParameter;
                        if (name.len == 0 or name.len > self.server_name.len) return error.IllegalParameter;
                        dns_name.validateHostName(name) catch return error.IllegalParameter;
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
                    const list_len = try ext.u16_();
                    if (list_len == 0) return error.MalformedHandshake;
                    var list = Reader{ .bytes = try ext.slice(list_len) };
                    try ext.expectEnd();
                    while (list.remaining() > 0) {
                        const name_len = try list.u8_();
                        if (name_len == 0) return error.MalformedHandshake;
                        const name = try list.slice(name_len);
                        alpn_offered = true;
                        if (self.profile.alpnPreference(name)) |preference| {
                            if (preference >= selected_alpn_preference) continue;
                            selected_alpn = name;
                            selected_alpn_preference = preference;
                        }
                    }
                    try list.expectEnd();
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
        if (!saw_signature_algorithms) return error.MissingExtension;
        if (self.peer_sig_scheme_count == 0) return error.MalformedHandshake;
        const client_share = peer_share orelse return error.MalformedHandshake;

        if (selected_alpn) |protocol| {
            self.setSelectedAlpn(protocol);
        } else if (alpn_offered or !self.profile.allowAbsentAlpn()) {
            self.core.handshake_lifecycle = .failed;
            return error.AlpnMismatch;
        }
        if (self.profile.extensionType() != null) {
            const extension = transport_params orelse return error.MissingTransportExtension;
            try self.capturePeerTransportExtension(extension);
        }

        try self.beginServerSelection(session_id, client_share, sink);
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
        if (self.selectedAlpn()) |protocol| try sink.emitAlpn(protocol);

        self.schedule = KeySchedule.init(&shared, self.core.transcriptHash());
        try self.emitHandshakeSecrets(sink);
        try sink.emitDiscardKeys(.initial);

        owned = false;
        try self.emitServerAuthFlight(credential, sink);
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
        // Sum the CertificateList entry encoding (each entry + its 5-byte
        // framing) and the Certificate message's own header. The remaining
        // preflight — that this plus EncryptedExtensions and CertificateRequest
        // all fit one flight buffer — is completed after those messages are
        // built, below, and before any state mutation.
        var certificate_message_len: usize = certificate_message_overhead;
        for (chain.entries) |entry| {
            if (entry.len == 0 or entry.len > max_certificate_len)
                return self.failCredential(.malformed_credential_chain);
            // CertificateEntry framing overhead: 3-byte cert_data length +
            // 2-byte extensions length.
            certificate_message_len = std.math.add(usize, certificate_message_len, entry.len + 5) catch
                return self.failCredential(.malformed_credential_chain);
            if (certificate_message_len > max_message_len)
                return self.failCredential(.malformed_credential_chain);
        }

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
            try w.u16_(2 + 2 * 2); // extension_data length
            try w.u16_(2 * 2); // supported_signature_algorithms list length
            try w.u16_(sigalg_ed25519);
            try w.u16_(sigalg_ecdsa_secp256r1_sha256);
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
                        return error.InvalidHandshakeState;
                    }
                    const session_id = self.pending_client_session_id[0..self.pending_client_session_id_len];
                    const client_share = self.pending_client_share;
                    self.pending_client_hello_ready = false;
                    self.pending_client_session_id_len = 0;
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
                .no_credential => return self.failCredential(.no_credential_available),
                else => {
                    releaseCompletionCredentials(completion, null);
                    return self.failCredential(.invalid_callback_behavior);
                },
            },
            .client_select => switch (completion) {
                .credential => |c| return self.emitSelectedClientCertificate(c, sink),
                // A selector that resolved to "no credential" declines with an
                // empty Certificate, exactly like the synchronous path.
                .no_credential => return self.emitClientCertificate(null, sink),
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
            .cipher_suite = tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256,
            .server_name = if (self.server_name_present) self.server_name[0..self.server_name_len] else null,
            .application_protocol = self.selectedAlpn(),
            .auth_binding = self.peerAuthBinding(),
            .transport_compat = self.peerTransportCompat(),
        };
    }

    fn peerAuthBinding(self: *const Tls13Backend) session.AuthBinding {
        if (self.peer_chain_count == 0) return session.AuthBinding.fromLeafCertificateDer("");
        const leaf = self.peer_chain_entries[0];
        return session.AuthBinding.fromLeafCertificateDer(self.peer_chain[leaf.start..][0..leaf.len]);
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

    pub fn emitNewSessionTicket(
        self: *Tls13Backend,
        allocator: std.mem.Allocator,
        sink: *EventSink,
        params: EmitNewSessionTicketParams,
        limits: session.Limits,
    ) HandshakeError!session.ServerRecoverableState {
        if (self.role != .server or self.core.handshake_lifecycle != .complete)
            return error.InvalidHandshakeState;
        if (self.resumption_master_secret.slice().len == 0)
            return error.InvalidHandshakeState;
        limits.validate() catch return error.InvalidTransportProfile;

        const emit_params: new_session_ticket.EmitParams = .{
            .ticket_lifetime = params.ticket_lifetime,
            .ticket_age_add = params.ticket_age_add,
            .ticket_nonce = params.ticket_nonce,
            .ticket = params.opaque_ticket,
            .max_early_data_size = params.max_early_data_size,
        };
        const body_len = new_session_ticket.encodedLen(emit_params) catch |err| return mapTicketEncodeError(err);
        if (body_len > max_new_session_ticket_message_len - 4) return error.TransportBufferOverflow;
        const message_len = handshake_header_len + body_len;

        var state = new_session_ticket.buildServerRecoverableState(
            allocator,
            emit_params,
            self.resumptionContext(),
            self.resumption_master_secret.slice(),
            params.issued_at_unix_ms,
            limits,
        ) catch |err| return mapTicketBuildServerError(err);
        errdefer state.deinit();

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
        return state;
    }

    /// The handshake is over: the transport sink owns every exported live
    /// secret, so wipe the engine's key schedule immediately.
    fn finish(self: *Tls13Backend) void {
        if (self.schedule) |*schedule| schedule.wipe();
        self.schedule = null;
        crypto.secureZero(u8, &self.expected_client_verify);
    }
};

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
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
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
    const invalid_alpn_policies = [_]AlpnPolicy{
        .{ .protocols = &.{""} },
        .{ .protocols = &.{&([_]u8{'a'} ** 256)} },
        .{ .protocols = &.{ "h2", "h2" } },
        .{ .protocols = &.{} },
    };
    for (invalid_alpn_policies) |alpn_policy| {
        var backend = Tls13Backend.initClient(
            entropy,
            .{ .pinned_certificate = testdata.certificate_der },
            .{ .record = .{ .alpn = alpn_policy } },
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
    try std.testing.expectError(error.InvalidTransportProfile, (AlpnPolicy{ .protocols = &names }).validate());

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
    try (AlpnPolicy{ .protocols = &near_names }).validate();
    var near_backend = Tls13Backend.initClient(
        entropy,
        .{ .pinned_certificate = testdata.certificate_der },
        .{ .record = .{ .alpn = .{ .protocols = &near_names } } },
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

test "client rejects malformed encrypted extensions ALPN framing" {
    var backend = Tls13Backend.initClient(
        Entropy{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x52} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
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
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
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
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
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
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
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

test "server ticket output failure is atomic and retryable" {
    var server = Tls13Backend.initServer(
        .{ .hello_random = [_]u8{0x61} ** 32, .key_share_seed = [_]u8{0x62} ** 32 },
        try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
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
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
    );
    defer server.deinit();
    server.core.handshake_lifecycle = .complete;
    try server.resumption_master_secret.replace(&([_]u8{0x44} ** hash_len));

    var client = Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0x73} ** 32, .key_share_seed = [_]u8{0x74} ** 32 },
        .{ .pinned_certificate = testdata.certificate_der },
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
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
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
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
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
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
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
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
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
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
        .{ .record = .{ .alpn = recordAlpnPolicy("h2") } },
    );
    server.deinit();
    try std.testing.expect(!server.identity_present);
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&server.identity), 0));
    try std.testing.expect(std.mem.allEqual(u8, &server.entropy.key_share_seed, 0));
}
