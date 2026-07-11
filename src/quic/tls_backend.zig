//! Pure-Zig TLS 1.3 engine in QUIC mode (#296): the concrete production
//! `TlsBackend` behind the `QuicTlsAdapter` seam. It consumes and produces raw
//! TLS 1.3 handshake messages (no record layer — QUIC packet protection covers
//! that), exports per-level traffic secrets, carries the QUIC
//! `quic_transport_parameters` extension (RFC 9000 §18), negotiates ALPN, and
//! authenticates the server with an Ed25519 X.509 certificate. Built entirely
//! on `std.crypto` primitives; no foreign TLS type crosses the seam.
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
//! rest of `src/quic/` — no ambient RNG.

const std = @import("std");
const config = @import("config.zig");
const varint = @import("quic_varint");
const tls_adapter = @import("tls_adapter.zig");
const tls_handshake = @import("tls_handshake.zig");
const tls_key_schedule = @import("tls_core").key_schedule;

const crypto = std.crypto;
const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;
const Certificate = crypto.Certificate;

const EncryptionLevel = tls_adapter.EncryptionLevel;
const CertificateState = tls_adapter.CertificateState;
const HandshakeError = tls_handshake.HandshakeError;
const EventSink = tls_handshake.EventSink;
const TlsBackend = tls_handshake.TlsBackend;
const Role = tls_handshake.Role;

pub const hash_len = tls_key_schedule.hash_len;
const TranscriptHash = tls_key_schedule.TranscriptHash;
/// Largest handshake message body we accept (u24 wire limit is 16 MiB; a
/// single-certificate Ed25519 flight is far below this).
pub const max_message_len = 8 * 1024;
pub const max_certificate_len = 2048;

const tls13_version: u16 = 0x0304;
const legacy_version: u16 = 0x0303;
const cipher_tls_aes_128_gcm_sha256: u16 = 0x1301;
const group_x25519: u16 = 0x001d;
const sigalg_ed25519: u16 = 0x0807;

const ext_supported_groups: u16 = 10;
const ext_signature_algorithms: u16 = 13;
const ext_alpn: u16 = 16;
const ext_supported_versions: u16 = 43;
const ext_key_share: u16 = 51;
/// RFC 9001 §8.2.
const ext_quic_transport_parameters: u16 = 57;

const MessageType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,
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
// QUIC transport parameters codec (RFC 9000 §18).
// ===========================================================================

const tp_max_idle_timeout: u64 = 0x01;
const tp_max_udp_payload_size: u64 = 0x03;
const tp_initial_max_data: u64 = 0x04;
const tp_initial_max_stream_data_bidi_local: u64 = 0x05;
const tp_initial_max_stream_data_bidi_remote: u64 = 0x06;
const tp_initial_max_stream_data_uni: u64 = 0x07;
const tp_initial_max_streams_bidi: u64 = 0x08;
const tp_initial_max_streams_uni: u64 = 0x09;
const tp_disable_active_migration: u64 = 0x0c;
const tp_active_connection_id_limit: u64 = 0x0e;

/// Upper bound of the encoding produced by `encodeTransportParameters`:
/// nine integer parameters (2-byte id + 1-byte length + 8-byte varint) plus the
/// zero-length disable_active_migration flag.
pub const max_transport_parameters_len = 9 * (2 + 1 + 8) + 3;

/// Encode `params` as the RFC 9000 §18 extension payload. Every parameter this
/// stack models is emitted explicitly, so the peer never falls back to a
/// default that disagrees with `config`.
///
/// Scope: this codec covers the `config.TransportParameters` subset — the
/// connection-binding parameters QUIC v1 requires from the connection layer
/// (`initial_source_connection_id`, and the server's
/// `original_destination_connection_id` / `retry_source_connection_id` /
/// `stateless_reset_token`) carry per-connection CIDs this backend never sees.
/// Packet-layer integration passes those through a connection-supplied payload
/// when it wires the driver into `connection.zig` (see docs/QUIC_TLS.md).
pub fn encodeTransportParameters(params: config.TransportParameters, buf: []u8) HandshakeError![]const u8 {
    var len: usize = 0;
    const entries = [_]struct { id: u64, value: u64 }{
        .{ .id = tp_max_idle_timeout, .value = params.max_idle_timeout_ms },
        .{ .id = tp_max_udp_payload_size, .value = params.max_udp_payload_size },
        .{ .id = tp_initial_max_data, .value = params.initial_max_data },
        .{ .id = tp_initial_max_stream_data_bidi_local, .value = params.initial_max_stream_data_bidi_local },
        .{ .id = tp_initial_max_stream_data_bidi_remote, .value = params.initial_max_stream_data_bidi_remote },
        .{ .id = tp_initial_max_stream_data_uni, .value = params.initial_max_stream_data_uni },
        .{ .id = tp_initial_max_streams_bidi, .value = params.initial_max_streams_bidi },
        .{ .id = tp_initial_max_streams_uni, .value = params.initial_max_streams_uni },
        .{ .id = tp_active_connection_id_limit, .value = params.active_connection_id_limit },
    };
    for (entries) |entry| {
        len += varint.encode(entry.id, buf[len..]) catch return error.HandshakeBufferOverflow;
        const value_len = varint.encodedLen(entry.value) catch return error.HandshakeBufferOverflow;
        len += varint.encode(value_len, buf[len..]) catch return error.HandshakeBufferOverflow;
        len += varint.encode(entry.value, buf[len..]) catch return error.HandshakeBufferOverflow;
    }
    if (params.disable_active_migration) {
        len += varint.encode(tp_disable_active_migration, buf[len..]) catch return error.HandshakeBufferOverflow;
        len += varint.encode(0, buf[len..]) catch return error.HandshakeBufferOverflow;
    }
    return buf[0..len];
}

/// Most distinct transport-parameter ids accepted in one extension payload.
/// Real stacks send ~15 known parameters plus a few GREASE entries; a peer
/// exceeding this is pathological and fails deterministically rather than
/// letting duplicate detection require unbounded state.
pub const max_distinct_transport_parameters = 64;

/// Decode a peer's RFC 9000 §18 extension payload. Unknown parameters are
/// ignored semantically (§7.4.2), but a duplicated parameter id — known or
/// unknown — is a protocol violation (§7.4) and fails, as do truncated
/// encodings and values RFC 9000 forbids, all with
/// `InvalidTransportParameters`. Absent parameters take their RFC defaults.
pub fn decodeTransportParameters(bytes: []const u8) HandshakeError!config.TransportParameters {
    var params = config.TransportParameters{
        .max_idle_timeout_ms = 0,
        .active_connection_id_limit = 2,
        .max_udp_payload_size = 65_527,
        .initial_max_data = 0,
        .initial_max_stream_data_bidi_local = 0,
        .initial_max_stream_data_bidi_remote = 0,
        .initial_max_stream_data_uni = 0,
        .initial_max_streams_bidi = 0,
        .initial_max_streams_uni = 0,
        .disable_active_migration = false,
    };
    var seen_ids: [max_distinct_transport_parameters]u64 = undefined;
    var seen_count: usize = 0;

    var offset: usize = 0;
    while (offset < bytes.len) {
        // varint.decode returns error.BufferTooShort unless the input holds the
        // full encoding, so the returned len never exceeds the slice and the
        // offset arithmetic below stays in bounds.
        const id = varint.decode(bytes[offset..]) catch return error.InvalidTransportParameters;
        offset += id.len;
        const value_len = varint.decode(bytes[offset..]) catch return error.InvalidTransportParameters;
        offset += value_len.len;
        if (value_len.value > bytes.len - offset) return error.InvalidTransportParameters;
        const value_bytes = bytes[offset..][0..@intCast(value_len.value)];
        offset += value_bytes.len;

        for (seen_ids[0..seen_count]) |seen_id| {
            if (seen_id == id.value) return error.InvalidTransportParameters;
        }
        if (seen_count == seen_ids.len) return error.InvalidTransportParameters;
        seen_ids[seen_count] = id.value;
        seen_count += 1;

        switch (id.value) {
            tp_max_idle_timeout => params.max_idle_timeout_ms = try integerParameter(value_bytes),
            tp_max_udp_payload_size => params.max_udp_payload_size = try integerParameter(value_bytes),
            tp_initial_max_data => params.initial_max_data = try integerParameter(value_bytes),
            tp_initial_max_stream_data_bidi_local => params.initial_max_stream_data_bidi_local = try integerParameter(value_bytes),
            tp_initial_max_stream_data_bidi_remote => params.initial_max_stream_data_bidi_remote = try integerParameter(value_bytes),
            tp_initial_max_stream_data_uni => params.initial_max_stream_data_uni = try integerParameter(value_bytes),
            tp_initial_max_streams_bidi => params.initial_max_streams_bidi = try integerParameter(value_bytes),
            tp_initial_max_streams_uni => params.initial_max_streams_uni = try integerParameter(value_bytes),
            tp_disable_active_migration => {
                if (value_bytes.len != 0) return error.InvalidTransportParameters;
                params.disable_active_migration = true;
            },
            tp_active_connection_id_limit => params.active_connection_id_limit = try integerParameter(value_bytes),
            else => {},
        }
    }

    // RFC 9000 §18.2 legality checks for the parameters this stack models.
    if (params.max_udp_payload_size < 1200 or params.max_udp_payload_size > 65_527) return error.InvalidTransportParameters;
    if (params.active_connection_id_limit < 2) return error.InvalidTransportParameters;
    return params;
}

fn integerParameter(value_bytes: []const u8) HandshakeError!u64 {
    const decoded = varint.decode(value_bytes) catch return error.InvalidTransportParameters;
    if (decoded.len != value_bytes.len) return error.InvalidTransportParameters;
    return decoded.value;
}

// ===========================================================================
// Bounded wire readers/writers for handshake messages.
// ===========================================================================

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn remaining(self: *const Reader) usize {
        return self.bytes.len - self.offset;
    }

    fn u8_(self: *Reader) HandshakeError!u8 {
        if (self.remaining() < 1) return error.MalformedHandshake;
        defer self.offset += 1;
        return self.bytes[self.offset];
    }

    fn u16_(self: *Reader) HandshakeError!u16 {
        if (self.remaining() < 2) return error.MalformedHandshake;
        defer self.offset += 2;
        return std.mem.readInt(u16, self.bytes[self.offset..][0..2], .big);
    }

    fn u24_(self: *Reader) HandshakeError!u24 {
        if (self.remaining() < 3) return error.MalformedHandshake;
        defer self.offset += 3;
        return std.mem.readInt(u24, self.bytes[self.offset..][0..3], .big);
    }

    fn slice(self: *Reader, len: usize) HandshakeError![]const u8 {
        if (self.remaining() < len) return error.MalformedHandshake;
        defer self.offset += len;
        return self.bytes[self.offset..][0..len];
    }

    fn expectEnd(self: *const Reader) HandshakeError!void {
        if (self.remaining() != 0) return error.MalformedHandshake;
    }
};

/// TLS forbids repeating an extension type within one extension block
/// (RFC 8446 §4.2: "There MUST NOT be more than one extension of the same type
/// in a given extension block"). Bounded tracker for the streaming parsers;
/// more than `max_extensions` extensions in one block is treated as malformed
/// rather than requiring unbounded state.
const ExtensionGuard = struct {
    pub const max_extensions = 64;

    ids: [max_extensions]u16 = undefined,
    len: usize = 0,

    fn check(self: *ExtensionGuard, ext_id: u16) HandshakeError!void {
        for (self.ids[0..self.len]) |seen| {
            if (seen == ext_id) return error.MalformedHandshake;
        }
        if (self.len == self.ids.len) return error.MalformedHandshake;
        self.ids[self.len] = ext_id;
        self.len += 1;
    }
};

const Writer = struct {
    buf: []u8,
    len: usize = 0,

    fn u8_(self: *Writer, value: u8) HandshakeError!void {
        try self.bytes(&[_]u8{value});
    }

    fn u16_(self: *Writer, value: u16) HandshakeError!void {
        var encoded: [2]u8 = undefined;
        std.mem.writeInt(u16, &encoded, value, .big);
        try self.bytes(&encoded);
    }

    fn bytes(self: *Writer, data: []const u8) HandshakeError!void {
        if (data.len > self.buf.len - self.len) return error.HandshakeBufferOverflow;
        @memcpy(self.buf[self.len..][0..data.len], data);
        self.len += data.len;
    }

    /// Reserve a big-endian length field of `width` bytes; `patch` writes the
    /// number of bytes appended since the reservation into it.
    fn reserve(self: *Writer, comptime width: usize) HandshakeError!usize {
        const index = self.len;
        try self.bytes(&([_]u8{0} ** width));
        return index;
    }

    fn patch(self: *Writer, comptime width: usize, index: usize) void {
        const value = self.len - index - width;
        var encoded: [width]u8 = undefined;
        const IntT = std.meta.Int(.unsigned, width * 8);
        std.mem.writeInt(IntT, &encoded, @intCast(value), .big);
        @memcpy(self.buf[index..][0..width], &encoded);
    }
};

// ===========================================================================
// Server identity and client trust.
// ===========================================================================

/// The server's certificate and Ed25519 signing key. `initPkcs8` loads the
/// standard PKCS#8 DER encoding (RFC 8410) produced by e.g.
/// `openssl genpkey -algorithm ed25519`.
pub const Identity = struct {
    certificate_der: []const u8,
    key_pair: Ed25519.KeyPair,

    pub const InitError = error{InvalidPrivateKey};

    pub fn initPkcs8(certificate_der: []const u8, pkcs8_key_der: []const u8) InitError!Identity {
        const seed = try ed25519SeedFromPkcs8(pkcs8_key_der);
        const key_pair = Ed25519.KeyPair.generateDeterministic(seed) catch return error.InvalidPrivateKey;
        return .{ .certificate_der = certificate_der, .key_pair = key_pair };
    }

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

const Expect = enum {
    start,
    client_hello,
    server_hello,
    encrypted_extensions,
    certificate,
    certificate_verify,
    finished,
    done,
};

fn InputBuffer(comptime capacity: usize) type {
    return struct {
        data: [capacity]u8 = undefined,
        len: usize = 0,

        const Self = @This();

        fn append(self: *Self, bytes: []const u8) HandshakeError!void {
            if (bytes.len > self.data.len - self.len) return error.MalformedHandshake;
            @memcpy(self.data[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }

        fn consume(self: *Self, count: usize) void {
            std.mem.copyForwards(u8, self.data[0 .. self.len - count], self.data[count..self.len]);
            self.len -= count;
        }
    };
}

pub const Tls13Backend = struct {
    role: Role,
    alpn: []const u8 = "h3",
    entropy: Entropy,
    identity: ?Identity = null,
    trust: Trust = .insecure_no_verification,

    /// Test-only: omit the quic_transport_parameters extension from this
    /// side's flight, driving the driver's `MissingTransportParameters` path
    /// through a real handshake. Never set outside tests.
    omit_transport_parameters: bool = false,

    local_params: config.TransportParameters = undefined,
    key_pair: ?X25519.KeyPair = null,
    transcript: TranscriptHash = TranscriptHash.init(.{}),
    schedule: ?KeySchedule = null,
    /// The client Finished verify_data the server expects (computed when its
    /// own flight is sent).
    expected_client_verify: [hash_len]u8 = undefined,
    expect: Expect = .start,
    /// Reassembled-but-unparsed handshake bytes per CRYPTO level; a message may
    /// arrive split across CRYPTO frames and packets. The application-level
    /// buffer exists because post-handshake messages (NewSessionTicket) may be
    /// fragmented across 1-RTT CRYPTO frames like any other handshake message.
    initial_input: InputBuffer(max_message_len + 4) = .{},
    handshake_input: InputBuffer(max_message_len + 4) = .{},
    application_input: InputBuffer(max_message_len + 4) = .{},
    /// The peer's leaf certificate (client role), kept for CertificateVerify.
    peer_certificate: [max_certificate_len]u8 = undefined,
    peer_certificate_len: usize = 0,

    pub fn initClient(entropy: Entropy, trust: Trust) Tls13Backend {
        return .{ .role = .client, .entropy = entropy, .trust = trust };
    }

    pub fn initServer(entropy: Entropy, identity: Identity) Tls13Backend {
        return .{ .role = .server, .entropy = entropy, .identity = identity };
    }

    pub fn backend(self: *Tls13Backend) TlsBackend {
        return .{ .ptr = self, .startFn = startImpl, .receiveFn = receiveImpl };
    }

    fn startImpl(ptr: *anyopaque, role: Role, params: config.TransportParameters, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        // The driver's role comes from Handshake.initClient/initServer and must
        // match how this backend was constructed; a mismatch is a wiring bug.
        std.debug.assert(role == self.role);
        std.debug.assert(self.expect == .start);
        self.local_params = params;
        switch (self.role) {
            .client => {
                try self.sendClientHello(sink);
                self.expect = .server_hello;
            },
            .server => self.expect = .client_hello,
        }
    }

    fn receiveImpl(ptr: *anyopaque, level: EncryptionLevel, bytes: []const u8, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        const input = switch (level) {
            .initial => &self.initial_input,
            .handshake => &self.handshake_input,
            // The adapter rejects 0-RTT CRYPTO before this point (RFC 9001:
            // 0-RTT has no CRYPTO stream).
            .zero_rtt => return error.UnexpectedCryptoLevel,
            // Application CRYPTO carries only post-handshake messages.
            .application => blk: {
                if (self.expect != .done) return error.UnexpectedCryptoLevel;
                break :blk &self.application_input;
            },
        };
        try input.append(bytes);

        while (input.len >= 4) {
            const body_len = std.mem.readInt(u24, input.data[1..4], .big);
            if (body_len > max_message_len) return error.MalformedHandshake;
            const message_len = 4 + @as(usize, body_len);
            if (input.len < message_len) break;
            const kind = std.enums.fromInt(MessageType, input.data[0]) orelse return error.MalformedHandshake;
            const raw = input.data[0..message_len];
            const body = raw[4..];
            try self.onMessage(kind, level, raw, body, sink);
            input.consume(message_len);
            // A failed or freshly completed handshake stops consuming its own
            // levels; post-handshake application CRYPTO keeps draining (a peer
            // may batch several NewSessionTickets).
            if (self.expect == .done and level != .application) break;
        }
    }

    fn onMessage(
        self: *Tls13Backend,
        kind: MessageType,
        level: EncryptionLevel,
        raw: []const u8,
        body: []const u8,
        sink: *EventSink,
    ) HandshakeError!void {
        // Enforce the CRYPTO level each message belongs to (RFC 9001 §4.1.3)
        // before anything else, so packet-number-space mistakes surface as
        // level errors rather than parse errors.
        const expected_level: EncryptionLevel = switch (kind) {
            .client_hello, .server_hello => .initial,
            .encrypted_extensions, .certificate, .certificate_verify, .finished => .handshake,
            .new_session_ticket => .application,
        };
        if (level != expected_level) return error.UnexpectedCryptoLevel;

        if (kind == .new_session_ticket) {
            // Tolerated and ignored: this backend does not implement
            // resumption, and a compliant peer sending tickets after the
            // handshake must not kill the connection. receiveImpl only routes
            // application CRYPTO here once the handshake is done.
            return;
        }

        switch (self.expect) {
            .client_hello => {
                if (kind != .client_hello) return error.MalformedHandshake;
                try self.onClientHello(raw, body, sink);
            },
            .server_hello => {
                if (kind != .server_hello) return error.MalformedHandshake;
                try self.onServerHello(raw, body, sink);
            },
            .encrypted_extensions => {
                if (kind != .encrypted_extensions) return error.MalformedHandshake;
                try self.onEncryptedExtensions(raw, body, sink);
            },
            .certificate => {
                if (kind != .certificate) return error.MalformedHandshake;
                try self.onCertificate(raw, body);
            },
            .certificate_verify => {
                if (kind != .certificate_verify) return error.MalformedHandshake;
                try self.onCertificateVerify(raw, body, sink);
            },
            .finished => {
                if (kind != .finished) return error.MalformedHandshake;
                switch (self.role) {
                    .client => try self.onServerFinished(raw, body, sink),
                    .server => try self.onClientFinished(raw, body, sink),
                }
            },
            .start, .done => return error.MalformedHandshake,
        }
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
        try w.u8_(0); // legacy_session_id: QUIC forbids compatibility mode (RFC 9001 §8.4)
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
        try w.u16_(4);
        try w.u16_(2);
        try w.u16_(sigalg_ed25519);

        try w.u16_(ext_key_share);
        try w.u16_(2 + 2 + 2 + X25519.public_length);
        try w.u16_(2 + 2 + X25519.public_length); // client_shares
        try w.u16_(group_x25519);
        try w.u16_(X25519.public_length);
        try w.bytes(&key_pair.public_key);

        try w.u16_(ext_alpn);
        const alpn_ext_len = try w.reserve(2);
        const alpn_list_len = try w.reserve(2);
        try w.u8_(@intCast(self.alpn.len));
        try w.bytes(self.alpn);
        w.patch(2, alpn_list_len);
        w.patch(2, alpn_ext_len);

        if (!self.omit_transport_parameters) {
            try w.u16_(ext_quic_transport_parameters);
            var params_buf: [max_transport_parameters_len]u8 = undefined;
            const params = try encodeTransportParameters(self.local_params, &params_buf);
            try w.u16_(@intCast(params.len));
            try w.bytes(params);
        }

        w.patch(2, extensions_len);
        w.patch(3, message_len);

        const message = buf[0..w.len];
        self.transcript.update(message);
        try sink.emitCrypto(.initial, message);
    }

    fn onServerHello(self: *Tls13Backend, raw: []const u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        var r = Reader{ .bytes = body };
        if (try r.u16_() != legacy_version) return error.MalformedHandshake;
        const random = try r.slice(32);
        if (std.mem.eql(u8, random, &hello_retry_request_random)) return error.MalformedHandshake;
        const session_id_len = try r.u8_();
        _ = try r.slice(session_id_len);
        if (try r.u16_() != cipher_tls_aes_128_gcm_sha256) return error.MalformedHandshake;
        if (try r.u8_() != 0) return error.MalformedHandshake;

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
                    if (try ext.u16_() != group_x25519) return error.MalformedHandshake;
                    if (try ext.u16_() != X25519.public_length) return error.MalformedHandshake;
                    peer_share = (try ext.slice(X25519.public_length))[0..X25519.public_length].*;
                    try ext.expectEnd();
                },
                else => {},
            }
        }
        if (selected_version != tls13_version) return error.MalformedHandshake;
        const share = peer_share orelse return error.MalformedHandshake;

        const shared = X25519.scalarmult(self.key_pair.?.secret_key, share) catch
            return error.MalformedHandshake;
        self.transcript.update(raw);
        self.schedule = KeySchedule.init(shared, self.transcript.peek());
        try self.emitHandshakeSecrets(sink);
        try sink.emitDiscardKeys(.initial);
        self.expect = .encrypted_extensions;
    }

    fn onEncryptedExtensions(self: *Tls13Backend, raw: []const u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        var r = Reader{ .bytes = body };
        var guard = ExtensionGuard{};
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
                ext_quic_transport_parameters => {
                    try sink.emitPeerTransportParameters(try decodeTransportParameters(ext.bytes));
                },
                else => {},
            }
        }
        self.transcript.update(raw);
        self.expect = .certificate;
    }

    fn onCertificate(self: *Tls13Backend, raw: []const u8, body: []const u8) HandshakeError!void {
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
        self.transcript.update(raw);
        self.expect = .certificate_verify;
    }

    fn onCertificateVerify(self: *Tls13Backend, raw: []const u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        var r = Reader{ .bytes = body };
        const algorithm = try r.u16_();
        const signature = try r.slice(try r.u16_());
        try r.expectEnd();

        // The signature covers the transcript through Certificate (RFC 8446
        // §4.4.3) — before this message is added.
        const content = certificateVerifyContent(.server, self.transcript.peek());
        const state = self.verifyServerCertificate(algorithm, signature, content.slice());
        try sink.emitCertificate(state);
        if (state == .invalid) {
            // The driver fails with CertificateInvalid when it applies the
            // event; stop consuming input on this side.
            self.expect = .done;
            return;
        }
        self.transcript.update(raw);
        self.expect = .finished;
    }

    fn verifyServerCertificate(self: *Tls13Backend, algorithm: u16, signature: []const u8, content: []const u8) CertificateState {
        if (algorithm != sigalg_ed25519) return .invalid;
        if (signature.len != Ed25519.Signature.encoded_length) return .invalid;
        const leaf = self.peer_certificate[0..self.peer_certificate_len];

        // Proof of key possession: the CertificateVerify signature must check
        // out against the certificate's public key in every trust mode.
        const parsed = (Certificate{ .buffer = leaf, .index = 0 }).parse() catch return .invalid;
        if (parsed.pub_key_algo != .curveEd25519) return .invalid;
        const pub_key_bytes = parsed.pubKey();
        if (pub_key_bytes.len != Ed25519.PublicKey.encoded_length) return .invalid;
        const public_key = Ed25519.PublicKey.fromBytes(pub_key_bytes[0..Ed25519.PublicKey.encoded_length].*) catch return .invalid;
        const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
        sig.verify(content, public_key) catch return .invalid;

        return switch (self.trust) {
            .pinned_certificate => |pin| if (std.mem.eql(u8, leaf, pin)) .valid else .invalid,
            .insecure_no_verification => .not_checked,
        };
    }

    fn onServerFinished(self: *Tls13Backend, raw: []const u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        const schedule = &self.schedule.?;
        if (body.len != hash_len) return error.MalformedHandshake;
        const expected = KeySchedule.verifyData(schedule.server_handshake_traffic, self.transcript.peek());
        if (!crypto.timing_safe.eql([hash_len]u8, expected, body[0..hash_len].*)) {
            return error.MalformedHandshake;
        }
        self.transcript.update(raw);

        // 1-RTT secrets exist from the transcript through server Finished.
        const finished_hash = self.transcript.peek();
        const app = schedule.applicationSecrets(finished_hash);
        try sink.emitSecret(.application, .write, &app.client);
        try sink.emitSecret(.application, .read, &app.server);

        // Client Finished covers the transcript including server Finished.
        var buf: [4 + hash_len]u8 = undefined;
        var w = Writer{ .buf = &buf };
        try w.u8_(@intFromEnum(MessageType.finished));
        const message_len = try w.reserve(3);
        try w.bytes(&KeySchedule.verifyData(schedule.client_handshake_traffic, finished_hash));
        w.patch(3, message_len);
        const message = buf[0..w.len];
        self.transcript.update(message);
        try sink.emitCrypto(.handshake, message);

        try sink.emitDiscardKeys(.handshake);
        try sink.emitHandshakeComplete();
        self.finish();
    }

    // -----------------------------------------------------------------------
    // Server flight.
    // -----------------------------------------------------------------------

    fn onClientHello(self: *Tls13Backend, raw: []const u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        var r = Reader{ .bytes = body };
        if (try r.u16_() != legacy_version) return error.MalformedHandshake;
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

        var offers_tls13 = false;
        var offers_x25519_group = false;
        var offers_ed25519 = false;
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
                        if (try algorithms.u16_() == sigalg_ed25519) offers_ed25519 = true;
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
                        if (std.mem.eql(u8, name, self.alpn)) alpn_match = true;
                    }
                },
                ext_quic_transport_parameters => transport_params = ext.bytes,
                else => {},
            }
        }
        if (!offers_tls13 or !offers_x25519_group or !offers_ed25519) return error.MalformedHandshake;
        const client_share = peer_share orelse return error.MalformedHandshake;

        // Validate the peer share before emitting anything: X25519.scalarmult
        // rejects low-order/identity public keys (all-zero shared secret)
        // rather than deriving a predictable secret.
        const key_pair = X25519.KeyPair.generateDeterministic(self.entropy.key_share_seed) catch
            return error.SecretExportFailed;
        self.key_pair = key_pair;
        const shared = X25519.scalarmult(key_pair.secret_key, client_share) catch
            return error.MalformedHandshake;

        if (!alpn_match) {
            // Report what the client offered instead of silently downgrading;
            // the driver fails with AlpnMismatch before any flight is sent.
            try sink.emitAlpn(first_alpn);
            self.expect = .done;
            return;
        }
        if (transport_params) |tp| {
            try sink.emitPeerTransportParameters(try decodeTransportParameters(tp));
        }
        self.transcript.update(raw);

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
        self.transcript.update(server_hello);
        try sink.emitCrypto(.initial, server_hello);
        try sink.emitAlpn(self.alpn);

        self.schedule = KeySchedule.init(shared, self.transcript.peek());
        try self.emitHandshakeSecrets(sink);
        try sink.emitDiscardKeys(.initial);

        try self.sendServerFlight(sink);
        self.expect = .finished;
    }

    /// EncryptedExtensions + Certificate + CertificateVerify + Finished at the
    /// Handshake level, followed by the 1-RTT secrets.
    fn sendServerFlight(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        const identity = self.identity.?;
        const schedule = &self.schedule.?;
        var buf: [max_message_len]u8 = undefined;
        var w = Writer{ .buf = &buf };

        // EncryptedExtensions: selected ALPN + our transport parameters.
        try w.u8_(@intFromEnum(MessageType.encrypted_extensions));
        const ee_len = try w.reserve(3);
        const ee_extensions = try w.reserve(2);
        try w.u16_(ext_alpn);
        const alpn_ext_len = try w.reserve(2);
        const alpn_list_len = try w.reserve(2);
        try w.u8_(@intCast(self.alpn.len));
        try w.bytes(self.alpn);
        w.patch(2, alpn_list_len);
        w.patch(2, alpn_ext_len);
        if (!self.omit_transport_parameters) {
            try w.u16_(ext_quic_transport_parameters);
            var params_buf: [max_transport_parameters_len]u8 = undefined;
            const params = try encodeTransportParameters(self.local_params, &params_buf);
            try w.u16_(@intCast(params.len));
            try w.bytes(params);
        }
        w.patch(2, ee_extensions);
        w.patch(3, ee_len);

        // Certificate.
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

        // CertificateVerify signs the transcript through Certificate.
        self.transcript.update(buf[0..w.len]);
        const content = certificateVerifyContent(.server, self.transcript.peek());
        const signature = identity.key_pair.sign(content.slice(), null) catch
            return error.SecretExportFailed;
        const verify_start = w.len;
        try w.u8_(@intFromEnum(MessageType.certificate_verify));
        const verify_len = try w.reserve(3);
        try w.u16_(sigalg_ed25519);
        try w.u16_(Ed25519.Signature.encoded_length);
        try w.bytes(&signature.toBytes());
        w.patch(3, verify_len);
        self.transcript.update(buf[verify_start..w.len]);

        // Finished covers the transcript through CertificateVerify.
        const finished_start = w.len;
        try w.u8_(@intFromEnum(MessageType.finished));
        const finished_len = try w.reserve(3);
        try w.bytes(&KeySchedule.verifyData(schedule.server_handshake_traffic, self.transcript.peek()));
        w.patch(3, finished_len);
        self.transcript.update(buf[finished_start..w.len]);

        try sink.emitCrypto(.handshake, buf[0..w.len]);

        // 1-RTT secrets from the transcript through server Finished; the
        // client Finished we will require is fixed by the same hash.
        const finished_hash = self.transcript.peek();
        const app = schedule.applicationSecrets(finished_hash);
        try sink.emitSecret(.application, .read, &app.client);
        try sink.emitSecret(.application, .write, &app.server);
        self.expected_client_verify = KeySchedule.verifyData(schedule.client_handshake_traffic, finished_hash);
    }

    fn onClientFinished(self: *Tls13Backend, raw: []const u8, body: []const u8, sink: *EventSink) HandshakeError!void {
        _ = raw;
        if (body.len != hash_len) return error.MalformedHandshake;
        if (!crypto.timing_safe.eql([hash_len]u8, self.expected_client_verify, body[0..hash_len].*)) {
            return error.MalformedHandshake;
        }
        // Client Finished confirms the handshake for the server (RFC 9001 §4.1.2).
        try sink.emitDiscardKeys(.handshake);
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
                try sink.emitSecret(.handshake, .write, &schedule.client_handshake_traffic);
                try sink.emitSecret(.handshake, .read, &schedule.server_handshake_traffic);
            },
            .server => {
                try sink.emitSecret(.handshake, .read, &schedule.client_handshake_traffic);
                try sink.emitSecret(.handshake, .write, &schedule.server_handshake_traffic);
            },
        }
    }

    /// The handshake is over: the adapter owns every live secret, so wipe the
    /// schedule (QUIC key updates derive from the adapter's 1-RTT secrets, not
    /// from TLS — RFC 9001 §6).
    fn finish(self: *Tls13Backend) void {
        if (self.schedule) |*schedule| schedule.wipe();
        self.schedule = null;
        crypto.secureZero(u8, &self.expected_client_verify);
        self.expect = .done;
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
    pub const certificate_der: []const u8 = @embedFile("testdata/test_server_cert.der");
    pub const private_key_pkcs8_der: []const u8 = @embedFile("testdata/test_server_key.der");
};

// ===========================================================================
// Tests.
// ===========================================================================

const testing = std.testing;
const QuicTlsAdapter = tls_adapter.QuicTlsAdapter;
const Handshake = tls_handshake.Handshake;

const fixture_certificate = testdata.certificate_der;
const fixture_key_pkcs8 = testdata.private_key_pkcs8_der;

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

fn fixtureIdentity() Identity {
    return Identity.initPkcs8(fixture_certificate, fixture_key_pkcs8) catch unreachable;
}

fn clientEntropy() Entropy {
    return .{ .hello_random = [_]u8{0xc1} ** 32, .key_share_seed = [_]u8{0x11} ** 32 };
}

fn serverEntropy() Entropy {
    return .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x22} ** 32 };
}

fn defaultParams() config.TransportParameters {
    return (config.Config{}).transportParameters() catch unreachable;
}

test "TLS 1.3 key schedule matches the RFC 8448 simple 1-RTT trace" {
    const shared = hexBytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const hello_hash = hexBytes("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    const schedule = KeySchedule.init(shared, hello_hash);

    try testing.expectEqualSlices(u8, &hexBytes("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), &schedule.handshake_secret);
    try testing.expectEqualSlices(u8, &hexBytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), &schedule.client_handshake_traffic);
    try testing.expectEqualSlices(u8, &hexBytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), &schedule.server_handshake_traffic);
    try testing.expectEqualSlices(u8, &hexBytes("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), &schedule.master_secret);

    const finished_hash = hexBytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    const app = schedule.applicationSecrets(finished_hash);
    try testing.expectEqualSlices(u8, &hexBytes("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"), &app.client);
    try testing.expectEqualSlices(u8, &hexBytes("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"), &app.server);

    try testing.expectEqualSlices(u8, &hexBytes("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"), &KeySchedule.finishedKey(schedule.server_handshake_traffic));
}

test "transport parameters round-trip through the RFC 9000 wire encoding" {
    const params = defaultParams();
    var buf: [max_transport_parameters_len]u8 = undefined;
    const encoded = try encodeTransportParameters(params, &buf);
    const decoded = try decodeTransportParameters(encoded);
    try testing.expectEqual(params, decoded);
}

test "transport parameter decoding ignores unknown parameters and applies defaults" {
    // grease-style unknown id 0x21 with an opaque value, then max_udp_payload_size.
    const bytes = [_]u8{ 0x21, 0x03, 0xaa, 0xbb, 0xcc, 0x03, 0x02, 0x45, 0xac };
    const decoded = try decodeTransportParameters(&bytes);
    try testing.expectEqual(@as(u64, 1452), decoded.max_udp_payload_size);
    // Absent parameters take RFC 9000 defaults.
    try testing.expectEqual(@as(u64, 2), decoded.active_connection_id_limit);
    try testing.expectEqual(@as(u64, 0), decoded.initial_max_data);
    try testing.expect(!decoded.disable_active_migration);
}

test "transport parameter decoding rejects duplicates, truncation, and illegal values" {
    // max_udp_payload_size sent twice.
    const duplicated = [_]u8{ 0x03, 0x02, 0x45, 0xac, 0x03, 0x02, 0x45, 0xac };
    try testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&duplicated));

    // An unknown parameter id sent twice is still a duplicate (RFC 9000 §7.4),
    // even though a single occurrence would be ignored.
    const duplicated_unknown = [_]u8{ 0x2a, 0x01, 0xaa, 0x2a, 0x01, 0xbb };
    try testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&duplicated_unknown));

    // Length runs past the end of the extension.
    const truncated = [_]u8{ 0x04, 0x08, 0x00 };
    try testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&truncated));

    // Integer parameter with trailing garbage inside its value.
    const overlong = [_]u8{ 0x04, 0x02, 0x01, 0xff };
    try testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&overlong));

    // max_udp_payload_size below the RFC 9000 §18.2 minimum of 1200.
    const illegal = [_]u8{ 0x03, 0x02, 0x40, 0x64 };
    try testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&illegal));

    // disable_active_migration must be zero-length.
    const flag_with_value = [_]u8{ 0x0c, 0x01, 0x01 };
    try testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&flag_with_value));
}

test "fixture identity loads and its key pair matches the certificate public key" {
    const identity = fixtureIdentity();
    const parsed = try (Certificate{ .buffer = fixture_certificate, .index = 0 }).parse();
    try testing.expect(parsed.pub_key_algo == .curveEd25519);
    try testing.expectEqualSlices(u8, parsed.pubKey(), &identity.key_pair.public_key.toBytes());
}

test "PKCS#8 parsing rejects non-Ed25519 and malformed keys" {
    try testing.expectError(error.InvalidPrivateKey, Identity.initPkcs8(fixture_certificate, fixture_key_pkcs8[0 .. fixture_key_pkcs8.len - 1]));
    var wrong_algorithm = hexBytes("302e020100300506032b6571042204200000000000000000000000000000000000000000000000000000000000000000");
    try testing.expectError(error.InvalidPrivateKey, Identity.initPkcs8(fixture_certificate, &wrong_algorithm));
}

// ---------------------------------------------------------------------------
// End-to-end harness: real TLS 1.3 client<->server through the QUIC handshake
// driver, bytes moving only through the adapter CRYPTO APIs.
// ---------------------------------------------------------------------------

const Harness = struct {
    client_adapter: QuicTlsAdapter = .{},
    server_adapter: QuicTlsAdapter = .{},
    client_backend: Tls13Backend,
    server_backend: Tls13Backend,
    client: Handshake = undefined,
    server: Handshake = undefined,
    /// CRYPTO bytes are moved between the sides in chunks of this size, so a
    /// small value exercises handshake messages fragmented across frames.
    chunk_size: usize = 2048,

    fn init() Harness {
        return .{
            .client_backend = Tls13Backend.initClient(clientEntropy(), .{ .pinned_certificate = fixture_certificate }),
            .server_backend = Tls13Backend.initServer(serverEntropy(), fixtureIdentity()),
        };
    }

    fn wire(self: *Harness) !void {
        // Initial secrets come from the client DCID via the connection layer.
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        _ = try self.client_adapter.installInitialSecrets(.client, &dcid);
        _ = try self.server_adapter.installInitialSecrets(.server, &dcid);
        self.client = Handshake.initClient(&self.client_adapter, self.client_backend.backend());
        self.server = Handshake.initServer(&self.server_adapter, self.server_backend.backend());
        try self.server.start(defaultParams());
    }

    fn run(self: *Harness) tls_handshake.HandshakeError!void {
        try self.client.start(defaultParams());
        var rounds: usize = 0;
        while (rounds < 256) : (rounds += 1) {
            var progressed = false;
            inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |level| {
                var buf: [2048]u8 = undefined;
                const chunk = buf[0..@min(self.chunk_size, buf.len)];
                while (try self.client.pollOutput(level, chunk)) |out| {
                    try self.server.onCrypto(level, out.offset, out.bytes);
                    progressed = true;
                }
                while (try self.server.pollOutput(level, chunk)) |out| {
                    try self.client.onCrypto(level, out.offset, out.bytes);
                    progressed = true;
                }
            }
            if (!progressed) break;
        }
    }
};

fn expectSecretsMatch(a: *const QuicTlsAdapter, b: *const QuicTlsAdapter, level: EncryptionLevel) !void {
    const a_write = a.protectionKeys(level, .write) orelse return error.TestUnexpectedResult;
    const b_read = b.protectionKeys(level, .read) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &a_write.key, &b_read.key);
    try testing.expectEqualSlices(u8, &a_write.iv, &b_read.iv);
    try testing.expectEqualSlices(u8, &a_write.hp, &b_read.hp);
}

test "real TLS 1.3 client<->server handshake completes with matching 1-RTT secrets" {
    var h = Harness.init();
    try h.wire();
    try h.run();

    try testing.expect(h.client.isComplete());
    try testing.expect(h.server.isComplete());
    try testing.expectEqual(@as(?HandshakeError, null), h.client.failure());
    try testing.expectEqual(@as(?HandshakeError, null), h.server.failure());

    try expectSecretsMatch(&h.client_adapter, &h.server_adapter, .application);
    try expectSecretsMatch(&h.server_adapter, &h.client_adapter, .application);

    // Phase ordering: Initial and Handshake keys are gone by completion.
    try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), h.client_adapter.protectionKeys(.initial, .write));
    try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), h.server_adapter.protectionKeys(.handshake, .read));

    // ALPN negotiated h3; the pinned certificate verified as valid.
    try testing.expect(h.client_adapter.negotiatedH3());
    try testing.expect(h.server_adapter.negotiatedH3());
    try testing.expectEqual(CertificateState.valid, h.client_adapter.certificateState());

    // Peer transport parameters are authenticated and match what was sent.
    const client_view = h.client_adapter.peerTransportParameters() orelse return error.TestUnexpectedResult;
    const server_view = h.server_adapter.peerTransportParameters() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(defaultParams(), client_view);
    try testing.expectEqual(defaultParams(), server_view);
}

test "handshake completes when CRYPTO delivery fragments every message" {
    var h = Harness.init();
    h.chunk_size = 9;
    try h.wire();
    try h.run();
    try testing.expect(h.client.isComplete());
    try testing.expect(h.server.isComplete());
    try expectSecretsMatch(&h.client_adapter, &h.server_adapter, .application);
}

test "handshake secrets match on both sides while the handshake level is live" {
    var h = Harness.init();
    try h.wire();
    try h.client.start(defaultParams());

    var buf: [2048]u8 = undefined;
    const ch = (try h.client.pollOutput(.initial, &buf)).?;
    try h.server.onCrypto(.initial, ch.offset, ch.bytes);
    const sh = (try h.server.pollOutput(.initial, &buf)).?;
    try h.client.onCrypto(.initial, sh.offset, sh.bytes);

    try expectSecretsMatch(&h.client_adapter, &h.server_adapter, .handshake);
    try expectSecretsMatch(&h.server_adapter, &h.client_adapter, .handshake);
}

test "a client that does not offer h3 fails the server deterministically" {
    var h = Harness.init();
    h.client_backend.alpn = "h2";
    try h.wire();
    try testing.expectError(error.AlpnMismatch, h.run());
    try testing.expect(!h.server.isComplete());
    try testing.expectEqual(@as(?HandshakeError, error.AlpnMismatch), h.server.failure());
}

test "a certificate that does not match the pin fails as CertificateInvalid" {
    var h = Harness.init();
    // Pin a different certificate than the one the server presents.
    const other_pin = [_]u8{0xab} ** 64;
    h.client_backend.trust = .{ .pinned_certificate = &other_pin };
    try h.wire();
    try testing.expectError(error.CertificateInvalid, h.run());
    try testing.expectEqual(CertificateState.invalid, h.client_adapter.certificateState());
    try testing.expect(!h.client.isComplete());
}

test "insecure trust reports not_checked and completes only with the explicit opt-in" {
    var strict = Harness.init();
    strict.client_backend.trust = .insecure_no_verification;
    try strict.wire();
    try testing.expectError(error.CertificateInvalid, strict.run());
    try testing.expectEqual(CertificateState.not_checked, strict.client_adapter.certificateState());

    var opted_in = Harness.init();
    opted_in.client_backend.trust = .insecure_no_verification;
    try opted_in.wire();
    opted_in.client.allow_unverified_certificate = true;
    try opted_in.run();
    try testing.expect(opted_in.client.isComplete());
    try testing.expect(opted_in.server.isComplete());
}

test "a tampered server Finished fails the client deterministically" {
    var h = Harness.init();
    try h.wire();
    try h.client.start(defaultParams());

    var buf: [4096]u8 = undefined;
    const ch = (try h.client.pollOutput(.initial, &buf)).?;
    try h.server.onCrypto(.initial, ch.offset, ch.bytes);
    const sh = (try h.server.pollOutput(.initial, &buf)).?;
    try h.client.onCrypto(.initial, sh.offset, sh.bytes);

    // The server flight ends with Finished; corrupt its last verify_data byte.
    var flight_buf: [4096]u8 = undefined;
    const flight = (try h.server.pollOutput(.handshake, &flight_buf)).?;
    flight.bytes[flight.bytes.len - 1] ^= 0x01;
    try testing.expectError(error.MalformedHandshake, h.client.onCrypto(.handshake, flight.offset, flight.bytes));
    try testing.expect(!h.client.isComplete());
}

test "a tampered CertificateVerify signature surfaces as CertificateInvalid" {
    var h = Harness.init();
    try h.wire();
    try h.client.start(defaultParams());

    var buf: [4096]u8 = undefined;
    const ch = (try h.client.pollOutput(.initial, &buf)).?;
    try h.server.onCrypto(.initial, ch.offset, ch.bytes);
    const sh = (try h.server.pollOutput(.initial, &buf)).?;
    try h.client.onCrypto(.initial, sh.offset, sh.bytes);

    // Locate the CertificateVerify signature inside the flight and flip a bit:
    // the message is <finished(4+32)> from the end, and the 64-byte signature
    // sits directly before it.
    var flight_buf: [4096]u8 = undefined;
    const flight = (try h.server.pollOutput(.handshake, &flight_buf)).?;
    flight.bytes[flight.bytes.len - (4 + hash_len) - 1] ^= 0x01;
    try testing.expectError(error.CertificateInvalid, h.client.onCrypto(.handshake, flight.offset, flight.bytes));
    try testing.expectEqual(CertificateState.invalid, h.client_adapter.certificateState());
}

/// Offset of the u16 extension-block length inside a ClientHello handshake
/// message: header, legacy_version, random, then the variable-length
/// session id / cipher suites / compression vectors.
fn chExtensionBlockOffset(message: []const u8) usize {
    var offset: usize = 4 + 2 + 32;
    offset += 1 + message[offset]; // legacy_session_id
    offset += 2 + std.mem.readInt(u16, message[offset..][0..2], .big); // cipher_suites
    offset += 1 + message[offset]; // legacy_compression_methods
    return offset;
}

/// Append a duplicate copy of extension `ext_id` at the end of the extension
/// block whose u16 length field sits at `block_len_at`, fixing up the block
/// length and the message length of the handshake message starting at offset
/// 0 (any following messages in `buf` are shifted intact). Returns the new
/// total length.
fn duplicateExtension(buf: []u8, total_len: usize, block_len_at: usize, ext_id: u16) usize {
    const block_len = std.mem.readInt(u16, buf[block_len_at..][0..2], .big);
    const block_start = block_len_at + 2;
    const block_end = block_start + block_len;

    var offset = block_start;
    var found_start: usize = 0;
    var found_len: usize = 0;
    while (offset < block_end) {
        const id = std.mem.readInt(u16, buf[offset..][0..2], .big);
        const ext_len = std.mem.readInt(u16, buf[offset + 2 ..][0..2], .big);
        const size = 4 + @as(usize, ext_len);
        if (id == ext_id) {
            found_start = offset;
            found_len = size;
        }
        offset += size;
    }
    std.debug.assert(found_len != 0);

    var copy: [512]u8 = undefined;
    @memcpy(copy[0..found_len], buf[found_start..][0..found_len]);
    std.mem.copyBackwards(u8, buf[block_end + found_len .. total_len + found_len], buf[block_end..total_len]);
    @memcpy(buf[block_end..][0..found_len], copy[0..found_len]);

    std.mem.writeInt(u16, buf[block_len_at..][0..2], @intCast(block_len + found_len), .big);
    const body_len = std.mem.readInt(u24, buf[1..4], .big);
    std.mem.writeInt(u24, buf[1..4], @intCast(body_len + found_len), .big);
    return total_len + found_len;
}

test "a ClientHello with a duplicated extension is rejected" {
    // RFC 8446 §4.2: no extension type may repeat within one extension block.
    inline for (.{ ext_alpn, ext_quic_transport_parameters }) |ext_id| {
        var h = Harness.init();
        try h.wire();
        try h.client.start(defaultParams());

        var buf: [2048]u8 = undefined;
        const ch = (try h.client.pollOutput(.initial, &buf)).?;
        const new_len = duplicateExtension(&buf, ch.bytes.len, chExtensionBlockOffset(ch.bytes), ext_id);
        try testing.expectError(error.MalformedHandshake, h.server.onCrypto(.initial, ch.offset, buf[0..new_len]));
        try testing.expect(!h.server.isComplete());
    }
}

test "EncryptedExtensions with a duplicated extension is rejected" {
    inline for (.{ ext_alpn, ext_quic_transport_parameters }) |ext_id| {
        var h = Harness.init();
        try h.wire();
        try h.client.start(defaultParams());

        var buf: [2048]u8 = undefined;
        const ch = (try h.client.pollOutput(.initial, &buf)).?;
        try h.server.onCrypto(.initial, ch.offset, ch.bytes);
        const sh = (try h.server.pollOutput(.initial, &buf)).?;
        try h.client.onCrypto(.initial, sh.offset, sh.bytes);

        // EncryptedExtensions is the first message of the server flight; its
        // extension block length sits right after the 4-byte message header.
        var flight_buf: [4096]u8 = undefined;
        const flight = (try h.server.pollOutput(.handshake, &flight_buf)).?;
        const new_len = duplicateExtension(&flight_buf, flight.bytes.len, 4, ext_id);
        try testing.expectError(error.MalformedHandshake, h.client.onCrypto(.handshake, flight.offset, flight_buf[0..new_len]));
        try testing.expect(!h.client.isComplete());
    }
}

test "an all-zero X25519 key share fails either side deterministically" {
    // Client share zeroed inside the ClientHello: the server must refuse to
    // derive a predictable (all-zero) shared secret.
    var h = Harness.init();
    try h.wire();
    try h.client.start(defaultParams());
    var buf: [2048]u8 = undefined;
    const ch = (try h.client.pollOutput(.initial, &buf)).?;
    const client_pub = (X25519.KeyPair.generateDeterministic(clientEntropy().key_share_seed) catch unreachable).public_key;
    const client_share_at = std.mem.indexOf(u8, ch.bytes, &client_pub) orelse return error.TestUnexpectedResult;
    @memset(buf[client_share_at..][0..X25519.public_length], 0);
    try testing.expectError(error.MalformedHandshake, h.server.onCrypto(.initial, ch.offset, ch.bytes));
    try testing.expect(!h.server.isComplete());

    // Server share zeroed inside the ServerHello: same on the client.
    var h2 = Harness.init();
    try h2.wire();
    try h2.client.start(defaultParams());
    const ch2 = (try h2.client.pollOutput(.initial, &buf)).?;
    try h2.server.onCrypto(.initial, ch2.offset, ch2.bytes);
    const sh = (try h2.server.pollOutput(.initial, &buf)).?;
    const server_pub = (X25519.KeyPair.generateDeterministic(serverEntropy().key_share_seed) catch unreachable).public_key;
    const server_share_at = std.mem.indexOf(u8, sh.bytes, &server_pub) orelse return error.TestUnexpectedResult;
    @memset(buf[server_share_at..][0..X25519.public_length], 0);
    try testing.expectError(error.MalformedHandshake, h2.client.onCrypto(.initial, sh.offset, sh.bytes));
    try testing.expect(!h2.client.isComplete());
}

test "a fragmented NewSessionTicket after completion is tolerated and ignored" {
    var h = Harness.init();
    try h.wire();
    try h.run();
    try testing.expect(h.client.isComplete());

    // NewSessionTicket (type 4) with an opaque body, split mid-header across
    // two 1-RTT CRYPTO deliveries like any other fragmented handshake message.
    const ticket = [_]u8{ 4, 0, 0, 5, 0xde, 0xad, 0xbe, 0xef, 0x01 };
    try h.client.onCrypto(.application, 0, ticket[0..3]);
    try h.client.onCrypto(.application, 3, ticket[3..]);
    try testing.expect(h.client.isComplete());
    try testing.expectEqual(@as(?HandshakeError, null), h.client.failure());

    // A second ticket on the same stream keeps draining.
    try h.client.onCrypto(.application, ticket.len, &ticket);
    try testing.expect(h.client.isComplete());
}

test "post-handshake application CRYPTO other than NewSessionTicket is rejected" {
    var h = Harness.init();
    try h.wire();
    try h.run();
    try testing.expect(h.client.isComplete());

    // An unknown handshake message type is malformed.
    const bogus = [_]u8{ 99, 0, 0, 0 };
    try testing.expectError(error.MalformedHandshake, h.client.onCrypto(.application, 0, &bogus));

    // A handshake-phase message (Finished) at the 1-RTT level is a level error.
    var h2 = Harness.init();
    try h2.wire();
    try h2.run();
    const stray_finished = [_]u8{ 20, 0, 0, 0 };
    try testing.expectError(error.UnexpectedCryptoLevel, h2.client.onCrypto(.application, 0, &stray_finished));
}

test "application CRYPTO before the handshake completes is a level error" {
    var h = Harness.init();
    try h.wire();
    try h.client.start(defaultParams());
    const ticket = [_]u8{ 4, 0, 0, 0 };
    try testing.expectError(error.UnexpectedCryptoLevel, h.client.onCrypto(.application, 0, &ticket));
}

test "a ClientHello delivered at the Handshake level is a level error" {
    var h = Harness.init();
    try h.wire();
    try h.client.start(defaultParams());

    var buf: [2048]u8 = undefined;
    const ch = (try h.client.pollOutput(.initial, &buf)).?;
    try testing.expectError(error.UnexpectedCryptoLevel, h.server.onCrypto(.handshake, ch.offset, ch.bytes));
    try testing.expect(!h.server.isComplete());
}

test "a ClientHello without transport parameters fails the server at completion" {
    var h = Harness.init();
    h.client_backend.omit_transport_parameters = true;
    try h.wire();
    // The server only detects the omission when the handshake authenticates
    // (client Finished), per the parsed-vs-authenticated distinction.
    try testing.expectError(error.MissingTransportParameters, h.run());
    try testing.expect(!h.server.isComplete());
    try testing.expectEqual(@as(?HandshakeError, error.MissingTransportParameters), h.server.failure());
}

test "a server omitting transport parameters fails the client at completion" {
    var h = Harness.init();
    h.server_backend.omit_transport_parameters = true;
    try h.wire();
    try testing.expectError(error.MissingTransportParameters, h.run());
    try testing.expect(!h.client.isComplete());
    try testing.expectEqual(@as(?HandshakeError, error.MissingTransportParameters), h.client.failure());
}
