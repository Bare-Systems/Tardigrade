//! QUIC handshake driver (#296): the backend-agnostic state machine that drives
//! a TLS 1.3 handshake through the `QuicTlsAdapter` seam (#249). It moves TLS
//! handshake bytes in and out of the adapter's CRYPTO streams per encryption
//! level, installs traffic secrets at the correct phase, authenticates peer
//! transport parameters, enforces ALPN `h3`, reports certificate state, and
//! surfaces typed failures — without any concrete TLS engine of its own.
//!
//! The concrete TLS engine is injected as a `TlsBackend` vtable, so no backend
//! type escapes into the rest of `src/quic/`. Zig 0.16's `std.crypto.tls` is a
//! client-only, record/stream TLS implementation with no way to pump raw
//! handshake bytes or export QUIC traffic secrets, so it cannot back QUIC
//! without inverting the design; the production backend is the pure-Zig TLS
//! TLS-owned 1.3 engine in `../tls/tls13_backend.zig`, adapted by
//! `tls_backend.zig`. See `docs/QUIC_TLS.md`. This module also
//! ships a deterministic in-memory `TestTlsBackend` that proves the driver end
//! to end and remains the regression seam for later packet-layer work.

const std = @import("std");
const config = @import("config.zig");
const tls_adapter = @import("tls_adapter.zig");
const tls_core = @import("tls_core");

const EncryptionLevel = tls_adapter.EncryptionLevel;
const Direction = tls_adapter.Direction;
const CertificateState = tls_adapter.CertificateState;
const Secret = tls_adapter.Secret;
const QuicTlsAdapter = tls_adapter.QuicTlsAdapter;
const traffic_secret_len = tls_adapter.traffic_secret_len;

pub const Role = tls_core.state.Role;

pub const HandshakeError = tls_core.events.HandshakeError || tls_core.messages.ReadError || tls_core.messages.WriteError || error{
    /// The generic TLS driver was called in an invalid lifecycle state.
    InvalidHandshakeState,
    /// A CRYPTO fragment arrived at a level the handshake never uses (0-RTT).
    UnexpectedCryptoLevel,
    /// Handshake completed without the peer's QUIC transport parameters.
    MissingTransportParameters,
    /// Peer QUIC transport parameters were malformed or carried an illegal value.
    InvalidTransportParameters,
    /// The backend or driver emitted more output than this bounded QUIC seam can buffer.
    HandshakeBufferOverflow,
};

const TransportContract = tls_core.transport.ContractWithOptions(
    config.TransportParameters,
    EncryptionLevel,
    HandshakeError,
    16,
    16 * 1024,
    error.HandshakeBufferOverflow,
);

pub const Event = TransportContract.Event;
pub const EventSink = TransportContract.EventSink;
pub const TlsTransportBackend = TransportContract.Backend;
pub const CoreDriver = tls_core.engine.Driver(TransportContract);

/// Runtime interface to a concrete TLS 1.3 engine. The engine consumes and
/// produces raw handshake bytes and reports keying material / negotiation
/// results through the shared transport `EventSink`; it never sees QUIC packets
/// or the adapter. QUIC connection-ID binding hooks stay local to this wrapper.
pub const TlsBackend = struct {
    transport: TlsTransportBackend,
    deinitFn: ?*const fn (ptr: *anyopaque) void = null,
    /// Optional RFC 9000 §7.3 authentication-binding hooks. A backend that
    /// carries connection IDs in its transport parameters implements both; the
    /// in-memory test backend leaves them null.
    setCidBindingFn: ?*const fn (ptr: *anyopaque, binding: config.CidBinding) void = null,
    peerCidBindingFn: ?*const fn (ptr: *anyopaque) config.CidBinding = null,

    fn start(self: TlsBackend, role: Role, params: config.TransportParameters, sink: *EventSink) HandshakeError!void {
        return self.transport.start(role, params, sink);
    }

    fn receive(self: TlsBackend, level: EncryptionLevel, bytes: []const u8, sink: *EventSink) HandshakeError!void {
        return self.transport.receive(level, bytes, sink);
    }

    pub fn setCidBinding(self: TlsBackend, binding: config.CidBinding) void {
        if (self.setCidBindingFn) |set| set(self.transport.ptr, binding);
    }

    pub fn peerCidBinding(self: TlsBackend) config.CidBinding {
        if (self.peerCidBindingFn) |get| return get(self.transport.ptr);
        return .{};
    }

    pub fn deinit(self: TlsBackend) void {
        self.transport.deinit();
    }
};

pub const State = tls_core.state.DriverState;

/// The connection-facing QUIC handshake driver. A QUIC connection calls
/// `start`, then pumps `onCrypto` / `pollOutput` per encryption level until
/// `isComplete()` or `failure()` is set.
pub const Handshake = struct {
    adapter: *QuicTlsAdapter,
    driver: CoreDriver,
    /// Require ALPN to negotiate exactly `h3` (the QUIC/H3 path). Always true
    /// for HTTP/3; exposed so future ALPNs can reuse the driver.
    require_alpn_h3: bool = true,
    /// Local-only escape hatch to accept `.not_checked` certificate state at
    /// completion. Off by default; tests must opt in explicitly.
    allow_unverified_certificate: bool = false,
    /// When true, the connection driver owns key-discard timing (RFC 9001
    /// §4.9 / RFC 9002 §6.4): backend discard events only mark the level in
    /// `discard_requested`, and the driver applies them through the adapter
    /// once its retransmission obligations for that level have ended. Without
    /// a driver (crypto-only harnesses), discards apply as soon as the level's
    /// queued output drains.
    manual_key_discard: bool = false,
    discard_requested: [4]bool = .{ false, false, false, false },
    /// Key discards requested by the backend for levels that still have
    /// undrained CRYPTO output. RFC 9001 §4.9: a level's write keys must
    /// outlive the flight they protect (the server's ServerHello is queued at
    /// the Initial level in the same event batch that discards Initial keys),
    /// so the discard is applied once `pollOutput` drains the level.
    pending_discard: [4]bool = .{ false, false, false, false },

    pub fn initClient(adapter: *QuicTlsAdapter, backend: TlsBackend) Handshake {
        return .{ .adapter = adapter, .driver = CoreDriver.init(.client, backend.transport) };
    }

    pub fn initServer(adapter: *QuicTlsAdapter, backend: TlsBackend) Handshake {
        return .{ .adapter = adapter, .driver = CoreDriver.init(.server, backend.transport) };
    }

    /// Securely wipe any traffic secret still copied into the driver's
    /// internal event sink from the last `start`/`onCrypto` call. The owning
    /// `Connection` calls this exactly once during its own teardown,
    /// regardless of whether the handshake completed, failed, or was
    /// abandoned mid-flight (#408 finding 2).
    pub fn deinit(self: *Handshake) void {
        self.driver.deinit();
    }

    /// Provide local transport parameters to TLS and emit the first flight
    /// (client) or arm the responder (server).
    pub fn start(self: *Handshake, local_params: config.TransportParameters) HandshakeError!void {
        self.adapter.setLocalTransportParameters(local_params);
        try self.applyEvents(try self.driver.start(local_params));
    }

    /// Feed a CRYPTO fragment received at `level`, reassemble it in order, and
    /// drive the backend with any newly contiguous handshake bytes.
    pub fn onCrypto(self: *Handshake, level: EncryptionLevel, offset: u64, bytes: []const u8) HandshakeError!void {
        if (self.driver.state == .failed) return self.driver.failure().?;
        self.adapter.receiveCrypto(level, offset, bytes) catch |err| return self.fail(switch (err) {
            error.InvalidCryptoLevel => error.UnexpectedCryptoLevel,
            error.CryptoBufferTooLarge, error.TooManyCryptoRanges => error.MalformedHandshake,
        });
        while (true) {
            const input = (self.adapter.nextHandshakeInput(level) catch return self.fail(error.UnexpectedCryptoLevel)) orelse break;
            try self.applyEvents(try self.driver.receive(input.level, input.bytes));
        }
    }

    /// Drain up to `buf.len` queued handshake bytes for `level`. Returns the
    /// stream offset and the slice written into `buf`, null when no bytes are
    /// pending, or `error.UnexpectedCryptoLevel` when asked for a level the
    /// handshake never sends on — a caller/state-machine bug, kept distinct from
    /// "idle".
    pub fn pollOutput(self: *Handshake, level: EncryptionLevel, buf: []u8) HandshakeError!?struct { offset: u64, bytes: []u8 } {
        // Apply a deferred key discard only once the caller comes back after
        // sealing the level's final chunk — never in the same call that hands
        // that chunk out, or the caller could not protect the packet carrying
        // it.
        self.applyDeferredDiscard(level);
        const output = (self.adapter.nextHandshakeOutput(level, buf.len) catch |err| return self.fail(switch (err) {
            error.InvalidCryptoLevel => error.UnexpectedCryptoLevel,
        })) orelse return null;
        @memcpy(buf[0..output.bytes.len], output.bytes);
        return .{ .offset = output.offset, .bytes = buf[0..output.bytes.len] };
    }

    pub fn isComplete(self: *const Handshake) bool {
        return self.driver.isComplete();
    }

    pub fn failure(self: *const Handshake) ?HandshakeError {
        return self.driver.failure();
    }

    fn fail(self: *Handshake, err: HandshakeError) HandshakeError {
        return self.driver.fail(err);
    }

    /// True once the backend has signalled that keys for `level` are no
    /// longer needed by TLS; in manual mode the connection driver applies the
    /// actual discard when retransmission rules allow.
    pub fn discardRequested(self: *const Handshake, level: EncryptionLevel) bool {
        return self.discard_requested[level.index()];
    }

    fn discardOrDefer(self: *Handshake, level: EncryptionLevel) void {
        if (self.manual_key_discard) {
            self.discard_requested[level.index()] = true;
            return;
        }
        if (level != .zero_rtt and self.adapter.outbound[level.index()].pending() > 0) {
            self.pending_discard[level.index()] = true;
            return;
        }
        self.adapter.discardSecrets(level);
    }

    fn applyDeferredDiscard(self: *Handshake, level: EncryptionLevel) void {
        if (level == .zero_rtt) return;
        if (!self.pending_discard[level.index()]) return;
        if (self.adapter.outbound[level.index()].pending() != 0) return;
        self.pending_discard[level.index()] = false;
        self.adapter.discardSecrets(level);
    }

    fn applyEvents(self: *Handshake, sink: *EventSink) HandshakeError!void {
        var index: usize = 0;
        while (index < sink.len) : (index += 1) {
            switch (sink.items[index]) {
                .handshake_bytes => |c| self.adapter.queueHandshakeOutput(c.epoch, c.data) catch |err| return self.fail(switch (err) {
                    error.InvalidCryptoLevel => error.UnexpectedCryptoLevel,
                    error.CryptoBufferTooLarge => error.HandshakeBufferOverflow,
                }),
                .traffic_secret => |s| {
                    const secret = Secret.init(s.epoch, s.direction, s.data) catch return self.fail(error.SecretExportFailed);
                    if (s.data.len != traffic_secret_len) return self.fail(error.SecretExportFailed);
                    self.adapter.installSecret(secret);
                },
                .peer_transport_parameters => |params| self.adapter.setPeerTransportParameters(params),
                .alpn => |protocol| {
                    self.adapter.markAlpn(protocol);
                    if (self.require_alpn_h3 and !self.adapter.negotiatedH3()) return self.fail(error.AlpnMismatch);
                },
                .certificate => |cert_state| {
                    self.adapter.setCertificateState(cert_state);
                    if (cert_state == .invalid) return self.fail(error.CertificateInvalid);
                },
                .discard_epoch => |level| self.discardOrDefer(level),
                .handshake_complete => try self.complete(),
                // QUIC never emits this: RFC 9001 SS4.8 has the connection
                // derive its own CRYPTO_ERROR close from the returned
                // HandshakeError rather than a record-layer alert. The
                // contract carries the variant so record mode can use it
                // (#408 finding 1); QUIC's backend does not populate it.
                .fatal_alert => {},
            }
        }
    }

    fn complete(self: *Handshake) HandshakeError!void {
        if (!self.adapter.peerTransportParametersReceived()) return self.fail(error.MissingTransportParameters);
        if (self.require_alpn_h3 and !self.adapter.negotiatedH3()) return self.fail(error.AlpnMismatch);
        // Only the client validates a peer certificate in the server-auth QUIC/H3
        // model; the server has no client certificate to check here.
        if (self.driver.role == .client and !self.allow_unverified_certificate and self.adapter.certificateState() != .valid) {
            return self.fail(error.CertificateInvalid);
        }
        // Transport parameters are only exposed to connection logic now that the
        // handshake has authenticated them.
        self.adapter.authenticatePeerTransportParameters();
        self.driver.complete();
    }
};

// ===========================================================================
// Deterministic in-memory test backend (#296 harness).
//
// Not a real TLS engine: it exchanges a compact, fixed message set that carries
// exactly what the QUIC handshake driver must route — ALPN, transport
// parameters, a certificate fixture, and per-level traffic secrets — so a
// client and server driver can complete a handshake purely by pumping CRYPTO
// bytes. Secrets are derived from the shared handshake transcript, so any
// dropped or reordered byte makes the two sides' secrets diverge and fails the
// test. This is the regression seam for later packet-layer integration; the
// production TLS backend implements the same `TlsBackend` interface.
// ===========================================================================

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

const MessageType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    encrypted_extensions = 3,
    certificate = 4,
    finished = 5,
};

/// Wire size of an encoded `config.TransportParameters` (nine u64 + one bool).
const transport_params_encoded_len = 9 * 8 + 1;

pub const TestTlsBackend = struct {
    role: Role = .client,
    /// ALPN this side offers (client) or supports/selects (server).
    alpn: []const u8 = "h3",
    /// Certificate fixture the server presents / the client reports.
    certificate: CertificateState = .valid,
    include_transport_params: bool = true,
    /// Emit deliberately illegal transport parameters (drives negative tests).
    corrupt_transport_params: bool = false,
    local_params: config.TransportParameters = undefined,
    transcript: [4096]u8 = undefined,
    transcript_len: usize = 0,

    pub fn backend(self: *TestTlsBackend) TlsBackend {
        return .{
            .transport = .{
                .ptr = self,
                .startFn = startImpl,
                .receiveFn = receiveImpl,
            },
        };
    }

    fn appendTranscript(self: *TestTlsBackend, bytes: []const u8) void {
        // Bounded by the small fixed message set; assert rather than error.
        std.debug.assert(bytes.len <= self.transcript.len - self.transcript_len);
        @memcpy(self.transcript[self.transcript_len..][0..bytes.len], bytes);
        self.transcript_len += bytes.len;
    }

    fn deriveSecret(self: *const TestTlsBackend, comptime label: []const u8) [traffic_secret_len]u8 {
        return HkdfSha256.extract(label, self.transcript[0..self.transcript_len]);
    }

    fn startImpl(ptr: *anyopaque, role: Role, params: config.TransportParameters, sink: *EventSink) HandshakeError!void {
        const self: *TestTlsBackend = @ptrCast(@alignCast(ptr));
        self.role = role;
        self.local_params = params;
        if (role != .client) return; // server waits for ClientHello

        var buf: [256]u8 = undefined;
        const hello = self.encodeHello(&buf, .client_hello);
        self.appendTranscript(hello);
        try sink.emitCrypto(.initial, hello);
    }

    fn receiveImpl(ptr: *anyopaque, level: EncryptionLevel, bytes: []const u8, sink: *EventSink) HandshakeError!void {
        const self: *TestTlsBackend = @ptrCast(@alignCast(ptr));
        var reader = MessageReader{ .bytes = bytes };
        while (try reader.next()) |message| {
            // Enforce the CRYPTO packet-number space each message belongs to, so
            // the connection layer can trust this seam to catch level mistakes.
            try expectLevel(message.kind, level);
            self.appendTranscript(message.raw);
            switch (self.role) {
                .server => try self.onServerMessage(message, sink),
                .client => try self.onClientMessage(message, sink),
            }
        }
    }

    fn onServerMessage(self: *TestTlsBackend, message: Message, sink: *EventSink) HandshakeError!void {
        switch (message.kind) {
            .client_hello => {},
            .finished => {
                // Client Finished confirms the handshake for the server.
                try sink.emitDiscardKeys(.handshake);
                try sink.emitHandshakeComplete();
                return;
            },
            // A well-formed server-flight message (ServerHello, etc.) that only
            // a client should receive: legal bytes, wrong role/state.
            else => return error.UnexpectedHandshakeMessage,
        }

        // The client's transport parameters ride in the ClientHello.
        if (message.transport_params) |params| {
            try sink.emitPeerTransportParameters(params);
        }

        // ServerHello selects ALPN and unlocks Handshake keys.
        var buf: [256]u8 = undefined;
        const server_hello = self.encodeHello(&buf, .server_hello);
        self.appendTranscript(server_hello);
        try sink.emitCrypto(.initial, server_hello);
        try sink.emitAlpn(self.alpn);
        try self.emitHandshakeSecrets(sink);
        try sink.emitDiscardKeys(.initial);

        // Server Handshake flight: EncryptedExtensions + Certificate + Finished.
        var flight: [512]u8 = undefined;
        const server_flight = self.encodeServerFlight(&flight);
        self.appendTranscript(server_flight);
        try sink.emitCrypto(.handshake, server_flight);
        try self.emitApplicationSecrets(sink);
    }

    fn onClientMessage(self: *TestTlsBackend, message: Message, sink: *EventSink) HandshakeError!void {
        switch (message.kind) {
            .server_hello => {
                try sink.emitAlpn(message.alpn);
                try self.emitHandshakeSecrets(sink);
                try sink.emitDiscardKeys(.initial);
            },
            .encrypted_extensions => {
                if (message.transport_params) |params| try sink.emitPeerTransportParameters(params);
            },
            .certificate => try sink.emitCertificate(message.certificate),
            .finished => {
                // Server Finished closes the server flight: install 1-RTT keys,
                // send the client Finished, and complete.
                try self.emitApplicationSecrets(sink);
                var buf: [8]u8 = undefined;
                const finished = encodeMessage(&buf, .finished, &.{});
                self.appendTranscript(finished);
                try sink.emitCrypto(.handshake, finished);
                try sink.emitDiscardKeys(.handshake);
                try sink.emitHandshakeComplete();
            },
            // A ClientHello is well-formed but only a server may receive one.
            .client_hello => return error.UnexpectedHandshakeMessage,
        }
    }

    fn emitHandshakeSecrets(self: *TestTlsBackend, sink: *EventSink) HandshakeError!void {
        const c2s = self.deriveSecret("quic-test hs c2s");
        const s2c = self.deriveSecret("quic-test hs s2c");
        switch (self.role) {
            .client => {
                try sink.emitSecret(.handshake, .write, &c2s);
                try sink.emitSecret(.handshake, .read, &s2c);
            },
            .server => {
                try sink.emitSecret(.handshake, .read, &c2s);
                try sink.emitSecret(.handshake, .write, &s2c);
            },
        }
    }

    fn emitApplicationSecrets(self: *TestTlsBackend, sink: *EventSink) HandshakeError!void {
        const c2s = self.deriveSecret("quic-test ap c2s");
        const s2c = self.deriveSecret("quic-test ap s2c");
        switch (self.role) {
            .client => {
                try sink.emitSecret(.application, .write, &c2s);
                try sink.emitSecret(.application, .read, &s2c);
            },
            .server => {
                try sink.emitSecret(.application, .read, &c2s);
                try sink.emitSecret(.application, .write, &s2c);
            },
        }
    }

    fn encodeHello(self: *const TestTlsBackend, buf: []u8, kind: MessageType) []const u8 {
        var payload: [1 + 64 + transport_params_encoded_len]u8 = undefined;
        var len: usize = 0;
        payload[len] = @intCast(self.alpn.len);
        len += 1;
        @memcpy(payload[len..][0..self.alpn.len], self.alpn);
        len += self.alpn.len;
        // ClientHello carries the client's transport parameters; ServerHello
        // does not (the server sends them in EncryptedExtensions).
        if (kind == .client_hello and self.include_transport_params) {
            len += self.encodeTransportParams(payload[len..]);
        }
        return encodeMessage(buf, kind, payload[0..len]);
    }

    fn encodeServerFlight(self: *const TestTlsBackend, buf: []u8) []const u8 {
        var len: usize = 0;
        if (self.include_transport_params) {
            var ee_payload: [transport_params_encoded_len]u8 = undefined;
            const n = self.encodeTransportParams(&ee_payload);
            len += encodeMessage(buf[len..], .encrypted_extensions, ee_payload[0..n]).len;
        } else {
            len += encodeMessage(buf[len..], .encrypted_extensions, &.{}).len;
        }
        const cert_payload = [_]u8{@intFromEnum(self.certificate)};
        len += encodeMessage(buf[len..], .certificate, &cert_payload).len;
        len += encodeMessage(buf[len..], .finished, &.{}).len;
        return buf[0..len];
    }

    fn encodeTransportParams(self: *const TestTlsBackend, buf: []u8) usize {
        const p = self.local_params;
        var offset: usize = 0;
        const fields = [_]u64{
            p.max_idle_timeout_ms,
            p.active_connection_id_limit,
            // A corrupt run emits an illegal (below-minimum) UDP payload size.
            if (self.corrupt_transport_params) 0 else p.max_udp_payload_size,
            p.initial_max_data,
            p.initial_max_stream_data_bidi_local,
            p.initial_max_stream_data_bidi_remote,
            p.initial_max_stream_data_uni,
            p.initial_max_streams_bidi,
            p.initial_max_streams_uni,
        };
        for (fields) |value| {
            std.mem.writeInt(u64, buf[offset..][0..8], value, .big);
            offset += 8;
        }
        buf[offset] = @intFromBool(p.disable_active_migration);
        offset += 1;
        return offset;
    }
};

/// The CRYPTO encryption level each handshake message must arrive at. Initial
/// carries the *Hello messages; the rest of the flight is Handshake-level.
/// 0-RTT never carries CRYPTO and Application post-handshake messages are out of
/// scope for this harness, so any other level is a deterministic error.
fn expectLevel(kind: MessageType, level: EncryptionLevel) HandshakeError!void {
    const expected: EncryptionLevel = switch (kind) {
        .client_hello, .server_hello => .initial,
        .encrypted_extensions, .certificate, .finished => .handshake,
    };
    if (level != expected) return error.UnexpectedCryptoLevel;
}

fn encodeMessage(buf: []u8, kind: MessageType, payload: []const u8) []const u8 {
    std.debug.assert(payload.len <= std.math.maxInt(u16));
    buf[0] = @intFromEnum(kind);
    std.mem.writeInt(u16, buf[1..3], @intCast(payload.len), .big);
    @memcpy(buf[3..][0..payload.len], payload);
    return buf[0 .. 3 + payload.len];
}

const Message = struct {
    kind: MessageType,
    raw: []const u8,
    alpn: []const u8 = "",
    transport_params: ?config.TransportParameters = null,
    certificate: CertificateState = .not_checked,
};

const MessageReader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn next(self: *MessageReader) HandshakeError!?Message {
        if (self.offset == self.bytes.len) return null;
        if (self.bytes.len - self.offset < 3) return error.MalformedHandshake;
        const kind = std.enums.fromInt(MessageType, self.bytes[self.offset]) orelse return error.MalformedHandshake;
        const payload_len = std.mem.readInt(u16, self.bytes[self.offset + 1 ..][0..2], .big);
        const header_end = self.offset + 3;
        if (self.bytes.len - header_end < payload_len) return error.MalformedHandshake;
        const payload = self.bytes[header_end..][0..payload_len];
        const raw = self.bytes[self.offset .. header_end + payload_len];
        self.offset = header_end + payload_len;

        var message = Message{ .kind = kind, .raw = raw };
        switch (kind) {
            .client_hello, .server_hello => try parseHello(payload, &message),
            .encrypted_extensions => if (payload.len > 0) {
                message.transport_params = try parseTransportParams(payload);
            },
            .certificate => {
                if (payload.len != 1) return error.MalformedHandshake;
                message.certificate = std.enums.fromInt(CertificateState, payload[0]) orelse return error.MalformedHandshake;
            },
            .finished => if (payload.len != 0) return error.MalformedHandshake,
        }
        return message;
    }
};

fn parseHello(payload: []const u8, message: *Message) HandshakeError!void {
    if (payload.len < 1) return error.MalformedHandshake;
    const alpn_len = payload[0];
    if (payload.len < 1 + alpn_len) return error.MalformedHandshake;
    message.alpn = payload[1 .. 1 + alpn_len];
    const rest = payload[1 + alpn_len ..];
    if (rest.len > 0) message.transport_params = try parseTransportParams(rest);
}

fn parseTransportParams(bytes: []const u8) HandshakeError!config.TransportParameters {
    if (bytes.len != transport_params_encoded_len) return error.InvalidTransportParameters;
    var offset: usize = 0;
    var values: [9]u64 = undefined;
    for (&values) |*value| {
        value.* = std.mem.readInt(u64, bytes[offset..][0..8], .big);
        offset += 8;
    }
    const params = config.TransportParameters{
        .max_idle_timeout_ms = values[0],
        .active_connection_id_limit = values[1],
        .max_udp_payload_size = values[2],
        .initial_max_data = values[3],
        .initial_max_stream_data_bidi_local = values[4],
        .initial_max_stream_data_bidi_remote = values[5],
        .initial_max_stream_data_uni = values[6],
        .initial_max_streams_bidi = values[7],
        .initial_max_streams_uni = values[8],
        .disable_active_migration = bytes[offset] != 0,
    };
    // Reject values QUIC forbids (RFC 9000 §18.2): a peer that advertises an
    // unusable maximum UDP payload size is a fatal, deterministic error.
    if (params.max_udp_payload_size < 1200) return error.InvalidTransportParameters;
    return params;
}

// ===========================================================================
// Tests: deterministic in-memory client<->server handshake harness.
// Bytes move ONLY through the adapter CRYPTO APIs via pollOutput/onCrypto — no
// UDP, packet protection, or HTTP/3 — per the #296 first-harness requirement.
// ===========================================================================

const testing = std.testing;

fn defaultParams() config.TransportParameters {
    return (config.Config{}).transportParameters() catch unreachable;
}

const Harness = struct {
    client_adapter: QuicTlsAdapter = .{},
    server_adapter: QuicTlsAdapter = .{},
    client_backend: TestTlsBackend = .{},
    server_backend: TestTlsBackend = .{},
    client: Handshake = undefined,
    server: Handshake = undefined,

    fn wire(self: *Harness) !void {
        // Initial secrets come from the client DCID (installed by the connection
        // layer, not TLS). They let us prove Initial-key discard through the driver.
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        _ = try self.client_adapter.installInitialSecrets(.client, &dcid);
        _ = try self.server_adapter.installInitialSecrets(.server, &dcid);
        self.client = Handshake.initClient(&self.client_adapter, self.client_backend.backend());
        self.server = Handshake.initServer(&self.server_adapter, self.server_backend.backend());
        // Arm the responder: the server's start() emits nothing but primes its
        // backend role and local transport parameters before the first flight.
        try self.server.start(defaultParams());
    }

    /// Pump handshake bytes between the two sides until both complete or no side
    /// makes progress. Returns the first deterministic failure, if any.
    fn run(self: *Harness) HandshakeError!void {
        if (self.client.driver.state == .idle) try self.client.start(defaultParams());
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |level| {
                var buf: [2048]u8 = undefined;
                while (try self.client.pollOutput(level, &buf)) |out| {
                    try self.server.onCrypto(level, out.offset, out.bytes);
                    progressed = true;
                }
                while (try self.server.pollOutput(level, &buf)) |out| {
                    try self.client.onCrypto(level, out.offset, out.bytes);
                    progressed = true;
                }
            }
            if (!progressed) break;
        }
    }
};

fn expectSecretsMatch(a: *const QuicTlsAdapter, b: *const QuicTlsAdapter, level: EncryptionLevel) !void {
    // What one side writes, the other must read (RFC 9001 secrets are shared).
    const a_write = a.protectionKeys(level, .write) orelse return error.TestUnexpectedResult;
    const b_read = b.protectionKeys(level, .read) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &a_write.key, &b_read.key);
}

test "in-memory client<->server handshake completes and installs matching 1-RTT secrets" {
    var h = Harness{};
    try h.wire();
    try h.run();

    try testing.expect(h.client.isComplete());
    try testing.expect(h.server.isComplete());
    try testing.expectEqual(@as(?HandshakeError, null), h.client.failure());
    try testing.expectEqual(@as(?HandshakeError, null), h.server.failure());

    // 1-RTT secrets are installed and shared in both directions.
    try expectSecretsMatch(&h.client_adapter, &h.server_adapter, .application);
    try expectSecretsMatch(&h.server_adapter, &h.client_adapter, .application);

    // Phase ordering: Initial and Handshake keys are discarded by completion,
    // 1-RTT keys remain.
    try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), h.client_adapter.protectionKeys(.initial, .write));
    try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), h.server_adapter.protectionKeys(.handshake, .read));
    try testing.expect(h.client_adapter.protectionKeys(.application, .write) != null);

    // ALPN negotiated h3; server certificate reported valid to the client.
    try testing.expect(h.client_adapter.negotiatedH3());
    try testing.expect(h.server_adapter.negotiatedH3());
    try testing.expectEqual(CertificateState.valid, h.client_adapter.certificateState());
}

test "handshake secrets match on both sides before they are discarded" {
    var h = Harness{};
    try h.wire();
    try h.client.start(defaultParams());

    // ClientHello -> server.
    var buf: [2048]u8 = undefined;
    const ch = (try h.client.pollOutput(.initial, &buf)).?;
    try h.server.onCrypto(.initial, ch.offset, ch.bytes);
    // ServerHello -> client (installs Handshake secrets on both sides).
    const sh = (try h.server.pollOutput(.initial, &buf)).?;
    try h.client.onCrypto(.initial, sh.offset, sh.bytes);

    try expectSecretsMatch(&h.client_adapter, &h.server_adapter, .handshake);
    try expectSecretsMatch(&h.server_adapter, &h.client_adapter, .handshake);
}

test "peer transport parameters are withheld until the handshake completes" {
    var h = Harness{};
    try h.wire();
    try h.client.start(defaultParams());

    // Deliver ClientHello: the server has received the peer params but must not
    // expose them before authentication.
    var buf: [2048]u8 = undefined;
    const ch = (try h.client.pollOutput(.initial, &buf)).?;
    try h.server.onCrypto(.initial, ch.offset, ch.bytes);
    try testing.expect(h.server_adapter.peerTransportParametersReceived());
    try testing.expectEqual(@as(?config.TransportParameters, null), h.server_adapter.peerTransportParameters());

    // After the full handshake, both sides expose authenticated peer params.
    try h.run();
    try testing.expect(h.client.isComplete() and h.server.isComplete());
    const client_view = h.client_adapter.peerTransportParameters() orelse return error.TestUnexpectedResult;
    const server_view = h.server_adapter.peerTransportParameters() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(defaultParams().initial_max_data, client_view.initial_max_data);
    try testing.expectEqual(defaultParams().initial_max_data, server_view.initial_max_data);
}

test "ALPN that is not h3 fails the handshake deterministically" {
    var h = Harness{};
    try h.wire();
    h.server_backend.alpn = "h2"; // server selects a non-h3 protocol
    try testing.expectError(error.AlpnMismatch, h.run());
    try testing.expect(!h.server.isComplete());
    try testing.expectEqual(@as(?HandshakeError, error.AlpnMismatch), h.server.failure());
}

test "an invalid server certificate fails the handshake deterministically" {
    var h = Harness{};
    try h.wire();
    h.server_backend.certificate = .invalid;
    try testing.expectError(error.CertificateInvalid, h.run());
    try testing.expectEqual(CertificateState.invalid, h.client_adapter.certificateState());
    try testing.expect(!h.client.isComplete());
}

test "missing peer transport parameters fail the handshake deterministically" {
    var h = Harness{};
    try h.wire();
    h.client_backend.include_transport_params = false; // ClientHello omits them
    try testing.expectError(error.MissingTransportParameters, h.run());
    try testing.expect(!h.server.isComplete());
}

test "malformed peer transport parameters fail the handshake deterministically" {
    var h = Harness{};
    try h.wire();
    h.client_backend.corrupt_transport_params = true; // illegal max_udp_payload_size
    try testing.expectError(error.InvalidTransportParameters, h.run());
    try testing.expect(!h.server.isComplete());
}

test "server omitting transport parameters fails the client deterministically" {
    var h = Harness{};
    try h.wire();
    h.server_backend.include_transport_params = false; // EncryptedExtensions omits them
    try testing.expectError(error.MissingTransportParameters, h.run());
    try testing.expect(!h.client.isComplete());
}

test "client certificate state not_checked fails by default" {
    var h = Harness{};
    try h.wire();
    h.server_backend.certificate = .not_checked;
    try testing.expectError(error.CertificateInvalid, h.run());
    try testing.expectEqual(CertificateState.not_checked, h.client_adapter.certificateState());
    try testing.expect(!h.client.isComplete());
}

test "client certificate state not_checked passes only in explicit unverified mode" {
    var h = Harness{};
    try h.wire();
    h.server_backend.certificate = .not_checked;
    h.client.allow_unverified_certificate = true; // local/insecure opt-in
    try h.run();
    try testing.expect(h.client.isComplete());
    try testing.expect(h.server.isComplete());
}

test "initial write keys survive until the queued ServerHello is drained" {
    var h = Harness{};
    try h.wire();
    try h.client.start(defaultParams());

    // Deliver the ClientHello: the server queues its ServerHello at the
    // Initial level and requests an Initial key discard in the same event
    // batch. The discard must not take effect while the flight is undrained —
    // the connection layer still has to seal the ServerHello packet.
    var buf: [2048]u8 = undefined;
    const ch = (try h.client.pollOutput(.initial, &buf)).?;
    try h.server.onCrypto(.initial, ch.offset, ch.bytes);
    try testing.expect(h.server_adapter.protectionKeys(.initial, .write) != null);

    // Draining hands out the final chunk with keys still live; the discard
    // lands on the next poll.
    while (try h.server.pollOutput(.initial, &buf)) |_| {
        try testing.expect(h.server_adapter.protectionKeys(.initial, .write) != null);
    }
    try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), h.server_adapter.protectionKeys(.initial, .write));
}

test "ClientHello delivered at the Handshake level is rejected" {
    var h = Harness{};
    try h.wire();
    try h.client.start(defaultParams());

    var buf: [2048]u8 = undefined;
    const ch = (try h.client.pollOutput(.initial, &buf)).?;
    // ClientHello belongs to the Initial space; delivering it as Handshake is a
    // packet-number-space error the seam must catch.
    try testing.expectError(error.UnexpectedCryptoLevel, h.server.onCrypto(.handshake, ch.offset, ch.bytes));
    try testing.expect(!h.server.isComplete());
}

test "server Handshake-flight bytes delivered at the Initial level are rejected" {
    var h = Harness{};
    try h.wire();
    try h.client.start(defaultParams());

    var buf: [2048]u8 = undefined;
    const ch = (try h.client.pollOutput(.initial, &buf)).?;
    try h.server.onCrypto(.initial, ch.offset, ch.bytes);
    // The client has not consumed any Initial bytes yet, so its Initial read
    // stream is fresh: mis-delivering the Handshake flight (EncryptedExtensions
    // first) at the Initial level is a deterministic level error.
    var flight_buf: [2048]u8 = undefined;
    const flight = (try h.server.pollOutput(.handshake, &flight_buf)).?;
    try testing.expectError(error.UnexpectedCryptoLevel, h.client.onCrypto(.initial, flight.offset, flight.bytes));
}

test "a well-formed message for the wrong role is an unexpected_message error" {
    // A server that receives a well-formed ServerHello (a message only a client
    // consumes): the bytes decode, but the message is illegal for this role.
    // That is `unexpected_message`, distinct from the `decode_error` reserved
    // for malformed bytes.
    var h = Harness{};
    try h.wire();
    // ServerHello (type 2) with a zero-length ALPN payload: valid framing.
    const server_hello = [_]u8{ 2, 0, 1, 0 };
    try testing.expectError(error.UnexpectedHandshakeMessage, h.server.onCrypto(.initial, 0, &server_hello));
    try testing.expectEqual(@as(?HandshakeError, error.UnexpectedHandshakeMessage), h.server.failure());
    try testing.expect(!h.server.isComplete());
}

test "a 0-RTT CRYPTO fragment is rejected while 0-RTT is disabled" {
    var adapter = QuicTlsAdapter{};
    var backend = TestTlsBackend{};
    var handshake = Handshake.initServer(&adapter, backend.backend());
    // 0-RTT has no CRYPTO stream (RFC 9001); feeding one is a deterministic error.
    try testing.expectError(error.UnexpectedCryptoLevel, handshake.onCrypto(.zero_rtt, 0, "early"));
    try testing.expectEqual(@as(?HandshakeError, error.UnexpectedCryptoLevel), handshake.failure());
}

test "the connection-facing driver exposes only the backend interface, not a concrete backend" {
    var adapter = QuicTlsAdapter{};
    var backend = TestTlsBackend{};
    const handshake = Handshake.initClient(&adapter, backend.backend());
    // The wrapper holds the protocol-neutral core driver over the runtime
    // transport vtable; no concrete backend type leaks into its public surface.
    try testing.expect(@TypeOf(handshake.driver) == CoreDriver);
    try testing.expect(@TypeOf(handshake.driver.backend) == TlsTransportBackend);
}
