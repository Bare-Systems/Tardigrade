//! Protocol-neutral TLS 1.3 handshake progression.
//!
//! This module owns the parts of a handshake that are independent of the
//! carrier: bounded message reassembly, transcript updates, message ordering,
//! and the lifetime of traffic-secret epochs. QUIC and record mode translate
//! the resulting messages and events through `transport.zig`.

const std = @import("std");
const events = @import("events.zig");
const messages = @import("messages.zig");
const state = @import("state.zig");
const transcript_mod = @import("transcript.zig");

pub const Error = events.HandshakeError || messages.ReassemblerError;
pub const Message = messages.HandshakeMessage;
pub const MessageType = messages.MessageType;
pub const Reader = messages.Reader;
pub const Writer = messages.Writer;
pub const ExtensionIterator = messages.ExtensionIterator;
pub const ExtensionGuard = messages.ExtensionGuard;
pub const Reassembler = messages.Reassembler;
pub const frameLength = messages.frameLength;
pub const decode = messages.decode;
const epoch_count = @typeInfo(events.EncryptionEpoch).@"enum".fields.len;

pub const SecretLifecycle = struct {
    const direction_count = @typeInfo(events.SecretDirection).@"enum".fields.len;
    const SecretState = enum { absent, live, discarded };
    state: [epoch_count][direction_count]SecretState =
        .{.{.absent} ** direction_count} ** epoch_count,

    pub fn install(
        self: *SecretLifecycle,
        epoch: events.EncryptionEpoch,
        direction: events.SecretDirection,
    ) events.SecretLifecycleError!void {
        const slot = &self.state[@intFromEnum(epoch)][@intFromEnum(direction)];
        if (slot.* == .discarded) return error.SecretAlreadyDiscarded;
        slot.* = .live;
    }

    pub fn discardEpoch(self: *SecretLifecycle, epoch: events.EncryptionEpoch) events.SecretLifecycleError!void {
        var found_live = false;
        for (&self.state[@intFromEnum(epoch)]) |*slot| {
            if (slot.* == .live) {
                slot.* = .discarded;
                found_live = true;
            }
        }
        if (!found_live) return error.SecretNotInstalled;
    }

    pub fn isLive(self: *const SecretLifecycle, epoch: events.EncryptionEpoch, direction: events.SecretDirection) bool {
        return self.state[@intFromEnum(epoch)][@intFromEnum(direction)] == .live;
    }
};

pub const HandshakeLifecycle = enum { idle, running, complete, failed };
pub const RetryState = enum { none, hrr_sent, hrr_received };

pub const Core = struct {
    role: state.Role,
    handshake_state: state.HandshakeState = .idle,
    handshake_lifecycle: HandshakeLifecycle = .idle,
    expected_inbound: ?MessageType = null,
    transcript: transcript_mod.Transcript = .{},
    secrets: SecretLifecycle = .{},
    /// Handshake-time client authentication (#334). The server sets
    /// `request_client_certificate` before its flight so it may emit
    /// CertificateRequest and then expect the client's certificate flight after
    /// its own Finished. The client sets `client_certificate_requested` when it
    /// receives that CertificateRequest, so it sends its own certificate flight
    /// before Finished. Both default off — the common no-client-auth path and
    /// QUIC are unchanged. Post-handshake client authentication is deferred.
    request_client_certificate: bool = false,
    client_certificate_requested: bool = false,
    /// Server inbound sub-state for the client's post-Finished certificate
    /// flight; `inactive` unless client auth was requested.
    client_auth_inbound: ClientAuthInbound = .inactive,
    /// Client outbound sub-state for its own certificate flight.
    client_auth_outbound: ClientAuthOutbound = .inactive,
    /// Set once a PSK-resumed handshake (#362) has been selected: the
    /// server flight after EncryptedExtensions goes straight to Finished
    /// (no CertificateRequest, Certificate, or CertificateVerify), and the
    /// client expects Finished immediately after EncryptedExtensions. Both
    /// sides set this — via `enterPskAuthenticated` — once they know a PSK
    /// was selected (server: after choosing to accept it, before its own
    /// EncryptedExtensions is sent; client: after parsing ServerHello's
    /// selected_identity, before EncryptedExtensions arrives). Never set
    /// together with `request_client_certificate`/a client-auth flight:
    /// handshake-time client authentication forces full-handshake fallback.
    psk_authenticated: bool = false,
    retry_state: RetryState = .none,

    pub const ClientAuthInbound = enum { inactive, expect_certificate, expect_certificate_verify, expect_finished };
    pub const ClientAuthOutbound = enum { inactive, send_certificate, send_certificate_verify, send_finished };

    pub fn init(role: state.Role) Core {
        return .{ .role = role };
    }

    /// Declare that a PSK-resumed handshake was selected (#362): the
    /// remaining flight on both sides skips straight from EncryptedExtensions
    /// to Finished. Must be called before the EncryptedExtensions message
    /// is sent (server) or accepted (client).
    pub fn enterPskAuthenticated(self: *Core) void {
        self.psk_authenticated = true;
    }

    /// Server: request that the client authenticate. Call before the server
    /// flight so CertificateRequest is emitted and the client certificate
    /// flight is expected after the server Finished.
    pub fn requestClientCertificate(self: *Core) void {
        self.request_client_certificate = true;
    }

    /// Server: after parsing the client's Certificate, declare whether it was
    /// empty (no client cert). An empty certificate skips CertificateVerify, so
    /// the server expects the client Finished next; a non-empty one expects
    /// CertificateVerify.
    pub fn clientCertificateWasEmpty(self: *Core, empty: bool) void {
        self.client_auth_inbound = if (empty) .expect_finished else .expect_certificate_verify;
    }

    /// Client: begin the local certificate flight after the server Finished.
    /// The client always sends a Certificate first (possibly empty); whether a
    /// CertificateVerify follows depends on whether that certificate was empty,
    /// which the outbound sequence permits either way.
    pub fn beginClientCertificateFlight(self: *Core) void {
        self.client_auth_outbound = .send_certificate;
    }

    pub fn start(self: *Core) Error!void {
        if (self.handshake_lifecycle != .idle) return error.InvalidHandshakeState;
        self.handshake_lifecycle = .running;
        self.expected_inbound = switch (self.role) {
            .client => .server_hello,
            .server => .client_hello,
        };
    }

    pub fn acceptReceived(self: *Core, raw: []const u8) Error!Message {
        if (self.handshake_lifecycle != .running and self.handshake_lifecycle != .complete)
            return error.InvalidHandshakeState;
        const message = messages.decode(raw) catch return error.MalformedHandshake;
        if (message.kind == .client_hello and self.retry_state == .hrr_sent)
            return error.UnexpectedHandshakeMessage;
        if (message.kind == .new_session_ticket) {
            if (self.handshake_lifecycle != .complete or self.role != .client)
                return error.UnexpectedHandshakeMessage;
            self.transcript.update(message.raw);
            return message;
        }
        // A CertificateRequest (server->client, #334) is an optional message the
        // server inserts before its Certificate. Accept it transparently while
        // the client is still expecting the server's Certificate; the client
        // remembers it and will authenticate after the server Finished.
        if (message.kind == .certificate_request) {
            // At most one CertificateRequest may appear in this position of the
            // server flight (RFC 8446 §4.3.2). `expected_inbound` stays
            // `.certificate` after the first, so the remembered flag is what
            // rejects a duplicate rather than accepting and re-hashing it.
            if (self.role != .client or
                self.expected_inbound != .certificate or
                self.client_certificate_requested)
                return error.UnexpectedHandshakeMessage;
            self.client_certificate_requested = true;
            self.transcript.update(message.raw);
            return message;
        }
        // Server inbound for the client's post-Finished certificate flight.
        if (self.client_auth_inbound != .inactive) {
            try self.checkClientAuthInbound(message.kind);
            self.transcript.update(message.raw);
            self.advanceClientAuthInbound(message.kind);
            return message;
        }
        if (!self.isExpectedClientFinished(message.kind)) {
            if (self.expected_inbound != message.kind)
                return error.UnexpectedHandshakeMessage;
        }
        self.transcript.update(message.raw);
        self.advanceAfterReceive(message.kind);
        return message;
    }

    fn checkClientAuthInbound(self: *const Core, kind: MessageType) Error!void {
        const ok = switch (self.client_auth_inbound) {
            .inactive => false,
            .expect_certificate => kind == .certificate,
            // Set by the backend once it has parsed the client's Certificate:
            // a non-empty cert requires CertificateVerify, an empty one skips it.
            .expect_certificate_verify => kind == .certificate_verify,
            .expect_finished => kind == .finished,
        };
        if (!ok) return error.UnexpectedHandshakeMessage;
    }

    fn advanceClientAuthInbound(self: *Core, kind: MessageType) void {
        switch (kind) {
            // After the Certificate the backend refines the next expectation via
            // `clientCertificateWasEmpty`; default to expecting CertificateVerify.
            .certificate => self.client_auth_inbound = .expect_certificate_verify,
            .certificate_verify => self.client_auth_inbound = .expect_finished,
            .finished => {
                self.client_auth_inbound = .inactive;
                self.handshake_lifecycle = .complete;
            },
            else => {},
        }
    }

    pub fn recordSent(self: *Core, raw: []const u8) Error!void {
        if (self.handshake_lifecycle != .running) return error.InvalidHandshakeState;
        const message = messages.decode(raw) catch return error.MalformedHandshake;
        if (message.kind == .client_hello and self.retry_state == .hrr_received)
            return error.UnexpectedHandshakeMessage;
        if (!self.validOutbound(message.kind)) return error.UnexpectedHandshakeMessage;
        self.transcript.update(message.raw);
        self.advanceAfterSend(message.kind);
    }

    pub fn acceptHelloRetryRequest(self: *Core, raw: []const u8) Error!Message {
        if (self.role != .client or
            self.handshake_lifecycle != .running or
            self.expected_inbound != .server_hello or
            self.handshake_state != .client_hello or
            self.retry_state != .none)
            return error.UnexpectedHandshakeMessage;
        const message = messages.decode(raw) catch return error.MalformedHandshake;
        if (message.kind != .server_hello) return error.UnexpectedHandshakeMessage;
        self.transcript.rebindClientHello();
        self.transcript.update(message.raw);
        self.retry_state = .hrr_received;
        self.expected_inbound = null;
        return message;
    }

    pub fn recordHelloRetryRequest(self: *Core, raw: []const u8) Error!void {
        if (self.role != .server or
            self.handshake_lifecycle != .running or
            self.handshake_state != .server_hello or
            self.retry_state != .none)
            return error.UnexpectedHandshakeMessage;
        const message = messages.decode(raw) catch return error.MalformedHandshake;
        if (message.kind != .server_hello) return error.UnexpectedHandshakeMessage;
        self.transcript.rebindClientHello();
        self.transcript.update(message.raw);
        self.retry_state = .hrr_sent;
        self.handshake_state = .idle;
        self.expected_inbound = .client_hello;
    }

    pub fn recordSecondClientHello(self: *Core, raw: []const u8) Error!void {
        if (self.role != .client or
            self.handshake_lifecycle != .running or
            self.retry_state != .hrr_received or
            self.expected_inbound != null)
            return error.UnexpectedHandshakeMessage;
        const message = messages.decode(raw) catch return error.MalformedHandshake;
        if (message.kind != .client_hello) return error.UnexpectedHandshakeMessage;
        self.transcript.update(message.raw);
        self.expected_inbound = .server_hello;
    }

    pub fn acceptSecondClientHello(self: *Core, raw: []const u8) Error!Message {
        if (self.role != .server or
            self.handshake_lifecycle != .running or
            self.retry_state != .hrr_sent or
            self.expected_inbound != .client_hello)
            return error.UnexpectedHandshakeMessage;
        const message = messages.decode(raw) catch return error.MalformedHandshake;
        if (message.kind != .client_hello) return error.UnexpectedHandshakeMessage;
        self.transcript.update(message.raw);
        self.handshake_state = .server_hello;
        self.expected_inbound = null;
        return message;
    }

    pub fn accept(self: *Core, raw: []const u8) Error!Message {
        return self.acceptReceived(raw);
    }

    pub fn transcriptHash(self: *const Core) [transcript_mod.digest_len]u8 {
        return self.transcript.peek();
    }

    fn isExpectedClientFinished(self: *const Core, kind: MessageType) bool {
        const is_server = self.role == .server;
        const awaiting_finished = self.handshake_state == .finished;
        return is_server and awaiting_finished and kind == .finished;
    }

    fn validOutbound(self: *const Core, kind: MessageType) bool {
        return switch (self.role) {
            .client => switch (self.client_auth_outbound) {
                // No client auth: the original client sequence.
                .inactive => (self.handshake_state == .idle and kind == .client_hello) or
                    (self.handshake_state == .finished and self.expected_inbound == null and kind == .finished),
                // Client certificate flight (#334): Certificate, then either
                // CertificateVerify (non-empty cert) or straight to Finished
                // (empty cert), then Finished.
                .send_certificate => kind == .certificate,
                .send_certificate_verify => kind == .certificate_verify or kind == .finished,
                .send_finished => kind == .finished,
            },
            .server => switch (self.handshake_state) {
                .server_hello => kind == .server_hello,
                .encrypted_extensions => kind == .encrypted_extensions,
                .certificate_request => kind == .certificate_request,
                .certificate => kind == .certificate,
                .certificate_verify => kind == .certificate_verify,
                .finished => kind == .finished,
                else => false,
            },
        };
    }

    fn advanceAfterReceive(self: *Core, kind: MessageType) void {
        switch (self.role) {
            .server => switch (kind) {
                .client_hello => {
                    self.handshake_state = .server_hello;
                    self.expected_inbound = null;
                },
                .finished => self.handshake_lifecycle = .complete,
                else => {},
            },
            .client => switch (kind) {
                .server_hello => {
                    self.handshake_state = .encrypted_extensions;
                    self.expected_inbound = .encrypted_extensions;
                },
                .encrypted_extensions => {
                    self.handshake_state = if (self.psk_authenticated) .finished else .certificate;
                    self.expected_inbound = if (self.psk_authenticated) .finished else .certificate;
                },
                .certificate => {
                    self.handshake_state = .certificate_verify;
                    self.expected_inbound = .certificate_verify;
                },
                .certificate_verify => {
                    self.handshake_state = .finished;
                    self.expected_inbound = .finished;
                },
                .finished => self.expected_inbound = null,
                else => {},
            },
        }
    }

    fn advanceAfterSend(self: *Core, kind: MessageType) void {
        switch (self.role) {
            .client => switch (self.client_auth_outbound) {
                .inactive => switch (kind) {
                    .client_hello => {
                        self.handshake_state = .client_hello;
                        self.expected_inbound = .server_hello;
                    },
                    .finished => self.handshake_lifecycle = .complete,
                    else => {},
                },
                else => switch (kind) {
                    .certificate => self.client_auth_outbound = .send_certificate_verify,
                    .certificate_verify => self.client_auth_outbound = .send_finished,
                    .finished => {
                        self.client_auth_outbound = .inactive;
                        self.handshake_lifecycle = .complete;
                    },
                    else => {},
                },
            },
            .server => switch (kind) {
                .server_hello => self.handshake_state = .encrypted_extensions,
                .encrypted_extensions => self.handshake_state = if (self.psk_authenticated)
                    .finished
                else if (self.request_client_certificate)
                    .certificate_request
                else
                    .certificate,
                .certificate_request => self.handshake_state = .certificate,
                .certificate => self.handshake_state = .certificate_verify,
                .certificate_verify => self.handshake_state = .finished,
                // After its own Finished the server either completes, or (when
                // it requested client auth) begins expecting the client's
                // certificate flight.
                .finished => {
                    self.handshake_state = .finished;
                    if (self.request_client_certificate) self.client_auth_inbound = .expect_certificate;
                },
                else => {},
            },
        }
    }
};

test "core records both directions of a client and server flight" {
    var client = Core.init(.client);
    var server = Core.init(.server);
    try client.start();
    try server.start();

    var bytes: [8]u8 = undefined;
    const ch = try messages.encode(.client_hello, "", &bytes);
    try client.recordSent(ch);
    _ = try server.acceptReceived(ch);
    const sh = try messages.encode(.server_hello, "", &bytes);
    try server.recordSent(sh);
    _ = try client.acceptReceived(sh);
    const ee = try messages.encode(.encrypted_extensions, "", &bytes);
    try server.recordSent(ee);
    _ = try client.acceptReceived(ee);
    const cert = try messages.encode(.certificate, "", &bytes);
    try server.recordSent(cert);
    _ = try client.acceptReceived(cert);
    const cv = try messages.encode(.certificate_verify, "", &bytes);
    try server.recordSent(cv);
    _ = try client.acceptReceived(cv);
    const sf = try messages.encode(.finished, "", &bytes);
    try server.recordSent(sf);
    _ = try client.acceptReceived(sf);
    const cf = try messages.encode(.finished, "", &bytes);
    try client.recordSent(cf);
    _ = try server.acceptReceived(cf);
    try std.testing.expectEqual(.complete, client.handshake_lifecycle);
    try std.testing.expectEqual(.complete, server.handshake_lifecycle);
    const client_hash = client.transcriptHash();
    const server_hash = server.transcriptHash();
    try std.testing.expectEqualSlices(u8, &client_hash, &server_hash);
}

test "PSK-authenticated core skips Certificate/CertificateVerify and still completes both directions" {
    var client = Core.init(.client);
    var server = Core.init(.server);
    try client.start();
    try server.start();

    var bytes: [8]u8 = undefined;
    const ch = try messages.encode(.client_hello, "", &bytes);
    try client.recordSent(ch);
    _ = try server.acceptReceived(ch);
    const sh = try messages.encode(.server_hello, "", &bytes);
    try server.recordSent(sh);
    _ = try client.acceptReceived(sh);

    // Both sides learn PSK was selected before EncryptedExtensions crosses
    // the wire (server: before sending it; client: before receiving it).
    server.enterPskAuthenticated();
    client.enterPskAuthenticated();

    const ee = try messages.encode(.encrypted_extensions, "", &bytes);
    try server.recordSent(ee);
    _ = try client.acceptReceived(ee);

    // Certificate/CertificateVerify are neither expected nor legal now.
    const cert = try messages.encode(.certificate, "", &bytes);
    try std.testing.expectError(error.UnexpectedHandshakeMessage, client.acceptReceived(cert));

    const sf = try messages.encode(.finished, "", &bytes);
    try server.recordSent(sf);
    _ = try client.acceptReceived(sf);
    const cf = try messages.encode(.finished, "", &bytes);
    try client.recordSent(cf);
    _ = try server.acceptReceived(cf);

    try std.testing.expectEqual(.complete, client.handshake_lifecycle);
    try std.testing.expectEqual(.complete, server.handshake_lifecycle);
    const client_hash = client.transcriptHash();
    const server_hash = server.transcriptHash();
    try std.testing.expectEqualSlices(u8, &client_hash, &server_hash);
}

test "core supports one HelloRetryRequest followed by ClientHello2" {
    var client = Core.init(.client);
    var server = Core.init(.server);
    try client.start();
    try server.start();

    var bytes: [16]u8 = undefined;
    const ch1 = try messages.encode(.client_hello, "one", &bytes);
    try client.recordSent(ch1);
    _ = try server.acceptReceived(ch1);

    const hrr = try messages.encode(.server_hello, "hrr", &bytes);
    try server.recordHelloRetryRequest(hrr);
    _ = try client.acceptHelloRetryRequest(hrr);

    const ch2 = try messages.encode(.client_hello, "two", &bytes);
    try client.recordSecondClientHello(ch2);
    _ = try server.acceptSecondClientHello(ch2);

    const sh = try messages.encode(.server_hello, "ok", &bytes);
    try server.recordSent(sh);
    _ = try client.acceptReceived(sh);

    try std.testing.expectEqual(RetryState.hrr_received, client.retry_state);
    try std.testing.expectEqual(RetryState.hrr_sent, server.retry_state);
    const client_hash = client.transcriptHash();
    const server_hash = server.transcriptHash();
    try std.testing.expectEqualSlices(u8, &client_hash, &server_hash);
}

test "core rejects repeated HRR and ClientHello2 without retry state" {
    var client = Core.init(.client);
    var server = Core.init(.server);
    try client.start();
    try server.start();

    var bytes: [16]u8 = undefined;
    const ch1 = try messages.encode(.client_hello, "one", &bytes);
    try client.recordSent(ch1);
    _ = try server.acceptReceived(ch1);

    const hrr = try messages.encode(.server_hello, "hrr", &bytes);
    try server.recordHelloRetryRequest(hrr);
    try std.testing.expectError(error.UnexpectedHandshakeMessage, server.recordHelloRetryRequest(hrr));

    var fresh_server = Core.init(.server);
    try fresh_server.start();
    try std.testing.expectError(error.UnexpectedHandshakeMessage, fresh_server.acceptSecondClientHello(ch1));
}

test "core rejects HRR before ClientHello1 was recorded without rebinding transcript" {
    var client = Core.init(.client);
    try client.start();
    const before = client.transcriptHash();

    var bytes: [8]u8 = undefined;
    const hrr = try messages.encode(.server_hello, "hrr", &bytes);
    try std.testing.expectError(error.UnexpectedHandshakeMessage, client.acceptHelloRetryRequest(hrr));
    const after = client.transcriptHash();
    try std.testing.expectEqualSlices(u8, &before, &after);
    try std.testing.expectEqual(RetryState.none, client.retry_state);
}

test "core requires dedicated ClientHello2 transitions after HRR" {
    var client = Core.init(.client);
    var server = Core.init(.server);
    try client.start();
    try server.start();

    var bytes: [16]u8 = undefined;
    const ch1 = try messages.encode(.client_hello, "one", &bytes);
    try client.recordSent(ch1);
    _ = try server.acceptReceived(ch1);

    const hrr = try messages.encode(.server_hello, "hrr", &bytes);
    try server.recordHelloRetryRequest(hrr);
    _ = try client.acceptHelloRetryRequest(hrr);

    const ch2 = try messages.encode(.client_hello, "two", &bytes);
    try std.testing.expectError(error.UnexpectedHandshakeMessage, client.recordSent(ch2));
    try std.testing.expectError(error.UnexpectedHandshakeMessage, server.acceptReceived(ch2));

    try client.recordSecondClientHello(ch2);
    _ = try server.acceptSecondClientHello(ch2);
}

test "a duplicate CertificateRequest in the server flight is rejected" {
    var client = Core.init(.client);
    try client.start();
    var bytes: [8]u8 = undefined;
    const ch = try messages.encode(.client_hello, "", &bytes);
    try client.recordSent(ch);
    const sh = try messages.encode(.server_hello, "", &bytes);
    _ = try client.acceptReceived(sh);
    const ee = try messages.encode(.encrypted_extensions, "", &bytes);
    _ = try client.acceptReceived(ee);

    // The first CertificateRequest is accepted (client auth requested).
    const cr = try messages.encode(.certificate_request, "", &bytes);
    _ = try client.acceptReceived(cr);
    try std.testing.expect(client.client_certificate_requested);
    // A second one in the same position is illegal (RFC 8446 §4.3.2).
    try std.testing.expectError(error.UnexpectedHandshakeMessage, client.acceptReceived(cr));
}

test "secret lifecycle tracks directions and rejects repeated discard" {
    var lifecycle = SecretLifecycle{};
    try std.testing.expectError(error.SecretNotInstalled, lifecycle.discardEpoch(.handshake));
    try lifecycle.install(.handshake, .read);
    try std.testing.expect(lifecycle.isLive(.handshake, .read));
    try std.testing.expect(!lifecycle.isLive(.handshake, .write));
    try lifecycle.discardEpoch(.handshake);
    try std.testing.expectError(error.SecretNotInstalled, lifecycle.discardEpoch(.handshake));
    try std.testing.expectError(error.SecretAlreadyDiscarded, lifecycle.install(.handshake, .read));
}
