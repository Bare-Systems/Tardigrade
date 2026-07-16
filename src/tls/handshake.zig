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

pub const Core = struct {
    role: state.Role,
    handshake_state: state.HandshakeState = .idle,
    handshake_lifecycle: HandshakeLifecycle = .idle,
    expected_inbound: ?MessageType = null,
    transcript: transcript_mod.Transcript = .{},
    secrets: SecretLifecycle = .{},

    pub fn init(role: state.Role) Core {
        return .{ .role = role };
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
        if (message.kind == .new_session_ticket) {
            if (self.handshake_lifecycle != .complete or self.role != .client)
                return error.UnexpectedHandshakeMessage;
            self.transcript.update(message.raw);
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

    pub fn recordSent(self: *Core, raw: []const u8) Error!void {
        if (self.handshake_lifecycle != .running) return error.InvalidHandshakeState;
        const message = messages.decode(raw) catch return error.MalformedHandshake;
        if (!self.validOutbound(message.kind)) return error.UnexpectedHandshakeMessage;
        self.transcript.update(message.raw);
        self.advanceAfterSend(message.kind);
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
            .client => (self.handshake_state == .idle and kind == .client_hello) or
                (self.handshake_state == .finished and self.expected_inbound == null and kind == .finished),
            .server => switch (self.handshake_state) {
                .server_hello => kind == .server_hello,
                .encrypted_extensions => kind == .encrypted_extensions,
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
                    self.handshake_state = .certificate;
                    self.expected_inbound = .certificate;
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
            .client => switch (kind) {
                .client_hello => {
                    self.expected_inbound = .server_hello;
                },
                .finished => self.handshake_lifecycle = .complete,
                else => {},
            },
            .server => switch (kind) {
                .server_hello => self.handshake_state = .encrypted_extensions,
                .encrypted_extensions => self.handshake_state = .certificate,
                .certificate => self.handshake_state = .certificate_verify,
                .certificate_verify, .finished => self.handshake_state = .finished,
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
