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

pub const Error = events.HandshakeError;
pub const Message = messages.HandshakeMessage;
pub const MessageType = messages.MessageType;
pub const Reader = messages.Reader;
pub const Writer = messages.Writer;
pub const ExtensionIterator = messages.ExtensionIterator;
pub const ExtensionGuard = messages.ExtensionGuard;

pub fn Reassembler(comptime capacity: usize) type {
    return struct {
        data: [capacity]u8 = undefined,
        len: usize = 0,

        const Self = @This();

        pub fn append(self: *Self, bytes: []const u8) Error!void {
            if (bytes.len > self.data.len - self.len) return error.MalformedHandshake;
            @memcpy(self.data[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }

        pub fn next(self: *Self) Error!?Message {
            if (self.len < 4) return null;
            const body_len = std.mem.readInt(u24, self.data[1..4], .big);
            if (self.data.len < 4 or @as(usize, body_len) > self.data.len - 4)
                return error.MalformedHandshake;
            const message_len = 4 + @as(usize, body_len);
            if (self.len < message_len) return null;
            return messages.decode(self.data[0..message_len]) catch
                return error.MalformedHandshake;
        }

        pub fn discard(self: *Self, count: usize) Error!void {
            if (count > self.len) return error.MalformedHandshake;
            std.mem.copyForwards(u8, self.data[0 .. self.len - count], self.data[count..self.len]);
            self.len -= count;
        }
    };
}

pub const SecretLifecycle = struct {
    installed: [4]bool = .{ false, false, false, false },
    discarded: [4]bool = .{ false, false, false, false },

    pub fn install(self: *SecretLifecycle, epoch: events.EncryptionEpoch) Error!void {
        const index = @intFromEnum(epoch);
        if (self.discarded[index]) return error.SecretExportFailed;
        self.installed[index] = true;
    }

    pub fn discard(self: *SecretLifecycle, epoch: events.EncryptionEpoch) Error!void {
        const index = @intFromEnum(epoch);
        if (!self.installed[index]) return error.SecretExportFailed;
        self.discarded[index] = true;
    }

    pub fn isLive(self: *const SecretLifecycle, epoch: events.EncryptionEpoch) bool {
        const index = @intFromEnum(epoch);
        return self.installed[index] and !self.discarded[index];
    }
};

pub const Core = struct {
    role: state.Role,
    handshake_state: state.HandshakeState = .idle,
    transcript: transcript_mod.Transcript = .{},
    secrets: SecretLifecycle = .{},

    pub fn init(role: state.Role) Core {
        return .{ .role = role };
    }

    pub fn start(self: *Core) void {
        self.handshake_state = switch (self.role) {
            .client => .client_hello,
            .server => .idle,
        };
    }

    /// Accept one complete handshake message from the carrier. The carrier
    /// remains responsible for selecting the encryption epoch; this method only
    /// handles TLS message ordering and transcript ownership.
    pub fn accept(self: *Core, raw: []const u8) Error!Message {
        const message = messages.decode(raw) catch return error.MalformedHandshake;
        if (!self.accepts(message.kind)) return error.UnexpectedHandshakeMessage;
        self.transcript.update(message.raw);
        self.advance(message.kind);
        return message;
    }

    pub fn transcriptHash(self: *const Core) [transcript_mod.digest_len]u8 {
        return self.transcript.peek();
    }

    fn accepts(self: *const Core, kind: MessageType) bool {
        return switch (self.handshake_state) {
            .client_hello => self.role == .server and kind == .client_hello,
            .server_hello => self.role == .client and kind == .server_hello,
            .encrypted_extensions => self.role == .client and kind == .encrypted_extensions,
            .certificate => self.role == .client and kind == .certificate,
            .certificate_verify => self.role == .client and kind == .certificate_verify,
            .finished => kind == .finished,
            .idle, .complete => false,
        };
    }

    fn advance(self: *Core, kind: MessageType) void {
        self.handshake_state = switch (kind) {
            .client_hello => .server_hello,
            .server_hello => .encrypted_extensions,
            .encrypted_extensions => .certificate,
            .certificate => .certificate_verify,
            .certificate_verify => .finished,
            .finished => .complete,
            else => self.handshake_state,
        };
    }
};

test "protocol-neutral core reassembles messages and owns transcript updates" {
    var bytes: [32]u8 = undefined;
    const raw = try messages.encode(.client_hello, "hello", &bytes);
    var reassembler = Reassembler(64){};
    try reassembler.append(raw[0..2]);
    try std.testing.expect(try reassembler.next() == null);
    try reassembler.append(raw[2..]);

    var core = Core.init(.server);
    core.start();
    const message = try core.accept((try reassembler.next()).?.raw);
    try std.testing.expectEqual(MessageType.client_hello, message.kind);
    try std.testing.expectEqual(state.HandshakeState.server_hello, core.handshake_state);
    const hash = core.transcriptHash();
    try std.testing.expect(!std.mem.eql(u8, &hash, &([_]u8{0} ** transcript_mod.digest_len)));
}

test "secret lifecycle rejects use after discard" {
    var lifecycle = SecretLifecycle{};
    try lifecycle.install(.handshake);
    try std.testing.expect(lifecycle.isLive(.handshake));
    try lifecycle.discard(.handshake);
    try std.testing.expect(!lifecycle.isLive(.handshake));
    try std.testing.expectError(error.SecretExportFailed, lifecycle.install(.handshake));
}
