//! Protocol-neutral TLS 1.3 core shell shared by QUIC and future record mode.
//!
//! The current QUIC adapter still owns CRYPTO-frame transport and packet-key
//! installation. This core exposes transport-neutral configuration/state so the
//! TLS handshake and secret lifecycle can be exercised without importing QUIC,
//! HTTP, socket, or record-layer types.

const std = @import("std");
pub const state = @import("state.zig");
pub const events = @import("events.zig");
pub const key_schedule = @import("key_schedule.zig");

pub const EngineConfig = struct {
    role: state.Role,
    transport_mode: state.TransportMode,
};

pub const Engine = struct {
    config: EngineConfig,
    handshake_state: state.HandshakeState = .idle,

    pub fn init(config: EngineConfig) Engine {
        return .{ .config = config };
    }

    pub fn start(self: *Engine) void {
        self.handshake_state = switch (self.config.role) {
            .client => .client_hello,
            .server => .idle,
        };
    }

    pub fn canUseRecordLayer(self: *const Engine) bool {
        return self.config.transport_mode == .record;
    }
};

test "core engine can be instantiated for record mode without record framing" {
    var engine = Engine.init(.{ .role = .server, .transport_mode = .record });
    try std.testing.expect(engine.canUseRecordLayer());
    engine.start();
    try std.testing.expectEqual(state.HandshakeState.idle, engine.handshake_state);
}
