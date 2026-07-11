//! Generic transport contract between a TLS 1.3 engine and its carrier.
//!
//! TLS does not own QUIC CRYPTO streams or TCP record buffering here. Callers
//! instantiate this contract with their own epoch and transport-parameter
//! payload types, then translate the emitted events into their local framing.

const std = @import("std");
const events = @import("events.zig");
const state = @import("state.zig");

pub fn Contract(
    comptime TransportParameters: type,
    comptime Epoch: type,
    comptime ErrorSet: type,
) type {
    return ContractWithOptions(
        TransportParameters,
        Epoch,
        ErrorSet,
        16,
        16 * 1024,
        error.TransportBufferOverflow,
    );
}

pub fn ContractWithOptions(
    comptime TransportParameters: type,
    comptime Epoch: type,
    comptime ErrorSet: type,
    comptime max_event_count: usize,
    comptime max_byte_count: usize,
    comptime buffer_overflow_error: ErrorSet,
) type {
    return struct {
        pub const Event = union(enum) {
            /// Raw TLS handshake bytes to send at `epoch`.
            handshake_bytes: struct { epoch: Epoch, data: []const u8 },
            /// A traffic secret to install for `epoch`/`direction`.
            traffic_secret: struct { epoch: Epoch, direction: events.SecretDirection, data: []const u8 },
            /// Transport-owned peer parameters carried by the TLS handshake.
            peer_transport_parameters: TransportParameters,
            /// The negotiated ALPN protocol.
            alpn: []const u8,
            /// The peer certificate validation outcome.
            certificate: events.CertificateState,
            /// Keys for `epoch` are no longer needed and should be discarded.
            discard_epoch: Epoch,
            /// The handshake authenticated and completed on this side.
            handshake_complete,
        };

        pub const EventSink = struct {
            pub const max_events = max_event_count;
            pub const max_bytes = max_byte_count;

            items: [max_events]Event = undefined,
            len: usize = 0,
            scratch: [max_bytes]u8 = undefined,
            used: usize = 0,

            pub fn reset(self: *EventSink) void {
                self.len = 0;
                self.used = 0;
            }

            fn store(self: *EventSink, bytes: []const u8) ErrorSet![]const u8 {
                if (bytes.len > self.scratch.len - self.used) return buffer_overflow_error;
                const start = self.used;
                @memcpy(self.scratch[start..][0..bytes.len], bytes);
                self.used += bytes.len;
                return self.scratch[start..][0..bytes.len];
            }

            fn push(self: *EventSink, event: Event) ErrorSet!void {
                if (self.len == self.items.len) return buffer_overflow_error;
                self.items[self.len] = event;
                self.len += 1;
            }

            pub fn emitHandshakeBytes(self: *EventSink, epoch: Epoch, data: []const u8) ErrorSet!void {
                try self.push(.{ .handshake_bytes = .{ .epoch = epoch, .data = try self.store(data) } });
            }

            /// Compatibility spelling for QUIC callers, where handshake bytes
            /// are carried in CRYPTO streams.
            pub fn emitCrypto(self: *EventSink, epoch: Epoch, data: []const u8) ErrorSet!void {
                try self.emitHandshakeBytes(epoch, data);
            }

            pub fn emitSecret(self: *EventSink, epoch: Epoch, direction: events.SecretDirection, data: []const u8) ErrorSet!void {
                try self.push(.{ .traffic_secret = .{ .epoch = epoch, .direction = direction, .data = try self.store(data) } });
            }

            pub fn emitPeerTransportParameters(self: *EventSink, params: TransportParameters) ErrorSet!void {
                try self.push(.{ .peer_transport_parameters = params });
            }

            pub fn emitAlpn(self: *EventSink, protocol: []const u8) ErrorSet!void {
                try self.push(.{ .alpn = try self.store(protocol) });
            }

            pub fn emitCertificate(self: *EventSink, cert_state: events.CertificateState) ErrorSet!void {
                try self.push(.{ .certificate = cert_state });
            }

            pub fn emitDiscardEpoch(self: *EventSink, epoch: Epoch) ErrorSet!void {
                try self.push(.{ .discard_epoch = epoch });
            }

            /// Compatibility spelling for QUIC callers.
            pub fn emitDiscardKeys(self: *EventSink, epoch: Epoch) ErrorSet!void {
                try self.emitDiscardEpoch(epoch);
            }

            pub fn emitHandshakeComplete(self: *EventSink) ErrorSet!void {
                try self.push(.handshake_complete);
            }
        };

        pub const Backend = struct {
            ptr: *anyopaque,
            startFn: *const fn (ptr: *anyopaque, role: state.Role, params: TransportParameters, sink: *EventSink) ErrorSet!void,
            receiveFn: *const fn (ptr: *anyopaque, epoch: Epoch, bytes: []const u8, sink: *EventSink) ErrorSet!void,

            pub fn start(self: Backend, role: state.Role, params: TransportParameters, sink: *EventSink) ErrorSet!void {
                return self.startFn(self.ptr, role, params, sink);
            }

            pub fn receive(self: Backend, epoch: Epoch, bytes: []const u8, sink: *EventSink) ErrorSet!void {
                return self.receiveFn(self.ptr, epoch, bytes, sink);
            }
        };
    };
}

test "generic transport sink stores copied event payloads" {
    const ErrorSet = error{TransportBufferOverflow};
    const Epoch = enum { initial, handshake };
    const Params = struct { enabled: bool = true };
    const T = Contract(Params, Epoch, ErrorSet);

    var sink = T.EventSink{};
    try sink.emitHandshakeBytes(.initial, "hello");
    try sink.emitSecret(.handshake, .write, "secret");
    try sink.emitPeerTransportParameters(.{ .enabled = false });

    try std.testing.expectEqual(@as(usize, 3), sink.len);
    try std.testing.expectEqualStrings("hello", sink.items[0].handshake_bytes.data);
    try std.testing.expectEqual(events.SecretDirection.write, sink.items[1].traffic_secret.direction);
    try std.testing.expect(!sink.items[2].peer_transport_parameters.enabled);
}

test "generic transport sink enforces bounded payload storage" {
    const ErrorSet = error{TransportBufferOverflow};
    const Epoch = enum { initial };
    const T = Contract(void, Epoch, ErrorSet);

    var sink = T.EventSink{};
    const oversized = [_]u8{0} ** (T.EventSink.max_bytes + 1);
    try std.testing.expectError(error.TransportBufferOverflow, sink.emitHandshakeBytes(.initial, &oversized));
}

test "generic transport sink accepts caller-owned limits and overflow error names" {
    const ErrorSet = error{CallerBufferFull};
    const Epoch = enum { initial };
    const T = ContractWithOptions(void, Epoch, ErrorSet, 1, 4, error.CallerBufferFull);

    var sink = T.EventSink{};
    try std.testing.expectError(error.CallerBufferFull, sink.emitHandshakeBytes(.initial, "hello"));
    try sink.emitHandshakeBytes(.initial, "ok");
    try std.testing.expectError(error.CallerBufferFull, sink.emitHandshakeBytes(.initial, ""));
}
