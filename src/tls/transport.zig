//! Generic transport contract between a TLS 1.3 engine and its carrier.
//!
//! TLS does not own QUIC CRYPTO streams or TCP record buffering here. Callers
//! instantiate this contract with their own epoch and transport-parameter
//! payload types, then translate the emitted events into their local framing.
//!
//! This is the single canonical handshake transport contract: QUIC's adapter
//! (`quic/tls_handshake.zig`) and TCP record mode (`record_epoch_bridge.zig`)
//! both instantiate `Contract`/`ContractWithOptions` directly rather than each
//! owning a parallel copy of the event/sink/driver machinery (#408 finding 1;
//! an earlier record-mode-only `record_transport.zig` duplicated this and has
//! been removed). Ownership rules are narrow and testable:
//!
//! - Every byte slice in an emitted event is copied into the driver-owned
//!   `EventSink`. Slices borrow the sink and remain valid only until the next
//!   `Driver.start`/`Driver.receive` call, both of which reset the sink.
//! - `EventSink.reset` and `EventSink.deinit` securely zero the scratch range
//!   a copied traffic secret occupied, so it does not survive past the event
//!   lifetime above. `Driver.deinit` calls the latter; every owner of a
//!   `Driver` must call it exactly once at teardown.
//! - Event emission is atomic: a rejected emit (event-count or byte overflow)
//!   never leaves a partial payload in scratch or a phantom event in `items`.
//! - The contract can carry terminal alert output (`Event.fatal_alert`) so a
//!   transport can serialize a fatal alert before closing, but deciding *when*
//!   to synthesize one from a handshake failure is transport policy, not
//!   defined here (record mode's alert/`close_notify` policy is #354).

const std = @import("std");
const crypto_secrets = @import("crypto_secrets");
const alerts = @import("alerts.zig");
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
        pub const TransportParametersType = TransportParameters;
        pub const EpochType = Epoch;
        pub const Error = ErrorSet;

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
            /// A fatal alert the transport must send before closing. Whether
            /// and when to emit one from a handshake error is transport
            /// policy (record mode's is #354); this variant only lets the
            /// contract carry it once a caller decides to.
            fatal_alert: alerts.AlertDescription,
        };

        pub const EventSink = struct {
            pub const max_events = max_event_count;
            pub const max_bytes = max_byte_count;

            items: [max_events]Event = undefined,
            len: usize = 0,
            scratch: [max_bytes]u8 = undefined,
            used: usize = 0,

            /// Clear all events and securely wipe the scratch range copied
            /// traffic secrets (and other emitted bytes) occupied, so they do
            /// not survive past the event lifetime documented on `Backend`.
            pub fn reset(self: *EventSink) void {
                self.zeroUsedScratch();
                self.len = 0;
                self.used = 0;
            }

            /// Final teardown: identical to `reset`, exposed under its own
            /// name so callers that only tear down once (rather than reset
            /// between `start`/`receive` calls) have an explicit, self-
            /// documenting call site. Every `Driver` calls this from its own
            /// `deinit`.
            pub fn deinit(self: *EventSink) void {
                self.reset();
            }

            fn zeroUsedScratch(self: *EventSink) void {
                if (self.used > 0) crypto_secrets.secureZero(self.scratch[0..self.used]);
            }

            /// True when `len` bytes can be copied into `scratch` without
            /// mutating any state. Callers must check this (and event-slot
            /// capacity) *before* copying, so a rejected emit never leaves a
            /// partial payload behind -- see `storeUnchecked`.
            fn hasByteCapacity(self: *const EventSink, len: usize) bool {
                return len <= self.scratch.len - self.used;
            }

            fn hasEventCapacity(self: *const EventSink) bool {
                return self.len < self.items.len;
            }

            /// Copy `bytes` into `scratch`. The caller must have already
            /// verified capacity with `hasByteCapacity`; this never fails.
            fn storeUnchecked(self: *EventSink, bytes: []const u8) []const u8 {
                const start = self.used;
                @memcpy(self.scratch[start..][0..bytes.len], bytes);
                self.used += bytes.len;
                return self.scratch[start..][0..bytes.len];
            }

            /// Append `event`. The caller must have already verified capacity
            /// with `hasEventCapacity`; this never fails.
            fn pushUnchecked(self: *EventSink, event: Event) void {
                self.items[self.len] = event;
                self.len += 1;
            }

            /// Reserve room for one event and `byte_len` scratch bytes without
            /// mutating anything, so the emit functions below can copy and
            /// push only after both capacities are known to be available --
            /// on any overflow, the sink is left exactly as it was.
            fn reserve(self: *const EventSink, byte_len: usize) ErrorSet!void {
                if (!self.hasEventCapacity() or !self.hasByteCapacity(byte_len)) return buffer_overflow_error;
            }

            pub fn emitHandshakeBytes(self: *EventSink, epoch: Epoch, data: []const u8) ErrorSet!void {
                try self.reserve(data.len);
                const stored = self.storeUnchecked(data);
                self.pushUnchecked(.{ .handshake_bytes = .{ .epoch = epoch, .data = stored } });
            }

            /// Compatibility spelling for QUIC callers, where handshake bytes
            /// are carried in CRYPTO streams.
            pub fn emitCrypto(self: *EventSink, epoch: Epoch, data: []const u8) ErrorSet!void {
                try self.emitHandshakeBytes(epoch, data);
            }

            pub fn emitSecret(self: *EventSink, epoch: Epoch, direction: events.SecretDirection, data: []const u8) ErrorSet!void {
                try self.reserve(data.len);
                const stored = self.storeUnchecked(data);
                self.pushUnchecked(.{ .traffic_secret = .{ .epoch = epoch, .direction = direction, .data = stored } });
            }

            pub fn emitPeerTransportParameters(self: *EventSink, params: TransportParameters) ErrorSet!void {
                try self.reserve(0);
                self.pushUnchecked(.{ .peer_transport_parameters = params });
            }

            pub fn emitAlpn(self: *EventSink, protocol: []const u8) ErrorSet!void {
                try self.reserve(protocol.len);
                const stored = self.storeUnchecked(protocol);
                self.pushUnchecked(.{ .alpn = stored });
            }

            pub fn emitCertificate(self: *EventSink, cert_state: events.CertificateState) ErrorSet!void {
                try self.reserve(0);
                self.pushUnchecked(.{ .certificate = cert_state });
            }

            pub fn emitDiscardEpoch(self: *EventSink, epoch: Epoch) ErrorSet!void {
                try self.reserve(0);
                self.pushUnchecked(.{ .discard_epoch = epoch });
            }

            /// Compatibility spelling for QUIC callers.
            pub fn emitDiscardKeys(self: *EventSink, epoch: Epoch) ErrorSet!void {
                try self.emitDiscardEpoch(epoch);
            }

            pub fn emitHandshakeComplete(self: *EventSink) ErrorSet!void {
                try self.reserve(0);
                self.pushUnchecked(.handshake_complete);
            }

            pub fn emitFatalAlert(self: *EventSink, alert: alerts.AlertDescription) ErrorSet!void {
                try self.reserve(0);
                self.pushUnchecked(.{ .fatal_alert = alert });
            }

            pub fn hasFatalAlert(self: *const EventSink) bool {
                for (self.items[0..self.len]) |event| {
                    if (event == .fatal_alert) return true;
                }
                return false;
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

test "reset securely zeroes the used scratch range, leaving unused bytes untouched" {
    const ErrorSet = error{TransportBufferOverflow};
    const Epoch = enum { handshake };
    const T = Contract(void, Epoch, ErrorSet);

    var sink = T.EventSink{};
    try sink.emitSecret(.handshake, .write, "top secret traffic key material");
    const used = sink.used;
    try std.testing.expect(used > 0);
    // The bytes beyond `used` are never written by an emit call; poison them
    // so the test can tell "left alone" from "reset zeroed the whole buffer".
    sink.scratch[used] = 0xaa;

    sink.reset();
    try std.testing.expectEqual(@as(usize, 0), sink.len);
    try std.testing.expectEqual(@as(usize, 0), sink.used);
    for (sink.scratch[0..used]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    try std.testing.expectEqual(@as(u8, 0xaa), sink.scratch[used]);
}

test "deinit securely zeroes the final sink contents" {
    const ErrorSet = error{TransportBufferOverflow};
    const Epoch = enum { application };
    const T = Contract(void, Epoch, ErrorSet);

    var sink = T.EventSink{};
    try sink.emitSecret(.application, .read, "application traffic secret");
    const used = sink.used;
    try std.testing.expect(used > 0);

    sink.deinit();
    try std.testing.expectEqual(@as(usize, 0), sink.used);
    for (sink.scratch[0..used]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "event emission is atomic: a full event array leaves scratch untouched on overflow" {
    const ErrorSet = error{TransportBufferOverflow};
    const Epoch = enum { handshake };
    // One event slot, ample scratch: fill the only slot, then a further emit
    // must fail on the event-count check before it ever copies bytes.
    const T = ContractWithOptions(void, Epoch, ErrorSet, 1, 64, error.TransportBufferOverflow);

    var sink = T.EventSink{};
    try sink.emitHandshakeBytes(.handshake, "first");
    const used_before = sink.used;

    try std.testing.expectError(error.TransportBufferOverflow, sink.emitSecret(.handshake, .write, "second traffic secret"));
    try std.testing.expectEqual(@as(usize, 1), sink.len);
    try std.testing.expectEqual(used_before, sink.used);
    // No trace of the rejected secret was copied into scratch.
    try std.testing.expect(std.mem.indexOf(u8, sink.scratch[0..sink.used], "second") == null);
}

test "event emission is atomic: insufficient scratch leaves the event count untouched" {
    const ErrorSet = error{TransportBufferOverflow};
    const Epoch = enum { handshake };
    // Ample event slots, tiny scratch: the first emit consumes most of it, a
    // second oversized emit must fail on the byte check without pushing a
    // phantom event that would reference a partially-copied payload.
    const T = ContractWithOptions(void, Epoch, ErrorSet, 8, 8, error.TransportBufferOverflow);

    var sink = T.EventSink{};
    try sink.emitHandshakeBytes(.handshake, "abcd");
    try std.testing.expectEqual(@as(usize, 1), sink.len);

    try std.testing.expectError(error.TransportBufferOverflow, sink.emitSecret(.handshake, .write, "too big for what remains"));
    try std.testing.expectEqual(@as(usize, 1), sink.len);
    try std.testing.expectEqual(@as(usize, 4), sink.used);
}

test "non-byte-bearing events also fail atomically on a full event array" {
    const ErrorSet = error{TransportBufferOverflow};
    const Epoch = enum { handshake };
    const T = ContractWithOptions(void, Epoch, ErrorSet, 1, 64, error.TransportBufferOverflow);

    var sink = T.EventSink{};
    try sink.emitHandshakeComplete();
    try std.testing.expectError(error.TransportBufferOverflow, sink.emitDiscardEpoch(.handshake));
    try std.testing.expectEqual(@as(usize, 1), sink.len);
    try std.testing.expectEqual(T.Event.handshake_complete, sink.items[0]);
}

test "the canonical contract carries terminal alert output" {
    const ErrorSet = error{TransportBufferOverflow};
    const Epoch = enum { initial };
    const T = Contract(void, Epoch, ErrorSet);

    var sink = T.EventSink{};
    try std.testing.expect(!sink.hasFatalAlert());
    try sink.emitHandshakeBytes(.initial, "partial flight before failure");
    try sink.emitFatalAlert(alerts.fromHandshakeError(error.UnexpectedHandshakeMessage));
    try std.testing.expect(sink.hasFatalAlert());
    try std.testing.expectEqual(alerts.AlertDescription.unexpected_message, sink.items[1].fatal_alert);
}
