//! Record-mode TLS handshake contract for future TLS-over-TCP support.
//!
//! This module is deliberately below any socket, readiness, ciphertext-buffer,
//! or record-codec layer. A future record implementation decrypts TLS records,
//! supplies the resulting handshake bytes to `Driver.receive`, and consumes the
//! events emitted here to write handshake bytes at their required protection
//! epoch, install traffic keys, surface negotiated metadata, send fatal alerts,
//! and observe completion.
//!
//! Ownership rules are narrow and testable:
//! - All byte slices in emitted events are copied into the driver's `EventSink`.
//! - Those slices borrow the sink and remain valid only until the next driver
//!   `start` or `receive`, both of which reset the sink.
//! - Resetting or deinitializing the sink securely zeroes the used scratch
//!   range, so copied traffic secrets do not survive the event lifetime.

const std = @import("std");
const alerts = @import("alerts.zig");
const crypto_secrets = @import("crypto_secrets");
const engine = @import("engine.zig");
const events = @import("events.zig");
const state = @import("state.zig");

pub const RecordEpoch = enum {
    /// Handshake bytes before record protection is active.
    plaintext,
    /// Handshake records protected with TLS handshake traffic keys.
    handshake_protected,
    /// Records protected with TLS application traffic keys.
    application_protected,
};

pub const Error = events.HandshakeError || error{
    InvalidHandshakeState,
    RecordTransportBufferOverflow,
};

pub const max_event_count = 16;
pub const max_byte_count = 16 * 1024;

pub const TrafficKeys = struct {
    epoch: RecordEpoch,
    secret: []const u8,
};

pub const PlaintextOutput = struct {
    epoch: RecordEpoch,
    data: []const u8,
};

pub const RecordHandshakeEvent = union(enum) {
    /// Handshake bytes the record layer must frame and write at `epoch`.
    emit_plaintext: PlaintextOutput,
    /// Activate read protection for records at `epoch`.
    install_read_keys: TrafficKeys,
    /// Activate write protection for records at `epoch`.
    install_write_keys: TrafficKeys,
    /// Negotiated application protocol.
    negotiated_alpn: []const u8,
    /// Peer certificate validation outcome.
    peer_certificate: events.CertificateState,
    /// Fatal alert the record layer must send before closing.
    fatal_alert: alerts.AlertDescription,
    /// This side has authenticated and completed the handshake.
    complete,
};

pub const EventSink = struct {
    pub const max_events = max_event_count;
    pub const max_bytes = max_byte_count;

    items: [max_events]RecordHandshakeEvent = undefined,
    len: usize = 0,
    scratch: [max_bytes]u8 = undefined,
    used: usize = 0,

    pub fn reset(self: *EventSink) void {
        self.zeroUsedScratch();
        self.len = 0;
        self.used = 0;
    }

    pub fn deinit(self: *EventSink) void {
        self.reset();
    }

    fn zeroUsedScratch(self: *EventSink) void {
        if (self.used > 0) crypto_secrets.secureZero(self.scratch[0..self.used]);
    }

    fn store(self: *EventSink, bytes: []const u8) Error![]const u8 {
        if (bytes.len > self.scratch.len - self.used) return error.RecordTransportBufferOverflow;
        const start = self.used;
        @memcpy(self.scratch[start..][0..bytes.len], bytes);
        self.used += bytes.len;
        return self.scratch[start..][0..bytes.len];
    }

    fn push(self: *EventSink, event: RecordHandshakeEvent) Error!void {
        if (self.len == self.items.len) return error.RecordTransportBufferOverflow;
        self.items[self.len] = event;
        self.len += 1;
    }

    pub fn emitPlaintext(self: *EventSink, epoch: RecordEpoch, bytes: []const u8) Error!void {
        try self.push(.{ .emit_plaintext = .{ .epoch = epoch, .data = try self.store(bytes) } });
    }

    pub fn installReadKeys(self: *EventSink, epoch: RecordEpoch, secret: []const u8) Error!void {
        try self.push(.{ .install_read_keys = .{ .epoch = epoch, .secret = try self.store(secret) } });
    }

    pub fn installWriteKeys(self: *EventSink, epoch: RecordEpoch, secret: []const u8) Error!void {
        try self.push(.{ .install_write_keys = .{ .epoch = epoch, .secret = try self.store(secret) } });
    }

    pub fn emitAlpn(self: *EventSink, protocol: []const u8) Error!void {
        try self.push(.{ .negotiated_alpn = try self.store(protocol) });
    }

    pub fn emitPeerCertificate(self: *EventSink, cert_state: events.CertificateState) Error!void {
        try self.push(.{ .peer_certificate = cert_state });
    }

    pub fn emitFatalAlert(self: *EventSink, alert: alerts.AlertDescription) Error!void {
        try self.push(.{ .fatal_alert = alert });
    }

    pub fn emitComplete(self: *EventSink) Error!void {
        try self.push(.complete);
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
    startFn: *const fn (ptr: *anyopaque, role: state.Role, params: void, sink: *EventSink) Error!void,
    receiveFn: *const fn (ptr: *anyopaque, epoch: RecordEpoch, bytes: []const u8, sink: *EventSink) Error!void,

    pub fn start(self: Backend, role: state.Role, params: void, sink: *EventSink) Error!void {
        return self.startFn(self.ptr, role, params, sink);
    }

    /// Supplies already-decrypted handshake bytes from a TLS record epoch.
    /// Record parsing, ciphertext buffering, socket readiness, and retry policy
    /// are outside this contract and stay owned by the record layer.
    pub fn receive(self: Backend, epoch: RecordEpoch, bytes: []const u8, sink: *EventSink) Error!void {
        return self.receiveFn(self.ptr, epoch, bytes, sink);
    }
};

pub const Contract = struct {
    pub const TransportParametersType = void;
    pub const EpochType = RecordEpoch;
    pub const Error = record_transport.Error;
    pub const Event = RecordHandshakeEvent;
    pub const EventSink = record_transport.EventSink;
    pub const Backend = record_transport.Backend;
};

const CoreDriver = engine.Driver(Contract);

pub const ReceiveResult = struct {
    sink: *EventSink,
    terminal_error: ?Error = null,
};

pub const Driver = struct {
    core: CoreDriver,

    pub fn init(role: state.Role, backend: Backend) Driver {
        return .{ .core = CoreDriver.init(role, backend) };
    }

    pub fn start(self: *Driver, params: void) Error!*EventSink {
        return self.core.start(params);
    }

    pub fn receive(self: *Driver, epoch: RecordEpoch, bytes: []const u8) Error!ReceiveResult {
        if (self.core.state == .failed) return self.core.failure_reason.?;
        self.core.sink.reset();
        self.core.backend.receive(epoch, bytes, &self.core.sink) catch |err| {
            if (!self.core.sink.hasFatalAlert()) {
                if (fatalAlertForError(err)) |alert| try self.core.sink.emitFatalAlert(alert);
            }
            self.core.state = .failed;
            self.core.failure_reason = err;
            return .{ .sink = &self.core.sink, .terminal_error = err };
        };
        return .{ .sink = &self.core.sink };
    }

    pub fn complete(self: *Driver) void {
        self.core.complete();
    }

    pub fn isComplete(self: *const Driver) bool {
        return self.core.isComplete();
    }

    pub fn failure(self: *const Driver) ?Error {
        return self.core.failure();
    }

    pub fn deinit(self: *Driver) void {
        self.core.sink.deinit();
    }
};

fn fatalAlertForError(err: Error) ?alerts.AlertDescription {
    return switch (err) {
        error.MalformedHandshake => alerts.fromHandshakeError(error.MalformedHandshake),
        error.IllegalParameter => alerts.fromHandshakeError(error.IllegalParameter),
        error.UnexpectedHandshakeMessage => alerts.fromHandshakeError(error.UnexpectedHandshakeMessage),
        error.AlpnMismatch => alerts.fromHandshakeError(error.AlpnMismatch),
        error.CertificateInvalid => alerts.fromHandshakeError(error.CertificateInvalid),
        error.SecretExportFailed => alerts.fromHandshakeError(error.SecretExportFailed),
        error.InvalidHandshakeState,
        error.RecordTransportBufferOverflow,
        => null,
    };
}

const record_transport = @This();
const testing = std.testing;

test "record transport sink copies payloads and zeroizes used storage on reset" {
    var sink = EventSink{};
    try sink.emitPlaintext(.plaintext, "client hello");
    try sink.installReadKeys(.handshake_protected, "read secret");
    try sink.installWriteKeys(.application_protected, "write secret");

    try testing.expectEqual(@as(usize, 3), sink.len);
    try testing.expectEqual(RecordEpoch.plaintext, sink.items[0].emit_plaintext.epoch);
    try testing.expectEqualStrings("client hello", sink.items[0].emit_plaintext.data);
    try testing.expectEqual(RecordEpoch.handshake_protected, sink.items[1].install_read_keys.epoch);
    try testing.expectEqualStrings("read secret", sink.items[1].install_read_keys.secret);
    try testing.expect(sink.used > 0);

    const used = sink.used;
    sink.reset();
    try testing.expectEqual(@as(usize, 0), sink.len);
    try testing.expectEqual(@as(usize, 0), sink.used);
    for (sink.scratch[0..used]) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "record transport sink enforces bounded event and byte storage" {
    var sink = EventSink{};
    const oversized = [_]u8{0xaa} ** (EventSink.max_bytes + 1);
    try testing.expectError(error.RecordTransportBufferOverflow, sink.emitPlaintext(.plaintext, &oversized));

    for (0..EventSink.max_events) |_| try sink.emitFatalAlert(.internal_error);
    try testing.expectError(error.RecordTransportBufferOverflow, sink.emitFatalAlert(.internal_error));
}

test "record transport driver fixture completes with asymmetric key transitions" {
    const Fixture = struct {
        const Self = @This();

        fn backend(self: *Self) Backend {
            return .{ .ptr = self, .startFn = start, .receiveFn = receive };
        }

        fn start(_: *anyopaque, role: state.Role, _: void, sink: *EventSink) Error!void {
            switch (role) {
                .client => try sink.emitPlaintext(.plaintext, "client hello"),
                .server => {},
            }
        }

        fn receive(_: *anyopaque, epoch: RecordEpoch, bytes: []const u8, sink: *EventSink) Error!void {
            if (epoch == .plaintext and std.mem.eql(u8, bytes, "client hello")) {
                try sink.installReadKeys(.handshake_protected, "server read handshake");
                try sink.installWriteKeys(.handshake_protected, "server write handshake");
                try sink.emitPlaintext(.plaintext, "server hello");
                try sink.emitAlpn("h2");
                try sink.emitPeerCertificate(.valid);
                return;
            }

            if (epoch == .plaintext and std.mem.eql(u8, bytes, "server hello")) {
                try sink.installReadKeys(.handshake_protected, "client read handshake");
                try sink.installWriteKeys(.application_protected, "client write application");
                try sink.emitPlaintext(.handshake_protected, "client finished");
                return;
            }

            if (epoch == .handshake_protected and std.mem.eql(u8, bytes, "client finished")) {
                try sink.installReadKeys(.application_protected, "server read application");
                try sink.installWriteKeys(.application_protected, "server write application");
                try sink.emitComplete();
                return;
            }

            try sink.emitFatalAlert(alerts.fromHandshakeError(error.UnexpectedHandshakeMessage));
            return error.UnexpectedHandshakeMessage;
        }
    };

    var client_fixture = Fixture{};
    var server_fixture = Fixture{};
    var client = Driver.init(.client, client_fixture.backend());
    var server = Driver.init(.server, server_fixture.backend());

    const client_start = try client.start({});
    try testing.expectEqual(@as(usize, 1), client_start.len);
    try testing.expectEqual(RecordEpoch.plaintext, client_start.items[0].emit_plaintext.epoch);
    try testing.expectEqualStrings("client hello", client_start.items[0].emit_plaintext.data);

    const server_result = try server.receive(.plaintext, client_start.items[0].emit_plaintext.data);
    try testing.expectEqual(@as(?Error, null), server_result.terminal_error);
    const server_flight = server_result.sink;
    try testing.expectEqual(RecordEpoch.handshake_protected, server_flight.items[0].install_read_keys.epoch);
    try testing.expectEqual(RecordEpoch.handshake_protected, server_flight.items[1].install_write_keys.epoch);
    try testing.expectEqual(RecordEpoch.plaintext, server_flight.items[2].emit_plaintext.epoch);
    try testing.expectEqualStrings("server hello", server_flight.items[2].emit_plaintext.data);
    try testing.expectEqualStrings("h2", server_flight.items[3].negotiated_alpn);
    try testing.expectEqual(events.CertificateState.valid, server_flight.items[4].peer_certificate);

    const client_result = try client.receive(.plaintext, server_flight.items[2].emit_plaintext.data);
    try testing.expectEqual(@as(?Error, null), client_result.terminal_error);
    const client_finished = client_result.sink;
    try testing.expectEqual(RecordEpoch.handshake_protected, client_finished.items[0].install_read_keys.epoch);
    try testing.expectEqual(RecordEpoch.application_protected, client_finished.items[1].install_write_keys.epoch);
    try testing.expectEqual(RecordEpoch.handshake_protected, client_finished.items[2].emit_plaintext.epoch);
    try testing.expectEqualStrings("client finished", client_finished.items[2].emit_plaintext.data);

    const complete_result = try server.receive(.handshake_protected, client_finished.items[2].emit_plaintext.data);
    try testing.expectEqual(@as(?Error, null), complete_result.terminal_error);
    const server_complete = complete_result.sink;
    try testing.expectEqual(RecordEpoch.application_protected, server_complete.items[0].install_read_keys.epoch);
    try testing.expectEqual(RecordEpoch.application_protected, server_complete.items[1].install_write_keys.epoch);
    try testing.expectEqual(RecordHandshakeEvent.complete, server_complete.items[2]);
}

test "record transport driver exposes fatal alert when receive fails" {
    const Fixture = struct {
        fn backend(self: *@This()) Backend {
            return .{ .ptr = self, .startFn = start, .receiveFn = receive };
        }

        fn start(_: *anyopaque, _: state.Role, _: void, _: *EventSink) Error!void {}

        fn receive(_: *anyopaque, _: RecordEpoch, _: []const u8, _: *EventSink) Error!void {
            return error.UnexpectedHandshakeMessage;
        }
    };

    var fixture = Fixture{};
    var driver = Driver.init(.server, fixture.backend());
    const result = try driver.receive(.plaintext, "finished");
    try testing.expectEqual(error.UnexpectedHandshakeMessage, result.terminal_error.?);
    try testing.expectEqual(alerts.AlertDescription.unexpected_message, result.sink.items[0].fatal_alert);
    try testing.expectEqual(error.UnexpectedHandshakeMessage, driver.failure().?);
}

test "record transport driver deinit zeroizes last emitted traffic secrets" {
    const Fixture = struct {
        fn backend(self: *@This()) Backend {
            return .{ .ptr = self, .startFn = start, .receiveFn = receive };
        }

        fn start(_: *anyopaque, _: state.Role, _: void, sink: *EventSink) Error!void {
            try sink.installWriteKeys(.handshake_protected, "last secret");
        }

        fn receive(_: *anyopaque, _: RecordEpoch, _: []const u8, _: *EventSink) Error!void {}
    };

    var fixture = Fixture{};
    var driver = Driver.init(.client, fixture.backend());
    const sink = try driver.start({});
    try testing.expect(sink.used > 0);
    const used = sink.used;

    driver.deinit();
    try testing.expectEqual(@as(usize, 0), driver.core.sink.used);
    for (driver.core.sink.scratch[0..used]) |byte| try testing.expectEqual(@as(u8, 0), byte);
}
