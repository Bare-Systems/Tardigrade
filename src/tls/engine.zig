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

pub fn Driver(comptime Transport: type) type {
    return struct {
        role: state.Role,
        backend: Transport.Backend,
        state: state.DriverState = .idle,
        failure_reason: ?Transport.Error = null,
        sink: Transport.EventSink = .{},

        const Self = @This();

        pub fn init(role: state.Role, backend: Transport.Backend) Self {
            return .{ .role = role, .backend = backend };
        }

        /// Start the backend and return the driver's internal event sink.
        /// The returned pointer and every event payload slice borrow storage
        /// owned by this driver; they stay valid only until the next `start` or
        /// `receive` call, both of which reset and overwrite the sink.
        pub fn start(self: *Self, params: Transport.TransportParametersType) Transport.Error!*Transport.EventSink {
            if (self.state != .idle) return self.fail(error.InvalidHandshakeState);
            self.state = .in_progress;
            self.sink.reset();
            self.backend.start(self.role, params, &self.sink) catch |err| return self.fail(err);
            return &self.sink;
        }

        /// Drive the backend with received handshake bytes and return the
        /// driver's internal event sink. The returned pointer and payload slices
        /// are borrowed only until the next `start` or `receive` call.
        pub fn receive(self: *Self, epoch: Transport.EpochType, bytes: []const u8) Transport.Error!*Transport.EventSink {
            if (self.state == .failed) return self.failure_reason.?;
            self.sink.reset();
            self.backend.receive(epoch, bytes, &self.sink) catch |err| return self.fail(err);
            return &self.sink;
        }

        pub fn complete(self: *Self) void {
            self.state = .complete;
        }

        pub fn isComplete(self: *const Self) bool {
            return self.state == .complete;
        }

        pub fn failure(self: *const Self) ?Transport.Error {
            return self.failure_reason;
        }

        pub fn fail(self: *Self, err: Transport.Error) Transport.Error {
            self.state = .failed;
            self.failure_reason = err;
            return err;
        }

        /// Final teardown: securely wipes any traffic secrets still copied
        /// into the internal sink from the last `start`/`receive` call. Every
        /// owner of a `Driver` -- QUIC's handshake adapter and record mode
        /// alike -- must call this exactly once when the handshake object is
        /// discarded, whether it completed, failed, or was abandoned mid-flight.
        pub fn deinit(self: *Self) void {
            self.sink.deinit();
        }
    };
}

test "core engine can be instantiated for record mode without record framing" {
    var engine = Engine.init(.{ .role = .server, .transport_mode = .record });
    try std.testing.expect(engine.canUseRecordLayer());
    engine.start();
    try std.testing.expectEqual(state.HandshakeState.idle, engine.handshake_state);
}

test "generic driver starts backend and stores emitted events" {
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, role: state.Role, _: void, sink: *T.EventSink) T.Error!void {
            std.debug.assert(role == .client);
            try sink.emitHandshakeBytes(.initial, "hello");
        }

        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.client, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    const sink = try driver.start({});
    try std.testing.expectEqual(state.DriverState.in_progress, driver.state);
    try std.testing.expectEqual(@as(usize, 1), sink.len);
    try std.testing.expectEqualStrings("hello", sink.items[0].handshake_bytes.data);
}

test "generic driver records backend failure" {
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, _: *T.EventSink) T.Error!void {
            return error.TransportBufferOverflow;
        }

        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.server, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    try std.testing.expectError(error.TransportBufferOverflow, driver.start({}));
    try std.testing.expectEqual(state.DriverState.failed, driver.state);
    try std.testing.expectEqual(error.TransportBufferOverflow, driver.failure().?);
}

test "generic driver rejects repeated start calls" {
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, sink: *T.EventSink) T.Error!void {
            try sink.emitHandshakeBytes(.initial, "hello");
        }

        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.client, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    _ = try driver.start({});
    try std.testing.expectError(error.InvalidHandshakeState, driver.start({}));
    try std.testing.expectEqual(state.DriverState.failed, driver.state);
    try std.testing.expectEqual(error.InvalidHandshakeState, driver.failure().?);
}

test "generic driver rejects start after completion" {
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, _: *T.EventSink) T.Error!void {}
        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.server, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    _ = try driver.start({});
    driver.complete();
    try std.testing.expectError(error.InvalidHandshakeState, driver.start({}));
}

test "driver deinit securely wipes the last emitted traffic secret" {
    const T = @import("transport.zig").Contract(void, enum { handshake }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, sink: *T.EventSink) T.Error!void {
            try sink.emitSecret(.handshake, .write, "last traffic secret before teardown");
        }
        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.client, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    const sink = try driver.start({});
    try std.testing.expect(sink.used > 0);
    const used = sink.used;

    driver.deinit();
    try std.testing.expectEqual(@as(usize, 0), driver.sink.used);
    for (driver.sink.scratch[0..used]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "driver deinit is safe after a failed handshake" {
    const T = @import("transport.zig").Contract(void, enum { initial }, error{ InvalidHandshakeState, TransportBufferOverflow });
    const D = Driver(T);
    const Backend = struct {
        fn start(_: *anyopaque, _: state.Role, _: void, sink: *T.EventSink) T.Error!void {
            try sink.emitHandshakeBytes(.initial, "partial before failure");
            return error.TransportBufferOverflow;
        }
        fn receive(_: *anyopaque, _: T.EpochType, _: []const u8, _: *T.EventSink) T.Error!void {}
    };

    var context: u8 = 0;
    var driver = D.init(.server, .{
        .ptr = &context,
        .startFn = Backend.start,
        .receiveFn = Backend.receive,
    });
    try std.testing.expectError(error.TransportBufferOverflow, driver.start({}));
    driver.deinit();
    try std.testing.expectEqual(@as(usize, 0), driver.sink.used);
}
