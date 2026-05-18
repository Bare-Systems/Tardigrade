const std = @import("std");

/// HTTP/2 stream states per RFC 7540 §5.1.
pub const StreamState = enum {
    idle,
    open,
    half_closed_local,
    half_closed_remote,
    closed,
    reserved_local,
    reserved_remote,
};

/// HTTP/2 connection and stream error codes per RFC 7540 §7.
pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,

    pub fn value(self: ErrorCode) u32 {
        return @intFromEnum(self);
    }
};

/// Per-stream protocol state for an HTTP/2 connection.
///
/// Tracks the RFC 7540 §5.1 state machine and per-stream flow control
/// windows. One instance lives in the connection's streams map for the
/// lifetime of the stream, and is removed once the state reaches `.closed`.
pub const Stream = struct {
    id: u31,
    state: StreamState,
    priority_weight: u8,
    /// Remaining bytes the server may send to the client on this stream
    /// (the client's stream receive window).
    send_window: i32,
    /// Remaining bytes the client may send to the server on this stream
    /// (the server's stream receive window).
    recv_window: i32,

    pub fn init(id: u31, initial_send_window: i32) Stream {
        return .{
            .id = id,
            .state = .open,
            .priority_weight = 16,
            .send_window = initial_send_window,
            .recv_window = 65_535,
        };
    }

    /// Transition: remote sent END_STREAM.
    /// open → half_closed_remote; half_closed_local → closed.
    pub fn remoteEndStream(self: *Stream) !void {
        switch (self.state) {
            .open => self.state = .half_closed_remote,
            .half_closed_local => self.state = .closed,
            else => return error.InvalidStreamState,
        }
    }

    /// Transition: local sent END_STREAM.
    /// open → half_closed_local; half_closed_remote → closed.
    pub fn localEndStream(self: *Stream) !void {
        switch (self.state) {
            .open => self.state = .half_closed_local,
            .half_closed_remote => self.state = .closed,
            else => return error.InvalidStreamState,
        }
    }

    /// Force-close the stream regardless of current state (RST_STREAM path).
    pub fn close(self: *Stream) void {
        self.state = .closed;
    }

    /// Returns true if the remote end may still send DATA or HEADERS.
    pub fn canReceive(self: *const Stream) bool {
        return switch (self.state) {
            .open, .half_closed_local => true,
            else => false,
        };
    }

    /// Returns true if the local end may still send DATA or HEADERS.
    pub fn canSend(self: *const Stream) bool {
        return switch (self.state) {
            .open, .half_closed_remote => true,
            else => false,
        };
    }
};

test "stream transitions to half_closed_remote on remote END_STREAM" {
    var s = Stream.init(1, 65_535);
    try s.remoteEndStream();
    try std.testing.expectEqual(StreamState.half_closed_remote, s.state);
    try std.testing.expect(!s.canReceive());
    try std.testing.expect(s.canSend());
}

test "stream transitions to half_closed_local on local END_STREAM" {
    var s = Stream.init(1, 65_535);
    try s.localEndStream();
    try std.testing.expectEqual(StreamState.half_closed_local, s.state);
    try std.testing.expect(s.canReceive());
    try std.testing.expect(!s.canSend());
}

test "stream transitions to closed from half_closed_remote on local END_STREAM" {
    var s = Stream.init(1, 65_535);
    try s.remoteEndStream();
    try s.localEndStream();
    try std.testing.expectEqual(StreamState.closed, s.state);
    try std.testing.expect(!s.canReceive());
    try std.testing.expect(!s.canSend());
}

test "stream transitions to closed from half_closed_local on remote END_STREAM" {
    var s = Stream.init(1, 65_535);
    try s.localEndStream();
    try s.remoteEndStream();
    try std.testing.expectEqual(StreamState.closed, s.state);
}

test "stream invalid transition returns error" {
    var s = Stream.init(1, 65_535);
    s.state = .closed;
    try std.testing.expectError(error.InvalidStreamState, s.remoteEndStream());
    try std.testing.expectError(error.InvalidStreamState, s.localEndStream());
}

test "stream RST_STREAM closes from any state" {
    const cases = [_]StreamState{ .open, .half_closed_local, .half_closed_remote };
    for (cases) |initial| {
        var s = Stream.init(1, 65_535);
        s.state = initial;
        s.close();
        try std.testing.expectEqual(StreamState.closed, s.state);
    }
}

test "stream initial state is open with default windows" {
    const s = Stream.init(3, 65_535);
    try std.testing.expectEqual(StreamState.open, s.state);
    try std.testing.expectEqual(@as(u31, 3), s.id);
    try std.testing.expectEqual(@as(i32, 65_535), s.send_window);
    try std.testing.expectEqual(@as(i32, 65_535), s.recv_window);
    try std.testing.expectEqual(@as(u8, 16), s.priority_weight);
    try std.testing.expect(s.canReceive());
    try std.testing.expect(s.canSend());
}

test "ErrorCode values match RFC 7540 §7" {
    try std.testing.expectEqual(@as(u32, 0x0), ErrorCode.no_error.value());
    try std.testing.expectEqual(@as(u32, 0x1), ErrorCode.protocol_error.value());
    try std.testing.expectEqual(@as(u32, 0x3), ErrorCode.flow_control_error.value());
    try std.testing.expectEqual(@as(u32, 0x5), ErrorCode.stream_closed.value());
    try std.testing.expectEqual(@as(u32, 0x6), ErrorCode.frame_size_error.value());
    try std.testing.expectEqual(@as(u32, 0x7), ErrorCode.refused_stream.value());
    try std.testing.expectEqual(@as(u32, 0x9), ErrorCode.compression_error.value());
}
