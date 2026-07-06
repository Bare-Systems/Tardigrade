//! HTTP-independent UDP endpoint contract for pure Zig QUIC (#248).
//!
//! This layer owns datagram metadata, socket tuning hooks, deterministic time,
//! and future batching/pacing extension points. It must not import gateway or
//! HTTP request types; QUIC packet routing happens above it by DCID.

const std = @import("std");

pub const Ecn = enum {
    unavailable,
    not_ect,
    ect0,
    ect1,
    ce,
};

pub const Address = struct {
    ip: []const u8,
    port: u16,
};

pub const ReceivedDatagram = struct {
    bytes: []const u8,
    local: ?Address = null,
    remote: Address,
    ecn: Ecn = .unavailable,
    received_at_us: u64,
};

pub const SendDatagram = struct {
    bytes: []const u8,
    local: ?Address = null,
    remote: Address,
    ecn: Ecn = .unavailable,
    /// Future pacing hook. `null` means send as soon as the endpoint can.
    send_at_us: ?u64 = null,
};

pub const BufferTuning = struct {
    recv_bytes: ?usize = null,
    send_bytes: ?usize = null,
};

pub const ReceiveError = error{
    WouldBlock,
    PacketTooLarge,
    SocketClosed,
    Unexpected,
};

pub const SendError = error{
    PacketTooLarge,
    SocketClosed,
    Unexpected,
};

pub const Clock = struct {
    ctx: *anyopaque,
    nowUsFn: *const fn (*anyopaque) u64,

    pub fn nowUs(self: Clock) u64 {
        return self.nowUsFn(self.ctx);
    }
};

pub const Endpoint = struct {
    ctx: *anyopaque,
    clock: Clock,
    recvFn: *const fn (*anyopaque, []u8, Clock) ReceiveError!ReceivedDatagram,
    sendFn: *const fn (*anyopaque, SendDatagram) SendError!usize,
    tuneBuffersFn: *const fn (*anyopaque, BufferTuning) void,

    pub fn receive(self: Endpoint, scratch: []u8) ReceiveError!ReceivedDatagram {
        return self.recvFn(self.ctx, scratch, self.clock);
    }

    pub fn send(self: Endpoint, datagram: SendDatagram) SendError!usize {
        return self.sendFn(self.ctx, datagram);
    }

    pub fn tuneBuffers(self: Endpoint, tuning: BufferTuning) void {
        self.tuneBuffersFn(self.ctx, tuning);
    }
};

pub const RouteKey = struct {
    dcid: []const u8,
};

pub fn routeByDcid(dcid: []const u8) ?RouteKey {
    if (dcid.len == 0) return null;
    return .{ .dcid = dcid };
}

const FakeClock = struct {
    now_us: u64,

    fn now(ctx: *anyopaque) u64 {
        const self: *FakeClock = @ptrCast(@alignCast(ctx));
        return self.now_us;
    }
};

const FakeEndpoint = struct {
    clock: FakeClock,
    recv_payload: []const u8,
    remote: Address,
    last_sent_len: usize = 0,
    last_tuning: BufferTuning = .{},

    fn receive(ctx: *anyopaque, scratch: []u8, clock: Clock) ReceiveError!ReceivedDatagram {
        const self: *FakeEndpoint = @ptrCast(@alignCast(ctx));
        if (scratch.len < self.recv_payload.len) return error.PacketTooLarge;
        @memcpy(scratch[0..self.recv_payload.len], self.recv_payload);
        return .{
            .bytes = scratch[0..self.recv_payload.len],
            .remote = self.remote,
            .ecn = .ect0,
            .received_at_us = clock.nowUs(),
        };
    }

    fn send(ctx: *anyopaque, datagram: SendDatagram) SendError!usize {
        const self: *FakeEndpoint = @ptrCast(@alignCast(ctx));
        self.last_sent_len = datagram.bytes.len;
        return datagram.bytes.len;
    }

    fn tune(ctx: *anyopaque, tuning: BufferTuning) void {
        const self: *FakeEndpoint = @ptrCast(@alignCast(ctx));
        self.last_tuning = tuning;
    }

    fn endpoint(self: *FakeEndpoint) Endpoint {
        return .{
            .ctx = self,
            .clock = .{ .ctx = &self.clock, .nowUsFn = FakeClock.now },
            .recvFn = FakeEndpoint.receive,
            .sendFn = FakeEndpoint.send,
            .tuneBuffersFn = FakeEndpoint.tune,
        };
    }
};

test "UDP endpoint carries datagram metadata and deterministic time" {
    var fake = FakeEndpoint{
        .clock = .{ .now_us = 42_000 },
        .recv_payload = "packet",
        .remote = .{ .ip = "127.0.0.1", .port = 4433 },
    };
    const endpoint = fake.endpoint();
    var scratch: [64]u8 = undefined;
    const datagram = try endpoint.receive(&scratch);
    try std.testing.expectEqualSlices(u8, "packet", datagram.bytes);
    try std.testing.expectEqualStrings("127.0.0.1", datagram.remote.ip);
    try std.testing.expectEqual(@as(u16, 4433), datagram.remote.port);
    try std.testing.expectEqual(Ecn.ect0, datagram.ecn);
    try std.testing.expectEqual(@as(u64, 42_000), datagram.received_at_us);
}

test "UDP endpoint exposes send and buffer tuning hooks" {
    var fake = FakeEndpoint{
        .clock = .{ .now_us = 1 },
        .recv_payload = "",
        .remote = .{ .ip = "127.0.0.1", .port = 4433 },
    };
    const endpoint = fake.endpoint();
    const sent = try endpoint.send(.{
        .bytes = "hello",
        .remote = .{ .ip = "127.0.0.1", .port = 4433 },
        .send_at_us = 100,
    });
    endpoint.tuneBuffers(.{ .recv_bytes = 4 * 1024 * 1024, .send_bytes = 1024 * 1024 });
    try std.testing.expectEqual(@as(usize, 5), sent);
    try std.testing.expectEqual(@as(usize, 5), fake.last_sent_len);
    try std.testing.expectEqual(@as(?usize, 4 * 1024 * 1024), fake.last_tuning.recv_bytes);
}

test "DCID routing key rejects empty IDs" {
    try std.testing.expect(routeByDcid("") == null);
    const key = routeByDcid("abcd").?;
    try std.testing.expectEqualSlices(u8, "abcd", key.dcid);
}
