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

pub const AddressFamily = enum {
    ip4,
    ip6,
};

pub const Address = struct {
    family: AddressFamily,
    bytes: [16]u8 = [_]u8{0} ** 16,
    port: u16,
    scope_id: u32 = 0,

    pub fn ip4(octets: [4]u8, port: u16) Address {
        var address = Address{ .family = .ip4, .port = port };
        @memcpy(address.bytes[0..4], &octets);
        return address;
    }

    pub fn ip6(octets: [16]u8, port: u16, scope_id: u32) Address {
        return .{ .family = .ip6, .bytes = octets, .port = port, .scope_id = scope_id };
    }

    pub fn slice(self: *const Address) []const u8 {
        return switch (self.family) {
            .ip4 => self.bytes[0..4],
            .ip6 => self.bytes[0..16],
        };
    }

    pub fn eql(self: Address, other: Address) bool {
        return self.sameHost(other) and self.port == other.port;
    }

    /// Same IP address (family, octets, scope) regardless of port. A NAT
    /// rebinding usually changes only the port; a host change is a real
    /// migration (RFC 9308 §4.1).
    pub fn sameHost(self: Address, other: Address) bool {
        if (self.family != other.family) return false;
        if (self.scope_id != other.scope_id) return false;
        return std.mem.eql(u8, self.slice(), other.slice());
    }
};

pub const ReceivedDatagram = struct {
    /// Slice into the caller-provided receive scratch buffer. Valid only until
    /// that scratch buffer is reused or the next receive call writes into it.
    /// Connection state that outlives dispatch must copy packet bytes it needs.
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
    sendFn: *const fn (*anyopaque, SendDatagram) SendError!void,
    tuneBuffersFn: *const fn (*anyopaque, BufferTuning) void,

    pub fn receive(self: Endpoint, scratch: []u8) ReceiveError!ReceivedDatagram {
        return self.recvFn(self.ctx, scratch, self.clock);
    }

    /// Send one complete UDP datagram. Short successful sends are not part of
    /// this contract; an implementation must translate them to an error.
    pub fn send(self: Endpoint, datagram: SendDatagram) SendError!void {
        try self.sendFn(self.ctx, datagram);
    }

    pub fn tuneBuffers(self: Endpoint, tuning: BufferTuning) void {
        self.tuneBuffersFn(self.ctx, tuning);
    }
};

pub const MaxConnectionIdLen = 20;

pub const ConnectionId = struct {
    bytes: [MaxConnectionIdLen]u8 = [_]u8{0} ** MaxConnectionIdLen,
    len: u8 = 0,

    pub fn init(raw: []const u8) !ConnectionId {
        if (raw.len == 0) return error.EmptyConnectionId;
        if (raw.len > MaxConnectionIdLen) return error.ConnectionIdTooLong;
        var id = ConnectionId{ .len = @intCast(raw.len) };
        @memcpy(id.bytes[0..raw.len], raw);
        return id;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const RouteKey = struct {
    dcid: ConnectionId,
};

pub fn routeByDcid(dcid: []const u8) !RouteKey {
    return .{ .dcid = try ConnectionId.init(dcid) };
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

    fn send(ctx: *anyopaque, datagram: SendDatagram) SendError!void {
        const self: *FakeEndpoint = @ptrCast(@alignCast(ctx));
        self.last_sent_len = datagram.bytes.len;
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
        .remote = Address.ip4(.{ 127, 0, 0, 1 }, 4433),
    };
    const endpoint = fake.endpoint();
    var scratch: [64]u8 = undefined;
    const datagram = try endpoint.receive(&scratch);
    try std.testing.expectEqualSlices(u8, "packet", datagram.bytes);
    try std.testing.expectEqual(AddressFamily.ip4, datagram.remote.family);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, datagram.remote.slice());
    try std.testing.expectEqual(@as(u16, 4433), datagram.remote.port);
    try std.testing.expectEqual(Ecn.ect0, datagram.ecn);
    try std.testing.expectEqual(@as(u64, 42_000), datagram.received_at_us);
}

test "UDP endpoint exposes send and buffer tuning hooks" {
    var fake = FakeEndpoint{
        .clock = .{ .now_us = 1 },
        .recv_payload = "",
        .remote = Address.ip4(.{ 127, 0, 0, 1 }, 4433),
    };
    const endpoint = fake.endpoint();
    try endpoint.send(.{
        .bytes = "hello",
        .remote = Address.ip4(.{ 127, 0, 0, 1 }, 4433),
        .send_at_us = 100,
    });
    endpoint.tuneBuffers(.{ .recv_bytes = 4 * 1024 * 1024, .send_bytes = 1024 * 1024 });
    try std.testing.expectEqual(@as(usize, 5), fake.last_sent_len);
    try std.testing.expectEqual(@as(?usize, 4 * 1024 * 1024), fake.last_tuning.recv_bytes);
}

test "DCID routing key owns a bounded connection ID" {
    try std.testing.expectError(error.EmptyConnectionId, routeByDcid(""));
    try std.testing.expectError(error.ConnectionIdTooLong, routeByDcid("012345678901234567890"));
    var source = [_]u8{ 'a', 'b', 'c', 'd' };
    const key = try routeByDcid(&source);
    source[0] = 'z';
    try std.testing.expectEqualSlices(u8, "abcd", key.dcid.slice());
}
