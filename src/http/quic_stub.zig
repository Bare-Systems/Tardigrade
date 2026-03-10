const std = @import("std");

// Archived QUIC parser/tracker stub kept only as local helper glue around the
// live ngtcp2-backed HTTP/3 transport. Real QUIC handshake, packet crypto, and
// stream lifecycle ownership now live in `ngtcp2_binding.zig`.

pub const PacketType = enum {
    initial,
    zero_rtt,
    handshake,
    retry,
    short,
};

pub const ParsedPacket = struct {
    packet_type: PacketType,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    payload: []const u8,
    counts: PacketCounts = .{},
};

pub const PacketCounts = struct {
    initial: usize = 0,
    zero_rtt: usize = 0,
    handshake: usize = 0,
    retry: usize = 0,
    short: usize = 0,
};

pub const ConnectionAddress = struct {
    ip: []const u8,
    port: u16,
};

pub const ConnectionTracker = struct {
    allocator: std.mem.Allocator,
    table: std.StringHashMap(ConnectionAddress),

    pub fn init(allocator: std.mem.Allocator) ConnectionTracker {
        return .{
            .allocator = allocator,
            .table = std.StringHashMap(ConnectionAddress).init(allocator),
        };
    }

    pub fn deinit(self: *ConnectionTracker) void {
        var it = self.table.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.ip);
        }
        self.table.deinit();
    }

    pub fn observe(self: *ConnectionTracker, packet: ParsedPacket, remote_ip: []const u8, remote_port: u16, allow_migration: bool) !bool {
        if (packet.dcid.len == 0) return false;
        const cid_hex = try std.fmt.allocPrint(self.allocator, "{s}", .{std.fmt.fmtSliceHexLower(packet.dcid)});
        defer self.allocator.free(cid_hex);

        if (self.table.getPtr(cid_hex)) |addr| {
            const same = std.mem.eql(u8, addr.ip, remote_ip) and addr.port == remote_port;
            if (same) return false;
            if (!allow_migration) return false;
            self.allocator.free(addr.ip);
            addr.ip = try self.allocator.dupe(u8, remote_ip);
            addr.port = remote_port;
            return true;
        }

        const key = try self.allocator.dupe(u8, cid_hex);
        errdefer self.allocator.free(key);
        const ip = try self.allocator.dupe(u8, remote_ip);
        errdefer self.allocator.free(ip);
        try self.table.put(key, .{ .ip = ip, .port = remote_port });
        return false;
    }
};

pub fn parsePacket(datagram: []const u8) !ParsedPacket {
    var offset: usize = 0;
    var first_packet: ?ParsedPacket = null;
    var counts = PacketCounts{};

    while (offset < datagram.len) {
        const parsed = try parsePacketAt(datagram, offset);
        switch (parsed.packet.packet_type) {
            .initial => counts.initial += 1,
            .zero_rtt => counts.zero_rtt += 1,
            .handshake => counts.handshake += 1,
            .retry => counts.retry += 1,
            .short => counts.short += 1,
        }
        if (first_packet == null) first_packet = parsed.packet;
        if (parsed.next_offset <= offset) return error.InvalidQuicPacket;
        offset = parsed.next_offset;
        if (parsed.packet.packet_type == .short or parsed.packet.packet_type == .retry) break;
    }

    var packet = first_packet orelse return error.InvalidQuicPacket;
    packet.counts = counts;
    return packet;
}

const ParseResult = struct {
    packet: ParsedPacket,
    next_offset: usize,
};

fn parsePacketAt(datagram: []const u8, start: usize) !ParseResult {
    if (start >= datagram.len) return error.InvalidQuicPacket;
    const first = datagram[start];
    const long_header = (first & 0x80) != 0;
    if (!long_header) {
        const short_dcid_len: usize = 16;
        if (start + 1 + short_dcid_len > datagram.len) return error.InvalidQuicPacket;
        return .{
            .packet = .{
                .packet_type = .short,
                .version = 0,
                .dcid = datagram[start + 1 .. start + 1 + short_dcid_len],
                .scid = "",
                .token = "",
                .payload = datagram[start + 1 + short_dcid_len ..],
            },
            .next_offset = datagram.len,
        };
    }

    if (start + 7 > datagram.len) return error.InvalidQuicPacket;
    const packet_type_bits = (first >> 4) & 0x03;
    const packet_type: PacketType = switch (packet_type_bits) {
        0 => .initial,
        1 => .zero_rtt,
        2 => .handshake,
        3 => .retry,
        else => .initial,
    };
    const version = std.mem.readInt(u32, @ptrCast(datagram[start + 1 .. start + 5].ptr), .big);
    var i: usize = start + 5;
    const dcid_len = datagram[i];
    i += 1;
    if (i + dcid_len > datagram.len) return error.InvalidQuicPacket;
    const dcid = datagram[i .. i + dcid_len];
    i += dcid_len;
    if (i >= datagram.len) return error.InvalidQuicPacket;
    const scid_len = datagram[i];
    i += 1;
    if (i + scid_len > datagram.len) return error.InvalidQuicPacket;
    const scid = datagram[i .. i + scid_len];
    i += scid_len;

    var token: []const u8 = "";
    if (packet_type == .retry) {
        return .{
            .packet = .{
                .packet_type = packet_type,
                .version = version,
                .dcid = dcid,
                .scid = scid,
                .token = datagram[i..],
                .payload = "",
            },
            .next_offset = datagram.len,
        };
    }

    if (packet_type == .initial) {
        const token_len = try decodeVarInt(datagram, &i);
        if (i + token_len > datagram.len) return error.InvalidQuicPacket;
        token = datagram[i .. i + token_len];
        i += token_len;
    }
    const length = try decodeVarInt(datagram, &i);
    const packet_number_len: usize = @as(usize, first & 0x03) + 1;
    if (length < packet_number_len) return error.InvalidQuicPacket;
    const next_offset = i + length;
    if (next_offset > datagram.len) return error.InvalidQuicPacket;

    return .{
        .packet = .{
            .packet_type = packet_type,
            .version = version,
            .dcid = dcid,
            .scid = scid,
            .token = token,
            .payload = datagram[i..next_offset],
        },
        .next_offset = next_offset,
    };
}

fn decodeVarInt(buf: []const u8, index: *usize) !usize {
    if (index.* >= buf.len) return error.InvalidQuicPacket;
    const first = buf[index.*];
    const len: usize = switch (first >> 6) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (index.* + len > buf.len) return error.InvalidQuicPacket;
    var value: u64 = first & 0x3f;
    var pos = index.* + 1;
    while (pos < index.* + len) : (pos += 1) {
        value = (value << 8) | buf[pos];
    }
    index.* += len;
    return std.math.cast(usize, value) orelse return error.InvalidQuicPacket;
}

test "parse initial packet and detect 0-rtt" {
    const initial = [_]u8{
        0xC0, 0x00, 0x00, 0x00, 0x01,
        0x04, 0xde, 0xad, 0xbe, 0xef,
        0x04, 0xca, 0xfe, 0xba, 0xbe,
        0x00, 0x02, 0x01, 0xaa,
    };
    const p = try parsePacket(initial[0..]);
    try std.testing.expect(p.packet_type == .initial);
    try std.testing.expectEqual(@as(usize, 4), p.dcid.len);
    try std.testing.expectEqual(@as(usize, 1), p.counts.initial);

    const zero_rtt = [_]u8{
        0xD0, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x11, 0x22, 0x02, 0x33, 0x44,
        0x02, 0x01, 0xaa,
    };
    const z = try parsePacket(zero_rtt[0..]);
    try std.testing.expect(z.packet_type == .zero_rtt);
    try std.testing.expectEqual(@as(usize, 1), z.counts.zero_rtt);

    const short = [_]u8{
        0x40,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0xaa, 0xbb,
    };
    const s = try parsePacket(short[0..]);
    try std.testing.expect(s.packet_type == .short);
    try std.testing.expectEqual(@as(usize, 16), s.dcid.len);
    try std.testing.expectEqual(@as(u8, 0x10), s.dcid[0]);
    try std.testing.expectEqual(@as(usize, 2), s.payload.len);
    try std.testing.expectEqual(@as(usize, 1), s.counts.short);
}

test "parse coalesced initial and zero-rtt packets" {
    const datagram = [_]u8{
        0xC0, 0x00, 0x00, 0x00, 0x01,
        0x04, 0xde, 0xad, 0xbe, 0xef,
        0x04, 0xca, 0xfe, 0xba, 0xbe,
        0x00, 0x02, 0x01, 0xaa,
        0xD0, 0x00, 0x00, 0x00, 0x01,
        0x04, 0xde, 0xad, 0xbe, 0xef,
        0x04, 0xca, 0xfe, 0xba, 0xbe,
        0x02, 0x01, 0xbb,
    };
    const parsed = try parsePacket(datagram[0..]);
    try std.testing.expect(parsed.packet_type == .initial);
    try std.testing.expectEqual(@as(usize, 1), parsed.counts.initial);
    try std.testing.expectEqual(@as(usize, 1), parsed.counts.zero_rtt);
}

test "connection migration tracking" {
    const allocator = std.testing.allocator;
    var tracker = ConnectionTracker.init(allocator);
    defer tracker.deinit();
    const packet = ParsedPacket{
        .packet_type = .short,
        .version = 0,
        .dcid = &[_]u8{ 0xaa, 0xbb, 0xcc },
        .scid = "",
        .token = "",
        .payload = "",
    };

    const first = try tracker.observe(packet, "10.0.0.1", 443, true);
    try std.testing.expect(!first);
    const migrated = try tracker.observe(packet, "10.0.0.2", 443, true);
    try std.testing.expect(migrated);
    const blocked = try tracker.observe(packet, "10.0.0.3", 443, false);
    try std.testing.expect(!blocked);
}
