//! Minimal DNS SRV (RFC 2782) client used by upstream service discovery.
//!
//! Zig's standard library only resolves A/AAAA, so this module carries the
//! small piece of DNS wire format SRV needs: query encoding, response parsing
//! (including name compression), a `resolv.conf` nameserver reader and a
//! blocking UDP exchange with a receive timeout. Target A/AAAA resolution is
//! intentionally NOT done here; callers reuse `compat.resolveHostAddresses`.
//!
//! Truncated (TC) UDP answers are used as-is when they carry records; there is
//! no TCP fallback. Callers bound the work via `max_records`.
const std = @import("std");
const compat = @import("zig_compat");

pub const max_records = 32;
const max_name_len = 255;
const type_srv: u16 = 33;
var query_counter = std.atomic.Value(usize).init(1);

pub const Error = error{
    Malformed,
    NxDomain,
    ServFail,
    Refused,
    Timeout,
    NoNameserver,
    NameTooLong,
    SocketFailed,
};

pub const SrvRecord = struct {
    priority: u16,
    weight: u16,
    port: u16,
    /// Owned, lowercase target name without trailing dot. Empty means the
    /// RFC 2782 "service not available" target ".".
    target: []u8,
};

pub const Response = struct {
    records: []SrvRecord,
    /// Smallest TTL (seconds) among the answer records; 0 when none.
    min_ttl: u32,

    pub fn deinit(self: Response, allocator: std.mem.Allocator) void {
        for (self.records) |r| allocator.free(r.target);
        allocator.free(self.records);
    }
};

/// Encode a single-question SRV query into `buf`; returns the used slice.
pub fn buildQuery(buf: []u8, id: u16, name: []const u8) Error![]u8 {
    if (buf.len < 12 + name.len + 2 + 4) return error.NameTooLong;
    std.mem.writeInt(u16, buf[0..2], id, .big);
    std.mem.writeInt(u16, buf[2..4], 0x0100, .big); // RD
    std.mem.writeInt(u16, buf[4..6], 1, .big);
    @memset(buf[6..12], 0);
    var pos: usize = 12;
    const trimmed = std.mem.trimEnd(u8, name, ".");
    var it = std.mem.splitScalar(u8, trimmed, '.');
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.NameTooLong;
        buf[pos] = @intCast(label.len);
        @memcpy(buf[pos + 1 ..][0..label.len], label);
        pos += 1 + label.len;
    }
    buf[pos] = 0;
    pos += 1;
    std.mem.writeInt(u16, buf[pos..][0..2], type_srv, .big);
    std.mem.writeInt(u16, buf[pos + 2 ..][0..2], 1, .big); // IN
    return buf[0 .. pos + 4];
}

/// Decode a possibly compressed name at `start`; writes dotted lowercase text
/// into `out` and returns {length, offset just past the name in the record}.
fn readName(msg: []const u8, start: usize, out: *[max_name_len]u8) Error!struct { len: usize, next: usize } {
    var pos = start;
    var next: ?usize = null;
    var len: usize = 0;
    var hops: usize = 0;
    while (true) {
        if (pos >= msg.len) return error.Malformed;
        const b = msg[pos];
        if (b == 0) {
            pos += 1;
            break;
        }
        if (b & 0xC0 == 0xC0) {
            if (pos + 1 >= msg.len) return error.Malformed;
            if (next == null) next = pos + 2;
            hops += 1;
            if (hops > 16) return error.Malformed;
            pos = (@as(usize, b & 0x3F) << 8) | msg[pos + 1];
            continue;
        }
        if (b & 0xC0 != 0) return error.Malformed;
        const l: usize = b;
        if (pos + 1 + l > msg.len) return error.Malformed;
        if (len + l + 1 > max_name_len) return error.NameTooLong;
        if (len > 0) {
            out[len] = '.';
            len += 1;
        }
        for (msg[pos + 1 ..][0..l]) |c| {
            out[len] = std.ascii.toLower(c);
            len += 1;
        }
        pos += 1 + l;
    }
    return .{ .len = len, .next = next orelse pos };
}

/// Parse a response to a query with the given id. Only SRV answer records are
/// kept (at most `max_records`); NXDOMAIN/SERVFAIL/REFUSED map to errors.
pub fn parseResponse(allocator: std.mem.Allocator, msg: []const u8, id: u16) (Error || error{OutOfMemory})!Response {
    if (msg.len < 12) return error.Malformed;
    if (std.mem.readInt(u16, msg[0..2], .big) != id) return error.Malformed;
    const flags = std.mem.readInt(u16, msg[2..4], .big);
    if (flags & 0x8000 == 0) return error.Malformed;
    switch (flags & 0xF) {
        0 => {},
        2 => return error.ServFail,
        3 => return error.NxDomain,
        else => return error.Refused,
    }
    const qd = std.mem.readInt(u16, msg[4..6], .big);
    const an = std.mem.readInt(u16, msg[6..8], .big);
    var name_buf: [max_name_len]u8 = undefined;
    var pos: usize = 12;
    var q: usize = 0;
    while (q < qd) : (q += 1) {
        const n = try readName(msg, pos, &name_buf);
        pos = n.next + 4;
        if (pos > msg.len) return error.Malformed;
    }

    var list: std.ArrayList(SrvRecord) = .empty;
    errdefer {
        for (list.items) |r| allocator.free(r.target);
        list.deinit(allocator);
    }
    var min_ttl: u32 = std.math.maxInt(u32);
    var a: usize = 0;
    while (a < an) : (a += 1) {
        const owner = try readName(msg, pos, &name_buf);
        pos = owner.next;
        if (pos + 10 > msg.len) return error.Malformed;
        const rtype = std.mem.readInt(u16, msg[pos..][0..2], .big);
        const ttl = std.mem.readInt(u32, msg[pos + 4 ..][0..4], .big);
        const rdlen: usize = std.mem.readInt(u16, msg[pos + 8 ..][0..2], .big);
        pos += 10;
        if (pos + rdlen > msg.len) return error.Malformed;
        const rdata_start = pos;
        pos += rdlen;
        if (rtype != type_srv) continue;
        if (rdlen < 7) return error.Malformed;
        if (list.items.len >= max_records) continue;
        const target = try readName(msg, rdata_start + 6, &name_buf);
        const owned = try allocator.dupe(u8, name_buf[0..target.len]);
        errdefer allocator.free(owned);
        try list.append(allocator, .{
            .priority = std.mem.readInt(u16, msg[rdata_start..][0..2], .big),
            .weight = std.mem.readInt(u16, msg[rdata_start + 2 ..][0..2], .big),
            .port = std.mem.readInt(u16, msg[rdata_start + 4 ..][0..2], .big),
            .target = owned,
        });
        min_ttl = @min(min_ttl, ttl);
    }
    return .{
        .records = try list.toOwnedSlice(allocator),
        .min_ttl = if (list.items.len == 0 and an == 0) 0 else if (min_ttl == std.math.maxInt(u32)) 0 else min_ttl,
    };
}

/// Extract up to `out.len` nameserver addresses from resolv.conf text.
pub fn parseResolvConf(text: []const u8, out: []std.Io.net.IpAddress) usize {
    var n: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        if (n >= out.len) break;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (!std.mem.startsWith(u8, line, "nameserver")) continue;
        const rest = std.mem.trim(u8, line["nameserver".len..], " \t");
        if (rest.len == 0 or rest.len == line.len - "nameserver".len) continue;
        const addr = std.Io.net.IpAddress.parse(rest, 53) catch continue;
        out[n] = addr;
        n += 1;
    }
    return n;
}

fn exchange(ns: std.Io.net.IpAddress, query: []const u8, resp: []u8, timeout_ms: u32) Error!usize {
    const fam: c_uint = switch (ns) {
        .ip4 => std.posix.AF.INET,
        .ip6 => std.posix.AF.INET6,
    };
    const sock = std.c.socket(fam, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    if (sock < 0) return error.SocketFailed;
    defer _ = std.c.close(sock);
    const tv = std.c.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    _ = std.c.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(std.c.timeval));
    const sent = switch (ns) {
        .ip4 => |ip4| blk: {
            const sin = std.c.sockaddr.in{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, ip4.port),
                .addr = @bitCast(ip4.bytes),
                .zero = [_]u8{0} ** 8,
            };
            break :blk std.c.sendto(sock, query.ptr, query.len, 0, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in));
        },
        .ip6 => |ip6| blk: {
            const sin6 = std.c.sockaddr.in6{
                .family = std.posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, ip6.port),
                .flowinfo = 0,
                .addr = ip6.bytes,
                .scope_id = 0,
            };
            break :blk std.c.sendto(sock, query.ptr, query.len, 0, @ptrCast(&sin6), @sizeOf(std.c.sockaddr.in6));
        },
    };
    if (sent < 0) return error.SocketFailed;
    const got = std.c.recv(sock, resp.ptr, resp.len, 0);
    if (got < 0) return error.Timeout;
    return @intCast(got);
}

/// Resolve SRV records for `name` via the system nameservers, trying each in
/// order. SERVFAIL/timeouts move on to the next nameserver; NXDOMAIN is
/// authoritative and returned immediately.
pub fn lookupSrv(allocator: std.mem.Allocator, name: []const u8, timeout_ms: u32) (Error || error{OutOfMemory})!Response {
    const text = compat.cwd().readFileAlloc(allocator, "/etc/resolv.conf", 64 * 1024) catch return error.NoNameserver;
    defer allocator.free(text);
    var servers: [3]std.Io.net.IpAddress = undefined;
    const ns_count = parseResolvConf(text, &servers);
    if (ns_count == 0) return error.NoNameserver;

    var qbuf: [512]u8 = undefined;
    var rbuf: [4096]u8 = undefined;
    const id: u16 = @truncate((query_counter.fetchAdd(1, .monotonic) *% 0x9E37) ^ @intFromPtr(&qbuf));
    const query = try buildQuery(&qbuf, id, name);
    var last: Error = error.Timeout;
    for (servers[0..ns_count]) |ns| {
        const n = exchange(ns, query, &rbuf, timeout_ms) catch |e| {
            last = e;
            continue;
        };
        return parseResponse(allocator, rbuf[0..n], id) catch |e| switch (e) {
            error.NxDomain => return e,
            error.OutOfMemory => return e,
            else => {
                last = @errorCast(e);
                continue;
            },
        };
    }
    return last;
}

const testing = std.testing;

fn testResponse(buf: []u8) []u8 {
    // Query for _a._tcp.x.test, two SRV answers using a compression pointer.
    var q: [128]u8 = undefined;
    const query = buildQuery(&q, 0x1234, "_a._tcp.x.test") catch unreachable;
    @memcpy(buf[0..query.len], query);
    var pos = query.len;
    std.mem.writeInt(u16, buf[2..4], 0x8180, .big);
    std.mem.writeInt(u16, buf[6..8], 2, .big);
    const recs = [_]struct { prio: u16, w: u16, port: u16 }{ .{ .prio = 10, .w = 5, .port = 8080 }, .{ .prio = 20, .w = 0, .port = 9090 } };
    for (recs) |r| {
        buf[pos] = 0xC0;
        buf[pos + 1] = 12;
        std.mem.writeInt(u16, buf[pos + 2 ..][0..2], 33, .big);
        std.mem.writeInt(u16, buf[pos + 4 ..][0..2], 1, .big);
        std.mem.writeInt(u32, buf[pos + 6 ..][0..4], 30, .big);
        // rdata: 6 bytes + "H1" label + pointer to "x.test" (offset of 'x' label = 12+3+5=20)
        std.mem.writeInt(u16, buf[pos + 10 ..][0..2], 6 + 3 + 2, .big);
        std.mem.writeInt(u16, buf[pos + 12 ..][0..2], r.prio, .big);
        std.mem.writeInt(u16, buf[pos + 14 ..][0..2], r.w, .big);
        std.mem.writeInt(u16, buf[pos + 16 ..][0..2], r.port, .big);
        buf[pos + 18] = 2;
        buf[pos + 19] = 'H';
        buf[pos + 20] = '1';
        buf[pos + 21] = 0xC0;
        buf[pos + 22] = 12 + 1 + 2 + 1 + 4; // offset of "x" label
        pos += 23;
    }
    return buf[0..pos];
}

test "parseResponse decodes SRV records with compression" {
    var buf: [512]u8 = undefined;
    const msg = testResponse(&buf);
    const resp = try parseResponse(testing.allocator, msg, 0x1234);
    defer resp.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), resp.records.len);
    try testing.expectEqualStrings("h1.x.test", resp.records[0].target);
    try testing.expectEqual(@as(u16, 8080), resp.records[0].port);
    try testing.expectEqual(@as(u16, 20), resp.records[1].priority);
    try testing.expectEqual(@as(u32, 30), resp.min_ttl);
}

test "parseResponse maps rcodes and rejects bad ids and loops" {
    var buf: [512]u8 = undefined;
    const msg = testResponse(&buf);
    try testing.expectError(error.Malformed, parseResponse(testing.allocator, msg, 1));
    std.mem.writeInt(u16, buf[2..4], 0x8183, .big);
    try testing.expectError(error.NxDomain, parseResponse(testing.allocator, msg, 0x1234));
    std.mem.writeInt(u16, buf[2..4], 0x8182, .big);
    try testing.expectError(error.ServFail, parseResponse(testing.allocator, msg, 0x1234));
    // Self-referential compression pointer.
    var loop = [_]u8{ 0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 33, 0, 1 };
    try testing.expectError(error.Malformed, parseResponse(testing.allocator, &loop, 1));
}

test "parseResolvConf" {
    var out: [3]std.Io.net.IpAddress = undefined;
    const n = parseResolvConf("# c\nsearch x\nnameserver 10.0.0.2\nnameserver bogus\nnameserver ::1\n", &out);
    try testing.expectEqual(@as(usize, 2), n);
}
