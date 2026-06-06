//! Socket, PROXY protocol, and request-read helpers for edge gateway
//! connections. The main gateway owns high-level request dispatch; this module
//! owns low-level fd mode, peer address, and per-connection framing helpers.

const compat = @import("zig_compat.zig");
const std = @import("std");
const edge_config = @import("edge_config.zig");

pub const ProxyHeaderOutcome = union(enum) {
    no_header,
    need_more,
    invalid,
    parsed: struct {
        consumed: usize,
        client_ip_len: usize,
    },
};

const proxy_v2_signature = "\r\n\r\n\x00\r\nQUIT\n";

pub fn clientIpKeyFromAddress(allocator: std.mem.Allocator, address: *const std.c.sockaddr.storage) ![]const u8 {
    return switch (address.family) {
        std.posix.AF.INET => blk: {
            const sin: *const std.c.sockaddr.in = @ptrCast(address);
            const b = @as(*const [4]u8, @ptrCast(&sin.addr));
            break :blk std.fmt.allocPrint(allocator, "v4:{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
        },
        std.posix.AF.INET6 => blk: {
            const sin6: *const std.c.sockaddr.in6 = @ptrCast(address);
            break :blk std.fmt.allocPrint(allocator, "v6:{f}", .{compat.fmtSliceHexLower(sin6.addr[0..])});
        },
        else => error.UnsupportedAddressFamily,
    };
}

pub fn clientIpFromAddress(allocator: std.mem.Allocator, address: *const std.c.sockaddr.storage) ![]const u8 {
    return switch (address.family) {
        std.posix.AF.INET => blk: {
            const sin: *const std.c.sockaddr.in = @ptrCast(address);
            const b = @as(*const [4]u8, @ptrCast(&sin.addr));
            break :blk std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
        },
        std.posix.AF.INET6 => blk: {
            const sin6: *const std.c.sockaddr.in6 = @ptrCast(address);
            const src = sin6.addr[0..];
            const g0 = std.mem.readInt(u16, src[0..2], .big);
            const g1 = std.mem.readInt(u16, src[2..4], .big);
            const g2 = std.mem.readInt(u16, src[4..6], .big);
            const g3 = std.mem.readInt(u16, src[6..8], .big);
            const g4 = std.mem.readInt(u16, src[8..10], .big);
            const g5 = std.mem.readInt(u16, src[10..12], .big);
            const g6 = std.mem.readInt(u16, src[12..14], .big);
            const g7 = std.mem.readInt(u16, src[14..16], .big);
            break :blk std.fmt.allocPrint(allocator, "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", .{ g0, g1, g2, g3, g4, g5, g6, g7 });
        },
        else => error.UnsupportedAddressFamily,
    };
}

pub fn clientIpFromFd(allocator: std.mem.Allocator, fd: std.posix.fd_t) ![]const u8 {
    var peer_addr: std.c.sockaddr.storage = undefined;
    var addr_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.storage);
    try std.posix.getpeername(fd, @ptrCast(&peer_addr), &addr_len);
    return clientIpFromAddress(allocator, &peer_addr);
}

pub fn setNoDelay(fd: std.posix.fd_t) !void {
    try std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&@as(c_int, 1)));
}

pub fn setNonBlocking(fd: std.posix.fd_t, enabled: bool) !void {
    const current_flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
    if (current_flags < 0) return error.Unexpected;
    var flags: usize = @intCast(current_flags);
    const nonblock_mask = @as(usize, 1) << @bitOffsetOf(std.posix.O, "NONBLOCK");
    if (enabled) {
        flags |= nonblock_mask;
    } else {
        flags &= ~nonblock_mask;
    }
    if (std.c.fcntl(fd, std.posix.F.SETFL, @as(c_int, @intCast(flags))) < 0) return error.Unexpected;
}

pub fn setSocketTimeoutMs(fd: std.posix.fd_t, recv_timeout_ms: u32, send_timeout_ms: u32) !void {
    const recv_tv = std.posix.timeval{
        .sec = @intCast(recv_timeout_ms / 1000),
        .usec = @intCast((recv_timeout_ms % 1000) * 1000),
    };
    const send_tv = std.posix.timeval{
        .sec = @intCast(send_timeout_ms / 1000),
        .usec = @intCast((send_timeout_ms % 1000) * 1000),
    };

    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&recv_tv));
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&send_tv));
}

pub fn maybeConsumeProxyProtocolPreface(
    conn: anytype,
    mode: edge_config.ProxyProtocolMode,
    pending_buf: []u8,
    pending_len: *usize,
    client_ip_buf: *[64]u8,
    client_ip_len: *usize,
) !void {
    if (mode == .off) return;

    while (true) {
        const outcome = parseProxyHeader(pending_buf[0..pending_len.*], mode, client_ip_buf);
        switch (outcome) {
            .no_header => return,
            .invalid => return error.InvalidProxyProtocolHeader,
            .parsed => |parsed| {
                client_ip_len.* = parsed.client_ip_len;
                if (parsed.consumed < pending_len.*) {
                    const remaining = pending_len.* - parsed.consumed;
                    std.mem.copyForwards(u8, pending_buf[0..remaining], pending_buf[parsed.consumed..pending_len.*]);
                    pending_len.* = remaining;
                } else {
                    pending_len.* = 0;
                }
                return;
            },
            .need_more => {
                if (pending_len.* == pending_buf.len) return error.ProxyProtocolHeaderTooLarge;
                const n = try conn.read(pending_buf[pending_len.*..]);
                if (n == 0) return error.ConnectionClosed;
                pending_len.* += n;
            },
        }
    }
}

/// Parse and consume a PROXY protocol header from a raw TCP socket fd before
/// the TLS handshake. Uses MSG_PEEK so unconsumed application bytes remain in
/// the kernel receive buffer for OpenSSL.
pub fn peekAndConsumeProxyHeaderFromRawFd(
    fd: std.posix.fd_t,
    mode: edge_config.ProxyProtocolMode,
    client_ip_buf: *[64]u8,
    client_ip_len: *usize,
) !void {
    if (mode == .off) return;
    const msg_peek: u32 = 2; // MSG_PEEK - peek without consuming.
    var peek_buf: [1024]u8 = undefined;
    var peeked: usize = 0;
    // Retry blocking sockets that may not have all bytes immediately. In
    // practice the PROXY header always arrives in the first TCP segment.
    var attempts: u32 = 0;
    while (attempts < 20) : (attempts += 1) {
        const n_raw = std.c.recv(fd, @as(*anyopaque, @ptrCast(&peek_buf)), peek_buf.len, @intCast(msg_peek));
        if (n_raw < 0) return error.ConnectionClosed;
        const n: usize = @intCast(n_raw);
        if (n == 0) return error.ConnectionClosed;
        if (n > peeked) peeked = n;
        const outcome = parseProxyHeader(peek_buf[0..peeked], mode, client_ip_buf);
        switch (outcome) {
            .no_header => return,
            .invalid => return error.InvalidProxyProtocolHeader,
            .parsed => |parsed| {
                client_ip_len.* = parsed.client_ip_len;
                var consumed_total: usize = 0;
                var discard: [1024]u8 = undefined;
                while (consumed_total < parsed.consumed) {
                    const to_read = @min(parsed.consumed - consumed_total, discard.len);
                    const nr_raw = std.c.recv(fd, @as(*anyopaque, @ptrCast(&discard)), to_read, 0);
                    if (nr_raw <= 0) return error.ConnectionClosed;
                    consumed_total += @intCast(nr_raw);
                }
                return;
            },
            .need_more => {
                if (peeked >= peek_buf.len) return error.ProxyProtocolHeaderTooLarge;
                std.Io.sleep(compat.io(), std.Io.Duration.fromMicroseconds(500), .awake) catch {}; // interrupt wakes are fine; loop continues immediately
            },
        }
    }
    return error.ProxyProtocolHeaderTooLarge;
}

pub fn parseProxyHeader(buf: []const u8, mode: edge_config.ProxyProtocolMode, client_ip_buf: *[64]u8) ProxyHeaderOutcome {
    return switch (mode) {
        .off => .no_header,
        .v1 => parseProxyHeaderV1(buf, true, client_ip_buf),
        .v2 => parseProxyHeaderV2(buf, true, client_ip_buf),
        .auto => blk: {
            if (buf.len == 0) break :blk .need_more;
            if (buf[0] == 'P') break :blk parseProxyHeaderV1(buf, false, client_ip_buf);
            if (buf[0] == '\r') break :blk parseProxyHeaderV2(buf, false, client_ip_buf);
            break :blk .no_header;
        },
    };
}

fn parseProxyHeaderV1(buf: []const u8, strict: bool, client_ip_buf: *[64]u8) ProxyHeaderOutcome {
    const prefix = "PROXY ";
    if (buf.len < prefix.len) {
        if (std.mem.eql(u8, buf, prefix[0..buf.len])) return .need_more;
        return if (strict) .invalid else .no_header;
    }
    if (!std.mem.eql(u8, buf[0..prefix.len], prefix)) return if (strict) .invalid else .no_header;

    const line_end = std.mem.find(u8, buf, "\r\n") orelse {
        if (buf.len >= 108) return .invalid;
        return .need_more;
    };
    const line = buf[0..line_end];

    var tok_it = std.mem.tokenizeScalar(u8, line, ' ');
    const sig = tok_it.next() orelse return .invalid;
    if (!std.mem.eql(u8, sig, "PROXY")) return .invalid;
    const proto = tok_it.next() orelse return .invalid;
    if (std.mem.eql(u8, proto, "UNKNOWN")) {
        return .{ .parsed = .{ .consumed = line_end + 2, .client_ip_len = 0 } };
    }

    if (!std.mem.eql(u8, proto, "TCP4") and !std.mem.eql(u8, proto, "TCP6")) return .invalid;
    const src_ip = tok_it.next() orelse return .invalid;
    _ = tok_it.next() orelse return .invalid;
    _ = tok_it.next() orelse return .invalid;
    _ = tok_it.next() orelse return .invalid;
    if (src_ip.len == 0 or src_ip.len > client_ip_buf.len) return .invalid;
    @memcpy(client_ip_buf[0..src_ip.len], src_ip);
    return .{ .parsed = .{ .consumed = line_end + 2, .client_ip_len = src_ip.len } };
}

fn parseProxyHeaderV2(buf: []const u8, strict: bool, client_ip_buf: *[64]u8) ProxyHeaderOutcome {
    if (buf.len < proxy_v2_signature.len) {
        if (std.mem.eql(u8, buf, proxy_v2_signature[0..buf.len])) return .need_more;
        return if (strict) .invalid else .no_header;
    }
    if (!std.mem.eql(u8, buf[0..proxy_v2_signature.len], proxy_v2_signature)) return if (strict) .invalid else .no_header;
    if (buf.len < 16) return .need_more;

    const ver_cmd = buf[12];
    if ((ver_cmd >> 4) != 0x2) return .invalid;
    const cmd = ver_cmd & 0x0f;
    const fam = buf[13] >> 4;
    const addr_len = std.mem.readInt(u16, buf[14..16], .big);
    const total_len: usize = 16 + addr_len;
    if (total_len > 1024) return .invalid;
    if (buf.len < total_len) return .need_more;

    if (cmd != 0x1) {
        return .{ .parsed = .{ .consumed = total_len, .client_ip_len = 0 } };
    }

    switch (fam) {
        0x1 => {
            if (addr_len < 12) return .invalid;
            const src = buf[16..20];
            const printed = std.fmt.bufPrint(client_ip_buf, "{d}.{d}.{d}.{d}", .{ src[0], src[1], src[2], src[3] }) catch return .invalid;
            return .{ .parsed = .{ .consumed = total_len, .client_ip_len = printed.len } };
        },
        0x2 => {
            if (addr_len < 36) return .invalid;
            const src = buf[16..32];
            const g0 = std.mem.readInt(u16, src[0..2], .big);
            const g1 = std.mem.readInt(u16, src[2..4], .big);
            const g2 = std.mem.readInt(u16, src[4..6], .big);
            const g3 = std.mem.readInt(u16, src[6..8], .big);
            const g4 = std.mem.readInt(u16, src[8..10], .big);
            const g5 = std.mem.readInt(u16, src[10..12], .big);
            const g6 = std.mem.readInt(u16, src[12..14], .big);
            const g7 = std.mem.readInt(u16, src[14..16], .big);
            const printed = std.fmt.bufPrint(client_ip_buf, "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", .{ g0, g1, g2, g3, g4, g5, g6, g7 }) catch return .invalid;
            return .{ .parsed = .{ .consumed = total_len, .client_ip_len = printed.len } };
        },
        else => return .{ .parsed = .{ .consumed = total_len, .client_ip_len = 0 } },
    }
}

pub fn readHttpRequest(conn: anytype, buf: []u8, pending_len: *usize) !usize {
    var total_read = pending_len.*;

    while (total_read <= buf.len) {
        if (firstRequestCompleteLen(buf[0..total_read])) |request_len| {
            pending_len.* = total_read;
            return @min(total_read, request_len);
        }
        if (total_read == buf.len) break;

        const n = conn.read(buf[total_read..]) catch |err| return err;
        if (n == 0) break;
        total_read += n;
    }

    pending_len.* = total_read;
    return total_read;
}

pub fn firstRequestCompleteLen(data: []const u8) ?usize {
    const header_pos = std.mem.find(u8, data, "\r\n\r\n") orelse return null;
    const headers_len = header_pos + 4;
    const content_length = parseContentLength(data[0..headers_len]) orelse 0;
    const full_len = headers_len + content_length;
    if (data.len >= full_len) return full_len;
    return null;
}

pub fn parseContentLength(headers: []const u8) ?usize {
    var it = std.mem.tokenizeAny(u8, headers, "\r\n");
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "content-length")) continue;

        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        return std.fmt.parseInt(usize, value, 10) catch null;
    }
    return null;
}
