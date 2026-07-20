//! Real-UDP native QUIC/H3 smoke test (#247 phase 4).
//!
//! Runs the native client and server drivers over actual loopback UDP
//! sockets: nonblocking I/O, poll(2) wakeups scheduled from the drivers'
//! `nextTimeoutUs`, server-side connection lookup by DCID through the CID
//! routing table, and full FD/allocator cleanup. Asserts forward progress
//! without busy loops by bounding the number of poll iterations.

const std = @import("std");
const quic = @import("quic");
const http3 = @import("http3");
const tls_core = @import("tls_core");

const connection = quic.connection;
const tls_backend = quic.tls_backend;
const Connection = connection.Connection;
const H3 = http3.conn.Conn(Connection);

const testing = std.testing;
const posix = std.posix;

const UdpSocket = struct {
    fd: std.c.fd_t,
    addr: std.c.sockaddr.in,

    fn open() !UdpSocket {
        // macOS/BSD reject SOCK_CLOEXEC/SOCK_NONBLOCK in the socket type
        // (EPROTOTYPE); apply them via fcntl after creation instead.
        const fd = std.c.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        if (fd < 0) return error.SocketFailed;
        errdefer _ = std.c.close(fd);
        const descriptor_flags = std.c.fcntl(fd, std.c.F.GETFD, @as(c_int, 0));
        if (descriptor_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFD, descriptor_flags | std.c.FD_CLOEXEC);
        const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (status_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFL, status_flags | @as(c_int, @bitCast(posix.O{ .NONBLOCK = true })));
        var bind_addr = std.c.sockaddr.in{
            .family = posix.AF.INET,
            .port = 0,
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        if (std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(std.c.sockaddr.in)) != 0) return error.BindFailed;
        var bound: std.c.sockaddr.in = undefined;
        var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        if (std.c.getsockname(fd, @ptrCast(&bound), &bound_len) != 0) return error.GetSockNameFailed;
        return .{ .fd = fd, .addr = bound };
    }

    fn close(self: *UdpSocket) void {
        _ = std.c.close(self.fd);
    }

    fn sendTo(self: *UdpSocket, peer: std.c.sockaddr.in, bytes: []const u8) !void {
        const sent = std.c.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(&peer), @sizeOf(std.c.sockaddr.in));
        if (sent < 0 or @as(usize, @intCast(sent)) != bytes.len) return error.SendFailed;
    }

    /// Nonblocking receive; null when the socket has nothing.
    fn recv(self: *UdpSocket, buf: []u8) !?[]u8 {
        const n = std.c.recvfrom(self.fd, buf.ptr, buf.len, 0, null, null);
        if (n < 0) {
            return switch (posix.errno(n)) {
                .AGAIN => null,
                else => error.RecvFailed,
            };
        }
        return buf[0..@intCast(n)];
    }
};

fn nowUs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1_000;
}

test "udp smoke: native client/server complete an H3 exchange over loopback" {
    const allocator = testing.allocator;

    var client_socket = try UdpSocket.open();
    defer client_socket.close();
    var server_socket = try UdpSocket.open();
    defer server_socket.close();

    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    var client_backend = tls_backend.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xc1} ** 32, .key_share_seed = [_]u8{0x11} ** 32 },
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
    );
    var server_backend = tls_backend.Tls13Backend.initServer(
        .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x22} ** 32 },
        try tls_backend.Identity.initPkcs8(
            tls_backend.testdata.certificate_der,
            tls_backend.testdata.private_key_pkcs8_der,
        ),
    );

    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_dcid = &odcid,
        .tls = client_backend.backend(),
        .now_us = nowUs(),
    });
    defer client.deinit();
    const server = try Connection.init(allocator, .{
        .role = .server,
        .local_cid = &odcid,
        .original_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = server_backend.backend(),
        .now_us = nowUs(),
    });
    defer server.deinit();

    // Server-side DCID routing: one entry per accepted connection. With one
    // connection this exercises exactly the lookup path a multi-connection
    // endpoint uses.
    var routes = quic.cid.CidRoutingTable.init(allocator);
    defer routes.deinit();
    const server_handle: u64 = 7;
    try routes.insert(try quic.cid.ConnectionId.init(server.localCid()), server_handle);

    var client_h3 = H3.init(allocator, .client);
    defer client_h3.deinit();
    var server_h3 = H3.init(allocator, .server);
    defer server_h3.deinit();

    var h3_started = false;
    var request_id: ?u64 = null;
    var responded = false;
    var response_done = false;
    var routed_datagrams: usize = 0;

    const deadline = nowUs() + 10_000_000; // 10s wall-clock budget
    var iterations: usize = 0;
    while (nowUs() < deadline and !response_done) : (iterations += 1) {
        // The exchange is a handful of round-trips on loopback; thousands of
        // wakeups would mean a busy loop or a missed timer.
        try testing.expect(iterations < 5_000);
        const now = nowUs();

        // Flush both drivers.
        var out: [2048]u8 = undefined;
        while (client.pollTransmit(&out, now)) |datagram| {
            try client_socket.sendTo(server_socket.addr, datagram);
        }
        while (server.pollTransmit(&out, now)) |datagram| {
            try server_socket.sendTo(client_socket.addr, datagram);
        }

        // Poll with a timeout derived from driver deadlines (bounded so the
        // test cannot hang on a scheduling bug).
        var next: u64 = now + 100_000;
        if (client.nextTimeoutUs()) |t| next = @min(next, t);
        if (server.nextTimeoutUs()) |t| next = @min(next, t);
        const timeout_ms: i32 = @intCast(@min((next -| now) / 1_000 + 1, 100));
        var fds = [_]posix.pollfd{
            .{ .fd = client_socket.fd, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = server_socket.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = try posix.poll(&fds, timeout_ms);

        var in: [2048]u8 = undefined;
        while (try client_socket.recv(&in)) |datagram| {
            try client.ingest(datagram, nowUs());
        }
        while (try server_socket.recv(&in)) |datagram| {
            // Route by DCID exactly like a multi-connection endpoint.
            const parsed = quic.packet.parsePacket(datagram, server.localCid().len) catch continue;
            const handle = routes.lookup(parsed.dcid) orelse continue;
            try testing.expectEqual(server_handle, handle);
            routed_datagrams += 1;
            try server.ingest(datagram, nowUs());
        }

        client.onTimeout(nowUs());
        server.onTimeout(nowUs());

        // HTTP/3 layer.
        if (!h3_started and client.isEstablished() and server.isEstablished()) {
            try client_h3.start(client);
            try server_h3.start(server);
            h3_started = true;
        }
        if (h3_started) {
            try server_h3.pump(server);
            if (!responded) {
                if (try server_h3.pollRequest()) |incoming| {
                    try testing.expectEqualStrings("/udp-smoke", incoming.exchange.request.path);
                    try server_h3.sendResponse(server, incoming.stream_id, 200, &.{
                        .{ .name = "server", .value = "tardigrade" },
                    }, "udp-smoke-response");
                    responded = true;
                }
            }
            if (request_id == null) {
                request_id = try client_h3.sendRequest(client, .{
                    .authority = "tardigrade.test",
                    .path = "/udp-smoke",
                    .body = "udp-smoke-request",
                });
            }
            try client_h3.pump(client);
            if (request_id) |id| {
                if (try client_h3.pollResponse(id)) |response| {
                    try testing.expectEqual(@as(u16, 200), response.status);
                    try testing.expectEqualStrings("udp-smoke-response", response.body);
                    response_done = true;
                    client_h3.releaseResponse(id);
                }
            }
        }
    }

    try testing.expect(response_done);
    try testing.expect(routed_datagrams > 0);
    try testing.expect(routes.metrics.routing_hits > 0);

    // Orderly close both ways; drain must not require more traffic.
    client.close(0, "udp-smoke-done", nowUs());
    var out: [2048]u8 = undefined;
    while (client.pollTransmit(&out, nowUs())) |datagram| {
        try client_socket.sendTo(server_socket.addr, datagram);
    }
    var settle: usize = 0;
    while (settle < 50 and server.state() != .draining) : (settle += 1) {
        var fds = [_]posix.pollfd{
            .{ .fd = server_socket.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = try posix.poll(&fds, 5);
        var in: [2048]u8 = undefined;
        while (try server_socket.recv(&in)) |datagram| {
            try server.ingest(datagram, nowUs());
        }
    }
    try testing.expectEqual(connection.State.draining, server.state());
}

// ---------------------------------------------------------------------------
// Appliance credential provider over native QUIC (#392): the same strict
// Ed25519 owner that authenticates native TCP TLS drives a real loopback QUIC
// handshake through `initServerWithProvider`. The client pins the provisioned
// leaf certificate, so an established connection proves the full chain was
// emitted and the Ed25519 CertificateVerify was accepted.
// ---------------------------------------------------------------------------

const native_ed25519_cert_pem = @embedFile("fixtures/tls/native_ed25519.crt");
const native_ed25519_key_pem = @embedFile("fixtures/tls/native_ed25519.key");

fn decodeSinglePemCertificate(allocator: std.mem.Allocator, pem: []const u8) ![]u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const begin_at = std.mem.indexOf(u8, pem, begin) orelse return error.PemBlockNotFound;
    const body_start = begin_at + begin.len;
    const end_at = std.mem.indexOfPos(u8, pem, body_start, end) orelse return error.PemBlockNotFound;
    var b64: std.ArrayList(u8) = .empty;
    defer b64.deinit(allocator);
    for (pem[body_start..end_at]) |ch| switch (ch) {
        '\n', '\r', ' ', '\t' => {},
        else => try b64.append(allocator, ch),
    };
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64.items) catch return error.InvalidPemBase64;
    const der = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(der);
    std.base64.standard.Decoder.decode(der, b64.items) catch return error.InvalidPemBase64;
    return der;
}

test "udp smoke: appliance credential provider authenticates native QUIC/H3" {
    const allocator = testing.allocator;

    var appliance = try tls_core.appliance_credentials.ApplianceCredentials.initFromBytes(
        allocator,
        native_ed25519_cert_pem,
        native_ed25519_key_pem,
        .{ .server_name = "tardigrade.test" },
    );
    defer appliance.deinit();
    const leaf_der = try decodeSinglePemCertificate(allocator, native_ed25519_cert_pem);
    defer allocator.free(leaf_der);

    var client_socket = try UdpSocket.open();
    defer client_socket.close();
    var server_socket = try UdpSocket.open();
    defer server_socket.close();

    const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const odcid = [_]u8{ 0x18, 0x27, 0x36, 0x45, 0x54, 0x63, 0x72, 0x81 };

    var client_backend = tls_backend.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xa9} ** 32, .key_share_seed = [_]u8{0x33} ** 32 },
        .{ .pinned_certificate = leaf_der },
    );
    var server_backend = tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0x77} ** 32, .key_share_seed = [_]u8{0x44} ** 32 },
        appliance.provider(),
    );

    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_dcid = &odcid,
        .tls = client_backend.backend(),
        .now_us = nowUs(),
    });
    defer client.deinit();
    const server = try Connection.init(allocator, .{
        .role = .server,
        .local_cid = &odcid,
        .original_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = server_backend.backend(),
        .now_us = nowUs(),
    });
    defer server.deinit();

    var client_h3 = H3.init(allocator, .client);
    defer client_h3.deinit();
    var server_h3 = H3.init(allocator, .server);
    defer server_h3.deinit();

    var h3_started = false;
    var request_id: ?u64 = null;
    var responded = false;
    var response_done = false;

    const deadline = nowUs() + 10_000_000;
    var iterations: usize = 0;
    while (nowUs() < deadline and !response_done) : (iterations += 1) {
        try testing.expect(iterations < 5_000);
        const now = nowUs();

        var out: [2048]u8 = undefined;
        while (client.pollTransmit(&out, now)) |datagram| {
            try client_socket.sendTo(server_socket.addr, datagram);
        }
        while (server.pollTransmit(&out, now)) |datagram| {
            try server_socket.sendTo(client_socket.addr, datagram);
        }

        var next: u64 = now + 100_000;
        if (client.nextTimeoutUs()) |t| next = @min(next, t);
        if (server.nextTimeoutUs()) |t| next = @min(next, t);
        const timeout_ms: i32 = @intCast(@min((next -| now) / 1_000 + 1, 100));
        var fds = [_]posix.pollfd{
            .{ .fd = client_socket.fd, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = server_socket.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = try posix.poll(&fds, timeout_ms);

        var in: [2048]u8 = undefined;
        while (try client_socket.recv(&in)) |datagram| {
            try client.ingest(datagram, nowUs());
        }
        while (try server_socket.recv(&in)) |datagram| {
            try server.ingest(datagram, nowUs());
        }

        client.onTimeout(nowUs());
        server.onTimeout(nowUs());

        if (!h3_started and client.isEstablished() and server.isEstablished()) {
            try client_h3.start(client);
            try server_h3.start(server);
            h3_started = true;
        }
        if (h3_started) {
            try server_h3.pump(server);
            if (!responded) {
                if (try server_h3.pollRequest()) |incoming| {
                    try server_h3.sendResponse(server, incoming.stream_id, 200, &.{}, "appliance-h3-response");
                    responded = true;
                }
            }
            if (request_id == null) {
                request_id = try client_h3.sendRequest(client, .{
                    .authority = "tardigrade.test",
                    .path = "/appliance",
                    .body = "",
                });
            }
            try client_h3.pump(client);
            if (request_id) |id| {
                if (try client_h3.pollResponse(id)) |response| {
                    try testing.expectEqual(@as(u16, 200), response.status);
                    try testing.expectEqualStrings("appliance-h3-response", response.body);
                    response_done = true;
                    client_h3.releaseResponse(id);
                }
            }
        }
    }

    // Pinned-leaf establishment proves the provisioned chain and Ed25519
    // CertificateVerify were accepted by an independent verifier.
    try testing.expect(response_done);

    // Provider lifetime: the owner remains selectable while (and after)
    // connections exist — teardown order is connections, then owner.
    var selection = tls_core.credentials.SelectionContext{
        .role = .server,
        .server_name = "tardigrade.test",
        .peer_signature_schemes = &.{0x0807},
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = "h3",
        .auth_policy = .{},
    };
    switch (try appliance.provider().selectCredential(&selection)) {
        .complete => |credential| credential.release(),
        .pending => return error.TestUnexpectedPending,
    }
}
