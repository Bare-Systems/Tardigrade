//! Real-UDP native QUIC/H3 smoke test (#247 phase 4).
//!
//! Runs the native client and server drivers over actual loopback UDP
//! sockets: nonblocking I/O, poll(2) wakeups scheduled from the drivers'
//! `nextTimeoutUs`, server-side connection lookup by DCID through the CID
//! routing table, and full FD/allocator cleanup. Asserts forward progress
//! without busy loops by bounding the number of poll iterations.

const std = @import("std");
const quic = @import("quic");
const test_quic_crypto = @import("test_quic_crypto");
const http3 = @import("http3");
const tls_core = @import("tls_core");
const http3_runtime = @import("http3_runtime");

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

/// Mirrors `http3_runtime.zig`'s conversion: `sockaddr_in`'s address/port are
/// already network-byte-order, so the octets bit-cast directly and only the
/// port needs an explicit big-to-native swap.
fn addressFromSockaddrIn(sa: std.c.sockaddr.in) quic.udp.Address {
    const octets: [4]u8 = @bitCast(sa.addr);
    return quic.udp.Address.ip4(octets, std.mem.bigToNative(u16, sa.port));
}

fn sockaddrInFromAddress(addr: quic.udp.Address) std.c.sockaddr.in {
    var octets: [4]u8 = undefined;
    @memcpy(&octets, addr.slice());
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, addr.port),
        .addr = @bitCast(octets),
        .zero = [_]u8{0} ** 8,
    };
}

/// Unused by ordinary on-path traffic (`PathManager` only consumes fresh
/// challenge entropy when a datagram starts a *new* candidate validation);
/// a fixed value is fine wherever a test never migrates.
const test_challenge_entropy = [_]u8{0xa5} ** quic.path.path_challenge_len;

const RuntimeHandlerState = struct {
    requests: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
};

fn runtimeSmokeHandler(
    _: std.mem.Allocator,
    request: *const http3_runtime.StreamRequest,
    response: *http3_runtime.Response,
    user_data: ?*anyopaque,
) anyerror!void {
    const state: *RuntimeHandlerState = @ptrCast(@alignCast(user_data.?));
    _ = state.requests.fetchAdd(1, .monotonic);
    try testing.expectEqualStrings("/runtime-retry", request.path);
    _ = response.setStatus(.ok).setBody("runtime-retry-response").setContentType("text/plain");
}

fn writeSyntheticInitial(
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    out: []u8,
) ![]const u8 {
    const header = try quic.packet.writeLongHeader(.initial, version, dcid, scid, token, 1, out);
    if (out.len < header.pn_offset + 1) return error.BufferTooShort;
    out[header.pn_offset] = 0;
    quic.packet.patchLongHeaderLength(out, header.length_offset, 1);
    return out[0 .. header.pn_offset + 1];
}

fn writeSpoofedShortHeader(dcid: []const u8, out: []u8) ![]const u8 {
    const pn_offset = try quic.packet.writeShortHeader(dcid, 0, 1, out);
    if (out.len < pn_offset + 32) return error.BufferTooShort;
    out[pn_offset] = 0;
    @memset(out[pn_offset + 1 .. pn_offset + 32], 0xa5);
    return out[0 .. pn_offset + 32];
}

fn waitRuntimeSnapshot(
    runtime: *http3_runtime.Runtime,
    comptime predicate: fn (http3_runtime.Snapshot) bool,
) !http3_runtime.Snapshot {
    const deadline = nowUs() + 5_000_000;
    while (nowUs() < deadline) {
        const snapshot = runtime.snapshot();
        if (predicate(snapshot)) return snapshot;
        var ts = std.c.timespec{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = std.posix.system.nanosleep(&ts, &ts);
    }
    return error.TestTimedOut;
}

fn hasNoTrackedConnections(snapshot: http3_runtime.Snapshot) bool {
    return snapshot.tracked_connections == 0;
}

fn processedRetryOffFlood(snapshot: http3_runtime.Snapshot) bool {
    return snapshot.datagrams_seen >= 8 and snapshot.tracked_connections == 0;
}

fn sawFiveInvalidTokens(snapshot: http3_runtime.Snapshot) bool {
    return snapshot.invalid_tokens >= 5 and snapshot.tracked_connections == 0;
}

fn sentFourRetries(snapshot: http3_runtime.Snapshot) bool {
    return snapshot.retry_packets_sent >= 4;
}

fn hasPathValidationFailure(snapshot: http3_runtime.Snapshot) bool {
    return snapshot.path_validations_failed > 0 and snapshot.tracked_connections > 0;
}

fn waitRuntimeDatagrams(runtime: *http3_runtime.Runtime, target: usize) !http3_runtime.Snapshot {
    const deadline = nowUs() + 5_000_000;
    while (nowUs() < deadline) {
        const snapshot = runtime.snapshot();
        if (snapshot.datagrams_seen >= target) return snapshot;
        var ts = std.c.timespec{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = std.posix.system.nanosleep(&ts, &ts);
    }
    return error.TestTimedOut;
}

fn driveRuntimeRetryRequest(
    client_socket: *UdpSocket,
    client: *Connection,
    client_h3: *H3,
    client_path: quic.path.PathKey,
    h3_started: *bool,
    body: []const u8,
    saw_retry: *bool,
) !void {
    var request_id: ?u64 = null;
    var response_done = false;
    const deadline = nowUs() + 10_000_000;
    var iterations: usize = 0;
    while (nowUs() < deadline and !response_done) : (iterations += 1) {
        try testing.expect(iterations < 5_000);
        const now = nowUs();

        var out: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&out, now)) |t| {
            try client_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }

        var next: u64 = now + 50_000;
        if (client.nextTimeoutUs()) |t| next = @min(next, t);
        const timeout_ms: i32 = @intCast(@min((next -| now) / 1_000 + 1, 50));
        var fds = [_]posix.pollfd{.{ .fd = client_socket.fd, .events = posix.POLL.IN, .revents = 0 }};
        _ = try posix.poll(&fds, timeout_ms);

        var in: [2048]u8 = undefined;
        while (try client_socket.recv(&in)) |datagram| {
            if (quic.packet.parsePacket(datagram, 0)) |parsed| {
                if (parsed.kind == .retry) saw_retry.* = true;
            } else |_| {}
            try client.ingestOnPath(datagram, client_path, test_challenge_entropy, nowUs());
        }
        client.onTimeout(nowUs());

        if (!h3_started.* and client.isEstablished()) {
            try client_h3.start(client);
            h3_started.* = true;
        }
        if (h3_started.*) {
            if (request_id == null) {
                request_id = try client_h3.sendRequest(client, .{
                    .authority = "tardigrade.test",
                    .path = "/runtime-retry",
                    .body = body,
                });
            }
            try client_h3.pump(client);
            if (request_id) |id| {
                if (try client_h3.pollResponse(id)) |response| {
                    try testing.expectEqual(@as(u16, 200), response.status);
                    try testing.expectEqualStrings("runtime-retry-response", response.body);
                    response_done = true;
                    client_h3.releaseResponse(id);
                }
            }
        }
    }
    try testing.expect(response_done);
}

test "udp smoke: native client/server complete an H3 exchange over loopback" {
    const allocator = testing.allocator;

    var client_socket = try UdpSocket.open();
    defer client_socket.close();
    var server_socket = try UdpSocket.open();
    defer server_socket.close();

    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    // Owned, per-test deterministic TLS-engine provider storage (#490
    // review), not the shared `test_quic_crypto.testHandshakeProvider()`
    // stream: independent of any other test in the process.
    var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var server_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend = tls_backend.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xc1} ** 32 },
        client_provider_storage.init(0x442_c),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
    );
    var server_backend = tls_backend.Tls13Backend.initServer(
        .{ .hello_random = [_]u8{0x51} ** 32 },
        server_provider_storage.init(0x442_5),
        try tls_backend.Identity.initPkcs8(
            tls_backend.testdata.certificate_der,
            tls_backend.testdata.private_key_pkcs8_der,
        ),
    );

    const client_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(client_socket.addr),
        .remote = addressFromSockaddrIn(server_socket.addr),
    };
    const server_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(server_socket.addr),
        .remote = addressFromSockaddrIn(client_socket.addr),
    };
    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .tls = client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = nowUs(),
        .initial_path = client_path,
    });
    defer client.deinit();
    const server = try Connection.init(allocator, .{
        .role = .server,
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = server_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = nowUs(),
        .initial_path = server_path,
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

        // Flush both drivers. Each transmit carries its own destination
        // (candidate-path probes would target a different address than
        // ordinary content); this exchange never migrates, so it always
        // resolves to the peer socket, but the send always honors it.
        var out: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&out, now)) |t| {
            try client_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
        while (server.pollTransmitOnPath(&out, now)) |t| {
            try server_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
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
            try client.ingestOnPath(datagram, client_path, test_challenge_entropy, nowUs());
        }
        while (try server_socket.recv(&in)) |datagram| {
            // Route by DCID exactly like a multi-connection endpoint.
            const parsed = quic.packet.parsePacket(datagram, server.localCid().len) catch continue;
            const handle = routes.lookup(parsed.dcid) orelse continue;
            try testing.expectEqual(server_handle, handle);
            routed_datagrams += 1;
            try server.ingestOnPath(datagram, server_path, test_challenge_entropy, nowUs());
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
    while (client.pollTransmitOnPath(&out, nowUs())) |t| {
        try client_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
    }
    var settle: usize = 0;
    while (settle < 50 and server.state() != .draining) : (settle += 1) {
        var fds = [_]posix.pollfd{
            .{ .fd = server_socket.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = try posix.poll(&fds, 5);
        var in: [2048]u8 = undefined;
        while (try server_socket.recv(&in)) |datagram| {
            try server.ingestOnPath(datagram, server_path, test_challenge_entropy, nowUs());
        }
    }
    try testing.expectEqual(connection.State.draining, server.state());
}

test "udp smoke: HTTP/3 runtime Retry sends tokenless Initials without tracked state" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = http3_runtime.Logger.init(.err, "udp-runtime-retry-flood-test");
    var handler_state = RuntimeHandlerState{};
    var runtime = try http3_runtime.Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
        .request_handler = runtimeSmokeHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    runtime.start();

    var client_socket = try UdpSocket.open();
    defer client_socket.close();
    const client_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(client_socket.addr),
        .remote = runtime.local_address,
    };

    const attempts = 4;
    for (0..attempts) |i| {
        {
            var client_cid = [_]u8{0xc1} ** 8;
            client_cid[7] = @intCast(i);
            var odcid = [_]u8{0x83} ** 8;
            odcid[7] = @intCast(i);
            // Fresh per-iteration storage (#490 review): each attempt gets
            // its own independent deterministic provider, not a shared
            // stream advancing across iterations or other tests.
            var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
            var client_backend = tls_backend.Tls13Backend.initClient(
                .{ .hello_random = [_]u8{0xc1} ** 32 },
                client_provider_storage.init(0x442_c),
                .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
            );
            const client = try Connection.init(allocator, .{
                .role = .client,
                .local_cid = &client_cid,
                .original_destination_cid = &odcid,
                .initial_secret_dcid = &odcid,
                .tls = client_backend.backend(),
                .crypto_provider = test_quic_crypto.testDefaultProvider(),
                .now_us = nowUs(),
                .initial_path = client_path,
            });
            errdefer client.deinit();
            var out: [2048]u8 = undefined;
            while (client.pollTransmitOnPath(&out, nowUs())) |t| {
                try client_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
            }
            client.deinit();
        }
    }

    var retries: usize = 0;
    const deadline = nowUs() + 5_000_000;
    while (nowUs() < deadline and retries < attempts) {
        var fds = [_]posix.pollfd{.{ .fd = client_socket.fd, .events = posix.POLL.IN, .revents = 0 }};
        _ = try posix.poll(&fds, 25);
        var in: [2048]u8 = undefined;
        while (try client_socket.recv(&in)) |datagram| {
            const parsed = quic.packet.parsePacket(datagram, 0) catch continue;
            if (parsed.kind == .retry) retries += 1;
        }
    }
    try testing.expectEqual(@as(usize, attempts), retries);

    const snapshot = try waitRuntimeSnapshot(&runtime, sentFourRetries);
    try testing.expectEqual(@as(usize, attempts), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 0), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 0), snapshot.invalid_tokens);
    try testing.expectEqual(@as(usize, 0), snapshot.tracked_connections);
    try testing.expectEqual(@as(usize, 0), handler_state.requests.load(.monotonic));
}

test "udp smoke: HTTP/3 runtime Retry-off flood cleans unauthenticated state" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = http3_runtime.Logger.init(.err, "udp-runtime-retry-off-flood-test");
    var handler_state = RuntimeHandlerState{};
    var runtime = try http3_runtime.Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .off,
        .request_handler = runtimeSmokeHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    runtime.start();

    var client_socket = try UdpSocket.open();
    defer client_socket.close();
    const runtime_addr = sockaddrInFromAddress(runtime.local_address);

    const flood_attempts: usize = 8;
    for (0..flood_attempts) |i| {
        var dcid = [_]u8{0x71} ** 8;
        dcid[7] = @intCast(i);
        var scid = [_]u8{0x72} ** 8;
        scid[7] = @intCast(i);
        var packet: [128]u8 = undefined;
        const initial = try writeSyntheticInitial(quic.packet.quic_v1, &dcid, &scid, "", &packet);
        try client_socket.sendTo(runtime_addr, initial);
    }

    const flood_snapshot = try waitRuntimeSnapshot(&runtime, processedRetryOffFlood);
    try testing.expect(flood_snapshot.datagrams_seen >= flood_attempts);
    try testing.expectEqual(@as(usize, 0), flood_snapshot.tracked_connections);
    try testing.expectEqual(@as(usize, 0), flood_snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 0), flood_snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 0), handler_state.requests.load(.monotonic));

    const client_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8 };
    const odcid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8 };
    const client_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(client_socket.addr),
        .remote = runtime.local_address,
    };
    var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend = tls_backend.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xe1} ** 32 },
        client_provider_storage.init(0x442_c),
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );
    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .tls = client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = nowUs(),
        .initial_path = client_path,
    });
    defer client.deinit();
    var client_h3 = H3.init(allocator, .client);
    defer client_h3.deinit();
    var h3_started = false;
    var saw_retry = false;
    try driveRuntimeRetryRequest(&client_socket, client, &client_h3, client_path, &h3_started, "runtime-retry-off-responsive", &saw_retry);
    try testing.expect(!saw_retry);
    try testing.expectEqual(@as(usize, 1), handler_state.requests.load(.monotonic));

    var cap_socket = try UdpSocket.open();
    defer cap_socket.close();
    const cap_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(cap_socket.addr),
        .remote = runtime.local_address,
    };
    const before_cap = runtime.snapshot();
    const cap_attempts: usize = 40;
    for (0..cap_attempts) |i| {
        var cap_client_cid = [_]u8{0x31} ** 8;
        cap_client_cid[6] = @intCast(i / 256);
        cap_client_cid[7] = @intCast(i);
        var cap_odcid = [_]u8{0x41} ** 8;
        cap_odcid[6] = @intCast(i / 256);
        cap_odcid[7] = @intCast(i);
        // Fresh per-iteration storage (#490 review) — see the matching
        // comment above.
        var cap_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
        var cap_backend = tls_backend.Tls13Backend.initClient(
            .{ .hello_random = [_]u8{0xa1} ** 32 },
            cap_provider_storage.init(0x442_c),
            .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
        );
        const cap_client = try Connection.init(allocator, .{
            .role = .client,
            .local_cid = &cap_client_cid,
            .original_destination_cid = &cap_odcid,
            .initial_secret_dcid = &cap_odcid,
            .tls = cap_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = nowUs(),
            .initial_path = cap_path,
        });
        errdefer cap_client.deinit();
        var out: [2048]u8 = undefined;
        while (cap_client.pollTransmitOnPath(&out, nowUs())) |t| {
            try cap_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
        cap_client.deinit();
    }

    const cap_snapshot = try waitRuntimeDatagrams(&runtime, before_cap.datagrams_seen + cap_attempts);
    try testing.expectEqual(@as(usize, 32), cap_snapshot.tracked_connections);
    try testing.expectEqual(@as(usize, 32), cap_snapshot.native_connections);
}

test "udp smoke: HTTP/3 runtime Retry rejects invalid token matrix without allocation" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = http3_runtime.Logger.init(.err, "udp-runtime-retry-invalid-matrix-test");
    var handler_state = RuntimeHandlerState{};
    var runtime = try http3_runtime.Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
        .request_handler = runtimeSmokeHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    runtime.start();

    var client_socket = try UdpSocket.open();
    defer client_socket.close();
    var other_socket = try UdpSocket.open();
    defer other_socket.close();
    const runtime_addr = sockaddrInFromAddress(runtime.local_address);
    const peer = addressFromSockaddrIn(client_socket.addr);

    const odcid = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };
    const retry_scid = [_]u8{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98 };
    const wrong_retry_scid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const client_scid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 };
    var token_buf: [quic.path.max_token_len]u8 = undefined;
    const fresh_token = try runtime.secrets.retry_tokens.issueRetry(
        &odcid,
        &retry_scid,
        quic.packet.quic_v1,
        peer,
        nowUs(),
        [_]u8{0x23} ** quic.path.token_nonce_len,
        &token_buf,
    );

    var tampered_storage: [quic.path.max_token_len]u8 = undefined;
    @memcpy(tampered_storage[0..fresh_token.len], fresh_token);
    tampered_storage[fresh_token.len - 1] ^= 0x01;

    var expired_buf: [quic.path.max_token_len]u8 = undefined;
    const expired_token = try runtime.secrets.retry_tokens.issueRetry(
        &odcid,
        &retry_scid,
        quic.packet.quic_v1,
        peer,
        0,
        [_]u8{0x24} ** quic.path.token_nonce_len,
        &expired_buf,
    );

    const Cases = [_]struct {
        version: u32,
        dcid: []const u8,
        token: []const u8,
        socket: *UdpSocket,
    }{
        .{ .version = quic.packet.quic_v1, .dcid = &retry_scid, .token = tampered_storage[0..fresh_token.len], .socket = &client_socket },
        .{ .version = quic.packet.quic_v1, .dcid = &retry_scid, .token = expired_token, .socket = &client_socket },
        .{ .version = quic.packet.quic_v1, .dcid = &retry_scid, .token = fresh_token, .socket = &other_socket },
        .{ .version = 0xff00_001d, .dcid = &retry_scid, .token = fresh_token, .socket = &client_socket },
        .{ .version = quic.packet.quic_v1, .dcid = &wrong_retry_scid, .token = fresh_token, .socket = &client_socket },
    };

    for (Cases, 0..) |case, i| {
        var scid = client_scid;
        scid[7] +%= @intCast(i);
        var packet: [512]u8 = undefined;
        const initial = try writeSyntheticInitial(case.version, case.dcid, &scid, case.token, &packet);
        try case.socket.sendTo(runtime_addr, initial);
    }

    const snapshot = try waitRuntimeSnapshot(&runtime, sawFiveInvalidTokens);
    try testing.expectEqual(@as(usize, 5), snapshot.invalid_tokens);
    try testing.expectEqual(@as(usize, 0), snapshot.tracked_connections);
    try testing.expectEqual(@as(usize, 0), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 0), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 0), handler_state.requests.load(.monotonic));
}

test "udp smoke: HTTP/3 runtime Retry round trip completes a native H3 request" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = http3_runtime.Logger.init(.err, "udp-runtime-retry-success-test");
    var handler_state = RuntimeHandlerState{};
    var runtime = try http3_runtime.Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
        .request_handler = runtimeSmokeHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    runtime.start();

    var client_socket = try UdpSocket.open();
    defer client_socket.close();

    const client_cid = [_]u8{ 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8 };
    const odcid = [_]u8{ 0x93, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(client_socket.addr),
        .remote = runtime.local_address,
    };
    var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend = tls_backend.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xd1} ** 32 },
        client_provider_storage.init(0x442_c),
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );
    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .tls = client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = nowUs(),
        .initial_path = client_path,
    });
    defer client.deinit();
    var client_h3 = H3.init(allocator, .client);
    defer client_h3.deinit();

    var h3_started = false;
    var saw_retry = false;
    try driveRuntimeRetryRequest(&client_socket, client, &client_h3, client_path, &h3_started, "runtime-retry-request", &saw_retry);

    try testing.expect(saw_retry);
    try testing.expectEqual(@as(usize, 1), handler_state.requests.load(.monotonic));
    const retry_snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 1), retry_snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 1), retry_snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 0), retry_snapshot.invalid_tokens);
    try testing.expect(retry_snapshot.tracked_connections > 0);

    var spoof_socket = try UdpSocket.open();
    defer spoof_socket.close();
    const before_spoof = runtime.snapshot();
    var spoofed_packet: [128]u8 = undefined;
    const spoofed = try writeSpoofedShortHeader(client.peer_cid.slice(), &spoofed_packet);
    try spoof_socket.sendTo(sockaddrInFromAddress(runtime.local_address), spoofed);
    const spoof_deadline = nowUs() + 500_000;
    while (nowUs() < spoof_deadline and runtime.snapshot().datagrams_seen <= before_spoof.datagrams_seen) {
        var ts = std.c.timespec{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = std.posix.system.nanosleep(&ts, &ts);
    }
    const after_spoof = runtime.snapshot();
    try testing.expect(after_spoof.datagrams_seen > before_spoof.datagrams_seen);
    try testing.expectEqual(before_spoof.path_challenges_sent, after_spoof.path_challenges_sent);
    try testing.expectEqual(before_spoof.path_validations_succeeded, after_spoof.path_validations_succeeded);
    try testing.expectEqual(before_spoof.nat_rebindings, after_spoof.nat_rebindings);
    try testing.expectEqual(before_spoof.tracked_connections, after_spoof.tracked_connections);

    var timeout_socket = try UdpSocket.open();
    defer timeout_socket.close();
    const before_timeout = runtime.snapshot();
    const timeout_request_id = try client_h3.sendRequest(client, .{
        .authority = "tardigrade.test",
        .path = "/runtime-retry",
        .body = "runtime-retry-timeout-request",
    });
    try client_h3.pump(client);
    var timeout_out: [2048]u8 = undefined;
    var sent_timeout_candidate = false;
    while (client.pollTransmitOnPath(&timeout_out, nowUs())) |t| {
        try timeout_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        sent_timeout_candidate = true;
    }
    try testing.expect(sent_timeout_candidate);
    _ = timeout_request_id;
    const timeout_snapshot = try waitRuntimeSnapshot(&runtime, hasPathValidationFailure);
    try testing.expect(timeout_snapshot.path_validations_failed > before_timeout.path_validations_failed);
    try testing.expectEqual(before_timeout.nat_rebindings, timeout_snapshot.nat_rebindings);
    try testing.expectEqual(before_timeout.migrations, timeout_snapshot.migrations);
    try testing.expect(timeout_snapshot.tracked_connections > 0);

    var rebind_socket = try UdpSocket.open();
    defer rebind_socket.close();
    const rebind_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(rebind_socket.addr),
        .remote = runtime.local_address,
    };
    const before_rebind = runtime.snapshot();
    try driveRuntimeRetryRequest(&rebind_socket, client, &client_h3, rebind_path, &h3_started, "runtime-retry-rebind-request", &saw_retry);
    try testing.expectEqual(@as(usize, 3), handler_state.requests.load(.monotonic));
    const snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 1), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 1), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 0), snapshot.invalid_tokens);
    try testing.expect(snapshot.tracked_connections > 0);
    try testing.expect(snapshot.path_validations_succeeded > before_rebind.path_validations_succeeded);
    try testing.expect(snapshot.nat_rebindings > before_rebind.nat_rebindings);
}

test "udp smoke: HTTP/3 runtime drain lets admitted work finish and rejects new work" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = http3_runtime.Logger.init(.err, "udp-runtime-drain-lifecycle-test");
    var handler_state = RuntimeHandlerState{};
    var runtime = try http3_runtime.Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .request_handler = runtimeSmokeHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    runtime.start();

    var client_socket = try UdpSocket.open();
    defer client_socket.close();

    const client_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8 };
    const odcid = [_]u8{ 0xa3, 0xa4, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(client_socket.addr),
        .remote = runtime.local_address,
    };
    var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend = tls_backend.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xe1} ** 32 },
        client_provider_storage.init(0x442_c),
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );
    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .tls = client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = nowUs(),
        .initial_path = client_path,
    });
    defer client.deinit();
    var client_h3 = H3.init(allocator, .client);
    defer client_h3.deinit();

    var h3_started = false;
    var request_a: ?u64 = null;
    var request_a_done = false;
    var request_b: ?u64 = null;
    var request_b_sent = false;
    var request_b_rejected_by_goaway = false;
    var drain_started = false;
    var sent_new_initial = false;
    var new_initial_seen = false;
    var new_conn_socket = try UdpSocket.open();
    defer new_conn_socket.close();
    var tracked_at_new_initial: usize = 0;
    var datagrams_before_new_initial: usize = 0;

    const deadline = nowUs() + 10_000_000;
    var iterations: usize = 0;
    while (nowUs() < deadline and !new_initial_seen) : (iterations += 1) {
        try testing.expect(iterations < 5_000);
        const now = nowUs();

        var out: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&out, now)) |t| {
            try client_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }

        var next: u64 = now + 50_000;
        if (client.nextTimeoutUs()) |t| next = @min(next, t);
        const timeout_ms: i32 = @intCast(@min((next -| now) / 1_000 + 1, 50));
        var fds = [_]posix.pollfd{.{ .fd = client_socket.fd, .events = posix.POLL.IN, .revents = 0 }};
        _ = try posix.poll(&fds, timeout_ms);

        var in: [2048]u8 = undefined;
        while (try client_socket.recv(&in)) |datagram| {
            try client.ingestOnPath(datagram, client_path, test_challenge_entropy, nowUs());
        }
        client.onTimeout(nowUs());

        if (!h3_started and client.isEstablished()) {
            try client_h3.start(client);
            h3_started = true;
        }
        if (h3_started and request_a == null) {
            request_a = try client_h3.sendRequest(client, .{
                .authority = "tardigrade.test",
                .path = "/runtime-retry",
                .body = "runtime-drain-admitted",
            });
        }
        try client_h3.pump(client);

        if (!drain_started and handler_state.requests.load(.monotonic) == 1) {
            runtime.beginDrain(http3_runtime.Runtime.nowUsPublic() + 5_000_000);
            drain_started = true;
        }

        if (request_a) |id| {
            if (!request_a_done) {
                if (try client_h3.pollResponse(id)) |response| {
                    try testing.expectEqual(@as(u16, 200), response.status);
                    try testing.expectEqualStrings("runtime-retry-response", response.body);
                    request_a_done = true;
                    client_h3.releaseResponse(id);
                }
            }
        }

        if (drain_started and request_a_done and request_b == null and !request_b_rejected_by_goaway) {
            request_b = client_h3.sendRequest(client, .{
                .authority = "tardigrade.test",
                .path = "/runtime-retry",
                .body = "runtime-drain-rejected",
            }) catch |err| switch (err) {
                error.GoawayReceived => blk: {
                    request_b_rejected_by_goaway = true;
                    break :blk null;
                },
                else => return err,
            };
            request_b_sent = request_b != null;
            while (client.pollTransmitOnPath(&out, nowUs())) |t| {
                try client_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
            }
        }

        const snapshot = runtime.snapshot();
        const request_b_rejected = request_b_sent or request_b_rejected_by_goaway;
        const drain_rejected_request = snapshot.h3_drain_request_rejections >= 1 or request_b_rejected_by_goaway;
        if (request_b_rejected and drain_rejected_request and !sent_new_initial) {
            tracked_at_new_initial = snapshot.tracked_connections;
            datagrams_before_new_initial = snapshot.datagrams_seen;
            var initial_buf: [128]u8 = undefined;
            const new_initial = try writeSyntheticInitial(
                quic.packet.quic_v1,
                &[_]u8{ 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8 },
                &[_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 },
                "",
                &initial_buf,
            );
            try new_conn_socket.sendTo(sockaddrInFromAddress(runtime.local_address), new_initial);
            sent_new_initial = true;
        }
        if (sent_new_initial) {
            const after_new = runtime.snapshot();
            if (after_new.datagrams_seen > datagrams_before_new_initial) {
                try testing.expectEqual(tracked_at_new_initial, after_new.tracked_connections);
                new_initial_seen = true;
            }
        }
    }

    if (sent_new_initial and !new_initial_seen) {
        const after_new = try waitRuntimeDatagrams(&runtime, datagrams_before_new_initial + 1);
        try testing.expectEqual(tracked_at_new_initial, after_new.tracked_connections);
        new_initial_seen = true;
    }

    try testing.expect(drain_started);
    try testing.expect(request_a_done);
    try testing.expect(request_b_sent or request_b_rejected_by_goaway);
    // #546: split what used to be a single `new_initial_seen` assertion into
    // two, so a future failure here tells apart the two very different
    // causes: `sent_new_initial == false` means the drain rejection (via
    // either the client-side GoawayReceived race or the server-side
    // `h3_drain_request_rejections` counter — see the loop above) was never
    // observed within the deadline, while `sent_new_initial == true` but
    // `new_initial_seen == false` means the rejection *was* observed and the
    // synthetic unknown-DCID Initial was sent, but the runtime never
    // ingested it.
    try testing.expect(sent_new_initial);
    try testing.expect(new_initial_seen);
    try testing.expectEqual(@as(usize, 1), handler_state.requests.load(.monotonic));
    const drained_snapshot = runtime.snapshot();
    try testing.expect(drained_snapshot.h3_goaway_sent >= 1);
    try testing.expect(drained_snapshot.h3_drain_request_rejections >= 1 or request_b_rejected_by_goaway);

    client.close(0, "runtime-drain-done", nowUs());
    var close_out: [2048]u8 = undefined;
    while (client.pollTransmitOnPath(&close_out, nowUs())) |t| {
        try client_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
    }
    const final_snapshot = try waitRuntimeSnapshot(&runtime, hasNoTrackedConnections);
    try testing.expectEqual(@as(usize, 0), final_snapshot.tracked_connections);
    try testing.expectEqual(@as(usize, 0), final_snapshot.active_cid_routes);
    try testing.expect(runtime.isDrained());
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

    var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var server_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend = tls_backend.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xa9} ** 32 },
        client_provider_storage.init(0x442_c),
        .{ .pinned_certificate = leaf_der },
    );
    var server_backend = tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0x77} ** 32 },
        server_provider_storage.init(0x442_5),
        appliance.provider(),
    );

    const client_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(client_socket.addr),
        .remote = addressFromSockaddrIn(server_socket.addr),
    };
    const server_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(server_socket.addr),
        .remote = addressFromSockaddrIn(client_socket.addr),
    };
    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .tls = client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = nowUs(),
        .initial_path = client_path,
    });
    defer client.deinit();
    const server = try Connection.init(allocator, .{
        .role = .server,
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = server_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = nowUs(),
        .initial_path = server_path,
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
        while (client.pollTransmitOnPath(&out, now)) |t| {
            try client_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
        while (server.pollTransmitOnPath(&out, now)) |t| {
            try server_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
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
            try client.ingestOnPath(datagram, client_path, test_challenge_entropy, nowUs());
        }
        while (try server_socket.recv(&in)) |datagram| {
            try server.ingestOnPath(datagram, server_path, test_challenge_entropy, nowUs());
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

// ---------------------------------------------------------------------------
// #763: downstream client-certificate authentication over real UDP + the real
// HTTP/3 runtime. The native client answers the server's CertificateRequest
// with fixture identities from `tests/fixtures/tls/h3mtls` (regenerate with
// its `gen.sh`); trust is the same `ClientTrustStore` the TCP listener uses.
// ---------------------------------------------------------------------------

const mtls_ca_path = "tests/fixtures/tls/h3mtls/ca.crt";

const MtlsFixture = struct {
    cert_der: []const u8,
    key_der: []const u8,
};

const mtls_valid = MtlsFixture{
    .cert_der = @embedFile("fixtures/tls/h3mtls/client.der"),
    .key_der = @embedFile("fixtures/tls/h3mtls/client.key.der"),
};
const mtls_expired = MtlsFixture{
    .cert_der = @embedFile("fixtures/tls/h3mtls/client_expired.der"),
    .key_der = @embedFile("fixtures/tls/h3mtls/client_expired.key.der"),
};
const mtls_not_yet_valid = MtlsFixture{
    .cert_der = @embedFile("fixtures/tls/h3mtls/client_not_yet_valid.der"),
    .key_der = @embedFile("fixtures/tls/h3mtls/client_not_yet_valid.key.der"),
};
const mtls_wrong_eku = MtlsFixture{
    .cert_der = @embedFile("fixtures/tls/h3mtls/client_wrong_eku.der"),
    .key_der = @embedFile("fixtures/tls/h3mtls/client_wrong_eku.key.der"),
};
const mtls_wrong_ca = MtlsFixture{
    .cert_der = @embedFile("fixtures/tls/h3mtls/client_wrong_ca.der"),
    .key_der = @embedFile("fixtures/tls/h3mtls/client_wrong_ca.key.der"),
};

const MtlsHandlerState = struct {
    requests: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    mutex: std.atomic.Mutex = .unlocked,
    cert_present: bool = false,
    fingerprint: [64]u8 = undefined,
    subject: [128]u8 = undefined,
    subject_len: usize = 0,
    san_email: [64]u8 = undefined,
    san_email_len: usize = 0,
    /// The request carried a client-supplied `x-tardigrade-client-cert-*`
    /// header (the spoof attempt); recorded to prove it never became identity.
    saw_spoof_header: bool = false,

    fn lock(self: *MtlsHandlerState) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }
};

fn mtlsHandler(
    _: std.mem.Allocator,
    request: *const http3_runtime.StreamRequest,
    response: *http3_runtime.Response,
    user_data: ?*anyopaque,
) anyerror!void {
    const state: *MtlsHandlerState = @ptrCast(@alignCast(user_data.?));
    state.lock();
    defer state.mutex.unlock();
    state.saw_spoof_header = request.headers.get("x-tardigrade-client-cert-verified") != null;
    if (request.headers.client_cert) |cert| {
        state.cert_present = true;
        @memcpy(&state.fingerprint, cert.fingerprint_sha256[0..64]);
        state.subject_len = cert.subject.len;
        @memcpy(state.subject[0..cert.subject.len], cert.subject);
        state.san_email_len = cert.san_email.len;
        @memcpy(state.san_email[0..cert.san_email.len], cert.san_email);
    } else {
        state.cert_present = false;
    }
    _ = state.requests.fetchAdd(1, .monotonic);
    _ = response.setStatus(.ok).setBody("mtls-ok").setContentType("text/plain");
}

var mtls_client_runs = std.atomic.Value(usize).init(0);

const MtlsOutcome = enum { served, refused, misdirected };

/// How the client corrupts its (otherwise valid) certificate DER before
/// sending it; the private key stays the real one so only the *verifier* can
/// be what refuses it.
const MtlsMutation = enum {
    none,
    /// Bytes after the outer SEQUENCE: legal to a lax parser, malformed DER.
    trailing_garbage,
    /// Flip a bit in the issuer signature: structurally fine, path invalid.
    tampered_signature,
    /// Not a certificate at all (declared length overruns the buffer).
    truncated,
};

/// Drive one native H3 client against `runtime` until it either completes a
/// request or its connection is torn down. `fixture == null` models a client
/// that answers CertificateRequest with an empty Certificate.
fn runMtlsClient(
    allocator: std.mem.Allocator,
    runtime: *http3_runtime.Runtime,
    fixture: ?MtlsFixture,
    mutation: MtlsMutation,
    spoof_header: bool,
) !MtlsOutcome {
    return runMtlsClientSni(allocator, runtime, fixture, mutation, spoof_header, null, "tardigrade.test");
}

/// `sni` is the TLS server_name the ClientHello carries; `authority` is the
/// request's `:authority`. They are deliberately independent so tests can
/// prove policy follows the SNI, never the authority.
fn runMtlsClientSni(
    allocator: std.mem.Allocator,
    runtime: *http3_runtime.Runtime,
    fixture: ?MtlsFixture,
    mutation: MtlsMutation,
    spoof_header: bool,
    sni: ?[]const u8,
    authority: []const u8,
) !MtlsOutcome {
    var client_socket = try UdpSocket.open();
    defer client_socket.close();

    // Distinct CIDs per client so sequential connections to one runtime never
    // collide with a lingering (e.g. refused) earlier connection.
    const run_id: u8 = @truncate(mtls_client_runs.fetchAdd(1, .monotonic));
    const client_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, run_id };
    const odcid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, run_id };
    const client_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(client_socket.addr),
        .remote = runtime.local_address,
    };

    var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend = tls_backend.Tls13Backend.initClientWithOptions(
        .{ .hello_random = [_]u8{0xe1} ** 32 },
        client_provider_storage.init(0x442_c),
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
        .{ .server_name = sni },
    );
    var client_identity_provider: ?tls_core.credentials.FixedCredentialProvider = null;
    defer if (client_identity_provider) |*p| p.deinit();
    var mutated_chain: ?[]u8 = null;
    defer if (mutated_chain) |bytes| allocator.free(bytes);
    if (fixture) |f| {
        client_identity_provider = tls_core.credentials.FixedCredentialProvider.init(
            try tls_core.credentials.Identity.initPkcs8(f.cert_der, f.key_der),
            tls_core.credentials.testdata.ignoredEntropy(),
        );
        if (mutation != .none) {
            const mutated = try allocator.alloc(u8, f.cert_der.len + 4);
            @memcpy(mutated[0..f.cert_der.len], f.cert_der);
            var len = f.cert_der.len;
            switch (mutation) {
                .none => unreachable,
                .trailing_garbage => {
                    @memcpy(mutated[len..][0..2], "\x00\x01");
                    len += 2;
                },
                .tampered_signature => mutated[len - 3] ^= 0x01,
                .truncated => len -= 7,
            }
            mutated_chain = mutated;
            client_identity_provider.?.chain_entry[0] = mutated[0..len];
        }
        client_backend.engine.setLocalCredentialProvider(client_identity_provider.?.provider());
    }

    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .tls = client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = nowUs(),
        .initial_path = client_path,
    });
    defer client.deinit();
    var client_h3 = H3.init(allocator, .client);
    defer client_h3.deinit();

    var h3_started = false;
    var request_id: ?u64 = null;
    const spoof = [_]http3.qpack.HeaderField{.{ .name = "x-tardigrade-client-cert-verified", .value = "1" }};
    const deadline = nowUs() + 8_000_000;
    var iterations: usize = 0;
    while (nowUs() < deadline) : (iterations += 1) {
        try testing.expect(iterations < 5_000);
        const now = nowUs();

        var out: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&out, now)) |t| {
            try client_socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }

        var next: u64 = now + 50_000;
        if (client.nextTimeoutUs()) |t| next = @min(next, t);
        const timeout_ms: i32 = @intCast(@min((next -| now) / 1_000 + 1, 50));
        var fds = [_]posix.pollfd{.{ .fd = client_socket.fd, .events = posix.POLL.IN, .revents = 0 }};
        _ = try posix.poll(&fds, timeout_ms);

        var in: [2048]u8 = undefined;
        while (try client_socket.recv(&in)) |datagram| {
            client.ingestOnPath(datagram, client_path, test_challenge_entropy, nowUs()) catch return .refused;
        }
        client.onTimeout(nowUs());

        switch (client.state()) {
            .closing, .draining, .closed => return .refused,
            else => {},
        }

        if (!h3_started and client.isEstablished()) {
            try client_h3.start(client);
            h3_started = true;
        }
        if (h3_started) {
            if (request_id == null) {
                request_id = try client_h3.sendRequest(client, .{
                    .authority = authority,
                    .path = "/mtls",
                    .headers = if (spoof_header) &spoof else &.{},
                });
            }
            try client_h3.pump(client);
            if (request_id) |id| {
                if (try client_h3.pollResponse(id)) |response| {
                    if (response.status == 421) {
                        client_h3.releaseResponse(id);
                        return .misdirected;
                    }
                    try testing.expectEqual(@as(u16, 200), response.status);
                    try testing.expectEqualStrings("mtls-ok", response.body);
                    client_h3.releaseResponse(id);
                    return .served;
                }
            }
        }
    }
    return .refused;
}

const MtlsServer = struct {
    fixed: tls_core.credentials.FixedCredentialProvider,
    logger: http3_runtime.Logger,
    handler_state: MtlsHandlerState = .{},
    trust: tls_core.client_trust.ClientTrustStore,
    runtime: http3_runtime.Runtime,

    fn start(self: *MtlsServer, allocator: std.mem.Allocator, mode: tls_core.tls13_backend.ClientAuthMode) !void {
        self.fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
        self.logger = http3_runtime.Logger.init(.err, "udp-h3-mtls-test");
        self.handler_state = .{};
        self.trust = tls_core.client_trust.ClientTrustStore.init(allocator);
        var prepared = try self.trust.prepare(mtls_ca_path, 3);
        self.trust.commit(&prepared);
        self.runtime = try http3_runtime.Runtime.init(allocator, &self.logger, .{
            .listen_host = "127.0.0.1",
            .quic_port = 0,
            .credential_provider = self.fixed.provider(),
            .client_auth = mode,
            .client_trust = &self.trust,
            .request_handler = mtlsHandler,
            .request_handler_ctx = &self.handler_state,
        });
        self.runtime.start();
    }

    fn stop(self: *MtlsServer) void {
        self.runtime.deinit();
        self.trust.deinit();
        self.fixed.deinit();
    }
};

fn expectMtlsRefused(mode: tls_core.tls13_backend.ClientAuthMode, fixture: ?MtlsFixture, mutation: MtlsMutation) !void {
    const allocator = testing.allocator;
    var server: MtlsServer = undefined;
    try server.start(allocator, mode);
    defer server.stop();

    const outcome = try runMtlsClient(allocator, &server.runtime, fixture, mutation, false);
    try testing.expectEqual(MtlsOutcome.refused, outcome);
    // The application never saw a request, and the server never reported a
    // completed handshake for the refused peer.
    try testing.expectEqual(@as(usize, 0), server.handler_state.requests.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), server.runtime.snapshot().handshakes_completed);
}

test "udp h3 mTLS: required mode serves a valid client certificate and captures verified identity (#763)" {
    const allocator = testing.allocator;
    var server: MtlsServer = undefined;
    try server.start(allocator, .required);
    defer server.stop();

    const outcome = try runMtlsClient(allocator, &server.runtime, mtls_valid, .none, true);
    try testing.expectEqual(MtlsOutcome.served, outcome);
    try testing.expectEqual(@as(usize, 1), server.handler_state.requests.load(.monotonic));

    server.handler_state.lock();
    defer server.handler_state.mutex.unlock();
    try testing.expect(server.handler_state.cert_present);
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(mtls_valid.cert_der, &digest, .{});
    var expected_fp: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&expected_fp, "{x}", .{&digest});
    try testing.expectEqualSlices(u8, &expected_fp, &server.handler_state.fingerprint);
    try testing.expectEqualStrings("CN=h3-client.example", server.handler_state.subject[0..server.handler_state.subject_len]);
    try testing.expectEqualStrings("h3@example.com", server.handler_state.san_email[0..server.handler_state.san_email_len]);
    // The spoofed header travelled as an ordinary request header; identity
    // came only from the handshake.
    try testing.expect(server.handler_state.saw_spoof_header);
}

test "udp h3 mTLS: required mode refuses a client that presents no certificate (#763)" {
    try expectMtlsRefused(.required, null, .none);
}

test "udp h3 mTLS: optional mode serves an anonymous client without any identity, spoofed header notwithstanding (#763)" {
    const allocator = testing.allocator;
    var server: MtlsServer = undefined;
    try server.start(allocator, .optional);
    defer server.stop();

    const outcome = try runMtlsClient(allocator, &server.runtime, null, .none, true);
    try testing.expectEqual(MtlsOutcome.served, outcome);
    server.handler_state.lock();
    defer server.handler_state.mutex.unlock();
    try testing.expect(!server.handler_state.cert_present);
    try testing.expect(server.handler_state.saw_spoof_header);
}

test "udp h3 mTLS: optional mode serves a valid presented certificate (#763)" {
    const allocator = testing.allocator;
    var server: MtlsServer = undefined;
    try server.start(allocator, .optional);
    defer server.stop();

    try testing.expectEqual(MtlsOutcome.served, try runMtlsClient(allocator, &server.runtime, mtls_valid, .none, false));
    server.handler_state.lock();
    defer server.handler_state.mutex.unlock();
    try testing.expect(server.handler_state.cert_present);
}

test "udp h3 mTLS: optional mode still rejects a presented certificate that does not verify (#763)" {
    try expectMtlsRefused(.optional, mtls_wrong_ca, .none);
}

test "udp h3 mTLS: malformed client certificates are refused (#763)" {
    try expectMtlsRefused(.required, mtls_valid, .trailing_garbage);
    try expectMtlsRefused(.required, mtls_valid, .truncated);
}

test "udp h3 mTLS: a client certificate with a tampered issuer signature is refused (#763)" {
    try expectMtlsRefused(.required, mtls_valid, .tampered_signature);
}

test "udp h3 mTLS: expired client certificate is refused (#763)" {
    try expectMtlsRefused(.required, mtls_expired, .none);
}

test "udp h3 mTLS: not-yet-valid client certificate is refused (#763)" {
    try expectMtlsRefused(.required, mtls_not_yet_valid, .none);
}

test "udp h3 mTLS: client certificate from an untrusted CA is refused (#763)" {
    try expectMtlsRefused(.required, mtls_wrong_ca, .none);
}

test "udp h3 mTLS: serverAuth-only client certificate (wrong EKU) is refused (#763)" {
    try expectMtlsRefused(.required, mtls_wrong_eku, .none);
}

test "udp h3 mTLS: a runtime asked for client auth without a trust store refuses every connection (#763)" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = http3_runtime.Logger.init(.err, "udp-h3-mtls-notrust-test");
    var handler_state = MtlsHandlerState{};
    var runtime = try http3_runtime.Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .client_auth = .required,
        .client_trust = null,
        .request_handler = mtlsHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    runtime.start();

    try testing.expectEqual(MtlsOutcome.refused, try runMtlsClient(allocator, &runtime, mtls_valid, .none, false));
    try testing.expectEqual(@as(usize, 0), handler_state.requests.load(.monotonic));
}

// ---------------------------------------------------------------------------
// Per-SNI client-auth policy (#763): two virtual hosts, two unrelated CAs.
// ---------------------------------------------------------------------------

const mtls_rogue_ca_path = "tests/fixtures/tls/h3mtls/rogue_ca.crt";
const host_a = "a.example.test";
const host_b = "b.example.test";
const host_open = "open.example.test";

const SniPolicyServer = struct {
    fixed: tls_core.credentials.FixedCredentialProvider,
    logger: http3_runtime.Logger,
    handler_state: MtlsHandlerState = .{},
    policies: tls_core.client_trust.PolicySet,
    runtime: http3_runtime.Runtime,

    fn specs(fallback_mode: tls_core.tls13_backend.ClientAuthMode, a_ca: []const u8) struct { fallback: tls_core.client_trust.PolicySpec, list: [3]tls_core.client_trust.PolicySpec } {
        return .{
            .fallback = .{ .mode = fallback_mode, .ca_path = mtls_ca_path, .max_path_length = 3 },
            .list = .{
                .{ .names = &.{host_a}, .mode = .required, .ca_path = a_ca, .max_path_length = 3 },
                .{ .names = &.{host_b}, .mode = .required, .ca_path = mtls_rogue_ca_path, .max_path_length = 3 },
                .{ .names = &.{host_open}, .mode = .disabled },
            },
        };
    }

    fn start(self: *SniPolicyServer, allocator: std.mem.Allocator, fallback_mode: tls_core.tls13_backend.ClientAuthMode) !void {
        self.fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
        self.logger = http3_runtime.Logger.init(.err, "udp-h3-sni-mtls-test");
        self.handler_state = .{};
        self.policies = tls_core.client_trust.PolicySet.init(allocator);
        const sp = specs(fallback_mode, mtls_ca_path);
        var prepared = try self.policies.prepare(sp.fallback, &sp.list, tls_core.client_trust.exactNameMatcher);
        self.policies.commit(&prepared);
        self.runtime = try http3_runtime.Runtime.init(allocator, &self.logger, .{
            .listen_host = "127.0.0.1",
            .quic_port = 0,
            .credential_provider = self.fixed.provider(),
            .client_policies = &self.policies,
            .request_handler = mtlsHandler,
            .request_handler_ctx = &self.handler_state,
        });
        self.runtime.start();
    }

    fn stop(self: *SniPolicyServer) void {
        self.runtime.deinit();
        self.policies.deinit();
        self.fixed.deinit();
    }

    fn requests(self: *SniPolicyServer) usize {
        return self.handler_state.requests.load(.monotonic);
    }
};

test "udp h3 per-SNI mTLS: a certificate trusted for host A authenticates to A and is refused by B, and vice versa (#763)" {
    const allocator = testing.allocator;
    var server: SniPolicyServer = undefined;
    try server.start(allocator, .required);
    defer server.stop();

    // CA-A client: served on A, refused on B.
    try testing.expectEqual(MtlsOutcome.served, try runMtlsClientSni(allocator, &server.runtime, mtls_valid, .none, false, host_a, host_a));
    try testing.expectEqual(@as(usize, 1), server.requests());
    try testing.expectEqual(MtlsOutcome.refused, try runMtlsClientSni(allocator, &server.runtime, mtls_valid, .none, false, host_b, host_b));
    try testing.expectEqual(@as(usize, 1), server.requests());

    // CA-B client: served on B, refused on A.
    try testing.expectEqual(MtlsOutcome.served, try runMtlsClientSni(allocator, &server.runtime, mtls_wrong_ca, .none, false, host_b, host_b));
    try testing.expectEqual(@as(usize, 2), server.requests());
    try testing.expectEqual(MtlsOutcome.refused, try runMtlsClientSni(allocator, &server.runtime, mtls_wrong_ca, .none, false, host_a, host_a));
    try testing.expectEqual(@as(usize, 2), server.requests());
}

test "udp h3 per-SNI mTLS: a host with mTLS disabled serves anonymous clients; required hosts refuse them (#763)" {
    const allocator = testing.allocator;
    var server: SniPolicyServer = undefined;
    try server.start(allocator, .required);
    defer server.stop();

    try testing.expectEqual(MtlsOutcome.served, try runMtlsClientSni(allocator, &server.runtime, null, .none, false, host_open, host_open));
    {
        server.handler_state.lock();
        defer server.handler_state.mutex.unlock();
        try testing.expect(!server.handler_state.cert_present);
    }
    try testing.expectEqual(MtlsOutcome.refused, try runMtlsClientSni(allocator, &server.runtime, null, .none, false, host_a, host_a));
    try testing.expectEqual(@as(usize, 1), server.requests());
}

test "udp h3 per-SNI mTLS: the policy follows SNI, never :authority — a mismatched authority is answered 421 (#763)" {
    const allocator = testing.allocator;
    var server: SniPolicyServer = undefined;
    try server.start(allocator, .required);
    defer server.stop();

    // Handshake under the open host's (disabled) policy, then ask for host A
    // (required): the stronger policy must not be bypassed.
    try testing.expectEqual(MtlsOutcome.misdirected, try runMtlsClientSni(allocator, &server.runtime, null, .none, false, host_open, host_a));
    // A CA-A cert admitted on A cannot be replayed at B's authority either.
    try testing.expectEqual(MtlsOutcome.misdirected, try runMtlsClientSni(allocator, &server.runtime, mtls_valid, .none, false, host_a, host_b));
    try testing.expectEqual(@as(usize, 0), server.requests());
}

test "udp h3 per-SNI mTLS: absent or unknown SNI falls back to the default policy (#763)" {
    const allocator = testing.allocator;
    var required: SniPolicyServer = undefined;
    try required.start(allocator, .required);
    defer required.stop();
    // Fallback = required/CA-A: anonymous refused, CA-A served, CA-B refused.
    try testing.expectEqual(MtlsOutcome.refused, try runMtlsClientSni(allocator, &required.runtime, null, .none, false, null, "tardigrade.test"));
    try testing.expectEqual(MtlsOutcome.refused, try runMtlsClientSni(allocator, &required.runtime, null, .none, false, "unknown.example.test", "unknown.example.test"));
    try testing.expectEqual(MtlsOutcome.served, try runMtlsClientSni(allocator, &required.runtime, mtls_valid, .none, false, null, "tardigrade.test"));
    try testing.expectEqual(MtlsOutcome.refused, try runMtlsClientSni(allocator, &required.runtime, mtls_wrong_ca, .none, false, null, "tardigrade.test"));
}

test "udp h3 per-SNI mTLS: a reload swaps trust atomically for new handshakes (#763)" {
    const allocator = testing.allocator;
    var server: SniPolicyServer = undefined;
    try server.start(allocator, .required);
    defer server.stop();

    try testing.expectEqual(MtlsOutcome.served, try runMtlsClientSni(allocator, &server.runtime, mtls_valid, .none, false, host_a, host_a));
    // Rotate host A's trust to the rogue CA: the old client is now refused,
    // the rogue-CA client admitted, with no restart.
    const sp = SniPolicyServer.specs(.required, mtls_rogue_ca_path);
    var prepared = try server.policies.prepare(sp.fallback, &sp.list, tls_core.client_trust.exactNameMatcher);
    server.policies.commit(&prepared);
    try testing.expectEqual(MtlsOutcome.refused, try runMtlsClientSni(allocator, &server.runtime, mtls_valid, .none, false, host_a, host_a));
    try testing.expectEqual(MtlsOutcome.served, try runMtlsClientSni(allocator, &server.runtime, mtls_wrong_ca, .none, false, host_a, host_a));
}
