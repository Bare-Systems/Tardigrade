//! Native QUIC/H3 interop tool (#247 phase 5).
//!
//! A small out-of-process client and server built on the native connection
//! driver and H3 glue, used to exercise interoperability against external
//! implementations (ngtcp2/nghttp3 example clients/servers, quiche, aioquic).
//! External peers stay out of process; nothing foreign links into Tardigrade.
//!
//! Usage:
//!   h3_interop_tool server --port N --cert cert.der --key key.pkcs8.der \
//!       [--response-body STR] [--requests N] [--verbose]
//!   h3_interop_tool client --host A.B.C.D --port N --authority NAME \
//!       --path /p [--body STR] [--insecure | --pin cert.der] [--verbose]
//!
//! The client exits 0 once it has received a complete response (status and
//! body are printed to stdout). The server exits 0 after serving --requests
//! requests (default 1) and seeing the connection close or drain. --verbose
//! streams connection-driver events (packet, loss, PTO, key, state) to
//! stderr for debugging interop failures.

const std = @import("std");
const quic = @import("quic");
const http3 = @import("http3");

const connection = quic.connection;
const tls_backend = quic.tls_backend;
const Connection = connection.Connection;
const H3 = http3.conn.Conn(Connection);
const posix = std.posix;

fn nowUs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1_000;
}

var verbose = false;

/// Plain sequential write(2) to fd 1. `Io.File.writer` uses positional
/// writes, which scribble over interleaved stderr output when both streams
/// are redirected to the same file (as interop scripts do with `2>&1`).
fn writeStdout(bytes: []const u8) void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = std.c.write(1, bytes.ptr + written, bytes.len - written);
        if (n <= 0) return;
        written += @intCast(n);
    }
}

fn logEvent(_: ?*anyopaque, event: connection.Event) void {
    if (!verbose) return;
    var buf: [256]u8 = undefined;
    const line = switch (event) {
        .state => |s| std.fmt.bufPrint(&buf, "state -> {s}", .{@tagName(s)}),
        .packet_received => |p| std.fmt.bufPrint(&buf, "rx space={s} pn={d} size={d}", .{ @tagName(p.space), p.packet_number, p.size }),
        .packet_sent => |p| std.fmt.bufPrint(&buf, "tx space={s} pn={d} size={d} ack_eliciting={}", .{ @tagName(p.space), p.packet_number, p.size, p.ack_eliciting }),
        .packet_dropped => |p| std.fmt.bufPrint(&buf, "drop reason={s} size={d}", .{ @tagName(p.reason), p.size }),
        .keys_discarded => |s| std.fmt.bufPrint(&buf, "keys discarded space={s}", .{@tagName(s)}),
        .handshake_complete => std.fmt.bufPrint(&buf, "handshake complete", .{}),
        .handshake_confirmed => std.fmt.bufPrint(&buf, "handshake confirmed", .{}),
        .pto_fired => |p| std.fmt.bufPrint(&buf, "pto space={s} count={d}", .{ @tagName(p.space), p.count }),
        .packets_lost => |p| std.fmt.bufPrint(&buf, "loss space={s} bytes={d}", .{ @tagName(p.space), p.bytes }),
        .close_sent => |c| std.fmt.bufPrint(&buf, "close sent code={d}", .{c.error_code}),
        .close_received => |c| std.fmt.bufPrint(&buf, "close received code={d} app={}", .{ c.error_code, c.is_application }),
        .idle_timeout => std.fmt.bufPrint(&buf, "idle timeout", .{}),
    } catch return;
    std.debug.print("h3-interop: {s}\n", .{line});
}

const Args = struct {
    mode: enum { client, server },
    host: []const u8 = "127.0.0.1",
    port: u16 = 4433,
    authority: []const u8 = "tardigrade.test",
    path: []const u8 = "/",
    body: []const u8 = "",
    cert: []const u8 = "",
    key: []const u8 = "",
    pin: []const u8 = "",
    insecure: bool = false,
    response_body: []const u8 = "hello from tardigrade native h3\n",
    requests: usize = 1,
    timeout_ms: u64 = 15_000,
};

fn parseArgs(allocator: std.mem.Allocator, init_args: std.process.Args) !Args {
    var it = init_args.iterate();
    _ = it.next(); // argv[0]
    const mode_str = it.next() orelse return error.MissingMode;
    var args = Args{
        .mode = if (std.mem.eql(u8, mode_str, "server")) .server else if (std.mem.eql(u8, mode_str, "client")) .client else return error.UnknownMode,
    };
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            args.insecure = true;
        } else if (std.mem.eql(u8, arg, "--host")) {
            args.host = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--port")) {
            args.port = try std.fmt.parseInt(u16, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--authority")) {
            args.authority = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--path")) {
            args.path = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--body")) {
            args.body = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--cert")) {
            args.cert = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--key")) {
            args.key = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--pin")) {
            args.pin = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--response-body")) {
            args.response_body = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--requests")) {
            args.requests = try std.fmt.parseInt(usize, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            args.timeout_ms = try std.fmt.parseInt(u64, it.next() orelse return error.MissingValue, 10);
        } else {
            std.debug.print("h3-interop: unknown argument {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }
    return args;
}

const UdpSocket = struct {
    fd: std.c.fd_t,

    fn open(bind_port: u16) !UdpSocket {
        const fd = std.c.socket(
            posix.AF.INET,
            posix.SOCK.DGRAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK,
            posix.IPPROTO.UDP,
        );
        if (fd < 0) return error.SocketFailed;
        errdefer _ = std.c.close(fd);
        var bind_addr = std.c.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, bind_port),
            .addr = 0, // INADDR_ANY
        };
        if (std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(std.c.sockaddr.in)) != 0) return error.BindFailed;
        return .{ .fd = fd };
    }

    fn close(self: *UdpSocket) void {
        _ = std.c.close(self.fd);
    }

    fn sendTo(self: *UdpSocket, peer: std.c.sockaddr.in, bytes: []const u8) !void {
        const sent = std.c.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(&peer), @sizeOf(std.c.sockaddr.in));
        if (sent < 0 or @as(usize, @intCast(sent)) != bytes.len) return error.SendFailed;
    }

    fn recvFrom(self: *UdpSocket, buf: []u8, from: *std.c.sockaddr.in) !?[]u8 {
        var from_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        const n = std.c.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(from), &from_len);
        if (n < 0) {
            return switch (posix.errno(n)) {
                .AGAIN => null,
                .CONNREFUSED => null,
                else => error.RecvFailed,
            };
        }
        return buf[0..@intCast(n)];
    }

    fn waitReadable(self: *UdpSocket, timeout_ms: i32) !void {
        var fds = [_]posix.pollfd{
            .{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = try posix.poll(&fds, timeout_ms);
    }
};

fn parseIp4(host: []const u8, port: u16) !std.c.sockaddr.in {
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, host, '.');
    for (&octets) |*octet| {
        const part = it.next() orelse return error.InvalidAddress;
        octet.* = try std.fmt.parseInt(u8, part, 10);
    }
    if (it.next() != null) return error.InvalidAddress;
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(octets),
    };
}

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8, max: usize) ![]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max));
}

fn randomBytes(buffer: []u8) void {
    std.Io.Threaded.global_single_threaded.io().random(buffer);
}

fn randomEntropy() tls_backend.Entropy {
    var entropy: tls_backend.Entropy = undefined;
    randomBytes(&entropy.hello_random);
    randomBytes(&entropy.key_share_seed);
    return entropy;
}

pub fn main(init: std.process.Init.Minimal) !void {
    // Short-lived tool: arena everything, reclaimed at exit.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = parseArgs(allocator, init.args) catch |err| {
        std.debug.print(
            "h3-interop: bad arguments ({s})\n" ++
                "usage: h3_interop_tool server --port N --cert cert.der --key key.pkcs8.der [--requests N]\n" ++
                "       h3_interop_tool client --host IP --port N --authority NAME --path /p [--insecure|--pin cert.der]\n",
            .{@errorName(err)},
        );
        std.process.exit(2);
    };

    switch (args.mode) {
        .client => try runClient(allocator, args),
        .server => try runServer(allocator, args),
    }
}

fn runClient(allocator: std.mem.Allocator, args: Args) !void {
    const peer_addr = try parseIp4(args.host, args.port);
    var socket = try UdpSocket.open(0);
    defer socket.close();

    var local_cid: [8]u8 = undefined;
    randomBytes(&local_cid);
    var odcid: [8]u8 = undefined;
    randomBytes(&odcid);

    const trust: tls_backend.Trust = if (args.pin.len > 0) blk: {
        const pinned = try readFileAlloc(allocator, args.pin, 64 * 1024);
        break :blk .{ .pinned_certificate = pinned };
    } else .insecure_no_verification;
    if (args.pin.len == 0 and !args.insecure) {
        std.debug.print("h3-interop: client needs --pin cert.der or --insecure\n", .{});
        std.process.exit(2);
    }

    var backend = tls_backend.Tls13Backend.initClient(randomEntropy(), trust);
    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &local_cid,
        .original_dcid = &odcid,
        .tls = backend.backend(),
        .now_us = nowUs(),
        .events = .{ .emitFn = logEvent },
        .allow_unverified_certificate = args.insecure,
    });
    defer client.deinit();

    var h3 = H3.init(allocator, .client);
    defer h3.deinit();

    var request_id: ?u64 = null;
    var from: std.c.sockaddr.in = undefined;
    const deadline = nowUs() + args.timeout_ms * 1_000;
    var success = false;

    while (nowUs() < deadline) {
        const now = nowUs();
        var out: [2048]u8 = undefined;
        while (client.pollTransmit(&out, now)) |datagram| {
            try socket.sendTo(peer_addr, datagram);
        }
        var next: u64 = now + 50_000;
        if (client.nextTimeoutUs()) |t| next = @min(next, t);
        try socket.waitReadable(@intCast(@min((next -| now) / 1_000 + 1, 50)));
        var in: [2048]u8 = undefined;
        while (try socket.recvFrom(&in, &from)) |datagram| {
            try client.ingest(datagram, nowUs());
        }
        client.onTimeout(nowUs());

        if (client.state() == .closed or client.state() == .draining) break;
        if (client.isEstablished()) {
            if (request_id == null) {
                std.debug.print("h3-interop: established, alpn_h3={}\n", .{client.negotiatedH3()});
                try h3.start(client);
                request_id = try h3.sendRequest(client, .{
                    .authority = args.authority,
                    .path = args.path,
                    .body = args.body,
                });
            }
            try h3.pump(client);
            if (request_id) |id| {
                if (try h3.pollResponse(id)) |response| {
                    var line: [8192]u8 = undefined;
                    writeStdout(std.fmt.bufPrint(&line, "status: {d}\n", .{response.status}) catch "");
                    for (response.headers) |header| {
                        writeStdout(std.fmt.bufPrint(&line, "{s}: {s}\n", .{ header.name, header.value }) catch "");
                    }
                    writeStdout("\n");
                    writeStdout(response.body);
                    h3.releaseResponse(id);
                    success = true;
                    break;
                }
            }
        }
    }

    if (!success) {
        std.debug.print("h3-interop: client failed: state={s} handshake_error={any}\n", .{
            @tagName(client.state()),
            client.handshakeFailure(),
        });
        std.process.exit(1);
    }
    // Orderly close.
    client.close(0, "done", nowUs());
    var out: [2048]u8 = undefined;
    while (client.pollTransmit(&out, nowUs())) |datagram| {
        try socket.sendTo(peer_addr, datagram);
    }
    std.debug.print("h3-interop: client ok\n", .{});
}

fn runServer(allocator: std.mem.Allocator, args: Args) !void {
    if (args.cert.len == 0 or args.key.len == 0) {
        std.debug.print("h3-interop: server needs --cert and --key (DER)\n", .{});
        std.process.exit(2);
    }
    const cert_der = try readFileAlloc(allocator, args.cert, 64 * 1024);
    defer allocator.free(cert_der);
    const key_der = try readFileAlloc(allocator, args.key, 4 * 1024);
    defer allocator.free(key_der);
    const identity = try tls_backend.Identity.initPkcs8(cert_der, key_der);

    var socket = try UdpSocket.open(args.port);
    defer socket.close();
    std.debug.print("h3-interop: server listening on udp port {d}\n", .{args.port});

    var served: usize = 0;
    const deadline = nowUs() + args.timeout_ms * 1_000;

    // One connection at a time: enough for focused interop runs, and each
    // connection exercises the full accept path.
    accept_loop: while (nowUs() < deadline) {
        // Wait for the first Initial of a new connection.
        var first: [2048]u8 = undefined;
        var peer: std.c.sockaddr.in = undefined;
        try socket.waitReadable(100);
        const first_datagram = (try socket.recvFrom(&first, &peer)) orelse continue;
        const parsed = quic.packet.parsePacket(first_datagram, 8) catch continue;
        if (parsed.kind != .initial) continue;
        std.debug.print("h3-interop: initial from client, dcid_len={d} scid_len={d}\n", .{
            parsed.dcid.len, parsed.scid.len,
        });

        var backend = tls_backend.Tls13Backend.initServer(randomEntropy(), identity);
        const server = try Connection.init(allocator, .{
            .role = .server,
            .local_cid = parsed.dcid,
            .original_dcid = parsed.dcid,
            .peer_cid = parsed.scid,
            .tls = backend.backend(),
            .now_us = nowUs(),
            .events = .{ .emitFn = logEvent },
        });
        defer server.deinit();
        var h3 = H3.init(allocator, .server);
        defer h3.deinit();
        try server.ingest(first_datagram, nowUs());

        var h3_started = false;
        while (nowUs() < deadline) {
            const now = nowUs();
            var out: [2048]u8 = undefined;
            while (server.pollTransmit(&out, now)) |datagram| {
                try socket.sendTo(peer, datagram);
            }
            var next: u64 = now + 50_000;
            if (server.nextTimeoutUs()) |t| next = @min(next, t);
            try socket.waitReadable(@intCast(@min((next -| now) / 1_000 + 1, 50)));
            var in: [2048]u8 = undefined;
            while (try socket.recvFrom(&in, &peer)) |datagram| {
                // Only this connection's DCID is routable; a new Initial for a
                // different connection would start a new accept cycle.
                try server.ingest(datagram, nowUs());
            }
            server.onTimeout(nowUs());

            switch (server.state()) {
                .closed, .draining, .closing => {
                    std.debug.print("h3-interop: connection ended state={s} served={d}\n", .{
                        @tagName(server.state()),
                        served,
                    });
                    if (served >= args.requests) break :accept_loop;
                    continue :accept_loop;
                },
                else => {},
            }
            if (server.isEstablished()) {
                if (!h3_started) {
                    std.debug.print("h3-interop: established, alpn_h3={}\n", .{server.negotiatedH3()});
                    try h3.start(server);
                    h3_started = true;
                }
                try h3.pump(server);
                if (try h3.pollRequest()) |incoming| {
                    const body_len: usize = switch (incoming.exchange.body) {
                        .buffered => |body| body.len,
                        else => 0,
                    };
                    std.debug.print("h3-interop: request {s} {s} authority={s} body_len={d}\n", .{
                        incoming.exchange.request.method,
                        incoming.exchange.request.path,
                        incoming.exchange.request.authority,
                        body_len,
                    });
                    try h3.sendResponse(server, incoming.stream_id, 200, &.{
                        .{ .name = "server", .value = "tardigrade-native-h3" },
                    }, args.response_body);
                    served += 1;
                    std.debug.print("h3-interop: served {d}/{d}\n", .{ served, args.requests });
                }
            }
        }
    }

    if (served < args.requests) {
        std.debug.print("h3-interop: server timed out with served={d}/{d}\n", .{ served, args.requests });
        std.process.exit(1);
    }
    std.debug.print("h3-interop: server ok, served={d}\n", .{served});
}
