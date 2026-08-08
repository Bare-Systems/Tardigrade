//! Native QUIC/H3 interop tool (#247 phase 5).
//!
//! A small out-of-process client and server built on the native connection
//! driver and H3 glue, used to exercise interoperability against external
//! implementations (ngtcp2/nghttp3 example clients/servers, quiche, aioquic).
//! External peers stay out of process; nothing foreign links into Tardigrade.
//!
//! Usage:
//!   h3_interop_tool server --port N --cert cert.der --key key.pkcs8.der \
//!       [--response-body STR] [--requests N] [--expect-hrr] [--verbose]
//!   h3_interop_tool client --host A.B.C.D --port N --authority NAME \
//!       --path /p [--body STR] [--empty-initial-key-share] \
//!       [--expect-hrr] [--insecure | --pin cert.der] [--verbose]
//!
//! The client exits 0 once it has received a complete response (status and
//! body are printed to stdout). The server exits 0 after serving --requests
//! requests (default 1) and seeing the connection close or drain. --verbose
//! streams connection-driver events (packet, loss, PTO, key, state) to
//! stderr for debugging interop failures.

const std = @import("std");
const quic = @import("quic");
const http3 = @import("http3");
const matrix = @import("tls_interop_matrix");

const connection = quic.connection;
const tls_backend = quic.tls_backend;
const production_crypto = quic.tls_core.production_crypto;
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
        .path_validation_started => |p| std.fmt.bufPrint(&buf, "path validation started change={s} remote_port={d}", .{ @tagName(p.change), p.path.remote.port }),
        .path_validation_succeeded => |p| std.fmt.bufPrint(&buf, "path validation succeeded change={s} remote_port={d}", .{ @tagName(p.change), p.path.remote.port }),
        .path_validation_failed => |p| std.fmt.bufPrint(&buf, "path validation failed change={s} remote_port={d}", .{ @tagName(p.change), p.path.remote.port }),
        .path_migration_blocked => |p| std.fmt.bufPrint(&buf, "path blocked change={s} reason={s} remote_port={d}", .{ @tagName(p.change), @tagName(p.reason), p.path.remote.port }),
        .path_promoted => |p| std.fmt.bufPrint(&buf, "path promoted change={s} remote_port={d}", .{ @tagName(p.change), p.path.remote.port }),
        .zero_rtt_packet => |z| std.fmt.bufPrint(&buf, "zero_rtt_packet outcome={s} size={d}", .{ @tagName(z.outcome), z.size }),
        .early_data_decision => |d| std.fmt.bufPrint(&buf, "early_data_decision {s}", .{@tagName(d)}),
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
    empty_initial_key_share: bool = false,
    expect_hrr: bool = false,
    /// #338: the shared conformance-matrix negotiation tuple. Left empty, the
    /// tool offers QUIC's ordinary default policy exactly as before.
    config: matrix.Config = .{},
};

/// The engine policy for this run: QUIC transport mode, h3 as the default
/// ALPN, and whatever the matrix row pinned. Built through the same
/// `matrix.Config` the record-transport tool uses, so "aes256-gcm-sha384 +
/// secp256r1 + ecdsa-p256-sha256" is one engine configuration regardless of
/// which transport is carrying it.
/// `args` is taken by pointer, not by value: the returned policy's
/// suite/group/signature slices point into `args.config`'s inline storage, so
/// a by-value parameter would hand back slices into a copy that dies with this
/// call.
fn quicPolicy(args: *const Args) quic.tls_core.policy.Policy {
    const default_alpns = [_]quic.tls_core.algorithms.ProtocolName{quic.tls_core.algorithms.alpn.h3};
    return args.config.policy(.quic, &default_alpns);
}

/// Emit the negotiated tuple in the shared matrix vocabulary, so a QUIC row
/// and a record row read identically in a CI log (#338).
fn reportNegotiated(args: Args, backend: *const tls_backend.Tls13Backend, saw_hrr: bool) void {
    std.debug.print("tls-interop: outcome=ok transport=quic role={s} suite={s} group={s} alpn={s} hrr={}\n", .{
        @tagName(args.mode),
        matrix.cipherSuiteName(backend.engine.negotiated_cipher_suite),
        matrix.namedGroupName(backend.engine.negotiated_named_group),
        backend.alpn,
        saw_hrr,
    });
}

/// A row that pinned exactly one value along a dimension is asserting the
/// peer landed on it, not merely that some handshake succeeded -- the same
/// check `tls_interop_tool` applies on the record transport.
fn matrixTupleHolds(args: Args, backend: *const tls_backend.Tls13Backend) bool {
    var ok = true;
    if (args.config.cipher_suites.len == 1 and backend.engine.negotiated_cipher_suite != args.config.cipher_suites.values[0]) {
        std.debug.print("h3-interop: expected suite {s} but negotiated {s}\n", .{
            matrix.cipherSuiteName(args.config.cipher_suites.values[0]),
            matrix.cipherSuiteName(backend.engine.negotiated_cipher_suite),
        });
        ok = false;
    }
    if (args.config.named_groups.len == 1 and backend.engine.negotiated_named_group != args.config.named_groups.values[0]) {
        std.debug.print("h3-interop: expected group {s} but negotiated {s}\n", .{
            matrix.namedGroupName(args.config.named_groups.values[0]),
            matrix.namedGroupName(backend.engine.negotiated_named_group),
        });
        ok = false;
    }
    return ok;
}

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
        } else if (std.mem.eql(u8, arg, "--empty-initial-key-share")) {
            args.empty_initial_key_share = true;
        } else if (std.mem.eql(u8, arg, "--expect-hrr")) {
            args.expect_hrr = true;
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
        } else if (std.mem.eql(u8, arg, "--cipher-suite")) {
            try args.config.addCipherSuite(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else if (std.mem.eql(u8, arg, "--group")) {
            try args.config.addNamedGroup(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else if (std.mem.eql(u8, arg, "--signature")) {
            try args.config.addSignatureScheme(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else if (std.mem.eql(u8, arg, "--alpn")) {
            try args.config.addAlpn(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else {
            std.debug.print("h3-interop: unknown argument {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }
    return args;
}

const UdpSocket = struct {
    fd: std.c.fd_t,
    /// The actually-bound local address (`getsockname` semantics): with
    /// `bind_port = 0` the OS assigns an ephemeral port only known after
    /// bind. Used as every `PathKey`'s local half for this socket.
    local: std.c.sockaddr.in,

    fn open(bind_port: u16) !UdpSocket {
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
            .port = std.mem.nativeToBig(u16, bind_port),
            .addr = 0, // INADDR_ANY
        };
        if (std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(std.c.sockaddr.in)) != 0) return error.BindFailed;
        var bound: std.c.sockaddr.in = undefined;
        var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        if (std.c.getsockname(fd, @ptrCast(&bound), &bound_len) != 0) return error.GetSockNameFailed;
        return .{ .fd = fd, .local = bound };
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
    };
}

/// Unused by ordinary on-path traffic (`PathManager` only consumes fresh
/// challenge entropy when a datagram starts a *new* candidate validation);
/// this tool talks to exactly one fixed external peer per run.
const test_challenge_entropy = [_]u8{0x5a} ** quic.path.path_challenge_len;

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
                "usage: h3_interop_tool server --port N --cert cert.pem --key key.pem [--requests N] [--expect-hrr]\n" ++
                "       h3_interop_tool client --host IP --port N --authority NAME --path /p [--empty-initial-key-share] [--expect-hrr] [--insecure|--pin cert.der]\n" ++
                "\nnegotiation (#338, shared vocabulary with tls_interop_tool):\n" ++
                matrix.flag_usage,
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

    const client_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(socket.local),
        .remote = addressFromSockaddrIn(peer_addr),
    };
    const client_options = tls_backend.ClientOptions{
        .initial_key_share_mode = if (args.empty_initial_key_share) .empty else .normal,
    };
    // A real OS-backed provider, owned for this process's lifetime (#490
    // review): this tool drives real network handshakes against real peers,
    // so ephemeral X25519 keys must not be predictable the way a
    // deterministic test provider's would be.
    var crypto_provider_entropy = production_crypto.OsEntropy{};
    var crypto_provider_state = production_crypto.Provider.init(crypto_provider_entropy.entropy());
    const crypto_provider = crypto_provider_state.cryptoProvider();
    var backend = tls_backend.Tls13Backend.initClientWithPolicyAndOptions(randomEntropy(), crypto_provider, trust, quicPolicy(&args), client_options);
    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &local_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .tls = backend.backend(),
        .crypto_provider = crypto_provider,
        .now_us = nowUs(),
        .events = .{ .emitFn = logEvent },
        .allow_unverified_certificate = args.insecure,
        .initial_path = client_path,
    });
    defer client.deinit();

    var h3 = H3.init(allocator, .client);
    defer h3.deinit();

    var request_id: ?u64 = null;
    const deadline = nowUs() + args.timeout_ms * 1_000;
    var success = false;

    while (nowUs() < deadline) {
        const now = nowUs();
        var out: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&out, now)) |t| {
            try socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
        var next: u64 = now + 50_000;
        if (client.nextTimeoutUs()) |t| next = @min(next, t);
        try socket.waitReadable(@intCast(@min((next -| now) / 1_000 + 1, 50)));
        var in: [2048]u8 = undefined;
        var from: std.c.sockaddr.in = undefined;
        while (try socket.recvFrom(&in, &from)) |datagram| {
            try client.ingestOnPath(datagram, client_path, test_challenge_entropy, nowUs());
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
    const saw_hrr = backend.engine.core.retry_state == .hrr_received;
    std.debug.print("h3-interop: tls retry_state={s}\n", .{@tagName(backend.engine.core.retry_state)});
    reportNegotiated(args, &backend, saw_hrr);
    if (args.expect_hrr and !saw_hrr) {
        std.debug.print("h3-interop: expected HelloRetryRequest but none was observed\n", .{});
        std.process.exit(1);
    }
    if (!matrixTupleHolds(args, &backend)) std.process.exit(1);
    // Orderly close.
    client.close(0, "done", nowUs());
    var out: [2048]u8 = undefined;
    while (client.pollTransmitOnPath(&out, nowUs())) |t| {
        try socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
    }
    std.debug.print("h3-interop: client ok\n", .{});
}

fn runServer(allocator: std.mem.Allocator, args: Args) !void {
    if (args.cert.len == 0 or args.key.len == 0) {
        std.debug.print("h3-interop: server needs --cert and --key (PEM or DER)\n", .{});
        std.process.exit(2);
    }
    // #338: loaded through the production identity loader rather than
    // `Identity.initPkcs8` directly, so a matrix row can hand this tool the
    // same PEM files it hands `tls_interop_tool` -- and so RSA identities
    // (whose import needs an entropy source for its primality witnesses)
    // work here at all.
    var identity_entropy = production_crypto.OsEntropy{};
    var loaded = try quic.tls_core.identity_loader.loadIdentity(allocator, args.cert, args.key, identity_entropy.entropy());
    defer loaded.deinit();
    const identity = loaded.identity;

    var socket = try UdpSocket.open(args.port);
    defer socket.close();
    std.debug.print("h3-interop: server listening on udp port {d}\n", .{args.port});

    var served: usize = 0;
    const deadline = nowUs() + args.timeout_ms * 1_000;
    var saw_hrr = false;

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

        const server_path = quic.path.PathKey{
            .local = addressFromSockaddrIn(socket.local),
            .remote = addressFromSockaddrIn(peer),
        };
        // A real OS-backed provider, owned for this process's lifetime
        // (#490 review) — see the matching comment in `runClient`.
        var crypto_provider_entropy = production_crypto.OsEntropy{};
        var crypto_provider_state = production_crypto.Provider.init(crypto_provider_entropy.entropy());
        const crypto_provider = crypto_provider_state.cryptoProvider();
        var backend = tls_backend.Tls13Backend.initServerWithPolicy(randomEntropy(), crypto_provider, identity, quicPolicy(&args));
        const server = try Connection.init(allocator, .{
            .role = .server,
            .local_cid = parsed.dcid,
            .original_destination_cid = parsed.dcid,
            .initial_secret_dcid = parsed.dcid,
            .peer_cid = parsed.scid,
            .tls = backend.backend(),
            .crypto_provider = crypto_provider,
            .now_us = nowUs(),
            .events = .{ .emitFn = logEvent },
            .initial_path = server_path,
        });
        defer server.deinit();
        var h3 = H3.init(allocator, .server);
        defer h3.deinit();
        try server.ingestOnPath(first_datagram, server_path, test_challenge_entropy, nowUs());

        var h3_started = false;
        while (nowUs() < deadline) {
            const now = nowUs();
            var out: [2048]u8 = undefined;
            while (server.pollTransmitOnPath(&out, now)) |t| {
                try socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
            }
            var next: u64 = now + 50_000;
            if (server.nextTimeoutUs()) |t| next = @min(next, t);
            try socket.waitReadable(@intCast(@min((next -| now) / 1_000 + 1, 50)));
            var in: [2048]u8 = undefined;
            while (try socket.recvFrom(&in, &peer)) |datagram| {
                // Only this connection's DCID is routable; a new Initial for a
                // different connection would start a new accept cycle.
                // Recompute the ingress path per datagram (not the fixed
                // `server_path` above): an interop peer that migrates or
                // rebinds sends from a different address than the one that
                // opened the connection.
                const ingress_path = quic.path.PathKey{ .local = server_path.local, .remote = addressFromSockaddrIn(peer) };
                try server.ingestOnPath(datagram, ingress_path, test_challenge_entropy, nowUs());
            }
            server.onTimeout(nowUs());

            switch (server.state()) {
                .closed, .draining, .closing => {
                    saw_hrr = saw_hrr or backend.engine.core.retry_state == .hrr_sent;
                    std.debug.print("h3-interop: connection ended state={s} served={d} handshake_error={any}\n", .{
                        @tagName(server.state()),
                        served,
                        server.handshakeFailure(),
                    });
                    if (served >= args.requests) break :accept_loop;
                    continue :accept_loop;
                },
                else => {},
            }
            if (server.isEstablished()) {
                if (!h3_started) {
                    std.debug.print("h3-interop: established, alpn_h3={}\n", .{server.negotiatedH3()});
                    reportNegotiated(args, &backend, backend.engine.core.retry_state == .hrr_sent);
                    if (!matrixTupleHolds(args, &backend)) std.process.exit(1);
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
        saw_hrr = saw_hrr or backend.engine.core.retry_state == .hrr_sent;
    }

    if (served < args.requests) {
        std.debug.print("h3-interop: server timed out with served={d}/{d}\n", .{ served, args.requests });
        std.process.exit(1);
    }
    std.debug.print("h3-interop: tls hello_retry_request={}\n", .{saw_hrr});
    if (args.expect_hrr and !saw_hrr) {
        std.debug.print("h3-interop: expected HelloRetryRequest but none was observed\n", .{});
        std.process.exit(1);
    }
    std.debug.print("h3-interop: server ok, served={d}\n", .{served});
}
