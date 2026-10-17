//! Real loopback TLS 1.3 + wire-format ACME CA server for #883 P1.
//!
//! `fake_ca.zig`'s `handle()` already speaks genuine RFC 8555 HTTP/1.1 over
//! raw bytes -- real JWS parsing and ES256 signature verification, real
//! single-use nonce issuance/consumption, a real directory/account/
//! order/authz/finalize/certificate state machine. The only thing fake about
//! it is the transport: `fake_ca.zig`'s own `dialer()` hands those bytes to
//! and from an in-memory `Connection`, so no byte ever actually crosses a
//! socket or a TLS handshake.
//!
//! This module gives that same protocol logic a real transport instead:
//! a real loopback TCP listener terminating a real server-role TLS 1.3
//! handshake through the shared native engine (the same `Tls13Backend` /
//! `PureZigRecordStream` pair the production listener and
//! `tests/tls_interop_tool.zig`'s server role use), so the production A2
//! client -- dialing through the real `http/acme_tls_dialer.zig` and
//! `UpstreamTlsConn`, with real hostname/chain verification against a real
//! trust anchor -- proves actual TCP/TLS/JWS/nonce interoperability, not
//! just that the order engine's state machine is internally consistent.
//!
//! No second TLS stack: this reuses the identical engine the production
//! client/server already ship, just in the server role, over a loopback
//! socket instead of a production network interface.
//!
//! What this does *not* prove: independent TLS 1.3 *implementation*
//! interoperability. Native client against native server exercises real
//! TCP/TLS/JWS wiring end to end, but both sides share the same engine, so
//! an engine-level interop bug in e.g. record framing could cancel out on
//! both ends and still pass here. `tests/tls_interop_tool.zig`'s own
//! OpenSSL/GnuTLS peer conformance gates remain the independent evidence
//! for the TLS engine itself; this module is evidence for the ACME
//! transport wiring on top of it.

const std = @import("std");
const builtin = @import("builtin");
const zig_compat = @import("zig_compat");
const tls = @import("tls_core");
const fake = @import("fake_ca.zig");

const production_crypto = tls.production_crypto;
const tls_backend = tls.tls13_backend;
const tls_policy = tls.policy;
const identity_loader = tls.identity_loader;
const credentials = tls.credentials;
const es = tls.encrypted_stream;

const posix = std.posix;

pub const default_cert_path = "tests/fixtures/tls/acme_live_ca/leaf.crt";
pub const default_key_path = "tests/fixtures/tls/acme_live_ca/leaf.key";
pub const default_ca_bundle_path = "tests/fixtures/tls/acme_live_ca/ca.crt";

/// A real ACME exchange is a handful of small JSON/JWS messages; a peer
/// that sends more than this per request is misbehaving, not a legitimate
/// client (mirrors `live_http01_tests.zig`'s `live_fetch_max_response_bytes`
/// bound on the HTTP-01 leg).
const max_request_bytes: usize = 64 * 1024;
/// Per-connection absolute deadline for the handshake plus the whole
/// request/response exchange: a stalled or hostile peer fails this
/// connection closed rather than blocking the accept loop forever.
const connection_deadline_ms: i64 = 5_000;

fn nowMs() i64 {
    return @intCast(@divTrunc(zig_compat.monotonicNanoTimestamp(), 1_000_000));
}

fn setNonBlocking(fd: posix.fd_t) !void {
    const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (status_flags < 0) return error.FcntlFailed;
    const nonblock = @as(c_int, @bitCast(posix.O{ .NONBLOCK = true }));
    if (std.c.fcntl(fd, std.c.F.SETFL, status_flags | nonblock) < 0) return error.FcntlFailed;
}

/// Bridges the TLS record engine to a real non-blocking socket fd, exactly
/// like `tests/tls_interop_tool.zig`'s `FdCarrier`.
const FdCarrier = struct {
    fd: posix.fd_t,

    fn carrier(self: *FdCarrier) es.Carrier {
        return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
    }

    fn read(ptr: *anyopaque, out: []u8) es.Error!usize {
        const self: *FdCarrier = @ptrCast(@alignCast(ptr));
        const n = std.c.read(self.fd, out.ptr, out.len);
        if (n < 0) {
            if (posix.errno(n) == .AGAIN) return error.WouldBlock;
            return error.SocketReadFailed;
        }
        return @intCast(n);
    }

    fn write(ptr: *anyopaque, bytes: []const u8) es.Error!usize {
        const self: *FdCarrier = @ptrCast(@alignCast(ptr));
        const n = std.c.write(self.fd, bytes.ptr, bytes.len);
        if (n < 0) {
            if (posix.errno(n) == .AGAIN) return error.WouldBlock;
            return error.SocketWriteFailed;
        }
        return @intCast(n);
    }

    fn close(ptr: *anyopaque) void {
        const self: *FdCarrier = @ptrCast(@alignCast(ptr));
        _ = std.c.shutdown(self.fd, posix.SHUT.WR);
    }
};

fn waitForCarrier(fd: posix.fd_t, stream: *es.PureZigRecordStream, deadline: i64) void {
    const readiness = stream.readiness();
    var wanted: i16 = 0;
    if (readiness.wants_read) wanted |= posix.POLL.IN;
    if (readiness.wants_write) wanted |= posix.POLL.OUT;
    if (wanted == 0) wanted = posix.POLL.IN;
    var fds = [_]posix.pollfd{.{ .fd = fd, .events = wanted, .revents = 0 }};
    const remaining = deadline - nowMs();
    if (remaining <= 0) return;
    _ = posix.poll(&fds, @intCast(@min(remaining, 50))) catch {};
}

/// The request body length this CA server must read before handing the
/// request to `fake_ca.zig`'s `handle()`, which (like the production
/// client's own writer) trusts a single `Content-Length` header and has no
/// chunked-request support -- there is none in RFC 8555 client traffic.
/// Absent or unparsable means no body (GET/HEAD), matching every real ACME
/// request shape this fixture ever receives.
fn contentLengthOf(head: []const u8) usize {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "content-length")) continue;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        return std.fmt.parseInt(usize, value, 10) catch 0;
    }
    return 0;
}

fn serveOne(allocator: std.mem.Allocator, ca: *fake.FakeCa, identity: credentials.Identity, fd: posix.fd_t) void {
    defer _ = std.c.close(fd);
    setNonBlocking(fd) catch return;

    var entropy_source = production_crypto.OsEntropy{};
    var provider_state = production_crypto.Provider.init(entropy_source.entropy());
    const crypto_provider = provider_state.cryptoProvider();
    const handshake_entropy = production_crypto.freshHandshakeEntropy() catch return;
    const policy = tls_policy.Policy.recordHttp1Only(false);

    var backend = tls_backend.Tls13Backend.initServerConfigured(
        handshake_entropy,
        crypto_provider,
        identity,
        tls_backend.recordConfig(policy),
    );

    var carrier_state = FdCarrier{ .fd = fd };
    var stream = es.PureZigRecordStream.initWithCarrierAndBackend(
        allocator,
        .server,
        crypto_provider,
        policy.cipher_suites[0],
        carrier_state.carrier(),
        backend.backend(),
    ) catch return;
    defer stream.deinit();

    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(allocator);
    var response: ?[]u8 = null;
    defer if (response) |r| allocator.free(r);
    var sent: usize = 0;
    var head_end: ?usize = null;
    var want_total: ?usize = null;

    const deadline = nowMs() + connection_deadline_ms;
    while (nowMs() < deadline) {
        _ = stream.drive() catch break;

        if (stream.applicationDataOpen()) {
            if (response == null) {
                var buf: [4096]u8 = undefined;
                const n = stream.stream().read(&buf) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => break,
                };
                if (n > 0) {
                    if (request.items.len + n > max_request_bytes) break;
                    request.appendSlice(allocator, buf[0..n]) catch break;
                }

                if (head_end == null) head_end = std.mem.indexOf(u8, request.items, "\r\n\r\n");
                if (head_end) |he| {
                    if (want_total == null) {
                        const body_len = contentLengthOf(request.items[0..he]);
                        const total = he + 4 + body_len;
                        if (total > max_request_bytes) break;
                        want_total = total;
                    }
                    if (request.items.len >= want_total.?) {
                        response = ca.handle(allocator, request.items[0..want_total.?]) catch break;
                    }
                }
            } else {
                const body = response.?;
                if (sent < body.len) {
                    const n = stream.stream().write(body[sent..]) catch |err| switch (err) {
                        error.WouldBlock => 0,
                        else => break,
                    };
                    sent += n;
                } else if (stream.bufferSnapshot().current.outbound_ciphertext == 0) {
                    break;
                }
            }
        }

        if (stream.failed) |_| break;
        waitForCarrier(fd, &stream, deadline);
    }
}

/// A real, independent-of-the-in-memory-fake ACME CA endpoint: real loopback
/// TCP, a real server-role TLS 1.3 handshake, and `fake_ca.zig`'s real
/// request handling underneath. One request per accepted connection, like
/// every other ACME transport in this codebase (`acme/transport.zig`'s doc
/// comment, design §6.3).
///
/// A mutating in-place starter (not a by-value `init`), like `Listener` and
/// `Env` elsewhere in this package: `acceptLoop` captures `&self`, so `self`
/// must already be at its final, stable address before `start` runs.
pub const Server = struct {
    allocator: std.mem.Allocator = undefined,
    ca: *fake.FakeCa = undefined,
    listener: zig_compat.NetServer = undefined,
    identity: identity_loader.LoadedIdentity = undefined,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),

    pub fn start(self: *Server, allocator: std.mem.Allocator, ca: *fake.FakeCa) !void {
        var entropy_source = production_crypto.OsEntropy{};
        self.allocator = allocator;
        self.ca = ca;
        self.identity = try identity_loader.loadIdentity(allocator, default_cert_path, default_key_path, entropy_source.entropy());
        errdefer self.identity.deinit();
        self.listener = try zig_compat.listenTcp("127.0.0.1", 0);
        errdefer self.listener.deinit();
        self.stopping = .init(false);
        self.thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
    }

    pub fn port(self: *const Server) u16 {
        return self.listener.port();
    }

    pub fn deinit(self: *Server) void {
        self.stopping.store(true, .release);
        // `accept()` below blocks; a throwaway loopback connection is the
        // simplest way to wake it so the accept thread notices `stopping`
        // and `join` below cannot hang on a server that never got another
        // real client.
        if (zig_compat.connectBoundedTcp("127.0.0.1", self.listener.port(), 1_000)) |fd| {
            zig_compat.closeFd(fd);
        } else |_| {}
        if (self.thread) |t| t.join();
        self.listener.deinit();
        self.identity.deinit();
        self.* = .{};
    }

    fn acceptLoop(self: *Server) void {
        while (!self.stopping.load(.acquire)) {
            const conn = self.listener.accept() catch |err| {
                if (self.stopping.load(.acquire)) return;
                if (err == error.Unexpected) continue;
                continue;
            };
            if (self.stopping.load(.acquire)) {
                conn.stream.close();
                return;
            }
            serveOne(self.allocator, self.ca, self.identity.identity, conn.stream.handle);
        }
    }
};

test "live ACME CA server: real TLS handshake and directory fetch over a real socket" {
    if (!builtin.is_test) return;
    const allocator = std.testing.allocator;
    var ca = fake.FakeCa.init(allocator);
    defer ca.deinit();

    var server: Server = .{};
    try server.start(allocator, &ca);
    defer server.deinit();

    const dialer_transport = @import("transport.zig");
    const snapshot = try dialer_transport.TrustAnchorSnapshot.load(allocator, default_ca_bundle_path);
    defer snapshot.release();
    const tls_dialer_mod = @import("../http/acme_tls_dialer.zig");
    var dialer = tls_dialer_mod.TlsDialer.init(snapshot);
    defer dialer.deinit();

    const t = dialer_transport.Transport{
        .allocator = allocator,
        .dialer = dialer.dialer(),
    };
    var url_buf: [64]u8 = undefined;
    const url_text = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/directory", .{server.port()});
    const target = try @import("url.zig").parse(url_text);
    var response = try t.request(.GET, target, null, null);
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status);
}
