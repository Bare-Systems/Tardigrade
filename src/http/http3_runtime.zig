//! Native HTTP/3 downstream listener runtime (#328).
//!
//! Runs Tardigrade's HTTP/3 endpoint entirely on the native Zig QUIC/H3
//! stack: the connection driver in `src/quic/connection.zig` plus the H3
//! session glue in `src/http3/conn.zig`. One background thread owns one UDP
//! socket, routes datagrams to connections by Destination Connection ID,
//! schedules wakeups from the drivers' timer deadlines, and bridges decoded
//! requests to the gateway's `RequestHandler`.
//!
//! ngtcp2/nghttp3 are gone from the build (#328); they remain available only
//! as out-of-process interop peers under `scripts/interop/`.
//!
//! TLS identity: the native TLS 1.3 backend authenticates with an Ed25519 or
//! ECDSA P-256 certificate (PEM or DER). Other key types (e.g. RSA) leave the
//! QUIC listener unbootstrapped with a logged warning while TCP continues to
//! serve — mirroring the previous behavior when HTTP/3 support was absent.

const compat = @import("../zig_compat.zig");
const std = @import("std");
const http3_session = @import("http3_session.zig");
const logger_mod = @import("logger.zig");
const response_mod = @import("response.zig");
const shutdown = @import("shutdown.zig");
const stream_transport = @import("stream_transport");
const quic = @import("quic");
const http3 = @import("http3");

const Connection = quic.connection.Connection;
const H3 = http3.conn.Conn(Connection);
const posix = std.posix;

pub const Http3RuntimeError = error{
    OutOfMemory,
    DependencyUnavailable,
    NotYetImplemented,
    BindFailed,
    TlsBootstrapFailed,
};

pub const RequestHandler = *const fn (
    allocator: std.mem.Allocator,
    request: *const http3_session.StreamRequest,
    response: *response_mod.Response,
    user_data: ?*anyopaque,
) anyerror!void;

pub const Config = struct {
    listen_host: []const u8,
    quic_port: u16,
    tls_cert_path: []const u8 = "",
    tls_key_path: []const u8 = "",
    tls_min_version: []const u8 = "1.3",
    tls_max_version: []const u8 = "1.3",
    enable_0rtt: bool = false,
    connection_migration: bool = false,
    max_datagram_size: usize = 1350,
    request_handler: ?RequestHandler = null,
    request_handler_ctx: ?*anyopaque = null,
};

pub const Snapshot = struct {
    quic_port: u16 = 0,
    server_bootstrapped: bool = false,
    datagrams_seen: usize = 0,
    bytes_seen: usize = 0,
    zero_rtt_packets_seen: usize = 0,
    tracked_connections: usize = 0,
    native_connections: usize = 0,
    native_reads_attempted: usize = 0,
    native_read_calls: usize = 0,
    handshakes_completed: usize = 0,
    stream_bytes_received: usize = 0,
    stream_chunks_received: usize = 0,
    requests_completed: usize = 0,
    packets_emitted: usize = 0,
    bytes_emitted: usize = 0,
    migration_events: usize = 0,
    last_error_code: i32 = 0,

    pub fn handshakeState(self: Snapshot) []const u8 {
        if (!self.server_bootstrapped) return "bootstrap_incomplete";
        if (self.handshakes_completed > 0) return "complete";
        if (self.native_connections > 0) return "connection_created";
        if (self.datagrams_seen > 0) return "datagram_seen";
        return "idle";
    }
};

/// One accepted QUIC connection with its HTTP/3 session state.
const ConnEntry = struct {
    backend: *quic.tls_backend.Tls13Backend,
    conn: *Connection,
    h3: H3,
    h3_started: bool = false,
    peer: std.c.sockaddr.in,
    cid_len: usize,

    fn deinit(self: *ConnEntry, allocator: std.mem.Allocator) void {
        self.h3.deinit();
        self.conn.deinit();
        allocator.destroy(self.backend);
    }
};

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    socket_fd: std.c.fd_t,
    thread: ?std.Thread,
    logger: *logger_mod.Logger,
    quic_port: u16,
    request_handler: ?RequestHandler,
    request_handler_ctx: ?*anyopaque,
    identity: ?quic.tls_backend.Identity,
    cert_der: []u8,
    key_der: []u8,
    snapshot_mutex: compat.Mutex = .{},
    snapshot_state: Snapshot,
    stopping: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, logger: *logger_mod.Logger, cfg: Config) Http3RuntimeError!Runtime {
        const address = compat.parseIpAddress(cfg.listen_host, cfg.quic_port) catch |err| {
            logger.warn(null, "http3: listen address parse failed: {s}", .{@errorName(err)});
            return error.BindFailed;
        };
        const sa_family = @as(*const std.c.sockaddr, @ptrCast(&address.storage)).family;
        const fd = std.c.socket(@intCast(sa_family), posix.SOCK.DGRAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, posix.IPPROTO.UDP);
        if (fd < 0) return error.BindFailed;
        errdefer _ = std.c.close(fd);

        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1))) catch {}; // REUSEADDR is advisory; bind proceeds regardless
        const bind_rc = std.c.bind(fd, @ptrCast(&address.storage), @intCast(address.len));
        if (bind_rc != 0) {
            logger.warn(null, "http3: udp bind failed: {s}", .{@tagName(posix.errno(bind_rc))});
            return error.BindFailed;
        }

        var runtime = Runtime{
            .allocator = allocator,
            .socket_fd = fd,
            .thread = null,
            .logger = logger,
            .quic_port = cfg.quic_port,
            .request_handler = cfg.request_handler,
            .request_handler_ctx = cfg.request_handler_ctx,
            .identity = null,
            .cert_der = &.{},
            .key_der = &.{},
            .snapshot_state = .{ .quic_port = cfg.quic_port },
            .stopping = std.atomic.Value(bool).init(false),
        };

        if (cfg.enable_0rtt) {
            logger.warn(null, "http3: 0-RTT is not supported by the native QUIC stack; continuing without it", .{});
        }
        if (cfg.tls_cert_path.len > 0 and cfg.tls_key_path.len > 0) {
            runtime.loadIdentity(cfg.tls_cert_path, cfg.tls_key_path) catch |err| {
                logger.warn(null, "http3: TLS identity unusable for QUIC ({s}); the native stack needs an Ed25519 or ECDSA P-256 certificate. QUIC bootstrap incomplete.", .{@errorName(err)});
            };
        }
        runtime.snapshot_state.server_bootstrapped = runtime.identity != null;
        return runtime;
    }

    fn loadIdentity(self: *Runtime, cert_path: []const u8, key_path: []const u8) !void {
        const cert_raw = try readSmallFile(self.allocator, cert_path);
        defer self.allocator.free(cert_raw);
        const key_raw = try readSmallFile(self.allocator, key_path);
        defer self.allocator.free(key_raw);

        const cert_der = try derFromPemOrDer(self.allocator, cert_raw, "CERTIFICATE");
        errdefer self.allocator.free(cert_der);
        const key_der = try keyDerFromPemOrDer(self.allocator, key_raw);
        errdefer self.allocator.free(key_der);

        const identity = try quic.tls_backend.Identity.initPkcs8(cert_der, key_der);
        self.cert_der = cert_der;
        self.key_der = key_der;
        self.identity = identity;
    }

    pub fn start(self: *Runtime) void {
        if (self.thread != null) return;
        self.thread = std.Thread.spawn(.{}, loopMain, .{self}) catch null;
    }

    pub fn deinit(self: *Runtime) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        _ = std.c.close(self.socket_fd);
        if (self.cert_der.len > 0) self.allocator.free(self.cert_der);
        if (self.key_der.len > 0) self.allocator.free(self.key_der);
        self.* = undefined;
    }

    pub fn snapshot(self: *Runtime) Snapshot {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        return self.snapshot_state;
    }

    fn nowUs() u64 {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1_000;
    }

    fn loopMain(self: *Runtime) void {
        self.serve() catch |err| {
            self.logger.warn(null, "http3: listener loop terminated: {s}", .{@errorName(err)});
        };
    }

    fn serve(self: *Runtime) !void {
        const allocator = self.allocator;
        var connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
        var routes = quic.cid.CidRoutingTable.init(allocator);
        var next_handle: u64 = 1;
        defer {
            var it = connections.valueIterator();
            while (it.next()) |entry| {
                entry.*.deinit(allocator);
                allocator.destroy(entry.*);
            }
            connections.deinit();
            routes.deinit();
        }

        while (!self.stopping.load(.acquire) and !shutdown.isShutdownRequested()) {
            const now = nowUs();

            // 1) Timers and transmission for every connection.
            var wake_us: u64 = now + 100_000;
            {
                var out: [2048]u8 = undefined;
                var reap: [16]u64 = undefined;
                var reap_count: usize = 0;
                var it = connections.iterator();
                while (it.next()) |kv| {
                    const entry = kv.value_ptr.*;
                    entry.conn.onTimeout(now);
                    while (entry.conn.pollTransmit(&out, now)) |datagram| {
                        self.sendDatagram(entry.peer, datagram);
                    }
                    self.pumpH3(entry, now);
                    while (entry.conn.pollTransmit(&out, now)) |datagram| {
                        self.sendDatagram(entry.peer, datagram);
                    }
                    if (entry.conn.state() == .closed) {
                        if (reap_count < reap.len) {
                            reap[reap_count] = kv.key_ptr.*;
                            reap_count += 1;
                        }
                        continue;
                    }
                    if (entry.conn.nextTimeoutUs()) |deadline| wake_us = @min(wake_us, deadline);
                }
                for (reap[0..reap_count]) |handle| {
                    if (connections.fetchRemove(handle)) |kv| {
                        routes.remove(quic.cid.ConnectionId.init(kv.value.conn.localCid()) catch unreachable);
                        kv.value.deinit(allocator);
                        allocator.destroy(kv.value);
                        self.noteConnectionClosed();
                    }
                }
            }

            // 2) Sleep until the earliest deadline or socket readability.
            const timeout_ms: i32 = @intCast(@min((wake_us -| nowUs()) / 1_000 + 1, 100));
            var fds = [_]posix.pollfd{
                .{ .fd = self.socket_fd, .events = posix.POLL.IN, .revents = 0 },
            };
            _ = posix.poll(&fds, timeout_ms) catch {};

            // 3) Ingest every waiting datagram.
            var buf: [2048]u8 = undefined;
            var from: std.c.sockaddr.storage = undefined;
            while (true) {
                var from_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);
                const n = std.c.recvfrom(self.socket_fd, &buf, buf.len, 0, @ptrCast(&from), &from_len);
                if (n < 0) {
                    const e = posix.errno(n);
                    if (e == .AGAIN) break;
                    if (e == .CONNREFUSED or e == .CONNRESET) continue;
                    break;
                }
                if (n == 0) continue;
                const datagram = buf[0..@intCast(n)];
                if (from.family != posix.AF.INET) continue;
                const peer: *const std.c.sockaddr.in = @ptrCast(&from);
                self.ingest(&connections, &routes, &next_handle, datagram, peer.*, nowUs());
            }
        }
    }

    fn ingest(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
        routes: *quic.cid.CidRoutingTable,
        next_handle: *u64,
        datagram: []const u8,
        peer: std.c.sockaddr.in,
        now: u64,
    ) void {
        self.noteDatagram(datagram.len);

        // Route by DCID. Long headers carry the DCID length; short headers
        // need the connection's own CID length, which the client chose per
        // connection — try each active length.
        var handle: ?u64 = null;
        if (datagram.len > 0 and datagram[0] & 0x80 != 0) {
            if (quic.packet.parsePacket(datagram, 0)) |parsed| {
                handle = routes.lookup(parsed.dcid);
                if (handle == null and parsed.kind == .initial) {
                    handle = self.accept(connections, routes, next_handle, parsed, peer, now);
                }
                if (parsed.kind == .zero_rtt) self.noteZeroRtt();
            } else |_| {
                return;
            }
        } else {
            var it = connections.iterator();
            while (it.next()) |kv| {
                const entry = kv.value_ptr.*;
                if (datagram.len < 1 + entry.cid_len) continue;
                if (routes.lookup(datagram[1..][0..entry.cid_len])) |found| {
                    handle = found;
                    break;
                }
            }
        }
        const found = handle orelse return;
        const entry = connections.get(found) orelse return;

        const was_established = entry.conn.isEstablished();
        entry.peer = peer; // reply to the packet's source (NAT rebinding)
        entry.conn.ingest(datagram, now) catch return;
        if (!was_established and entry.conn.isEstablished()) {
            self.noteHandshakeComplete();
        }

        var out: [2048]u8 = undefined;
        while (entry.conn.pollTransmit(&out, now)) |response_datagram| {
            self.sendDatagram(entry.peer, response_datagram);
        }
        self.pumpH3(entry, now);
        while (entry.conn.pollTransmit(&out, now)) |response_datagram| {
            self.sendDatagram(entry.peer, response_datagram);
        }
    }

    fn accept(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
        routes: *quic.cid.CidRoutingTable,
        next_handle: *u64,
        parsed: quic.packet.ParsedPacket,
        peer: std.c.sockaddr.in,
        now: u64,
    ) ?u64 {
        const identity = self.identity orelse return null;
        if (parsed.version != quic.packet.quic_v1) return null;
        if (parsed.dcid.len < 8 or parsed.scid.len == 0) return null;
        const allocator = self.allocator;

        const backend = allocator.create(quic.tls_backend.Tls13Backend) catch return null;
        var entropy: quic.tls_backend.Entropy = undefined;
        compat.randomBytes(&entropy.hello_random);
        compat.randomBytes(&entropy.key_share_seed);
        backend.* = quic.tls_backend.Tls13Backend.initServer(entropy, identity);

        const conn = Connection.init(allocator, .{
            .role = .server,
            .local_cid = parsed.dcid,
            .original_dcid = parsed.dcid,
            .peer_cid = parsed.scid,
            .tls = backend.backend(),
            .now_us = now,
        }) catch {
            allocator.destroy(backend);
            return null;
        };

        const entry = allocator.create(ConnEntry) catch {
            conn.deinit();
            allocator.destroy(backend);
            return null;
        };
        entry.* = .{
            .backend = backend,
            .conn = conn,
            .h3 = H3.init(allocator, .server),
            .peer = peer,
            .cid_len = parsed.dcid.len,
        };

        const handle = next_handle.*;
        next_handle.* += 1;
        const cid = quic.cid.ConnectionId.init(parsed.dcid) catch {
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        routes.insert(cid, handle) catch {
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        connections.put(handle, entry) catch {
            routes.remove(cid);
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        self.noteConnectionAccepted();
        return handle;
    }

    fn pumpH3(self: *Runtime, entry: *ConnEntry, now: u64) void {
        if (!entry.conn.isEstablished()) return;
        if (!entry.h3_started) {
            entry.h3.start(entry.conn) catch return;
            entry.h3_started = true;
        }
        entry.h3.pump(entry.conn) catch |err| {
            // An H3-level protocol error closes the connection with the
            // specific RFC 9114 §8.1 code the session layer recorded.
            const code = entry.h3.closeCode();
            self.logger.warn(null, "http3: session error {s} (close code 0x{x}); closing connection", .{ @errorName(err), code });
            entry.conn.close(code, "h3 protocol error", now);
            return;
        };
        while (true) {
            const incoming = entry.h3.pollRequest() catch {
                entry.conn.close(entry.h3.closeCode(), "h3 request error", now);
                return;
            } orelse break;
            self.serveRequest(entry, incoming, now);
        }
    }

    fn serveRequest(self: *Runtime, entry: *ConnEntry, incoming: H3.IncomingRequest, now: u64) void {
        const allocator = self.allocator;
        const handler = self.request_handler orelse {
            entry.h3.sendResponse(entry.conn, incoming.stream_id, 404, &.{}, "") catch {};
            return;
        };

        var request = buildStreamRequest(allocator, incoming.exchange) catch {
            entry.h3.sendResponse(entry.conn, incoming.stream_id, 500, &.{}, "") catch {};
            entry.h3.finishRequest(incoming.stream_id);
            return;
        };
        defer request.deinit();

        var response = response_mod.Response.init(allocator);
        defer response.deinit();
        handler(allocator, &request, &response, self.request_handler_ctx) catch |err| {
            self.logger.warn(null, "http3: request handler failed: {s}", .{@errorName(err)});
            entry.h3.sendResponse(entry.conn, incoming.stream_id, 500, &.{}, "") catch {};
            entry.h3.finishRequest(incoming.stream_id);
            return;
        };

        var headers_buf: [64]stream_transport.Header = undefined;
        var header_count: usize = 0;
        for (response.headers.iterator()) |header| {
            if (header_count == headers_buf.len) break;
            headers_buf[header_count] = .{ .name = header.name, .value = header.value };
            header_count += 1;
        }
        entry.h3.sendResponse(
            entry.conn,
            incoming.stream_id,
            response.status.code(),
            headers_buf[0..header_count],
            response.body orelse "",
        ) catch |err| {
            self.logger.warn(null, "http3: response send failed: {s}", .{@errorName(err)});
            entry.conn.resetStream(incoming.stream_id, 0x0102) catch {}; // H3_INTERNAL_ERROR
            entry.h3.finishRequest(incoming.stream_id);
            return;
        };
        _ = now;
        self.noteRequestCompleted();
    }

    fn sendDatagram(self: *Runtime, peer: std.c.sockaddr.in, datagram: []const u8) void {
        const sent = std.c.sendto(self.socket_fd, datagram.ptr, datagram.len, 0, @ptrCast(&peer), @sizeOf(std.c.sockaddr.in));
        if (sent >= 0 and @as(usize, @intCast(sent)) == datagram.len) {
            self.notePacketOut(datagram.len);
        }
    }

    fn noteConnectionAccepted(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.native_connections += 1;
        self.snapshot_state.tracked_connections += 1;
    }

    fn noteConnectionClosed(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.native_connections -|= 1;
        self.snapshot_state.tracked_connections -|= 1;
    }

    fn noteHandshakeComplete(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.handshakes_completed += 1;
    }

    fn noteRequestCompleted(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.requests_completed += 1;
    }

    fn noteDatagram(self: *Runtime, len: usize) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.datagrams_seen += 1;
        self.snapshot_state.bytes_seen += len;
    }

    fn noteZeroRtt(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.zero_rtt_packets_seen += 1;
    }

    fn notePacketOut(self: *Runtime, len: usize) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.packets_emitted += 1;
        self.snapshot_state.bytes_emitted += len;
    }
};

/// Convert the protocol-neutral `stream_transport.Exchange` into the
/// gateway-facing `StreamRequest`, preserving the `:path` query string and
/// mapping `:authority` to a Host header when absent.
fn buildStreamRequest(allocator: std.mem.Allocator, exchange: stream_transport.Exchange) !http3_session.StreamRequest {
    var assembler = http3_session.StreamAssembler.init(allocator);
    defer assembler.deinit();

    var fields: [72]http3_session.HeaderField = undefined;
    fields[0] = .{ .name = ":method", .value = exchange.request.method };
    fields[1] = .{ .name = ":path", .value = exchange.request.path };
    fields[2] = .{ .name = ":authority", .value = exchange.request.authority };
    var count: usize = 3;
    for (exchange.request.headers) |header| {
        if (count == fields.len) break;
        fields[count] = .{ .name = header.name, .value = header.value };
        count += 1;
    }
    try assembler.appendHeaderBlock(fields[0..count]);
    switch (exchange.body) {
        .buffered => |body| try assembler.appendBody(body),
        else => {},
    }
    return assembler.finish();
}

fn readSmallFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return compat.cwd().readFileAlloc(allocator, path, 256 * 1024);
}

/// Accept PEM (first matching block) or raw DER for the certificate.
fn derFromPemOrDer(allocator: std.mem.Allocator, raw: []const u8, block_name: []const u8) ![]u8 {
    if (raw.len > 0 and raw[0] == 0x30) return allocator.dupe(u8, raw);
    return pemBlockToDer(allocator, raw, block_name);
}

/// Accept PEM ("PRIVATE KEY" or "EC PRIVATE KEY") or raw DER for the key.
fn keyDerFromPemOrDer(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (raw.len > 0 and raw[0] == 0x30) return allocator.dupe(u8, raw);
    if (pemBlockToDer(allocator, raw, "PRIVATE KEY")) |der| return der else |_| {}
    return pemBlockToDer(allocator, raw, "EC PRIVATE KEY");
}

fn pemBlockToDer(allocator: std.mem.Allocator, pem: []const u8, block_name: []const u8) ![]u8 {
    var begin_buf: [64]u8 = undefined;
    var end_buf: [64]u8 = undefined;
    const begin = try std.fmt.bufPrint(&begin_buf, "-----BEGIN {s}-----", .{block_name});
    const end = try std.fmt.bufPrint(&end_buf, "-----END {s}-----", .{block_name});
    const begin_at = std.mem.find(u8, pem, begin) orelse return error.PemBlockNotFound;
    const body_start = begin_at + begin.len;
    const end_at = std.mem.findPos(u8, pem, body_start, end) orelse return error.PemBlockNotFound;
    const body = pem[body_start..end_at];

    var compact = try allocator.alloc(u8, body.len);
    defer allocator.free(compact);
    var len: usize = 0;
    for (body) |char| {
        if (char == '\n' or char == '\r' or char == ' ' or char == '\t') continue;
        compact[len] = char;
        len += 1;
    }
    const decoder = std.base64.standard.Decoder;
    const der_len = try decoder.calcSizeForSlice(compact[0..len]);
    const der = try allocator.alloc(u8, der_len);
    errdefer allocator.free(der);
    try decoder.decode(der, compact[0..len]);
    return der;
}

const testing = std.testing;

test "PEM block decoding extracts DER bytes" {
    const allocator = testing.allocator;
    // "0\x03\x02\x01\x00" is a tiny DER SEQUENCE; base64 "MAMCAQA=".
    const pem = "junk\n-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n";
    const der = try pemBlockToDer(allocator, pem, "CERTIFICATE");
    defer allocator.free(der);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 }, der);
    try testing.expectError(error.PemBlockNotFound, pemBlockToDer(allocator, pem, "PRIVATE KEY"));
}

test "stream request bridge maps exchange fields and Host" {
    const allocator = testing.allocator;
    var request = try buildStreamRequest(allocator, .{
        .request = .{
            .method = "POST",
            .scheme = "https",
            .authority = "example.com",
            .path = "/api?x=1",
            .headers = &.{.{ .name = "content-type", .value = "application/json" }},
        },
        .body = .{ .buffered = @constCast("{}") },
    });
    defer request.deinit();
    try testing.expectEqualStrings("POST", request.method);
    try testing.expectEqualStrings("/api?x=1", request.path);
    try testing.expectEqualStrings("example.com", request.authority.?);
    try testing.expectEqualStrings("example.com", request.headers.get("Host").?);
    try testing.expectEqualStrings("application/json", request.headers.get("content-type").?);
    try testing.expectEqualStrings("{}", request.body);
}

test {
    std.testing.refAllDecls(@This());
}
