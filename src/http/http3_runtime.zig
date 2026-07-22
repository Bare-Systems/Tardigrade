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
//! TLS identity: the runtime owns no certificate or key material. It borrows
//! a provider-neutral `tls_core.credentials.CredentialProvider` from the
//! composition root (#392) — the same provider instance that authenticates
//! native TCP TLS — and hands it to each accepted QUIC connection's TLS
//! backend. Without a provider the QUIC listener stays unbootstrapped with a
//! logged warning while TCP continues to serve.

const compat = @import("zig_compat");
const std = @import("std");
const http3_session = @import("http3_session.zig");
const logger_mod = @import("logger.zig");
const response_mod = @import("response.zig");
const shutdown = @import("shutdown.zig");
const stream_transport = @import("stream_transport");
const quic = @import("quic");
const http3 = @import("http3");
const tls_core = @import("tls_core");

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
    /// Borrowed local credential provider shared with the TCP TLS path. The
    /// owner must outlive this runtime and every QUIC connection it accepts.
    credential_provider: ?tls_core.credentials.CredentialProvider = null,
    tls_min_version: []const u8 = "1.3",
    tls_max_version: []const u8 = "1.3",
    enable_0rtt: bool = false,
    connection_migration: bool = false,
    max_datagram_size: usize = 1350,
    request_handler: ?RequestHandler = null,
    request_handler_ctx: ?*anyopaque = null,
};

/// Half-open admission limits (#328 review). The native stack does not send
/// Retry, so an off-path spoofer can forge Initial packets. Rather than
/// implement address validation now, we bound the state a spoofer can pin: a
/// global connection cap, a per-source-IP cap, immediate teardown of an Initial
/// that authenticates nothing, and a handshake deadline well under the idle
/// timeout so half-open connections are reaped promptly.
const max_connections: usize = 1024;
const max_connections_per_source: u32 = 32;
const handshake_timeout_us: u64 = 10 * std.time.us_per_s;

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
    /// Source address of the Initial that opened the connection. Fixed for the
    /// connection's lifetime: migration is unsupported (the native stack
    /// advertises `disable_active_migration`), so replies always target this
    /// address regardless of later packet sources.
    peer: std.c.sockaddr.in,
    cid_len: usize,
    /// Monotonic microseconds when the connection was accepted; used to reap
    /// connections that never complete the handshake.
    accepted_at_us: u64,

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
    credential_provider: ?tls_core.credentials.CredentialProvider,
    quic_config: quic.config.Config,
    snapshot_mutex: compat.Mutex = .{},
    snapshot_state: Snapshot,
    stopping: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, logger: *logger_mod.Logger, cfg: Config) Http3RuntimeError!Runtime {
        const address = compat.parseIpAddress(cfg.listen_host, cfg.quic_port) catch |err| {
            logger.warn(null, "http3: listen address parse failed: {s}", .{@errorName(err)});
            return error.BindFailed;
        };
        const sa_family = @as(*const std.c.sockaddr, @ptrCast(&address.storage)).family;
        const fd = openUdpSocket(sa_family);
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
            .credential_provider = cfg.credential_provider,
            .quic_config = quicConfigFrom(cfg),
            .snapshot_state = .{ .quic_port = cfg.quic_port },
            .stopping = std.atomic.Value(bool).init(false),
        };

        if (cfg.enable_0rtt) {
            logger.warn(null, "http3: 0-RTT is not supported by the native QUIC stack; continuing without it", .{});
        }
        if (cfg.connection_migration) {
            logger.warn(null, "http3: connection migration is not supported by the native QUIC stack; disable_active_migration stays advertised", .{});
        }
        if (!std.mem.eql(u8, cfg.tls_min_version, "1.3") or !std.mem.eql(u8, cfg.tls_max_version, "1.3")) {
            logger.warn(null, "http3: native QUIC requires TLS 1.3; ignoring tls_min_version={s}/tls_max_version={s}", .{ cfg.tls_min_version, cfg.tls_max_version });
        }
        if (cfg.credential_provider == null) {
            logger.warn(null, "http3: no TLS credential provider configured; QUIC bootstrap incomplete.", .{});
        }
        runtime.snapshot_state.server_bootstrapped = runtime.credential_provider != null;
        return runtime;
    }

    pub fn start(self: *Runtime) void {
        if (self.thread != null) return;
        self.thread = std.Thread.spawn(.{}, loopMain, .{self}) catch null;
    }

    pub fn deinit(self: *Runtime) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        _ = std.c.close(self.socket_fd);
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
        // Half-open admission accounting, keyed on the source IPv4 address.
        var per_ip = std.AutoHashMap(u32, u32).init(allocator);
        var next_handle: u64 = 1;
        defer {
            var it = connections.valueIterator();
            while (it.next()) |entry| {
                entry.*.deinit(allocator);
                allocator.destroy(entry.*);
            }
            connections.deinit();
            routes.deinit();
            per_ip.deinit();
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
                    // Reap closed connections and half-open connections that
                    // blew the handshake deadline (spoofed/stalled Initials).
                    const stalled = !entry.conn.isEstablished() and now -| entry.accepted_at_us > handshake_timeout_us;
                    if (entry.conn.state() == .closed or stalled) {
                        if (reap_count < reap.len) {
                            reap[reap_count] = kv.key_ptr.*;
                            reap_count += 1;
                        }
                        continue;
                    }
                    if (entry.conn.nextTimeoutUs()) |deadline| wake_us = @min(wake_us, deadline);
                }
                for (reap[0..reap_count]) |handle| {
                    self.removeConnection(&connections, &routes, &per_ip, handle);
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
                self.ingest(&connections, &routes, &per_ip, &next_handle, datagram, peer.*, nowUs());
            }
        }
    }

    fn ingest(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
        routes: *quic.cid.CidRoutingTable,
        per_ip: *std.AutoHashMap(u32, u32),
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
        var freshly_accepted = false;
        if (datagram.len > 0 and datagram[0] & 0x80 != 0) {
            if (quic.packet.parsePacket(datagram, 0)) |parsed| {
                handle = routes.lookup(parsed.dcid);
                if (handle == null and parsed.kind == .initial) {
                    handle = self.accept(connections, routes, per_ip, next_handle, parsed, peer, now);
                    freshly_accepted = handle != null;
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
        // `packets_received` only advances after AEAD open succeeds, so its
        // delta tells us whether this datagram authenticated — without trusting
        // its source address.
        const packets_before = entry.conn.metrics.packets_received;
        entry.conn.ingest(datagram, now) catch {
            if (freshly_accepted) self.removeConnection(connections, routes, per_ip, found);
            return;
        };
        const authenticated = entry.conn.metrics.packets_received > packets_before;
        switch (classifyIngest(freshly_accepted, authenticated, !sockaddrInEqual(peer, entry.peer))) {
            // A just-accepted connection whose first datagram authenticates
            // nothing is an unsolicited or spoofed Initial: drop the half-open
            // state now instead of holding it until the handshake deadline.
            .drop_unauthenticated => {
                self.removeConnection(connections, routes, per_ip, found);
                return;
            },
            // An authenticated packet from a source other than the one that
            // opened the connection is a migration attempt. The native stack
            // does not rebind (disable_active_migration is advertised), so
            // record it and keep replying on the original path.
            .migrated => self.noteMigrationEvent(),
            .keep => {},
        }

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
        per_ip: *std.AutoHashMap(u32, u32),
        next_handle: *u64,
        parsed: quic.packet.ParsedPacket,
        peer: std.c.sockaddr.in,
        now: u64,
    ) ?u64 {
        const credential_provider = self.credential_provider orelse return null;
        if (parsed.version != quic.packet.quic_v1) return null;
        if (parsed.dcid.len < 8 or parsed.scid.len == 0) return null;
        // Bound half-open state before allocating anything for this Initial.
        if (!admissionAllowed(connections.count(), per_ip.get(peer.addr) orelse 0)) return null;
        const allocator = self.allocator;

        const backend = allocator.create(quic.tls_backend.Tls13Backend) catch return null;
        var entropy: quic.tls_backend.Entropy = undefined;
        compat.randomBytes(&entropy.hello_random);
        compat.randomBytes(&entropy.key_share_seed);
        backend.* = quic.tls_backend.Tls13Backend.initServerWithProvider(entropy, credential_provider);

        const conn = Connection.init(allocator, .{
            .role = .server,
            .config = self.quic_config,
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
            .accepted_at_us = now,
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
        incPerIp(per_ip, peer.addr) catch {
            _ = connections.remove(handle);
            routes.remove(cid);
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        self.noteConnectionAccepted();
        return handle;
    }

    /// Remove a tracked connection: drop its CID route, release its per-source
    /// admission slot, and free its state. Safe to call with a stale handle.
    fn removeConnection(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
        routes: *quic.cid.CidRoutingTable,
        per_ip: *std.AutoHashMap(u32, u32),
        handle: u64,
    ) void {
        if (connections.fetchRemove(handle)) |kv| {
            routes.remove(quic.cid.ConnectionId.init(kv.value.conn.localCid()) catch unreachable);
            decPerIp(per_ip, kv.value.peer.addr);
            kv.value.deinit(self.allocator);
            self.allocator.destroy(kv.value);
            self.noteConnectionClosed();
        }
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

    fn noteMigrationEvent(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.migration_events += 1;
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

/// Map the operator-facing runtime config onto the native QUIC transport
/// config. Only `max_datagram_size` is honored today (clamped to the range the
/// 2048-byte work buffers can carry); the remaining transport knobs keep their
/// conservative defaults, including `migration_policy = .disabled`.
fn quicConfigFrom(cfg: Config) quic.config.Config {
    return .{
        .max_udp_payload_size = std.math.clamp(cfg.max_datagram_size, 1200, 2048),
    };
}

fn sockaddrInEqual(a: std.c.sockaddr.in, b: std.c.sockaddr.in) bool {
    return a.addr == b.addr and a.port == b.port;
}

/// Whether a new half-open connection may be admitted given the current global
/// and per-source connection counts. Bounds the state an off-path spoofer can
/// pin with forged Initials (the native stack sends no Retry).
fn admissionAllowed(total: usize, per_source: u32) bool {
    return total < max_connections and per_source < max_connections_per_source;
}

/// What to do with a tracked connection after ingesting a datagram, decided
/// purely from whether the datagram authenticated (the post-AEAD
/// `packets_received` delta), whether the connection was just accepted for this
/// datagram, and whether the source address differs from the connection's.
const IngestOutcome = enum {
    /// Process normally (transmit, pump H3).
    keep,
    /// A freshly accepted connection whose first datagram authenticated
    /// nothing — an unsolicited or spoofed Initial. Tear it down.
    drop_unauthenticated,
    /// An authenticated packet arrived from a new source. Record the migration
    /// event; the runtime does not follow it.
    migrated,
};

fn classifyIngest(freshly_accepted: bool, authenticated: bool, source_changed: bool) IngestOutcome {
    if (freshly_accepted and !authenticated) return .drop_unauthenticated;
    if (authenticated and !freshly_accepted and source_changed) return .migrated;
    return .keep;
}

fn incPerIp(per_ip: *std.AutoHashMap(u32, u32), addr: u32) !void {
    const gop = try per_ip.getOrPut(addr);
    if (!gop.found_existing) gop.value_ptr.* = 0;
    gop.value_ptr.* += 1;
}

fn decPerIp(per_ip: *std.AutoHashMap(u32, u32), addr: u32) void {
    if (per_ip.getPtr(addr)) |count| {
        count.* -= 1;
        if (count.* == 0) _ = per_ip.remove(addr);
    }
}

/// Create a non-blocking, close-on-exec UDP socket for `sa_family`. Returns a
/// negative fd on failure (caller inspects `errno`). macOS/BSD reject
/// `SOCK_CLOEXEC`/`SOCK_NONBLOCK` in the socket `type` argument (EPROTOTYPE),
/// unlike Linux, so the flags are applied with `fcntl` after creation to keep
/// the listener working on both platforms.
fn openUdpSocket(sa_family: u32) std.c.fd_t {
    const fd = std.c.socket(@intCast(sa_family), posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    if (fd < 0) return fd;
    const descriptor_flags = std.c.fcntl(fd, std.c.F.GETFD, @as(c_int, 0));
    if (descriptor_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFD, descriptor_flags | std.c.FD_CLOEXEC);
    const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (status_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFL, status_flags | @as(c_int, @bitCast(posix.O{ .NONBLOCK = true })));
    return fd;
}

const testing = std.testing;

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

test "quicConfigFrom clamps datagram size into the work-buffer range" {
    // Below the QUIC minimum snaps up to 1200.
    try testing.expectEqual(@as(u64, 1200), quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .max_datagram_size = 512,
    }).max_udp_payload_size);
    // Above the 2048-byte work buffer snaps down.
    try testing.expectEqual(@as(u64, 2048), quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .max_datagram_size = 9000,
    }).max_udp_payload_size);
    // An in-range value passes through, and migration stays disabled.
    const mid = quicConfigFrom(.{ .listen_host = "::", .quic_port = 443, .max_datagram_size = 1350 });
    try testing.expectEqual(@as(u64, 1350), mid.max_udp_payload_size);
    try testing.expectEqual(quic.config.MigrationPolicy.disabled, mid.migration_policy);
}

test "admissionAllowed enforces global and per-source caps at the boundary" {
    // Under both caps: admitted.
    try testing.expect(admissionAllowed(0, 0));
    try testing.expect(admissionAllowed(max_connections - 1, max_connections_per_source - 1));
    // At the global cap: rejected regardless of per-source count.
    try testing.expect(!admissionAllowed(max_connections, 0));
    try testing.expect(!admissionAllowed(max_connections + 1, 0));
    // At the per-source cap: rejected regardless of global room.
    try testing.expect(!admissionAllowed(0, max_connections_per_source));
    try testing.expect(!admissionAllowed(0, max_connections_per_source + 1));
    // Either cap alone is sufficient to reject.
    try testing.expect(!admissionAllowed(max_connections, max_connections_per_source));
}

test "classifyIngest routes spoofed Initials, migration, and normal traffic" {
    // Freshly accepted + first datagram authenticates nothing -> spoofed
    // Initial, torn down. The source-changed flag never overrides this: a
    // freshly accepted entry's peer is exactly the datagram's source.
    try testing.expectEqual(IngestOutcome.drop_unauthenticated, classifyIngest(true, false, false));
    try testing.expectEqual(IngestOutcome.drop_unauthenticated, classifyIngest(true, false, true));

    // Freshly accepted + authenticated (a legitimate Initial) -> keep and let
    // the handshake proceed.
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(true, true, false));

    // Established connection, authenticated packet from a new source -> counted
    // as a migration attempt, not followed.
    try testing.expectEqual(IngestOutcome.migrated, classifyIngest(false, true, true));

    // Authenticated packet from the same source -> ordinary traffic.
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(false, true, false));

    // Unauthenticated packet from a new source on an existing connection is
    // ignored (never promoted to a migration event): the source is untrusted.
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(false, false, true));
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(false, false, false));
}

test "per-source admission counter increments and prunes to empty" {
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    try incPerIp(&per_ip, 0x0100007f);
    try incPerIp(&per_ip, 0x0100007f);
    try testing.expectEqual(@as(u32, 2), per_ip.get(0x0100007f).?);
    decPerIp(&per_ip, 0x0100007f);
    try testing.expectEqual(@as(u32, 1), per_ip.get(0x0100007f).?);
    decPerIp(&per_ip, 0x0100007f);
    try testing.expect(per_ip.get(0x0100007f) == null);
    // Decrementing an unknown address is a no-op, not a crash.
    decPerIp(&per_ip, 0xdeadbeef);
}

test "runtime borrows the credential provider and owns no key material" {
    // Structural guarantee (#392): the runtime has no owned identity, DER, or
    // key buffers to leak — only the borrowed provider handle.
    comptime {
        for (@typeInfo(Runtime).@"struct".fields) |field| {
            std.debug.assert(!std.mem.eql(u8, field.name, "identity"));
            std.debug.assert(!std.mem.eql(u8, field.name, "cert_der"));
            std.debug.assert(!std.mem.eql(u8, field.name, "key_der"));
        }
    }

    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-test");

    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    try testing.expect(runtime.snapshot().server_bootstrapped);
    runtime.deinit();

    // Tearing the runtime down must not release the shared provider: the
    // same instance keeps serving native TCP TLS selections.
    var selection = tls_core.credentials.SelectionContext{
        .role = .server,
        .server_name = null,
        .peer_signature_schemes = &.{0x0807},
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = "h2",
        .auth_policy = .{},
    };
    switch (try fixed.provider().selectCredential(&selection)) {
        .complete => |credential| credential.release(),
        .pending => return error.TestUnexpectedPending,
    }

    var unbootstrapped = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    });
    try testing.expect(!unbootstrapped.snapshot().server_bootstrapped);
    unbootstrapped.deinit();
}

test {
    std.testing.refAllDecls(@This());
}
