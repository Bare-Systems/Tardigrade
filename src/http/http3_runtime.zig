const std = @import("std");
const ngtcp2_binding = @import("ngtcp2_binding.zig");
const logger_mod = @import("logger.zig");
const quic = @import("quic.zig");
const shutdown = @import("shutdown.zig");

pub const Http3RuntimeError = error{
    OutOfMemory,
    DependencyUnavailable,
    NotYetImplemented,
    BindFailed,
    TlsBootstrapFailed,
};

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
};

pub const Snapshot = struct {
    quic_port: u16 = 0,
    server_bootstrapped: bool = false,
    datagrams_seen: usize = 0,
    bytes_seen: usize = 0,
    tracked_connections: usize = 0,
    native_connections: usize = 0,
    native_reads_attempted: usize = 0,
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
        if (self.native_reads_attempted > 0 and self.last_error_code != 0) return "read_error";
        if (self.native_reads_attempted > 0) return "read_started";
        if (self.native_connections > 0) return "connection_created";
        if (self.datagrams_seen > 0) return "datagram_seen";
        return "idle";
    }
};

pub const Runtime = struct {
    socket_fd: std.posix.fd_t,
    thread: ?std.Thread,
    logger: *logger_mod.Logger,
    local_address: std.net.Address,
    max_datagram_size: usize,
    allow_migration: bool,
    quic_port: u16,
    tls_cert_path: []const u8,
    tls_key_path: []const u8,
    tls_min_version: []const u8,
    tls_max_version: []const u8,
    tracker: quic.ConnectionTracker,
    snapshot_mutex: std.Thread.Mutex = .{},
    snapshot_state: Snapshot,
    server: ?ngtcp2_binding.Server,
    stopping: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, logger: *logger_mod.Logger, cfg: Config) Http3RuntimeError!Runtime {
        ngtcp2_binding.validateConfig(.{
            .enable_0rtt = cfg.enable_0rtt,
            .connection_migration = cfg.connection_migration,
            .max_datagram_size = cfg.max_datagram_size,
        }) catch |err| switch (err) {
            error.DependencyUnavailable => return error.DependencyUnavailable,
            else => return error.NotYetImplemented,
        };

        const address = std.net.Address.parseIp(cfg.listen_host, cfg.quic_port) catch return error.BindFailed;
        const fd = std.posix.socket(address.any.family, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.UDP) catch return error.BindFailed;
        errdefer std.posix.close(fd);

        std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1))) catch {};
        std.posix.bind(fd, &address.any, address.getOsSockLen()) catch return error.BindFailed;
        setNonBlocking(fd, true) catch {};

        var runtime = Runtime{
            .socket_fd = fd,
            .thread = null,
            .logger = logger,
            .local_address = address,
            .max_datagram_size = cfg.max_datagram_size,
            .allow_migration = cfg.connection_migration,
            .quic_port = cfg.quic_port,
            .tls_cert_path = cfg.tls_cert_path,
            .tls_key_path = cfg.tls_key_path,
            .tls_min_version = cfg.tls_min_version,
            .tls_max_version = cfg.tls_max_version,
            .tracker = quic.ConnectionTracker.init(allocator),
            .snapshot_state = .{ .quic_port = cfg.quic_port },
            .server = null,
            .stopping = std.atomic.Value(bool).init(false),
        };
        if (cfg.tls_cert_path.len > 0 and cfg.tls_key_path.len > 0) {
            runtime.server = ngtcp2_binding.bootstrapServer(allocator, .{
                .quic_port = cfg.quic_port,
                .tls_cert_path = cfg.tls_cert_path,
                .tls_key_path = cfg.tls_key_path,
                .tls_min_version = cfg.tls_min_version,
                .tls_max_version = cfg.tls_max_version,
                .enable_0rtt = cfg.enable_0rtt,
                .connection_migration = cfg.connection_migration,
                .max_datagram_size = cfg.max_datagram_size,
            }) catch |err| switch (err) {
                error.NotYetImplemented => null,
                else => return err,
            };
        }
        runtime.refreshSnapshot();
        return runtime;
    }

    pub fn start(self: *Runtime) void {
        if (self.thread != null) return;
        self.thread = std.Thread.spawn(.{}, loopMain, .{self}) catch null;
    }

    pub fn deinit(self: *Runtime) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        std.posix.close(self.socket_fd);
        if (self.server) |*server| server.deinit();
        self.tracker.deinit();
        self.* = undefined;
    }

    pub fn snapshot(self: *Runtime) Snapshot {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        return self.snapshot_state;
    }

    fn loopMain(self: *Runtime) void {
        const allocator = std.heap.page_allocator;
        const buf = allocator.alloc(u8, self.max_datagram_size) catch return;
        defer allocator.free(buf);
        const out_buf = allocator.alloc(u8, self.max_datagram_size) catch return;
        defer allocator.free(out_buf);

        var from: std.net.Address = undefined;
        var from_len: std.posix.socklen_t = @sizeOf(std.net.Address);
        while (!self.stopping.load(.acquire) and !shutdown.isShutdownRequested()) {
            const received = std.posix.recvfrom(self.socket_fd, buf, 0, &from.any, &from_len) catch |err| switch (err) {
                error.WouldBlock => {
                    std.time.sleep(25 * std.time.ns_per_ms);
                    continue;
                },
                error.ConnectionRefused, error.ConnectionResetByPeer => continue,
                else => {
                    self.logger.warn(null, "http3 udp recv failed: {}", .{err});
                    std.time.sleep(25 * std.time.ns_per_ms);
                    continue;
                },
            };
            if (received == 0) continue;
            ingestDatagram(self, buf[0..received], from, out_buf) catch {};
            from_len = @sizeOf(std.net.Address);
        }
    }

    fn refreshSnapshot(self: *Runtime) void {
        var next = Snapshot{
            .quic_port = self.quic_port,
            .server_bootstrapped = self.server != null,
            .migration_events = self.snapshot().migration_events,
        };
        if (self.server) |*server| {
            const server_view = ngtcp2_binding.snapshot(server);
            next.datagrams_seen = server_view.datagrams_seen;
            next.bytes_seen = server_view.bytes_seen;
            next.tracked_connections = server_view.tracked_connections;
            next.native_connections = server_view.native_connections;
            next.native_reads_attempted = server_view.native_reads_attempted;
            next.handshakes_completed = server_view.handshakes_completed;
            next.stream_bytes_received = server_view.stream_bytes_received;
            next.stream_chunks_received = server_view.stream_chunks_received;
            next.requests_completed = server_view.requests_completed;
            next.packets_emitted = server_view.packets_emitted;
            next.bytes_emitted = server_view.bytes_emitted;
            next.last_error_code = server_view.last_error_code;
        }
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        next.migration_events = self.snapshot_state.migration_events;
        self.snapshot_state = next;
    }

    fn noteMigration(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.migration_events += 1;
    }
};

fn ingestDatagram(self: *Runtime, datagram: []const u8, from: std.net.Address, out_buf: []u8) !void {
    const packet = quic.parsePacket(datagram) catch return;
    if (packet.dcid.len == 0) return;
    const ip = formatAddressIp(from) orelse return;
    defer std.heap.page_allocator.free(ip);
    const migrated = try self.tracker.observe(packet, ip, from.getPort(), self.allow_migration);
    if (migrated) {
        self.noteMigration();
        self.logger.info(null, "http3 connection migration observed for dcid={s}", .{std.fmt.fmtSliceHexLower(packet.dcid)});
    }
    if (self.server) |*server| {
        const result = ngtcp2_binding.handleDatagram(server, packet, datagram, ip, self.local_address, from, out_buf) catch |err| {
            self.logger.warn(null, "http3 ngtcp2 ingest failed: {}", .{err});
            self.refreshSnapshot();
            return;
        };
        if (result.bytes_to_send > 0) {
            _ = std.posix.sendto(self.socket_fd, out_buf[0..result.bytes_to_send], 0, &from.any, from.getOsSockLen()) catch {};
        }
    }
    self.refreshSnapshot();
}

fn formatAddressIp(address: std.net.Address) ?[]u8 {
    return switch (address.any.family) {
        std.posix.AF.INET => blk: {
            const b = @as(*const [4]u8, @ptrCast(&address.in.sa.addr));
            break :blk std.fmt.allocPrint(std.heap.page_allocator, "v4:{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }) catch null;
        },
        std.posix.AF.INET6 => std.fmt.allocPrint(std.heap.page_allocator, "v6:{s}", .{std.fmt.fmtSliceHexLower(address.in6.sa.addr[0..])}) catch null,
        else => null,
    };
}

fn setNonBlocking(fd: std.posix.fd_t, enabled: bool) !void {
    const flags = try std.posix.fcntl(fd, std.posix.F.GETFL, 0);
    const nonblock_flag = @as(usize, 1) << @bitOffsetOf(std.posix.O, "NONBLOCK");
    const new_flags = if (enabled) flags | nonblock_flag else flags & ~nonblock_flag;
    _ = try std.posix.fcntl(fd, std.posix.F.SETFL, new_flags);
}
