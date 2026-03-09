const std = @import("std");
const build_options = @import("build_options");
const http3_session = @import("http3_session.zig");
const quic = @import("quic.zig");
const response_mod = @import("response.zig");
const status_mod = @import("status.zig");

pub const enabled = build_options.enable_http3_ngtcp2;

pub const Ngtcp2Error = error{
    DependencyUnavailable,
    NotYetImplemented,
    TlsBootstrapFailed,
    OutOfMemory,
};

pub const RuntimeSupport = struct {
    enabled: bool,
    ngtcp2_version: ?[]const u8,
    nghttp3_version: ?[]const u8,
};

pub const alpn_h3 = "h3";

pub const TransportConfig = struct {
    enable_0rtt: bool = false,
    connection_migration: bool = false,
    max_datagram_size: usize = 1350,
};

pub const RequestHandler = *const fn (
    allocator: std.mem.Allocator,
    request: *const http3_session.StreamRequest,
    response: *response_mod.Response,
    user_data: ?*anyopaque,
) anyerror!void;

pub const ServerBootstrap = struct {
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

pub const ServerStats = struct {
    datagrams_seen: usize = 0,
    bytes_seen: usize = 0,
    initial_packets_seen: usize = 0,
    handshake_packets_seen: usize = 0,
    zero_rtt_packets_seen: usize = 0,
    retry_packets_seen: usize = 0,
    short_packets_seen: usize = 0,
    connections_created: usize = 0,
    packets_emitted: usize = 0,
    bytes_emitted: usize = 0,
};

pub const ServerSnapshot = struct {
    datagrams_seen: usize = 0,
    bytes_seen: usize = 0,
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
    last_error_code: i32 = 0,
};

pub const DatagramResult = struct {
    bytes_to_send: usize = 0,
};

pub const TimerResult = struct {
    bytes_to_send: usize = 0,
    remote_addr: ?std.net.Address = null,
};

pub const WriteResult = TimerResult;

pub const ConnectionState = struct {
    cid_hex: []u8,
    remote_ip: []u8,
    remote_port: u16,
    packet_type: quic.PacketType,
    version: u32,
    packets_seen: usize = 0,
    bytes_seen: usize = 0,
    zero_rtt_seen: bool = false,
    native_connection_created: bool = false,
    native_read_attempted: bool = false,
    native_read_calls: usize = 0,
    handshake_complete: bool = false,
    stream_bytes_received: usize = 0,
    stream_chunks_received: usize = 0,
    requests_completed: usize = 0,
    native_last_error_code: i32 = 0,
};

pub const Binding = if (enabled) struct {
    const c = @cImport({
        @cInclude("ngtcp2/ngtcp2.h");
        @cInclude("ngtcp2/ngtcp2_crypto.h");
        @cInclude("ngtcp2/ngtcp2_crypto_ossl.h");
        @cInclude("nghttp3/nghttp3.h");
        @cInclude("openssl/ssl.h");
        @cInclude("openssl/err.h");
    });

    pub const Server = struct {
        const NativeConnection = struct {
            server_ptr: *anyopaque,
            conn: ?*c.ngtcp2_conn,
            ssl: *c.SSL,
            crypto_ctx: *c.ngtcp2_crypto_ossl_ctx,
            session: ?http3_session.ServerSession,
            stream_bytes_received: usize,
            stream_chunks_received: usize,
            requests_completed: usize,
            conn_ref: c.ngtcp2_crypto_conn_ref,
            path_storage: c.ngtcp2_path_storage,
            local_addr: std.net.Address,
            remote_addr: std.net.Address,
            scid: c.ngtcp2_cid,
            dcid: c.ngtcp2_cid,
        };

        allocator: std.mem.Allocator,
        ssl_ctx: *c.SSL_CTX,
        config: ServerBootstrap,
        stats: ServerStats = .{},
        connections: std.StringHashMap(ConnectionState),
        native_connections: std.StringHashMap(*NativeConnection),
        native_connection_aliases: std.StringHashMap([]u8),

        pub fn deinit(self: *@This()) void {
            var it = self.connections.iterator();
            while (it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.cid_hex);
                self.allocator.free(entry.value_ptr.remote_ip);
            }
            self.connections.deinit();
            var native_it = self.native_connections.iterator();
            while (native_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                const native = entry.value_ptr.*;
                _ = c.SSL_set_app_data(native.ssl, null);
                if (native.session) |*session| session.deinit();
                c.ngtcp2_conn_del(native.conn);
                c.ngtcp2_crypto_ossl_ctx_del(native.crypto_ctx);
                c.SSL_free(native.ssl);
                self.allocator.destroy(native);
            }
            self.native_connections.deinit();
            var alias_it = self.native_connection_aliases.iterator();
            while (alias_it.next()) |entry| {
                self.allocator.free(entry.key_ptr.*);
                self.allocator.free(entry.value_ptr.*);
            }
            self.native_connection_aliases.deinit();
            c.SSL_CTX_free(self.ssl_ctx);
            self.* = undefined;
        }
    };

    pub fn runtimeSupport() RuntimeSupport {
        const ngtcp2_info = c.ngtcp2_version(0);
        const nghttp3_info = c.nghttp3_version(0);
        return .{
            .enabled = true,
            .ngtcp2_version = if (ngtcp2_info != null and ngtcp2_info.*.version_str != null) std.mem.span(ngtcp2_info.*.version_str) else null,
            .nghttp3_version = if (nghttp3_info != null and nghttp3_info.*.version_str != null) std.mem.span(nghttp3_info.*.version_str) else null,
        };
    }

    pub fn validateConfig(cfg: TransportConfig) Ngtcp2Error!void {
        if (cfg.max_datagram_size == 0) return error.NotYetImplemented;
    }

    pub fn errorName(code: i32) ?[]const u8 {
        if (code == 0) return null;
        const text = c.ngtcp2_strerror(@intCast(code));
        if (text == null) return null;
        return std.mem.span(text);
    }

    pub fn snapshot(server: *const @This().Server) ServerSnapshot {
        var view = ServerSnapshot{
            .datagrams_seen = server.stats.datagrams_seen,
            .bytes_seen = server.stats.bytes_seen,
            .tracked_connections = server.connections.count(),
            .native_connections = server.native_connections.count(),
            .stream_bytes_received = 0,
            .stream_chunks_received = 0,
            .requests_completed = 0,
            .packets_emitted = server.stats.packets_emitted,
            .bytes_emitted = server.stats.bytes_emitted,
        };
        var it = server.connections.valueIterator();
        while (it.next()) |conn| {
            if (conn.native_read_attempted) view.native_reads_attempted += 1;
            view.native_read_calls += conn.native_read_calls;
            if (conn.handshake_complete) view.handshakes_completed += 1;
            view.stream_bytes_received += conn.stream_bytes_received;
            view.stream_chunks_received += conn.stream_chunks_received;
            view.requests_completed += conn.requests_completed;
            if (conn.native_last_error_code != 0) view.last_error_code = conn.native_last_error_code;
        }
        if (view.handshakes_completed == 0) {
            var native_it = server.native_connections.valueIterator();
            while (native_it.next()) |native| {
                if (c.ngtcp2_conn_get_handshake_completed(native.*.conn) != 0 or c.SSL_is_init_finished(native.*.ssl) == 1) {
                    view.handshakes_completed += 1;
                }
            }
        }
        return view;
    }

    pub fn bootstrapServer(allocator: std.mem.Allocator, cfg: ServerBootstrap) Ngtcp2Error!@This().Server {
        if (cfg.quic_port == 0 or cfg.tls_cert_path.len == 0 or cfg.tls_key_path.len == 0) return error.NotYetImplemented;
        if (!std.mem.eql(u8, cfg.tls_min_version, "1.3") or !std.mem.eql(u8, cfg.tls_max_version, "1.3")) return error.NotYetImplemented;
        try Binding.validateConfig(.{
            .enable_0rtt = cfg.enable_0rtt,
            .connection_migration = cfg.connection_migration,
            .max_datagram_size = cfg.max_datagram_size,
        });
        if (c.ngtcp2_crypto_ossl_init() != 0) return error.TlsBootstrapFailed;
        const ssl_ctx = try createQuicServerTlsContext(cfg);
        return .{
            .allocator = allocator,
            .ssl_ctx = ssl_ctx,
            .config = cfg,
            .connections = std.StringHashMap(ConnectionState).init(allocator),
            .native_connections = std.StringHashMap(*@This().Server.NativeConnection).init(allocator),
            .native_connection_aliases = std.StringHashMap([]u8).init(allocator),
        };
    }

    pub fn handleDatagram(server: *@This().Server, packet: quic.ParsedPacket, datagram: []const u8, remote_ip: []const u8, local_addr: std.net.Address, remote_addr: std.net.Address, out_buf: []u8) Ngtcp2Error!DatagramResult {
        if (datagram.len == 0) return .{};
        server.stats.datagrams_seen += 1;
        server.stats.bytes_seen += datagram.len;
        switch (packet.packet_type) {
            .initial => server.stats.initial_packets_seen += 1,
            .handshake => server.stats.handshake_packets_seen += 1,
            .zero_rtt => server.stats.zero_rtt_packets_seen += 1,
            .retry => server.stats.retry_packets_seen += 1,
            .short => server.stats.short_packets_seen += 1,
        }
        try upsertConnection(server, packet, datagram, remote_ip, remote_addr.getPort());
        if (packet.packet_type == .initial) {
            if (try findNativeConnection(server, packet) == null) {
                if (c.ngtcp2_accept(null, datagram.ptr, datagram.len) != 0) return .{};
                try ensureNativeConnection(server, packet, local_addr, remote_addr);
            }
        }
        const native = try findNativeConnection(server, packet) orelse return .{};
        const read_rc = try readNativePacket(server, native, datagram, local_addr, remote_addr);
        const bytes_to_send = if (read_rc == 0)
            try writeNativePacket(server, native, local_addr, remote_addr, out_buf)
        else
            0;
        _ = c.ngtcp2_version(0);
        return .{ .bytes_to_send = bytes_to_send };
    }

    pub fn handleExpiry(server: *@This().Server, out_buf: []u8) Ngtcp2Error!TimerResult {
        var it = server.native_connections.valueIterator();
        while (it.next()) |native_ptr| {
            const native = native_ptr.*;
            const expiry = c.ngtcp2_conn_get_expiry(native.conn);
            const now = timestampNow();
            if (expiry > now) continue;
            const rc = c.ngtcp2_conn_handle_expiry(native.conn, now);
            const handshake_complete = c.ngtcp2_conn_get_handshake_completed(native.conn) != 0;
            setConnectionStateFlags(server, native.dcid.data[0..native.dcid.datalen], true, true, handshake_complete, rc);
            if (rc != 0) continue;
            const bytes_to_send = try writeNativePacket(server, native, native.local_addr, native.remote_addr, out_buf);
            if (bytes_to_send > 0) {
                return .{ .bytes_to_send = bytes_to_send, .remote_addr = native.remote_addr };
            }
        }
        return .{};
    }

    pub fn flushPendingWrites(server: *@This().Server, out_buf: []u8) Ngtcp2Error!WriteResult {
        var it = server.native_connections.valueIterator();
        while (it.next()) |native_ptr| {
            const native = native_ptr.*;
            const bytes_to_send = try writeNativePacket(server, native, native.local_addr, native.remote_addr, out_buf);
            if (bytes_to_send > 0) {
                return .{ .bytes_to_send = bytes_to_send, .remote_addr = native.remote_addr };
            }
        }
        return .{};
    }

    fn upsertConnection(server: *@This().Server, packet: quic.ParsedPacket, datagram: []const u8, remote_ip: []const u8, remote_port: u16) !void {
        if (packet.dcid.len == 0) return;
        const cid_hex = try std.fmt.allocPrint(server.allocator, "{s}", .{std.fmt.fmtSliceHexLower(packet.dcid)});
        defer server.allocator.free(cid_hex);

        if (server.connections.getPtr(cid_hex)) |conn| {
            if (!std.mem.eql(u8, conn.remote_ip, remote_ip)) {
                server.allocator.free(conn.remote_ip);
                conn.remote_ip = try server.allocator.dupe(u8, remote_ip);
            }
            conn.remote_port = remote_port;
            conn.packet_type = packet.packet_type;
            conn.version = packet.version;
            conn.packets_seen += 1;
            conn.bytes_seen += datagram.len;
            conn.zero_rtt_seen = conn.zero_rtt_seen or packet.packet_type == .zero_rtt;
            return;
        }

        const key = try server.allocator.dupe(u8, cid_hex);
        errdefer server.allocator.free(key);
        const conn_cid = try server.allocator.dupe(u8, cid_hex);
        errdefer server.allocator.free(conn_cid);
        const ip = try server.allocator.dupe(u8, remote_ip);
        errdefer server.allocator.free(ip);
        try server.connections.put(key, .{
            .cid_hex = conn_cid,
            .remote_ip = ip,
            .remote_port = remote_port,
            .packet_type = packet.packet_type,
            .version = packet.version,
            .packets_seen = 1,
            .bytes_seen = datagram.len,
            .zero_rtt_seen = packet.packet_type == .zero_rtt,
        });
        server.stats.connections_created += 1;
    }

    fn ensureNativeConnection(server: *@This().Server, packet: quic.ParsedPacket, local_addr: std.net.Address, remote_addr: std.net.Address) !void {
        const original_dcid = packet.dcid;
        if (original_dcid.len == 0) return;
        if (packet.scid.len == 0) return;

        const cid_hex = try std.fmt.allocPrint(server.allocator, "{s}", .{std.fmt.fmtSliceHexLower(original_dcid)});
        defer server.allocator.free(cid_hex);
        if (server.native_connections.contains(cid_hex)) return;

        const ssl = c.SSL_new(server.ssl_ctx) orelse return error.TlsBootstrapFailed;
        errdefer c.SSL_free(ssl);
        c.SSL_set_accept_state(ssl);

        var crypto_ctx: ?*c.ngtcp2_crypto_ossl_ctx = null;
        if (c.ngtcp2_crypto_ossl_ctx_new(&crypto_ctx, ssl) != 0 or crypto_ctx == null) return error.TlsBootstrapFailed;
        errdefer c.ngtcp2_crypto_ossl_ctx_del(crypto_ctx.?);

        const native = try server.allocator.create(@This().Server.NativeConnection);
        errdefer server.allocator.destroy(native);
        native.* = .{
            .server_ptr = server,
            .conn = null,
            .ssl = ssl,
            .crypto_ctx = crypto_ctx.?,
            .session = try http3_session.ServerSession.init(server.allocator),
            .stream_bytes_received = 0,
            .stream_chunks_received = 0,
            .requests_completed = 0,
            .conn_ref = .{
                .get_conn = getConnFromRef,
                .user_data = null,
            },
            .path_storage = undefined,
            .local_addr = local_addr,
            .remote_addr = remote_addr,
            .scid = undefined,
            .dcid = undefined,
        };

        var callbacks = std.mem.zeroes(c.ngtcp2_callbacks);
        callbacks.recv_client_initial = c.ngtcp2_crypto_recv_client_initial_cb;
        callbacks.recv_crypto_data = c.ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.handshake_completed = handshakeCompletedCb;
        callbacks.encrypt = c.ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = c.ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = c.ngtcp2_crypto_hp_mask_cb;
        callbacks.recv_stream_data = recvStreamDataCb;
        callbacks.acked_stream_data_offset = ackedStreamDataOffsetCb;
        callbacks.stream_close = streamCloseCb;
        callbacks.rand = randCb;
        callbacks.get_new_connection_id = getNewConnectionIdCb;
        callbacks.update_key = c.ngtcp2_crypto_update_key_cb;
        callbacks.extend_max_remote_streams_bidi = extendMaxRemoteStreamsBidiCb;
        callbacks.extend_max_stream_data = extendMaxStreamDataCb;
        callbacks.delete_crypto_aead_ctx = c.ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = c.ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data = c.ngtcp2_crypto_get_path_challenge_data_cb;
        callbacks.version_negotiation = c.ngtcp2_crypto_version_negotiation_cb;
        callbacks.recv_tx_key = recvTxKeyCb;

        var settings: c.ngtcp2_settings = undefined;
        c.ngtcp2_settings_default(&settings);
        settings.initial_ts = timestampNow();
        settings.max_tx_udp_payload_size = @intCast(server.config.max_datagram_size);

        var params: c.ngtcp2_transport_params = undefined;
        c.ngtcp2_transport_params_default(&params);
        params.initial_max_stream_data_bidi_local = 1 * 1024 * 1024;
        params.initial_max_stream_data_bidi_remote = 1 * 1024 * 1024;
        params.initial_max_stream_data_uni = 1 * 1024 * 1024;
        params.initial_max_data = 4 * 1024 * 1024;
        params.initial_max_streams_bidi = 32;
        params.initial_max_streams_uni = 32;
        params.max_idle_timeout = 30 * std.time.ns_per_s;
        params.max_udp_payload_size = server.config.max_datagram_size;
        params.active_connection_id_limit = 7;
        params.disable_active_migration = if (server.config.connection_migration) 0 else 1;
        params.grease_quic_bit = 1;

        c.ngtcp2_cid_init(&native.dcid, original_dcid.ptr, original_dcid.len);
        params.original_dcid = native.dcid;
        params.original_dcid_present = 1;
        var client_scid: c.ngtcp2_cid = undefined;
        c.ngtcp2_cid_init(&client_scid, packet.scid.ptr, packet.scid.len);
        var scid_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&scid_bytes);
        c.ngtcp2_cid_init(&native.scid, &scid_bytes, scid_bytes.len);
        c.ngtcp2_path_storage_init(
            &native.path_storage,
            @ptrCast(&local_addr.any),
            local_addr.getOsSockLen(),
            @ptrCast(&remote_addr.any),
            remote_addr.getOsSockLen(),
            null,
        );

        if (c.ngtcp2_conn_server_new(
            &native.conn,
            &client_scid,
            &native.scid,
            &native.path_storage.path,
            packet.version,
            &callbacks,
            &settings,
            &params,
            c.ngtcp2_mem_default(),
            native,
        ) != 0) return error.NotYetImplemented;
        errdefer if (native.conn) |conn| c.ngtcp2_conn_del(conn);
        errdefer if (native.session) |*session| session.deinit();

        native.conn_ref.user_data = native;
        c.ngtcp2_conn_set_tls_native_handle(native.conn, native.crypto_ctx);
        _ = c.SSL_set_app_data(native.ssl, &native.conn_ref);
        if (c.ngtcp2_crypto_ossl_configure_server_session(native.ssl) != 0) return error.TlsBootstrapFailed;
        _ = c.SSL_set_quic_tls_early_data_enabled(native.ssl, 1);

        const key = try server.allocator.dupe(u8, cid_hex);
        errdefer server.allocator.free(key);
        try server.native_connections.put(key, native);
        try addNativeAlias(server, native.scid.data[0..native.scid.datalen], key);
        setConnectionStateFlags(server, packet.dcid, true, false, false, 0);
    }

    fn readNativePacket(server: *@This().Server, native: *@This().Server.NativeConnection, datagram: []const u8, local_addr: std.net.Address, remote_addr: std.net.Address) !c_int {
        native.local_addr = local_addr;
        native.remote_addr = remote_addr;
        c.ngtcp2_path_storage_init(
            &native.path_storage,
            @ptrCast(&local_addr.any),
            local_addr.getOsSockLen(),
            @ptrCast(&remote_addr.any),
            remote_addr.getOsSockLen(),
            null,
        );
        var pkt_info = std.mem.zeroes(c.ngtcp2_pkt_info);
        pkt_info.ecn = c.NGTCP2_ECN_NOT_ECT;
        const rc = c.ngtcp2_conn_read_pkt(
            native.conn,
            &native.path_storage.path,
            &pkt_info,
            datagram.ptr,
            datagram.len,
            timestampNow(),
        );
        if (c.SSL_is_init_finished(native.ssl) == 1) {
            c.ngtcp2_conn_tls_handshake_completed(native.conn);
            if (native.session) |*session| {
                if (!session.isActivated() and native.conn != null) {
                    session.activate(@ptrCast(native.conn.?)) catch |err| {
                        std.debug.print("http3 session activation failed: {any}\n", .{err});
                    };
                    if (session.isActivated()) std.debug.print("http3 session activated after tls finish\n", .{});
                }
            }
        }
        if (rc != 0 and native.conn != null) {
            const ccerr = c.ngtcp2_conn_get_ccerr(native.conn.?);
            std.debug.print("http3 read rc={d} ccerr_type={d} ccerr_code={d}\n", .{ rc, ccerr.*.type, ccerr.*.error_code });
        }
        const handshake_complete = c.ngtcp2_conn_get_handshake_completed(native.conn) != 0;
        setConnectionStateFlags(server, native.dcid.data[0..native.dcid.datalen], true, true, handshake_complete, rc);
        return rc;
    }

    fn writeNativePacket(server: *@This().Server, native: *@This().Server.NativeConnection, local_addr: std.net.Address, remote_addr: std.net.Address, out_buf: []u8) !usize {
        if (out_buf.len == 0) return 0;
        c.ngtcp2_path_storage_init(
            &native.path_storage,
            @ptrCast(&local_addr.any),
            local_addr.getOsSockLen(),
            @ptrCast(&remote_addr.any),
            remote_addr.getOsSockLen(),
            null,
        );
        var pkt_info = std.mem.zeroes(c.ngtcp2_pkt_info);
        pkt_info.ecn = c.NGTCP2_ECN_NOT_ECT;
        const handshake_complete = c.ngtcp2_conn_get_handshake_completed(native.conn) != 0;
        const written = if (native.session != null and native.session.?.isActivated() and handshake_complete)
            try writeNativeHttp3Packet(native, &native.path_storage.path, &pkt_info, out_buf)
        else
            c.ngtcp2_conn_write_pkt(
                native.conn,
                &native.path_storage.path,
                &pkt_info,
                out_buf.ptr,
                out_buf.len,
                timestampNow(),
            );
        if (written < 0) {
            setConnectionStateFlags(server, native.dcid.data[0..native.dcid.datalen], true, true, false, @intCast(written));
            return 0;
        }
        if (written == 0) return 0;
        server.stats.packets_emitted += 1;
        server.stats.bytes_emitted += @intCast(written);
        return @intCast(written);
    }

    fn writeNativeHttp3Packet(native: *@This().Server.NativeConnection, path: *c.ngtcp2_path, pkt_info: *c.ngtcp2_pkt_info, out_buf: []u8) !c.ngtcp2_ssize {
        const session = &(native.session.?);
        const http3_conn: *c.nghttp3_conn = @ptrCast(@alignCast(session.rawConn()));
        var vecs: [16]c.nghttp3_vec = undefined;

        while (true) {
            var stream_id: i64 = -1;
            var fin: c_int = 0;
            var stream_vec_count: c.nghttp3_ssize = 0;

            if (c.ngtcp2_conn_get_max_data_left(native.conn) != 0) {
                stream_vec_count = c.nghttp3_conn_writev_stream(http3_conn, &stream_id, &fin, &vecs, vecs.len);
                if (stream_vec_count < 0) {
                    std.debug.print("http3 writev_stream failed: {d}\n", .{stream_vec_count});
                    return error.NotYetImplemented;
                }
            }
            const vec_count: usize = @intCast(@max(stream_vec_count, 0));
            const quic_vec_ptr: [*c]const c.ngtcp2_vec = if (vec_count == 0) null else @as([*c]const c.ngtcp2_vec, @ptrCast(vecs[0..vec_count].ptr));

            var data_written: c.ngtcp2_ssize = -1;
            var flags: u32 = c.NGTCP2_WRITE_STREAM_FLAG_MORE | c.NGTCP2_WRITE_STREAM_FLAG_PADDING;
            if (fin != 0) flags |= c.NGTCP2_WRITE_STREAM_FLAG_FIN;

            const packet_written = c.ngtcp2_conn_writev_stream(
                native.conn,
                path,
                pkt_info,
                out_buf.ptr,
                out_buf.len,
                &data_written,
                flags,
                stream_id,
                quic_vec_ptr,
                vec_count,
                timestampNow(),
            );
            if (packet_written < 0) {
                switch (packet_written) {
                    c.NGTCP2_ERR_STREAM_DATA_BLOCKED => {
                        std.debug.print("http3 stream data blocked: stream_id={d}\n", .{stream_id});
                        if (stream_id >= 0) _ = c.nghttp3_conn_block_stream(http3_conn, stream_id);
                        continue;
                    },
                    c.NGTCP2_ERR_STREAM_SHUT_WR => {
                        std.debug.print("http3 stream shutdown write: stream_id={d}\n", .{stream_id});
                        if (stream_id >= 0) _ = c.nghttp3_conn_shutdown_stream_write(http3_conn, stream_id);
                        continue;
                    },
                    c.NGTCP2_ERR_WRITE_MORE => {
                        std.debug.print("http3 write more: stream_id={d} data_written={d}\n", .{ stream_id, data_written });
                        if (stream_id >= 0 and data_written >= 0) {
                            _ = c.nghttp3_conn_add_write_offset(http3_conn, stream_id, @intCast(data_written));
                            session.addWriteOffset(stream_id, @intCast(data_written));
                        }
                        continue;
                    },
                    else => {
                        std.debug.print("http3 ngtcp2 writev_stream failed: {d}\n", .{packet_written});
                        return packet_written;
                    },
                }
            }

            if (stream_id >= 0 and data_written >= 0) {
                std.debug.print("http3 wrote stream data: stream_id={d} data_written={d} packet_written={d} fin={d}\n", .{ stream_id, data_written, packet_written, fin });
                _ = c.nghttp3_conn_add_write_offset(http3_conn, stream_id, @intCast(data_written));
                session.addWriteOffset(stream_id, @intCast(data_written));
            }
            return packet_written;
        }
    }

    fn findNativeConnection(server: *@This().Server, packet: quic.ParsedPacket) !?*@This().Server.NativeConnection {
        if (packet.scid.len > 0) {
            if (try lookupNativeConnection(server, packet.scid)) |native| return native;
        }
        if (packet.dcid.len > 0) {
            if (try lookupNativeConnection(server, packet.dcid)) |native| return native;
        }
        return null;
    }

    fn lookupNativeConnection(server: *@This().Server, cid: []const u8) !?*@This().Server.NativeConnection {
        if (cid.len == 0) return null;
        const cid_hex = try std.fmt.allocPrint(server.allocator, "{s}", .{std.fmt.fmtSliceHexLower(cid)});
        defer server.allocator.free(cid_hex);
        if (server.native_connections.getPtr(cid_hex)) |native| return native.*;
        if (server.native_connection_aliases.get(cid_hex)) |primary_key| {
            if (server.native_connections.getPtr(primary_key)) |entry| return entry.*;
        }
        return null;
    }

    fn addNativeAlias(server: *@This().Server, alias_cid: []const u8, primary_key: []const u8) !void {
        if (alias_cid.len == 0) return;
        const alias_hex = try std.fmt.allocPrint(server.allocator, "{s}", .{std.fmt.fmtSliceHexLower(alias_cid)});
        defer server.allocator.free(alias_hex);
        if (server.native_connection_aliases.contains(alias_hex)) return;
        const key = try server.allocator.dupe(u8, alias_hex);
        errdefer server.allocator.free(key);
        const value = try server.allocator.dupe(u8, primary_key);
        errdefer server.allocator.free(value);
        try server.native_connection_aliases.put(key, value);
    }

    fn setConnectionStateFlags(server: *@This().Server, cid: []const u8, native_created: bool, read_attempted: bool, handshake_complete: bool, last_error_code: c_int) void {
        if (cid.len == 0) return;
        const cid_hex = std.fmt.allocPrint(server.allocator, "{s}", .{std.fmt.fmtSliceHexLower(cid)}) catch return;
        defer server.allocator.free(cid_hex);
        if (server.connections.getPtr(cid_hex)) |conn| {
            conn.native_connection_created = conn.native_connection_created or native_created;
            conn.native_read_attempted = conn.native_read_attempted or read_attempted;
            if (read_attempted) conn.native_read_calls += 1;
            conn.handshake_complete = conn.handshake_complete or handshake_complete;
            conn.native_last_error_code = last_error_code;
        }
    }

    fn noteStreamData(server: *@This().Server, cid: []const u8, datalen: usize, completed_request: bool) void {
        if (cid.len == 0) return;
        const cid_hex = std.fmt.allocPrint(server.allocator, "{s}", .{std.fmt.fmtSliceHexLower(cid)}) catch return;
        defer server.allocator.free(cid_hex);
        if (server.connections.getPtr(cid_hex)) |conn| {
            conn.stream_bytes_received += datalen;
            conn.stream_chunks_received += 1;
            if (completed_request) conn.requests_completed += 1;
        }
    }

    fn timestampNow() c.ngtcp2_tstamp {
        return @intCast(std.time.nanoTimestamp());
    }

    fn getConnFromRef(ref: [*c]c.ngtcp2_crypto_conn_ref) callconv(.c) ?*c.ngtcp2_conn {
        const conn_ref: *c.ngtcp2_crypto_conn_ref = @ptrCast(ref);
        const native: *@This().Server.NativeConnection = @ptrCast(@alignCast(conn_ref.user_data.?));
        return native.conn;
    }

    fn handshakeCompletedCb(_: ?*c.ngtcp2_conn, user_data: ?*anyopaque) callconv(.c) c_int {
        const native: *@This().Server.NativeConnection = @ptrCast(@alignCast(user_data orelse return -1));
        const server: *@This().Server = @ptrCast(@alignCast(native.server_ptr));
        setConnectionStateFlags(server, native.dcid.data[0..native.dcid.datalen], true, true, true, 0);
        return 0;
    }

    fn recvStreamDataCb(conn: ?*c.ngtcp2_conn, flags: u32, stream_id: i64, _: u64, data: [*c]const u8, datalen: usize, user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        const native: *@This().Server.NativeConnection = @ptrCast(@alignCast(user_data orelse return c.NGTCP2_ERR_CALLBACK_FAILURE));
        const server: *@This().Server = @ptrCast(@alignCast(native.server_ptr));
        const fin = (flags & c.NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
        if (native.session) |*session| {
            const consumed = session.ingestRequestBytes(stream_id, data[0..datalen], fin) catch |err| {
                std.debug.print("http3 ingest request bytes failed: stream_id={d} datalen={d} fin={} err={any}\n", .{ stream_id, datalen, fin, err });
                return c.NGTCP2_ERR_CALLBACK_FAILURE;
            };
            std.debug.print("http3 recv stream data: stream_id={d} datalen={d} consumed={d} fin={}\n", .{ stream_id, datalen, consumed, fin });
            if (conn) |quic_conn| {
                _ = c.ngtcp2_conn_extend_max_stream_offset(quic_conn, stream_id, consumed);
                c.ngtcp2_conn_extend_max_offset(quic_conn, consumed);
            }
            native.stream_bytes_received += datalen;
            native.stream_chunks_received += 1;
            var completed = false;
            if (session.takeCompletedRequest(stream_id)) |request| {
                completed = true;
                native.requests_completed += 1;
                var owned_request = request;
                var response = response_mod.Response.init(server.allocator);
                defer response.deinit();
                if (server.config.request_handler) |handler| {
                    handler(server.allocator, &owned_request, &response, server.config.request_handler_ctx) catch |err| {
                        std.debug.print("http3 request handler failed: stream_id={d} err={any}\n", .{ stream_id, err });
                        owned_request.deinit();
                        return c.NGTCP2_ERR_CALLBACK_FAILURE;
                    };
                } else {
                    populateFallbackResponse(&response, &owned_request);
                }
                session.submitResponse(server.allocator, stream_id, &response) catch |err| {
                    std.debug.print("http3 submit response failed: stream_id={d} err={any}\n", .{ stream_id, err });
                    owned_request.deinit();
                    return c.NGTCP2_ERR_CALLBACK_FAILURE;
                };
                owned_request.deinit();
            }
            noteStreamData(server, native.dcid.data[0..native.dcid.datalen], datalen, completed);
        }
        return 0;
    }

    fn ackedStreamDataOffsetCb(_: ?*c.ngtcp2_conn, stream_id: i64, _: u64, datalen: u64, user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        const native: *@This().Server.NativeConnection = @ptrCast(@alignCast(user_data orelse return c.NGTCP2_ERR_CALLBACK_FAILURE));
        if (native.session) |*session| {
            session.addAckOffset(stream_id, datalen) catch return c.NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    fn streamCloseCb(_: ?*c.ngtcp2_conn, _: u32, stream_id: i64, _: u64, user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        const native: *@This().Server.NativeConnection = @ptrCast(@alignCast(user_data orelse return c.NGTCP2_ERR_CALLBACK_FAILURE));
        if (native.session) |*session| session.closeStream(stream_id);
        return 0;
    }

    fn randCb(dest: [*c]u8, destlen: usize, _: [*c]const c.ngtcp2_rand_ctx) callconv(.c) void {
        std.crypto.random.bytes(dest[0..destlen]);
    }

    fn getNewConnectionIdCb(_: ?*c.ngtcp2_conn, cid: [*c]c.ngtcp2_cid, token: [*c]u8, cidlen: usize, _: ?*anyopaque) callconv(.c) c_int {
        var cid_bytes: [c.NGTCP2_MAX_CIDLEN]u8 = undefined;
        std.crypto.random.bytes(cid_bytes[0..cidlen]);
        c.ngtcp2_cid_init(cid, &cid_bytes, cidlen);
        std.crypto.random.bytes(token[0..c.NGTCP2_STATELESS_RESET_TOKENLEN]);
        return 0;
    }

    fn extendMaxRemoteStreamsBidiCb(_: ?*c.ngtcp2_conn, max_streams: u64, user_data: ?*anyopaque) callconv(.c) c_int {
        const native: *@This().Server.NativeConnection = @ptrCast(@alignCast(user_data orelse return c.NGTCP2_ERR_CALLBACK_FAILURE));
        if (native.session) |*session| {
            session.setMaxClientStreamsBidi(max_streams);
        }
        return 0;
    }

    fn extendMaxStreamDataCb(_: ?*c.ngtcp2_conn, stream_id: i64, _: u64, user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        const native: *@This().Server.NativeConnection = @ptrCast(@alignCast(user_data orelse return c.NGTCP2_ERR_CALLBACK_FAILURE));
        if (native.session) |*session| {
            session.unblockStream(stream_id) catch return c.NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    fn recvTxKeyCb(conn: ?*c.ngtcp2_conn, level: c.ngtcp2_encryption_level, user_data: ?*anyopaque) callconv(.c) c_int {
        std.debug.print("http3 recv_tx_key level={d} has_conn={} has_user_data={}\n", .{ level, conn != null, user_data != null });
        if (level != c.NGTCP2_ENCRYPTION_LEVEL_1RTT) return 0;
        if (conn == null or user_data == null) return 0;
        const native: *@This().Server.NativeConnection = @ptrCast(@alignCast(user_data.?));
        if (native.session) |*session| {
            if (!session.isActivated()) {
                session.activate(@ptrCast(conn.?)) catch |err| {
                    std.debug.print("http3 recv_tx_key activation failed: {any}\n", .{err});
                };
                std.debug.print("http3 recv_tx_key activation state={}\n", .{session.isActivated()});
            }
        }
        return 0;
    }

    fn populateFallbackResponse(response: *response_mod.Response, request: *const http3_session.StreamRequest) void {
        if (std.mem.eql(u8, request.method, "GET") and std.mem.eql(u8, request.path, "/health")) {
            _ = response
                .setStatus(.ok)
                .setHeader("content-type", "application/json")
                .setHeader("server", "tardigrade/http3")
                .setContentLength(0);
            return;
        }
        _ = response
            .setStatus(.not_found)
            .setHeader("content-type", "text/plain")
            .setHeader("server", "tardigrade/http3")
            .setContentLength(0);
    }

    fn createQuicServerTlsContext(cfg: ServerBootstrap) Ngtcp2Error!*c.SSL_CTX {
        if (c.OPENSSL_init_ssl(0, null) != 1) return error.TlsBootstrapFailed;
        const method = c.TLS_method() orelse return error.TlsBootstrapFailed;
        const ctx = c.SSL_CTX_new(method) orelse return error.TlsBootstrapFailed;
        errdefer c.SSL_CTX_free(ctx);

        if (c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_3_VERSION) != 1) return error.TlsBootstrapFailed;
        if (c.SSL_CTX_set_max_proto_version(ctx, c.TLS1_3_VERSION) != 1) return error.TlsBootstrapFailed;
        c.SSL_CTX_set_alpn_select_cb(ctx, selectAlpnCb, null);

        const cert_path_z = std.heap.c_allocator.dupeZ(u8, cfg.tls_cert_path) catch return error.TlsBootstrapFailed;
        defer std.heap.c_allocator.free(cert_path_z);
        const key_path_z = std.heap.c_allocator.dupeZ(u8, cfg.tls_key_path) catch return error.TlsBootstrapFailed;
        defer std.heap.c_allocator.free(key_path_z);

        if (c.SSL_CTX_use_certificate_file(ctx, cert_path_z.ptr, c.SSL_FILETYPE_PEM) != 1) return error.TlsBootstrapFailed;
        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_path_z.ptr, c.SSL_FILETYPE_PEM) != 1) return error.TlsBootstrapFailed;
        if (c.SSL_CTX_check_private_key(ctx) != 1) return error.TlsBootstrapFailed;

        return ctx;
    }

    fn selectAlpnCb(ssl: ?*c.SSL, out: [*c][*c]const u8, outlen: [*c]u8, in: [*c]const u8, inlen: c_uint, _: ?*anyopaque) callconv(.c) c_int {
        const conn_ref = c.SSL_get_app_data(ssl) orelse return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        const typed_ref: *c.ngtcp2_crypto_conn_ref = @ptrCast(@alignCast(conn_ref));
        const get_conn = typed_ref.get_conn orelse return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        const conn = get_conn(typed_ref) orelse return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        const version = c.ngtcp2_conn_get_client_chosen_version(conn);
        switch (version) {
            c.NGTCP2_PROTO_VER_V1, c.NGTCP2_PROTO_VER_V2 => {},
            else => return c.SSL_TLSEXT_ERR_ALERT_FATAL,
        }

        const protocols = in[0..inlen];
        const h3 = c.NGHTTP3_ALPN_H3[0..3];
        var offset: usize = 0;
        while (offset < protocols.len) {
            const proto_len = protocols[offset];
            offset += 1;
            if (offset + proto_len > protocols.len) break;
            if (proto_len == h3[0] and std.mem.eql(u8, protocols[offset - 1 .. offset + proto_len], h3)) {
                out.* = @ptrCast(&in[offset]);
                outlen.* = @intCast(proto_len);
                return c.SSL_TLSEXT_ERR_OK;
            }
            offset += proto_len;
        }
        return c.SSL_TLSEXT_ERR_ALERT_FATAL;
    }
} else struct {
    pub const Server = struct {
        stats: ServerStats = .{},

        pub fn deinit(self: *@This()) void {
            self.* = undefined;
        }
    };

    pub fn runtimeSupport() RuntimeSupport {
        return .{
            .enabled = false,
            .ngtcp2_version = null,
            .nghttp3_version = null,
        };
    }

    pub fn validateConfig(cfg: TransportConfig) Ngtcp2Error!void {
        _ = cfg;
        return error.DependencyUnavailable;
    }

    pub fn errorName(_: i32) ?[]const u8 {
        return null;
    }

    pub fn snapshot(_: *const @This().Server) ServerSnapshot {
        return .{};
    }

    pub fn bootstrapServer(_: std.mem.Allocator, cfg: ServerBootstrap) Ngtcp2Error!@This().Server {
        _ = cfg;
        return error.DependencyUnavailable;
    }

    pub fn handleDatagram(_: *@This().Server, _: quic.ParsedPacket, _: []const u8, _: []const u8, _: std.net.Address, _: std.net.Address, _: []u8) Ngtcp2Error!DatagramResult {
        return error.DependencyUnavailable;
    }

    pub fn handleExpiry(_: *@This().Server, _: []u8) Ngtcp2Error!TimerResult {
        return error.DependencyUnavailable;
    }

    pub fn flushPendingWrites(_: *@This().Server, _: []u8) Ngtcp2Error!WriteResult {
        return error.DependencyUnavailable;
    }
};

pub const Server = Binding.Server;

pub fn runtimeSupport() RuntimeSupport {
    return Binding.runtimeSupport();
}

pub fn validateConfig(cfg: TransportConfig) Ngtcp2Error!void {
    return Binding.validateConfig(cfg);
}

pub fn errorName(code: i32) ?[]const u8 {
    return Binding.errorName(code);
}

pub fn snapshot(server: *const Server) ServerSnapshot {
    return Binding.snapshot(server);
}

pub fn bootstrapServer(allocator: std.mem.Allocator, cfg: ServerBootstrap) Ngtcp2Error!Server {
    return Binding.bootstrapServer(allocator, cfg);
}

pub fn handleDatagram(server: *Server, packet: quic.ParsedPacket, datagram: []const u8, remote_ip: []const u8, local_addr: std.net.Address, remote_addr: std.net.Address, out_buf: []u8) Ngtcp2Error!DatagramResult {
    return Binding.handleDatagram(server, packet, datagram, remote_ip, local_addr, remote_addr, out_buf);
}

pub fn handleExpiry(server: *Server, out_buf: []u8) Ngtcp2Error!TimerResult {
    return Binding.handleExpiry(server, out_buf);
}

pub fn flushPendingWrites(server: *Server, out_buf: []u8) Ngtcp2Error!WriteResult {
    return Binding.flushPendingWrites(server, out_buf);
}

test "runtime support reports disabled when ngtcp2 integration is off" {
    if (enabled) return;
    const support = runtimeSupport();
    try std.testing.expect(!support.enabled);
    try std.testing.expect(support.ngtcp2_version == null);
    try std.testing.expectError(error.DependencyUnavailable, validateConfig(.{}));
    try std.testing.expectError(error.DependencyUnavailable, bootstrapServer(std.testing.allocator, .{ .quic_port = 443 }));
    var server = Server{};
    const packet = quic.ParsedPacket{
        .packet_type = .initial,
        .version = 1,
        .dcid = &.{ 0xaa },
        .scid = "",
        .token = "",
        .payload = "",
    };
    const local_addr = try std.net.Address.parseIp("127.0.0.1", 443);
    const remote_addr = try std.net.Address.parseIp("127.0.0.1", 44444);
    var out_buf: [64]u8 = undefined;
    try std.testing.expectError(error.DependencyUnavailable, handleDatagram(&server, packet, "hello", "127.0.0.1", local_addr, remote_addr, &out_buf));
}

test "enabled binding ignores malformed initial packets before native bootstrap" {
    if (!enabled) return;

    const allocator = std.testing.allocator;
    var server = try bootstrapServer(allocator, .{
        .quic_port = 9444,
        .tls_cert_path = "tests/fixtures/tls/server.crt",
        .tls_key_path = "tests/fixtures/tls/server.key",
    });
    defer server.deinit();

    const datagram = [_]u8{
        0xC0, 0x00, 0x00, 0x00, 0x01,
        0x08, 0xde, 0xad, 0xbe, 0xef, 0x10, 0x20, 0x30, 0x40,
        0x08, 0xca, 0xfe, 0xba, 0xbe, 0x50, 0x60, 0x70, 0x80,
        0x01, 0x42, 0xaa, 0xbb,
    };
    const packet = try quic.parsePacket(&datagram);
    const local_addr = try std.net.Address.parseIp("127.0.0.1", 9444);
    const remote_addr = try std.net.Address.parseIp("127.0.0.1", 44444);

    var out_buf: [1500]u8 = undefined;
    const result = try handleDatagram(&server, packet, &datagram, "v4:127.0.0.1", local_addr, remote_addr, &out_buf);

    const view = snapshot(&server);
    try std.testing.expectEqual(@as(usize, 1), view.datagrams_seen);
    try std.testing.expectEqual(@as(usize, 1), view.tracked_connections);
    try std.testing.expectEqual(@as(usize, 0), view.native_connections);
    try std.testing.expectEqual(@as(usize, 0), view.native_reads_attempted);
    try std.testing.expectEqual(@as(usize, 0), result.bytes_to_send);
}
