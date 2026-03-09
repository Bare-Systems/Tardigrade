const std = @import("std");

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509_vfy.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/crypto.h");
});

extern fn SSL_CTX_set_alpn_select_cb(
    ctx: *c.SSL_CTX,
    cb: *const fn (?*c.SSL, [*c][*c]u8, [*c]u8, [*c]const u8, c_uint, ?*anyopaque) callconv(.c) c_int,
    arg: ?*anyopaque,
) void;

const ssl_op_no_ticket: c_ulong = @as(c_ulong, 1) << @as(u6, 14);
const openssl_npn_negotiated: c_int = 1;

pub const TlsError = error{
    OutOfMemory,
    OpenSslInitFailed,
    ContextInitFailed,
    CertificateLoadFailed,
    PrivateKeyLoadFailed,
    CertificateKeyMismatch,
    ProtocolConfigFailed,
    CipherConfigFailed,
    VerifyConfigFailed,
    CrlLoadFailed,
    OcspLoadFailed,
    HandshakeFailed,
    TlsReadFailed,
    TlsWriteFailed,
};

pub const SniCertSpec = struct {
    server_name: []const u8,
    cert_path: []const u8,
    key_path: []const u8,
};

pub const TlsOptions = struct {
    cert_path: []const u8,
    key_path: []const u8,
    min_version: []const u8 = "1.2",
    max_version: []const u8 = "1.3",
    cipher_list: []const u8 = "",
    cipher_suites: []const u8 = "",
    sni_certs: []const SniCertSpec = &[_]SniCertSpec{},
    session_cache_enabled: bool = true,
    session_cache_size: u32 = 20_480,
    session_timeout_seconds: u32 = 300,
    session_tickets_enabled: bool = true,
    ocsp_stapling_enabled: bool = false,
    ocsp_response_path: []const u8 = "",
    client_ca_path: []const u8 = "",
    client_verify: bool = false,
    client_verify_depth: u32 = 3,
    crl_path: []const u8 = "",
    crl_check: bool = false,
    dynamic_reload_interval_ms: u64 = 5_000,
    acme_enabled: bool = false,
    acme_cert_dir: []const u8 = "",
    http2_enabled: bool = true,
};

pub const NegotiatedProtocol = enum {
    http1_1,
    http2,
};

const ManagedSniCert = struct {
    host_lc: []u8,
    cert_path_z: [:0]u8,
    key_path_z: [:0]u8,
};

const State = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    dynamic_reload_interval_ms: u64,
    next_reload_ms: u64 = 0,
    default_cert_path: []const u8,
    default_key_path: []const u8,
    default_cert_mtime: ?i128 = null,
    default_key_mtime: ?i128 = null,
    ocsp_enabled: bool,
    ocsp_response_path: []const u8,
    ocsp_response: ?[]u8 = null,
    ocsp_mtime: ?i128 = null,
    client_ca_path: []const u8,
    crl_path: []const u8,
    crl_check: bool,
    acme_enabled: bool,
    acme_cert_dir: []const u8,
    static_sni_specs: []const SniCertSpec,
    sni_certs: std.ArrayList(ManagedSniCert),
    http2_enabled: bool,

    fn deinit(self: *State) void {
        if (self.ocsp_response) |resp| self.allocator.free(resp);
        for (self.sni_certs.items) |sc| {
            self.allocator.free(sc.host_lc);
            std.heap.c_allocator.free(sc.cert_path_z);
            std.heap.c_allocator.free(sc.key_path_z);
        }
        self.sni_certs.deinit();
    }
};

pub const TlsTerminator = struct {
    allocator: std.mem.Allocator,
    ctx: *c.SSL_CTX,
    state: *State,

    pub fn init(allocator: std.mem.Allocator, opts: TlsOptions) TlsError!TlsTerminator {
        if (c.OPENSSL_init_ssl(0, null) != 1) return error.OpenSslInitFailed;

        const method = c.TLS_server_method() orelse return error.ContextInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return error.ContextInitFailed;
        errdefer c.SSL_CTX_free(ctx);

        var st = try allocator.create(State);
        errdefer allocator.destroy(st);
        st.* = .{
            .allocator = allocator,
            .dynamic_reload_interval_ms = opts.dynamic_reload_interval_ms,
            .default_cert_path = opts.cert_path,
            .default_key_path = opts.key_path,
            .ocsp_enabled = opts.ocsp_stapling_enabled,
            .ocsp_response_path = opts.ocsp_response_path,
            .client_ca_path = opts.client_ca_path,
            .crl_path = opts.crl_path,
            .crl_check = opts.crl_check,
            .acme_enabled = opts.acme_enabled,
            .acme_cert_dir = opts.acme_cert_dir,
            .static_sni_specs = opts.sni_certs,
            .sni_certs = std.ArrayList(ManagedSniCert).init(allocator),
            .http2_enabled = opts.http2_enabled,
        };
        errdefer st.deinit();

        try configureProtocolVersions(ctx, opts.min_version, opts.max_version);
        try configureCiphers(ctx, opts.cipher_list, opts.cipher_suites);
        try loadDefaultCertificate(ctx, st);
        try configureSessionCache(ctx, opts.session_cache_enabled, opts.session_cache_size, opts.session_timeout_seconds, opts.session_tickets_enabled);
        try configureClientVerification(ctx, opts.client_ca_path, opts.client_verify, opts.client_verify_depth);
        if (opts.crl_check and opts.crl_path.len > 0) try configureCrl(ctx, opts.crl_path);
        if (opts.ocsp_stapling_enabled and opts.ocsp_response_path.len > 0) try loadOcspResponse(st);
        try rebuildSniCertificates(st);
        if (st.sni_certs.items.len > 0) {
            _ = c.SSL_CTX_callback_ctrl(
                ctx,
                c.SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,
                @ptrCast(&sniCallback),
            );
            _ = c.SSL_CTX_ctrl(
                ctx,
                c.SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG,
                0,
                st,
            );
        }
        SSL_CTX_set_alpn_select_cb(ctx, alpnSelectCallback, st);

        return .{ .allocator = allocator, .ctx = ctx, .state = st };
    }

    pub fn deinit(self: *TlsTerminator) void {
        self.state.deinit();
        self.allocator.destroy(self.state);
        c.SSL_CTX_free(self.ctx);
        self.* = undefined;
    }

    pub fn runMaintenance(self: *TlsTerminator, now_ms: u64) void {
        self.state.mutex.lock();
        defer self.state.mutex.unlock();
        if (self.state.dynamic_reload_interval_ms == 0) return;
        if (self.state.next_reload_ms != 0 and now_ms < self.state.next_reload_ms) return;
        self.state.next_reload_ms = now_ms + self.state.dynamic_reload_interval_ms;

        const cert_mtime = fileMtime(self.state.default_cert_path) catch self.state.default_cert_mtime;
        const key_mtime = fileMtime(self.state.default_key_path) catch self.state.default_key_mtime;
        if (cert_mtime != self.state.default_cert_mtime or key_mtime != self.state.default_key_mtime) {
            _ = loadDefaultCertificate(self.ctx, self.state) catch {};
        }

        if (self.state.crl_check and self.state.crl_path.len > 0) {
            _ = configureCrl(self.ctx, self.state.crl_path) catch {};
        }

        if (self.state.ocsp_enabled and self.state.ocsp_response_path.len > 0) {
            const ocsp_mtime = fileMtime(self.state.ocsp_response_path) catch self.state.ocsp_mtime;
            if (ocsp_mtime != self.state.ocsp_mtime) {
                _ = loadOcspResponse(self.state) catch {};
            }
        }

        _ = rebuildSniCertificates(self.state) catch {};
    }

    pub fn accept(self: *TlsTerminator, fd: std.posix.fd_t) TlsError!TlsConnection {
        const ssl = c.SSL_new(self.ctx) orelse return error.ContextInitFailed;
        errdefer c.SSL_free(ssl);
        if (c.SSL_set_fd(ssl, fd) != 1) return error.HandshakeFailed;

        if (self.state.ocsp_enabled) {
            self.state.mutex.lock();
            defer self.state.mutex.unlock();
            if (self.state.ocsp_response) |resp| {
                const copied = @as([*]u8, @ptrCast(std.c.malloc(resp.len) orelse return error.OutOfMemory))[0..resp.len];
                std.mem.copyForwards(u8, copied, resp);
                if (c.SSL_set_tlsext_status_ocsp_resp(ssl, copied.ptr, @as(c_int, @intCast(copied.len))) != 1) {
                    std.c.free(copied.ptr);
                }
            }
        }

        if (c.SSL_accept(ssl) != 1) return error.HandshakeFailed;
        return .{ .ssl = ssl };
    }
};

pub const TlsConnection = struct {
    ssl: *c.SSL,

    pub fn deinit(self: *TlsConnection) void {
        _ = c.SSL_shutdown(self.ssl);
        c.SSL_free(self.ssl);
        self.* = undefined;
    }

    pub fn read(self: *TlsConnection, buf: []u8) TlsError!usize {
        const rc = c.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (rc > 0) return @intCast(rc);
        if (c.SSL_get_error(self.ssl, rc) == c.SSL_ERROR_ZERO_RETURN) return 0;
        return error.TlsReadFailed;
    }

    pub const Writer = std.io.Writer(*TlsConnection, TlsError, writeFn);

    pub fn writer(self: *TlsConnection) Writer {
        return .{ .context = self };
    }

    pub fn negotiatedProtocol(self: *const TlsConnection) NegotiatedProtocol {
        var data: [*c]const u8 = null;
        var len: c_uint = 0;
        c.SSL_get0_alpn_selected(self.ssl, &data, &len);
        if (data != null and len == 2 and std.mem.eql(u8, data[0..2], "h2")) return .http2;
        return .http1_1;
    }

    fn writeFn(self: *TlsConnection, data: []const u8) TlsError!usize {
        const rc = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (rc > 0) return @intCast(rc);
        return error.TlsWriteFailed;
    }
};

fn loadDefaultCertificate(ctx: *c.SSL_CTX, st: *State) TlsError!void {
    const cert_z = try std.heap.c_allocator.dupeZ(u8, st.default_cert_path);
    defer std.heap.c_allocator.free(cert_z);
    const key_z = try std.heap.c_allocator.dupeZ(u8, st.default_key_path);
    defer std.heap.c_allocator.free(key_z);
    if (c.SSL_CTX_use_certificate_file(ctx, cert_z.ptr, c.SSL_FILETYPE_PEM) != 1) return error.CertificateLoadFailed;
    if (c.SSL_CTX_use_PrivateKey_file(ctx, key_z.ptr, c.SSL_FILETYPE_PEM) != 1) return error.PrivateKeyLoadFailed;
    if (c.SSL_CTX_check_private_key(ctx) != 1) return error.CertificateKeyMismatch;
    st.default_cert_mtime = fileMtime(st.default_cert_path) catch null;
    st.default_key_mtime = fileMtime(st.default_key_path) catch null;
}

fn configureProtocolVersions(ctx: *c.SSL_CTX, min: []const u8, max: []const u8) TlsError!void {
    const min_v = parseVersion(min) orelse return error.ProtocolConfigFailed;
    const max_v = parseVersion(max) orelse return error.ProtocolConfigFailed;
    if (c.SSL_CTX_set_min_proto_version(ctx, min_v) != 1) return error.ProtocolConfigFailed;
    if (c.SSL_CTX_set_max_proto_version(ctx, max_v) != 1) return error.ProtocolConfigFailed;
}

fn parseVersion(raw: []const u8) ?c_int {
    if (std.mem.eql(u8, raw, "1.2")) return c.TLS1_2_VERSION;
    if (std.mem.eql(u8, raw, "1.3")) return c.TLS1_3_VERSION;
    return null;
}

fn configureCiphers(ctx: *c.SSL_CTX, cipher_list: []const u8, cipher_suites: []const u8) TlsError!void {
    if (cipher_list.len > 0) {
        const z = try std.heap.c_allocator.dupeZ(u8, cipher_list);
        defer std.heap.c_allocator.free(z);
        if (c.SSL_CTX_set_cipher_list(ctx, z.ptr) != 1) return error.CipherConfigFailed;
    }
    if (cipher_suites.len > 0) {
        const z = try std.heap.c_allocator.dupeZ(u8, cipher_suites);
        defer std.heap.c_allocator.free(z);
        if (c.SSL_CTX_set_ciphersuites(ctx, z.ptr) != 1) return error.CipherConfigFailed;
    }
}

fn configureSessionCache(ctx: *c.SSL_CTX, enabled: bool, size: u32, timeout_seconds: u32, tickets_enabled: bool) TlsError!void {
    if (enabled) {
        _ = c.SSL_CTX_set_session_cache_mode(ctx, c.SSL_SESS_CACHE_SERVER);
        _ = c.SSL_CTX_sess_set_cache_size(ctx, size);
        _ = c.SSL_CTX_set_timeout(ctx, timeout_seconds);
    } else {
        _ = c.SSL_CTX_set_session_cache_mode(ctx, c.SSL_SESS_CACHE_OFF);
    }
    if (!tickets_enabled) _ = c.SSL_CTX_set_options(ctx, ssl_op_no_ticket);
}

fn configureClientVerification(ctx: *c.SSL_CTX, ca_path: []const u8, verify: bool, depth: u32) TlsError!void {
    if (ca_path.len > 0) {
        const ca_z = try std.heap.c_allocator.dupeZ(u8, ca_path);
        defer std.heap.c_allocator.free(ca_z);
        if (c.SSL_CTX_load_verify_locations(ctx, ca_z.ptr, null) != 1) return error.VerifyConfigFailed;
    }
    const verify_mode: c_int = if (verify) c.SSL_VERIFY_PEER | c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT else c.SSL_VERIFY_NONE;
    c.SSL_CTX_set_verify(ctx, verify_mode, null);
    c.SSL_CTX_set_verify_depth(ctx, @intCast(depth));
}

fn configureCrl(ctx: *c.SSL_CTX, crl_path: []const u8) TlsError!void {
    const path_z = try std.heap.c_allocator.dupeZ(u8, crl_path);
    defer std.heap.c_allocator.free(path_z);
    const bio = c.BIO_new_file(path_z.ptr, "r") orelse return error.CrlLoadFailed;
    defer _ = c.BIO_free(bio);
    const crl = c.PEM_read_bio_X509_CRL(bio, null, null, null) orelse return error.CrlLoadFailed;
    defer c.X509_CRL_free(crl);
    const store = c.SSL_CTX_get_cert_store(ctx) orelse return error.CrlLoadFailed;
    if (c.X509_STORE_add_crl(store, crl) != 1) return error.CrlLoadFailed;
    if (c.X509_STORE_set_flags(store, c.X509_V_FLAG_CRL_CHECK | c.X509_V_FLAG_CRL_CHECK_ALL) != 1) return error.CrlLoadFailed;
}

fn loadOcspResponse(st: *State) TlsError!void {
    if (st.ocsp_response) |old| st.allocator.free(old);
    st.ocsp_response = null;
    st.ocsp_response = std.fs.cwd().readFileAlloc(st.allocator, st.ocsp_response_path, 1024 * 1024) catch return error.OcspLoadFailed;
    st.ocsp_mtime = fileMtime(st.ocsp_response_path) catch null;
}

fn rebuildSniCertificates(st: *State) TlsError!void {
    for (st.sni_certs.items) |sc| {
        st.allocator.free(sc.host_lc);
        std.heap.c_allocator.free(sc.cert_path_z);
        std.heap.c_allocator.free(sc.key_path_z);
    }
    st.sni_certs.clearRetainingCapacity();

    for (st.static_sni_specs) |spec| {
        try appendSniCert(st, spec.server_name, spec.cert_path, spec.key_path);
    }

    if (st.acme_enabled and st.acme_cert_dir.len > 0) {
        var dir = std.fs.cwd().openDir(st.acme_cert_dir, .{ .iterate = true }) catch return;
        defer dir.close();
        var it = dir.iterate();
        while (it.next() catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".crt")) continue;
            const host = entry.name[0 .. entry.name.len - 4];
            const cert_path = std.fmt.allocPrint(st.allocator, "{s}/{s}", .{ st.acme_cert_dir, entry.name }) catch continue;
            defer st.allocator.free(cert_path);
            const key_file = std.fmt.allocPrint(st.allocator, "{s}.key", .{host}) catch continue;
            defer st.allocator.free(key_file);
            const key_path = std.fmt.allocPrint(st.allocator, "{s}/{s}", .{ st.acme_cert_dir, key_file }) catch continue;
            defer st.allocator.free(key_path);
            std.fs.cwd().access(key_path, .{}) catch continue;
            try appendSniCert(st, host, cert_path, key_path);
        }
    }
}

fn appendSniCert(st: *State, host: []const u8, cert_path: []const u8, key_path: []const u8) TlsError!void {
    const host_lc = try st.allocator.dupe(u8, host);
    for (host_lc) |*ch| ch.* = std.ascii.toLower(ch.*);
    const cert_z = try std.heap.c_allocator.dupeZ(u8, cert_path);
    const key_z = try std.heap.c_allocator.dupeZ(u8, key_path);
    try st.sni_certs.append(.{
        .host_lc = host_lc,
        .cert_path_z = cert_z,
        .key_path_z = key_z,
    });
}

fn sniCallback(ssl: ?*c.SSL, alert: ?*c_int, arg: ?*anyopaque) callconv(.c) c_int {
    _ = alert;
    const s = ssl orelse return c.SSL_TLSEXT_ERR_NOACK;
    const state: *State = @ptrCast(@alignCast(arg orelse return c.SSL_TLSEXT_ERR_NOACK));
    const servername_ptr = c.SSL_get_servername(s, c.TLSEXT_NAMETYPE_host_name) orelse return c.SSL_TLSEXT_ERR_NOACK;
    const servername = std.mem.span(servername_ptr);

    state.mutex.lock();
    defer state.mutex.unlock();
    for (state.sni_certs.items) |entry| {
        if (!std.ascii.eqlIgnoreCase(servername, entry.host_lc)) continue;
        if (c.SSL_use_certificate_file(s, entry.cert_path_z.ptr, c.SSL_FILETYPE_PEM) != 1) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        if (c.SSL_use_PrivateKey_file(s, entry.key_path_z.ptr, c.SSL_FILETYPE_PEM) != 1) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        if (c.SSL_check_private_key(s) != 1) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
        return c.SSL_TLSEXT_ERR_OK;
    }
    return c.SSL_TLSEXT_ERR_NOACK;
}

fn alpnSelectCallback(
    _ssl: ?*c.SSL,
    out: [*c][*c]u8,
    outlen: [*c]u8,
    in: [*c]const u8,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = _ssl;
    const state: *State = @ptrCast(@alignCast(arg orelse return c.SSL_TLSEXT_ERR_NOACK));
    const h2_and_http11 = "\x02h2\x08http/1.1";
    const http11_only = "\x08http/1.1";
    const server_protos = if (state.http2_enabled) h2_and_http11 else http11_only;
    const rc = c.SSL_select_next_proto(out, outlen, server_protos.ptr, @intCast(server_protos.len), in, inlen);
    return if (rc == openssl_npn_negotiated) c.SSL_TLSEXT_ERR_OK else c.SSL_TLSEXT_ERR_NOACK;
}

fn fileMtime(path: []const u8) !i128 {
    const stat = try std.fs.cwd().statFile(path);
    return stat.mtime;
}

test "openssl init" {
    try std.testing.expect(c.OPENSSL_init_ssl(0, null) == 1);
}
