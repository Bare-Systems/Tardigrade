const std = @import("std");
const acme_client = @import("acme_client.zig");

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/x509_vfy.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/x509v3.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/ocsp.h");
});

extern fn SSL_CTX_set_alpn_select_cb(
    ctx: *c.SSL_CTX,
    cb: *const fn (?*c.SSL, [*c][*c]u8, [*c]u8, [*c]const u8, c_uint, ?*anyopaque) callconv(.c) c_int,
    arg: ?*anyopaque,
) void;

const ssl_op_no_ticket: c_ulong = @as(c_ulong, 1) << @as(u6, 14);
const openssl_npn_negotiated: c_int = 1;
const embedded_server_crt = @embedFile("testdata/test_server.crt");
const embedded_server_key = @embedFile("testdata/test_server.key");
const embedded_alt_server_crt = @embedFile("testdata/test_alt_server.crt");
const embedded_alt_server_key = @embedFile("testdata/test_alt_server.key");

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
    /// When true, Tardigrade fetches OCSP responses from the responder URL
    /// embedded in the certificate's AIA extension instead of relying on a
    /// static file.  The static-file path is used as a warm-start fallback on
    /// the first boot if a pre-fetched file is present.
    ocsp_auto_refresh_enabled: bool = false,
    /// How often (ms) to re-fetch the OCSP response from the responder.
    ocsp_refresh_interval_ms: u64 = 3_600_000,
    /// Per-request timeout (ms) when contacting the OCSP responder.
    ocsp_refresh_timeout_ms: u32 = 10_000,
    client_ca_path: []const u8 = "",
    client_verify: bool = false,
    client_verify_depth: u32 = 3,
    crl_path: []const u8 = "",
    crl_check: bool = false,
    dynamic_reload_interval_ms: u64 = 5_000,
    acme_enabled: bool = false,
    acme_cert_dir: []const u8 = "",
    /// When true, Tardigrade runs the ACME issuance/renewal workflow automatically.
    acme_auto_issue: bool = false,
    /// ACME directory URL (Let's Encrypt production or staging, or pebble for tests).
    acme_directory_url: []const u8 = "https://acme-v02.api.letsencrypt.org/directory",
    /// Comma-separated domain names to request a certificate for.
    acme_domains: []const []const u8 = &.{},
    /// Contact email for ACME account registration.
    acme_email: []const u8 = "",
    /// PEM file path for the persistent ECDSA account private key.
    acme_account_key_path: []const u8 = "",
    /// Days before certificate expiry to trigger renewal.
    acme_renew_days_before_expiry: u32 = 30,
    /// Pointer to the HTTP-01 challenge token store shared with the gateway.
    acme_challenge_store: ?*@import("acme_client.zig").ChallengeStore = null,
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
    ocsp_auto_refresh_enabled: bool,
    ocsp_refresh_interval_ms: u64,
    ocsp_refresh_timeout_ms: u32,
    ocsp_next_auto_refresh_ms: u64 = 0,
    /// OCSP responder URL extracted from the leaf certificate's AIA extension.
    /// Empty when no AIA OCSP entry is present.
    ocsp_responder_url: []u8 = &.{},
    client_ca_path: []const u8,
    crl_path: []const u8,
    crl_check: bool,
    acme_enabled: bool,
    acme_cert_dir: []const u8,
    acme_auto_issue: bool,
    acme_directory_url: []const u8,
    acme_domains: []const []const u8,
    acme_email: []const u8,
    acme_account_key_path: []const u8,
    acme_renew_days_before_expiry: u32,
    acme_challenge_store: ?*acme_client.ChallengeStore,
    acme_next_check_ms: u64 = 0,
    static_sni_specs: []SniCertSpec,
    sni_certs: std.ArrayList(ManagedSniCert),
    http2_enabled: bool,

    fn deinit(self: *State) void {
        if (self.ocsp_response) |resp| self.allocator.free(resp);
        if (self.ocsp_responder_url.len > 0) self.allocator.free(self.ocsp_responder_url);
        self.allocator.free(self.static_sni_specs);
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
        const owned_sni_specs = owned: {
            const specs = try allocator.alloc(SniCertSpec, opts.sni_certs.len);
            errdefer allocator.free(specs);
            @memcpy(specs, opts.sni_certs);
            break :owned specs;
        };

        var st = try allocator.create(State);
        errdefer allocator.destroy(st);
        st.* = .{
            .allocator = allocator,
            .dynamic_reload_interval_ms = opts.dynamic_reload_interval_ms,
            .default_cert_path = opts.cert_path,
            .default_key_path = opts.key_path,
            .ocsp_enabled = opts.ocsp_stapling_enabled,
            .ocsp_response_path = opts.ocsp_response_path,
            .ocsp_auto_refresh_enabled = opts.ocsp_auto_refresh_enabled,
            .ocsp_refresh_interval_ms = opts.ocsp_refresh_interval_ms,
            .ocsp_refresh_timeout_ms = opts.ocsp_refresh_timeout_ms,
            .client_ca_path = opts.client_ca_path,
            .crl_path = opts.crl_path,
            .crl_check = opts.crl_check,
            .acme_enabled = opts.acme_enabled,
            .acme_cert_dir = opts.acme_cert_dir,
            .acme_auto_issue = opts.acme_auto_issue,
            .acme_directory_url = opts.acme_directory_url,
            .acme_domains = opts.acme_domains,
            .acme_email = opts.acme_email,
            .acme_account_key_path = opts.acme_account_key_path,
            .acme_renew_days_before_expiry = opts.acme_renew_days_before_expiry,
            .acme_challenge_store = opts.acme_challenge_store,
            .static_sni_specs = owned_sni_specs,
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
        // Extract OCSP responder URL from the leaf certificate so auto-refresh knows where to go.
        if (opts.ocsp_auto_refresh_enabled) {
            if (extractOcspResponderUrl(allocator, ctx)) |url| {
                st.ocsp_responder_url = url;
            }
        }
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

        if (self.state.ocsp_auto_refresh_enabled and self.state.ocsp_responder_url.len > 0) {
            if (self.state.ocsp_next_auto_refresh_ms == 0 or now_ms >= self.state.ocsp_next_auto_refresh_ms) {
                _ = fetchAndStoreOcspResponse(self.state, self.ctx) catch {};
                self.state.ocsp_next_auto_refresh_ms = now_ms + self.state.ocsp_refresh_interval_ms;
            }
        }

        // Trigger ACME renewal if enabled and the check interval has elapsed.
        if (self.state.acme_auto_issue and
            self.state.acme_challenge_store != null and
            self.state.acme_domains.len > 0 and
            (self.state.acme_next_check_ms == 0 or now_ms >= self.state.acme_next_check_ms))
        {
            self.state.acme_next_check_ms = now_ms + 3_600_000; // recheck every hour
            acme_client.runOnce(.{
                .allocator = self.state.allocator,
                .directory_url = self.state.acme_directory_url,
                .domains = self.state.acme_domains,
                .email = self.state.acme_email,
                .account_key_path = self.state.acme_account_key_path,
                .cert_dir = self.state.acme_cert_dir,
                .renew_days_before_expiry = self.state.acme_renew_days_before_expiry,
                .challenge_store = self.state.acme_challenge_store.?,
            }) catch |err| switch (err) {
                // Not yet due is expected and silent.
                error.CertNotYetDue => {},
                else => {},
            };
            // After a successful issuance, rebuild the SNI cert list to pick up the new cert.
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

pub fn lastOpenSslError(allocator: std.mem.Allocator) ?[]u8 {
    const err_code = c.ERR_get_error();
    if (err_code == 0) return null;

    var buf: [256]u8 = undefined;
    _ = c.ERR_error_string_n(err_code, &buf, buf.len);
    return allocator.dupe(u8, std.mem.sliceTo(&buf, 0)) catch null;
}

fn loadDefaultCertificate(ctx: *c.SSL_CTX, st: *State) TlsError!void {
    const cert_z = try std.heap.c_allocator.dupeZ(u8, st.default_cert_path);
    defer std.heap.c_allocator.free(cert_z);
    const key_z = try std.heap.c_allocator.dupeZ(u8, st.default_key_path);
    defer std.heap.c_allocator.free(key_z);
    if (c.SSL_CTX_use_certificate_chain_file(ctx, cert_z.ptr) != 1) return error.CertificateLoadFailed;
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

/// Extract the first OCSP responder URL from the leaf certificate's Authority
/// Information Access (AIA) extension.  Returns an allocated slice owned by the
/// caller, or null if no OCSP entry is found.
fn extractOcspResponderUrl(allocator: std.mem.Allocator, ctx: *c.SSL_CTX) ?[]u8 {
    const cert: ?*c.X509 = c.SSL_CTX_get0_certificate(ctx);
    const raw_cert = cert orelse return null;

    const aia_raw: ?*anyopaque = c.X509_get_ext_d2i(raw_cert, c.NID_info_access, null, null);
    const aia: *c.AUTHORITY_INFO_ACCESS = @ptrCast(aia_raw orelse return null);
    defer c.AUTHORITY_INFO_ACCESS_free(aia);

    const count: c_int = c.sk_ACCESS_DESCRIPTION_num(aia);
    var i: c_int = 0;
    while (i < count) : (i += 1) {
        const ad: ?*c.ACCESS_DESCRIPTION = c.sk_ACCESS_DESCRIPTION_value(aia, i);
        const desc = ad orelse continue;
        // OID for id-ad-ocsp
        if (c.OBJ_obj2nid(desc.method) != c.NID_ad_OCSP) continue;
        if (desc.location.*.type != c.GEN_URI) continue;
        const uri = desc.location.*.d.uniformResourceIdentifier;
        const url_bytes = uri.*.data[0..@intCast(uri.*.length)];
        return allocator.dupe(u8, url_bytes) catch null;
    }
    return null;
}

/// Build a minimal DER-encoded OCSP request for the leaf certificate and POST
/// it to the responder URL.  On success the raw DER response bytes (suitable
/// for SSL_set_tlsext_status_ocsp_resp) are written into st.ocsp_response.
/// Failures are non-fatal; the last-known-good response is preserved.
fn fetchAndStoreOcspResponse(st: *State, ctx: *c.SSL_CTX) TlsError!void {
    const cert: ?*c.X509 = c.SSL_CTX_get0_certificate(ctx);
    const leaf = cert orelse return error.OcspLoadFailed;

    // Build OCSP request for the leaf cert.  We need the issuer cert to
    // compute the cert ID; retrieve it from the extra chain if available.
    const chain_stack: ?*c.struct_stack_st_X509 = blk: {
        var chain_ptr: ?*c.struct_stack_st_X509 = null;
        _ = c.SSL_CTX_get0_extra_chain_certs(ctx, &chain_ptr);
        break :blk chain_ptr;
    };
    const issuer: ?*c.X509 = if (chain_stack != null and c.sk_X509_num(chain_stack) > 0)
        c.sk_X509_value(chain_stack, 0)
    else
        null;

    const cert_id: ?*c.OCSP_CERTID = if (issuer != null)
        c.OCSP_cert_to_id(null, leaf, issuer)
    else
        null;
    if (cert_id == null) return error.OcspLoadFailed;
    defer c.OCSP_CERTID_free(cert_id);

    const req: ?*c.OCSP_REQUEST = c.OCSP_REQUEST_new();
    if (req == null) return error.OcspLoadFailed;
    defer c.OCSP_REQUEST_free(req);

    if (c.OCSP_request_add0_id(req, cert_id) == null) return error.OcspLoadFailed;
    _ = c.OCSP_request_add1_nonce(req, null, -1);

    // DER-encode the request.
    var req_buf: ?[*]u8 = null;
    const req_len = c.i2d_OCSP_REQUEST(req, &req_buf);
    if (req_len <= 0 or req_buf == null) return error.OcspLoadFailed;
    defer std.c.free(req_buf);
    const req_bytes = req_buf.?[0..@intCast(req_len)];

    // HTTP POST to responder URL using std.http.Client.
    var client = std.http.Client{ .allocator = st.allocator };
    defer client.deinit();

    const uri = std.Uri.parse(st.ocsp_responder_url) catch return error.OcspLoadFailed;
    var server_header_buf: [4096]u8 = undefined;
    var ocsp_req = client.open(.POST, uri, .{
        .server_header_buffer = &server_header_buf,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/ocsp-request" },
        },
        .keep_alive = false,
    }) catch return error.OcspLoadFailed;
    defer ocsp_req.deinit();
    ocsp_req.transfer_encoding = .{ .content_length = req_bytes.len };
    ocsp_req.send() catch return error.OcspLoadFailed;
    ocsp_req.writeAll(req_bytes) catch return error.OcspLoadFailed;
    ocsp_req.finish() catch return error.OcspLoadFailed;
    ocsp_req.wait() catch return error.OcspLoadFailed;
    if (ocsp_req.response.status != .ok) return error.OcspLoadFailed;

    var resp_body = std.ArrayList(u8).init(st.allocator);
    defer resp_body.deinit();
    ocsp_req.reader().readAllArrayList(&resp_body, 64 * 1024) catch return error.OcspLoadFailed;

    // Parse and validate the OCSP response structure minimally.
    const body = resp_body.items;
    var body_ptr: [*c]const u8 = body.ptr;
    const ocsp_resp: ?*c.OCSP_RESPONSE = c.d2i_OCSP_RESPONSE(null, &body_ptr, @intCast(body.len));
    if (ocsp_resp == null) return error.OcspLoadFailed;
    defer c.OCSP_RESPONSE_free(ocsp_resp);

    if (c.OCSP_response_status(ocsp_resp) != c.OCSP_RESPONSE_STATUS_SUCCESSFUL) return error.OcspLoadFailed;

    // Re-encode to DER (ensures clean bytes for stapling).
    var der_buf: ?[*]u8 = null;
    const der_len = c.i2d_OCSP_RESPONSE(ocsp_resp, &der_buf);
    if (der_len <= 0 or der_buf == null) return error.OcspLoadFailed;
    defer std.c.free(der_buf);

    const new_response = st.allocator.dupe(u8, der_buf.?[0..@intCast(der_len)]) catch return error.OcspLoadFailed;
    if (st.ocsp_response) |old| st.allocator.free(old);
    st.ocsp_response = new_response;

    // Persist to the static-file path so it survives restarts (best-effort).
    if (st.ocsp_response_path.len > 0) {
        std.fs.cwd().writeFile(.{ .sub_path = st.ocsp_response_path, .data = new_response }) catch {};
    }
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
        if (c.SSL_use_certificate_chain_file(s, entry.cert_path_z.ptr) != 1) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
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

// ---------------------------------------------------------------------------
// Upstream mTLS / custom-CA HTTPS transport (Issue #17)
// ---------------------------------------------------------------------------

pub const UpstreamTlsOptions = struct {
    /// Skip server certificate verification (insecure; for testing only).
    skip_verify: bool = false,
    /// Path to PEM CA bundle for verifying the upstream server cert.
    /// When empty, the OpenSSL default CA store is used.
    ca_bundle_path: []const u8 = "",
    /// Override the SNI hostname sent during the TLS ClientHello.
    /// When empty, the connect hostname is used.
    sni_override: []const u8 = "",
    /// PEM path to the client certificate for mTLS (optional).
    client_cert_path: []const u8 = "",
    /// PEM path to the client private key for mTLS (optional).
    client_key_path: []const u8 = "",
};

/// An OpenSSL-backed TLS client connection to a TCP stream.
/// Used for upstream HTTPS connections that require mTLS or custom CA/SNI.
pub const UpstreamTlsConn = struct {
    ssl: *c.SSL,
    ctx: *c.SSL_CTX,

    pub fn connect(
        fd: std.posix.fd_t,
        host: []const u8,
        opts: UpstreamTlsOptions,
    ) TlsError!UpstreamTlsConn {
        if (c.OPENSSL_init_ssl(0, null) != 1) return error.OpenSslInitFailed;
        const method = c.TLS_client_method() orelse return error.ContextInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return error.ContextInitFailed;
        errdefer c.SSL_CTX_free(ctx);

        if (opts.skip_verify) {
            c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
        } else if (opts.ca_bundle_path.len > 0) {
            const ca_z = try std.heap.c_allocator.dupeZ(u8, opts.ca_bundle_path);
            defer std.heap.c_allocator.free(ca_z);
            if (c.SSL_CTX_load_verify_locations(ctx, ca_z.ptr, null) != 1) return error.VerifyConfigFailed;
            c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
        } else {
            if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) return error.VerifyConfigFailed;
            c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
        }

        if (opts.client_cert_path.len > 0) {
            const cert_z = try std.heap.c_allocator.dupeZ(u8, opts.client_cert_path);
            defer std.heap.c_allocator.free(cert_z);
            if (c.SSL_CTX_use_certificate_file(ctx, cert_z.ptr, c.SSL_FILETYPE_PEM) != 1) return error.CertificateLoadFailed;
        }
        if (opts.client_key_path.len > 0) {
            const key_z = try std.heap.c_allocator.dupeZ(u8, opts.client_key_path);
            defer std.heap.c_allocator.free(key_z);
            if (c.SSL_CTX_use_PrivateKey_file(ctx, key_z.ptr, c.SSL_FILETYPE_PEM) != 1) return error.PrivateKeyLoadFailed;
            if (c.SSL_CTX_check_private_key(ctx) != 1) return error.CertificateKeyMismatch;
        }

        const ssl = c.SSL_new(ctx) orelse return error.ContextInitFailed;
        errdefer c.SSL_free(ssl);

        const sni_host = if (opts.sni_override.len > 0) opts.sni_override else host;
        const sni_z = try std.heap.c_allocator.dupeZ(u8, sni_host);
        defer std.heap.c_allocator.free(sni_z);
        _ = c.SSL_set_tlsext_host_name(ssl, sni_z.ptr);

        if (!opts.skip_verify) {
            const verify_host_z = try std.heap.c_allocator.dupeZ(u8, sni_host);
            defer std.heap.c_allocator.free(verify_host_z);
            const param = c.SSL_get0_param(ssl);
            _ = c.X509_VERIFY_PARAM_set_hostflags(param, c.X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (c.X509_VERIFY_PARAM_set1_host(param, verify_host_z.ptr, 0) != 1) return error.VerifyConfigFailed;
        }

        if (c.SSL_set_fd(ssl, fd) != 1) return error.HandshakeFailed;
        if (c.SSL_connect(ssl) != 1) return error.HandshakeFailed;

        return .{ .ssl = ssl, .ctx = ctx };
    }

    pub fn deinit(self: *UpstreamTlsConn) void {
        _ = c.SSL_shutdown(self.ssl);
        c.SSL_free(self.ssl);
        c.SSL_CTX_free(self.ctx);
        self.* = undefined;
    }

    pub fn read(self: *UpstreamTlsConn, buf: []u8) TlsError!usize {
        const rc = c.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (rc > 0) return @intCast(rc);
        if (c.SSL_get_error(self.ssl, rc) == c.SSL_ERROR_ZERO_RETURN) return 0;
        return error.TlsReadFailed;
    }

    pub fn writeAll(self: *UpstreamTlsConn, data: []const u8) TlsError!void {
        var offset: usize = 0;
        while (offset < data.len) {
            const rc = c.SSL_write(self.ssl, data.ptr + offset, @intCast(data.len - offset));
            if (rc <= 0) return error.TlsWriteFailed;
            offset += @intCast(rc);
        }
    }
};

test "openssl init" {
    try std.testing.expect(c.OPENSSL_init_ssl(0, null) == 1);
}

test "tls terminator copies sni specs for maintenance reload" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "test_server.crt", .data = embedded_server_crt });
    try tmp.dir.writeFile(.{ .sub_path = "test_server.key", .data = embedded_server_key });
    try tmp.dir.writeFile(.{ .sub_path = "test_alt_server.crt", .data = embedded_alt_server_crt });
    try tmp.dir.writeFile(.{ .sub_path = "test_alt_server.key", .data = embedded_alt_server_key });

    const alt_cert_path = try tmp.dir.realpathAlloc(allocator, "test_alt_server.crt");
    defer allocator.free(alt_cert_path);
    const alt_key_path = try tmp.dir.realpathAlloc(allocator, "test_alt_server.key");
    defer allocator.free(alt_key_path);
    const cert_path = try tmp.dir.realpathAlloc(allocator, "test_server.crt");
    defer allocator.free(cert_path);
    const key_path = try tmp.dir.realpathAlloc(allocator, "test_server.key");
    defer allocator.free(key_path);

    var specs = try allocator.alloc(SniCertSpec, 1);
    defer allocator.free(specs);
    specs[0] = .{
        .server_name = "sni.integration.test",
        .cert_path = alt_cert_path,
        .key_path = alt_key_path,
    };

    var tls = try TlsTerminator.init(allocator, .{
        .cert_path = cert_path,
        .key_path = key_path,
        .sni_certs = specs,
        .dynamic_reload_interval_ms = 1,
    });
    defer tls.deinit();

    tls.runMaintenance(1);
    tls.runMaintenance(2);
}
