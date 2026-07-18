const std = @import("std");
const compat = @import("../zig_compat.zig");
const acme_client = @import("acme_client.zig");
const encrypted_stream = @import("tls_core").encrypted_stream;
const negotiated_dispatch = @import("negotiated_dispatch.zig");

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

extern fn SSL_CTX_set_client_hello_cb(
    ctx: *c.SSL_CTX,
    cb: *const fn (?*c.SSL, [*c]c_int, ?*anyopaque) callconv(.c) c_int,
    arg: ?*anyopaque,
) void;

extern fn SSL_client_hello_get0_ext(
    s: ?*c.SSL,
    typ: c_uint,
    out: *[*c]const u8,
    outlen: *usize,
) c_int;

const ssl_op_no_ticket: c_ulong = @as(c_ulong, 1) << @as(u6, 14);
const openssl_npn_negotiated: c_int = 1;
const openssl_stream_mode: c_long = c.SSL_MODE_ENABLE_PARTIAL_WRITE;
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
    http1_enabled: bool = true,
    http2_enabled: bool = true,
    http1_alpn_fallback_enabled: bool = false,
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
    mutex: compat.Mutex = .{},
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
    protocol_policy: negotiated_dispatch.ListenerProtocolPolicy,
    policy_ex_index: c_int,

    fn deinit(self: *State) void {
        if (self.ocsp_response) |resp| self.allocator.free(resp);
        if (self.ocsp_responder_url.len > 0) self.allocator.free(self.ocsp_responder_url);
        self.allocator.free(self.static_sni_specs);
        for (self.sni_certs.items) |sc| {
            self.allocator.free(sc.host_lc);
            std.heap.c_allocator.free(sc.cert_path_z);
            std.heap.c_allocator.free(sc.key_path_z);
        }
        self.sni_certs.deinit(self.allocator);
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
        if (!opts.http1_enabled and !opts.http2_enabled) return error.ProtocolConfigFailed;
        const policy_ex_index = c.CRYPTO_get_ex_new_index(c.CRYPTO_EX_INDEX_SSL, 0, null, null, null, null);
        if (policy_ex_index < 0) return error.ProtocolConfigFailed;
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
            .sni_certs = .empty,
            .protocol_policy = .{
                .http1_enabled = opts.http1_enabled,
                .http2_enabled = opts.http2_enabled,
                .allow_http1_without_alpn = opts.http1_alpn_fallback_enabled,
            },
            .policy_ex_index = policy_ex_index,
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
        SSL_CTX_set_client_hello_cb(ctx, clientHelloCallback, st);
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
            _ = loadDefaultCertificate(self.ctx, self.state) catch {}; // cert reload is best-effort; existing certificate remains active
        }

        if (self.state.crl_check and self.state.crl_path.len > 0) {
            _ = configureCrl(self.ctx, self.state.crl_path) catch {}; // CRL reload is best-effort; existing CRL remains active
        }

        if (self.state.ocsp_enabled and self.state.ocsp_response_path.len > 0) {
            const ocsp_mtime = fileMtime(self.state.ocsp_response_path) catch self.state.ocsp_mtime;
            if (ocsp_mtime != self.state.ocsp_mtime) {
                _ = loadOcspResponse(self.state) catch {}; // OCSP reload is best-effort; stapled response may be stale
            }
        }

        if (self.state.ocsp_auto_refresh_enabled and self.state.ocsp_responder_url.len > 0) {
            if (self.state.ocsp_next_auto_refresh_ms == 0 or now_ms >= self.state.ocsp_next_auto_refresh_ms) {
                _ = fetchAndStoreOcspResponse(self.state, self.ctx) catch {}; // OCSP auto-fetch is best-effort; stapling continues with cached response
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

        _ = rebuildSniCertificates(self.state) catch {}; // SNI cert rebuild is best-effort; existing certificate mappings remain active
    }

    pub fn protocolPolicySnapshot(self: *TlsTerminator) negotiated_dispatch.ListenerProtocolPolicy {
        self.state.mutex.lock();
        defer self.state.mutex.unlock();
        return self.state.protocol_policy;
    }

    pub fn updateProtocolPolicy(self: *TlsTerminator, policy: negotiated_dispatch.ListenerProtocolPolicy) TlsError!void {
        if (!policy.http1_enabled and !policy.http2_enabled) return error.ProtocolConfigFailed;
        self.state.mutex.lock();
        defer self.state.mutex.unlock();
        self.state.protocol_policy = policy;
    }

    pub fn accept(self: *TlsTerminator, fd: std.posix.fd_t) TlsError!TlsConnection {
        const policy_box = try self.allocator.create(negotiated_dispatch.ListenerProtocolPolicy);
        errdefer self.allocator.destroy(policy_box);
        policy_box.* = self.protocolPolicySnapshot();
        const ssl = c.SSL_new(self.ctx) orelse return error.ContextInitFailed;
        errdefer c.SSL_free(ssl);
        if (c.SSL_set_ex_data(ssl, self.state.policy_ex_index, policy_box) != 1) return error.ProtocolConfigFailed;
        _ = c.SSL_ctrl(ssl, c.SSL_CTRL_MODE, openssl_stream_mode, null);
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
        return .{
            .ssl = ssl,
            .allocator = self.allocator,
            .protocol_policy = policy_box.*,
            .policy_box = policy_box,
            .policy_ex_index = self.state.policy_ex_index,
        };
    }
};

pub const TlsConnection = struct {
    ssl: *c.SSL,
    allocator: std.mem.Allocator = undefined,
    stream_lifecycle: OpenSslStreamLifecycle = .open,
    retry_direction: OpenSslRetryDirection = .none,
    pending_write: ?OpenSslPendingWrite = null,
    close_requested: bool = false,
    peer_closed: bool = false,
    stream_failure: ?encrypted_stream.Error = null,
    stream_buffer_peaks: encrypted_stream.QueueBytes = .{},
    stream_peak_total: usize = 0,
    stream_pause_state: encrypted_stream.PauseState = .{},
    stream_buffer_counters: encrypted_stream.BufferCounters = .{},
    protocol_policy: negotiated_dispatch.ListenerProtocolPolicy = .{},
    policy_box: ?*negotiated_dispatch.ListenerProtocolPolicy = null,
    policy_ex_index: c_int = -1,

    pub fn deinit(self: *TlsConnection) void {
        if (self.policy_ex_index >= 0) _ = c.SSL_set_ex_data(self.ssl, self.policy_ex_index, null);
        if (opensslShouldShutdownOnDeinit(self)) {
            c.ERR_clear_error();
            _ = c.SSL_shutdown(self.ssl);
        }
        c.SSL_free(self.ssl);
        if (self.policy_box) |box| self.allocator.destroy(box);
        self.* = undefined;
    }

    pub fn read(self: *TlsConnection, buf: []u8) TlsError!usize {
        const rc = c.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (rc > 0) return @intCast(rc);
        if (c.SSL_get_error(self.ssl, rc) == c.SSL_ERROR_ZERO_RETURN) return 0;
        return error.TlsReadFailed;
    }

    /// Bytes of already-decrypted application data buffered inside OpenSSL,
    /// readable without touching the socket. Used by keepalive parking (#138):
    /// if a pipelined request is already buffered after a response, the
    /// connection must be served immediately rather than parked, because a
    /// socket-readiness event will never fire for data already drained off the
    /// socket into OpenSSL's buffer.
    pub fn pending(self: *const TlsConnection) usize {
        const n = c.SSL_pending(self.ssl);
        return if (n > 0) @intCast(n) else 0;
    }

    /// Return the underlying TCP socket fd so callers can apply per-phase
    /// socket timeouts (SO_RCVTIMEO/SO_SNDTIMEO) without going through OpenSSL.
    pub fn rawFd(self: *const TlsConnection) std.posix.fd_t {
        return @intCast(c.SSL_get_fd(self.ssl));
    }

    pub const Writer = struct {
        conn: *TlsConnection,

        pub fn writeAll(self: Writer, data: []const u8) TlsError!void {
            var remaining = data;
            while (remaining.len > 0) {
                const n = try writeFn(self.conn, remaining);
                remaining = remaining[n..];
            }
        }

        pub fn print(self: Writer, comptime fmt: []const u8, args: anytype) !void {
            // Format into a stack buffer to avoid heap allocation for the
            // common case of short header lines (< 4 KiB).
            var buf: [4096]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, fmt, args);
            return self.writeAll(s);
        }

        pub fn writeByte(self: Writer, byte: u8) TlsError!void {
            return self.writeAll(&[_]u8{byte});
        }
    };

    pub fn writer(self: *TlsConnection) Writer {
        return .{ .conn = self };
    }

    pub fn stream(self: *TlsConnection) encrypted_stream.EncryptedStream {
        return .{ .ptr = self, .vtable = &openssl_stream_vtable };
    }

    pub fn negotiatedAlpn(self: *const TlsConnection) ?[]const u8 {
        var data: [*c]const u8 = null;
        var len: c_uint = 0;
        c.SSL_get0_alpn_selected(self.ssl, &data, &len);
        if (data == null or len == 0) return null;
        return data[0..@intCast(len)];
    }

    pub fn negotiatedProtocol(self: *const TlsConnection) negotiated_dispatch.Error!NegotiatedProtocol {
        return self.validatedNegotiatedProtocol();
    }

    pub fn validatedNegotiatedProtocol(self: *const TlsConnection) negotiated_dispatch.Error!NegotiatedProtocol {
        return negotiated_dispatch.selectNegotiatedProtocol(self.negotiatedAlpn(), self.protocol_policy);
    }

    fn writeFn(self: *TlsConnection, data: []const u8) TlsError!usize {
        const rc = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (rc > 0) return @intCast(rc);
        return error.TlsWriteFailed;
    }
};

const OpenSslStreamLifecycle = enum {
    open,
    closing,
    closed,
    failed,
};

const OpenSslRetryDirection = enum {
    none,
    read,
    write,
};

const OpenSslPendingWrite = struct {
    ptr_addr: usize,
    len: usize,

    fn init(bytes: []const u8) OpenSslPendingWrite {
        return .{ .ptr_addr = @intFromPtr(bytes.ptr), .len = bytes.len };
    }

    fn matches(self: OpenSslPendingWrite, bytes: []const u8) bool {
        return self.ptr_addr == @intFromPtr(bytes.ptr) and self.len == bytes.len;
    }
};

fn opensslClearRetry(self: *TlsConnection) void {
    self.retry_direction = .none;
    self.pending_write = null;
    if (self.stream_lifecycle == .open and !self.close_requested) opensslObserveBackpressure(self);
}

fn opensslShouldShutdownOnDeinit(self: *const TlsConnection) bool {
    return self.stream_failure == null and self.stream_lifecycle != .closed and self.pending_write == null;
}

fn opensslStreamFail(self: *TlsConnection, err: encrypted_stream.Error) encrypted_stream.Error {
    self.stream_lifecycle = .failed;
    opensslClearRetry(self);
    self.close_requested = false;
    self.stream_pause_state = .{};
    self.stream_failure = err;
    return err;
}

fn opensslSawUnexpectedEof() bool {
    const err = c.ERR_peek_error();
    if (err == 0) return true;
    if (@hasDecl(c, "ERR_GET_REASON") and @hasDecl(c, "SSL_R_UNEXPECTED_EOF_WHILE_READING")) {
        return c.ERR_GET_REASON(err) == c.SSL_R_UNEXPECTED_EOF_WHILE_READING;
    }
    return false;
}

fn opensslRefreshPeerClosed(self: *TlsConnection) void {
    self.peer_closed = self.peer_closed or (c.SSL_get_shutdown(self.ssl) & c.SSL_RECEIVED_SHUTDOWN) != 0;
}

fn opensslSetRetry(self: *TlsConnection, ssl_error: c_int) void {
    self.retry_direction = switch (ssl_error) {
        c.SSL_ERROR_WANT_READ => .read,
        c.SSL_ERROR_WANT_WRITE => .write,
        else => .none,
    };
    if (self.stream_lifecycle == .open and !self.close_requested) opensslObserveBackpressure(self);
}

fn opensslSetWriteRetry(self: *TlsConnection, bytes: []const u8, ssl_error: c_int) void {
    self.retry_direction = switch (ssl_error) {
        c.SSL_ERROR_WANT_READ => .read,
        c.SSL_ERROR_WANT_WRITE => .write,
        else => .none,
    };
    self.pending_write = OpenSslPendingWrite.init(bytes);
    if (self.stream_lifecycle == .open and !self.close_requested) opensslObserveBackpressure(self);
}

fn opensslCurrentBufferUsage(self: *const TlsConnection) encrypted_stream.QueueBytes {
    return .{
        .inbound_plaintext = if (self.stream_lifecycle == .failed or self.stream_lifecycle == .closed) 0 else self.pending(),
    };
}

fn opensslObserveBufferUsage(self: *TlsConnection) encrypted_stream.QueueBytes {
    const current = opensslCurrentBufferUsage(self);
    self.stream_buffer_peaks.inbound_plaintext = @max(self.stream_buffer_peaks.inbound_plaintext, current.inbound_plaintext);
    self.stream_peak_total = @max(self.stream_peak_total, current.total());
    return current;
}

fn opensslDerivedPauseState(self: *TlsConnection) encrypted_stream.PauseState {
    const readiness = opensslStreamReadiness(self);
    return .{
        .inbound_read_paused = self.stream_lifecycle == .open and !self.peer_closed and !readiness.wants_read and !readiness.can_read_plaintext,
        .plaintext_write_paused = self.stream_lifecycle == .open and !readiness.can_write_plaintext,
    };
}

fn opensslObserveBackpressure(self: *TlsConnection) void {
    const next = opensslDerivedPauseState(self);
    if (!self.stream_pause_state.inbound_read_paused and next.inbound_read_paused) {
        self.stream_buffer_counters.inbound_read_pauses += 1;
    } else if (self.stream_pause_state.inbound_read_paused and !next.inbound_read_paused) {
        self.stream_buffer_counters.inbound_read_resumes += 1;
    }
    if (!self.stream_pause_state.plaintext_write_paused and next.plaintext_write_paused) {
        self.stream_buffer_counters.plaintext_write_pauses += 1;
    } else if (self.stream_pause_state.plaintext_write_paused and !next.plaintext_write_paused) {
        self.stream_buffer_counters.plaintext_write_resumes += 1;
    }
    self.stream_pause_state = next;
}

fn opensslStreamBackend(_: *anyopaque) encrypted_stream.BackendKind {
    return .openssl;
}

fn opensslStreamRead(ptr: *anyopaque, out: []u8) encrypted_stream.Error!usize {
    const self: *TlsConnection = @ptrCast(@alignCast(ptr));
    if (self.stream_failure) |err| return err;
    if (self.stream_lifecycle != .open) return error.StreamClosed;
    if (self.pending_write != null) return error.RetryOperationPending;
    if (self.close_requested) return error.StreamClosed;
    _ = opensslObserveBufferUsage(self);
    c.ERR_clear_error();
    const rc = c.SSL_read(self.ssl, out.ptr, @intCast(out.len));
    _ = opensslObserveBufferUsage(self);
    if (rc > 0) {
        opensslClearRetry(self);
        opensslRefreshPeerClosed(self);
        _ = opensslObserveBufferUsage(self);
        return @intCast(rc);
    }
    const ssl_error = c.SSL_get_error(self.ssl, rc);
    return switch (ssl_error) {
        c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => blocked: {
            opensslSetRetry(self, ssl_error);
            break :blocked error.WouldBlock;
        },
        c.SSL_ERROR_ZERO_RETURN => eof: {
            opensslClearRetry(self);
            self.peer_closed = true;
            break :eof error.EndOfStream;
        },
        c.SSL_ERROR_SYSCALL => {
            if (rc == 0 and opensslSawUnexpectedEof()) return opensslStreamFail(self, error.TruncatedStream);
            return opensslStreamFail(self, error.SocketReadFailed);
        },
        c.SSL_ERROR_SSL => {
            if (opensslSawUnexpectedEof()) return opensslStreamFail(self, error.TruncatedStream);
            return opensslStreamFail(self, error.SocketReadFailed);
        },
        else => opensslStreamFail(self, error.SocketReadFailed),
    };
}

fn opensslStreamWrite(ptr: *anyopaque, bytes: []const u8) encrypted_stream.Error!usize {
    const self: *TlsConnection = @ptrCast(@alignCast(ptr));
    if (self.stream_failure) |err| return err;
    if (self.stream_lifecycle != .open) return error.StreamClosed;
    if (self.pending_write) |pending| {
        if (!pending.matches(bytes)) return error.RetryOperationPending;
    } else {
        if (self.close_requested) return error.StreamClosed;
        if (bytes.len == 0) return 0;
    }
    c.ERR_clear_error();
    const rc = c.SSL_write(self.ssl, bytes.ptr, @intCast(bytes.len));
    if (rc > 0) {
        opensslClearRetry(self);
        opensslRefreshPeerClosed(self);
        return @intCast(rc);
    }
    const ssl_error = c.SSL_get_error(self.ssl, rc);
    return switch (ssl_error) {
        c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => blocked: {
            opensslSetWriteRetry(self, bytes, ssl_error);
            break :blocked error.WouldBlock;
        },
        c.SSL_ERROR_ZERO_RETURN => eof: {
            opensslClearRetry(self);
            self.peer_closed = true;
            break :eof error.EndOfStream;
        },
        else => opensslStreamFail(self, error.SocketWriteFailed),
    };
}

fn opensslAdvanceShutdown(self: *TlsConnection) encrypted_stream.Error!bool {
    if (self.stream_failure) |err| return err;
    if (self.stream_lifecycle == .closed) return false;
    self.close_requested = true;
    if (self.pending_write != null) return error.RetryOperationPending;

    self.stream_lifecycle = .closing;
    self.stream_pause_state = .{};
    c.ERR_clear_error();
    const rc = c.SSL_shutdown(self.ssl);
    opensslRefreshPeerClosed(self);
    if (rc == 1) {
        self.stream_lifecycle = .closed;
        self.close_requested = false;
        opensslClearRetry(self);
        return true;
    }
    if (rc == 0) {
        self.retry_direction = .read;
        return true;
    }

    const ssl_error = c.SSL_get_error(self.ssl, rc);
    return switch (ssl_error) {
        c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => blocked: {
            opensslSetRetry(self, ssl_error);
            break :blocked false;
        },
        c.SSL_ERROR_ZERO_RETURN => peer_closed: {
            self.peer_closed = true;
            self.retry_direction = .write;
            break :peer_closed true;
        },
        else => opensslStreamFail(self, error.SocketWriteFailed),
    };
}

fn opensslStreamClose(ptr: *anyopaque) void {
    const self: *TlsConnection = @ptrCast(@alignCast(ptr));
    if (self.stream_lifecycle == .closed or self.stream_lifecycle == .failed) return;
    self.close_requested = true;
    _ = opensslAdvanceShutdown(self) catch {};
}

fn opensslStreamReadiness(ptr: *anyopaque) encrypted_stream.Readiness {
    const self: *TlsConnection = @ptrCast(@alignCast(ptr));
    opensslRefreshPeerClosed(self);
    if (self.stream_lifecycle == .failed or self.stream_lifecycle == .closed) {
        return .{ .peer_closed = self.peer_closed };
    }
    if (self.stream_lifecycle == .closing) {
        return .{
            .wants_read = self.retry_direction == .read,
            .wants_write = self.retry_direction == .write,
            .peer_closed = self.peer_closed,
        };
    }
    const pending = self.pending();
    if (self.pending_write != null) {
        return .{
            .wants_read = self.retry_direction == .read,
            .wants_write = self.retry_direction == .write,
            .peer_closed = self.peer_closed,
        };
    }
    if (self.close_requested) {
        return .{
            .wants_write = true,
            .peer_closed = self.peer_closed,
        };
    }
    return .{
        .wants_read = self.retry_direction == .read or (self.retry_direction == .none and pending == 0 and !self.peer_closed),
        .wants_write = self.retry_direction == .write,
        .can_read_plaintext = pending > 0,
        .can_write_plaintext = self.retry_direction == .none,
        .peer_closed = self.peer_closed,
    };
}

fn opensslStreamDrive(ptr: *anyopaque) encrypted_stream.Error!encrypted_stream.DriveResult {
    const self: *TlsConnection = @ptrCast(@alignCast(ptr));
    if (self.stream_failure) |err| return err;
    const made_progress = if (self.stream_lifecycle == .closing or (self.close_requested and self.pending_write == null))
        try opensslAdvanceShutdown(self)
    else
        false;
    if (!made_progress and (self.stream_pause_state.inbound_read_paused or self.stream_pause_state.plaintext_write_paused)) {
        self.stream_buffer_counters.stalled_drives += 1;
    }
    return .{ .made_progress = made_progress, .readiness = opensslStreamReadiness(ptr) };
}

fn opensslStreamBufferSnapshot(ptr: *anyopaque) encrypted_stream.BufferSnapshot {
    const self: *TlsConnection = @ptrCast(@alignCast(ptr));
    const current = opensslObserveBufferUsage(self);
    return .{
        .current = current,
        .peak = self.stream_buffer_peaks,
        .peak_total = self.stream_peak_total,
        .pause_state = self.stream_pause_state,
        .counters = self.stream_buffer_counters,
        .accounting_boundary = .backend_opaque,
    };
}

const openssl_stream_vtable = encrypted_stream.EncryptedStream.VTable{
    .backendFn = opensslStreamBackend,
    .readFn = opensslStreamRead,
    .writeFn = opensslStreamWrite,
    .closeFn = opensslStreamClose,
    .readinessFn = opensslStreamReadiness,
    .driveFn = opensslStreamDrive,
    .bufferSnapshotFn = opensslStreamBufferSnapshot,
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

    // OpenSSL 3.x stack helpers are not consistently available through Zig's
    // translated headers on all local toolchains. When the issuer cannot be
    // recovered portably, treat OCSP refresh as unavailable and preserve the
    // last-known-good stapled response.
    const issuer: ?*c.X509 = null;

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
    var client = std.http.Client{ .allocator = st.allocator, .io = compat.io() };
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

    var resp_body: std.ArrayList(u8) = .empty;
    defer resp_body.deinit(st.allocator);
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
        compat.cwd().writeFile(.{ .sub_path = st.ocsp_response_path, .data = new_response }) catch {}; // best-effort disk persist; response is already loaded in memory
    }
}

fn loadOcspResponse(st: *State) TlsError!void {
    if (st.ocsp_response) |old| st.allocator.free(old);
    st.ocsp_response = null;
    st.ocsp_response = std.Io.Dir.cwd().readFileAlloc(compat.io(), st.ocsp_response_path, st.allocator, .limited(1024 * 1024)) catch return error.OcspLoadFailed;
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
        var dir = std.Io.Dir.cwd().openDir(compat.io(), st.acme_cert_dir, .{ .iterate = true }) catch return;
        defer dir.close(compat.io());
        var it = dir.iterate();
        while (it.next(compat.io()) catch null) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".crt")) continue;
            const host = entry.name[0 .. entry.name.len - 4];
            const cert_path = std.fmt.allocPrint(st.allocator, "{s}/{s}", .{ st.acme_cert_dir, entry.name }) catch continue;
            defer st.allocator.free(cert_path);
            const key_file = std.fmt.allocPrint(st.allocator, "{s}.key", .{host}) catch continue;
            defer st.allocator.free(key_file);
            const key_path = std.fmt.allocPrint(st.allocator, "{s}/{s}", .{ st.acme_cert_dir, key_file }) catch continue;
            defer st.allocator.free(key_path);
            std.Io.Dir.cwd().access(compat.io(), key_path, .{}) catch continue;
            try appendSniCert(st, host, cert_path, key_path);
        }
    }
}

fn appendSniCert(st: *State, host: []const u8, cert_path: []const u8, key_path: []const u8) TlsError!void {
    const host_lc = try st.allocator.dupe(u8, host);
    for (host_lc) |*ch| ch.* = std.ascii.toLower(ch.*);
    const cert_z = try std.heap.c_allocator.dupeZ(u8, cert_path);
    const key_z = try std.heap.c_allocator.dupeZ(u8, key_path);
    try st.sni_certs.append(st.allocator, .{
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

fn clientHelloCallback(ssl: ?*c.SSL, alert: [*c]c_int, arg: ?*anyopaque) callconv(.c) c_int {
    const s = ssl orelse return c.SSL_CLIENT_HELLO_ERROR;
    const state: *State = @ptrCast(@alignCast(arg orelse return c.SSL_CLIENT_HELLO_ERROR));
    const policy = policyForSsl(s, state.policy_ex_index) orelse return c.SSL_CLIENT_HELLO_ERROR;

    var ext_ptr: [*c]const u8 = null;
    var ext_len: usize = 0;
    const present = SSL_client_hello_get0_ext(
        s,
        c.TLSEXT_TYPE_application_layer_protocol_negotiation,
        &ext_ptr,
        &ext_len,
    ) == 1;
    if (!present) {
        if (policy.fallbackPolicy() == .allow_http1_default) return c.SSL_CLIENT_HELLO_SUCCESS;
        alert.* = c.SSL_AD_NO_APPLICATION_PROTOCOL;
        return c.SSL_CLIENT_HELLO_ERROR;
    }
    const ext = ext_ptr[0..ext_len];
    if (!isValidAlpnExtension(ext)) {
        alert.* = c.SSL_AD_NO_APPLICATION_PROTOCOL;
        return c.SSL_CLIENT_HELLO_ERROR;
    }
    return c.SSL_CLIENT_HELLO_SUCCESS;
}

fn policyForSsl(s: *c.SSL, policy_ex_index: c_int) ?*const negotiated_dispatch.ListenerProtocolPolicy {
    if (policy_ex_index < 0) return null;
    return @ptrCast(@alignCast(c.SSL_get_ex_data(s, policy_ex_index)));
}

fn isValidAlpnExtension(ext: []const u8) bool {
    if (ext.len < 2) return false;
    const list_len = std.mem.readInt(u16, ext[0..2], .big);
    if (list_len == 0 or list_len != ext.len - 2) return false;
    var offset: usize = 2;
    while (offset < ext.len) {
        const name_len = ext[offset];
        offset += 1;
        if (name_len == 0) return false;
        if (offset + name_len > ext.len) return false;
        offset += name_len;
    }
    return offset == ext.len;
}

fn alpnSelectCallback(
    _ssl: ?*c.SSL,
    out: [*c][*c]u8,
    outlen: [*c]u8,
    in: [*c]const u8,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    const s = _ssl orelse return c.SSL_TLSEXT_ERR_ALERT_FATAL;
    const state: *State = @ptrCast(@alignCast(arg orelse return c.SSL_TLSEXT_ERR_ALERT_FATAL));
    const policy = policyForSsl(s, state.policy_ex_index) orelse return c.SSL_TLSEXT_ERR_ALERT_FATAL;
    const server_protos = policy.encodedAdvertisedAlpns();
    if (server_protos.len == 0) return c.SSL_TLSEXT_ERR_ALERT_FATAL;
    const rc = c.SSL_select_next_proto(out, outlen, server_protos.ptr, @intCast(server_protos.len), in, inlen);
    return if (rc == openssl_npn_negotiated) c.SSL_TLSEXT_ERR_OK else c.SSL_TLSEXT_ERR_ALERT_FATAL;
}

fn fileMtime(path: []const u8) !i128 {
    const stat = try std.Io.Dir.cwd().statFile(compat.io(), path, .{});
    return @intCast(stat.mtime.toNanoseconds());
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
    /// Offer HTTP/2 via ALPN ("h2", "http/1.1"). When false only "http/1.1"
    /// is offered. The negotiated protocol is read via `negotiatedProtocol`.
    offer_h2: bool = false,
};

/// An OpenSSL-backed TLS client connection to a TCP stream.
/// Used for upstream HTTPS connections that require mTLS or custom CA/SNI.
pub const UpstreamTlsConn = struct {
    ssl: *c.SSL,
    ctx: *c.SSL_CTX,
    fd: std.posix.fd_t = -1,

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

        // Offer ALPN. h2 must precede http/1.1 (client preference order).
        const alpn_wire: []const u8 = if (opts.offer_h2) "\x02h2\x08http/1.1" else "\x08http/1.1";
        _ = c.SSL_set_alpn_protos(ssl, alpn_wire.ptr, @intCast(alpn_wire.len));

        if (!opts.skip_verify) {
            const verify_host_z = try std.heap.c_allocator.dupeZ(u8, sni_host);
            defer std.heap.c_allocator.free(verify_host_z);
            const param = c.SSL_get0_param(ssl);
            _ = c.X509_VERIFY_PARAM_set_hostflags(param, c.X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (c.X509_VERIFY_PARAM_set1_host(param, verify_host_z.ptr, 0) != 1) return error.VerifyConfigFailed;
        }

        if (c.SSL_set_fd(ssl, fd) != 1) return error.HandshakeFailed;
        if (c.SSL_connect(ssl) != 1) return error.HandshakeFailed;

        return .{ .ssl = ssl, .ctx = ctx, .fd = fd };
    }

    pub fn deinit(self: *UpstreamTlsConn) void {
        _ = c.SSL_shutdown(self.ssl);
        c.SSL_free(self.ssl);
        c.SSL_CTX_free(self.ctx);
        self.* = undefined;
    }

    /// Full teardown for owners that also own the fd (e.g. the h2 connection
    /// actor): SSL shutdown/free, then close the socket. Unlike `deinit`, which
    /// leaves the fd to a separate `NetStream.close()` (the HTTP/1.1 pool's
    /// ownership split), this closes the fd itself.
    pub fn close(self: *UpstreamTlsConn) void {
        const fd = self.fd;
        self.deinit();
        if (fd >= 0) _ = std.c.close(fd);
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

    /// Bytes already decrypted and buffered in OpenSSL, not yet read. A `poll`
    /// on the fd cannot see these, so callers that poll-bound their reads must
    /// check this first.
    pub fn pending(self: *const UpstreamTlsConn) usize {
        const n = c.SSL_pending(self.ssl);
        return if (n > 0) @intCast(n) else 0;
    }

    /// The ALPN protocol the handshake selected (`.http2` if the peer chose h2,
    /// else `.http1_1`).
    pub fn negotiatedProtocol(self: *const UpstreamTlsConn) NegotiatedProtocol {
        var data: [*c]const u8 = null;
        var len: c_uint = 0;
        c.SSL_get0_alpn_selected(self.ssl, &data, &len);
        if (data != null and len == 2 and std.mem.eql(u8, data[0..2], "h2")) return .http2;
        return .http1_1;
    }
};

const TestTlsPair = struct {
    client_ssl: *c.SSL,
    client_ctx: *c.SSL_CTX,
    client_fd: std.posix.fd_t,
    server_fd: std.posix.fd_t,
    server: TlsConnection,

    fn deinit(self: *TestTlsPair) void {
        self.server.deinit();
        c.SSL_free(self.client_ssl);
        c.SSL_CTX_free(self.client_ctx);
        _ = std.c.close(self.client_fd);
        _ = std.c.close(self.server_fd);
        self.* = undefined;
    }
};

const TestTlsPairOptions = struct {
    server_http1_enabled: bool = true,
    server_http2_enabled: bool = true,
    server_http1_alpn_fallback_enabled: bool = false,
    client_alpn_wire: ?[]const u8 = http11_only_wire_for_tests,
};

const h2_and_http11_wire_for_tests = "\x02h2\x08http/1.1";
const http11_and_h2_wire_for_tests = "\x08http/1.1\x02h2";
const http11_only_wire_for_tests = "\x08http/1.1";

const ServerAcceptContext = struct {
    terminator: *TlsTerminator,
    fd: std.posix.fd_t,
    conn: ?TlsConnection = null,
    err: ?TlsError = null,
};

fn serverAcceptThread(ctx: *ServerAcceptContext) void {
    ctx.conn = ctx.terminator.accept(ctx.fd) catch |err| {
        ctx.err = err;
        return;
    };
}

fn testSetNonBlocking(fd: std.posix.fd_t, nonblocking: bool) !void {
    const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (status_flags < 0) return error.FcntlFailed;
    const nonblock = @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
    const new_flags = if (nonblocking) status_flags | nonblock else status_flags & ~nonblock;
    if (std.c.fcntl(fd, std.c.F.SETFL, new_flags) < 0) return error.FcntlFailed;
}

fn makeTestTlsPair(allocator: std.mem.Allocator) !TestTlsPair {
    return makeTestTlsPairWithOptions(allocator, .{});
}

fn makeTestTlsPairWithOptions(allocator: std.mem.Allocator, opts: TestTlsPairOptions) !TestTlsPair {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "test_server.crt", .data = embedded_server_crt });
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "test_server.key", .data = embedded_server_key });
    const cert_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, "test_server.crt");
    defer allocator.free(cert_path);
    const key_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, "test_server.key");
    defer allocator.free(key_path);

    var terminator = try TlsTerminator.init(allocator, .{
        .cert_path = cert_path,
        .key_path = key_path,
        .dynamic_reload_interval_ms = 0,
        .http1_enabled = opts.server_http1_enabled,
        .http2_enabled = opts.server_http2_enabled,
        .http1_alpn_fallback_enabled = opts.server_http1_alpn_fallback_enabled,
    });
    defer terminator.deinit();

    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    errdefer _ = std.c.close(fds[0]);
    errdefer _ = std.c.close(fds[1]);

    var accept_ctx = ServerAcceptContext{ .terminator = &terminator, .fd = fds[1] };
    const thread = try std.Thread.spawn(.{}, serverAcceptThread, .{&accept_ctx});
    var thread_joined = false;
    defer if (!thread_joined) thread.join();

    const client_ctx = c.SSL_CTX_new(c.TLS_client_method() orelse return error.ContextInitFailed) orelse return error.ContextInitFailed;
    errdefer c.SSL_CTX_free(client_ctx);
    c.SSL_CTX_set_verify(client_ctx, c.SSL_VERIFY_NONE, null);
    const client_ssl = c.SSL_new(client_ctx) orelse return error.ContextInitFailed;
    errdefer c.SSL_free(client_ssl);
    if (opts.client_alpn_wire) |wire| {
        if (c.SSL_set_alpn_protos(client_ssl, wire.ptr, @intCast(wire.len)) != 0) return error.ProtocolConfigFailed;
    }
    if (c.SSL_set_fd(client_ssl, fds[0]) != 1) return error.HandshakeFailed;
    if (c.SSL_connect(client_ssl) != 1) return error.HandshakeFailed;

    thread.join();
    thread_joined = true;
    if (accept_ctx.err) |err| return err;
    var server = accept_ctx.conn orelse return error.HandshakeFailed;
    errdefer server.deinit();

    try testSetNonBlocking(fds[1], true);

    return .{
        .client_ssl = client_ssl,
        .client_ctx = client_ctx,
        .client_fd = fds[0],
        .server_fd = fds[1],
        .server = server,
    };
}

fn clientWriteAll(ssl: *c.SSL, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const rc = c.SSL_write(ssl, bytes.ptr + offset, @intCast(bytes.len - offset));
        if (rc <= 0) return error.TlsWriteFailed;
        offset += @intCast(rc);
    }
}

fn clientReadExact(ssl: *c.SSL, out: []u8) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const rc = c.SSL_read(ssl, out.ptr + offset, @intCast(out.len - offset));
        if (rc <= 0) return error.TlsReadFailed;
        offset += @intCast(rc);
    }
}

const ClientReadContext = struct {
    ssl: *c.SSL,
    out: []u8,
    err: ?anyerror = null,
};

fn clientReadThread(ctx: *ClientReadContext) void {
    clientReadExact(ctx.ssl, ctx.out) catch |err| {
        ctx.err = err;
    };
}

const ClientReadToCloseContext = struct {
    ssl: *c.SSL,
    allocator: std.mem.Allocator,
    out: std.ArrayList(u8) = .empty,
    err: ?anyerror = null,

    fn deinit(self: *ClientReadToCloseContext) void {
        self.out.deinit(self.allocator);
    }
};

fn clientReadToCloseThread(ctx: *ClientReadToCloseContext) void {
    var buf: [4096]u8 = undefined;
    while (true) {
        c.ERR_clear_error();
        const rc = c.SSL_read(ctx.ssl, &buf, buf.len);
        if (rc > 0) {
            ctx.out.appendSlice(ctx.allocator, buf[0..@intCast(rc)]) catch |err| {
                ctx.err = err;
                return;
            };
            continue;
        }

        const ssl_error = c.SSL_get_error(ctx.ssl, rc);
        switch (ssl_error) {
            c.SSL_ERROR_ZERO_RETURN => {
                c.ERR_clear_error();
                _ = c.SSL_shutdown(ctx.ssl);
                return;
            },
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => std.Thread.yield() catch {},
            else => {
                ctx.err = error.TlsReadFailed;
                return;
            },
        }
    }
}

const ForcedWriteBlock = struct {
    expected: std.ArrayList(u8) = .empty,
    chunk: [16 * 1024]u8 = undefined,
    retry_bytes: []const u8 = &.{},

    fn deinit(self: *ForcedWriteBlock, allocator: std.mem.Allocator) void {
        self.expected.deinit(allocator);
    }
};

fn forceOpenSslWriteBackpressure(
    allocator: std.mem.Allocator,
    pair: *TestTlsPair,
    stream: encrypted_stream.EncryptedStream,
    blocked: *ForcedWriteBlock,
) !void {
    blocked.* = .{};
    errdefer {
        blocked.deinit(allocator);
        blocked.* = .{};
    }

    const send_buffer: c_int = 4096;
    try std.posix.setsockopt(pair.server_fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&send_buffer));

    write_until_blocked: for (0..1024) |sequence| {
        for (&blocked.chunk, 0..) |*byte, index| byte.* = @truncate(sequence + index);
        var remaining: []const u8 = &blocked.chunk;
        while (remaining.len > 0) {
            const written = stream.write(remaining) catch |err| switch (err) {
                error.WouldBlock => {
                    blocked.retry_bytes = remaining;
                    break :write_until_blocked;
                },
                else => return err,
            };
            try std.testing.expect(written > 0);
            try blocked.expected.appendSlice(allocator, remaining[0..written]);
            remaining = remaining[written..];
        }
    }

    if (blocked.retry_bytes.len == 0) return error.TestUnexpectedResult;
}

test "openssl init" {
    try std.testing.expect(c.OPENSSL_init_ssl(0, null) == 1);
}

test "tls terminator copies sni specs for maintenance reload" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "test_server.crt", .data = embedded_server_crt });
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "test_server.key", .data = embedded_server_key });
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "test_alt_server.crt", .data = embedded_alt_server_crt });
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "test_alt_server.key", .data = embedded_alt_server_key });

    const alt_cert_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, "test_alt_server.crt");
    defer allocator.free(alt_cert_path);
    const alt_key_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, "test_alt_server.key");
    defer allocator.free(alt_key_path);
    const cert_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, "test_server.crt");
    defer allocator.free(cert_path);
    const key_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, "test_server.key");
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

test "tls terminator updates protocol policy for future snapshots" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "test_server.crt", .data = embedded_server_crt });
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "test_server.key", .data = embedded_server_key });

    const cert_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, "test_server.crt");
    defer allocator.free(cert_path);
    const key_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, "test_server.key");
    defer allocator.free(key_path);

    var tls = try TlsTerminator.init(allocator, .{
        .cert_path = cert_path,
        .key_path = key_path,
        .http1_enabled = true,
        .http2_enabled = true,
    });
    defer tls.deinit();

    const initial = tls.protocolPolicySnapshot();
    try std.testing.expect(initial.http1_enabled);
    try std.testing.expect(initial.http2_enabled);

    try tls.updateProtocolPolicy(.{ .http1_enabled = true, .http2_enabled = false });
    const reloaded = tls.protocolPolicySnapshot();
    try std.testing.expect(reloaded.http1_enabled);
    try std.testing.expect(!reloaded.http2_enabled);
    try std.testing.expectError(error.ProtocolConfigFailed, tls.updateProtocolPolicy(.{ .http1_enabled = false, .http2_enabled = false }));
}

test "openssl encrypted stream adapter conforms over production connection" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPair(allocator);
    defer pair.deinit();

    const stream = pair.server.stream();
    try encrypted_stream.expectOpenIdleConformance(stream, .openssl);

    var scratch: [32]u8 = undefined;
    try clientWriteAll(pair.client_ssl, "client-payload");
    const pending_snapshot = stream.bufferSnapshot();
    try std.testing.expectEqual(encrypted_stream.AccountingBoundary.backend_opaque, pending_snapshot.accounting_boundary);
    try std.testing.expect(!pending_snapshot.limits_enforced);
    try std.testing.expect(pending_snapshot.limits == null);
    const partial = try stream.read(scratch[0..6]);
    try std.testing.expectEqualStrings("client", scratch[0..partial]);
    try std.testing.expect(stream.readiness().can_read_plaintext);
    var buffered_snapshot = stream.bufferSnapshot();
    try std.testing.expect(buffered_snapshot.current.inbound_plaintext > 0);
    try std.testing.expect(buffered_snapshot.peak.inbound_plaintext >= buffered_snapshot.current.inbound_plaintext);

    const rest = try stream.read(scratch[0..16]);
    try std.testing.expectEqualStrings("-payload", scratch[0..rest]);
    try std.testing.expect(!stream.readiness().can_read_plaintext);
    buffered_snapshot = stream.bufferSnapshot();
    try std.testing.expectEqual(@as(usize, 0), buffered_snapshot.current.inbound_plaintext);
    try std.testing.expect(buffered_snapshot.peak.inbound_plaintext > 0);

    const written = try stream.write("server-reply");
    try std.testing.expectEqual(@as(usize, "server-reply".len), written);
    var client_buf: ["server-reply".len]u8 = undefined;
    try clientReadExact(pair.client_ssl, &client_buf);
    try std.testing.expectEqualStrings("server-reply", &client_buf);
}

test "openssl listener ALPN follows server preference" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPairWithOptions(allocator, .{
        .client_alpn_wire = http11_and_h2_wire_for_tests,
    });
    defer pair.deinit();

    try std.testing.expectEqual(NegotiatedProtocol.http2, try pair.server.validatedNegotiatedProtocol());
    try std.testing.expectEqualStrings("h2", pair.server.negotiatedAlpn().?);
}

test "openssl h1-only listener advertises only HTTP/1.1" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPairWithOptions(allocator, .{
        .server_http2_enabled = false,
        .client_alpn_wire = h2_and_http11_wire_for_tests,
    });
    defer pair.deinit();

    try std.testing.expectEqual(NegotiatedProtocol.http1_1, try pair.server.validatedNegotiatedProtocol());
    try std.testing.expectEqualStrings("http/1.1", pair.server.negotiatedAlpn().?);
}

test "openssl h2-only listener accepts only h2" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPairWithOptions(allocator, .{
        .server_http1_enabled = false,
        .server_http2_enabled = true,
        .client_alpn_wire = h2_and_http11_wire_for_tests,
    });
    defer pair.deinit();

    try std.testing.expectEqual(NegotiatedProtocol.http2, try pair.server.validatedNegotiatedProtocol());
    try std.testing.expectEqualStrings("h2", pair.server.negotiatedAlpn().?);

    try std.testing.expectError(error.HandshakeFailed, makeTestTlsPairWithOptions(allocator, .{
        .server_http1_enabled = false,
        .server_http2_enabled = true,
        .client_alpn_wire = http11_only_wire_for_tests,
    }));
}

test "openssl absent ALPN requires explicit HTTP/1.1 fallback during handshake" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.HandshakeFailed, makeTestTlsPairWithOptions(allocator, .{
        .client_alpn_wire = null,
        .server_http1_alpn_fallback_enabled = false,
    }));

    var fallback = try makeTestTlsPairWithOptions(allocator, .{
        .client_alpn_wire = null,
        .server_http1_alpn_fallback_enabled = true,
    });
    defer fallback.deinit();
    try std.testing.expect(fallback.server.negotiatedAlpn() == null);
    try std.testing.expectEqual(NegotiatedProtocol.http1_1, try fallback.server.validatedNegotiatedProtocol());
}

test "openssl encrypted stream preserves write retry direction under socket backpressure" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPair(allocator);
    defer pair.deinit();

    const stream = pair.server.stream();
    var blocked: ForcedWriteBlock = .{};
    defer blocked.deinit(allocator);
    try forceOpenSslWriteBackpressure(allocator, &pair, stream, &blocked);
    const retry_bytes = blocked.retry_bytes;
    const blocked_readiness = stream.readiness();
    try std.testing.expect(!blocked_readiness.wants_read);
    try std.testing.expect(blocked_readiness.wants_write);
    try std.testing.expect(!blocked_readiness.can_write_plaintext);
    const blocked_drive = try stream.drive();
    try std.testing.expect(!blocked_drive.made_progress);
    try std.testing.expect(blocked_drive.readiness.wants_write);
    const blocked_snapshot = stream.bufferSnapshot();
    try std.testing.expectEqual(encrypted_stream.AccountingBoundary.backend_opaque, blocked_snapshot.accounting_boundary);
    try std.testing.expect(!blocked_snapshot.limits_enforced);
    try std.testing.expect(blocked_snapshot.limits == null);
    try std.testing.expect(blocked_snapshot.pause_state.plaintext_write_paused);
    try std.testing.expectEqual(@as(u64, 1), blocked_snapshot.counters.plaintext_write_pauses);
    try std.testing.expectEqual(@as(u64, 0), blocked_snapshot.counters.plaintext_write_resumes);
    try std.testing.expectEqual(@as(u64, 1), blocked_snapshot.counters.stalled_drives);
    const repeated_blocked_drive = try stream.drive();
    try std.testing.expect(!repeated_blocked_drive.made_progress);
    const repeated_blocked_snapshot = stream.bufferSnapshot();
    try std.testing.expectEqual(@as(u64, 1), repeated_blocked_snapshot.counters.plaintext_write_pauses);
    try std.testing.expectEqual(@as(u64, 0), repeated_blocked_snapshot.counters.plaintext_write_resumes);
    try std.testing.expectEqual(@as(u64, 2), repeated_blocked_snapshot.counters.stalled_drives);

    var interleaved_read: [1]u8 = undefined;
    try std.testing.expectError(error.RetryOperationPending, stream.read(&interleaved_read));
    const changed_retry = try allocator.dupe(u8, retry_bytes);
    defer allocator.free(changed_retry);
    changed_retry[0] +%= 1;
    try std.testing.expectError(error.RetryOperationPending, stream.write(changed_retry));
    try std.testing.expect(stream.readiness().wants_write);
    try std.testing.expect(!stream.readiness().can_write_plaintext);

    const target = try allocator.alloc(u8, blocked.expected.items.len + retry_bytes.len);
    defer allocator.free(target);
    @memcpy(target[0..blocked.expected.items.len], blocked.expected.items);
    @memcpy(target[blocked.expected.items.len..], retry_bytes);
    const received = try allocator.alloc(u8, target.len);
    defer allocator.free(received);
    var read_ctx = ClientReadContext{ .ssl = pair.client_ssl, .out = received };
    const reader = try std.Thread.spawn(.{}, clientReadThread, .{&read_ctx});

    var remaining = retry_bytes;
    while (remaining.len > 0) {
        const written = stream.write(remaining) catch |err| switch (err) {
            error.WouldBlock => {
                std.Thread.yield() catch {};
                continue;
            },
            else => return err,
        };
        try std.testing.expect(written > 0);
        remaining = remaining[written..];
    }
    reader.join();
    if (read_ctx.err) |err| return err;

    try std.testing.expectEqualSlices(u8, target, received);
    try std.testing.expect(!stream.readiness().wants_write);
    try std.testing.expect(stream.readiness().can_write_plaintext);
    const resumed_snapshot = stream.bufferSnapshot();
    try std.testing.expect(!resumed_snapshot.pause_state.plaintext_write_paused);
    try std.testing.expectEqual(@as(u64, 1), resumed_snapshot.counters.plaintext_write_resumes);
}

test "openssl encrypted stream records pending plaintext peak before first snapshot" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPair(allocator);
    defer pair.deinit();

    const stream = pair.server.stream();
    try clientWriteAll(pair.client_ssl, "client-payload");

    var scratch: [6]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 6), try stream.read(&scratch));
    try std.testing.expectEqualStrings("client", &scratch);

    var rest: [16]u8 = undefined;
    const rest_len = try stream.read(&rest);
    try std.testing.expectEqualStrings("-payload", rest[0..rest_len]);

    const snapshot = stream.bufferSnapshot();
    try std.testing.expectEqual(@as(usize, 0), snapshot.current.inbound_plaintext);
    try std.testing.expect(snapshot.peak.inbound_plaintext >= "-payload".len);
    try std.testing.expect(snapshot.peak_total >= "-payload".len);
    try std.testing.expect(!snapshot.limits_enforced);
    try std.testing.expect(snapshot.limits == null);
}

test "openssl encrypted stream preserves close requested during pending write retry" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPair(allocator);
    defer pair.deinit();

    const stream = pair.server.stream();
    var blocked: ForcedWriteBlock = .{};
    defer blocked.deinit(allocator);
    try forceOpenSslWriteBackpressure(allocator, &pair, stream, &blocked);

    stream.close();
    try std.testing.expect(pair.server.close_requested);
    try std.testing.expectEqual(OpenSslStreamLifecycle.open, pair.server.stream_lifecycle);
    const close_blocked = stream.readiness();
    try std.testing.expect(close_blocked.wants_write);
    try std.testing.expect(!close_blocked.can_write_plaintext);

    var read_ctx = ClientReadToCloseContext{ .ssl = pair.client_ssl, .allocator = allocator };
    defer read_ctx.deinit();
    const reader = try std.Thread.spawn(.{}, clientReadToCloseThread, .{&read_ctx});

    var retry_written: usize = 0;
    while (pair.server.pending_write != null) {
        const written = stream.write(blocked.retry_bytes) catch |err| switch (err) {
            error.WouldBlock => {
                std.Thread.yield() catch {};
                continue;
            },
            else => return err,
        };
        try std.testing.expect(written > 0);
        retry_written += written;
    }
    try std.testing.expect(retry_written > 0);
    try blocked.expected.appendSlice(allocator, blocked.retry_bytes[0..retry_written]);

    const pending_close = stream.readiness();
    try std.testing.expect(pending_close.wants_write);
    try std.testing.expect(!pending_close.can_write_plaintext);
    try std.testing.expectError(error.StreamClosed, stream.write("after-close"));

    for (0..1024) |_| {
        _ = try stream.drive();
        if (pair.server.stream_lifecycle == .closed) break;
        std.Thread.yield() catch {};
    }

    reader.join();
    if (read_ctx.err) |err| return err;

    for (0..1024) |_| {
        _ = try stream.drive();
        if (pair.server.stream_lifecycle == .closed) break;
        std.Thread.yield() catch {};
    }
    try std.testing.expectEqual(OpenSslStreamLifecycle.closed, pair.server.stream_lifecycle);
    try std.testing.expectEqualSlices(u8, blocked.expected.items, read_ctx.out.items);
    try encrypted_stream.expectClosedConformance(stream);
}

test "openssl encrypted stream close does not synthesize pause transitions" {
    const allocator = std.testing.allocator;

    {
        var pair = try makeTestTlsPair(allocator);
        defer pair.deinit();
        const stream = pair.server.stream();

        const before = stream.bufferSnapshot();
        try std.testing.expectEqual(@as(u64, 0), before.counters.inbound_read_pauses);
        try std.testing.expectEqual(@as(u64, 0), before.counters.plaintext_write_pauses);

        stream.close();
        const after = stream.bufferSnapshot();
        try std.testing.expect(!after.pause_state.inbound_read_paused);
        try std.testing.expect(!after.pause_state.plaintext_write_paused);
        try std.testing.expectEqual(@as(u64, 0), after.counters.inbound_read_pauses);
        try std.testing.expectEqual(@as(u64, 0), after.counters.inbound_read_resumes);
        try std.testing.expectEqual(@as(u64, 0), after.counters.plaintext_write_pauses);
        try std.testing.expectEqual(@as(u64, 0), after.counters.plaintext_write_resumes);
    }

    {
        var pair = try makeTestTlsPair(allocator);
        defer pair.deinit();
        const stream = pair.server.stream();
        var blocked: ForcedWriteBlock = .{};
        defer blocked.deinit(allocator);
        try forceOpenSslWriteBackpressure(allocator, &pair, stream, &blocked);

        const before_close = stream.bufferSnapshot();
        try std.testing.expect(before_close.pause_state.plaintext_write_paused);
        try std.testing.expectEqual(@as(u64, 1), before_close.counters.plaintext_write_pauses);

        stream.close();
        const after_close = stream.bufferSnapshot();
        try std.testing.expect(after_close.pause_state.plaintext_write_paused);
        try std.testing.expectEqual(@as(u64, 1), after_close.counters.plaintext_write_pauses);
        try std.testing.expectEqual(@as(u64, 0), after_close.counters.plaintext_write_resumes);
    }
}

test "openssl encrypted stream cleanup skips shutdown with pending write retry" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPair(allocator);
    defer pair.deinit();

    const stream = pair.server.stream();
    var blocked: ForcedWriteBlock = .{};
    defer blocked.deinit(allocator);
    try forceOpenSslWriteBackpressure(allocator, &pair, stream, &blocked);

    try std.testing.expect(pair.server.pending_write != null);
    try std.testing.expect(!opensslShouldShutdownOnDeinit(&pair.server));
}

test "openssl encrypted stream drives graceful bidirectional shutdown" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPair(allocator);
    defer pair.deinit();

    const stream = pair.server.stream();
    stream.close();
    const closing = stream.readiness();
    try std.testing.expect(closing.wants_read);
    try std.testing.expect(!closing.peer_closed);
    try std.testing.expect(!closing.can_write_plaintext);

    var byte: [1]u8 = undefined;
    c.ERR_clear_error();
    const read_rc = c.SSL_read(pair.client_ssl, &byte, byte.len);
    try std.testing.expectEqual(@as(c_int, 0), read_rc);
    try std.testing.expectEqual(c.SSL_ERROR_ZERO_RETURN, c.SSL_get_error(pair.client_ssl, read_rc));
    try std.testing.expect((c.SSL_get_shutdown(pair.client_ssl) & c.SSL_RECEIVED_SHUTDOWN) != 0);

    c.ERR_clear_error();
    try std.testing.expectEqual(@as(c_int, 1), c.SSL_shutdown(pair.client_ssl));
    const driven = try stream.drive();
    try std.testing.expect(driven.made_progress);
    try std.testing.expect(driven.readiness.peer_closed);
    try std.testing.expect(!driven.readiness.wants_read);
    try std.testing.expect(!driven.readiness.wants_write);
    try encrypted_stream.expectClosedConformance(stream);
}

test "openssl encrypted stream keeps write side open after peer close_notify" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPair(allocator);
    defer pair.deinit();

    const stream = pair.server.stream();
    try std.testing.expectEqual(@as(c_int, 0), c.SSL_shutdown(pair.client_ssl));

    var scratch: [32]u8 = undefined;
    try std.testing.expectError(error.EndOfStream, stream.read(&scratch));
    const one_sided = stream.readiness();
    try std.testing.expect(one_sided.peer_closed);
    try std.testing.expect(!one_sided.wants_read);
    try std.testing.expect(one_sided.can_write_plaintext);

    const final_payload = "server-final";
    try std.testing.expectEqual(final_payload.len, try stream.write(final_payload));
    var client_buf: [final_payload.len]u8 = undefined;
    try clientReadExact(pair.client_ssl, &client_buf);
    try std.testing.expectEqualStrings(final_payload, &client_buf);

    stream.close();
    for (0..1024) |_| {
        _ = try stream.drive();
        if (pair.server.stream_lifecycle == .closed) break;
        std.Thread.yield() catch {};
    }

    c.ERR_clear_error();
    try std.testing.expectEqual(@as(c_int, 1), c.SSL_shutdown(pair.client_ssl));
    const driven = try stream.drive();
    try std.testing.expect(driven.readiness.peer_closed);
    try encrypted_stream.expectClosedConformance(stream);
}

test "openssl encrypted stream adapter reports peer EOF" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPair(allocator);
    defer pair.deinit();

    const stream = pair.server.stream();
    _ = c.SSL_shutdown(pair.client_ssl);

    var scratch: [8]u8 = undefined;
    try std.testing.expectError(error.EndOfStream, stream.read(&scratch));
}

test "openssl encrypted stream reports truncation without peer close_notify" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPair(allocator);
    defer pair.deinit();

    try std.testing.expectEqual(@as(c_int, 0), std.c.shutdown(pair.client_fd, std.posix.SHUT.WR));

    var scratch: [8]u8 = undefined;
    const stream = pair.server.stream();
    try std.testing.expectError(error.TruncatedStream, stream.read(&scratch));
    try encrypted_stream.expectLatchedFailureConformance(stream, error.TruncatedStream);
}

test "openssl encrypted stream adapter latches fatal wire failures" {
    const allocator = std.testing.allocator;
    var pair = try makeTestTlsPair(allocator);
    defer pair.deinit();

    const malformed = "not a TLS record";
    try std.testing.expectEqual(@as(isize, @intCast(malformed.len)), std.c.write(pair.client_fd, malformed.ptr, malformed.len));

    var scratch: [32]u8 = undefined;
    const stream = pair.server.stream();
    try std.testing.expectError(error.SocketReadFailed, stream.read(&scratch));
    try encrypted_stream.expectLatchedFailureConformance(stream, error.SocketReadFailed);
    stream.close();
    try std.testing.expectEqual(OpenSslStreamLifecycle.failed, pair.server.stream_lifecycle);
    try std.testing.expectEqual(@as(c_int, 0), c.SSL_get_shutdown(pair.server.ssl) & c.SSL_SENT_SHUTDOWN);
}
