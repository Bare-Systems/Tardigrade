const std = @import("std");

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});

pub const TlsError = error{
    OutOfMemory,
    OpenSslInitFailed,
    ContextInitFailed,
    CertificateLoadFailed,
    PrivateKeyLoadFailed,
    CertificateKeyMismatch,
    HandshakeFailed,
    TlsReadFailed,
    TlsWriteFailed,
};

pub const TlsTerminator = struct {
    ctx: *c.SSL_CTX,

    pub fn init(cert_path: []const u8, key_path: []const u8) TlsError!TlsTerminator {
        if (c.OPENSSL_init_ssl(0, null) != 1) return error.OpenSslInitFailed;

        const cert_z = std.heap.c_allocator.dupeZ(u8, cert_path) catch return error.OutOfMemory;
        defer std.heap.c_allocator.free(cert_z);
        const key_z = std.heap.c_allocator.dupeZ(u8, key_path) catch return error.OutOfMemory;
        defer std.heap.c_allocator.free(key_z);

        const method = c.TLS_server_method() orelse return error.ContextInitFailed;
        const ctx = c.SSL_CTX_new(method) orelse return error.ContextInitFailed;
        errdefer c.SSL_CTX_free(ctx);

        if (c.SSL_CTX_use_certificate_file(ctx, cert_z.ptr, c.SSL_FILETYPE_PEM) != 1) {
            return error.CertificateLoadFailed;
        }

        if (c.SSL_CTX_use_PrivateKey_file(ctx, key_z.ptr, c.SSL_FILETYPE_PEM) != 1) {
            return error.PrivateKeyLoadFailed;
        }

        if (c.SSL_CTX_check_private_key(ctx) != 1) {
            return error.CertificateKeyMismatch;
        }

        // Disable legacy protocols; only TLS 1.2+.
        _ = c.SSL_CTX_set_min_proto_version(ctx, c.TLS1_2_VERSION);

        return .{ .ctx = ctx };
    }

    pub fn deinit(self: *TlsTerminator) void {
        c.SSL_CTX_free(self.ctx);
        self.* = undefined;
    }

    pub fn accept(self: *TlsTerminator, fd: std.posix.fd_t) TlsError!TlsConnection {
        const ssl = c.SSL_new(self.ctx) orelse return error.ContextInitFailed;
        errdefer c.SSL_free(ssl);

        if (c.SSL_set_fd(ssl, fd) != 1) {
            return error.HandshakeFailed;
        }

        if (c.SSL_accept(ssl) != 1) {
            return error.HandshakeFailed;
        }

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

        const err_code = c.SSL_get_error(self.ssl, rc);
        if (err_code == c.SSL_ERROR_ZERO_RETURN) return 0;
        return error.TlsReadFailed;
    }

    pub const Writer = std.io.Writer(*TlsConnection, TlsError, writeFn);

    pub fn writer(self: *TlsConnection) Writer {
        return .{ .context = self };
    }

    fn writeFn(self: *TlsConnection, data: []const u8) TlsError!usize {
        const rc = c.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (rc > 0) return @intCast(rc);
        return error.TlsWriteFailed;
    }
};

test "openssl init" {
    try std.testing.expect(c.OPENSSL_init_ssl(0, null) == 1);
}
