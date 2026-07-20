//! No-OpenSSL TLS termination stub for the Bare Systems appliance profile
//! (#379, epic #327).
//!
//! Selected by `-Dtls-profile=appliance` in `src/http.zig`. Presents the
//! same public surface as `tls_termination.zig` so every call site compiles
//! unchanged, but contains no `@cImport`, no OpenSSL types, and no C
//! linkage. Until the native TLS path lands (#391 defines the appliance
//! support matrix), any attempt to construct a terminator or upstream TLS
//! connection fails closed at startup with `error.ContextInitFailed` — a
//! deliberate, inspectable failure rather than a hidden runtime fallback.
//!
//! Option structs are duplicated field-for-field from the adapter so
//! configuration parsing behaves identically in both profiles; only the
//! I/O-bearing types are inert.

const std = @import("std");
const encrypted_stream = @import("tls_core").encrypted_stream;
const negotiated_dispatch = @import("negotiated_dispatch.zig");

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
    NoApplicationProtocol,
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
    ocsp_auto_refresh_enabled: bool = false,
    ocsp_refresh_interval_ms: u64 = 3_600_000,
    ocsp_refresh_timeout_ms: u32 = 10_000,
    client_ca_path: []const u8 = "",
    client_verify: bool = false,
    client_verify_depth: u32 = 3,
    crl_path: []const u8 = "",
    crl_check: bool = false,
    dynamic_reload_interval_ms: u64 = 5_000,
    acme_enabled: bool = false,
    acme_cert_dir: []const u8 = "",
    acme_auto_issue: bool = false,
    acme_directory_url: []const u8 = "https://acme-v02.api.letsencrypt.org/directory",
    acme_domains: []const []const u8 = &.{},
    acme_email: []const u8 = "",
    acme_account_key_path: []const u8 = "",
    acme_renew_days_before_expiry: u32 = 30,
    acme_challenge_store: ?*@import("acme_challenge_store.zig").ChallengeStore = null,
    http1_enabled: bool = true,
    http2_enabled: bool = true,
    http1_alpn_fallback_enabled: bool = false,
};

pub const NegotiatedProtocol = enum {
    http1_1,
    http2,
};

const unavailable_message = "TLS termination is unavailable: this binary was built with " ++
    "-Dtls-profile=appliance and contains no OpenSSL adapter; the native TLS " ++
    "path is tracked by #391";

pub const TlsTerminator = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, opts: TlsOptions) TlsError!TlsTerminator {
        _ = allocator;
        _ = opts;
        return error.ContextInitFailed;
    }

    pub fn deinit(self: *TlsTerminator) void {
        self.* = undefined;
    }

    pub fn runMaintenance(self: *TlsTerminator, now_ms: u64) void {
        _ = self;
        _ = now_ms;
    }

    pub fn protocolPolicySnapshot(self: *TlsTerminator) negotiated_dispatch.ListenerProtocolPolicy {
        _ = self;
        return .{};
    }

    pub fn updateProtocolPolicy(self: *TlsTerminator, policy: negotiated_dispatch.ListenerProtocolPolicy) TlsError!void {
        _ = self;
        if (!policy.http1_enabled and !policy.http2_enabled) return error.ProtocolConfigFailed;
    }

    pub fn accept(self: *TlsTerminator, fd: std.posix.fd_t) TlsError!TlsConnection {
        return self.acceptWithPolicy(fd, .{});
    }

    pub fn acceptWithPolicy(self: *TlsTerminator, fd: std.posix.fd_t, policy: negotiated_dispatch.ListenerProtocolPolicy) TlsError!TlsConnection {
        _ = self;
        _ = fd;
        if (!policy.http1_enabled and !policy.http2_enabled) return error.ProtocolConfigFailed;
        return error.HandshakeFailed;
    }
};

pub const TlsConnection = struct {
    pub fn deinit(self: *TlsConnection) void {
        self.* = undefined;
    }

    pub fn read(self: *TlsConnection, buf: []u8) TlsError!usize {
        _ = self;
        _ = buf;
        return error.TlsReadFailed;
    }

    pub fn attachBufferMetrics(self: *TlsConnection, metrics: anytype, mutex: anytype) void {
        _ = self;
        _ = metrics;
        _ = mutex;
    }

    pub fn pending(self: *const TlsConnection) usize {
        _ = self;
        return 0;
    }

    pub fn rawFd(self: *const TlsConnection) std.posix.fd_t {
        _ = self;
        return -1;
    }

    pub const Writer = struct {
        conn: *TlsConnection,

        pub fn writeAll(self: Writer, data: []const u8) TlsError!void {
            _ = self;
            _ = data;
            return error.TlsWriteFailed;
        }

        pub fn print(self: Writer, comptime fmt: []const u8, args: anytype) !void {
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
        return .{ .ptr = self, .vtable = &stub_stream_vtable };
    }

    pub fn negotiatedAlpn(self: *const TlsConnection) ?[]const u8 {
        _ = self;
        return null;
    }

    pub fn negotiatedProtocol(self: *const TlsConnection) negotiated_dispatch.Error!NegotiatedProtocol {
        return self.validatedNegotiatedProtocol();
    }

    pub fn validatedNegotiatedProtocol(self: *const TlsConnection) negotiated_dispatch.Error!NegotiatedProtocol {
        _ = self;
        return error.NoApplicationProtocol;
    }
};

fn stubStreamBackend(_: *anyopaque) encrypted_stream.BackendKind {
    return .openssl;
}

fn stubStreamRead(_: *anyopaque, _: []u8) encrypted_stream.Error!usize {
    return error.StreamClosed;
}

fn stubStreamWrite(_: *anyopaque, _: []const u8) encrypted_stream.Error!usize {
    return error.StreamClosed;
}

fn stubStreamClose(_: *anyopaque) void {}

fn stubStreamReadiness(_: *anyopaque) encrypted_stream.Readiness {
    return .{ .peer_closed = true };
}

fn stubStreamDrive(ptr: *anyopaque) encrypted_stream.Error!encrypted_stream.DriveResult {
    return .{ .made_progress = false, .readiness = stubStreamReadiness(ptr) };
}

fn stubStreamBufferSnapshot(_: *anyopaque) encrypted_stream.BufferSnapshot {
    return .{};
}

const stub_stream_vtable = encrypted_stream.EncryptedStream.VTable{
    .backendFn = stubStreamBackend,
    .readFn = stubStreamRead,
    .writeFn = stubStreamWrite,
    .closeFn = stubStreamClose,
    .readinessFn = stubStreamReadiness,
    .driveFn = stubStreamDrive,
    .bufferSnapshotFn = stubStreamBufferSnapshot,
};

/// In the OpenSSL adapter this drains the error queue; here it reports why
/// TLS is unavailable so handshake-failure logs stay self-explanatory.
pub fn lastOpenSslError(allocator: std.mem.Allocator) ?[]u8 {
    return allocator.dupe(u8, unavailable_message) catch null;
}

pub const UpstreamTlsOptions = struct {
    skip_verify: bool = false,
    ca_bundle_path: []const u8 = "",
    sni_override: []const u8 = "",
    client_cert_path: []const u8 = "",
    client_key_path: []const u8 = "",
    alpn_policy: UpstreamAlpnPolicy = .require_http1,
};

pub const UpstreamAlpnPolicy = enum {
    require_http1,
    require_h2,
    prefer_h2_allow_http1,

    pub fn offersH2(self: UpstreamAlpnPolicy) bool {
        return self != .require_http1;
    }
};

pub const UpstreamTlsConn = struct {
    fd: std.posix.fd_t = -1,
    protocol: NegotiatedProtocol = .http1_1,

    pub fn connect(
        fd: std.posix.fd_t,
        host: []const u8,
        opts: UpstreamTlsOptions,
    ) TlsError!UpstreamTlsConn {
        _ = fd;
        _ = host;
        _ = opts;
        return error.ContextInitFailed;
    }

    pub fn deinit(self: *UpstreamTlsConn) void {
        self.* = undefined;
    }

    pub fn close(self: *UpstreamTlsConn) void {
        const fd = self.fd;
        self.deinit();
        if (fd >= 0) _ = std.c.close(fd);
    }

    pub fn read(self: *UpstreamTlsConn, buf: []u8) TlsError!usize {
        _ = self;
        _ = buf;
        return error.TlsReadFailed;
    }

    pub fn writeAll(self: *UpstreamTlsConn, data: []const u8) TlsError!void {
        _ = self;
        _ = data;
        return error.TlsWriteFailed;
    }

    pub fn pending(self: *const UpstreamTlsConn) usize {
        _ = self;
        return 0;
    }

    pub fn negotiatedProtocol(self: *const UpstreamTlsConn) NegotiatedProtocol {
        return self.protocol;
    }
};

test "stub terminator and upstream connections fail closed" {
    try std.testing.expectError(error.ContextInitFailed, TlsTerminator.init(std.testing.allocator, .{
        .cert_path = "unused.crt",
        .key_path = "unused.key",
    }));
    try std.testing.expectError(error.ContextInitFailed, UpstreamTlsConn.connect(-1, "example.com", .{}));
    const message = lastOpenSslError(std.testing.allocator) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(message);
    try std.testing.expect(std.mem.startsWith(u8, message, "TLS termination is unavailable"));
}
