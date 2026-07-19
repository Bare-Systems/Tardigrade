const std = @import("std");
const builtin = @import("builtin");
const tls = @import("tls_core");
const encrypted_stream_connection = @import("encrypted_stream_connection.zig");
const negotiated_dispatch = @import("negotiated_dispatch.zig");

const encrypted_stream = tls.encrypted_stream;
const production_crypto = tls.production_crypto;
const tls_backend = tls.tls13_backend;
const sni_provider = tls.sni_provider;
const credentials = tls.credentials;

pub const ListenerProtocolPolicy = negotiated_dispatch.ListenerProtocolPolicy;
pub const NegotiatedProtocol = negotiated_dispatch.NegotiatedProtocol;

pub const SniCertSpec = struct {
    server_name: []const u8,
    cert_path: []const u8,
    key_path: []const u8,
};

pub const NativeCredentialStore = struct {
    allocator: std.mem.Allocator,
    provider_state: sni_provider.ReloadableProvider,

    pub fn init(allocator: std.mem.Allocator) NativeCredentialStore {
        return .{
            .allocator = allocator,
            .provider_state = sni_provider.ReloadableProvider.init(allocator),
        };
    }

    pub fn provider(self: *NativeCredentialStore) credentials.CredentialProvider {
        return self.provider_state.provider();
    }

    pub fn deinit(self: *NativeCredentialStore) void {
        self.provider_state.deinit();
        self.* = undefined;
    }

    pub fn reloadFromFiles(
        self: *NativeCredentialStore,
        default_cert_path: []const u8,
        default_key_path: []const u8,
        sni_certs: []const SniCertSpec,
    ) !void {
        var loaded = try self.allocator.alloc(LoadedBundle, 1 + sni_certs.len);
        defer self.allocator.free(loaded);
        var loaded_len: usize = 0;
        defer {
            for (loaded[0..loaded_len]) |*bundle| bundle.deinit();
        }

        try loaded[loaded_len].initDefault(self.allocator, default_cert_path, default_key_path);
        loaded_len += 1;
        for (sni_certs) |spec| {
            try loaded[loaded_len].initNamed(self.allocator, spec);
            loaded_len += 1;
        }

        var configs = try self.allocator.alloc(sni_provider.CredentialBundleConfig, loaded_len);
        defer {
            for (configs) |*config| config.signer.release();
            self.allocator.free(configs);
        }
        for (loaded[0..loaded_len], 0..) |*bundle, i| configs[i] = bundle.config();

        try self.provider_state.reload(configs, .{
            .absent_sni_policy = .use_default,
            .unknown_sni_policy = .fail_handshake,
        });
    }
};

const LoadedBundle = struct {
    loaded: tls.identity_loader.LoadedIdentity = undefined,
    chain: [1][]const u8 = undefined,
    patterns: [1][]const u8 = undefined,
    is_default: bool = false,

    fn initDefault(
        self: *LoadedBundle,
        allocator: std.mem.Allocator,
        cert_path: []const u8,
        key_path: []const u8,
    ) !void {
        try self.init(allocator, cert_path, key_path, "default.invalid", true);
    }

    fn initNamed(self: *LoadedBundle, allocator: std.mem.Allocator, spec: SniCertSpec) !void {
        try self.init(allocator, spec.cert_path, spec.key_path, spec.server_name, false);
    }

    fn init(
        self: *LoadedBundle,
        allocator: std.mem.Allocator,
        cert_path: []const u8,
        key_path: []const u8,
        pattern: []const u8,
        is_default: bool,
    ) !void {
        self.* = .{};
        self.loaded = try tls.identity_loader.loadIdentity(allocator, cert_path, key_path);
        self.chain = .{self.loaded.cert_der};
        self.patterns = .{pattern};
        self.is_default = is_default;
    }

    fn config(self: *const LoadedBundle) sni_provider.CredentialBundleConfig {
        const scheme = self.loaded.identity.signatureScheme();
        return .{
            .chain = self.chain[0..],
            .patterns = self.patterns[0..],
            .signer = sni_provider.SignAdapter.fromIdentity(self.loaded.identity),
            .key_kind = keyKindForScheme(scheme),
            .supported_schemes = &.{scheme},
            .is_default = self.is_default,
        };
    }

    fn deinit(self: *LoadedBundle) void {
        self.loaded.deinit();
        self.* = undefined;
    }
};

fn keyKindForScheme(scheme: credentials.SignatureScheme) sni_provider.KeyKind {
    return switch (scheme) {
        .ed25519 => .ed25519,
        .ecdsa_secp256r1_sha256 => .ecdsa_p256,
    };
}

pub const NativeTlsConnection = struct {
    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    backend: *tls_backend.Tls13Backend,
    record: *encrypted_stream.PureZigRecordStream,
    policy: ListenerProtocolPolicy,
    negotiated: ?NegotiatedProtocol = null,
    entropy_source: production_crypto.OsEntropy = .{},
    crypto_provider_state: production_crypto.Provider = undefined,

    pub fn create(
        allocator: std.mem.Allocator,
        fd: std.posix.fd_t,
        policy: ListenerProtocolPolicy,
        provider: credentials.CredentialProvider,
    ) !*NativeTlsConnection {
        if (!policy.http1_enabled and !policy.http2_enabled) return error.ProtocolConfigFailed;
        try setNonBlocking(fd);

        const self = try allocator.create(NativeTlsConnection);
        errdefer allocator.destroy(self);

        const backend = try allocator.create(tls_backend.Tls13Backend);
        var backend_owned_by_record = false;
        errdefer if (!backend_owned_by_record) {
            backend.deinit();
            allocator.destroy(backend);
        };
        backend.* = tls_backend.Tls13Backend.initServerWithProvider(
            try production_crypto.freshHandshakeEntropy(),
            provider,
            .{ .record = .{ .alpn = policy.nativeAlpnPolicy() } },
        );

        const record = try allocator.create(encrypted_stream.PureZigRecordStream);
        errdefer allocator.destroy(record);

        self.* = .{
            .allocator = allocator,
            .fd = fd,
            .backend = backend,
            .record = record,
            .policy = policy,
        };
        self.crypto_provider_state = production_crypto.Provider.init(self.entropy_source.entropy());
        record.* = encrypted_stream.PureZigRecordStream.initWithCarrierAndBackend(
            .server,
            self.crypto_provider_state.cryptoProvider(),
            .tls_aes_128_gcm_sha256,
            self.socketCarrier(),
            backend.backend(),
        );
        backend_owned_by_record = true;
        return self;
    }

    pub fn destroy(self: *NativeTlsConnection) void {
        const allocator = self.allocator;
        self.deinit();
        allocator.destroy(self);
    }

    pub fn deinit(self: *NativeTlsConnection) void {
        self.record.deinit();
        self.allocator.destroy(self.record);
        self.allocator.destroy(self.backend);
        self.* = undefined;
    }

    pub fn stream(self: *NativeTlsConnection) encrypted_stream.EncryptedStream {
        return self.record.stream();
    }

    pub fn httpConnection(self: *NativeTlsConnection) encrypted_stream_connection.EncryptedStreamHttpConnection {
        return encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(self.stream(), self.fd);
    }

    pub fn rawFd(self: *const NativeTlsConnection) std.posix.fd_t {
        return self.fd;
    }

    pub fn readiness(self: *const NativeTlsConnection) encrypted_stream.Readiness {
        return self.record.readiness();
    }

    pub fn drive(self: *NativeTlsConnection) encrypted_stream.Error!encrypted_stream.DriveResult {
        return self.record.drive();
    }

    pub fn validatedNegotiatedProtocol(self: *NativeTlsConnection) negotiated_dispatch.Error!NegotiatedProtocol {
        if (self.negotiated) |protocol| return protocol;
        const protocol = try negotiated_dispatch.selectNegotiatedProtocol(
            self.record.negotiatedAlpn(),
            self.policy,
        );
        self.negotiated = protocol;
        return protocol;
    }

    fn socketCarrier(self: *NativeTlsConnection) encrypted_stream.Carrier {
        return .{
            .ptr = self,
            .readFn = carrierRead,
            .writeFn = carrierWrite,
            .closeFn = carrierClose,
            .owns_handle = true,
        };
    }

    fn carrierRead(ptr: *anyopaque, out: []u8) encrypted_stream.Error!usize {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        if (self.fd < 0) return error.StreamClosed;
        return readFd(self.fd, out);
    }

    fn carrierWrite(ptr: *anyopaque, bytes: []const u8) encrypted_stream.Error!usize {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        if (self.fd < 0) return error.StreamClosed;
        return writeFd(self.fd, bytes);
    }

    fn carrierClose(ptr: *anyopaque) void {
        const self: *NativeTlsConnection = @ptrCast(@alignCast(ptr));
        if (self.fd < 0) return;
        closeFd(self.fd);
        self.fd = -1;
    }
};

fn readFd(fd: std.posix.fd_t, out: []u8) encrypted_stream.Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.read(fd, out.ptr, out.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketReadFailed,
        };
    }
    const rc = std.c.read(fd, out.ptr, out.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketReadFailed;
    }
    return @intCast(rc);
}

fn writeFd(fd: std.posix.fd_t, bytes: []const u8) encrypted_stream.Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.write(fd, bytes.ptr, bytes.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketWriteFailed,
        };
    }
    const rc = std.c.write(fd, bytes.ptr, bytes.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketWriteFailed;
    }
    return @intCast(rc);
}

fn closeFd(fd: std.posix.fd_t) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.close(fd);
    } else {
        _ = std.c.close(fd);
    }
}

fn setNonBlocking(fd: std.posix.fd_t) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const status_flags = linux.fcntl(fd, linux.F.GETFL, 0);
        if (linux.errno(status_flags) != .SUCCESS) return error.FcntlFailed;
        const nonblock: usize = @intCast(@as(u32, @bitCast(linux.O{ .NONBLOCK = true })));
        const rc = linux.fcntl(fd, linux.F.SETFL, status_flags | nonblock);
        if (linux.errno(rc) != .SUCCESS) return error.FcntlFailed;
    } else {
        const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (status_flags < 0) return error.FcntlFailed;
        const nonblock = @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
        if (std.c.fcntl(fd, std.c.F.SETFL, status_flags | nonblock) < 0) return error.FcntlFailed;
    }
}

test "native ALPN policy follows listener preference and fallback" {
    const dual = (ListenerProtocolPolicy{
        .http1_enabled = true,
        .http2_enabled = true,
        .allow_http1_without_alpn = true,
    }).nativeAlpnPolicy();
    try std.testing.expectEqual(@as(usize, 2), dual.protocols.len);
    try std.testing.expectEqualStrings("h2", dual.protocols[0]);
    try std.testing.expectEqualStrings("http/1.1", dual.protocols[1]);
    try std.testing.expect(dual.allow_absent);

    const h2_only = (ListenerProtocolPolicy{
        .http1_enabled = false,
        .http2_enabled = true,
        .allow_http1_without_alpn = true,
    }).nativeAlpnPolicy();
    try std.testing.expectEqual(@as(usize, 1), h2_only.protocols.len);
    try std.testing.expectEqualStrings("h2", h2_only.protocols[0]);
    try std.testing.expect(!h2_only.allow_absent);
}

test "native TLS owner heap-stabilizes backend record and owns fd close" {
    var fixed = credentials.FixedCredentialProvider.init(credentials.testdata.identity());
    defer fixed.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[1]);

    const conn = try NativeTlsConnection.create(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
    );
    const original_fd = conn.rawFd();
    try std.testing.expect(original_fd >= 0);
    try std.testing.expectEqual(@intFromPtr(conn.backend), @intFromPtr(conn.backend.backend().ptr));
    try std.testing.expectEqual(encrypted_stream.BackendKind.pure_zig_record, conn.stream().backend());
    conn.destroy();

    try std.testing.expectError(error.SocketWriteFailed, writeFd(original_fd, "x"));
}

fn testSocketPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
        if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    } else {
        if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    }
    errdefer closeFd(fds[0]);
    errdefer closeFd(fds[1]);
    return fds;
}
