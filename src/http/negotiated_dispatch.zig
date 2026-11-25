const std = @import("std");
const tls = @import("tls_core");
const encrypted_stream_connection = @import("encrypted_stream_connection.zig");

/// The negotiated application protocol, shared by both the native
/// downstream listener (`native_tls_connection.zig`) and the native
/// upstream HTTPS client (`upstream_tls.zig`) — defined here rather than in
/// either, since neither is a dependency the other should need just for
/// this enum.
pub const NegotiatedProtocol = enum {
    http1_1,
    http2,
    /// RFC 8737 TLS-ALPN-01 (#939): the downstream listener negotiated the
    /// exclusive `acme-tls/1` offer. Never produced for the upstream client
    /// (`upstream_tls.zig` never offers it) -- terminal for the downstream
    /// listener too: the handshake itself *is* the validation, so the
    /// connection closes without any HTTP dispatch.
    acme_challenge,
};

pub const AlpnFallbackPolicy = enum {
    require_match,
    allow_http1_default,
};

pub const Error = error{
    HandshakeNotComplete,
    NoApplicationProtocol,
    ProtocolDisabled,
};

pub const ListenerProtocolPolicy = struct {
    http1_enabled: bool = true,
    http2_enabled: bool = true,
    allow_http1_without_alpn: bool = false,
    /// #939: the native TCP listener additionally recognizes an exclusive
    /// `acme-tls/1` ClientHello offer (RFC 8737 TLS-ALPN-01) and negotiates
    /// it -- but ONLY when the client's entire offered ALPN list is that one
    /// protocol; an absent, ordinary, mixed, or duplicated offer negotiates
    /// ordinary HTTP exactly as if this were false (`Policy.
    /// exclusive_only_alpn_protocols`). Never applies to QUIC/H3, which has
    /// its own, separate policy. Defaults to false: every existing listener
    /// negotiates exactly as before.
    acme_tls_alpn_enabled: bool = false,

    pub fn fallbackPolicy(self: ListenerProtocolPolicy) AlpnFallbackPolicy {
        return if (self.http1_enabled and self.allow_http1_without_alpn)
            .allow_http1_default
        else
            .require_match;
    }

    pub fn negotiatedFallbackPolicy(self: ListenerProtocolPolicy) AlpnFallbackPolicy {
        return self.fallbackPolicy();
    }

    pub fn selectedProtocolAllowed(self: ListenerProtocolPolicy, protocol: NegotiatedProtocol) bool {
        return switch (protocol) {
            .http1_1 => self.http1_enabled,
            .http2 => self.http2_enabled,
            // Already gated by `acme_tls_alpn_enabled` at negotiation time
            // (see `selectNegotiatedProtocol`): reaching here at all means
            // the engine's own policy already required it.
            .acme_challenge => true,
        };
    }

    pub fn validateSelected(self: ListenerProtocolPolicy, protocol: NegotiatedProtocol) Error!void {
        if (!self.selectedProtocolAllowed(protocol)) return error.ProtocolDisabled;
    }

    pub fn advertisedAlpns(self: ListenerProtocolPolicy) []const tls.algorithms.ProtocolName {
        if (self.http2_enabled and self.http1_enabled) return &dual_protocol_preference;
        if (self.http2_enabled) return &h2_only;
        if (self.http1_enabled) return &h1_only;
        return &.{};
    }

    pub fn encodedAdvertisedAlpns(self: ListenerProtocolPolicy) []const u8 {
        if (self.http2_enabled and self.http1_enabled) return h2_and_http11_wire;
        if (self.http2_enabled) return h2_only_wire;
        if (self.http1_enabled) return http11_only_wire;
        return "";
    }

    pub fn nativeTlsPolicy(self: ListenerProtocolPolicy) tls.policy.Policy {
        var policy = self.nativeTlsAlpnPolicy();
        // The SNI credential provider can select an RSA-PSS identity whenever
        // the peer offers it; the policy must allow every scheme it can pick,
        // or `inspectSelectedCredential` rejects the selection and the
        // handshake dies with `CredentialProviderFailed`.
        policy.signature_schemes = &server_signature_schemes;
        return policy;
    }

    fn nativeTlsAlpnPolicy(self: ListenerProtocolPolicy) tls.policy.Policy {
        if (self.http2_enabled and self.http1_enabled) {
            var policy = tls.policy.Policy.recordDefault();
            policy.allow_absent_alpn = self.allow_http1_without_alpn;
            if (self.acme_tls_alpn_enabled) self.addAcmeTlsAlpn(&policy, &dual_protocol_with_acme);
            return policy;
        }
        if (self.http2_enabled) {
            var policy = tls.policy.Policy.recordH2Only();
            if (self.acme_tls_alpn_enabled) self.addAcmeTlsAlpn(&policy, &h2_only_with_acme);
            return policy;
        }
        if (!self.http1_enabled) {
            var policy = tls.policy.Policy.recordDefault();
            policy.alpn_protocols = &.{};
            // Neither HTTP protocol is enabled; `createWithOptions` already
            // refuses this configuration before it can reach the engine, so
            // `acme_tls_alpn_enabled` is moot here.
            return policy;
        }
        var policy = tls.policy.Policy.recordHttp1Only(self.allow_http1_without_alpn);
        if (self.acme_tls_alpn_enabled) self.addAcmeTlsAlpn(&policy, &http1_only_with_acme);
        return policy;
    }

    fn addAcmeTlsAlpn(_: ListenerProtocolPolicy, policy: *tls.policy.Policy, with_acme: []const tls.algorithms.ProtocolName) void {
        policy.alpn_protocols = with_acme;
        policy.exclusive_only_alpn_protocols = &acme_only_alpn;
    }
};

const acme_tls_alpn = tls.algorithms.alpn.acme_tls_1;
const acme_only_alpn = [_]tls.algorithms.ProtocolName{acme_tls_alpn};
const dual_protocol_with_acme = [_]tls.algorithms.ProtocolName{ tls.algorithms.alpn.h2, tls.algorithms.alpn.http_1_1, acme_tls_alpn };
const h2_only_with_acme = [_]tls.algorithms.ProtocolName{ tls.algorithms.alpn.h2, acme_tls_alpn };
const http1_only_with_acme = [_]tls.algorithms.ProtocolName{ tls.algorithms.alpn.http_1_1, acme_tls_alpn };

const server_signature_schemes = [_]tls.algorithms.SignatureScheme{
    .ed25519,
    .ecdsa_secp256r1_sha256,
    .rsa_pss_rsae_sha256,
};

const dual_protocol_preference = [_]tls.algorithms.ProtocolName{
    tls.algorithms.alpn.h2,
    tls.algorithms.alpn.http_1_1,
};
const h2_only = [_]tls.algorithms.ProtocolName{tls.algorithms.alpn.h2};
const h1_only = [_]tls.algorithms.ProtocolName{tls.algorithms.alpn.http_1_1};

pub const h2_and_http11_wire = "\x02h2\x08http/1.1";
pub const h2_only_wire = "\x02h2";
pub const http11_only_wire = "\x08http/1.1";

pub fn mapNegotiatedHttpProtocol(
    negotiated_alpn: ?[]const u8,
    fallback: AlpnFallbackPolicy,
) Error!NegotiatedProtocol {
    if (negotiated_alpn) |alpn| {
        if (std.mem.eql(u8, alpn, tls.algorithms.alpn.h2.bytes)) return .http2;
        if (std.mem.eql(u8, alpn, tls.algorithms.alpn.http_1_1.bytes)) return .http1_1;
        return error.NoApplicationProtocol;
    }

    return switch (fallback) {
        .require_match => error.NoApplicationProtocol,
        .allow_http1_default => .http1_1,
    };
}

pub fn selectNegotiatedProtocol(
    negotiated_alpn: ?[]const u8,
    policy: ListenerProtocolPolicy,
) Error!NegotiatedProtocol {
    // #939: checked ahead of the ordinary h2/http1.1 mapping so it can never
    // be shadowed by it. Reaching this with `negotiated_alpn` equal to
    // `acme-tls/1` already means the engine's own policy was built with
    // `acme_tls_alpn_enabled` (only then does `acme-tls/1` ever appear in
    // the ALPN policy `negotiateServerHello` selected from); the flag check
    // here is belt-and-suspenders, not load-bearing.
    if (policy.acme_tls_alpn_enabled) {
        if (negotiated_alpn) |alpn| {
            if (std.mem.eql(u8, alpn, acme_tls_alpn.bytes)) return .acme_challenge;
        }
    }
    const protocol = try mapNegotiatedHttpProtocol(negotiated_alpn, policy.negotiatedFallbackPolicy());
    try policy.validateSelected(protocol);
    return protocol;
}

pub fn dispatchToRuntime(
    runtime: anytype,
    conn: anytype,
    negotiated: NegotiatedProtocol,
    comptime Runtime: type,
) !Runtime.Outcome {
    return switch (negotiated) {
        .http2 => blk: {
            try Runtime.handleHttp2(runtime, conn);
            break :blk .close;
        },
        .http1_1 => while (true) {
            switch (try Runtime.serveHttp1(runtime, conn)) {
                .serve_again => {},
                .park => break .park,
                .close => break .close,
            }
        },
        // #939: never actually reached in production -- the native listener
        // closes a completed challenge connection itself, before any
        // `dispatchToRuntime` call, per the module doc on `.acme_challenge`.
        // Required for exhaustiveness and kept terminal to match that intent.
        .acme_challenge => .close,
    };
}

test "ALPN mapping is explicit" {
    try std.testing.expectEqual(NegotiatedProtocol.http2, try mapNegotiatedHttpProtocol(tls.algorithms.alpn.h2.bytes, .require_match));
    try std.testing.expectEqual(NegotiatedProtocol.http1_1, try mapNegotiatedHttpProtocol(tls.algorithms.alpn.http_1_1.bytes, .require_match));
    try std.testing.expectError(error.NoApplicationProtocol, mapNegotiatedHttpProtocol("spdy/3", .require_match));
    try std.testing.expectError(error.NoApplicationProtocol, mapNegotiatedHttpProtocol(null, .require_match));
    try std.testing.expectEqual(NegotiatedProtocol.http1_1, try mapNegotiatedHttpProtocol(null, .allow_http1_default));
}

test "listener protocol snapshot advertises only enabled protocols in server preference" {
    try std.testing.expectEqualStrings(h2_and_http11_wire, (ListenerProtocolPolicy{}).encodedAdvertisedAlpns());
    try std.testing.expectEqualStrings(http11_only_wire, (ListenerProtocolPolicy{ .http2_enabled = false }).encodedAdvertisedAlpns());
    try std.testing.expectEqualStrings(h2_only_wire, (ListenerProtocolPolicy{ .http1_enabled = false }).encodedAdvertisedAlpns());
    try std.testing.expectEqual(@as(usize, 2), (ListenerProtocolPolicy{}).advertisedAlpns().len);
    try std.testing.expect((ListenerProtocolPolicy{}).advertisedAlpns()[0].eql(tls.algorithms.alpn.h2));
}

test "pinned listener policy validates selected protocol and fallback" {
    try std.testing.expectError(error.ProtocolDisabled, selectNegotiatedProtocol(tls.algorithms.alpn.h2.bytes, .{ .http2_enabled = false }));
    try std.testing.expectError(error.NoApplicationProtocol, selectNegotiatedProtocol(null, .{ .allow_http1_without_alpn = false }));
    try std.testing.expectEqual(NegotiatedProtocol.http1_1, try selectNegotiatedProtocol(null, .{ .allow_http1_without_alpn = true }));
    try std.testing.expectError(error.NoApplicationProtocol, selectNegotiatedProtocol(null, .{ .http1_enabled = false, .allow_http1_without_alpn = true }));
}

test "ACME-disabled listener policy never offers acme-tls/1 in the engine policy" {
    const policy = (ListenerProtocolPolicy{}).nativeTlsPolicy();
    try std.testing.expect(!policy.containsAlpn(acme_tls_alpn.bytes));
    try std.testing.expectEqual(@as(usize, 0), policy.exclusive_only_alpn_protocols.len);
}

test "ACME-enabled listener policy offers acme-tls/1 as exclusive-only, for every http1/h2 combination" {
    for ([_]ListenerProtocolPolicy{
        .{ .acme_tls_alpn_enabled = true },
        .{ .acme_tls_alpn_enabled = true, .http1_enabled = false },
        .{ .acme_tls_alpn_enabled = true, .http2_enabled = false },
    }) |listener_policy| {
        const policy = listener_policy.nativeTlsPolicy();
        try std.testing.expect(policy.containsAlpn(acme_tls_alpn.bytes));
        try std.testing.expectEqual(@as(usize, 1), policy.exclusive_only_alpn_protocols.len);
        try std.testing.expect(policy.exclusive_only_alpn_protocols[0].eql(acme_tls_alpn));
    }
}

test "selectNegotiatedProtocol recognizes acme-tls/1 only when the listener enabled it" {
    try std.testing.expectEqual(
        NegotiatedProtocol.acme_challenge,
        try selectNegotiatedProtocol(acme_tls_alpn.bytes, .{ .acme_tls_alpn_enabled = true }),
    );
    // Belt-and-suspenders (module doc): even if somehow negotiated without
    // the flag, it is treated as any other unrecognized ALPN value, never
    // silently granted the challenge outcome.
    try std.testing.expectError(
        error.NoApplicationProtocol,
        selectNegotiatedProtocol(acme_tls_alpn.bytes, .{ .acme_tls_alpn_enabled = false }),
    );
    // acme_challenge is unconditionally allowed once negotiated -- it is not
    // gated by http1_enabled/http2_enabled the way ordinary protocols are.
    try std.testing.expectEqual(
        NegotiatedProtocol.acme_challenge,
        try selectNegotiatedProtocol(acme_tls_alpn.bytes, .{ .acme_tls_alpn_enabled = true, .http1_enabled = false, .http2_enabled = false }),
    );
}

test "shared runtime dispatch accepts generic and EncryptedStream connection shapes" {
    var runtime = TestRuntime{};
    var generic_conn = TestGenericConn{ .fd = 11 };
    try std.testing.expectEqual(TestOutcome.park, try dispatchToRuntime(&runtime, &generic_conn, .http1_1, TestRuntime));
    try std.testing.expectEqual(@as(usize, 1), runtime.http1_calls);
    try std.testing.expectEqual(@as(std.posix.fd_t, 11), runtime.last_fd);
    try std.testing.expectEqualStrings("h", generic_conn.written[0..generic_conn.written_len]);

    var fake_stream = TestEncryptedStream{ .readiness_state = .{ .can_write_plaintext = true } };
    var pure_zig_conn = encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(fake_stream.stream(), 22);
    try std.testing.expectEqual(TestOutcome.close, try dispatchToRuntime(&runtime, &pure_zig_conn, .http2, TestRuntime));
    try std.testing.expectEqual(@as(usize, 1), runtime.http2_calls);
    try std.testing.expectEqual(@as(std.posix.fd_t, 22), runtime.last_fd);
    try std.testing.expectEqualStrings("2", fake_stream.written[0..fake_stream.written_len]);
}

const TestOutcome = enum { serve_again, park, close };

const TestGenericConn = struct {
    fd: std.posix.fd_t,
    pending_plaintext: usize = 0,
    written: [8]u8 = undefined,
    written_len: usize = 0,

    pub fn pending(self: *const TestGenericConn) usize {
        return self.pending_plaintext;
    }

    pub fn rawFd(self: *const TestGenericConn) std.posix.fd_t {
        return self.fd;
    }

    pub const Writer = struct {
        conn: *TestGenericConn,

        pub fn writeByte(self: Writer, byte: u8) !void {
            self.conn.written[self.conn.written_len] = byte;
            self.conn.written_len += 1;
        }
    };

    pub fn writer(self: *TestGenericConn) Writer {
        return .{ .conn = self };
    }
};

const TestRuntime = struct {
    const Outcome = TestOutcome;

    http1_calls: usize = 0,
    http2_calls: usize = 0,
    last_fd: std.posix.fd_t = -1,
    last_pending: usize = 0,

    pub fn serveHttp1(self: *@This(), conn: anytype) !Outcome {
        self.http1_calls += 1;
        self.last_fd = conn.rawFd();
        self.last_pending = conn.pending();
        try conn.writer().writeByte('h');
        return .park;
    }

    pub fn handleHttp2(self: *@This(), conn: anytype) !void {
        self.http2_calls += 1;
        self.last_fd = conn.rawFd();
        self.last_pending = conn.pending();
        try conn.writer().writeByte('2');
    }
};

const TestEncryptedStream = struct {
    readiness_state: tls.encrypted_stream.Readiness = .{},
    written: [8]u8 = undefined,
    written_len: usize = 0,

    fn stream(self: *TestEncryptedStream) tls.encrypted_stream.EncryptedStream {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn backend(_: *anyopaque) tls.encrypted_stream.BackendKind {
        return .pure_zig_record;
    }

    fn read(_: *anyopaque, _: []u8) tls.encrypted_stream.Error!usize {
        return error.WouldBlock;
    }

    fn write(ptr: *anyopaque, bytes: []const u8) tls.encrypted_stream.Error!usize {
        const self: *TestEncryptedStream = @ptrCast(@alignCast(ptr));
        if (!self.readiness_state.can_write_plaintext) return error.WouldBlock;
        const n = @min(bytes.len, self.written.len - self.written_len);
        @memcpy(self.written[self.written_len .. self.written_len + n], bytes[0..n]);
        self.written_len += n;
        return n;
    }

    fn close(_: *anyopaque) void {}

    fn readiness(ptr: *anyopaque) tls.encrypted_stream.Readiness {
        const self: *TestEncryptedStream = @ptrCast(@alignCast(ptr));
        return self.readiness_state;
    }

    fn drive(ptr: *anyopaque) tls.encrypted_stream.Error!tls.encrypted_stream.DriveResult {
        const self: *TestEncryptedStream = @ptrCast(@alignCast(ptr));
        return .{ .made_progress = false, .readiness = self.readiness_state };
    }

    fn bufferSnapshot(_: *anyopaque) tls.encrypted_stream.BufferSnapshot {
        return .{};
    }

    const vtable = tls.encrypted_stream.EncryptedStream.VTable{
        .backendFn = backend,
        .readFn = read,
        .writeFn = write,
        .closeFn = close,
        .readinessFn = readiness,
        .driveFn = drive,
        .bufferSnapshotFn = bufferSnapshot,
    };
};
