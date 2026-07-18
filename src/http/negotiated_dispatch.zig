const std = @import("std");
const tls = @import("tls_core");
const tls_termination = @import("tls_backend.zig");

pub const AlpnFallbackPolicy = enum {
    require_match,
    allow_http1_default,
};

pub const Error = error{
    NoApplicationProtocol,
    ProtocolDisabled,
};

pub const ListenerProtocolPolicy = struct {
    http1_enabled: bool = true,
    http2_enabled: bool = true,
    allow_http1_without_alpn: bool = false,

    pub fn fallbackPolicy(self: ListenerProtocolPolicy) AlpnFallbackPolicy {
        return if (self.http1_enabled and self.allow_http1_without_alpn)
            .allow_http1_default
        else
            .require_match;
    }

    pub fn negotiatedFallbackPolicy(self: ListenerProtocolPolicy) AlpnFallbackPolicy {
        return self.fallbackPolicy();
    }

    pub fn selectedProtocolAllowed(self: ListenerProtocolPolicy, protocol: tls_termination.NegotiatedProtocol) bool {
        return switch (protocol) {
            .http1_1 => self.http1_enabled,
            .http2 => self.http2_enabled,
        };
    }

    pub fn validateSelected(self: ListenerProtocolPolicy, protocol: tls_termination.NegotiatedProtocol) Error!void {
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
) Error!tls_termination.NegotiatedProtocol {
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
) Error!tls_termination.NegotiatedProtocol {
    const protocol = try mapNegotiatedHttpProtocol(negotiated_alpn, policy.negotiatedFallbackPolicy());
    try policy.validateSelected(protocol);
    return protocol;
}

pub fn dispatchToRuntime(
    runtime: anytype,
    conn: anytype,
    negotiated: tls_termination.NegotiatedProtocol,
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
    };
}

test "ALPN mapping is explicit" {
    try std.testing.expectEqual(tls_termination.NegotiatedProtocol.http2, try mapNegotiatedHttpProtocol(tls.algorithms.alpn.h2.bytes, .require_match));
    try std.testing.expectEqual(tls_termination.NegotiatedProtocol.http1_1, try mapNegotiatedHttpProtocol(tls.algorithms.alpn.http_1_1.bytes, .require_match));
    try std.testing.expectError(error.NoApplicationProtocol, mapNegotiatedHttpProtocol("spdy/3", .require_match));
    try std.testing.expectError(error.NoApplicationProtocol, mapNegotiatedHttpProtocol(null, .require_match));
    try std.testing.expectEqual(tls_termination.NegotiatedProtocol.http1_1, try mapNegotiatedHttpProtocol(null, .allow_http1_default));
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
    try std.testing.expectEqual(tls_termination.NegotiatedProtocol.http1_1, try selectNegotiatedProtocol(null, .{ .allow_http1_without_alpn = true }));
    try std.testing.expectError(error.NoApplicationProtocol, selectNegotiatedProtocol(null, .{ .http1_enabled = false, .allow_http1_without_alpn = true }));
}

test "shared runtime dispatch accepts OpenSSL and pure-Zig encrypted stream adapters" {
    var runtime = TestRuntime{};
    var openssl_conn = TestConn{ .backend = .openssl };
    try std.testing.expectEqual(TestOutcome.park, try dispatchToRuntime(&runtime, &openssl_conn, .http1_1, TestRuntime));
    try std.testing.expectEqual(@as(usize, 1), runtime.http1_calls);
    try std.testing.expectEqual(tls.encrypted_stream.BackendKind.openssl, runtime.last_backend.?);

    var pure_zig_conn = TestConn{ .backend = .pure_zig_record };
    try std.testing.expectEqual(TestOutcome.close, try dispatchToRuntime(&runtime, &pure_zig_conn, .http2, TestRuntime));
    try std.testing.expectEqual(@as(usize, 1), runtime.http2_calls);
    try std.testing.expectEqual(tls.encrypted_stream.BackendKind.pure_zig_record, runtime.last_backend.?);
}

const TestOutcome = enum { serve_again, park, close };

const TestConn = struct {
    backend: tls.encrypted_stream.BackendKind,

    fn streamBackend(self: *const TestConn) tls.encrypted_stream.BackendKind {
        return self.backend;
    }
};

const TestRuntime = struct {
    const Outcome = TestOutcome;

    http1_calls: usize = 0,
    http2_calls: usize = 0,
    last_backend: ?tls.encrypted_stream.BackendKind = null,

    pub fn serveHttp1(self: *@This(), conn: anytype) !Outcome {
        self.http1_calls += 1;
        self.last_backend = conn.streamBackend();
        return .park;
    }

    pub fn handleHttp2(self: *@This(), conn: anytype) !void {
        self.http2_calls += 1;
        self.last_backend = conn.streamBackend();
    }
};
