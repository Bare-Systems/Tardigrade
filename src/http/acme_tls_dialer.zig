//! Native TLS dialer for ACME CA traffic (#832, design §9.3 model a).
//!
//! Implements `acme/transport.zig`'s `Dialer` over `UpstreamTlsConn`. The CA
//! certificate chain and hostname are verified against a preloaded
//! `TrustAnchorSnapshot` (`UpstreamTlsOptions.trust_anchors`), so a dial never
//! touches the filesystem and keeps working after a privilege drop or chroot.
//! Verification is never skipped.

const std = @import("std");
const zig_compat = @import("zig_compat");
const transport = @import("../acme/transport.zig");
const upstream_tls = @import("upstream_tls.zig");

const Connection = transport.Connection;
const IoError = transport.IoError;
const DialError = transport.DialError;
const Dialer = transport.Dialer;

pub const TlsDialer = struct {
    snapshot: *transport.TrustAnchorSnapshot,

    pub fn dialer(self: *TlsDialer) Dialer {
        return .{ .ptr = self, .dialFn = dial };
    }

    const TlsConnection = struct {
        allocator: std.mem.Allocator,
        conn: upstream_tls.UpstreamTlsConn,
    };

    fn dial(ptr: *anyopaque, allocator: std.mem.Allocator, host: []const u8, port: u16, timeout_ms: u32) DialError!Connection {
        const self: *TlsDialer = @ptrCast(@alignCast(ptr));
        const fd = zig_compat.connectBoundedTcp(host, port, timeout_ms) catch |err| return switch (err) {
            error.Timeout => error.Timeout,
            else => error.DialFailed,
        };
        errdefer _ = std.c.close(fd);
        zig_compat.setSocketTimeoutsMs(fd, timeout_ms, timeout_ms);
        const wrapper = try allocator.create(TlsConnection);
        errdefer allocator.destroy(wrapper);
        wrapper.allocator = allocator;
        wrapper.conn = upstream_tls.UpstreamTlsConn.connect(fd, host, .{
            .trust_anchors = &self.snapshot.anchors,
            .alpn_policy = .require_http1,
        }) catch return error.DialFailed;
        return .{ .ptr = wrapper, .vtable = &tls_vtable };
    }

    const tls_vtable = Connection.VTable{ .read = tlsRead, .writeAll = tlsWriteAll, .close = tlsClose };

    fn tlsRead(ptr: *anyopaque, buf: []u8) IoError!usize {
        const wrapper: *TlsConnection = @ptrCast(@alignCast(ptr));
        return wrapper.conn.read(buf) catch error.Failed;
    }

    fn tlsWriteAll(ptr: *anyopaque, data: []const u8) IoError!void {
        const wrapper: *TlsConnection = @ptrCast(@alignCast(ptr));
        wrapper.conn.writeAll(data) catch return error.Failed;
    }

    fn tlsClose(ptr: *anyopaque) void {
        const wrapper: *TlsConnection = @ptrCast(@alignCast(ptr));
        const allocator = wrapper.allocator;
        wrapper.conn.close();
        allocator.destroy(wrapper);
    }
};

test "ACME TLS dialer: fails closed when nothing is listening" {
    const snapshot = try transport.TrustAnchorSnapshot.load(std.testing.allocator, "src/pki/testdata/ecdsa_p256_ca.crt");
    defer snapshot.release();
    var tls = TlsDialer{ .snapshot = snapshot };
    // Port 1 on loopback: connection refused, never a silent success.
    const result = tls.dialer().dialFn(tls.dialer().ptr, std.testing.allocator, "127.0.0.1", 1, 500);
    try std.testing.expectError(error.DialFailed, result);
}
