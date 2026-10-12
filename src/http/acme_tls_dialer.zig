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

/// Owns one reference to the trust-anchor snapshot for its whole lifetime, so
/// a reload that retires the configured snapshot cannot free anchors under a
/// handshake in flight (design §9.3). Reload swaps whole dialer owners and
/// calls `deinit` on the old one only after nothing can start a new request
/// through it.
pub const TlsDialer = struct {
    snapshot: *transport.TrustAnchorSnapshot,

    pub fn init(snapshot: *transport.TrustAnchorSnapshot) TlsDialer {
        return .{ .snapshot = snapshot.retain() };
    }

    pub fn deinit(self: *TlsDialer) void {
        self.snapshot.release();
        self.* = undefined;
    }

    pub fn dialer(self: *TlsDialer) Dialer {
        return .{ .ptr = self, .dialFn = dial };
    }

    const TlsConnection = struct {
        allocator: std.mem.Allocator,
        conn: upstream_tls.UpstreamTlsConn,
    };

    fn dial(ptr: *anyopaque, allocator: std.mem.Allocator, host: []const u8, port: u16, remaining_ms: u32) DialError!Connection {
        const self: *TlsDialer = @ptrCast(@alignCast(ptr));
        // One absolute deadline for the whole connection: TCP connect, the TLS
        // handshake and every later read/write are clamped to what is left.
        const started = upstream_tls.monotonicMs();
        const deadline_ms = started + @as(i64, remaining_ms);
        const fd = zig_compat.connectBoundedTcp(host, port, remaining_ms) catch |err| return switch (err) {
            error.Timeout => error.Timeout,
            else => error.DialFailed,
        };
        errdefer zig_compat.closeFd(fd);
        const after_connect = deadline_ms - upstream_tls.monotonicMs();
        if (after_connect <= 0) return error.Timeout;
        const socket_ms: u32 = @intCast(@min(after_connect, @as(i64, std.math.maxInt(u32))));
        zig_compat.setSocketTimeoutsMs(fd, socket_ms, socket_ms);
        const wrapper = try allocator.create(TlsConnection);
        errdefer allocator.destroy(wrapper);
        wrapper.allocator = allocator;
        wrapper.conn = upstream_tls.UpstreamTlsConn.connect(fd, host, .{
            .trust_anchors = &self.snapshot.anchors,
            .alpn_policy = .require_http1,
            .deadline_ms = deadline_ms,
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
    var tls = TlsDialer.init(snapshot);
    defer tls.deinit();
    // Port 1 on loopback: connection refused, never a silent success.
    const result = tls.dialer().dialFn(tls.dialer().ptr, std.testing.allocator, "127.0.0.1", 1, 500);
    try std.testing.expectError(error.DialFailed, result);
}

const DribbleCtx = struct {
    server: *zig_compat.NetServer,
    done: std.atomic.Value(bool) = .init(false),
};

/// Accepts one connection and sends the start of a plausible TLS record, then
/// one more byte every 150 ms for 600 ms, then goes silent (without closing,
/// so the client never sees an EOF or RST).
fn dribbleServer(ctx: *DribbleCtx) void {
    const conn = ctx.server.accept() catch return;
    const header = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0xff };
    conn.stream.writeAll(&header) catch return;
    for (0..4) |_| {
        zig_compat.sleepNs(150 * std.time.ns_per_ms);
        conn.stream.writeAll(&[_]u8{0}) catch return;
    }
    while (!ctx.done.load(.acquire)) zig_compat.sleepNs(20 * std.time.ns_per_ms);
    conn.stream.close();
}

test "ACME TLS dialer: one absolute deadline bounds TCP, TLS and a dribbling peer" {
    const snapshot = try transport.TrustAnchorSnapshot.load(std.testing.allocator, "src/pki/testdata/ecdsa_p256_ca.crt");
    defer snapshot.release();
    var server = try zig_compat.listenTcp("127.0.0.1", 0);
    defer server.deinit();
    var ctx = DribbleCtx{ .server = &server };
    const thread = try std.Thread.spawn(.{}, dribbleServer, .{&ctx});
    defer {
        ctx.done.store(true, .release);
        thread.join();
    }

    var tls = TlsDialer.init(snapshot);
    defer tls.deinit();
    const t = transport.Transport{
        .allocator = std.testing.allocator,
        .dialer = tls.dialer(),
        .limits = .{ .request_deadline_ms = 800 },
    };
    var url_buf: [64]u8 = undefined;
    const url_text = try std.fmt.bufPrint(&url_buf, "https://127.0.0.1:{d}/directory", .{server.port()});
    const target = try @import("../acme/url.zig").parse(url_text);

    const started = upstream_tls.monotonicMs();
    try std.testing.expectError(error.DialFailed, t.request(.GET, target, null, null));
    const elapsed = upstream_tls.monotonicMs() - started;
    // Every byte the peer sent would have reset a per-wait timeout (800 ms
    // after the last byte at ~600 ms = ~1400 ms); the shared deadline cuts it
    // at ~800 ms regardless.
    try std.testing.expect(elapsed >= 700);
    try std.testing.expect(elapsed < 1200);
}

test "ACME TLS dialer: retiring the configured snapshot does not free anchors under a dialer" {
    const configured = try transport.TrustAnchorSnapshot.load(std.testing.allocator, "src/pki/testdata/ecdsa_p256_ca.crt");
    var dialer_owner = TlsDialer.init(configured);
    // Reload retires the configured reference; the dialer's own reference
    // keeps the anchors alive (the testing allocator would flag a
    // use-after-free or a leak).
    configured.release();
    try std.testing.expect(dialer_owner.snapshot.anchors.anchors().len > 0);
    try std.testing.expectEqual(@as(u32, 1), dialer_owner.snapshot.refs.load(.acquire));
    dialer_owner.deinit();
}
