//! Bidirectional byte relay for upgraded connections (#812).
//!
//! After a WebSocket handshake is relayed, Tardigrade stops speaking HTTP on
//! both hops and copies bytes between the client and the origin until either
//! side closes. `relay` never parses frames. It runs on the worker thread
//! that handled the handshake, drives both endpoints non-blocking from one
//! `poll()` loop, and holds at most one fixed buffer per direction: a slow
//! reader stops the relay from reading the other side, so TCP flow control
//! pushes back on the fast writer instead of memory growing.
//!
//! An endpoint is any value with these methods:
//!
//! - `fd() fd_t`: the socket to poll.
//! - `read(buf) !?usize`: `null` when nothing is available yet, `0` at a
//!   clean end of stream.
//! - `write(bytes) !usize`: bytes accepted; `0` when the socket is full.
//! - `flush() !void`: push queued ciphertext without blocking.
//! - `pendingOutput() bool`: ciphertext is still queued for the socket.
//! - `bufferedInput() bool`: `read` can return without the socket becoming
//!   readable (already-decrypted plaintext, or a received TLS close).

const std = @import("std");
const compat = @import("zig_compat");
const builtin = @import("builtin");
const encrypted_stream_connection = @import("encrypted_stream_connection.zig");
const upstream_tls = @import("upstream_tls.zig");
const event_loop = @import("event_loop.zig");

pub const Error = error{TunnelIoFailed};

/// Why a tunnel ended. `label` is the bounded metrics/access-log value.
pub const CloseReason = enum {
    /// The client closed its side.
    client,
    /// The origin closed its side.
    upstream,
    /// No bytes moved in either direction for the idle timeout.
    idle,
    /// The optional maximum lifetime elapsed.
    lifetime,
    /// Graceful shutdown's drain window elapsed.
    shutdown,
    /// A hot reload superseded the tunnel's configuration and its
    /// `proxy_websocket_reload drain` window elapsed.
    reload,
    /// A read or write on the client failed.
    client_error,
    /// A read or write on the origin failed.
    upstream_error,

    pub fn label(self: CloseReason) []const u8 {
        return switch (self) {
            .client_error, .upstream_error => "error",
            else => @tagName(self),
        };
    }
};

pub const Options = struct {
    /// Close after this long with no bytes moving either way. Zero disables.
    idle_timeout_ms: u32,
    /// Close this long after the tunnel opened. Zero disables.
    max_lifetime_ms: u32 = 0,
    /// Once shutdown is requested, keep relaying this long, then close.
    drain_timeout_ms: u64 = 0,
    /// Checked at least every `poll_interval_ms`.
    shutdown_requested: *const fn () bool,
    /// Set for tunnels admitted with `proxy_websocket_reload drain`.
    reload_drain: ?ReloadDrain = null,
    poll_interval_ms: u32 = 250,
    /// After one side closes, how long bytes already read from it may take to
    /// reach the other side before the tunnel is torn down anyway.
    close_flush_timeout_ms: u32 = 1_000,
};

/// How a `drain`-mode tunnel learns that a hot reload superseded the
/// configuration it was admitted under (#812).
pub const ReloadDrain = struct {
    /// The admission configuration generation's supersession time
    /// (`event_loop.monotonicMs`), 0 while it is current. Published once by
    /// the reload that replaces it and never changed afterwards, so the
    /// deadline derived from it cannot be extended by later reloads.
    superseded_at_ms: *const std.atomic.Value(u64),
    /// How long the tunnel keeps relaying after that, from the admission
    /// configuration.
    timeout_ms: u32,
};

pub const Stats = struct {
    client_to_upstream_bytes: u64 = 0,
    upstream_to_client_bytes: u64 = 0,
    duration_ms: u64 = 0,
    close_reason: CloseReason = .client,
};

/// A plain stream socket (TCP or Unix). `relay` switches it to non-blocking
/// mode for the tunnel's lifetime (macOS does not honor `MSG_DONTWAIT` on
/// `send` for Unix sockets); the connection is closed afterwards anyway.
pub const SocketEndpoint = struct {
    handle: std.posix.fd_t,

    pub fn fd(self: SocketEndpoint) std.posix.fd_t {
        return self.handle;
    }

    pub fn begin(self: SocketEndpoint) void {
        setNonBlocking(self.handle);
    }

    pub fn read(self: SocketEndpoint, buf: []u8) Error!?usize {
        if (builtin.os.tag == .linux) {
            const linux = std.os.linux;
            const rc = linux.recvfrom(self.handle, buf.ptr, buf.len, linux.MSG.DONTWAIT, null, null);
            return switch (linux.errno(rc)) {
                .SUCCESS => rc,
                .AGAIN, .INTR => null,
                else => error.TunnelIoFailed,
            };
        }
        const rc = std.c.recv(self.handle, buf.ptr, buf.len, std.c.MSG.DONTWAIT);
        if (rc < 0) return switch (std.posix.errno(rc)) {
            .AGAIN, .INTR => null,
            else => error.TunnelIoFailed,
        };
        return @intCast(rc);
    }

    pub fn write(self: SocketEndpoint, bytes: []const u8) Error!usize {
        if (builtin.os.tag == .linux) {
            const linux = std.os.linux;
            const rc = linux.sendto(self.handle, bytes.ptr, bytes.len, linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL, null, 0);
            return switch (linux.errno(rc)) {
                .SUCCESS => rc,
                .AGAIN, .INTR => 0,
                else => error.TunnelIoFailed,
            };
        }
        const rc = std.c.send(self.handle, bytes.ptr, bytes.len, std.c.MSG.DONTWAIT);
        if (rc < 0) return switch (std.posix.errno(rc)) {
            .AGAIN, .INTR => 0,
            else => error.TunnelIoFailed,
        };
        return @intCast(rc);
    }

    pub fn flush(_: SocketEndpoint) Error!void {}

    pub fn pendingOutput(_: SocketEndpoint) bool {
        return false;
    }

    pub fn bufferedInput(_: SocketEndpoint) bool {
        return false;
    }
};

/// A downstream connection on Tardigrade's native TLS stack, whose socket is
/// already non-blocking.
pub const EncryptedEndpoint = struct {
    conn: *encrypted_stream_connection.EncryptedStreamHttpConnection,

    pub fn fd(self: EncryptedEndpoint) std.posix.fd_t {
        return self.conn.rawFd();
    }

    pub fn read(self: EncryptedEndpoint, buf: []u8) Error!?usize {
        return self.conn.read(buf) catch |err| switch (err) {
            error.WouldBlock => null,
            // A peer that closes without close_notify ends the tunnel the same
            // way: WebSocket framing, not TLS, tells the application whether
            // its last message was complete.
            error.EndOfStream, error.TruncatedStream => 0,
            else => error.TunnelIoFailed,
        };
    }

    pub fn write(self: EncryptedEndpoint, bytes: []const u8) Error!usize {
        return self.conn.write(bytes) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => error.TunnelIoFailed,
        };
    }

    pub fn flush(self: EncryptedEndpoint) Error!void {
        self.conn.flush() catch |err| switch (err) {
            error.WouldBlock => {},
            else => return error.TunnelIoFailed,
        };
    }

    pub fn pendingOutput(self: EncryptedEndpoint) bool {
        return self.conn.readiness().wants_write;
    }

    pub fn bufferedInput(self: EncryptedEndpoint) bool {
        return self.conn.pendingPlaintext() > 0 or self.conn.readiness().peer_closed;
    }
};

/// An upstream `wss://` connection on the native upstream TLS client.
pub const UpstreamTlsEndpoint = struct {
    tls: *upstream_tls.UpstreamTlsConn,

    pub fn fd(self: UpstreamTlsEndpoint) std.posix.fd_t {
        return self.tls.fd;
    }

    pub fn read(self: UpstreamTlsEndpoint, buf: []u8) Error!?usize {
        return self.tls.readNonBlocking(buf) catch error.TunnelIoFailed;
    }

    pub fn write(self: UpstreamTlsEndpoint, bytes: []const u8) Error!usize {
        return self.tls.writeNonBlocking(bytes) catch error.TunnelIoFailed;
    }

    pub fn flush(self: UpstreamTlsEndpoint) Error!void {
        self.tls.flushNonBlocking() catch return error.TunnelIoFailed;
    }

    pub fn pendingOutput(self: UpstreamTlsEndpoint) bool {
        return self.tls.hasQueuedOutput();
    }

    pub fn bufferedInput(self: UpstreamTlsEndpoint) bool {
        return self.tls.readReady();
    }
};

fn setNonBlocking(fd: std.posix.fd_t) void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const flags = linux.fcntl(fd, linux.F.GETFL, 0);
        if (linux.errno(flags) != .SUCCESS) return;
        const nonblock: usize = @intCast(@as(u32, @bitCast(linux.O{ .NONBLOCK = true })));
        _ = linux.fcntl(fd, linux.F.SETFL, flags | nonblock);
    } else {
        const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (flags < 0) return;
        const nonblock = @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
        _ = std.c.fcntl(fd, std.c.F.SETFL, flags | nonblock);
    }
}

fn beginEndpoint(endpoint: anytype) void {
    if (comptime @hasDecl(@TypeOf(endpoint), "begin")) endpoint.begin();
}

const Direction = struct {
    buf: []u8,
    /// Bytes read from the source (or handed in up front) not yet written.
    pending: []const u8,
    /// The source reached end of stream.
    eof: bool = false,
    /// Bytes delivered to the destination.
    delivered: u64 = 0,
};

const Side = enum { client, upstream };

const StepFailure = struct { side: Side };

/// Bounded work per direction per wakeup, so one busy direction cannot
/// starve the other or the timers.
const max_moves_per_step = 16;

/// Move bytes `src` -> `dst` until neither can make progress. Returns whether
/// anything moved, or which side failed.
fn step(dir: *Direction, src: anytype, src_side: Side, dst: anytype, dst_side: Side, reading: bool) union(enum) { progressed: bool, failed: Side } {
    var progressed = false;
    var moves: usize = 0;
    while (moves < max_moves_per_step) : (moves += 1) {
        if (dir.pending.len > 0) {
            const n = dst.write(dir.pending) catch return .{ .failed = dst_side };
            if (n == 0) break;
            dir.pending = dir.pending[n..];
            dir.delivered += n;
            progressed = true;
            continue;
        }
        if (!reading or dir.eof) break;
        const read = src.read(dir.buf) catch return .{ .failed = src_side };
        const n = read orelse break;
        progressed = true;
        if (n == 0) {
            dir.eof = true;
            break;
        }
        dir.pending = dir.buf[0..n];
    }
    dst.flush() catch return .{ .failed = dst_side };
    return .{ .progressed = progressed };
}

fn remainingMs(now: u64, deadline: ?u64) ?u64 {
    const at = deadline orelse return null;
    return if (at > now) at - now else 0;
}

fn minDeadline(a: ?u64, b: ?u64) ?u64 {
    if (a == null) return b;
    if (b == null) return a;
    return @min(a.?, b.?);
}

/// Relay bytes between `client` and `upstream` until the tunnel closes.
/// `initial_to_upstream` / `initial_to_client` are bytes already read past
/// the handshake on either hop; they are delivered first and need not live
/// in the direction buffers. Never returns an error: every way a tunnel can
/// end is a `CloseReason`.
pub fn relay(
    client: anytype,
    upstream: anytype,
    client_to_upstream_buf: []u8,
    upstream_to_client_buf: []u8,
    initial_to_upstream: []const u8,
    initial_to_client: []const u8,
    opts: Options,
) Stats {
    beginEndpoint(client);
    beginEndpoint(upstream);
    var c2u = Direction{ .buf = client_to_upstream_buf, .pending = initial_to_upstream };
    var u2c = Direction{ .buf = upstream_to_client_buf, .pending = initial_to_client };
    const started = event_loop.monotonicMs();
    var last_activity = started;
    const lifetime_deadline: ?u64 = if (opts.max_lifetime_ms > 0) started + opts.max_lifetime_ms else null;
    var shutdown_deadline: ?u64 = null;
    var reload_deadline: ?u64 = null;
    // Set once a side has closed: the other direction's already-read bytes
    // get a bounded flush, and nothing more is read from either side.
    var closing: ?CloseReason = null;
    var closing_deadline: ?u64 = null;
    // A side whose socket reported hang-up while the relay was not reading
    // it is left out of `poll` (it would wake it forever) and read again
    // once its direction has room.
    var client_hup = false;
    var upstream_hup = false;

    const reason: CloseReason = loop: while (true) {
        const reading = closing == null;
        const c2u_step = step(&c2u, client, .client, upstream, .upstream, reading);
        const u2c_step = step(&u2c, upstream, .upstream, client, .client, reading);
        var progressed = false;
        switch (c2u_step) {
            .failed => |side| break :loop if (side == .client) .client_error else .upstream_error,
            .progressed => |p| progressed = progressed or p,
        }
        switch (u2c_step) {
            .failed => |side| break :loop if (side == .client) .client_error else .upstream_error,
            .progressed => |p| progressed = progressed or p,
        }

        const now = event_loop.monotonicMs();
        if (progressed) {
            last_activity = now;
            client_hup = false;
            upstream_hup = false;
        }
        if (closing == null) {
            if (c2u.eof) {
                closing = .client;
            } else if (u2c.eof) {
                closing = .upstream;
            }
            if (closing != null) closing_deadline = now + opts.close_flush_timeout_ms;
        }
        const flushed = c2u.pending.len == 0 and u2c.pending.len == 0 and !client.pendingOutput() and !upstream.pendingOutput();
        if (closing) |why| {
            if (flushed or now >= closing_deadline.?) break :loop why;
        }
        if (opts.idle_timeout_ms > 0 and now -| last_activity >= opts.idle_timeout_ms) break :loop .idle;
        if (lifetime_deadline) |at| if (now >= at) break :loop .lifetime;
        if (shutdown_deadline == null and opts.shutdown_requested()) shutdown_deadline = now + opts.drain_timeout_ms;
        if (reload_deadline == null) if (opts.reload_drain) |drain| {
            const superseded_at = drain.superseded_at_ms.load(.acquire);
            if (superseded_at != 0) reload_deadline = superseded_at + drain.timeout_ms;
        };
        // Shutdown and reload drains are independent; whichever deadline is
        // earlier ends the tunnel.
        if (earliestDue(now, shutdown_deadline, reload_deadline)) |why| break :loop why;
        if (progressed) continue;

        // Nothing moved: sleep until a socket can make progress or a timer
        // is due.
        const wants_client_in = reading and !c2u.eof and c2u.pending.len == 0;
        const wants_upstream_in = reading and !u2c.eof and u2c.pending.len == 0;
        if ((wants_client_in and client.bufferedInput()) or (wants_upstream_in and upstream.bufferedInput())) continue;
        const wants_client_out = u2c.pending.len > 0 or client.pendingOutput();
        const wants_upstream_out = c2u.pending.len > 0 or upstream.pendingOutput();

        var fds = [2]std.posix.pollfd{
            pollEntry(client.fd(), wants_client_in and !client_hup, wants_client_out),
            pollEntry(upstream.fd(), wants_upstream_in and !upstream_hup, wants_upstream_out),
        };
        var wait_deadline = now + opts.poll_interval_ms;
        if (opts.idle_timeout_ms > 0) wait_deadline = @min(wait_deadline, last_activity + opts.idle_timeout_ms);
        wait_deadline = minDeadline(wait_deadline, minDeadline(lifetime_deadline, minDeadline(shutdown_deadline, minDeadline(reload_deadline, closing_deadline)))).?;
        const timeout: i32 = @intCast(@min(remainingMs(now, wait_deadline).?, @as(u64, std.math.maxInt(i32))));
        _ = std.posix.poll(&fds, timeout) catch {};
        if (hungUp(fds[0])) client_hup = true;
        if (hungUp(fds[1])) upstream_hup = true;
    };

    return .{
        .client_to_upstream_bytes = c2u.delivered,
        .upstream_to_client_bytes = u2c.delivered,
        .duration_ms = event_loop.monotonicMs() -| started,
        .close_reason = reason,
    };
}

/// The drain whose deadline has passed, preferring the earlier deadline when
/// both have.
fn earliestDue(now: u64, shutdown_deadline: ?u64, reload_deadline: ?u64) ?CloseReason {
    const shutdown_due = if (shutdown_deadline) |at| now >= at else false;
    const reload_due = if (reload_deadline) |at| now >= at else false;
    if (shutdown_due and reload_due) return if (reload_deadline.? < shutdown_deadline.?) .reload else .shutdown;
    if (shutdown_due) return .shutdown;
    if (reload_due) return .reload;
    return null;
}

fn pollEntry(fd: std.posix.fd_t, want_in: bool, want_out: bool) std.posix.pollfd {
    var events: i16 = 0;
    if (want_in) events |= std.posix.POLL.IN;
    if (want_out) events |= std.posix.POLL.OUT;
    // A negative fd is ignored by poll, so a side the relay is not waiting on
    // cannot wake it with a hang-up.
    return .{ .fd = if (events == 0) -1 else fd, .events = events, .revents = 0 };
}

/// Hang-up or error reported without readable data: the next read on that
/// side decides what it means, but polling it again would spin.
fn hungUp(entry: std.posix.pollfd) bool {
    const bad = std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL;
    return (entry.revents & bad) != 0 and (entry.revents & std.posix.POLL.IN) == 0;
}

// Tests

fn testSocketPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
        if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    } else {
        if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    }
    return fds;
}

fn testClose(fd: std.posix.fd_t) void {
    _ = std.c.close(fd);
}

fn neverShutdown() bool {
    return false;
}

var test_shutdown_flag = std.atomic.Value(bool).init(false);

fn testShutdown() bool {
    return test_shutdown_flag.load(.acquire);
}

fn testWriteAll(fd: std.posix.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = std.c.write(fd, bytes[off..].ptr, bytes.len - off);
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }
}

fn testReadExact(fd: std.posix.fd_t, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        var pfd = [1]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
        if (try std.posix.poll(&pfd, 5_000) == 0) return error.Timeout;
        const n = std.c.read(fd, out[off..].ptr, out.len - off);
        if (n <= 0) return error.ReadFailed;
        off += @intCast(n);
    }
}

/// Runs `relay` on its own thread between two socketpairs; the test drives
/// the far ends, `client_peer` and `upstream_peer`.
const TestTunnel = struct {
    client_pair: [2]std.posix.fd_t,
    upstream_pair: [2]std.posix.fd_t,
    c2u: [64]u8 = undefined,
    u2c: [64]u8 = undefined,
    initial_to_upstream: []const u8 = "",
    initial_to_client: []const u8 = "",
    opts: Options,
    stats: Stats = .{},
    thread: std.Thread = undefined,

    fn init(opts: Options) !TestTunnel {
        const client_pair = try testSocketPair();
        errdefer {
            testClose(client_pair[0]);
            testClose(client_pair[1]);
        }
        return .{ .client_pair = client_pair, .upstream_pair = try testSocketPair(), .opts = opts };
    }

    fn clientPeer(self: *const TestTunnel) std.posix.fd_t {
        return self.client_pair[1];
    }

    fn upstreamPeer(self: *const TestTunnel) std.posix.fd_t {
        return self.upstream_pair[1];
    }

    fn start(self: *TestTunnel) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn run(self: *TestTunnel) void {
        self.stats = relay(
            SocketEndpoint{ .handle = self.client_pair[0] },
            SocketEndpoint{ .handle = self.upstream_pair[0] },
            &self.c2u,
            &self.u2c,
            self.initial_to_upstream,
            self.initial_to_client,
            self.opts,
        );
    }

    fn join(self: *TestTunnel) void {
        self.thread.join();
    }

    fn deinit(self: *TestTunnel) void {
        for (self.client_pair) |fd| testClose(fd);
        for (self.upstream_pair) |fd| testClose(fd);
    }
};

test "relay copies bytes both ways, initial bytes first, until a side closes" {
    var tunnel = try TestTunnel.init(.{ .idle_timeout_ms = 5_000, .shutdown_requested = neverShutdown });
    defer tunnel.deinit();
    tunnel.initial_to_upstream = "early-client|";
    tunnel.initial_to_client = "early-origin|";
    try tunnel.start();

    // More than one direction buffer's worth, so the relay has to loop.
    const big = "0123456789abcdef" ** 32;
    try testWriteAll(tunnel.clientPeer(), big);
    var got: ["early-client|".len + big.len]u8 = undefined;
    try testReadExact(tunnel.upstreamPeer(), &got);
    try std.testing.expectEqualStrings("early-client|" ++ big, &got);

    try testWriteAll(tunnel.upstreamPeer(), "pong");
    var back: ["early-origin|pong".len]u8 = undefined;
    try testReadExact(tunnel.clientPeer(), &back);
    try std.testing.expectEqualStrings("early-origin|pong", &back);

    // The origin closes after its last bytes: they still reach the client.
    try testWriteAll(tunnel.upstreamPeer(), "bye");
    testClose(tunnel.upstream_pair[1]);
    tunnel.upstream_pair[1] = -1;
    var last: [3]u8 = undefined;
    try testReadExact(tunnel.clientPeer(), &last);
    try std.testing.expectEqualStrings("bye", &last);
    tunnel.join();

    try std.testing.expectEqual(CloseReason.upstream, tunnel.stats.close_reason);
    try std.testing.expectEqual(@as(u64, "early-client|".len + big.len), tunnel.stats.client_to_upstream_bytes);
    try std.testing.expectEqual(@as(u64, "early-origin|pongbye".len), tunnel.stats.upstream_to_client_bytes);
}

test "relay reports a client close" {
    var tunnel = try TestTunnel.init(.{ .idle_timeout_ms = 5_000, .shutdown_requested = neverShutdown });
    defer tunnel.deinit();
    try tunnel.start();
    try testWriteAll(tunnel.clientPeer(), "last");
    testClose(tunnel.client_pair[1]);
    tunnel.client_pair[1] = -1;
    var got: [4]u8 = undefined;
    try testReadExact(tunnel.upstreamPeer(), &got);
    tunnel.join();
    try std.testing.expectEqual(CloseReason.client, tunnel.stats.close_reason);
    try std.testing.expectEqualStrings("last", &got);
}

test "relay closes an idle tunnel" {
    var tunnel = try TestTunnel.init(.{ .idle_timeout_ms = 50, .shutdown_requested = neverShutdown, .poll_interval_ms = 10 });
    defer tunnel.deinit();
    try tunnel.start();
    tunnel.join();
    try std.testing.expectEqual(CloseReason.idle, tunnel.stats.close_reason);
    try std.testing.expect(tunnel.stats.duration_ms >= 50);
}

test "relay enforces the maximum lifetime even while traffic flows" {
    var tunnel = try TestTunnel.init(.{ .idle_timeout_ms = 5_000, .max_lifetime_ms = 80, .shutdown_requested = neverShutdown, .poll_interval_ms = 10 });
    defer tunnel.deinit();
    try tunnel.start();
    var i: usize = 0;
    var buf: [1]u8 = undefined;
    while (i < 5) : (i += 1) {
        testWriteAll(tunnel.clientPeer(), "x") catch break;
        testReadExact(tunnel.upstreamPeer(), &buf) catch break;
    }
    tunnel.join();
    try std.testing.expectEqual(CloseReason.lifetime, tunnel.stats.close_reason);
}

test "relay drains for the shutdown window, then closes" {
    test_shutdown_flag.store(false, .release);
    defer test_shutdown_flag.store(false, .release);
    var tunnel = try TestTunnel.init(.{ .idle_timeout_ms = 5_000, .drain_timeout_ms = 60, .shutdown_requested = testShutdown, .poll_interval_ms = 10 });
    defer tunnel.deinit();
    try tunnel.start();
    test_shutdown_flag.store(true, .release);
    // Traffic still flows inside the drain window.
    try testWriteAll(tunnel.clientPeer(), "draining");
    var got: [8]u8 = undefined;
    try testReadExact(tunnel.upstreamPeer(), &got);
    try std.testing.expectEqualStrings("draining", &got);
    tunnel.join();
    try std.testing.expectEqual(CloseReason.shutdown, tunnel.stats.close_reason);
}

test "relay never buffers more than one direction buffer for a stalled reader" {
    // The client never reads. The relay may fill the client socket and its
    // own 64-byte buffer, and must then stop reading the origin, so the
    // origin's writes eventually hit a full socket instead of memory growing.
    var tunnel = try TestTunnel.init(.{ .idle_timeout_ms = 200, .shutdown_requested = neverShutdown, .poll_interval_ms = 10 });
    defer tunnel.deinit();
    try tunnel.start();
    const origin = tunnel.upstreamPeer();
    setNonBlocking(origin);
    const chunk = [_]u8{'z'} ** 4096;
    var accepted: usize = 0;
    var stalled = false;
    var attempts: usize = 0;
    while (attempts < 20_000) : (attempts += 1) {
        const n = std.c.write(origin, &chunk, chunk.len);
        if (n > 0) {
            accepted += @intCast(n);
            continue;
        }
        stalled = true;
        break;
    }
    try std.testing.expect(stalled);
    tunnel.join();
    try std.testing.expectEqual(CloseReason.idle, tunnel.stats.close_reason);
    // Everything the origin managed to send sits in kernel socket buffers or
    // the relay's single 64-byte buffer; nothing else was read.
    try std.testing.expect(tunnel.stats.upstream_to_client_bytes <= accepted);
}

test "relay keeps a drain-mode tunnel open until its configuration is superseded, then for the reload timeout (#812)" {
    var superseded = std.atomic.Value(u64).init(0);
    var tunnel = try TestTunnel.init(.{
        .idle_timeout_ms = 5_000,
        .shutdown_requested = neverShutdown,
        .reload_drain = .{ .superseded_at_ms = &superseded, .timeout_ms = 120 },
        .poll_interval_ms = 10,
    });
    defer tunnel.deinit();
    try tunnel.start();

    // Still current: traffic flows and nothing closes.
    compat.sleepNs(150 * std.time.ns_per_ms);
    try testWriteAll(tunnel.clientPeer(), "before");
    var got: [6]u8 = undefined;
    try testReadExact(tunnel.upstreamPeer(), &got);

    const reloaded_at = event_loop.monotonicMs();
    superseded.store(reloaded_at, .release);
    // Inside the window the tunnel still carries traffic.
    try testWriteAll(tunnel.clientPeer(), "during");
    try testReadExact(tunnel.upstreamPeer(), &got);
    try std.testing.expectEqualStrings("during", &got);
    tunnel.join();
    const closed_after = event_loop.monotonicMs() - reloaded_at;
    try std.testing.expectEqual(CloseReason.reload, tunnel.stats.close_reason);
    try std.testing.expect(closed_after >= 120);
    try std.testing.expect(closed_after < 1_000);
}

test "relay honors whichever of the reload and shutdown drains ends first (#812)" {
    // An earlier reload deadline beats a later shutdown deadline.
    test_shutdown_flag.store(false, .release);
    defer test_shutdown_flag.store(false, .release);
    var early_reload = std.atomic.Value(u64).init(event_loop.monotonicMs());
    var reload_first = try TestTunnel.init(.{
        .idle_timeout_ms = 5_000,
        .drain_timeout_ms = 5_000,
        .shutdown_requested = testShutdown,
        .reload_drain = .{ .superseded_at_ms = &early_reload, .timeout_ms = 80 },
        .poll_interval_ms = 10,
    });
    defer reload_first.deinit();
    test_shutdown_flag.store(true, .release);
    try reload_first.start();
    reload_first.join();
    try std.testing.expectEqual(CloseReason.reload, reload_first.stats.close_reason);
    try std.testing.expect(reload_first.stats.duration_ms < 2_000);

    // A shutdown whose window ends first beats a long reload drain.
    var late_reload = std.atomic.Value(u64).init(event_loop.monotonicMs());
    var shutdown_first = try TestTunnel.init(.{
        .idle_timeout_ms = 5_000,
        .drain_timeout_ms = 60,
        .shutdown_requested = testShutdown,
        .reload_drain = .{ .superseded_at_ms = &late_reload, .timeout_ms = 5_000 },
        .poll_interval_ms = 10,
    });
    defer shutdown_first.deinit();
    try shutdown_first.start();
    shutdown_first.join();
    try std.testing.expectEqual(CloseReason.shutdown, shutdown_first.stats.close_reason);
    try std.testing.expect(shutdown_first.stats.duration_ms < 2_000);
}

test "CloseReason labels collapse I/O failures into one error label" {
    try std.testing.expectEqualStrings("client", CloseReason.client.label());
    try std.testing.expectEqualStrings("error", CloseReason.client_error.label());
    try std.testing.expectEqualStrings("error", CloseReason.upstream_error.label());
    try std.testing.expectEqualStrings("shutdown", CloseReason.shutdown.label());
    try std.testing.expectEqualStrings("reload", CloseReason.reload.label());
}
