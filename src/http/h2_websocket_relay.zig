//! Bidirectional byte relay between a connection-owned H2 stream session
//! (#867, `h2_stream_session.zig`) and an upgraded H1 WebSocket upstream
//! connection (#864's RFC 8441 downstream translation).
//!
//! `Session`'s consumer API is deliberately blocking -- its own doc comment
//! says the consumer runs on its own worker thread, never touching the
//! connection's socket. The upstream connection's blocking `read`/`writeAll`
//! pair pins the other end of that same thread-per-tunnel model. Since both
//! sides can block, one thread cannot service both directions at once: `run`
//! uses two, one per direction, and drives them as a bounded watchdog on the
//! calling thread so idle/lifetime/shutdown limits end the tunnel even while
//! both I/O threads are parked waiting for bytes that may never arrive.
const std = @import("std");
const compat = @import("zig_compat");
const h2_stream_session = @import("h2_stream_session.zig");
const tunnel = @import("tunnel.zig");
const upstream_tls = @import("upstream_tls.zig");
const event_loop = @import("event_loop.zig");

pub const Stats = tunnel.Stats;
pub const CloseReason = tunnel.CloseReason;
pub const ReloadDrain = tunnel.ReloadDrain;

pub const Options = struct {
    /// Close after this long with no bytes moving either way. Zero disables.
    idle_timeout_ms: u32,
    /// Close this long after the tunnel opened. Zero disables.
    max_lifetime_ms: u32 = 0,
    /// Once shutdown is requested, keep relaying this long, then close
    /// (mirrors `tunnel.Options.drain_timeout_ms`, the H1 tunnel contract).
    drain_timeout_ms: u64 = 0,
    /// Checked at least every `poll_interval_ms`.
    shutdown_requested: *const fn () bool,
    /// Set for tunnels admitted with `proxy_websocket_reload drain`.
    reload_drain: ?ReloadDrain = null,
    poll_interval_ms: u32 = 250,
};

/// The upgraded upstream WebSocket connection's transport: a plain TCP/Unix
/// socket, or the native upstream TLS client over one.
pub const Upstream = struct {
    fd: std.posix.fd_t,
    tls: ?*upstream_tls.UpstreamTlsConn,

    fn read(self: Upstream, buf: []u8) !usize {
        if (self.tls) |t| return t.read(buf) catch return error.TunnelIoFailed;
        return compat.netStreamFromFd(self.fd).read(buf) catch return error.TunnelIoFailed;
    }

    fn writeAll(self: Upstream, bytes: []const u8) !void {
        if (self.tls) |t| {
            t.writeAll(bytes) catch return error.TunnelIoFailed;
            return;
        }
        compat.netStreamFromFd(self.fd).writeAll(bytes) catch return error.TunnelIoFailed;
    }

    /// Force both directions of a thread blocked in `read`/`writeAll` above
    /// to return, from another thread, without racing a `close()` of a file
    /// descriptor something else might already be reusing.
    fn shutdownBoth(self: Upstream) void {
        // `std.posix.shutdown` is unavailable in this std; use `std.c`
        // directly, mirroring `upstream_h2.zig`'s `SHUT_RDWR` teardown.
        _ = std.c.shutdown(self.fd, 2);
    }
};

/// Settles the tunnel exactly once, from whichever side (an I/O thread or the
/// watchdog) ends it first, and forces the other side's blocking call to
/// return: `session.requestCancel()` asks the connection runtime to
/// RST_STREAM (which settles the session and wakes a blocked
/// `read`/`write`), and shutting down the upstream socket wakes a blocked
/// upstream `read`/`writeAll`.
const Shared = struct {
    mutex: compat.Mutex = .{},
    done: bool = false,
    reason: CloseReason = .client,
    last_activity_ms: std.atomic.Value(u64),
    session: *h2_stream_session.Session,
    upstream: Upstream,

    fn touch(self: *Shared) void {
        self.last_activity_ms.store(event_loop.monotonicMs(), .monotonic);
    }

    fn finishOnce(self: *Shared, reason: CloseReason) void {
        self.mutex.lock();
        const already_done = self.done;
        if (!already_done) {
            self.done = true;
            self.reason = reason;
        }
        self.mutex.unlock();
        if (already_done) return;
        self.session.requestCancel();
        self.upstream.shutdownBoth();
    }

    fn isDone(self: *Shared) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.done;
    }
};

fn closeReasonForTerminal(terminal: h2_stream_session.TerminalReason) CloseReason {
    return switch (terminal) {
        .reset => .client_error,
        .goaway => .client,
        .connection_closed => .client_error,
        .shutdown => .shutdown,
    };
}

const relay_chunk_bytes = 16 * 1024;

const SessionToUpstream = struct {
    shared: *Shared,
    bytes: u64 = 0,

    fn run(self: *SessionToUpstream) void {
        var buf: [relay_chunk_bytes]u8 = undefined;
        while (true) {
            const result = self.shared.session.read(&buf);
            switch (result) {
                .data => |n| {
                    self.shared.upstream.writeAll(buf[0..n]) catch {
                        self.shared.finishOnce(.upstream_error);
                        return;
                    };
                    self.bytes += n;
                    self.shared.touch();
                },
                // The client half-closed its side (RFC 9113 half-closed
                // remote). The origin may still have bytes left to send --
                // `UpstreamToSession` ends the whole tunnel once it sees the
                // origin's own EOF -- so this side simply stops forwarding
                // rather than tearing the tunnel down unilaterally.
                .end_stream => return,
                .reset => {
                    self.shared.finishOnce(.client_error);
                    return;
                },
                .closed => |why| {
                    self.shared.finishOnce(closeReasonForTerminal(why));
                    return;
                },
            }
        }
    }
};

const UpstreamToSession = struct {
    shared: *Shared,
    bytes: u64 = 0,

    fn run(self: *UpstreamToSession) void {
        var buf: [relay_chunk_bytes]u8 = undefined;
        while (true) {
            const n = self.shared.upstream.read(&buf) catch {
                self.shared.session.finishLocal();
                self.shared.finishOnce(.upstream_error);
                return;
            };
            if (n == 0) {
                // A clean origin close ends the whole tunnel (RFC 6455
                // WebSockets do not have an independent TCP half-close
                // convention Tardigrade can rely on while treating frames as
                // opaque bytes): tell the H2 side we are done producing,
                // then settle.
                self.shared.session.finishLocal();
                self.shared.finishOnce(.upstream);
                return;
            }
            const result = self.shared.session.write(buf[0..n]) catch {
                self.shared.finishOnce(.upstream_error);
                return;
            };
            switch (result) {
                .ok => {
                    self.bytes += n;
                    self.shared.touch();
                },
                .reset, .closed, .finished => {
                    self.shared.finishOnce(.client_error);
                    return;
                },
            }
        }
    }
};

/// Relay bytes between `session` and `upstream` until the tunnel closes,
/// blocking the calling thread for the tunnel's whole life. `initial_to_client`
/// is bytes the H1 upgrade handshake already read past the origin's `101`
/// head (its first WebSocket frames); they are delivered to the H2 side
/// before the relay threads start so nothing reorders them behind freshly
/// read bytes.
pub fn run(session: *h2_stream_session.Session, upstream: Upstream, initial_to_client: []const u8, opts: Options) Stats {
    const started = event_loop.monotonicMs();
    var shared = Shared{
        .last_activity_ms = std.atomic.Value(u64).init(started),
        .session = session,
        .upstream = upstream,
    };

    if (initial_to_client.len > 0) {
        // Best effort: a failure here still leaves the relay threads below
        // to observe and report the same terminal session state.
        _ = session.write(initial_to_client) catch {};
    }

    var s2u = SessionToUpstream{ .shared = &shared };
    var u2s = UpstreamToSession{ .shared = &shared };

    const s2u_thread = std.Thread.spawn(.{}, SessionToUpstream.run, .{&s2u}) catch {
        shared.finishOnce(.upstream_error);
        return statsFor(&shared, &s2u, &u2s, started);
    };
    const u2s_thread = std.Thread.spawn(.{}, UpstreamToSession.run, .{&u2s}) catch {
        shared.finishOnce(.upstream_error);
        s2u_thread.join();
        return statsFor(&shared, &s2u, &u2s, started);
    };

    const lifetime_deadline: ?u64 = if (opts.max_lifetime_ms > 0) started + @as(u64, opts.max_lifetime_ms) else null;
    const sleep_ns: u64 = @as(u64, @max(opts.poll_interval_ms, 10)) * std.time.ns_per_ms;
    var shutdown_deadline: ?u64 = null;
    var reload_deadline: ?u64 = null;
    while (!shared.isDone()) {
        const now = event_loop.monotonicMs();
        if (opts.idle_timeout_ms > 0 and now -| shared.last_activity_ms.load(.monotonic) >= opts.idle_timeout_ms) {
            shared.finishOnce(.idle);
            break;
        }
        if (lifetime_deadline) |at| if (now >= at) {
            shared.finishOnce(.lifetime);
            break;
        };
        if (shutdown_deadline == null and opts.shutdown_requested()) shutdown_deadline = now + opts.drain_timeout_ms;
        if (reload_deadline == null) if (opts.reload_drain) |drain| {
            const superseded_at = drain.superseded_at_ms.load(.acquire);
            if (superseded_at != 0) reload_deadline = superseded_at + drain.timeout_ms;
        };
        // Shutdown and reload drains are independent; whichever deadline is
        // earlier ends the tunnel (mirrors `tunnel.zig`'s `earliestDue`).
        if (shutdown_deadline) |at| if (now >= at) {
            shared.finishOnce(.shutdown);
            break;
        };
        if (reload_deadline) |at| if (now >= at) {
            shared.finishOnce(.reload);
            break;
        };
        compat.sleepNs(sleep_ns);
    }

    s2u_thread.join();
    u2s_thread.join();
    return statsFor(&shared, &s2u, &u2s, started);
}

fn statsFor(shared: *Shared, s2u: *const SessionToUpstream, u2s: *const UpstreamToSession, started: u64) Stats {
    return .{
        .client_to_upstream_bytes = s2u.bytes,
        .upstream_to_client_bytes = u2s.bytes,
        .duration_ms = event_loop.monotonicMs() -| started,
        .close_reason = shared.reason,
    };
}

/// `run`'s watchdog and `SessionToUpstream` both end a session only by
/// asking the connection runtime to RST_STREAM it (`requestCancel`), exactly
/// as production does: the runtime, not the relay, is responsible for
/// actually writing RST_STREAM to the peer before `deliverReset` settles the
/// session and wakes a blocked consumer `read`/`write`. These tests stand in
/// for that runtime with a one-shot responder thread, mirroring
/// `SessionDrainCtx.drain`'s `takeCancelRequest` -> `deliverReset` pairing in
/// `edge_gateway.zig`.
fn cancelResponder(session: *h2_stream_session.Session) void {
    while (!session.takeCancelRequest()) compat.sleepNs(2 * std.time.ns_per_ms);
    session.deliverReset(.cancel);
}

test "run relays bytes both ways and reports idle close" {
    const allocator = std.testing.allocator;
    var session = try h2_stream_session.Session.init(allocator, 1, 1, 64 * 1024, 64 * 1024);
    defer session.deinit();

    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    const origin_side = fds[0];
    const test_side = fds[1];
    defer _ = std.c.close(test_side);

    const Ctx = struct {
        session: *h2_stream_session.Session,
        upstream: Upstream,
        stats: Stats = undefined,
        fn runRelay(ctx: *@This()) void {
            ctx.stats = run(ctx.session, ctx.upstream, "", .{ .idle_timeout_ms = 200, .shutdown_requested = neverShutdown, .poll_interval_ms = 20 });
        }
    };
    var ctx = Ctx{ .session = &session, .upstream = .{ .fd = origin_side, .tls = null } };
    const relay_thread = try std.Thread.spawn(.{}, Ctx.runRelay, .{&ctx});
    const responder_thread = try std.Thread.spawn(.{}, cancelResponder, .{&session});

    // Client -> upstream: the session's consumer (the relay) reads this and
    // writes it to the origin socket.
    try session.deliverInbound("hello-origin");
    var got: [12]u8 = undefined;
    try readExactBlocking(test_side, &got);
    try std.testing.expectEqualStrings("hello-origin", &got);

    // Upstream -> client: written to the origin socket, relayed into the
    // session's outbound queue for the connection runtime to drain.
    try writeAllBlocking(test_side, "hello-client");
    var buf: [32]u8 = undefined;
    var total: usize = 0;
    while (total < "hello-client".len) {
        const n = session.peekOutbound(buf.len - total) orelse continue;
        @memcpy(buf[total..][0..n.len], n);
        total += n.len;
        session.commitOutboundSent(n.len);
    }
    try std.testing.expectEqualStrings("hello-client", buf[0..total]);

    relay_thread.join();
    responder_thread.join();
    try std.testing.expectEqual(CloseReason.idle, ctx.stats.close_reason);
    try std.testing.expectEqual(@as(u64, "hello-origin".len), ctx.stats.client_to_upstream_bytes);
    try std.testing.expectEqual(@as(u64, "hello-client".len), ctx.stats.upstream_to_client_bytes);
}

test "run ends the whole tunnel once the origin closes" {
    const allocator = std.testing.allocator;
    var session = try h2_stream_session.Session.init(allocator, 1, 1, 64 * 1024, 64 * 1024);
    defer session.deinit();

    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    const origin_side = fds[0];
    const test_side = fds[1];

    const Ctx = struct {
        session: *h2_stream_session.Session,
        upstream: Upstream,
        stats: Stats = undefined,
        fn runRelay(ctx: *@This()) void {
            ctx.stats = run(ctx.session, ctx.upstream, "", .{ .idle_timeout_ms = 5_000, .shutdown_requested = neverShutdown, .poll_interval_ms = 20 });
        }
    };
    var ctx = Ctx{ .session = &session, .upstream = .{ .fd = origin_side, .tls = null } };
    const relay_thread = try std.Thread.spawn(.{}, Ctx.runRelay, .{&ctx});
    const responder_thread = try std.Thread.spawn(.{}, cancelResponder, .{&session});

    _ = std.c.close(test_side);
    relay_thread.join();
    responder_thread.join();
    try std.testing.expectEqual(CloseReason.upstream, ctx.stats.close_reason);

    // `UpstreamToSession` called `finishLocal` before settling: local
    // production is over even though the session itself settled via the
    // simulated runtime's RST, not a clean END_STREAM.
    var buf: [4]u8 = undefined;
    try std.testing.expectEqual(h2_stream_session.ReadResult{ .reset = .cancel }, session.read(&buf));
}

test "run ends the tunnel once proxy_websocket_reload drain's timeout elapses after supersession" {
    const allocator = std.testing.allocator;
    var session = try h2_stream_session.Session.init(allocator, 1, 1, 64 * 1024, 64 * 1024);
    defer session.deinit();

    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    const origin_side = fds[0];
    const test_side = fds[1];
    defer _ = std.c.close(test_side);

    var superseded_at = std.atomic.Value(u64).init(0);
    const Ctx = struct {
        session: *h2_stream_session.Session,
        upstream: Upstream,
        superseded_at: *std.atomic.Value(u64),
        stats: Stats = undefined,
        fn runRelay(ctx: *@This()) void {
            ctx.stats = run(ctx.session, ctx.upstream, "", .{
                .idle_timeout_ms = 5_000,
                .shutdown_requested = neverShutdown,
                .reload_drain = .{ .superseded_at_ms = ctx.superseded_at, .timeout_ms = 40 },
                .poll_interval_ms = 10,
            });
        }
    };
    var ctx = Ctx{ .session = &session, .upstream = .{ .fd = origin_side, .tls = null }, .superseded_at = &superseded_at };
    const relay_thread = try std.Thread.spawn(.{}, Ctx.runRelay, .{&ctx});
    const responder_thread = try std.Thread.spawn(.{}, cancelResponder, .{&session});

    // The reload that supersedes this tunnel's admission configuration can
    // land at any point in its life; the drain timeout starts counting from
    // that stamp, not from tunnel start.
    compat.sleepNs(15 * std.time.ns_per_ms);
    superseded_at.store(event_loop.monotonicMs(), .release);

    relay_thread.join();
    responder_thread.join();
    try std.testing.expectEqual(CloseReason.reload, ctx.stats.close_reason);
}

test "run keeps relaying through drain_timeout_ms before a requested shutdown closes it" {
    const allocator = std.testing.allocator;
    var session = try h2_stream_session.Session.init(allocator, 1, 1, 64 * 1024, 64 * 1024);
    defer session.deinit();

    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    const origin_side = fds[0];
    const test_side = fds[1];
    defer _ = std.c.close(test_side);

    test_shutdown_requested.store(false, .release);
    defer test_shutdown_requested.store(false, .release);

    const Ctx = struct {
        session: *h2_stream_session.Session,
        upstream: Upstream,
        stats: Stats = undefined,
        fn runRelay(ctx: *@This()) void {
            ctx.stats = run(ctx.session, ctx.upstream, "", .{
                .idle_timeout_ms = 5_000,
                .shutdown_requested = testShutdownRequested,
                .drain_timeout_ms = 300,
                .poll_interval_ms = 10,
            });
        }
    };
    var ctx = Ctx{ .session = &session, .upstream = .{ .fd = origin_side, .tls = null } };
    const relay_thread = try std.Thread.spawn(.{}, Ctx.runRelay, .{&ctx});
    const responder_thread = try std.Thread.spawn(.{}, cancelResponder, .{&session});

    test_shutdown_requested.store(true, .release);
    // Still relaying inside the drain window: a byte sent now must still
    // reach the other side rather than the tunnel closing immediately.
    try session.deliverInbound("x");
    var got: [1]u8 = undefined;
    try readExactBlocking(test_side, &got);
    try std.testing.expectEqualStrings("x", &got);

    relay_thread.join();
    responder_thread.join();
    try std.testing.expectEqual(CloseReason.shutdown, ctx.stats.close_reason);
    try std.testing.expect(ctx.stats.duration_ms >= 300);
}

fn neverShutdown() bool {
    return false;
}

var test_shutdown_requested = std.atomic.Value(bool).init(false);
fn testShutdownRequested() bool {
    return test_shutdown_requested.load(.acquire);
}

fn readExactBlocking(fd: std.posix.fd_t, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = std.c.read(fd, out[off..].ptr, out.len - off);
        if (n <= 0) return error.ReadFailed;
        off += @intCast(n);
    }
}

fn writeAllBlocking(fd: std.posix.fd_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = std.c.write(fd, bytes[off..].ptr, bytes.len - off);
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }
}
