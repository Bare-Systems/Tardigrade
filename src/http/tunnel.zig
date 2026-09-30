//! Bidirectional byte relay for upgraded connections (#812).
//!
//! After a WebSocket handshake is relayed, Tardigrade stops speaking HTTP on
//! both hops and copies bytes between the client and the origin until either
//! side closes. The relay never parses frames. `Relay` drives both endpoints
//! non-blocking and holds at most one fixed buffer per direction: a slow
//! reader stops the relay from reading the other side, so TCP flow control
//! pushes back on the fast writer instead of memory growing. Established
//! tunnels run on `tunnel_reactor` threads, many per thread (#818); `relay`
//! runs one on the calling thread.
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
//! - `yielded() bool`: the last call stopped on its TLS drive budget with
//!   record-layer work possibly left (#818); the relay retries it right
//!   after other tunnels get a turn instead of waiting for the socket.

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

    pub fn yielded(_: SocketEndpoint) bool {
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
        return self.conn.readBounded(buf, budget) catch |err| switch (err) {
            error.WouldBlock => null,
            // A peer that closes without close_notify ends the tunnel the same
            // way: WebSocket framing, not TLS, tells the application whether
            // its last message was complete.
            error.EndOfStream, error.TruncatedStream => 0,
            else => error.TunnelIoFailed,
        };
    }

    pub fn write(self: EncryptedEndpoint, bytes: []const u8) Error!usize {
        return self.conn.writeBounded(bytes, budget) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => error.TunnelIoFailed,
        };
    }

    pub fn flush(self: EncryptedEndpoint) Error!void {
        self.conn.flushBounded(budget) catch |err| switch (err) {
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

    pub fn yielded(self: EncryptedEndpoint) bool {
        return self.conn.drive_budget_exhausted;
    }

    const budget = encrypted_stream_connection.EncryptedStreamHttpConnection.tunnel_drive_budget;
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

    pub fn yielded(self: UpstreamTlsEndpoint) bool {
        return self.tls.drive_budget_exhausted;
    }
};

/// Any of the endpoint kinds above, so one `Relay` type can carry every
/// plaintext/TLS combination of client and origin (#818).
pub const AnyEndpoint = union(enum) {
    socket: SocketEndpoint,
    encrypted: EncryptedEndpoint,
    upstream_tls: UpstreamTlsEndpoint,

    pub fn fd(self: AnyEndpoint) std.posix.fd_t {
        return switch (self) {
            inline else => |e| e.fd(),
        };
    }

    pub fn begin(self: AnyEndpoint) void {
        switch (self) {
            .socket => |e| e.begin(),
            else => {},
        }
    }

    pub fn read(self: AnyEndpoint, buf: []u8) Error!?usize {
        return switch (self) {
            inline else => |e| e.read(buf),
        };
    }

    pub fn write(self: AnyEndpoint, bytes: []const u8) Error!usize {
        return switch (self) {
            inline else => |e| e.write(bytes),
        };
    }

    pub fn flush(self: AnyEndpoint) Error!void {
        return switch (self) {
            inline else => |e| e.flush(),
        };
    }

    pub fn pendingOutput(self: AnyEndpoint) bool {
        return switch (self) {
            inline else => |e| e.pendingOutput(),
        };
    }

    pub fn bufferedInput(self: AnyEndpoint) bool {
        return switch (self) {
            inline else => |e| e.bufferedInput(),
        };
    }

    pub fn yielded(self: AnyEndpoint) bool {
        return switch (self) {
            inline else => |e| e.yielded(),
        };
    }
};

pub fn setNonBlocking(fd: std.posix.fd_t) void {
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

const StepResult = union(enum) {
    progressed: struct { moved: bool, yielded: bool },
    failed: Side,
};

/// Move bytes `src` -> `dst` until neither can make progress. Returns whether
/// anything moved and whether a TLS endpoint stopped on its drive budget
/// (sampled after each call, since the next call clears it), or which side
/// failed.
fn step(dir: *Direction, src: anytype, src_side: Side, dst: anytype, dst_side: Side, reading: bool) StepResult {
    var progressed = false;
    var yielded = false;
    var moves: usize = 0;
    while (moves < max_moves_per_step) : (moves += 1) {
        if (dir.pending.len > 0) {
            const n = dst.write(dir.pending) catch return .{ .failed = dst_side };
            if (dst.yielded()) yielded = true;
            if (n == 0) break;
            dir.pending = dir.pending[n..];
            dir.delivered += n;
            progressed = true;
            continue;
        }
        if (!reading or dir.eof) break;
        const read = src.read(dir.buf) catch return .{ .failed = src_side };
        if (src.yielded()) yielded = true;
        const n = read orelse break;
        progressed = true;
        if (n == 0) {
            dir.eof = true;
            break;
        }
        dir.pending = dir.buf[0..n];
    }
    dst.flush() catch return .{ .failed = dst_side };
    if (dst.yielded()) yielded = true;
    return .{ .progressed = .{ .moved = progressed, .yielded = yielded } };
}

fn minDeadline(a: ?u64, b: ?u64) ?u64 {
    if (a == null) return b;
    if (b == null) return a;
    return @min(a.?, b.?);
}

/// What one endpoint's socket must be watched for.
pub const Interest = struct {
    in: bool = false,
    out: bool = false,

    pub fn any(self: Interest) bool {
        return self.in or self.out;
    }
};

/// Where a live tunnel is parked until something can move.
pub const Wait = struct {
    client: Interest,
    upstream: Interest,
    /// Monotonic ms at which the tunnel must be advanced even if neither
    /// socket is ready; null when no timer is armed.
    deadline_ms: ?u64,
    /// Work is already possible (buffered TLS plaintext, or the per-advance
    /// budget ran out): advance again without waiting.
    ready_now: bool = false,
};

pub const Progress = union(enum) {
    wait: Wait,
    closed: CloseReason,
};

/// Rounds of both-direction work one `advance` does before yielding, so a
/// reactor that owns many tunnels serves them all fairly.
const max_rounds_per_advance = 4;

/// The tunnel relay as a resumable state machine (#818). `advance` moves
/// whatever can move without blocking, checks every timer, and says either
/// why the tunnel ended or what it is waiting for. `relay` drives one from a
/// dedicated thread; `tunnel_reactor` drives many from a few threads. Both
/// share the same buffering, backpressure and close rules.
pub fn Relay(comptime Client: type, comptime Upstream: type) type {
    return struct {
        const Self = @This();

        client: Client,
        upstream: Upstream,
        c2u: Direction,
        u2c: Direction,
        opts: Options,
        started: u64,
        last_activity: u64,
        lifetime_deadline: ?u64,
        shutdown_deadline: ?u64 = null,
        reload_deadline: ?u64 = null,
        /// Set once a side has closed: the other direction's already-read
        /// bytes get a bounded flush, and nothing more is read from either
        /// side.
        closing: ?CloseReason = null,
        closing_deadline: ?u64 = null,
        /// A side whose socket reported hang-up while the relay was not
        /// reading it is left out of the next wait (it would wake it
        /// forever) and read again once its direction has room.
        client_hup: bool = false,
        upstream_hup: bool = false,
        result: ?CloseReason = null,

        /// `initial_to_upstream` / `initial_to_client` are bytes already read
        /// past the handshake on either hop; they are delivered first and
        /// need not live in the direction buffers.
        pub fn init(
            client: Client,
            upstream: Upstream,
            client_to_upstream_buf: []u8,
            upstream_to_client_buf: []u8,
            initial_to_upstream: []const u8,
            initial_to_client: []const u8,
            opts: Options,
        ) Self {
            beginEndpoint(client);
            beginEndpoint(upstream);
            const started = event_loop.monotonicMs();
            return .{
                .client = client,
                .upstream = upstream,
                .c2u = .{ .buf = client_to_upstream_buf, .pending = initial_to_upstream },
                .u2c = .{ .buf = upstream_to_client_buf, .pending = initial_to_client },
                .opts = opts,
                .started = started,
                .last_activity = started,
                .lifetime_deadline = if (opts.max_lifetime_ms > 0) started + opts.max_lifetime_ms else null,
            };
        }

        /// Record what `poll` reported for each socket since the last wait.
        pub fn observe(self: *Self, client_revents: i16, upstream_revents: i16) void {
            if (hungUpEvents(client_revents)) self.client_hup = true;
            if (hungUpEvents(upstream_revents)) self.upstream_hup = true;
        }

        /// Move bytes and check timers without blocking. Once it returns
        /// `.closed` the tunnel is over and `advance` must not be called
        /// again.
        pub fn advance(self: *Self) Progress {
            std.debug.assert(self.result == null);
            var rounds: usize = 0;
            while (true) {
                const reading = self.closing == null;
                const c2u_step = step(&self.c2u, self.client, .client, self.upstream, .upstream, reading);
                const u2c_step = step(&self.u2c, self.upstream, .upstream, self.client, .client, reading);
                var progressed = false;
                // A TLS endpoint stopped on its drive budget: more work may
                // be waiting in the record layer, not on the socket.
                var yielded = false;
                switch (c2u_step) {
                    .failed => |side| return self.finish(if (side == .client) .client_error else .upstream_error),
                    .progressed => |p| {
                        progressed = progressed or p.moved;
                        yielded = yielded or p.yielded;
                    },
                }
                switch (u2c_step) {
                    .failed => |side| return self.finish(if (side == .client) .client_error else .upstream_error),
                    .progressed => |p| {
                        progressed = progressed or p.moved;
                        yielded = yielded or p.yielded;
                    },
                }

                const now = event_loop.monotonicMs();
                if (progressed) {
                    self.last_activity = now;
                    self.client_hup = false;
                    self.upstream_hup = false;
                }
                if (self.closing == null) {
                    if (self.c2u.eof) {
                        self.closing = .client;
                    } else if (self.u2c.eof) {
                        self.closing = .upstream;
                    }
                    if (self.closing != null) self.closing_deadline = now + self.opts.close_flush_timeout_ms;
                }
                const flushed = self.c2u.pending.len == 0 and self.u2c.pending.len == 0 and
                    !self.client.pendingOutput() and !self.upstream.pendingOutput();
                if (self.closing) |why| {
                    if (flushed or now >= self.closing_deadline.?) return self.finish(why);
                }
                if (self.opts.idle_timeout_ms > 0 and now -| self.last_activity >= self.opts.idle_timeout_ms) return self.finish(.idle);
                if (self.lifetime_deadline) |at| if (now >= at) return self.finish(.lifetime);
                if (self.shutdown_deadline == null and self.opts.shutdown_requested()) self.shutdown_deadline = now + self.opts.drain_timeout_ms;
                if (self.reload_deadline == null) if (self.opts.reload_drain) |drain| {
                    const superseded_at = drain.superseded_at_ms.load(.acquire);
                    if (superseded_at != 0) self.reload_deadline = superseded_at + drain.timeout_ms;
                };
                // Shutdown and reload drains are independent; whichever
                // deadline is earlier ends the tunnel.
                if (earliestDue(now, self.shutdown_deadline, self.reload_deadline)) |why| return self.finish(why);

                const wants_client_in = reading and !self.c2u.eof and self.c2u.pending.len == 0;
                const wants_upstream_in = reading and !self.u2c.eof and self.u2c.pending.len == 0;
                const buffered = (wants_client_in and self.client.bufferedInput()) or
                    (wants_upstream_in and self.upstream.bufferedInput());
                if (progressed or buffered or yielded) {
                    rounds += 1;
                    if (rounds < max_rounds_per_advance) continue;
                }

                var deadline: ?u64 = if (self.opts.poll_interval_ms > 0) now + self.opts.poll_interval_ms else null;
                if (self.opts.idle_timeout_ms > 0) deadline = minDeadline(deadline, self.last_activity + self.opts.idle_timeout_ms);
                deadline = minDeadline(deadline, minDeadline(self.lifetime_deadline, minDeadline(self.shutdown_deadline, minDeadline(self.reload_deadline, self.closing_deadline))));
                return .{ .wait = .{
                    .client = .{
                        .in = wants_client_in and !self.client_hup,
                        .out = self.u2c.pending.len > 0 or self.client.pendingOutput(),
                    },
                    .upstream = .{
                        .in = wants_upstream_in and !self.upstream_hup,
                        .out = self.c2u.pending.len > 0 or self.upstream.pendingOutput(),
                    },
                    .deadline_ms = deadline,
                    .ready_now = progressed or buffered or yielded,
                } };
            }
        }

        fn finish(self: *Self, reason: CloseReason) Progress {
            self.result = reason;
            return .{ .closed = reason };
        }

        pub fn stats(self: *const Self) Stats {
            return .{
                .client_to_upstream_bytes = self.c2u.delivered,
                .upstream_to_client_bytes = self.u2c.delivered,
                .duration_ms = event_loop.monotonicMs() -| self.started,
                .close_reason = self.result orelse .shutdown,
            };
        }
    };
}

/// Relay bytes between `client` and `upstream` on the calling thread until
/// the tunnel closes. Never returns an error: every way a tunnel can end is
/// a `CloseReason`.
pub fn relay(
    client: anytype,
    upstream: anytype,
    client_to_upstream_buf: []u8,
    upstream_to_client_buf: []u8,
    initial_to_upstream: []const u8,
    initial_to_client: []const u8,
    opts: Options,
) Stats {
    var state = Relay(@TypeOf(client), @TypeOf(upstream)).init(client, upstream, client_to_upstream_buf, upstream_to_client_buf, initial_to_upstream, initial_to_client, opts);
    while (true) {
        const wait = switch (state.advance()) {
            .closed => break,
            .wait => |wait| wait,
        };
        if (wait.ready_now) continue;
        var fds = [2]std.posix.pollfd{
            pollEntry(client.fd(), wait.client),
            pollEntry(upstream.fd(), wait.upstream),
        };
        const now = event_loop.monotonicMs();
        const timeout: i32 = if (wait.deadline_ms) |at|
            @intCast(@min(at -| now, @as(u64, std.math.maxInt(i32))))
        else
            -1;
        _ = std.posix.poll(&fds, timeout) catch {};
        state.observe(fds[0].revents, fds[1].revents);
    }
    return state.stats();
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

pub fn pollEntry(fd: std.posix.fd_t, interest: Interest) std.posix.pollfd {
    var events: i16 = 0;
    if (interest.in) events |= std.posix.POLL.IN;
    if (interest.out) events |= std.posix.POLL.OUT;
    // A negative fd is ignored by poll, so a side the relay is not waiting on
    // cannot wake it with a hang-up.
    return .{ .fd = if (events == 0) -1 else fd, .events = events, .revents = 0 };
}

/// Hang-up or error reported without readable data: the next read on that
/// side decides what it means, but polling it again would spin.
fn hungUpEvents(revents: i16) bool {
    const bad = std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL;
    return (revents & bad) != 0 and (revents & std.posix.POLL.IN) == 0;
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
