//! Dedicated, bounded, challenge-only HTTP-01 listener (#881, design
//! docs/ACME_AUTOMATIC_HTTPS.md §8.0).
//!
//! Isolated from the main gateway's accept path and worker pool on purpose:
//! it serves exactly `GET`/`HEAD /.well-known/acme-challenge/<token>` for a
//! managed host, from the shared `ChallengeStore` (#877), and fails closed
//! (`404`/`421`) for everything else. There is no application routing,
//! proxying, auth, or rewrite behind this listener, so none of those paths
//! can be reached through it, and a flood against it cannot consume the main
//! listener's worker budget (its own small bounded pool, §8.0).

const std = @import("std");
const compat = @import("zig_compat");
const challenge_store = @import("acme_challenge_store.zig");
const request_mod = @import("request.zig");
const response_mod = @import("response.zig");
const status_mod = @import("status.zig");

pub const ChallengeStore = challenge_store.ChallengeStore;
pub const matchManagedHost = challenge_store.matchManagedHost;

/// Caps and deadlines from design §8.0. `max_head_bytes` sizes a fixed
/// per-connection stack buffer, so it is a compile-time constant, not an
/// operator- or test-tunable option; `max_connections` and the deadlines are
/// tunable via `Options` so tests can exercise the same logic on a much
/// shorter clock.
pub const max_head_bytes: usize = 8 * 1024;
pub const default_max_connections: usize = 64;
pub const default_head_read_deadline_ms: u32 = 5_000;
pub const default_total_deadline_ms: u32 = 10_000;

pub const challenge_prefix = "/.well-known/acme-challenge/";

pub const Options = struct {
    /// Already-canonical-lowercase managed hostnames (`acme/names.zig`'s
    /// output shape); borrowed for the listener's lifetime.
    managed_hosts: []const []const u8,
    /// Borrowed; must outlive the listener.
    store: *ChallengeStore,
    max_connections: usize = default_max_connections,
    head_read_deadline_ms: u32 = default_head_read_deadline_ms,
    total_deadline_ms: u32 = default_total_deadline_ms,
};

/// Bounded, isolated HTTP-01 challenge listener. Caller owns storage with a
/// stable address for the listener's lifetime (`start` spawns a thread that
/// borrows `self`); the conventional shape is a `var` declared immediately
/// before `start` is called, matching `http.tunnel_reactor.Reactor`.
pub const Listener = struct {
    allocator: std.mem.Allocator,
    server: std.Io.net.Server,
    listen_fd: std.posix.fd_t,
    managed_hosts: []const []const u8,
    store: *ChallengeStore,
    max_connections: usize,
    head_read_deadline_ms: u32,
    total_deadline_ms: u32,
    stopping: std.atomic.Value(bool) = .init(false),
    active: std.atomic.Value(usize) = .init(0),
    accept_thread: ?std.Thread = null,

    /// Binds `host:port` -- before privilege drop/chroot, per §8.0 and §9.3 --
    /// and starts the dedicated accept loop. A bind failure is returned
    /// as-is so the caller can fail startup deterministically, naming the
    /// address; nothing is left running on this path (`errdefer` closes the
    /// listening socket).
    pub fn start(self: *Listener, allocator: std.mem.Allocator, host: []const u8, listen_port: u16, options: Options) !void {
        const address = try std.Io.net.IpAddress.parse(host, listen_port);
        var server = try address.listen(compat.io(), .{ .reuse_address = true });
        errdefer server.deinit(compat.io());
        const fd = server.socket.handle;
        try setNonBlocking(fd);

        self.* = .{
            .allocator = allocator,
            .server = server,
            .listen_fd = fd,
            .managed_hosts = options.managed_hosts,
            .store = options.store,
            .max_connections = @max(options.max_connections, 1),
            .head_read_deadline_ms = options.head_read_deadline_ms,
            .total_deadline_ms = options.total_deadline_ms,
        };
        self.accept_thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
    }

    /// Stops accepting, joins the accept thread, and waits for in-flight
    /// connections to settle. Every handler enforces its own
    /// `total_deadline_ms` budget, so this is bounded even if a peer never
    /// sends another byte -- it never blocks indefinitely. Safe to call at
    /// most once; idempotent no-op if `start` never ran or already failed.
    pub fn deinit(self: *Listener) void {
        self.stopping.store(true, .release);
        if (self.accept_thread) |t| t.join();
        self.accept_thread = null;

        const settle_deadline_ms = compat.milliTimestamp() + @as(i64, self.total_deadline_ms) + 1_000;
        while (self.active.load(.acquire) > 0 and compat.milliTimestamp() < settle_deadline_ms) {
            compat.sleepNs(10 * std.time.ns_per_ms);
        }
        self.server.deinit(compat.io());
        self.* = undefined;
    }

    /// Current in-flight connection count (test/observability only).
    pub fn activeConnections(self: *const Listener) usize {
        return self.active.load(.acquire);
    }

    pub fn port(self: *const Listener) u16 {
        return self.server.socket.address.getPort();
    }

    fn tryAdmit(self: *Listener) bool {
        while (true) {
            const cur = self.active.load(.monotonic);
            if (cur >= self.max_connections) return false;
            if (self.active.cmpxchgWeak(cur, cur + 1, .monotonic, .monotonic) == null) return true;
        }
    }

    fn release(self: *Listener) void {
        _ = self.active.fetchSub(1, .release);
    }

    fn acceptLoop(self: *Listener) void {
        var pfd = [_]std.posix.pollfd{.{ .fd = self.listen_fd, .events = std.posix.POLL.IN, .revents = 0 }};
        while (!self.stopping.load(.acquire)) {
            // 250 ms so shutdown is noticed promptly without a busy loop,
            // matching the main listener's shard accept loop
            // (`gateway_accept.zig`).
            const ready = std.posix.poll(&pfd, 250) catch continue;
            if (ready == 0) continue;
            if ((pfd[0].revents & std.posix.POLL.IN) == 0) continue;

            while (!self.stopping.load(.acquire)) {
                const client_fd = std.c.accept(self.listen_fd, null, null);
                if (client_fd < 0) {
                    const e = std.posix.errno(client_fd);
                    if (e == .AGAIN) break;
                    if (e == .CONNABORTED) continue;
                    break;
                }
                _ = std.c.fcntl(client_fd, std.c.F.SETFD, @as(c_int, 1)); // FD_CLOEXEC

                // Excess connections are accepted off the kernel backlog and
                // immediately closed rather than left pending or queued
                // behind the main listener's worker pool (§8.0): a flood here
                // can never exceed this listener's own small bounded pool.
                if (self.stopping.load(.acquire) or !self.tryAdmit()) {
                    _ = std.c.close(client_fd);
                    continue;
                }
                const handle = std.Thread.spawn(.{}, handleConnection, .{ self, client_fd }) catch {
                    _ = std.c.close(client_fd);
                    self.release();
                    continue;
                };
                handle.detach();
            }
        }
    }

    fn handleConnection(self: *Listener, fd: std.posix.fd_t) void {
        defer {
            _ = std.c.close(fd);
            self.release();
        }
        const started_ms = compat.milliTimestamp();
        compat.setSocketTimeoutsMs(fd, self.head_read_deadline_ms, self.head_read_deadline_ms);
        const stream = compat.NetStream{ .handle = fd, .inner = null };

        var buf: [max_head_bytes]u8 = undefined;
        var len: usize = 0;
        var head_len: ?usize = null;
        while (len < buf.len) {
            const n = stream.read(buf[len..]) catch break;
            if (n == 0) break;
            len += n;
            if (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n")) |idx| {
                head_len = idx + 4;
                break;
            }
            if (self.elapsedMs(started_ms) >= self.total_deadline_ms) break;
        }
        // No complete head within the byte cap, the read deadline, or the
        // total deadline: close without a response rather than acting on a
        // request that was never fully read (slowloris / oversize head).
        const end = head_len orelse return;

        const remaining = self.remainingMs(started_ms);
        if (remaining == 0) return;
        compat.setSocketTimeoutsMs(fd, remaining, remaining);

        const parsed = request_mod.Request.parseHead(self.allocator, buf[0..end], 0) catch {
            respondStatus(self.allocator, stream, .bad_request);
            return;
        };
        var req = parsed.request;
        defer req.deinit();
        self.dispatch(&req, stream);
    }

    fn elapsedMs(self: *const Listener, started_ms: i64) u32 {
        const now = compat.milliTimestamp();
        if (now <= started_ms) return 0;
        const diff = now - started_ms;
        if (diff >= self.total_deadline_ms) return self.total_deadline_ms;
        return @intCast(diff);
    }

    fn remainingMs(self: *const Listener, started_ms: i64) u32 {
        return self.total_deadline_ms - self.elapsedMs(started_ms);
    }

    fn dispatch(self: *Listener, req: *const request_mod.Request, stream: compat.NetStream) void {
        // Only GET/HEAD ever reach a response; everything else -- including
        // every other method -- is a plain 404, never a routed verb error,
        // since there is no application route behind this listener (§8.0).
        if (req.method != .GET and req.method != .HEAD) {
            respondStatus(self.allocator, stream, .not_found);
            return;
        }
        if (hasBodyOrUpgrade(req)) {
            respondStatus(self.allocator, stream, .bad_request);
            return;
        }
        if (!std.mem.startsWith(u8, req.uri.path, challenge_prefix)) {
            respondStatus(self.allocator, stream, .not_found);
            return;
        }
        const token = req.uri.path[challenge_prefix.len..];
        if (token.len == 0 or std.mem.indexOfAny(u8, token, "/?#") != null) {
            respondStatus(self.allocator, stream, .not_found);
            return;
        }
        const managed_host = matchManagedHost(self.managed_hosts, req.host()) orelse {
            respondStatus(self.allocator, stream, .misdirected_request);
            return;
        };
        const key_auth = self.store.getCopy(self.allocator, compat.unixTimestamp(), managed_host, token) orelse {
            respondStatus(self.allocator, stream, .not_found);
            return;
        };
        defer self.allocator.free(key_auth);
        respondChallenge(self.allocator, stream, key_auth, req.method == .HEAD);
    }
};

/// No request bodies, upgrades, or chunked transfer are ever read by this
/// listener (§8.0 limits); a request that claims one is a protocol violation
/// here, not a miss.
fn hasBodyOrUpgrade(req: *const request_mod.Request) bool {
    if (req.contentLength()) |content_length| {
        if (content_length > 0) return true;
    }
    if (req.headers.get("transfer-encoding") != null) return true;
    if (req.headers.get("upgrade") != null) return true;
    return false;
}

fn respondStatus(allocator: std.mem.Allocator, stream: compat.NetStream, code: status_mod.Status) void {
    var resp = response_mod.Response.init(allocator);
    defer resp.deinit();
    _ = resp.setStatus(code).setConnection(false);
    resp.write(stream.writer()) catch {};
}

fn respondChallenge(allocator: std.mem.Allocator, stream: compat.NetStream, key_authorization: []const u8, head_only: bool) void {
    var resp = response_mod.Response.init(allocator);
    defer resp.deinit();
    _ = resp.setStatus(.ok)
        .setBody(key_authorization)
        .setHeader("Content-Type", "application/octet-stream")
        .setHeader("Cache-Control", "no-store")
        .setConnection(false);
    if (head_only) {
        resp.writeHead(stream.writer()) catch {};
    } else {
        resp.write(stream.writer()) catch {};
    }
}

fn setNonBlocking(fd: std.posix.fd_t) !void {
    const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (flags < 0) return error.Unexpected;
    const nonblock: c_int = @intCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
    if (std.c.fcntl(fd, std.c.F.SETFL, flags | nonblock) < 0) return error.Unexpected;
}

const testing = std.testing;

fn sendAndRecv(allocator: std.mem.Allocator, listener_port: u16, request_bytes: []const u8, out: *std.ArrayList(u8)) !void {
    const stream = try compat.tcpConnectToHost(allocator, "127.0.0.1", listener_port);
    defer stream.close();
    try stream.writeAll(request_bytes);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = stream.read(&buf) catch break;
        if (n == 0) break;
        try out.appendSlice(allocator, buf[0..n]);
    }
}

test "Listener serves a managed host's live challenge for GET and HEAD, fails closed otherwise (#881)" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    // The listener's own clock is the real wall clock (`compat.unixTimestamp`),
    // not an injectable fake, so the TTL here must be relative to it.
    const now = compat.unixTimestamp();
    try store.put(now, "a.example.com", "abcdefghijklmnop", "abcdefghijklmnop.thumb", now + 600);

    const managed = [_][]const u8{"a.example.com"};
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{ .managed_hosts = &managed, .store = &store });
    defer listener.deinit();
    const p = listener.port();

    // GET: 200, correct content type, cache-control, and body bytes.
    {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try sendAndRecv(allocator, p, "GET /.well-known/acme-challenge/abcdefghijklmnop HTTP/1.1\r\nHost: a.example.com\r\n\r\n", &out);
        try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 200"));
        // Header names are rendered lowercase (`Headers.append` normalizes
        // case on insert); HTTP header names are case-insensitive.
        try testing.expect(std.mem.indexOf(u8, out.items, "content-type: application/octet-stream\r\n") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "cache-control: no-store\r\n") != null);
        try testing.expect(std.mem.indexOf(u8, out.items, "connection: close\r\n") != null);
        try testing.expect(std.mem.endsWith(u8, out.items, "abcdefghijklmnop.thumb"));
    }

    // HEAD: 200, same headers, no body.
    {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try sendAndRecv(allocator, p, "HEAD /.well-known/acme-challenge/abcdefghijklmnop HTTP/1.1\r\nHost: a.example.com\r\n\r\n", &out);
        try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 200"));
        try testing.expect(std.mem.endsWith(u8, out.items, "\r\n\r\n"));
    }

    // Unmanaged host: 421, even though the token exists for a different host.
    {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try sendAndRecv(allocator, p, "GET /.well-known/acme-challenge/abcdefghijklmnop HTTP/1.1\r\nHost: evil.example.com\r\n\r\n", &out);
        try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 421"));
    }

    // Managed host, unknown token: 404.
    {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try sendAndRecv(allocator, p, "GET /.well-known/acme-challenge/zzzzzzzzzzzzzzzz HTTP/1.1\r\nHost: a.example.com\r\n\r\n", &out);
        try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 404"));
    }

    // Any other path: 404, never reaches any routing.
    {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try sendAndRecv(allocator, p, "GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n", &out);
        try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 404"));
    }

    // POST is never served, even on an otherwise-valid challenge request.
    {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try sendAndRecv(allocator, p, "POST /.well-known/acme-challenge/abcdefghijklmnop HTTP/1.1\r\nHost: a.example.com\r\n\r\n", &out);
        try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 404"));
    }

    // A request body is rejected outright.
    {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try sendAndRecv(allocator, p, "GET /.well-known/acme-challenge/abcdefghijklmnop HTTP/1.1\r\nHost: a.example.com\r\nContent-Length: 4\r\n\r\nabcd", &out);
        try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 400"));
    }
}

test "Listener admission cap accepts up to the configured bound and rejects beyond it" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const managed = [_][]const u8{"a.example.com"};
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{ .managed_hosts = &managed, .store = &store, .max_connections = 2 });
    defer listener.deinit();

    try testing.expect(listener.tryAdmit());
    try testing.expect(listener.tryAdmit());
    try testing.expect(!listener.tryAdmit());
    listener.release();
    try testing.expect(listener.tryAdmit());
    listener.release();
    listener.release();
    try testing.expectEqual(@as(usize, 0), listener.activeConnections());
}

test "Listener closes a connection that never completes its head within the total deadline" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const managed = [_][]const u8{"a.example.com"};
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{
        .managed_hosts = &managed,
        .store = &store,
        .head_read_deadline_ms = 2_000,
        .total_deadline_ms = 150,
    });
    defer listener.deinit();

    const stream = try compat.tcpConnectToHost(allocator, "127.0.0.1", listener.port());
    defer stream.close();
    // An incomplete head (no terminating blank line) that is never finished.
    try stream.writeAll("GET /.well-known/acme-challenge/abcdefghijklmnop HTTP/1.1\r\n");

    // The listener closes the socket once its total deadline elapses, which
    // a subsequent read observes as EOF, well within a generous bound.
    const deadline_ms = compat.milliTimestamp() + 5_000;
    var closed = false;
    while (compat.milliTimestamp() < deadline_ms) {
        var buf: [16]u8 = undefined;
        const n = stream.read(&buf) catch {
            closed = true;
            break;
        };
        if (n == 0) {
            closed = true;
            break;
        }
        compat.sleepNs(10 * std.time.ns_per_ms);
    }
    try testing.expect(closed);
}

test "Listener.start fails deterministically on an invalid listen address" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const managed = [_][]const u8{"a.example.com"};
    var first: Listener = undefined;
    try first.start(allocator, "127.0.0.1", 0, .{ .managed_hosts = &managed, .store = &store });
    defer first.deinit();

    var second: Listener = undefined;
    try testing.expectError(error.ParseFailed, second.start(allocator, "not-an-ip-address", 0, .{ .managed_hosts = &managed, .store = &store }));

    // The first listener is unaffected by the second's failed bind attempt.
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try sendAndRecv(allocator, first.port(), "GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n", &out);
    try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 404"));
}
