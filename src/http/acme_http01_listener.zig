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

/// Injectable "has this managed host ever been published" query (#884,
/// design §8.3), the same ctx/fn-pointer seam `orders.Cancel`/`orders.Waiter`
/// use. Kept this narrow (rather than importing the top-level ACME
/// activation module directly) so this listener stays a leaf `http/`
/// module with no dependency on it -- `edge_gateway.zig`, which already
/// depends on both, supplies the real implementation.
pub const PublishedCheck = struct {
    ctx: ?*anyopaque = null,
    isPublishedFn: *const fn (ctx: ?*anyopaque, host: []const u8) bool = alwaysUnpublished,

    fn alwaysUnpublished(_: ?*anyopaque, _: []const u8) bool {
        return false;
    }

    pub fn isPublished(self: PublishedCheck, host: []const u8) bool {
        return self.isPublishedFn(self.ctx, host);
    }
};

/// Design §8.3: optional HTTP->HTTPS redirect, served by this listener for
/// managed hosts only, only once published (never for a first-run
/// deployment whose certificate does not exist yet).
pub const HttpsRedirectOptions = struct {
    published: PublishedCheck,
    /// The main listener's HTTPS port; the redirect target rewrites the
    /// validated Host's port to this one.
    https_port: u16,
};

pub const Options = struct {
    /// Already-canonical-lowercase managed hostnames (`acme/names.zig`'s
    /// output shape); borrowed for the listener's lifetime.
    managed_hosts: []const []const u8,
    /// Borrowed; must outlive the listener.
    store: *ChallengeStore,
    max_connections: usize = default_max_connections,
    /// §8.0's "per-IP accept cap shared with existing accept limits":
    /// typically `cfg.max_connections_per_ip`. `0` disables the per-IP
    /// cap (global `max_connections` still applies), matching the main
    /// listener's own zero-means-unlimited convention.
    max_connections_per_ip: u32 = 0,
    head_read_deadline_ms: u32 = default_head_read_deadline_ms,
    total_deadline_ms: u32 = default_total_deadline_ms,
    /// `null` (the default): never redirect, exactly today's behavior.
    https_redirect: ?HttpsRedirectOptions = null,
};

/// A peer's raw address bytes, family-tagged, for per-IP admission counting.
/// Deliberately not a formatted string: this listener never allocates on
/// the accept path, so a fixed-size bounded table of these is scanned
/// in-place instead (#897 review).
const PeerKey = struct {
    family: u32,
    bytes: [16]u8 = @splat(0),

    fn eql(a: PeerKey, b: PeerKey) bool {
        return a.family == b.family and std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    fn fromSockAddr(address: *const std.c.sockaddr.storage) ?PeerKey {
        return switch (address.family) {
            std.posix.AF.INET => blk: {
                const sin: *const std.c.sockaddr.in = @ptrCast(address);
                var key = PeerKey{ .family = @intCast(address.family) };
                @memcpy(key.bytes[0..4], @as(*const [4]u8, @ptrCast(&sin.addr)));
                break :blk key;
            },
            std.posix.AF.INET6 => blk: {
                const sin6: *const std.c.sockaddr.in6 = @ptrCast(address);
                break :blk .{ .family = @intCast(address.family), .bytes = sin6.addr };
            },
            else => null,
        };
    }
};

/// One admitted connection's bookkeeping. Every field is guarded by the
/// owning `Listener.slots_mutex`; `thread` is only ever written by the
/// (single) accept-loop thread and only ever joined by `reapFinishedLocked`
/// (called from `tryAdmit`, on the accept-loop thread, and unconditionally
/// from `deinit`), so a handler thread never touches another slot's memory
/// (#897 review).
const ConnSlot = struct {
    in_use: bool = false,
    finished: bool = false,
    fd: std.posix.fd_t = -1,
    peer: ?PeerKey = null,
    thread: ?std.Thread = null,
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
    max_connections_per_ip: u32,
    head_read_deadline_ms: u32,
    total_deadline_ms: u32,
    https_redirect: ?HttpsRedirectOptions,
    stopping: std.atomic.Value(bool) = .init(false),
    slots_mutex: compat.Mutex = .{},
    slots: [default_max_connections]ConnSlot = @splat(.{}),
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
            // §8.0's ceiling is an advertised invariant, not an
            // operator-overridable one: silently clamp an override above it
            // rather than admitting more than the design's bounded pool
            // promise (#897 review).
            .max_connections = std.math.clamp(options.max_connections, 1, default_max_connections),
            .max_connections_per_ip = options.max_connections_per_ip,
            .head_read_deadline_ms = options.head_read_deadline_ms,
            .total_deadline_ms = options.total_deadline_ms,
            .https_redirect = options.https_redirect,
        };
        self.accept_thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
    }

    /// Stops accepting, joins the accept thread, forcibly unblocks any
    /// in-flight connection's socket I/O, and -- unconditionally, not just
    /// up to some deadline -- joins every handler thread before tearing
    /// down `self.server` and `self.* = undefined`. #897 review: a handler
    /// that outlived a bounded wait here would go on to dereference `self`
    /// and its borrowed `store`/`allocator` after they were freed; this
    /// listener's own absolute head/total deadlines (`handleConnection`)
    /// plus the forced `shutdown()` below keep that join bounded in
    /// practice, but correctness here does not depend on that bound. Safe
    /// to call at most once; idempotent no-op if `start` never ran or
    /// already failed.
    pub fn deinit(self: *Listener) void {
        self.stopping.store(true, .release);
        if (self.accept_thread) |t| t.join();
        self.accept_thread = null;

        self.slots_mutex.lock();
        for (&self.slots) |*slot| {
            // `fd >= 0` (not just `!slot.finished`): `finishConnection` sets
            // `fd = -1` in the same critical section it closes it in, so a
            // slot can only be `in_use` with a live `fd` here if its handler
            // has not yet reached that section (#897 review).
            if (slot.in_use and slot.fd >= 0) {
                _ = std.c.shutdown(slot.fd, std.c.SHUT.RDWR);
            }
        }
        self.slots_mutex.unlock();

        while (true) {
            self.slots_mutex.lock();
            self.reapFinishedLocked();
            const remaining = self.activeCountLocked();
            self.slots_mutex.unlock();
            if (remaining == 0) break;
            compat.sleepNs(5 * std.time.ns_per_ms);
        }
        self.server.deinit(compat.io());
        self.* = undefined;
    }

    /// Current in-flight connection count (test/observability only).
    pub fn activeConnections(self: *Listener) usize {
        self.slots_mutex.lock();
        defer self.slots_mutex.unlock();
        self.reapFinishedLocked();
        return self.activeCountLocked();
    }

    pub fn port(self: *const Listener) u16 {
        return self.server.socket.address.getPort();
    }

    fn activeCountLocked(self: *const Listener) usize {
        var count: usize = 0;
        for (self.slots) |slot| {
            if (slot.in_use) count += 1;
        }
        return count;
    }

    /// Joins and frees every slot whose handler has already signaled
    /// completion (`finishConnection`). By the time `finished` is visible
    /// here (under `slots_mutex`, the same lock `finishConnection` sets it
    /// under), the handler thread has no remaining work -- `finished` is
    /// the last thing it does before returning -- so `join()` here never
    /// blocks meaningfully. Caller holds `slots_mutex`.
    fn reapFinishedLocked(self: *Listener) void {
        for (&self.slots) |*slot| {
            // `thread != null` matters here: `acceptLoop` reserves a slot
            // (via `tryAdmit`) and spawns its handler *before* it can store
            // the resulting `std.Thread` back into `slots[idx].thread`. A
            // handler fast enough to finish inside that window would set
            // `finished = true` while `thread` is still `null`; resetting
            // the slot right then would both leak that not-yet-stored
            // handle and free the slot for a *different* connection just
            // before `acceptLoop` overwrites its `thread` field with the
            // stale handle. Leaving `finished`-but-not-yet-handled slots
            // alone for one more pass (they are still `in_use`, so still
            // correctly counted) avoids that.
            if (slot.in_use and slot.finished and slot.thread != null) {
                slot.thread.?.join();
                slot.* = .{};
            }
        }
    }

    /// Admits `fd` from `peer` if both the global and (when configured)
    /// per-IP caps allow it, reserving a slot and returning its index.
    /// Caller spawns the handler and must store the resulting `std.Thread`
    /// into `slots[idx].thread` (see `acceptLoop`); nothing joins a
    /// not-yet-stored `null` thread handle, since a reserved slot only
    /// becomes reapable once `finished` is set, and `finishConnection`
    /// runs strictly after the accept loop has stored the handle.
    fn tryAdmit(self: *Listener, peer: ?PeerKey, fd: std.posix.fd_t) ?usize {
        self.slots_mutex.lock();
        defer self.slots_mutex.unlock();
        self.reapFinishedLocked();

        if (self.activeCountLocked() >= self.max_connections) return null;
        if (self.max_connections_per_ip > 0) {
            if (peer) |p| {
                var count_for_peer: u32 = 0;
                for (self.slots) |slot| {
                    if (slot.in_use) {
                        if (slot.peer) |sp| {
                            if (PeerKey.eql(sp, p)) count_for_peer += 1;
                        }
                    }
                }
                if (count_for_peer >= self.max_connections_per_ip) return null;
            }
        }
        for (&self.slots, 0..) |*slot, i| {
            if (!slot.in_use) {
                slot.* = .{ .in_use = true, .fd = fd, .peer = peer };
                return i;
            }
        }
        return null; // unreachable: active < max_connections <= slots.len
    }

    /// Releases a slot reserved by `tryAdmit` that never got a handler
    /// thread (spawn failure); unlike `finishConnection`, there is no
    /// thread to join.
    fn releaseUnstarted(self: *Listener, idx: usize) void {
        self.slots_mutex.lock();
        defer self.slots_mutex.unlock();
        self.slots[idx] = .{};
    }

    /// Called by a handler thread as the very last thing it does
    /// (`handleConnection`'s `defer`) to close its own fd and mark its slot
    /// reapable, both under `slots_mutex`. #897 review: closing `fd` before
    /// taking this lock raced `deinit`'s shutdown scan, which also runs
    /// under `slots_mutex` and decides whether to `shutdown()` a slot's `fd`
    /// from whether it is `in_use && !finished`. If the handler closed `fd`
    /// first and the OS reused that descriptor number for an unrelated
    /// connection before the handler reacquired the lock, `deinit` could
    /// `shutdown()` that unrelated connection instead. Closing and marking
    /// `finished` in one critical section -- with `deinit` only ever acting
    /// on a slot's `fd` while holding the same lock -- makes that
    /// interleaving impossible: either this closes first and `deinit` never
    /// observes `fd` again, or `deinit` shuts it down first and this close
    /// races harmlessly with that shutdown on the same, still-owned fd.
    fn finishConnection(self: *Listener, idx: usize, fd: std.posix.fd_t) void {
        self.slots_mutex.lock();
        defer self.slots_mutex.unlock();
        _ = std.c.close(fd);
        self.slots[idx].fd = -1;
        self.slots[idx].finished = true;
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
                var peer_storage: std.c.sockaddr.storage = undefined;
                var peer_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);
                const client_fd = std.c.accept(self.listen_fd, @ptrCast(&peer_storage), &peer_len);
                if (client_fd < 0) {
                    const e = std.posix.errno(client_fd);
                    if (e == .AGAIN) break;
                    if (e == .CONNABORTED) continue;
                    break;
                }
                _ = std.c.fcntl(client_fd, std.c.F.SETFD, @as(c_int, 1)); // FD_CLOEXEC
                // #897 review: some platforms hand an accepted connection
                // the listening socket's O_NONBLOCK; force it back to
                // blocking so `handleConnection`'s SO_RCVTIMEO-bounded reads
                // actually wait instead of returning WouldBlock instantly.
                setBlocking(client_fd) catch {
                    _ = std.c.close(client_fd);
                    continue;
                };

                // Excess connections are accepted off the kernel backlog and
                // immediately closed rather than left pending or queued
                // behind the main listener's worker pool (§8.0): a flood here
                // can never exceed this listener's own small bounded pool,
                // nor its per-IP share of it.
                const peer = PeerKey.fromSockAddr(&peer_storage);
                const slot_idx = if (self.stopping.load(.acquire)) null else self.tryAdmit(peer, client_fd);
                const idx = slot_idx orelse {
                    _ = std.c.close(client_fd);
                    continue;
                };
                const handle = std.Thread.spawn(.{}, handleConnection, .{ self, client_fd, idx }) catch {
                    _ = std.c.close(client_fd);
                    self.releaseUnstarted(idx);
                    continue;
                };
                // Joinable, not detached (#897 review): `reapFinishedLocked`
                // (from `tryAdmit` opportunistically, and unconditionally
                // from `deinit`) is the only code that joins this handle,
                // and only after the handler has signaled completion.
                self.slots_mutex.lock();
                self.slots[idx].thread = handle;
                self.slots_mutex.unlock();
            }
        }
    }

    fn handleConnection(self: *Listener, fd: std.posix.fd_t, slot_idx: usize) void {
        // #897 review: deadlines are derived from the monotonic clock
        // (`std.Io.Clock.awake`, not `std.Io.Clock.real`), so a wall-clock
        // adjustment (NTP correction, manual set, VM clock jump) during a
        // connection's lifetime can neither extend nor shorten its stated
        // 5 s head / 10 s total budget.
        const started_ns = compat.monotonicNanoTimestamp();
        defer self.finishConnection(slot_idx, fd);
        const head_deadline_ns = started_ns + @as(i128, self.head_read_deadline_ms) * std.time.ns_per_ms;
        const total_deadline_ns = started_ns + @as(i128, self.total_deadline_ms) * std.time.ns_per_ms;
        const stream = compat.NetStream{ .handle = fd, .inner = null };

        var buf: [max_head_bytes]u8 = undefined;
        var len: usize = 0;
        var head_len: ?usize = null;
        while (len < buf.len) {
            // #897 review: recompute and reapply the *absolute* remaining
            // budget before every blocking read, rather than resetting a
            // fixed per-read timeout. A peer that trickles one byte just
            // before each read's timeout would otherwise keep resetting an
            // unbounded clock; here each read's own timeout shrinks toward
            // zero as either the head or total deadline approaches, so the
            // loop cannot run past `min(head_deadline, total_deadline)` no
            // matter how the peer paces its bytes.
            const now_ns = compat.monotonicNanoTimestamp();
            const deadline_ns = @min(head_deadline_ns, total_deadline_ns);
            if (now_ns >= deadline_ns) break;
            const remaining_ms = msFromRemainingNs(deadline_ns - now_ns);
            // Fail closed, not silently unbounded, if the timeout can't be
            // set (a `{0,0}` SO_RCVTIMEO means "block forever" on every
            // supported platform, so skipping a failed setup here would be
            // exactly the bug this rewrite fixes).
            compat.setSocketTimeoutsMsChecked(fd, remaining_ms, remaining_ms) catch return;
            const n = stream.read(buf[len..]) catch break;
            if (n == 0) break;
            len += n;
            if (std.mem.indexOf(u8, buf[0..len], "\r\n\r\n")) |idx| {
                head_len = idx + 4;
                break;
            }
        }
        // No complete head within the byte cap, the read deadline, or the
        // total deadline: close without a response rather than acting on a
        // request that was never fully read (slowloris / oversize head).
        const end = head_len orelse return;

        const now_after_head_ns = compat.monotonicNanoTimestamp();
        if (!completedHeadWithinDeadlines(now_after_head_ns, head_deadline_ns, total_deadline_ns)) return;
        const parsed = request_mod.Request.parseHead(self.allocator, buf[0..end], 0) catch {
            respondStatus(self.allocator, fd, total_deadline_ns, .bad_request);
            return;
        };
        var req = parsed.request;
        defer req.deinit();
        self.dispatch(&req, fd, total_deadline_ns);
    }

    fn dispatch(self: *Listener, req: *const request_mod.Request, fd: std.posix.fd_t, total_deadline_ns: i128) void {
        // Only GET/HEAD ever reach a response; everything else -- including
        // every other method -- is a plain 404, never a routed verb error,
        // since there is no application route behind this listener (§8.0).
        if (req.method != .GET and req.method != .HEAD) {
            respondStatus(self.allocator, fd, total_deadline_ns, .not_found);
            return;
        }
        if (hasBodyOrUpgrade(req)) {
            respondStatus(self.allocator, fd, total_deadline_ns, .bad_request);
            return;
        }
        if (!std.mem.startsWith(u8, req.uri.path, challenge_prefix)) {
            // Design §8.3: the challenge path itself is exempt from the
            // redirect (handled above, before this branch is ever
            // reached); only non-challenge requests for an already-managed,
            // already-published host are redirected.
            if (self.https_redirect) |redirect| {
                if (matchManagedHost(self.managed_hosts, req.host())) |managed_host| {
                    if (redirect.published.isPublished(managed_host)) {
                        respondRedirect(self.allocator, fd, total_deadline_ns, managed_host, redirect.https_port, req.uri.path, req.uri.query);
                        return;
                    }
                }
            }
            respondStatus(self.allocator, fd, total_deadline_ns, .not_found);
            return;
        }
        const token = req.uri.path[challenge_prefix.len..];
        if (token.len == 0 or std.mem.indexOfAny(u8, token, "/?#") != null) {
            respondStatus(self.allocator, fd, total_deadline_ns, .not_found);
            return;
        }
        const managed_host = matchManagedHost(self.managed_hosts, req.host()) orelse {
            respondStatus(self.allocator, fd, total_deadline_ns, .misdirected_request);
            return;
        };
        const key_auth = self.store.getCopy(self.allocator, compat.unixTimestamp(), managed_host, token) orelse {
            respondStatus(self.allocator, fd, total_deadline_ns, .not_found);
            return;
        };
        defer self.allocator.free(key_auth);
        respondChallenge(self.allocator, fd, total_deadline_ns, key_auth, req.method == .HEAD);
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

/// A request head that became complete after either absolute budget expired is
/// never dispatched. Keeping this comparison separate makes the post-read
/// check testable without relying on scheduler timing around a socket read.
fn completedHeadWithinDeadlines(now_ns: i128, head_deadline_ns: i128, total_deadline_ns: i128) bool {
    return now_ns < head_deadline_ns and now_ns < total_deadline_ns;
}

fn respondStatus(allocator: std.mem.Allocator, fd: std.posix.fd_t, total_deadline_ns: i128, code: status_mod.Status) void {
    var resp = response_mod.Response.init(allocator);
    defer resp.deinit();
    _ = resp.setStatus(code).setConnection(false);
    writeResponseBeforeDeadline(allocator, fd, total_deadline_ns, &resp, "");
}

/// Design §8.3: `host` is always the *canonical* `managed_hosts` entry the
/// caller already matched (`matchManagedHost`'s return value, never the raw
/// `Host` header), and `path`/`query` come from the already-parsed request
/// line, so none of these three can carry CRLF or otherwise inject into the
/// response. A `host`/`path`/`query` combination too long for `buf` fails
/// closed to a plain `404` rather than truncating a Location header.
fn respondRedirect(
    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    total_deadline_ns: i128,
    host: []const u8,
    https_port: u16,
    path: []const u8,
    query: ?[]const u8,
) void {
    var buf: [1536]u8 = undefined;
    const location = (if (https_port == 443)
        if (query) |q| std.fmt.bufPrint(&buf, "https://{s}{s}?{s}", .{ host, path, q }) else std.fmt.bufPrint(&buf, "https://{s}{s}", .{ host, path })
    else if (query) |q|
        std.fmt.bufPrint(&buf, "https://{s}:{d}{s}?{s}", .{ host, https_port, path, q })
    else
        std.fmt.bufPrint(&buf, "https://{s}:{d}{s}", .{ host, https_port, path })) catch {
        respondStatus(allocator, fd, total_deadline_ns, .not_found);
        return;
    };
    var resp = response_mod.Response.redirect(allocator, location, .permanent_redirect);
    defer resp.deinit();
    _ = resp.setConnection(false);
    writeResponseBeforeDeadline(allocator, fd, total_deadline_ns, &resp, "");
}

fn respondChallenge(allocator: std.mem.Allocator, fd: std.posix.fd_t, total_deadline_ns: i128, key_authorization: []const u8, head_only: bool) void {
    var resp = response_mod.Response.init(allocator);
    defer resp.deinit();
    _ = resp.setStatus(.ok)
        .setBody(key_authorization)
        .setHeader("Content-Type", "application/octet-stream")
        .setHeader("Cache-Control", "no-store")
        .setConnection(false);
    writeResponseBeforeDeadline(allocator, fd, total_deadline_ns, &resp, if (head_only) "" else key_authorization);
}

/// Emits the listener's deliberately small response before its original total
/// deadline. A successful vectored send may be short, so remaining header and
/// body bytes are retried with a freshly reduced socket timeout; the absolute
/// monotonic deadline itself is never reset.
fn writeResponseBeforeDeadline(
    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    total_deadline_ns: i128,
    resp: *response_mod.Response,
    body: []const u8,
) void {
    const header = resp.buildHeaderBytes(allocator) catch return;
    defer allocator.free(header);

    const Context = struct {
        fd: std.posix.fd_t,

        fn clock(_: @This()) i128 {
            return compat.monotonicNanoTimestamp();
        }

        fn setTimeouts(self: @This(), timeout_ms: u32) !void {
            try compat.setSocketTimeoutsMsChecked(self.fd, timeout_ms, timeout_ms);
        }

        fn send(self: @This(), fragments: []const std.posix.iovec_const) !usize {
            return compat.sendSocketIovNoSignal(self.fd, fragments);
        }
    };
    writeResponseFragmentsBeforeDeadline(Context, .{ .fd = fd }, total_deadline_ns, header, body, Context.clock, Context.setTimeouts, Context.send);
}

fn writeResponseFragmentsBeforeDeadline(
    comptime Context: type,
    context: Context,
    total_deadline_ns: i128,
    header: []const u8,
    body: []const u8,
    clock_fn: *const fn (Context) i128,
    set_timeouts_fn: *const fn (Context, u32) anyerror!void,
    send_fn: *const fn (Context, []const std.posix.iovec_const) anyerror!usize,
) void {
    var header_offset: usize = 0;
    var body_offset: usize = 0;
    while (header_offset < header.len or body_offset < body.len) {
        const now_ns = clock_fn(context);
        if (now_ns >= total_deadline_ns) return;
        const remaining_ms = msFromRemainingNs(total_deadline_ns - now_ns);
        set_timeouts_fn(context, remaining_ms) catch return;

        var fragments: [2]std.posix.iovec_const = undefined;
        var fragment_count: usize = 0;
        if (header_offset < header.len) {
            fragments[fragment_count] = .{ .base = header[header_offset..].ptr, .len = header.len - header_offset };
            fragment_count += 1;
        }
        if (body_offset < body.len) {
            fragments[fragment_count] = .{ .base = body[body_offset..].ptr, .len = body.len - body_offset };
            fragment_count += 1;
        }
        const written = send_fn(context, fragments[0..fragment_count]) catch |err| switch (err) {
            error.Interrupted => continue,
            error.BrokenPipe, error.ConnectionReset => return,
            else => return,
        };
        if (written == 0) return;

        const pending = header.len - header_offset + body.len - body_offset;
        if (written > pending) return;
        var remaining = written;
        if (header_offset < header.len) {
            const header_remaining = header.len - header_offset;
            const consumed = @min(remaining, header_remaining);
            header_offset += consumed;
            remaining -= consumed;
        }
        body_offset += remaining;
    }
}

/// Converts a positive remaining-nanosecond budget (caller already checked
/// `> 0`) into whole milliseconds for `SO_RCVTIMEO`/`SO_SNDTIMEO`, rounding
/// any nonzero sub-millisecond remainder up rather than down to zero: a
/// zero timeout means "block forever" on every supported platform, which
/// would turn an almost-expired deadline into no deadline at all.
fn msFromRemainingNs(remaining_ns: i128) u32 {
    const ms = @divFloor(remaining_ns, std.time.ns_per_ms);
    const rem = @mod(remaining_ns, std.time.ns_per_ms);
    const rounded = ms + @as(i128, @intFromBool(rem != 0));
    return @intCast(@max(rounded, 1));
}

fn setNonBlocking(fd: std.posix.fd_t) !void {
    const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (flags < 0) return error.Unexpected;
    const nonblock: c_int = @intCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
    if (std.c.fcntl(fd, std.c.F.SETFL, flags | nonblock) < 0) return error.Unexpected;
}

/// #897 review: on at least one supported platform, a connection `accept()`-ed
/// off this listener's non-blocking listening socket inherits `O_NONBLOCK`
/// on the new fd too. `handleConnection`'s absolute-deadline reads depend on
/// `SO_RCVTIMEO` actually blocking -- on a non-blocking socket it is inert
/// and every read returns `WouldBlock` immediately regardless of the
/// timeout, which would silently turn every deadline into "close instantly"
/// instead of "close at the deadline". Force each accepted connection back
/// to blocking mode before handing it to a handler.
fn setBlocking(fd: std.posix.fd_t) !void {
    const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (flags < 0) return error.Unexpected;
    const nonblock: c_int = @intCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
    if (std.c.fcntl(fd, std.c.F.SETFL, flags & ~nonblock) < 0) return error.Unexpected;
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

const ScriptedResponseWriter = struct {
    allocator: std.mem.Allocator,
    clock_values: []const i128,
    write_sizes: []const usize,
    clock_index: usize = 0,
    write_index: usize = 0,
    output: std.ArrayList(u8) = .empty,
    timeout_values: std.ArrayList(u32) = .empty,

    fn deinit(self: *ScriptedResponseWriter) void {
        self.output.deinit(self.allocator);
        self.timeout_values.deinit(self.allocator);
    }

    fn clock(self: *ScriptedResponseWriter) i128 {
        const index = @min(self.clock_index, self.clock_values.len - 1);
        self.clock_index += 1;
        return self.clock_values[index];
    }

    fn setTimeouts(self: *ScriptedResponseWriter, timeout_ms: u32) !void {
        try self.timeout_values.append(self.allocator, timeout_ms);
    }

    fn send(self: *ScriptedResponseWriter, fragments: []const std.posix.iovec_const) !usize {
        if (self.write_index >= self.write_sizes.len) return error.TestUnexpectedSend;
        const written = self.write_sizes[self.write_index];
        self.write_index += 1;

        var remaining = written;
        for (fragments) |fragment| {
            if (remaining == 0) break;
            const taken = @min(remaining, fragment.len);
            try self.output.appendSlice(self.allocator, fragment.base[0..taken]);
            remaining -= taken;
        }
        if (remaining != 0) return error.TestSendBeyondInput;
        return written;
    }
};

test "a request head completed just after its head deadline is not dispatched" {
    const head_deadline_ns = 5 * std.time.ns_per_s;
    const total_deadline_ns = 10 * std.time.ns_per_s;
    try testing.expect(!completedHeadWithinDeadlines(head_deadline_ns + 1, head_deadline_ns, total_deadline_ns));
    try testing.expect(completedHeadWithinDeadlines(head_deadline_ns - 1, head_deadline_ns, total_deadline_ns));
}

test "HTTP-01 response retries short vectored writes without resetting its deadline" {
    const deadline_ns = 100 * std.time.ns_per_ms;
    const clock_values = [_]i128{ 0, 0, 0 };
    const write_sizes = [_]usize{ 2, 4, 2 };
    var writer = ScriptedResponseWriter{
        .allocator = testing.allocator,
        .clock_values = &clock_values,
        .write_sizes = &write_sizes,
    };
    defer writer.deinit();

    // The second write crosses the header/body boundary; a retry that starts
    // over, or that drops the suffix, would not reproduce this exact stream.
    writeResponseFragmentsBeforeDeadline(
        *ScriptedResponseWriter,
        &writer,
        deadline_ns,
        "HEAD",
        "BODY",
        ScriptedResponseWriter.clock,
        ScriptedResponseWriter.setTimeouts,
        ScriptedResponseWriter.send,
    );

    try testing.expectEqualStrings("HEADBODY", writer.output.items);
    try testing.expectEqual(@as(usize, 3), writer.timeout_values.items.len);
    for (writer.timeout_values.items) |timeout_ms| try testing.expectEqual(@as(u32, 100), timeout_ms);
}

test "HTTP-01 response stops after a short write when its original deadline expires" {
    const deadline_ns = 100 * std.time.ns_per_ms;
    const clock_values = [_]i128{ 0, deadline_ns };
    const write_sizes = [_]usize{2};
    var writer = ScriptedResponseWriter{
        .allocator = testing.allocator,
        .clock_values = &clock_values,
        .write_sizes = &write_sizes,
    };
    defer writer.deinit();

    writeResponseFragmentsBeforeDeadline(
        *ScriptedResponseWriter,
        &writer,
        deadline_ns,
        "HEAD",
        "BODY",
        ScriptedResponseWriter.clock,
        ScriptedResponseWriter.setTimeouts,
        ScriptedResponseWriter.send,
    );

    try testing.expectEqualStrings("HE", writer.output.items);
    try testing.expectEqual(@as(usize, 1), writer.timeout_values.items.len);
    try testing.expectEqual(@as(usize, 1), writer.write_index);
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

const TestPublished = struct {
    hosts: []const []const u8,

    fn isPublished(ctx: ?*anyopaque, host: []const u8) bool {
        const self: *const TestPublished = @ptrCast(@alignCast(ctx.?));
        for (self.hosts) |h| {
            if (std.mem.eql(u8, h, host)) return true;
        }
        return false;
    }

    fn check(self: *const TestPublished) PublishedCheck {
        return .{ .ctx = @constCast(self), .isPublishedFn = isPublished };
    }
};

test "Listener's optional https_redirect (#884, design §8.3) redirects only a managed, published host, never the challenge path or an unmanaged/unpublished host" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const now = compat.unixTimestamp();
    try store.put(now, "a.example.com", "abcdefghijklmnop", "abcdefghijklmnop.thumb", now + 600);

    const managed = [_][]const u8{ "a.example.com", "b.example.com" };
    const published = TestPublished{ .hosts = &.{"a.example.com"} };
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{
        .managed_hosts = &managed,
        .store = &store,
        .https_redirect = .{ .published = published.check(), .https_port = 443 },
    });
    defer listener.deinit();
    const p = listener.port();

    // Published managed host, non-challenge path with a query string: 308
    // to the HTTPS equivalent, port omitted because it is the default 443.
    {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try sendAndRecv(allocator, p, "GET /some/path?q=1 HTTP/1.1\r\nHost: a.example.com\r\n\r\n", &out);
        try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 308"));
        try testing.expect(std.mem.indexOf(u8, out.items, "location: https://a.example.com/some/path?q=1\r\n") != null);
    }

    // The challenge path itself is exempt even for a published host: it
    // still answers the challenge, not a redirect.
    {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try sendAndRecv(allocator, p, "GET /.well-known/acme-challenge/abcdefghijklmnop HTTP/1.1\r\nHost: a.example.com\r\n\r\n", &out);
        try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 200"));
    }

    // Managed but not yet published: no redirect, no door to a certificate
    // that does not exist yet (design §8.3).
    {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try sendAndRecv(allocator, p, "GET / HTTP/1.1\r\nHost: b.example.com\r\n\r\n", &out);
        try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 404"));
    }

    // Unmanaged host: never redirected regardless of `https_redirect`.
    {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(allocator);
        try sendAndRecv(allocator, p, "GET / HTTP/1.1\r\nHost: evil.example.com\r\n\r\n", &out);
        try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 404"));
    }
}

test "Listener's https_redirect includes a non-default HTTPS port in the Location" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const managed = [_][]const u8{"a.example.com"};
    const published = TestPublished{ .hosts = &managed };
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{
        .managed_hosts = &managed,
        .store = &store,
        .https_redirect = .{ .published = published.check(), .https_port = 8443 },
    });
    defer listener.deinit();

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    try sendAndRecv(allocator, listener.port(), "GET /x HTTP/1.1\r\nHost: a.example.com\r\n\r\n", &out);
    try testing.expect(std.mem.startsWith(u8, out.items, "HTTP/1.1 308"));
    try testing.expect(std.mem.indexOf(u8, out.items, "location: https://a.example.com:8443/x\r\n") != null);
}

test "Listener admission cap accepts up to the configured bound and rejects beyond it" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const managed = [_][]const u8{"a.example.com"};
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{ .managed_hosts = &managed, .store = &store, .max_connections = 2 });
    defer listener.deinit();

    const slot1 = listener.tryAdmit(null, -1) orelse return error.TestUnexpectedResult;
    const slot2 = listener.tryAdmit(null, -1) orelse return error.TestUnexpectedResult;
    try testing.expect(listener.tryAdmit(null, -1) == null);
    listener.releaseUnstarted(slot1);
    const slot3 = listener.tryAdmit(null, -1) orelse return error.TestUnexpectedResult;
    listener.releaseUnstarted(slot2);
    listener.releaseUnstarted(slot3);
    try testing.expectEqual(@as(usize, 0), listener.activeConnections());
}

test "Listener clamps an overridden max_connections to the §8.0 ceiling of 64 (#897 review)" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const managed = [_][]const u8{"a.example.com"};
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{ .managed_hosts = &managed, .store = &store, .max_connections = 1_000 });
    defer listener.deinit();
    try testing.expectEqual(default_max_connections, listener.max_connections);
}

test "Listener per-IP admission cap bounds one peer without starving a different peer (#897 review)" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const managed = [_][]const u8{"a.example.com"};
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{
        .managed_hosts = &managed,
        .store = &store,
        .max_connections = 4,
        .max_connections_per_ip = 2,
    });
    defer listener.deinit();

    const peer_a: PeerKey = .{ .family = std.posix.AF.INET, .bytes = [_]u8{ 10, 0, 0, 1 } ++ ([_]u8{0} ** 12) };
    const peer_b: PeerKey = .{ .family = std.posix.AF.INET, .bytes = [_]u8{ 10, 0, 0, 2 } ++ ([_]u8{0} ** 12) };

    const a1 = listener.tryAdmit(peer_a, -1) orelse return error.TestUnexpectedResult;
    const a2 = listener.tryAdmit(peer_a, -1) orelse return error.TestUnexpectedResult;
    // The global cap (4) still has room, but peer_a alone has already
    // saturated its own per-IP cap (2): a third connection from the same
    // address is rejected even though the listener as a whole is not full.
    try testing.expect(listener.tryAdmit(peer_a, -1) == null);
    // A different peer is unaffected by peer_a's per-IP saturation.
    const b1 = listener.tryAdmit(peer_b, -1) orelse return error.TestUnexpectedResult;

    listener.releaseUnstarted(a1);
    listener.releaseUnstarted(a2);
    listener.releaseUnstarted(b1);
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

fn trickleWriter(stream: compat.NetStream, count: usize, interval_ms: u64) void {
    var i: usize = 0;
    while (i < count) : (i += 1) {
        stream.writeAll("x") catch return;
        compat.sleepNs(interval_ms * std.time.ns_per_ms);
    }
}

test "Listener closes by the absolute head deadline even when the total deadline is looser (#897 review)" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const managed = [_][]const u8{"a.example.com"};
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{
        .managed_hosts = &managed,
        .store = &store,
        .head_read_deadline_ms = 120,
        .total_deadline_ms = 200,
    });
    defer listener.deinit();

    const stream = try compat.tcpConnectToHost(allocator, "127.0.0.1", listener.port());
    defer stream.close();

    const started_ms = compat.milliTimestamp();
    // One byte every 40 ms, never completing the head. Resetting a fixed
    // per-read timeout on every successful read would let this run to the
    // 200 ms total-deadline check instead (the bug this rewrite fixes);
    // the absolute 120 ms head deadline must close it well before that.
    const writer_thread = try std.Thread.spawn(.{}, trickleWriter, .{ stream, @as(usize, 10), @as(u64, 40) });
    defer writer_thread.join();

    var buf: [16]u8 = undefined;
    var closed = false;
    while (true) {
        const n = stream.read(&buf) catch {
            closed = true;
            break;
        };
        if (n == 0) {
            closed = true;
            break;
        }
    }
    const elapsed_ms = compat.milliTimestamp() - started_ms;
    try testing.expect(closed);
    try testing.expect(elapsed_ms < 180);
}

test "Listener closes by the absolute total deadline, not a stale fixed per-read timeout (#897 review)" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const managed = [_][]const u8{"a.example.com"};
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{
        .managed_hosts = &managed,
        .store = &store,
        .head_read_deadline_ms = 500,
        .total_deadline_ms = 150,
    });
    defer listener.deinit();

    const stream = try compat.tcpConnectToHost(allocator, "127.0.0.1", listener.port());
    defer stream.close();

    const started_ms = compat.milliTimestamp();
    // A partial header sent once, then silence. The old code set
    // SO_RCVTIMEO to the fixed 500 ms head-read deadline once and only
    // checked the 150 ms total deadline after a read *returned*; a read
    // that blocks until its own timeout never reaches that check, so the
    // stall would run the full 500 ms instead of closing at ~150 ms.
    try stream.writeAll("GET /.well-known/acme-challenge/abcdefghijklmnop HTTP/1.1\r\n");

    var buf: [16]u8 = undefined;
    var closed = false;
    while (true) {
        const n = stream.read(&buf) catch {
            closed = true;
            break;
        };
        if (n == 0) {
            closed = true;
            break;
        }
    }
    const elapsed_ms = compat.milliTimestamp() - started_ms;
    try testing.expect(closed);
    try testing.expect(elapsed_ms < 300);
}

test "Listener.deinit forcibly unblocks and joins an in-flight handler instead of freeing early (#897 review)" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const managed = [_][]const u8{"a.example.com"};
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{
        .managed_hosts = &managed,
        .store = &store,
        // A head-read deadline far longer than the total deadline: the old
        // code's fixed SO_RCVTIMEO used this value directly, so a stuck
        // handler's blocking read could still be waiting on it long after
        // `deinit`'s old bounded settle wait (total_deadline_ms + 1 s) gave
        // up and freed the listener out from under it. The 400 ms total
        // deadline (rather than something tighter) leaves comfortable
        // margin for the polling loop below to observe the connection
        // before the handler's own deadline reaps it on a slow CI host.
        .head_read_deadline_ms = 5_000,
        .total_deadline_ms = 400,
    });

    const stream = try compat.tcpConnectToHost(allocator, "127.0.0.1", listener.port());
    try stream.writeAll("GET /.well-known/acme-challenge/abcdefghijklmnop HTTP/1.1\r\n");

    var waited: usize = 0;
    while (listener.activeConnections() == 0 and waited < 2_000) : (waited += 1) {
        compat.sleepNs(1 * std.time.ns_per_ms);
    }
    try testing.expect(listener.activeConnections() > 0);

    // The regression check is `deinit` itself: it must not return (and
    // free `self`/`self.store`) until the handler has actually finished.
    // A crash, a hang past the stale 5 s timeout, or a use-after-free
    // under a sanitizer is the failure mode this guards against.
    const deinit_started_ms = compat.milliTimestamp();
    listener.deinit();
    const deinit_elapsed_ms = compat.milliTimestamp() - deinit_started_ms;
    stream.close();
    try testing.expect(deinit_elapsed_ms < 3_000);
}

test "finishConnection closes and invalidates a slot's fd atomically, so deinit's shutdown scan can never observe a reused descriptor (#897 review)" {
    const allocator = testing.allocator;
    var store = ChallengeStore.init(allocator);
    defer store.deinit();
    const managed = [_][]const u8{"a.example.com"};
    var listener: Listener = undefined;
    try listener.start(allocator, "127.0.0.1", 0, .{ .managed_hosts = &managed, .store = &store });
    defer listener.deinit();

    // A real, closeable fd (one end of an AF_UNIX socketpair, matching
    // this codebase's established pattern for synthesizing a test fd --
    // `std.posix.pipe` is not available on every platform Zig 0.16
    // supports) standing in for an accepted connection: `finishConnection`
    // must actually close it, not merely forget it, so the kernel is free
    // to reuse the descriptor number only *after* this slot can no longer
    // be mistaken for still owning it.
    var fds: [2]std.posix.fd_t = undefined;
    try testing.expectEqual(@as(c_int, 0), std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds));
    defer _ = std.c.close(fds[1]);
    const idx = listener.tryAdmit(null, fds[0]) orelse return error.TestUnexpectedResult;
    try testing.expect(listener.slots[idx].fd == fds[0]);

    listener.finishConnection(idx, fds[0]);

    // The old code closed `fd` *before* taking `slots_mutex`, leaving a
    // window where `deinit`'s shutdown scan (also gated on this same lock)
    // could see `in_use && !finished` and call `shutdown()` on a descriptor
    // number the kernel had already reassigned elsewhere. Asserting both
    // conditions together, read back under the lock, is exactly the state
    // `deinit`'s scan inspects.
    listener.slots_mutex.lock();
    const slot = listener.slots[idx];
    listener.slots_mutex.unlock();
    try testing.expect(slot.finished);
    try testing.expect(slot.fd < 0);

    // The fd was really closed by the OS (not merely forgotten by the
    // slot): `fcntl(F.GETFD)` on an already-closed descriptor fails with
    // EBADF. (Not a write-based probe: writing to a peer-closed socket can
    // raise SIGPIPE and kill the test process.)
    try testing.expectEqual(std.posix.E.BADF, std.posix.errno(std.c.fcntl(fds[0], std.c.F.GETFD, @as(c_int, 0))));

    listener.releaseUnstarted(idx);
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
