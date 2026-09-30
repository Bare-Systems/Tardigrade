//! Sharded reactor for established byte tunnels (#818).
//!
//! A worker thread runs a WebSocket handshake and admission, then hands the
//! established tunnel to this reactor and goes back to serving requests. A
//! fixed number of reactor threads (shards) each own many tunnels and drive
//! them with the same non-blocking `tunnel.Relay` state machine, sleeping in
//! one `poll()` over every socket they own. A tunnel therefore costs two
//! sockets and its two direction buffers, never a thread.
//!
//! Each shard wakes when a socket it owns is ready, when one of its tunnels'
//! own timers (idle, lifetime, close flush, shutdown/reload drain) is due,
//! when a tunnel is handed to it, or when `wakeAll` signals a hot reload or
//! shutdown. Idle tunnels without due timers cost nothing between wakeups.
//!
//! A tunnel is a `Job` embedded in a caller-owned object. The reactor only
//! calls its vtable; the owner decides what closing it releases.

const std = @import("std");
const compat = @import("zig_compat");
const builtin = @import("builtin");
const tunnel = @import("tunnel.zig");
const event_loop = @import("event_loop.zig");

pub const Job = struct {
    vtable: *const VTable,
    /// Reactor bookkeeping; initialize with `.{ .vtable = ... }` only.
    next_inbox: ?*Job = null,
    wait: tunnel.Wait = .{ .client = .{}, .upstream = .{}, .deadline_ms = null, .ready_now = true },
    revents: [2]i16 = .{ 0, 0 },

    pub const VTable = struct {
        /// The client and upstream sockets, in that order.
        fds: *const fn (*Job) [2]std.posix.fd_t,
        /// Record `poll` results since the last wait (see `Relay.observe`).
        observe: *const fn (*Job, client_revents: i16, upstream_revents: i16) void,
        /// Move bytes and check timers (see `Relay.advance`).
        advance: *const fn (*Job) tunnel.Progress,
        /// The tunnel is over: release everything it owns, including the
        /// `Job` itself. Called exactly once, on a reactor thread, after
        /// `advance` returned `.closed`, or by `submit`'s caller when the
        /// reactor refused it.
        finish: *const fn (*Job) void,
    };
};

pub const Options = struct {
    threads: u16,
    /// Polled at every wakeup so shutdown drains start even if `wakeAll` is
    /// never called; the fallback wakeup interval bounds how late.
    shutdown_requested: *const fn () bool,
    fallback_wakeup_ms: u32 = 250,
};

pub const ShardSnapshot = struct {
    tunnels: u32,
    wakeups_total: u64,
};

pub const Snapshot = struct {
    threads: u16,
    tunnels: u32,
    handoffs_total: u64,
    wakeups_total: u64,
    /// Most tunnels on any one shard (load skew).
    max_shard_tunnels: u32,
};

const Shard = struct {
    reactor: *Reactor,
    index: usize,
    thread: ?std.Thread = null,
    mutex: compat.Mutex = .{},
    /// Handed-off jobs not yet adopted by the shard thread (LIFO; order does
    /// not matter). Guarded by `mutex`.
    inbox: ?*Job = null,
    stopping: bool = false,
    wake_read: std.posix.fd_t,
    wake_write: std.posix.fd_t,
    /// Jobs owned (or about to be) by this shard; used to pick a shard.
    tunnels: std.atomic.Value(u32) = .init(0),
    wakeups_total: std.atomic.Value(u64) = .init(0),
    /// Set by `wakeAll`: advance every tunnel at the next wakeup.
    broadcast: std.atomic.Value(bool) = .init(false),

    fn wake(self: *Shard) void {
        const byte = [1]u8{1};
        // A full pipe already guarantees a wakeup.
        _ = std.c.write(self.wake_write, &byte, 1);
    }

    fn drainWake(self: *Shard) void {
        var buf: [64]u8 = undefined;
        while (std.c.read(self.wake_read, &buf, buf.len) > 0) {}
    }

    fn run(self: *Shard) void {
        const allocator = self.reactor.allocator;
        var jobs: std.ArrayList(*Job) = .empty;
        defer jobs.deinit(allocator);
        var pfds: std.ArrayList(std.posix.pollfd) = .empty;
        defer pfds.deinit(allocator);
        var seen_shutdown = false;

        while (true) {
            // Adopt handed-off tunnels.
            self.mutex.lock();
            var incoming = self.inbox;
            self.inbox = null;
            const stopping = self.stopping;
            self.mutex.unlock();
            while (incoming) |job| {
                incoming = job.next_inbox;
                job.next_inbox = null;
                job.wait = .{ .client = .{}, .upstream = .{}, .deadline_ms = null, .ready_now = true };
                jobs.append(allocator, job) catch {
                    // Out of memory for bookkeeping: the tunnel cannot be
                    // served, so end it as an error rather than leak it.
                    self.finishJob(job);
                };
            }
            if (stopping and jobs.items.len == 0) break;

            var advance_all = self.broadcast.swap(false, .acq_rel);
            if (!seen_shutdown and self.reactor.opts.shutdown_requested()) {
                seen_shutdown = true;
                advance_all = true;
            }

            // Advance every tunnel that has something to do.
            const now = event_loop.monotonicMs();
            var i: usize = 0;
            while (i < jobs.items.len) {
                const job = jobs.items[i];
                const due = if (job.wait.deadline_ms) |at| now >= at else false;
                const ready = advance_all or job.wait.ready_now or due or job.revents[0] != 0 or job.revents[1] != 0;
                if (ready) {
                    job.vtable.observe(job, job.revents[0], job.revents[1]);
                    job.revents = .{ 0, 0 };
                    switch (job.vtable.advance(job)) {
                        .wait => |wait| job.wait = wait,
                        .closed => {
                            _ = jobs.swapRemove(i);
                            self.finishJob(job);
                            continue;
                        },
                    }
                }
                i += 1;
            }
            // A stopping shard exits as soon as its last tunnel ends.
            if (stopping and jobs.items.len == 0) break;

            // Sleep until a socket, a timer, a handoff, or a broadcast.
            pfds.ensureTotalCapacity(allocator, 1 + 2 * jobs.items.len) catch {
                // Cannot wait on every socket; spin briefly instead of
                // sleeping blind, and retry the allocation next round.
                compat.sleepNs(std.time.ns_per_ms);
                continue;
            };
            pfds.clearRetainingCapacity();
            pfds.appendAssumeCapacity(.{ .fd = self.wake_read, .events = std.posix.POLL.IN, .revents = 0 });
            var deadline: u64 = now + self.reactor.opts.fallback_wakeup_ms;
            var ready_now = false;
            for (jobs.items) |job| {
                const fds = job.vtable.fds(job);
                pfds.appendAssumeCapacity(tunnel.pollEntry(fds[0], job.wait.client));
                pfds.appendAssumeCapacity(tunnel.pollEntry(fds[1], job.wait.upstream));
                if (job.wait.ready_now) ready_now = true;
                if (job.wait.deadline_ms) |at| deadline = @min(deadline, at);
            }
            const after = event_loop.monotonicMs();
            const timeout: i32 = if (ready_now) 0 else @intCast(@min(deadline -| after, @as(u64, std.math.maxInt(i32))));
            _ = std.posix.poll(pfds.items, timeout) catch {};
            _ = self.wakeups_total.fetchAdd(1, .monotonic);
            if (pfds.items[0].revents != 0) self.drainWake();
            for (jobs.items, 0..) |job, j| {
                job.revents = .{ pfds.items[1 + 2 * j].revents, pfds.items[2 + 2 * j].revents };
            }
        }
    }

    fn finishJob(self: *Shard, job: *Job) void {
        _ = self.tunnels.fetchSub(1, .acq_rel);
        job.vtable.finish(job);
    }
};

pub const Reactor = struct {
    allocator: std.mem.Allocator,
    opts: Options,
    shards: []Shard,
    handoffs_total: std.atomic.Value(u64) = .init(0),
    stopped: std.atomic.Value(bool) = .init(false),

    pub const SubmitError = error{ReactorStopped};

    /// Start `opts.threads` reactor threads. `self` must not move afterwards.
    pub fn start(self: *Reactor, allocator: std.mem.Allocator, opts: Options) !void {
        std.debug.assert(opts.threads > 0);
        self.* = .{ .allocator = allocator, .opts = opts, .shards = try allocator.alloc(Shard, opts.threads) };
        var made: usize = 0;
        errdefer {
            for (self.shards[0..made]) |*shard| {
                _ = std.c.close(shard.wake_read);
                _ = std.c.close(shard.wake_write);
            }
            allocator.free(self.shards);
        }
        for (self.shards, 0..) |*shard, index| {
            var fds: [2]std.c.fd_t = undefined;
            if (std.c.pipe(&fds) != 0) return error.ReactorWakePipeFailed;
            tunnel.setNonBlocking(fds[0]);
            tunnel.setNonBlocking(fds[1]);
            shard.* = .{ .reactor = self, .index = index, .wake_read = fds[0], .wake_write = fds[1] };
            made += 1;
        }
        var spawned: usize = 0;
        errdefer {
            for (self.shards[0..spawned]) |*shard| {
                shard.mutex.lock();
                shard.stopping = true;
                shard.mutex.unlock();
                shard.wake();
                shard.thread.?.join();
            }
        }
        for (self.shards) |*shard| {
            shard.thread = try std.Thread.spawn(.{}, Shard.run, .{shard});
            spawned += 1;
        }
    }

    /// Hand `job` to the least-loaded shard. On `error.ReactorStopped` the
    /// caller still owns the job and must end it itself.
    pub fn submit(self: *Reactor, job: *Job) SubmitError!void {
        var best = &self.shards[0];
        var best_load = best.tunnels.load(.acquire);
        for (self.shards[1..]) |*shard| {
            const load = shard.tunnels.load(.acquire);
            if (load < best_load) {
                best = shard;
                best_load = load;
            }
        }
        best.mutex.lock();
        if (best.stopping) {
            best.mutex.unlock();
            return error.ReactorStopped;
        }
        job.next_inbox = best.inbox;
        best.inbox = job;
        _ = best.tunnels.fetchAdd(1, .acq_rel);
        best.mutex.unlock();
        _ = self.handoffs_total.fetchAdd(1, .monotonic);
        best.wake();
    }

    /// Make every shard advance all of its tunnels now, so they observe a
    /// hot reload's supersession stamp or a shutdown request immediately
    /// instead of at their next socket event or timer.
    pub fn wakeAll(self: *Reactor) void {
        for (self.shards) |*shard| {
            shard.broadcast.store(true, .release);
            shard.wake();
        }
    }

    /// Refuse new tunnels and wait for every shard to finish the ones it
    /// owns. Tunnels end on their own terms (shutdown drain, idle, a side
    /// closing), so this returns within the shutdown drain window once
    /// shutdown has been requested.
    pub fn stopAndJoin(self: *Reactor) void {
        if (self.stopped.swap(true, .acq_rel)) return;
        for (self.shards) |*shard| {
            shard.mutex.lock();
            shard.stopping = true;
            shard.mutex.unlock();
            shard.broadcast.store(true, .release);
            shard.wake();
        }
        for (self.shards) |*shard| {
            if (shard.thread) |thread| thread.join();
            shard.thread = null;
        }
    }

    /// Stop (see `stopAndJoin`) and free the shards.
    pub fn deinit(self: *Reactor) void {
        self.stopAndJoin();
        for (self.shards) |*shard| {
            _ = std.c.close(shard.wake_read);
            _ = std.c.close(shard.wake_write);
        }
        self.allocator.free(self.shards);
        self.* = undefined;
    }

    pub fn snapshot(self: *Reactor) Snapshot {
        var out = Snapshot{
            .threads = @intCast(self.shards.len),
            .tunnels = 0,
            .handoffs_total = self.handoffs_total.load(.monotonic),
            .wakeups_total = 0,
            .max_shard_tunnels = 0,
        };
        for (self.shards) |*shard| {
            const n = shard.tunnels.load(.acquire);
            out.tunnels += n;
            out.max_shard_tunnels = @max(out.max_shard_tunnels, n);
            out.wakeups_total += shard.wakeups_total.load(.monotonic);
        }
        return out;
    }

    pub fn shardSnapshot(self: *Reactor, index: usize) ShardSnapshot {
        const shard = &self.shards[index];
        return .{ .tunnels = shard.tunnels.load(.acquire), .wakeups_total = shard.wakeups_total.load(.monotonic) };
    }
};

// Tests

const SocketRelay = tunnel.Relay(tunnel.SocketEndpoint, tunnel.SocketEndpoint);

const TestJob = struct {
    job: Job = .{ .vtable = &vtable },
    relay: SocketRelay,
    c2u: [64]u8 = undefined,
    u2c: [64]u8 = undefined,
    /// Tunnel-side socket ends; the test keeps the peer ends.
    client_fd: std.posix.fd_t,
    upstream_fd: std.posix.fd_t,
    done: *std.atomic.Value(u32),
    last_reason: *std.atomic.Value(u8),
    freed: *std.atomic.Value(u32),

    const vtable = Job.VTable{ .fds = fds, .observe = observe, .advance = advance, .finish = finish };

    fn create(client_fd: std.posix.fd_t, upstream_fd: std.posix.fd_t, opts: tunnel.Options, done: *std.atomic.Value(u32), last_reason: *std.atomic.Value(u8), freed: *std.atomic.Value(u32)) !*TestJob {
        const self = try std.testing.allocator.create(TestJob);
        self.* = .{
            .relay = undefined,
            .client_fd = client_fd,
            .upstream_fd = upstream_fd,
            .done = done,
            .last_reason = last_reason,
            .freed = freed,
        };
        self.relay = SocketRelay.init(.{ .handle = client_fd }, .{ .handle = upstream_fd }, &self.c2u, &self.u2c, "", "", opts);
        return self;
    }

    fn from(job: *Job) *TestJob {
        return @fieldParentPtr("job", job);
    }

    fn fds(job: *Job) [2]std.posix.fd_t {
        const self = from(job);
        return .{ self.client_fd, self.upstream_fd };
    }

    fn observe(job: *Job, c: i16, u: i16) void {
        from(job).relay.observe(c, u);
    }

    fn advance(job: *Job) tunnel.Progress {
        return from(job).relay.advance();
    }

    fn finish(job: *Job) void {
        const self = from(job);
        self.last_reason.store(@intFromEnum(self.relay.stats().close_reason), .release);
        _ = std.c.close(self.client_fd);
        _ = std.c.close(self.upstream_fd);
        _ = self.freed.fetchAdd(1, .acq_rel);
        const done = self.done;
        std.testing.allocator.destroy(self);
        _ = done.fetchAdd(1, .acq_rel);
    }
};

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

fn waitFor(counter: *std.atomic.Value(u32), want: u32, timeout_ms: u64) !void {
    const until = event_loop.monotonicMs() + timeout_ms;
    while (counter.load(.acquire) < want) {
        if (event_loop.monotonicMs() > until) return error.Timeout;
        compat.sleepNs(2 * std.time.ns_per_ms);
    }
}

fn neverShutdown() bool {
    return false;
}

var test_shutdown_flag = std.atomic.Value(bool).init(false);

fn testShutdown() bool {
    return test_shutdown_flag.load(.acquire);
}

/// Raise the soft descriptor limit toward `want` and return what is usable.
fn raiseFdLimit(want: u64) u64 {
    var lim = std.posix.getrlimit(std.posix.rlimit_resource.NOFILE) catch return 256;
    if (lim.cur < want) {
        var raised = lim;
        raised.cur = @min(want, lim.max);
        if (std.posix.setrlimit(std.posix.rlimit_resource.NOFILE, raised)) |_| lim = raised else |_| {}
    }
    return lim.cur;
}

const PeerPair = struct { client_peer: std.posix.fd_t, upstream_peer: std.posix.fd_t };

fn submitTestTunnel(reactor: *Reactor, opts: tunnel.Options, done: *std.atomic.Value(u32), reason: *std.atomic.Value(u8), freed: *std.atomic.Value(u32)) !PeerPair {
    const c = try testSocketPair();
    const u = try testSocketPair();
    const job = try TestJob.create(c[0], u[0], opts, done, reason, freed);
    try reactor.submit(&job.job);
    return .{ .client_peer = c[1], .upstream_peer = u[1] };
}

test "reactor relays many tunnels on a fixed number of threads (#818)" {
    // Scale to the descriptors this process may open: each tunnel uses four
    // (two socketpairs), and the thread count stays at two regardless.
    const limit = raiseFdLimit(8192);
    const budget = if (limit > 128) (limit - 64) / 4 else 0;
    const count: usize = @intCast(@min(budget, 1500));
    try std.testing.expect(count >= 32);

    var reactor: Reactor = undefined;
    try reactor.start(std.testing.allocator, .{ .threads = 2, .shutdown_requested = neverShutdown });
    defer reactor.deinit();

    var done = std.atomic.Value(u32).init(0);
    var reason = std.atomic.Value(u8).init(0);
    var freed = std.atomic.Value(u32).init(0);
    const peers = try std.testing.allocator.alloc(PeerPair, count);
    defer std.testing.allocator.free(peers);
    for (peers) |*p| p.* = try submitTestTunnel(&reactor, .{ .idle_timeout_ms = 30_000, .shutdown_requested = neverShutdown, .poll_interval_ms = 0 }, &done, &reason, &freed);

    const snap = reactor.snapshot();
    try std.testing.expectEqual(@as(u16, 2), snap.threads);
    try std.testing.expectEqual(@as(u32, @intCast(count)), snap.tunnels);
    try std.testing.expectEqual(@as(u64, count), snap.handoffs_total);
    // Least-loaded placement keeps the shards balanced.
    try std.testing.expect(snap.max_shard_tunnels <= count / 2 + 1);

    // Every tunnel carries traffic both ways while all of them stay open.
    var stride: usize = 0;
    while (stride < count) : (stride += 7) {
        const p = peers[stride];
        try testWriteAll(p.client_peer, "ping");
        var got: [4]u8 = undefined;
        try testReadExact(p.upstream_peer, &got);
        try std.testing.expectEqualStrings("ping", &got);
        try testWriteAll(p.upstream_peer, "pong");
        try testReadExact(p.client_peer, &got);
        try std.testing.expectEqualStrings("pong", &got);
    }
    try std.testing.expectEqual(@as(u32, 0), done.load(.acquire));

    // Closing each client ends its tunnel and releases everything it owns.
    for (peers) |p| {
        _ = std.c.close(p.client_peer);
    }
    try waitFor(&done, @intCast(count), 10_000);
    for (peers) |p| {
        _ = std.c.close(p.upstream_peer);
    }
    try std.testing.expectEqual(@as(u32, @intCast(count)), freed.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), reactor.snapshot().tunnels);
    try std.testing.expectEqual(@intFromEnum(tunnel.CloseReason.client), reason.load(.acquire));
}

test "reactor enforces per-tunnel idle timers without a periodic tick (#818)" {
    var reactor: Reactor = undefined;
    try reactor.start(std.testing.allocator, .{ .threads = 1, .shutdown_requested = neverShutdown, .fallback_wakeup_ms = 5_000 });
    defer reactor.deinit();
    var done = std.atomic.Value(u32).init(0);
    var reason = std.atomic.Value(u8).init(0);
    var freed = std.atomic.Value(u32).init(0);
    const started = event_loop.monotonicMs();
    const p = try submitTestTunnel(&reactor, .{ .idle_timeout_ms = 60, .shutdown_requested = neverShutdown, .poll_interval_ms = 0 }, &done, &reason, &freed);
    defer _ = std.c.close(p.client_peer);
    defer _ = std.c.close(p.upstream_peer);
    try waitFor(&done, 1, 2_000);
    const elapsed = event_loop.monotonicMs() - started;
    try std.testing.expectEqual(@intFromEnum(tunnel.CloseReason.idle), reason.load(.acquire));
    try std.testing.expect(elapsed >= 60);
    // The idle deadline itself woke the shard, not the 5 s fallback.
    try std.testing.expect(elapsed < 2_000);
}

test "reactor wakeAll lets drain-mode tunnels see a reload stamp immediately (#818)" {
    var reactor: Reactor = undefined;
    try reactor.start(std.testing.allocator, .{ .threads = 2, .shutdown_requested = neverShutdown, .fallback_wakeup_ms = 10_000 });
    defer reactor.deinit();
    var done = std.atomic.Value(u32).init(0);
    var reason = std.atomic.Value(u8).init(0);
    var freed = std.atomic.Value(u32).init(0);
    var superseded = std.atomic.Value(u64).init(0);
    const opts = tunnel.Options{
        .idle_timeout_ms = 60_000,
        .shutdown_requested = neverShutdown,
        .reload_drain = .{ .superseded_at_ms = &superseded, .timeout_ms = 50 },
        .poll_interval_ms = 0,
    };
    var peers: [4]PeerPair = undefined;
    for (&peers) |*p| p.* = try submitTestTunnel(&reactor, opts, &done, &reason, &freed);
    defer for (peers) |p| {
        _ = std.c.close(p.client_peer);
        _ = std.c.close(p.upstream_peer);
    };
    compat.sleepNs(100 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), done.load(.acquire));

    const reloaded_at = event_loop.monotonicMs();
    superseded.store(reloaded_at, .release);
    reactor.wakeAll();
    try waitFor(&done, 4, 3_000);
    try std.testing.expectEqual(@intFromEnum(tunnel.CloseReason.reload), reason.load(.acquire));
    // Well before the 10 s fallback wakeup.
    try std.testing.expect(event_loop.monotonicMs() - reloaded_at < 3_000);
}

test "reactor drains tunnels for the shutdown window, then stopAndJoin returns (#818)" {
    test_shutdown_flag.store(false, .release);
    defer test_shutdown_flag.store(false, .release);
    var reactor: Reactor = undefined;
    try reactor.start(std.testing.allocator, .{ .threads = 2, .shutdown_requested = testShutdown, .fallback_wakeup_ms = 10_000 });
    defer reactor.deinit();
    var done = std.atomic.Value(u32).init(0);
    var reason = std.atomic.Value(u8).init(0);
    var freed = std.atomic.Value(u32).init(0);
    const opts = tunnel.Options{ .idle_timeout_ms = 60_000, .drain_timeout_ms = 80, .shutdown_requested = testShutdown, .poll_interval_ms = 0 };
    var peers: [6]PeerPair = undefined;
    for (&peers) |*p| p.* = try submitTestTunnel(&reactor, opts, &done, &reason, &freed);
    defer for (peers) |p| {
        _ = std.c.close(p.client_peer);
        _ = std.c.close(p.upstream_peer);
    };

    test_shutdown_flag.store(true, .release);
    const requested = event_loop.monotonicMs();
    reactor.wakeAll();
    // Inside the drain window traffic still flows.
    try testWriteAll(peers[0].client_peer, "late");
    var got: [4]u8 = undefined;
    try testReadExact(peers[0].upstream_peer, &got);
    try std.testing.expectEqualStrings("late", &got);

    reactor.stopAndJoin();
    const elapsed = event_loop.monotonicMs() - requested;
    try std.testing.expectEqual(@as(u32, 6), done.load(.acquire));
    try std.testing.expectEqual(@as(u32, 6), freed.load(.acquire));
    try std.testing.expectEqual(@intFromEnum(tunnel.CloseReason.shutdown), reason.load(.acquire));
    try std.testing.expect(elapsed >= 80);
    try std.testing.expect(elapsed < 3_000);

    // A stopped reactor refuses handoffs; the caller keeps the job.
    const c = try testSocketPair();
    const u = try testSocketPair();
    const job = try TestJob.create(c[0], u[0], opts, &done, &reason, &freed);
    try std.testing.expectError(error.ReactorStopped, reactor.submit(&job.job));
    job.job.vtable.finish(&job.job);
    _ = std.c.close(c[1]);
    _ = std.c.close(u[1]);
}

test "reactor keeps one buffer per direction for a stalled reader (#818)" {
    var reactor: Reactor = undefined;
    try reactor.start(std.testing.allocator, .{ .threads = 1, .shutdown_requested = neverShutdown });
    defer reactor.deinit();
    var done = std.atomic.Value(u32).init(0);
    var reason = std.atomic.Value(u8).init(0);
    var freed = std.atomic.Value(u32).init(0);
    const p = try submitTestTunnel(&reactor, .{ .idle_timeout_ms = 200, .shutdown_requested = neverShutdown, .poll_interval_ms = 0 }, &done, &reason, &freed);
    defer _ = std.c.close(p.client_peer);
    defer _ = std.c.close(p.upstream_peer);
    // The client never reads: the origin's writes must eventually hit a full
    // socket instead of the reactor buffering without bound.
    tunnel.setNonBlocking(p.upstream_peer);
    const chunk = [_]u8{'z'} ** 4096;
    var stalled = false;
    var attempts: usize = 0;
    while (attempts < 20_000) : (attempts += 1) {
        if (std.c.write(p.upstream_peer, &chunk, chunk.len) > 0) continue;
        stalled = true;
        break;
    }
    try std.testing.expect(stalled);
    try waitFor(&done, 1, 3_000);
    try std.testing.expectEqual(@intFromEnum(tunnel.CloseReason.idle), reason.load(.acquire));
}
