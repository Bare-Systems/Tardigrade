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
const encrypted_stream_connection = @import("encrypted_stream_connection.zig");
const encrypted_stream = @import("tls_core").encrypted_stream;

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
        /// The tunnel is over after `advance` returned `.closed`: release
        /// everything it owns, including the `Job` itself.
        finish: *const fn (*Job) void,
        /// The reactor accepted ownership but could not begin serving the
        /// tunnel (for example, registry bookkeeping OOM). Release it with an
        /// explicit error close reason instead of inferring one from an
        /// unstarted relay.
        abort: *const fn (*Job, tunnel.CloseReason) void,
    };
};

pub const Options = struct {
    threads: u16,
    /// Checked at every wakeup; a change makes the shard advance every
    /// tunnel so shutdown drains start. Production calls `wakeAll` when
    /// shutdown or a hot reload happens, so no periodic check is needed.
    shutdown_requested: *const fn () bool,
    /// Optional safety-net wakeup interval. Zero (the default) disables it:
    /// a shard sleeps until a socket is ready, a tunnel's own earliest
    /// deadline, a handoff, or `wakeAll`, so idle tunnels cost nothing.
    fallback_wakeup_ms: u32 = 0,
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

const WakeWriteResult = enum {
    written,
    interrupted,
    already_pending,
    failed,
};
const WakeWriter = *const fn (std.posix.fd_t) WakeWriteResult;

fn systemWakeWrite(fd: std.posix.fd_t) WakeWriteResult {
    const byte = [1]u8{1};
    const rc = std.c.write(fd, &byte, byte.len);
    if (rc == 1) return .written;
    if (rc < 0) return switch (std.posix.errno(rc)) {
        .INTR => .interrupted,
        .AGAIN => .already_pending,
        else => .failed,
    };
    return .failed;
}

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

    fn wake(self: *Shard) error{ReactorWakeFailed}!void {
        while (true) switch (self.reactor.wake_writer(self.wake_write)) {
            .written, .already_pending => return,
            .interrupted => continue,
            .failed => return error.ReactorWakeFailed,
        };
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
                _ = self.adoptJob(&jobs, job);
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
            const fallback = self.reactor.opts.fallback_wakeup_ms;
            var deadline: ?u64 = if (fallback > 0) now + fallback else null;
            var ready_now = false;
            for (jobs.items) |job| {
                const fds = job.vtable.fds(job);
                pfds.appendAssumeCapacity(tunnel.pollEntry(fds[0], job.wait.client));
                pfds.appendAssumeCapacity(tunnel.pollEntry(fds[1], job.wait.upstream));
                if (job.wait.ready_now) ready_now = true;
                if (job.wait.deadline_ms) |at| deadline = if (deadline) |d| @min(d, at) else at;
            }
            const after = event_loop.monotonicMs();
            // No deadline: sleep until a socket or the wake pipe.
            const timeout: i32 = if (ready_now) 0 else if (deadline) |at| @intCast(@min(at -| after, @as(u64, std.math.maxInt(i32)))) else -1;
            _ = std.posix.poll(pfds.items, timeout) catch {};
            _ = self.wakeups_total.fetchAdd(1, .monotonic);
            if (pfds.items[0].revents != 0) self.drainWake();
            for (jobs.items, 0..) |job, j| {
                job.revents = .{ pfds.items[1 + 2 * j].revents, pfds.items[2 + 2 * j].revents };
            }
        }
    }

    fn adoptJob(self: *Shard, jobs: *std.ArrayList(*Job), job: *Job) bool {
        job.wait = .{ .client = .{}, .upstream = .{}, .deadline_ms = null, .ready_now = true };
        jobs.append(self.reactor.allocator, job) catch {
            // Accepted ownership but failed reactor bookkeeping: this is an
            // internal error, never a graceful shutdown.
            self.abortJob(job, .upstream_error);
            return false;
        };
        return true;
    }

    fn finishJob(self: *Shard, job: *Job) void {
        _ = self.tunnels.fetchSub(1, .acq_rel);
        job.vtable.finish(job);
    }

    fn abortJob(self: *Shard, job: *Job, reason: tunnel.CloseReason) void {
        _ = self.tunnels.fetchSub(1, .acq_rel);
        job.vtable.abort(job, reason);
    }
};

pub const Reactor = struct {
    allocator: std.mem.Allocator,
    opts: Options,
    shards: []Shard,
    wake_writer: WakeWriter,
    handoffs_total: std.atomic.Value(u64) = .init(0),
    stopped: std.atomic.Value(bool) = .init(false),

    pub const SubmitError = error{
        ReactorStopped,
        ReactorWakeFailed,
    };

    /// Start `opts.threads` reactor threads. `self` must not move afterwards.
    pub fn start(self: *Reactor, allocator: std.mem.Allocator, opts: Options) !void {
        try self.startWithWakeWriter(allocator, opts, systemWakeWrite);
    }

    fn startWithWakeWriter(self: *Reactor, allocator: std.mem.Allocator, opts: Options, wake_writer: WakeWriter) !void {
        std.debug.assert(opts.threads > 0);
        self.* = .{ .allocator = allocator, .opts = opts, .shards = try allocator.alloc(Shard, opts.threads), .wake_writer = wake_writer };
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
                shard.wake() catch @panic("tunnel reactor wake pipe failed during start rollback");
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
        // Keep the mutex until the signal succeeds. The shard cannot remove
        // this head concurrently, so an unexpected wake failure can roll
        // ownership back cleanly to the caller.
        best.wake() catch |err| {
            best.inbox = job.next_inbox;
            job.next_inbox = null;
            _ = best.tunnels.fetchSub(1, .acq_rel);
            best.mutex.unlock();
            return err;
        };
        best.mutex.unlock();
        _ = self.handoffs_total.fetchAdd(1, .monotonic);
    }

    /// Make every shard advance all of its tunnels now, so they observe a
    /// hot reload's supersession stamp or a shutdown request immediately
    /// instead of at their next socket event or timer.
    pub fn wakeAll(self: *Reactor) void {
        for (self.shards) |*shard| {
            shard.broadcast.store(true, .release);
            // Ownership has already transferred. Silently losing this wake
            // could violate reload/shutdown deadlines, so fail closed.
            shard.wake() catch @panic("tunnel reactor wake pipe failed after ownership transfer");
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
            shard.wake() catch @panic("tunnel reactor wake pipe failed during shutdown");
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

    const vtable = Job.VTable{ .fds = fds, .observe = observe, .advance = advance, .finish = finish, .abort = abort };

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
        self.release(self.relay.stats().close_reason);
    }

    fn abort(job: *Job, reason: tunnel.CloseReason) void {
        from(job).release(reason);
    }

    fn release(self: *TestJob, reason: tunnel.CloseReason) void {
        self.last_reason.store(@intFromEnum(reason), .release);
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

fn waitForDrive(counter: *std.atomic.Value(u64), timeout_ms: u64) !void {
    const until = event_loop.monotonicMs() + timeout_ms;
    while (counter.load(.acquire) == 0) {
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

var test_wake_writer_calls = std.atomic.Value(u32).init(0);

fn interruptOnceWakeWriter(fd: std.posix.fd_t) WakeWriteResult {
    const call = test_wake_writer_calls.fetchAdd(1, .acq_rel);
    if (call == 0) return .interrupted;
    return systemWakeWrite(fd);
}

fn failedWakeWriter(_: std.posix.fd_t) WakeWriteResult {
    return .failed;
}

test "reactor retries an interrupted wake write with fallback polling disabled (#818)" {
    test_wake_writer_calls.store(0, .release);
    var reactor: Reactor = undefined;
    try reactor.startWithWakeWriter(std.testing.allocator, .{ .threads = 1, .shutdown_requested = neverShutdown }, interruptOnceWakeWriter);
    defer reactor.deinit();

    var done = std.atomic.Value(u32).init(0);
    var reason = std.atomic.Value(u8).init(0);
    var freed = std.atomic.Value(u32).init(0);
    const p = try submitTestTunnel(&reactor, .{ .idle_timeout_ms = 30_000, .shutdown_requested = neverShutdown, .poll_interval_ms = 0 }, &done, &reason, &freed);
    defer _ = std.c.close(p.client_peer);
    defer _ = std.c.close(p.upstream_peer);

    try testWriteAll(p.client_peer, "wake");
    var got: [4]u8 = undefined;
    try testReadExact(p.upstream_peer, &got);
    try std.testing.expectEqualStrings("wake", &got);
    try std.testing.expect(test_wake_writer_calls.load(.acquire) >= 2);

    _ = std.c.shutdown(p.client_peer, std.posix.SHUT.RDWR);
    try waitFor(&done, 1, 2_000);
}

test "reactor submit rolls ownership back when the wake pipe fails (#818)" {
    var reactor: Reactor = undefined;
    try reactor.startWithWakeWriter(std.testing.allocator, .{ .threads = 1, .shutdown_requested = neverShutdown }, failedWakeWriter);
    defer {
        // The test-only writer intentionally fails. Restore the production
        // writer so teardown can wake and join the shard.
        reactor.wake_writer = systemWakeWrite;
        reactor.deinit();
    }

    var done = std.atomic.Value(u32).init(0);
    var reason = std.atomic.Value(u8).init(0);
    var freed = std.atomic.Value(u32).init(0);
    const c = try testSocketPair();
    const u = try testSocketPair();
    const job = try TestJob.create(c[0], u[0], .{ .idle_timeout_ms = 30_000, .shutdown_requested = neverShutdown, .poll_interval_ms = 0 }, &done, &reason, &freed);

    try std.testing.expectError(error.ReactorWakeFailed, reactor.submit(&job.job));
    try std.testing.expectEqual(@as(u32, 0), reactor.snapshot().tunnels);
    try std.testing.expectEqual(@as(u64, 0), reactor.snapshot().handoffs_total);
    job.job.vtable.finish(&job.job);
    _ = std.c.close(c[1]);
    _ = std.c.close(u[1]);
    try std.testing.expectEqual(@as(u32, 1), freed.load(.acquire));
}

test "reactor registry OOM aborts an accepted handoff as an error (#818)" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var no_shards: [0]Shard = .{};
    var fake_reactor = Reactor{
        .allocator = failing.allocator(),
        .opts = .{ .threads = 1, .shutdown_requested = neverShutdown },
        .shards = &no_shards,
        .wake_writer = systemWakeWrite,
    };
    var shard = Shard{
        .reactor = &fake_reactor,
        .index = 0,
        .wake_read = -1,
        .wake_write = -1,
    };

    var done = std.atomic.Value(u32).init(0);
    var reason = std.atomic.Value(u8).init(0);
    var freed = std.atomic.Value(u32).init(0);
    const c = try testSocketPair();
    const u = try testSocketPair();
    const job = try TestJob.create(c[0], u[0], .{ .idle_timeout_ms = 30_000, .shutdown_requested = neverShutdown, .poll_interval_ms = 0 }, &done, &reason, &freed);
    var jobs: std.ArrayList(*Job) = .empty;
    defer jobs.deinit(failing.allocator());

    shard.tunnels.store(1, .release);
    try std.testing.expect(!shard.adoptJob(&jobs, &job.job));
    try std.testing.expectEqual(@as(u32, 0), shard.tunnels.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), done.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), freed.load(.acquire));
    try std.testing.expectEqual(@intFromEnum(tunnel.CloseReason.upstream_error), reason.load(.acquire));
    _ = std.c.close(c[1]);
    _ = std.c.close(u[1]);
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
    try reactor.start(std.testing.allocator, .{ .threads = 1, .shutdown_requested = neverShutdown });
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
    // The idle deadline itself woke the shard (there is no fallback tick).
    try std.testing.expect(elapsed < 2_000);
}

test "reactor wakeAll lets drain-mode tunnels see a reload stamp immediately (#818)" {
    var reactor: Reactor = undefined;
    try reactor.start(std.testing.allocator, .{ .threads = 2, .shutdown_requested = neverShutdown });
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
    // Promptly, with no fallback tick.
    try std.testing.expect(event_loop.monotonicMs() - reloaded_at < 3_000);
}

test "reactor drains tunnels for the shutdown window, then stopAndJoin returns (#818)" {
    test_shutdown_flag.store(false, .release);
    defer test_shutdown_flag.store(false, .release);
    var reactor: Reactor = undefined;
    try reactor.start(std.testing.allocator, .{ .threads = 2, .shutdown_requested = testShutdown });
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

test "reactor shards stay asleep while their tunnels are idle, then wake for wakeAll and timers (#818)" {
    const limit = raiseFdLimit(4096);
    const budget = if (limit > 128) (limit - 64) / 4 else 0;
    const count: usize = @intCast(@min(budget, 400));
    try std.testing.expect(count >= 32);

    var reactor: Reactor = undefined;
    try reactor.start(std.testing.allocator, .{ .threads = 2, .shutdown_requested = neverShutdown });
    defer reactor.deinit();
    var done = std.atomic.Value(u32).init(0);
    var reason = std.atomic.Value(u8).init(0);
    var freed = std.atomic.Value(u32).init(0);
    const peers = try std.testing.allocator.alloc(PeerPair, count);
    defer std.testing.allocator.free(peers);
    const quiet = tunnel.Options{ .idle_timeout_ms = 60_000, .shutdown_requested = neverShutdown, .poll_interval_ms = 0 };
    for (peers) |*p| p.* = try submitTestTunnel(&reactor, quiet, &done, &reason, &freed);
    defer for (peers) |p| {
        _ = std.c.close(p.client_peer);
        _ = std.c.close(p.upstream_peer);
    };

    // Let the handoffs settle, then watch a quiet period much shorter than
    // any tunnel deadline: no shard wakes at all.
    compat.sleepNs(100 * std.time.ns_per_ms);
    const before = reactor.snapshot().wakeups_total;
    compat.sleepNs(600 * std.time.ns_per_ms);
    try std.testing.expectEqual(before, reactor.snapshot().wakeups_total);

    // wakeAll still reaches every shard...
    reactor.wakeAll();
    const until = event_loop.monotonicMs() + 2_000;
    while (reactor.snapshot().wakeups_total < before + 2) {
        if (event_loop.monotonicMs() > until) return error.Timeout;
        compat.sleepNs(2 * std.time.ns_per_ms);
    }
    // ...and a tunnel's own deadline still wakes its shard on time.
    const started = event_loop.monotonicMs();
    const short = try submitTestTunnel(&reactor, .{ .idle_timeout_ms = 80, .shutdown_requested = neverShutdown, .poll_interval_ms = 0 }, &done, &reason, &freed);
    defer _ = std.c.close(short.client_peer);
    defer _ = std.c.close(short.upstream_peer);
    try waitFor(&done, 1, 2_000);
    try std.testing.expectEqual(@intFromEnum(tunnel.CloseReason.idle), reason.load(.acquire));
    try std.testing.expect(event_loop.monotonicMs() - started >= 80);
    // The quiet tunnels are all still open and relaying.
    try testWriteAll(peers[0].client_peer, "ok");
    var got: [2]u8 = undefined;
    try testReadExact(peers[0].upstream_peer, &got);
    try std.testing.expectEqualStrings("ok", &got);
}

/// A native TLS stream whose peer keeps the record layer busy forever
/// (every drive makes progress) without ever producing application data.
const SpinningTlsStream = struct {
    drives: std.atomic.Value(u64) = .init(0),

    fn stream(self: *SpinningTlsStream) encrypted_stream.EncryptedStream {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn backend(_: *anyopaque) encrypted_stream.BackendKind {
        return .pure_zig_record;
    }

    fn read(_: *anyopaque, _: []u8) encrypted_stream.Error!usize {
        return error.WouldBlock;
    }

    fn write(_: *anyopaque, _: []const u8) encrypted_stream.Error!usize {
        return error.WouldBlock;
    }

    fn close(_: *anyopaque) void {}

    fn readiness(_: *anyopaque) encrypted_stream.Readiness {
        return .{};
    }

    fn drive(ptr: *anyopaque) encrypted_stream.Error!encrypted_stream.DriveResult {
        const self: *SpinningTlsStream = @ptrCast(@alignCast(ptr));
        _ = self.drives.fetchAdd(1, .monotonic);
        return .{ .made_progress = true, .readiness = .{} };
    }

    fn bufferSnapshot(_: *anyopaque) encrypted_stream.BufferSnapshot {
        return .{};
    }

    const vtable = encrypted_stream.EncryptedStream.VTable{
        .backendFn = backend,
        .readFn = read,
        .writeFn = write,
        .closeFn = close,
        .readinessFn = readiness,
        .driveFn = drive,
        .bufferSnapshotFn = bufferSnapshot,
    };
};

const TlsSpinJob = struct {
    job: Job = .{ .vtable = &vtable },
    spin: SpinningTlsStream = .{},
    conn: encrypted_stream_connection.EncryptedStreamHttpConnection = undefined,
    relay: AnyRelay = undefined,
    c2u: [64]u8 = undefined,
    u2c: [64]u8 = undefined,
    fds_: [2]std.posix.fd_t,
    done: *std.atomic.Value(u32),
    reason: *std.atomic.Value(u8),

    const AnyRelay = tunnel.Relay(tunnel.AnyEndpoint, tunnel.AnyEndpoint);
    const vtable = Job.VTable{ .fds = fds, .observe = observe, .advance = advance, .finish = finish, .abort = abort };

    fn from(job: *Job) *TlsSpinJob {
        return @fieldParentPtr("job", job);
    }

    fn fds(job: *Job) [2]std.posix.fd_t {
        return from(job).fds_;
    }

    fn observe(job: *Job, c: i16, u: i16) void {
        from(job).relay.observe(c, u);
    }

    fn advance(job: *Job) tunnel.Progress {
        return from(job).relay.advance();
    }

    fn finish(job: *Job) void {
        const self = from(job);
        self.reason.store(@intFromEnum(self.relay.stats().close_reason), .release);
        _ = self.done.fetchAdd(1, .acq_rel);
    }

    fn abort(job: *Job, reason: tunnel.CloseReason) void {
        const self = from(job);
        self.reason.store(@intFromEnum(reason), .release);
        _ = self.done.fetchAdd(1, .acq_rel);
    }
};

test "a TLS peer that keeps the record layer busy cannot starve the rest of its shard (#818)" {
    var reactor: Reactor = undefined;
    try reactor.start(std.testing.allocator, .{ .threads = 1, .shutdown_requested = neverShutdown });
    defer reactor.deinit();

    // The spinning tunnel: a native TLS client endpoint whose record layer
    // always has more to do. Its sockets exist only so it can be polled.
    const c = try testSocketPair();
    defer for (c) |fd| {
        _ = std.c.close(fd);
    };
    const u = try testSocketPair();
    defer for (u) |fd| {
        _ = std.c.close(fd);
    };
    var spin_done = std.atomic.Value(u32).init(0);
    var spin_reason = std.atomic.Value(u8).init(0);
    var spinner = TlsSpinJob{ .fds_ = .{ c[0], u[0] }, .done = &spin_done, .reason = &spin_reason };
    spinner.conn = encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(spinner.spin.stream(), c[0]);
    spinner.relay = TlsSpinJob.AnyRelay.init(
        .{ .encrypted = .{ .conn = &spinner.conn } },
        .{ .socket = .{ .handle = u[0] } },
        &spinner.c2u,
        &spinner.u2c,
        "",
        "",
        .{ .idle_timeout_ms = 400, .shutdown_requested = neverShutdown, .poll_interval_ms = 0 },
    );
    try reactor.submit(&spinner.job);

    // Do not mistake an unadopted inbox entry for a busy TLS peer. Under a
    // contended ARM runner the submission wake and the neighbour submission
    // can otherwise race the first reactor pass, leaving the assertion below
    // to sample before the spinner has ever been driven.
    try waitForDrive(&spinner.spin.drives, 2_000);

    // A plaintext neighbour on the same (only) shard.
    var done = std.atomic.Value(u32).init(0);
    var reason = std.atomic.Value(u8).init(0);
    var freed = std.atomic.Value(u32).init(0);
    const p = try submitTestTunnel(&reactor, .{ .idle_timeout_ms = 150, .shutdown_requested = neverShutdown, .poll_interval_ms = 0 }, &done, &reason, &freed);
    defer _ = std.c.close(p.client_peer);
    defer _ = std.c.close(p.upstream_peer);

    // The neighbour's traffic still moves promptly while the spinner is
    // being driven...
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const sent = event_loop.monotonicMs();
        try testWriteAll(p.client_peer, "ping");
        var got: [4]u8 = undefined;
        try testReadExact(p.upstream_peer, &got);
        try std.testing.expect(event_loop.monotonicMs() - sent < 100);
    }
    try std.testing.expect(spinner.spin.drives.load(.monotonic) > 0);
    // ...and its short idle deadline still fires on time.
    const quiet_from = event_loop.monotonicMs();
    try waitFor(&done, 1, 2_000);
    try std.testing.expectEqual(@intFromEnum(tunnel.CloseReason.idle), reason.load(.acquire));
    try std.testing.expect(event_loop.monotonicMs() - quiet_from < 1_000);

    // The spinner moved no bytes, so its own idle timeout ends it.
    try waitFor(&spin_done, 1, 3_000);
    try std.testing.expectEqual(@intFromEnum(tunnel.CloseReason.idle), spin_reason.load(.acquire));
}
