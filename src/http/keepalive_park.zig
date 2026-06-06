// Idle keepalive connection parking (#138).
//
// Tardigrade serves requests on a bounded worker pool with blocking I/O. Without
// parking, a worker stays attached to a keepalive connection for its whole
// lifetime — blocked in read() between requests — so connections beyond the
// worker count starve and tail latency explodes (measured: 4 workers + 10
// keepalive conns -> p90 ~26ms).
//
// This module moves the *idle wait* off the worker: after a response, a
// keepalive connection's state (fd, pooled session, optional TLS state) is moved
// into a heap-owned `ParkedConnection` registered in the `ParkedRegistry`, and
// the worker returns to the pool. The event loop watches the parked fd; when the
// next request arrives it dispatches the connection back to a worker, which
// serves one request and re-parks or closes. Active request handling still uses
// a worker with blocking I/O, so only the idle gap is decoupled.
//
// Lifecycle of a single ParkedConnection:
//   parkNew  -> [in map, .parked] -> resumeReady (event loop) -> [.resuming]
//            -> checkout (worker)  -> [out of map, owned by worker]
//            -> repark (keep-alive) back to .parked, or closeSlot (done).
//
// The `.parked`/`.resuming` flag lets the idle reaper skip a connection that the
// event loop has already handed to a worker, avoiding a reap/resume race. All
// map and counter access is guarded by a single mutex; the registry is touched
// by the event-loop thread (resumeReady, reapIdle, closeAll) and worker threads
// (parkNew, checkout, repark, closeSlot).

const std = @import("std");
const compat = @import("../zig_compat.zig");
const gateway_state = @import("../gateway_state.zig");
const tls_termination = @import("tls_termination.zig");

const ConnectionSession = gateway_state.ConnectionSession;
const ConnectionSessionPool = gateway_state.ConnectionSessionPool;
const TlsConnection = tls_termination.TlsConnection;

pub const ParkState = enum { parked, resuming };

pub const ParkedConnection = struct {
    fd: std.posix.fd_t,
    session: *ConnectionSession,
    /// TLS state moved off the worker stack; null for plaintext connections.
    tls: ?TlsConnection,
    /// Requests already served on this connection (for max_requests_per_connection).
    served: u32,
    /// Monotonic ms timestamp of the last park, used for idle-timeout reaping.
    parked_at_ms: u64,
    state: ParkState,
    ip_buf: [64]u8 = undefined,
    ip_len: usize = 0,

    pub fn ip(self: *const ParkedConnection) []const u8 {
        return self.ip_buf[0..self.ip_len];
    }

    fn setIp(self: *ParkedConnection, value: []const u8) void {
        const n = @min(value.len, self.ip_buf.len);
        @memcpy(self.ip_buf[0..n], value[0..n]);
        self.ip_len = n;
    }
};

pub const CloseReason = enum { idle_timeout, shutdown, peer, max_requests, @"error" };

pub const ParkedRegistry = struct {
    allocator: std.mem.Allocator,
    session_pool: *ConnectionSessionPool,
    mutex: compat.Mutex = .{},
    map: std.AutoHashMapUnmanaged(std.posix.fd_t, *ParkedConnection) = .{},

    // Counters (guarded by mutex) for observability (#138 metrics).
    resumes_total: u64 = 0,
    timeouts_total: u64 = 0,
    closed_total: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, session_pool: *ConnectionSessionPool) ParkedRegistry {
        return .{ .allocator = allocator, .session_pool = session_pool };
    }

    pub fn deinit(self: *ParkedRegistry) void {
        self.closeAll();
        self.mutex.lock();
        self.map.deinit(self.allocator);
        self.mutex.unlock();
        self.* = undefined;
    }

    /// Park a brand-new connection (first keepalive idle gap). Ownership of
    /// `session`, `tls`, and `fd` transfers to the returned/registered slot.
    /// The caller must register `fd` with the event loop only on success; on
    /// error the caller still owns the resources and must close them.
    pub fn parkNew(
        self: *ParkedRegistry,
        fd: std.posix.fd_t,
        session: *ConnectionSession,
        tls: ?TlsConnection,
        served: u32,
        client_ip: []const u8,
        now_ms: u64,
    ) !void {
        const pc = try self.allocator.create(ParkedConnection);
        errdefer self.allocator.destroy(pc);
        pc.* = .{
            .fd = fd,
            .session = session,
            .tls = tls,
            .served = served,
            .parked_at_ms = now_ms,
            .state = .parked,
        };
        pc.setIp(client_ip);

        self.mutex.lock();
        defer self.mutex.unlock();
        try self.map.put(self.allocator, fd, pc);
    }

    /// Re-park a connection that a worker just finished serving on resume. The
    /// `pc` was previously checked out, so its object is reused (no allocation).
    /// On error the caller still owns `pc` and must close it via `closeSlot`.
    pub fn repark(self: *ParkedRegistry, pc: *ParkedConnection, now_ms: u64) !void {
        pc.state = .parked;
        pc.parked_at_ms = now_ms;
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.map.put(self.allocator, pc.fd, pc);
    }

    /// Event-loop side: a parked fd became readable. Flip it to `.resuming` so
    /// the idle reaper leaves it alone until a worker checks it out. Returns
    /// true if the fd was a parked connection (vs the listener or an unknown fd).
    pub fn resumeReady(self: *ParkedRegistry, fd: std.posix.fd_t) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const pc = self.map.get(fd) orelse return false;
        pc.state = .resuming;
        self.resumes_total += 1;
        return true;
    }

    /// Worker side: take ownership of the parked connection for `fd` to serve a
    /// request. Removes it from the map so the reaper cannot touch it while the
    /// worker holds it. Returns null if it is not (or no longer) parked.
    pub fn checkout(self: *ParkedRegistry, fd: std.posix.fd_t) ?*ParkedConnection {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.map.fetchRemove(fd)) |kv| return kv.value;
        return null;
    }

    /// Free a checked-out connection: release the pooled session, tear down TLS,
    /// close the socket, and destroy the slot. Caller must NOT hold the mutex.
    pub fn closeSlot(self: *ParkedRegistry, pc: *ParkedConnection, reason: CloseReason) void {
        _ = reason;
        if (pc.tls) |*tls| tls.deinit();
        _ = std.c.close(pc.fd);
        self.session_pool.release(pc.session);
        self.allocator.destroy(pc);
        self.mutex.lock();
        self.closed_total += 1;
        self.mutex.unlock();
    }

    /// Close connections idle in the `.parked` state longer than `timeout_ms`.
    /// Runs on the event-loop thread from the timer tick. Returns the count
    /// reaped. `timeout_ms == 0` disables reaping.
    pub fn reapIdle(self: *ParkedRegistry, now_ms: u64, timeout_ms: u64) usize {
        if (timeout_ms == 0) return 0;

        // Collect victims first; AutoHashMap does not allow removal during
        // iteration. Reaping runs on the periodic timer tick, not the hot path.
        var victims: std.ArrayList(*ParkedConnection) = .empty;
        defer victims.deinit(self.allocator);

        self.mutex.lock();
        var it = self.map.iterator();
        while (it.next()) |entry| {
            const pc = entry.value_ptr.*;
            if (pc.state != .parked) continue;
            const age = if (now_ms >= pc.parked_at_ms) now_ms - pc.parked_at_ms else 0;
            if (age >= timeout_ms) {
                victims.append(self.allocator, pc) catch break;
            }
        }
        for (victims.items) |pc| _ = self.map.remove(pc.fd);
        self.timeouts_total += victims.items.len;
        self.mutex.unlock();

        for (victims.items) |pc| {
            if (pc.tls) |*tls| tls.deinit();
            _ = std.c.close(pc.fd);
            self.session_pool.release(pc.session);
            self.allocator.destroy(pc);
        }
        return victims.items.len;
    }

    /// Close every parked connection (graceful shutdown / deinit).
    pub fn closeAll(self: *ParkedRegistry) void {
        var victims: std.ArrayList(*ParkedConnection) = .empty;
        defer victims.deinit(self.allocator);

        self.mutex.lock();
        var it = self.map.iterator();
        while (it.next()) |entry| {
            victims.append(self.allocator, entry.value_ptr.*) catch break;
        }
        self.map.clearRetainingCapacity();
        self.closed_total += victims.items.len;
        self.mutex.unlock();

        for (victims.items) |pc| {
            if (pc.tls) |*tls| tls.deinit();
            _ = std.c.close(pc.fd);
            self.session_pool.release(pc.session);
            self.allocator.destroy(pc);
        }
    }

    pub const Stats = struct {
        parked: usize,
        resumes_total: u64,
        timeouts_total: u64,
        closed_total: u64,
    };

    pub fn stats(self: *ParkedRegistry) Stats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .parked = self.map.count(),
            .resumes_total = self.resumes_total,
            .timeouts_total = self.timeouts_total,
            .closed_total = self.closed_total,
        };
    }

    pub fn count(self: *ParkedRegistry) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.map.count();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const http_buffer_pool = @import("buffer_pool.zig");

test "parkNew, resumeReady, checkout, repark transitions" {
    const allocator = testing.allocator;
    var bufs = http_buffer_pool.BufferPool.init(allocator, 4096, 4);
    defer bufs.deinit();
    var pool = ConnectionSessionPool.init(allocator, &bufs, 8);
    defer pool.deinit();

    var reg = ParkedRegistry.init(allocator, &pool);
    defer reg.deinit();

    const s1 = try pool.acquire();
    // Use a harmless dummy fd; closeSlot/reap will call close() which just
    // returns EBADF on a non-socket fd.
    const dummy_fd: std.posix.fd_t = 90001;
    try reg.parkNew(dummy_fd, s1, null, 0, "127.0.0.1", 1000);
    try testing.expectEqual(@as(usize, 1), reg.count());

    // Unknown fd is not a parked connection.
    try testing.expect(!reg.resumeReady(90002));
    // Real parked fd flips to resuming.
    try testing.expect(reg.resumeReady(dummy_fd));

    const pc = reg.checkout(dummy_fd) orelse return error.MissingParked;
    try testing.expectEqual(@as(usize, 0), reg.count()); // checked out -> out of map
    try testing.expectEqual(@as(u32, 0), pc.served);
    try testing.expectEqualStrings("127.0.0.1", pc.ip());

    // Re-park the same slot (no new allocation).
    pc.served += 1;
    try reg.repark(pc, 2000);
    try testing.expectEqual(@as(usize, 1), reg.count());

    const st = reg.stats();
    try testing.expectEqual(@as(u64, 1), st.resumes_total);
    try testing.expectEqual(@as(usize, 1), st.parked);

    // Clean up the still-parked slot through closeAll (frees session + slot).
    reg.closeAll();
    try testing.expectEqual(@as(usize, 0), reg.count());
}

test "reapIdle closes only sufficiently-idle parked connections" {
    const allocator = testing.allocator;
    var bufs = http_buffer_pool.BufferPool.init(allocator, 4096, 4);
    defer bufs.deinit();
    var pool = ConnectionSessionPool.init(allocator, &bufs, 8);
    defer pool.deinit();

    var reg = ParkedRegistry.init(allocator, &pool);
    defer reg.deinit();

    try reg.parkNew(90010, try pool.acquire(), null, 0, "10.0.0.1", 1000); // old
    try reg.parkNew(90011, try pool.acquire(), null, 0, "10.0.0.2", 5000); // fresh
    try testing.expectEqual(@as(usize, 2), reg.count());

    // now=5500, timeout=1000: fd 90010 (age 4500) reaped, 90011 (age 500) kept.
    const reaped = reg.reapIdle(5500, 1000);
    try testing.expectEqual(@as(usize, 1), reaped);
    try testing.expectEqual(@as(usize, 1), reg.count());
    try testing.expectEqual(@as(u64, 1), reg.stats().timeouts_total);

    // A resuming connection is never reaped even if old.
    try testing.expect(reg.resumeReady(90011));
    try testing.expectEqual(@as(usize, 0), reg.reapIdle(99999, 1));
    try testing.expectEqual(@as(usize, 1), reg.count());
}
