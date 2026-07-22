const compat = @import("zig_compat");
const builtin = @import("builtin");
const std = @import("std");

pub const Backend = enum {
    epoll,
    kqueue,
};

pub const Event = struct {
    fd: std.posix.fd_t,
    readable: bool = false,
    writable: bool = false,
    errored: bool = false,
};

pub const Interest = packed struct {
    read: bool = false,
    write: bool = false,

    pub fn any(self: Interest) bool {
        return self.read or self.write;
    }
};

pub const EventLoop = struct {
    fd: std.posix.fd_t,
    backend: Backend,

    pub fn init() !EventLoop {
        return if (builtin.os.tag == .linux) blk: {
            const linux = std.os.linux;
            const rc = linux.epoll_create1(@intCast(linux.EPOLL.CLOEXEC));
            if (linux.errno(rc) != .SUCCESS) return error.SystemResources;
            break :blk .{ .fd = @intCast(rc), .backend = .epoll };
        } else blk: {
            const fd = std.c.kqueue();
            if (fd < 0) return error.SystemResources;
            break :blk .{ .fd = fd, .backend = .kqueue };
        };
    }

    pub fn deinit(self: *EventLoop) void {
        _ = std.c.close(self.fd);
        self.* = undefined;
    }

    pub fn backendName(self: *const EventLoop) []const u8 {
        return switch (self.backend) {
            .epoll => "epoll",
            .kqueue => "kqueue",
        };
    }

    pub fn addReadFd(self: *EventLoop, fd: std.posix.fd_t) !void {
        return self.add(fd, .{ .read = true });
    }

    pub fn add(self: *EventLoop, fd: std.posix.fd_t, interest: Interest) !void {
        if (!interest.any()) return error.InvalidEventInterest;
        if (builtin.os.tag == .linux) {
            const linux = std.os.linux;
            var event = linux.epoll_event{
                .events = epollEventsFor(interest),
                .data = .{ .fd = @intCast(fd) },
            };
            const rc = linux.epoll_ctl(@intCast(self.fd), linux.EPOLL.CTL_ADD, @intCast(fd), &event);
            if (linux.errno(rc) != .SUCCESS) return error.Unexpected;
        } else {
            try self.applyKqueueInterest(fd, interest, .add);
        }
    }

    pub fn modify(self: *EventLoop, fd: std.posix.fd_t, interest: Interest) !void {
        if (!interest.any()) return error.InvalidEventInterest;
        if (builtin.os.tag == .linux) {
            const linux = std.os.linux;
            var event = linux.epoll_event{
                .events = epollEventsFor(interest),
                .data = .{ .fd = @intCast(fd) },
            };
            const rc = linux.epoll_ctl(@intCast(self.fd), linux.EPOLL.CTL_MOD, @intCast(fd), &event);
            if (linux.errno(rc) != .SUCCESS) return error.Unexpected;
        } else {
            try self.applyKqueueInterest(fd, interest, .modify);
        }
    }

    /// Stop watching `fd` for readiness. Used to un-park a keepalive connection
    /// before dispatching it to a worker (#138), so the level-triggered backends
    /// do not keep re-firing while the worker drains the socket. Safe to call
    /// from a worker thread concurrently with `wait` on the loop thread, since
    /// both epoll_ctl and kevent change-list updates are thread-safe.
    pub fn removeReadFd(self: *EventLoop, fd: std.posix.fd_t) !void {
        return self.remove(fd);
    }

    pub fn remove(self: *EventLoop, fd: std.posix.fd_t) !void {
        if (builtin.os.tag == .linux) {
            const linux = std.os.linux;
            // EPOLL_CTL_DEL ignores the event argument on modern kernels, but a
            // valid pointer is passed for portability with older ones.
            var event = linux.epoll_event{
                .events = 0,
                .data = .{ .fd = @intCast(fd) },
            };
            const rc = linux.epoll_ctl(@intCast(self.fd), linux.EPOLL.CTL_DEL, @intCast(fd), &event);
            if (linux.errno(rc) != .SUCCESS) return error.Unexpected;
        } else {
            try self.applyKqueueInterest(fd, .{}, .remove);
        }
    }

    pub fn wait(self: *EventLoop, out_events: []Event, timeout_ms: i32) !usize {
        if (out_events.len == 0) return 0;

        return if (builtin.os.tag == .linux)
            self.waitEpoll(out_events, timeout_ms)
        else
            self.waitKqueue(out_events, timeout_ms);
    }

    fn waitEpoll(self: *EventLoop, out_events: []Event, timeout_ms: i32) usize {
        const linux = std.os.linux;
        var epoll_events: [64]linux.epoll_event = undefined;
        const cap = @min(out_events.len, epoll_events.len);
        const rc = linux.epoll_wait(@intCast(self.fd), epoll_events[0..cap].ptr, @intCast(cap), timeout_ms);
        if (linux.errno(rc) != .SUCCESS) return 0;
        const n: usize = @intCast(rc);

        for (epoll_events[0..n], 0..) |ev, idx| {
            const errored = (ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR)) != 0;
            out_events[idx] = .{
                .fd = @intCast(ev.data.fd),
                .readable = (ev.events & linux.EPOLL.IN) != 0 or errored,
                .writable = (ev.events & linux.EPOLL.OUT) != 0,
                .errored = errored,
            };
        }
        return n;
    }

    fn waitKqueue(self: *EventLoop, out_events: []Event, timeout_ms: i32) !usize {
        var kq_events: [128]std.c.Kevent = undefined;
        const requested = std.math.mul(usize, out_events.len, 2) catch out_events.len;
        const cap = @min(requested, kq_events.len);

        var ts: std.c.timespec = undefined;
        const timeout_ptr: ?*const std.c.timespec = if (timeout_ms < 0)
            null
        else blk: {
            const millis: u64 = @intCast(timeout_ms);
            ts = .{
                .sec = @intCast(millis / std.time.ms_per_s),
                .nsec = @intCast((millis % std.time.ms_per_s) * std.time.ns_per_ms),
            };
            break :blk &ts;
        };

        var dummy_ev: std.c.Kevent = undefined;
        const n = std.c.kevent(self.fd, @as([*]const std.c.Kevent, @ptrCast(&dummy_ev)), 0, kq_events[0..cap].ptr, @intCast(cap), timeout_ptr);
        if (n < 0) {
            // A blocking kevent is interrupted by any signal delivered to this
            // thread (EINTR) — common once background worker threads (e.g. the
            // HTTP/2 upstream readers) are active. Treat it as "no events" and
            // let the caller loop again, mirroring the epoll path.
            if (std.posix.errno(n) == .INTR) return 0;
            return error.Unexpected;
        }
        var out_len: usize = 0;
        for (kq_events[0..@intCast(n)]) |ev| {
            const errored = (ev.flags & (std.c.EV.ERROR | std.c.EV.EOF)) != 0;
            const fd: std.posix.fd_t = @intCast(ev.ident);
            const slot = findOrAppendByFd(out_events, &out_len, fd) orelse continue;
            slot.readable = slot.readable or ev.filter == std.c.EVFILT.READ or errored;
            slot.writable = slot.writable or ev.filter == std.c.EVFILT.WRITE;
            slot.errored = slot.errored or errored;
        }
        return out_len;
    }

    fn findOrAppendByFd(out_events: []Event, out_len: *usize, fd: std.posix.fd_t) ?*Event {
        for (out_events[0..out_len.*]) |*event| {
            if (event.fd == fd) return event;
        }
        if (out_len.* == out_events.len) return null;
        const slot = &out_events[out_len.*];
        slot.* = .{ .fd = fd };
        out_len.* += 1;
        return slot;
    }

    fn applyKqueueInterest(self: *EventLoop, fd: std.posix.fd_t, interest: Interest, op: enum { add, modify, remove }) !void {
        if (op == .modify or op == .remove) {
            try self.kqueueFilterChange(fd, std.c.EVFILT.READ, std.c.EV.DELETE, true);
            try self.kqueueFilterChange(fd, std.c.EVFILT.WRITE, std.c.EV.DELETE, true);
        }
        if (op == .remove) return;
        if (interest.read) try self.kqueueFilterChange(fd, std.c.EVFILT.READ, std.c.EV.ADD | std.c.EV.ENABLE, false);
        if (interest.write) try self.kqueueFilterChange(fd, std.c.EVFILT.WRITE, std.c.EV.ADD | std.c.EV.ENABLE, false);
    }

    fn kqueueFilterChange(
        self: *EventLoop,
        fd: std.posix.fd_t,
        filter: i16,
        flags: u16,
        ignore_missing: bool,
    ) !void {
        const changes = [_]std.c.Kevent{.{
            .ident = @intCast(fd),
            .filter = filter,
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        }};
        const ret = std.c.kevent(self.fd, &changes, @intCast(changes.len), @as([*]std.c.Kevent, @ptrCast(@constCast(&changes))), 0, null);
        if (ret < 0) {
            if (ignore_missing and std.posix.errno(ret) == .NOENT) return;
            return error.Unexpected;
        }
    }
};

fn epollEventsFor(interest: Interest) u32 {
    const linux = std.os.linux;
    var events: u32 = linux.EPOLL.HUP | linux.EPOLL.ERR;
    if (interest.read) events |= linux.EPOLL.IN;
    if (interest.write) events |= linux.EPOLL.OUT;
    return events;
}

pub const TimerManager = struct {
    interval_ms: u64,
    next_tick_ms: u64,

    pub fn init(interval_ms: u64) TimerManager {
        const now = monotonicMs();
        return .{
            .interval_ms = interval_ms,
            .next_tick_ms = now + interval_ms,
        };
    }

    pub fn msUntilNextTick(self: *const TimerManager, now_ms: u64) i32 {
        if (self.interval_ms == 0) return -1;
        if (now_ms >= self.next_tick_ms) return 0;

        const delta = self.next_tick_ms - now_ms;
        return @intCast(@min(delta, @as(u64, std.math.maxInt(i32))));
    }

    pub fn consumeTick(self: *TimerManager, now_ms: u64) bool {
        if (self.interval_ms == 0) return false;
        if (now_ms < self.next_tick_ms) return false;

        while (self.next_tick_ms <= now_ms) {
            self.next_tick_ms += self.interval_ms;
        }
        return true;
    }
};

pub fn detectBackend() !Backend {
    return switch (builtin.os.tag) {
        .linux => .epoll,
        .macos, .ios, .tvos, .watchos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => .kqueue,
        else => error.UnsupportedPlatform,
    };
}

pub fn monotonicMs() u64 {
    const now = compat.milliTimestamp();
    return if (now <= 0) 0 else @intCast(now);
}

test "detectBackend matches current platform" {
    const backend = try detectBackend();
    switch (builtin.os.tag) {
        .linux => try std.testing.expectEqual(Backend.epoll, backend),
        .macos, .ios, .tvos, .watchos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => try std.testing.expectEqual(Backend.kqueue, backend),
        else => try std.testing.expect(false),
    }
}

test "timer manager ticks on interval" {
    var timer = TimerManager{
        .interval_ms = 100,
        .next_tick_ms = 1_000,
    };

    try std.testing.expectEqual(@as(i32, 100), timer.msUntilNextTick(900));
    try std.testing.expect(!timer.consumeTick(999));
    try std.testing.expect(timer.consumeTick(1_000));
    try std.testing.expectEqual(@as(u64, 1_100), timer.next_tick_ms);
}

test "event loop reports write readiness" {
    var loop = try EventLoop.init();
    defer loop.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try loop.add(fds[0], .{ .write = true });
    defer loop.remove(fds[0]) catch {};

    var events: [4]Event = undefined;
    const count = try loop.wait(&events, 50);
    try std.testing.expect(count > 0);
    var saw_write = false;
    for (events[0..count]) |ev| {
        if (ev.fd == fds[0] and ev.writable) saw_write = true;
    }
    try std.testing.expect(saw_write);
}

test "event loop modify replaces write interest with read interest" {
    var loop = try EventLoop.init();
    defer loop.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try loop.add(fds[0], .{ .write = true });
    defer loop.remove(fds[0]) catch {};
    try loop.modify(fds[0], .{ .read = true });

    var events: [4]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), try loop.wait(&events, 10));
    try writeFd(fds[1], "x");
    const count = try loop.wait(&events, 50);
    try std.testing.expect(count > 0);
    var saw_read = false;
    var saw_write = false;
    for (events[0..count]) |ev| {
        if (ev.fd != fds[0]) continue;
        saw_read = saw_read or ev.readable;
        saw_write = saw_write or ev.writable;
    }
    try std.testing.expect(saw_read);
    try std.testing.expect(!saw_write);
}

test "event loop coalesces simultaneous read and write readiness by fd" {
    var loop = try EventLoop.init();
    defer loop.deinit();
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    try loop.add(fds[0], .{ .read = true, .write = true });
    defer loop.remove(fds[0]) catch {};
    try writeFd(fds[1], "x");

    var events: [1]Event = undefined;
    const count = try loop.wait(&events, 50);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(fds[0], events[0].fd);
    try std.testing.expect(events[0].readable);
    try std.testing.expect(events[0].writable);
}

fn testSocketPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
        if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    } else {
        if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    }
    errdefer closeFd(fds[0]);
    errdefer closeFd(fds[1]);
    return fds;
}

fn writeFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.write(fd, bytes.ptr, bytes.len);
        if (linux.errno(rc) != .SUCCESS) return error.SocketWriteFailed;
        if (rc != bytes.len) return error.ShortWrite;
        return;
    }
    const rc = std.c.write(fd, bytes.ptr, bytes.len);
    if (rc < 0) return error.SocketWriteFailed;
    if (@as(usize, @intCast(rc)) != bytes.len) return error.ShortWrite;
}

fn closeFd(fd: std.posix.fd_t) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.close(fd);
    } else {
        _ = std.c.close(fd);
    }
}
