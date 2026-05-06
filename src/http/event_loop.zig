const compat = @import("../zig_compat.zig");
const builtin = @import("builtin");
const std = @import("std");

pub const Backend = enum {
    epoll,
    kqueue,
};

pub const Event = struct {
    fd: std.posix.fd_t,
    readable: bool,
};

pub const EventLoop = struct {
    fd: std.posix.fd_t,
    backend: Backend,

    pub fn init() !EventLoop {
        return if (builtin.os.tag == .linux) blk: {
            const linux = std.os.linux;
            const rc = linux.epoll_create1(@intCast(linux.EPOLL.CLOEXEC));
            if (linux.getErrno(rc) != .SUCCESS) return error.SystemResources;
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
        if (builtin.os.tag == .linux) {
            const linux = std.os.linux;
            var event = linux.epoll_event{
                .events = linux.EPOLL.IN,
                .data = .{ .fd = @intCast(fd) },
            };
            const rc = linux.epoll_ctl(@intCast(self.fd), linux.EPOLL.CTL_ADD, @intCast(fd), &event);
            if (linux.getErrno(rc) != .SUCCESS) return error.Unexpected;
        } else {
            const changes = [_]std.c.Kevent{.{
                .ident = @intCast(fd),
                .filter = std.c.EVFILT.READ,
                .flags = std.c.EV.ADD | std.c.EV.ENABLE,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            const ret = std.c.kevent(self.fd, &changes, @intCast(changes.len), @as([*]std.c.Kevent, @constCast(@ptrCast(&changes))), 0, null);
            if (ret < 0) return error.Unexpected;
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
        if (linux.getErrno(rc) != .SUCCESS) return 0;
        const n: usize = @intCast(rc);

        for (epoll_events[0..n], 0..) |ev, idx| {
            const readable = (ev.events & (linux.EPOLL.IN | linux.EPOLL.HUP | linux.EPOLL.ERR)) != 0;
            out_events[idx] = .{
                .fd = @intCast(ev.data.fd),
                .readable = readable,
            };
        }
        return n;
    }

    fn waitKqueue(self: *EventLoop, out_events: []Event, timeout_ms: i32) !usize {
        var kq_events: [64]std.c.Kevent = undefined;
        const cap = @min(out_events.len, kq_events.len);

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
        if (n < 0) return error.Unexpected;
        for (kq_events[0..@intCast(n)], 0..) |ev, idx| {
            out_events[idx] = .{
                .fd = @intCast(ev.ident),
                .readable = ev.filter == std.c.EVFILT.READ,
            };
        }
        return @intCast(n);
    }
};

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
