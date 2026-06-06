//! Listener accept-loop helpers. This module owns accepting ready sockets,
//! applying listener fd limits, and rejecting overloaded clients before they
//! enter the worker pool.

const builtin = @import("builtin");
const compat = @import("zig_compat.zig");
const std = @import("std");
const http = @import("http.zig");
const gc = @import("gateway_connection.zig");
const gs = @import("gateway_state.zig");

const GatewayState = gs.GatewayState;

pub fn acceptReadyConnections(listen_fd: std.posix.fd_t, worker_pool: *http.worker_pool.WorkerPool, state: *GatewayState) void {
    while (!http.shutdown.isShutdownRequested()) {
        var accepted_addr: std.c.sockaddr.storage = undefined;
        var addr_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);

        const client_fd = std.c.accept(listen_fd, @ptrCast(&accepted_addr), &addr_len);
        if (client_fd >= 0) {
            const flags = std.c.fcntl(client_fd, std.c.F.GETFL, @as(c_int, 0));
            if (flags >= 0) {
                const nonblock: c_int = @intCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
                _ = std.c.fcntl(client_fd, std.c.F.SETFL, flags | nonblock);
            }
            _ = std.c.fcntl(client_fd, std.c.F.SETFD, @as(c_int, 1)); // FD_CLOEXEC
        }
        if (client_fd < 0) {
            const e = std.posix.errno(client_fd);
            if (e == .AGAIN) return;
            if (e == .CONNABORTED) continue;
            state.logger.err(null, "accept error: {}", .{e});
            return;
        }

        const owned_ip_key = gc.clientIpKeyFromAddress(state.allocator, &accepted_addr) catch null;
        defer if (owned_ip_key) |key| state.allocator.free(key);
        const ip_key = owned_ip_key orelse "unknown";

        const slot_result = state.tryAcquireConnectionSlot(client_fd, ip_key) catch |err| {
            state.logger.warn(null, "connection slot tracking error: {}", .{err});
            _ = std.c.close(client_fd);
            continue;
        };
        switch (slot_result) {
            .accepted => {},
            .over_ip_limit => {
                state.logger.warn(null, "per-IP connection limit reached for {s}", .{ip_key});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
            .over_global_limit => {
                state.logger.warn(null, "global active connection limit reached", .{});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
            .over_global_memory_limit => {
                state.logger.warn(null, "global connection memory estimate limit reached", .{});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
        }

        worker_pool.submit(client_fd) catch |err| {
            state.logger.warn(null, "worker queue submit failed: {}", .{err});
            state.metricsRecordQueueRejection();
            state.metricsRecordErrorCode("overload");
            state.releaseConnectionSlot(client_fd);
            rejectOverloadedClient(client_fd);
            continue;
        };
    }
}

pub fn rejectOverloadedClient(client_fd: std.posix.fd_t) void {
    gc.setNonBlocking(client_fd, false) catch {}; // connection is usable in blocking mode; write and close still succeed
    const stream = compat.netStreamFromFd(client_fd);
    stream.writer().writeAll(
        "HTTP/1.1 503 Service Unavailable\r\n" ++
            "Connection: close\r\n" ++
            "Content-Length: 0\r\n" ++
            "Retry-After: 1\r\n" ++
            "\r\n",
    ) catch {}; // best-effort 503; client will time out if the write fails
    stream.close();
}

pub fn applyFdSoftLimit(desired: u64) !?u64 {
    if (desired == 0) return null;
    switch (builtin.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos, .ios, .tvos, .watchos, .visionos => {},
        else => return null,
    }

    var limits = try std.posix.getrlimit(std.posix.rlimit_resource.NOFILE);
    const current_soft: u64 = @intCast(limits.cur);
    const hard: u64 = @intCast(limits.max);
    const target: u64 = @min(desired, hard);
    if (target == current_soft) return target;

    limits.cur = @intCast(target);
    try std.posix.setrlimit(std.posix.rlimit_resource.NOFILE, limits);
    return target;
}
