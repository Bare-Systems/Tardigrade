const std = @import("std");

/// Global shutdown flag, checked by the server accept loop.
/// When set to true, the server exits its accept loop gracefully.
var shutdown_requested: bool = false;
var reload_requested: bool = false;

/// Returns whether a graceful shutdown has been requested.
pub fn isShutdownRequested() bool {
    return @atomicLoad(bool, &shutdown_requested, .seq_cst);
}

/// Manually request a shutdown (for testing or programmatic use).
pub fn requestShutdown() void {
    @atomicStore(bool, &shutdown_requested, true, .seq_cst);
}

pub fn requestReload() void {
    @atomicStore(bool, &reload_requested, true, .seq_cst);
}

pub fn isReloadRequested() bool {
    return @atomicLoad(bool, &reload_requested, .seq_cst);
}

pub fn consumeReloadRequested() bool {
    return @cmpxchgStrong(bool, &reload_requested, true, false, .seq_cst, .seq_cst) == null;
}

/// Reset the shutdown flag (for testing).
pub fn reset() void {
    @atomicStore(bool, &shutdown_requested, false, .seq_cst);
    @atomicStore(bool, &reload_requested, false, .seq_cst);
}

/// Install signal handlers for SIGTERM, SIGINT and SIGHUP.
/// On receipt, sets the shutdown flag so the accept loop exits cleanly.
pub fn installSignalHandlers() void {
    const handler = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };

    std.posix.sigaction(std.posix.SIG.TERM, &handler, null) catch |err| {
        std.log.warn("Failed to install SIGTERM handler: {}", .{err});
    };
    std.posix.sigaction(std.posix.SIG.INT, &handler, null) catch |err| {
        std.log.warn("Failed to install SIGINT handler: {}", .{err});
    };
    std.posix.sigaction(std.posix.SIG.HUP, &handler, null) catch |err| {
        std.log.warn("Failed to install SIGHUP handler: {}", .{err});
    };
}

fn handleSignal(sig: c_int) callconv(.c) void {
    if (sig == std.posix.SIG.HUP) {
        @atomicStore(bool, &reload_requested, true, .seq_cst);
    } else {
        @atomicStore(bool, &shutdown_requested, true, .seq_cst);
    }
}

// Tests

test "shutdown flag starts false" {
    reset();
    try std.testing.expect(!isShutdownRequested());
}

test "requestShutdown sets the flag" {
    reset();
    requestShutdown();
    try std.testing.expect(isShutdownRequested());
    reset();
}

test "requestReload sets reload flag" {
    reset();
    requestReload();
    try std.testing.expect(isReloadRequested());
    try std.testing.expect(consumeReloadRequested());
    try std.testing.expect(!isReloadRequested());
}

test "reset clears the flag" {
    requestShutdown();
    try std.testing.expect(isShutdownRequested());
    reset();
    try std.testing.expect(!isShutdownRequested());
}
