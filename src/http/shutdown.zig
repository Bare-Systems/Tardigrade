const std = @import("std");

/// Global shutdown flag, checked by the server accept loop.
/// When set to true, the server exits its accept loop gracefully.
var shutdown_requested: bool = false;

/// Returns whether a graceful shutdown has been requested.
pub fn isShutdownRequested() bool {
    return @atomicLoad(&shutdown_requested);
}

/// Manually request a shutdown (for testing or programmatic use).
pub fn requestShutdown() void {
    @atomicStore(&shutdown_requested, true);
}

/// Reset the shutdown flag (for testing).
pub fn reset() void {
    @atomicStore(&shutdown_requested, false);
}

/// Install signal handlers for SIGTERM and SIGINT.
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
}

fn handleSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    @atomicStore(&shutdown_requested, true);
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

test "reset clears the flag" {
    requestShutdown();
    try std.testing.expect(isShutdownRequested());
    reset();
    try std.testing.expect(!isShutdownRequested());
}
