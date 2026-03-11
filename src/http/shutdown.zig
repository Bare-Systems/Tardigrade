const std = @import("std");

/// Global shutdown flag, checked by the server accept loop.
/// When set to true, the server exits its accept loop gracefully.
var shutdown_requested: bool = false;
var reload_requested: bool = false;
var upgrade_requested: bool = false;
var reopen_logs_requested: bool = false;

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

pub fn requestUpgrade() void {
    @atomicStore(bool, &upgrade_requested, true, .seq_cst);
}

pub fn isUpgradeRequested() bool {
    return @atomicLoad(bool, &upgrade_requested, .seq_cst);
}

pub fn consumeUpgradeRequested() bool {
    return @cmpxchgStrong(bool, &upgrade_requested, true, false, .seq_cst, .seq_cst) == null;
}

pub fn requestReopenLogs() void {
    @atomicStore(bool, &reopen_logs_requested, true, .seq_cst);
}

pub fn isReopenLogsRequested() bool {
    return @atomicLoad(bool, &reopen_logs_requested, .seq_cst);
}

pub fn consumeReopenLogsRequested() bool {
    return @cmpxchgStrong(bool, &reopen_logs_requested, true, false, .seq_cst, .seq_cst) == null;
}

/// Reset the shutdown flag (for testing).
pub fn reset() void {
    @atomicStore(bool, &shutdown_requested, false, .seq_cst);
    @atomicStore(bool, &reload_requested, false, .seq_cst);
    @atomicStore(bool, &upgrade_requested, false, .seq_cst);
    @atomicStore(bool, &reopen_logs_requested, false, .seq_cst);
}

/// Install signal handlers for SIGTERM, SIGINT, SIGHUP, SIGUSR1 and SIGUSR2.
/// On receipt, sets the shutdown flag so the accept loop exits cleanly.
pub fn installSignalHandlers() void {
    const handler = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };

    std.posix.sigaction(std.posix.SIG.TERM, &handler, null);
    std.posix.sigaction(std.posix.SIG.INT, &handler, null);
    std.posix.sigaction(std.posix.SIG.HUP, &handler, null);
    std.posix.sigaction(std.posix.SIG.USR1, &handler, null);
    std.posix.sigaction(std.posix.SIG.USR2, &handler, null);
}

fn handleSignal(sig: c_int) callconv(.c) void {
    if (sig == std.posix.SIG.HUP) {
        @atomicStore(bool, &reload_requested, true, .seq_cst);
    } else if (sig == std.posix.SIG.USR1) {
        @atomicStore(bool, &reopen_logs_requested, true, .seq_cst);
    } else if (sig == std.posix.SIG.USR2) {
        @atomicStore(bool, &upgrade_requested, true, .seq_cst);
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

test "requestUpgrade sets upgrade flag" {
    reset();
    requestUpgrade();
    try std.testing.expect(isUpgradeRequested());
    try std.testing.expect(consumeUpgradeRequested());
    try std.testing.expect(!isUpgradeRequested());
}

test "requestReopenLogs sets reopen flag" {
    reset();
    requestReopenLogs();
    try std.testing.expect(isReopenLogsRequested());
    try std.testing.expect(consumeReopenLogsRequested());
    try std.testing.expect(!isReopenLogsRequested());
}

test "reset clears the flag" {
    requestShutdown();
    try std.testing.expect(isShutdownRequested());
    reset();
    try std.testing.expect(!isShutdownRequested());
}
