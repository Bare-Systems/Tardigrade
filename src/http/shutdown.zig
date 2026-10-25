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
    notifyShutdownWaiters();
}

// #863 review: `isShutdownRequested` is a plain atomic flag with no fd a
// blocked `poll()` call can observe, so a connection already parked inside
// its blocking wait when `requestShutdown` fires elsewhere cannot notice
// until something else wakes it (peer traffic, or its own prior timeout
// elapsing) -- the per-connection drain deadline installed once the H2
// loop *does* notice is not itself a bound on how long that first notice
// can take. This self-pipe (same `pipe()` + nonblocking-read-end shape
// `h2_outbound_scheduler.Scheduler` already uses for its own wake fd) lets
// any connection's blocking wait include a real fd in its own poll set, so
// `requestShutdown` wakes it immediately instead of only being checked at
// the next loop iteration that happens to run anyway.
var shutdown_notify_read: std.posix.fd_t = -1;
var shutdown_notify_write: std.posix.fd_t = -1;
var shutdown_notify_init: std.atomic.Value(bool) = .init(false);

/// Lazily creates the self-pipe above. Idempotent and safe to call from
/// multiple threads (e.g. once per connection, from inside its own
/// blocking-wait helper) before reading `shutdownNotifyReadFd`. A failed
/// `pipe()` leaves both fds at -1, which callers already treat as an
/// always-ignored poll slot, so this degrades to the pre-#863 best-effort
/// behavior rather than erroring.
pub fn ensureShutdownNotifyPipe() void {
    if (shutdown_notify_init.swap(true, .acq_rel)) return;
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.pipe(&fds) != 0) return;
    const flags = std.c.fcntl(fds[0], std.c.F.GETFL, @as(c_int, 0));
    if (flags < 0 or std.c.fcntl(fds[0], std.c.F.SETFL, flags | @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }))) < 0) {
        _ = std.c.close(fds[0]);
        _ = std.c.close(fds[1]);
        return;
    }
    shutdown_notify_read = fds[0];
    shutdown_notify_write = fds[1];
}

/// -1 until `ensureShutdownNotifyPipe` has run (and succeeded); every
/// caller already treats -1 as an always-ignored poll slot.
pub fn shutdownNotifyReadFd() std.posix.fd_t {
    return shutdown_notify_read;
}

fn notifyShutdownWaiters() void {
    if (shutdown_notify_write < 0) return;
    // Deliberately never drained in normal operation: once a shutdown is
    // requested, every connection's blocking wait should keep observing
    // this fd as readable (never block on it again) for the rest of the
    // process's life -- the process is exiting, not leaking a long-lived
    // resource -- rather than only the one wait call that happened to be
    // blocked at the exact moment this fired.
    var byte = [1]u8{1};
    _ = std.c.write(shutdown_notify_write, &byte, 1);
}

/// Test-only: drains any pending byte so `reset()` leaves a clean slate.
/// Every test in this binary shares the same process-wide pipe once
/// `ensureShutdownNotifyPipe` has run anywhere, so a byte written by one
/// test's `requestShutdown` must not stay readable for an unrelated test's
/// own later blocking wait.
fn drainShutdownNotifyPipe() void {
    if (shutdown_notify_read < 0) return;
    var buf: [8]u8 = undefined;
    while (std.c.read(shutdown_notify_read, &buf, buf.len) > 0) {}
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
    drainShutdownNotifyPipe();
}

/// Install signal handlers for SIGTERM, SIGINT, SIGHUP, SIGUSR1 and SIGUSR2.
/// On receipt, sets the shutdown flag so the accept loop exits cleanly.
pub fn installSignalHandlers() void {
    const handler = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    std.posix.sigaction(std.posix.SIG.TERM, &handler, null);
    std.posix.sigaction(std.posix.SIG.INT, &handler, null);
    std.posix.sigaction(std.posix.SIG.HUP, &handler, null);
    std.posix.sigaction(std.posix.SIG.USR1, &handler, null);
    std.posix.sigaction(std.posix.SIG.USR2, &handler, null);
}

fn handleSignal(sig: std.c.SIG) callconv(.c) void {
    if (sig == std.posix.SIG.HUP) {
        @atomicStore(bool, &reload_requested, true, .seq_cst);
    } else if (sig == std.posix.SIG.USR1) {
        @atomicStore(bool, &reopen_logs_requested, true, .seq_cst);
    } else if (sig == std.posix.SIG.USR2) {
        @atomicStore(bool, &upgrade_requested, true, .seq_cst);
    } else {
        @atomicStore(bool, &shutdown_requested, true, .seq_cst);
        // `std.c.write` on an already-nonblocking fd is on the standard
        // async-signal-safe function list, unlike most of this module's
        // other call sites, so calling it directly from the signal handler
        // itself (not just from `requestShutdown`'s programmatic path) is
        // safe.
        notifyShutdownWaiters();
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

test "#863: requestShutdown wakes a blocked poll() on shutdownNotifyReadFd immediately" {
    reset();
    ensureShutdownNotifyPipe();
    const read_fd = shutdownNotifyReadFd();
    try std.testing.expect(read_fd >= 0);

    var fds = [_]std.posix.pollfd{.{ .fd = read_fd, .events = std.posix.POLL.IN, .revents = 0 }};
    // Nothing has requested shutdown yet: a bounded poll should see no
    // event and simply time out, not already-ready from some earlier
    // test's stale byte -- `reset()` above is what guarantees that.
    try std.testing.expectEqual(@as(usize, 0), try std.posix.poll(&fds, 50));

    requestShutdown();
    fds[0].revents = 0;
    try std.testing.expectEqual(@as(usize, 1), try std.posix.poll(&fds, 5_000));
    try std.testing.expect((fds[0].revents & std.posix.POLL.IN) != 0);

    reset();
    fds[0].revents = 0;
    // `reset()` drained the pipe, so a connection's wait that starts after
    // an unrelated earlier test's shutdown must still actually block
    // rather than spuriously firing on a leftover byte.
    try std.testing.expectEqual(@as(usize, 0), try std.posix.poll(&fds, 50));
}
