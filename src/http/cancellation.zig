const std = @import("std");
const builtin = @import("builtin");
const compat = @import("zig_compat");

/// Why a request stopped before completion.
pub const CancelReason = enum {
    timeout,
    client_disconnect,
    shutdown,
    upstream_timeout,
};

/// Lightweight cancellation primitive scoped to a single request.
///
/// Tracks both an explicit cancellation signal (e.g. client disconnect,
/// shutdown) and a wall-clock deadline. Both represent "stop now" from
/// the perspective of any code holding a pointer to this token.
///
/// Thread safety: `cancel()` and all read accessors are safe to call
/// from any thread. The token is intended to be stack-allocated in the
/// connection handler and passed by pointer to downstream functions.
pub const CancellationToken = struct {
    /// Absolute monotonic deadline in milliseconds (0 = no deadline).
    deadline_ms: i64,
    /// `0` while live; otherwise `1 + @intFromEnum(reason)` for the reason
    /// recorded by the first caller to cancel. Cancelled-ness and the reason
    /// are published together through this single atomic so a concurrent
    /// reader on another thread can never observe `isCancelled() == true`
    /// before the reason is visible (a plain `reason` field written after a
    /// separate atomic flag would race: `cancel()` may run on the QUIC
    /// reactor while a worker thread reads the token concurrently).
    state: std.atomic.Value(u8),

    const live_state: u8 = 0;

    pub fn init(deadline_ms: i64) CancellationToken {
        return .{
            .deadline_ms = deadline_ms,
            .state = std.atomic.Value(u8).init(live_state),
        };
    }

    /// Returns true if `cancel()` has been called.
    pub fn isCancelled(self: *const CancellationToken) bool {
        return self.state.load(.acquire) != live_state;
    }

    /// Returns the reason recorded by the first `cancel()` call, if any.
    pub fn cancelReason(self: *const CancellationToken) ?CancelReason {
        const code = self.state.load(.acquire);
        if (code == live_state) return null;
        return @enumFromInt(code - 1);
    }

    /// Returns true if the deadline has passed.
    pub fn isDeadlineExceeded(self: *const CancellationToken) bool {
        if (self.deadline_ms == 0) return false;
        return compat.milliTimestamp() >= self.deadline_ms;
    }

    /// Returns true if the request should stop (cancelled or past deadline).
    pub fn isStopped(self: *const CancellationToken) bool {
        return self.isCancelled() or self.isDeadlineExceeded();
    }

    /// Cancel the request. Only the first caller's reason is recorded.
    pub fn cancel(self: *CancellationToken, reason: CancelReason) void {
        const code: u8 = @as(u8, @intFromEnum(reason)) + 1;
        _ = self.state.cmpxchgStrong(live_state, code, .acq_rel, .acquire);
    }

    /// Milliseconds remaining until the deadline (0 if no deadline or already past).
    pub fn remainingMs(self: *const CancellationToken) u32 {
        if (self.deadline_ms == 0) return 0;
        const now = compat.milliTimestamp();
        if (now >= self.deadline_ms) return 0;
        const rem = self.deadline_ms - now;
        if (rem > std.math.maxInt(u32)) return std.math.maxInt(u32);
        return @intCast(rem);
    }

    /// Return the lesser of `fallback_ms` and the remaining deadline budget.
    ///
    /// When there is no deadline (`deadline_ms == 0`) the fallback is returned
    /// unchanged. When the deadline is already past, 1 ms is returned so that
    /// downstream socket operations time out immediately rather than blocking
    /// for the full fallback window.
    pub fn effectiveTimeoutMs(self: *const CancellationToken, fallback_ms: u32) u32 {
        if (self.deadline_ms == 0) return fallback_ms;
        const rem = self.remainingMs();
        if (rem == 0) return 1;
        return @min(rem, fallback_ms);
    }
};

// Tests

test "CancellationToken: no deadline, not cancelled" {
    const tok = CancellationToken.init(0);
    try std.testing.expect(!tok.isCancelled());
    try std.testing.expect(!tok.isDeadlineExceeded());
    try std.testing.expect(!tok.isStopped());
}

test "CancellationToken: explicit cancel records reason" {
    var tok = CancellationToken.init(0);
    tok.cancel(.timeout);
    try std.testing.expect(tok.isCancelled());
    try std.testing.expect(tok.isStopped());
    try std.testing.expectEqual(CancelReason.timeout, tok.cancelReason().?);
}

test "CancellationToken: cancel is idempotent, first reason wins" {
    var tok = CancellationToken.init(0);
    tok.cancel(.timeout);
    tok.cancel(.client_disconnect);
    try std.testing.expectEqual(CancelReason.timeout, tok.cancelReason().?);
}

test "CancellationToken: cross-thread cancel publishes reason before cancelled is visible" {
    if (builtin.single_threaded) return error.SkipZigTest;
    var tok = CancellationToken.init(0);
    const Ctx = struct {
        tok: *CancellationToken,
        fn run(ctx: *@This()) void {
            ctx.tok.cancel(.upstream_timeout);
        }
    };
    var ctx = Ctx{ .tok = &tok };
    const thread = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});
    defer thread.join();
    while (!tok.isCancelled()) {}
    try std.testing.expectEqual(CancelReason.upstream_timeout, tok.cancelReason().?);
}

test "CancellationToken: deadline in the past" {
    const tok = CancellationToken.init(1); // epoch + 1ms is always past
    try std.testing.expect(tok.isDeadlineExceeded());
    try std.testing.expect(tok.isStopped());
}

test "CancellationToken: effectiveTimeoutMs with no deadline returns fallback" {
    const tok = CancellationToken.init(0);
    try std.testing.expectEqual(@as(u32, 5000), tok.effectiveTimeoutMs(5000));
}

test "CancellationToken: effectiveTimeoutMs with past deadline returns 1" {
    const tok = CancellationToken.init(1);
    try std.testing.expectEqual(@as(u32, 1), tok.effectiveTimeoutMs(5000));
}
