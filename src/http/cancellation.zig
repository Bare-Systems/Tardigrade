const std = @import("std");
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
    /// Set once when the request is explicitly cancelled.
    cancelled: std.atomic.Value(bool),
    /// Reason recorded at cancellation time.
    reason: ?CancelReason,

    pub fn init(deadline_ms: i64) CancellationToken {
        return .{
            .deadline_ms = deadline_ms,
            .cancelled = std.atomic.Value(bool).init(false),
            .reason = null,
        };
    }

    /// Returns true if `cancel()` has been called.
    pub fn isCancelled(self: *const CancellationToken) bool {
        return self.cancelled.load(.seq_cst);
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
        if (self.cancelled.cmpxchgStrong(false, true, .seq_cst, .seq_cst) == null) {
            self.reason = reason;
        }
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
    try std.testing.expectEqual(CancelReason.timeout, tok.reason.?);
}

test "CancellationToken: cancel is idempotent, first reason wins" {
    var tok = CancellationToken.init(0);
    tok.cancel(.timeout);
    tok.cancel(.client_disconnect);
    try std.testing.expectEqual(CancelReason.timeout, tok.reason.?);
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
