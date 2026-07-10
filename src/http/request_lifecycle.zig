const std = @import("std");
const compat = @import("../zig_compat.zig");
const cancellation = @import("cancellation.zig");

pub const CancellationToken = cancellation.CancellationToken;
pub const CancelReason = cancellation.CancelReason;

/// Named checkpoints used in lifecycle logs.
pub const Phase = enum {
    headers_read,
    auth,
    routing,
    upstream_connect,
    upstream_response,
    response_write,

    pub fn label(self: Phase) []const u8 {
        return switch (self) {
            .headers_read => "headers_read",
            .auth => "auth",
            .routing => "routing",
            .upstream_connect => "upstream_connect",
            .upstream_response => "upstream_response",
            .response_write => "response_write",
        };
    }
};

/// Per-request lifecycle tracker.
///
/// Created once per request, immediately after the correlation ID is known.
/// Owns the CancellationToken and emits structured log lines for timeout
/// and cancellation events so they appear in a consistent format regardless
/// of where in the pipeline the termination occurs.
///
/// Stack-allocated in the connection handler; passed by pointer to middleware
/// and upstream functions.
pub const RequestLifecycle = struct {
    token: CancellationToken,
    /// Correlation ID — borrowed from the arena; valid for request lifetime.
    request_id: []const u8,
    /// Configured overall request timeout (stored for log context).
    total_timeout_ms: u32,
    /// Monotonic start time in milliseconds.
    started_ms: i64,

    /// Create a lifecycle with an optional overall timeout.
    ///
    /// When `total_timeout_ms` is 0 no deadline is set.
    pub fn init(request_id: []const u8, total_timeout_ms: u32) RequestLifecycle {
        const now = compat.milliTimestamp();
        const deadline: i64 = if (total_timeout_ms > 0) now + @as(i64, total_timeout_ms) else 0;
        return .{
            .token = CancellationToken.init(deadline),
            .request_id = request_id,
            .total_timeout_ms = total_timeout_ms,
            .started_ms = now,
        };
    }

    /// Elapsed milliseconds since the lifecycle was created.
    pub fn elapsedMs(self: *const RequestLifecycle) i64 {
        return compat.milliTimestamp() - self.started_ms;
    }

    /// Emit a structured log line when a request times out.
    pub fn logTimeout(self: *const RequestLifecycle, phase: []const u8) void {
        std.log.warn(
            "event=request_timeout request_id={s} phase={s} elapsed_ms={d} configured_timeout_ms={d}",
            .{ self.request_id, phase, self.elapsedMs(), self.total_timeout_ms },
        );
    }

    /// Emit a structured log line when a request is cancelled.
    pub fn logCancellation(self: *const RequestLifecycle, reason: CancelReason) void {
        std.log.warn(
            "event=request_cancelled request_id={s} reason={s} elapsed_ms={d}",
            .{ self.request_id, @tagName(reason), self.elapsedMs() },
        );
    }

    /// Convenience: check deadline and, if exceeded, cancel + log.
    ///
    /// Returns true when the deadline was newly exceeded so the caller can
    /// take the appropriate action (e.g. return a 408 / 504).
    pub fn checkDeadline(self: *RequestLifecycle, phase: Phase) bool {
        if (!self.token.isDeadlineExceeded()) return false;
        if (!self.token.isCancelled()) {
            self.token.cancel(.timeout);
            self.logTimeout(phase.label());
        }
        return true;
    }
};

// Tests

test "RequestLifecycle: no timeout, deadline is zero" {
    const lc = RequestLifecycle.init("req-1", 0);
    try std.testing.expectEqual(@as(i64, 0), lc.token.deadline_ms);
    try std.testing.expect(!lc.token.isStopped());
}

test "RequestLifecycle: timeout in the future, not yet stopped" {
    const lc = RequestLifecycle.init("req-2", 60_000);
    try std.testing.expect(lc.token.deadline_ms > 0);
    try std.testing.expect(!lc.token.isDeadlineExceeded());
}

test "RequestLifecycle: checkDeadline on past deadline cancels once and returns true" {
    // checkDeadline logs the timeout at warn level by design; keep the expected
    // line off stderr, where the zig build runner would render the passing step
    // with a red "failed command:" banner.
    const previous_log_level = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = previous_log_level;

    var lc = RequestLifecycle.init("req-3", 0);
    // Manually force an already-elapsed deadline.
    lc.token.deadline_ms = 1; // epoch+1ms is always in the past
    try std.testing.expect(lc.checkDeadline(.routing));
    try std.testing.expect(lc.token.isCancelled());
    try std.testing.expectEqual(CancelReason.timeout, lc.token.reason.?);
    // Second call: still true (deadline still past) but cancel was already set
    try std.testing.expect(lc.checkDeadline(.auth));
}

test "RequestLifecycle: elapsedMs is non-negative" {
    const lc = RequestLifecycle.init("req-4", 0);
    try std.testing.expect(lc.elapsedMs() >= 0);
}
