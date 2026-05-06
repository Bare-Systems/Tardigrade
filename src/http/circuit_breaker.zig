const std = @import("std");
const compat = @import("../zig_compat.zig");

/// Circuit breaker states.
///
/// Closed → normal operation, requests pass through.
/// Open   → upstream considered down; requests fast-fail without calling upstream.
/// Half-Open → testing recovery; one probe request allowed; success closes, failure re-opens.
pub const State = enum { closed, open, half_open };

/// Circuit breaker configuration.
pub const Config = struct {
    /// Number of consecutive failures before opening the circuit (0 = disabled).
    threshold: u32 = 5,
    /// Number of successful probe requests needed to close from half-open.
    half_open_successes: u32 = 1,
    /// Milliseconds to wait in open state before transitioning to half-open.
    timeout_ms: u64 = 30_000,
};

/// Upstream circuit breaker.
///
/// Tracks failure/success rates and transitions between states to prevent
/// cascading failures when the upstream is unhealthy.
pub const CircuitBreaker = struct {
    state: State,
    failure_count: u32,
    success_count: u32,
    /// Nanosecond timestamp of the last recorded failure.
    last_failure_ns: i128,
    config: Config,

    /// Create a circuit breaker with the given config.
    pub fn init(config: Config) CircuitBreaker {
        return .{
            .state = .closed,
            .failure_count = 0,
            .success_count = 0,
            .last_failure_ns = 0,
            .config = config,
        };
    }

    /// Returns whether a request may proceed to the upstream.
    ///
    /// Side effects: if the circuit is open and the recovery timeout has
    /// elapsed, transitions to half-open and allows one probe through.
    pub fn tryAcquire(self: *CircuitBreaker) bool {
        if (self.config.threshold == 0) return true; // disabled

        return switch (self.state) {
            .closed => true,
            .open => blk: {
                const now = compat.nanoTimestamp();
                const elapsed_ns = now - self.last_failure_ns;
                if (elapsed_ns < 0) break :blk false;
                const elapsed_ms: u64 = @intCast(@divFloor(elapsed_ns, std.time.ns_per_ms));
                if (elapsed_ms >= self.config.timeout_ms) {
                    self.state = .half_open;
                    self.success_count = 0;
                    break :blk true;
                }
                break :blk false;
            },
            .half_open => self.success_count < self.config.half_open_successes,
        };
    }

    /// Record a successful upstream call.
    pub fn recordSuccess(self: *CircuitBreaker) void {
        if (self.config.threshold == 0) return;

        switch (self.state) {
            .closed => self.failure_count = 0,
            .half_open => {
                self.success_count += 1;
                if (self.success_count >= self.config.half_open_successes) {
                    self.state = .closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                }
            },
            .open => {},
        }
    }

    /// Record a failed upstream call (connection error or 5xx).
    pub fn recordFailure(self: *CircuitBreaker) void {
        if (self.config.threshold == 0) return;

        self.last_failure_ns = compat.nanoTimestamp();
        switch (self.state) {
            .closed => {
                self.failure_count += 1;
                if (self.failure_count >= self.config.threshold) {
                    self.state = .open;
                }
            },
            .half_open => self.state = .open,
            .open => {},
        }
    }

    /// Human-readable state label for logging.
    pub fn stateName(self: *const CircuitBreaker) []const u8 {
        return switch (self.state) {
            .closed => "closed",
            .open => "open",
            .half_open => "half-open",
        };
    }
};

// Tests

test "circuit breaker starts closed" {
    var cb = CircuitBreaker.init(.{});
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expect(cb.tryAcquire());
}

test "circuit breaker opens after threshold failures" {
    var cb = CircuitBreaker.init(.{ .threshold = 3 });

    cb.recordFailure();
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expect(cb.tryAcquire());

    cb.recordFailure();
    try std.testing.expectEqual(State.closed, cb.state);

    cb.recordFailure();
    try std.testing.expectEqual(State.open, cb.state);
    try std.testing.expect(!cb.tryAcquire());
}

test "circuit breaker success resets failure count" {
    var cb = CircuitBreaker.init(.{ .threshold = 3 });
    cb.recordFailure();
    cb.recordFailure();
    cb.recordSuccess();
    try std.testing.expectEqual(@as(u32, 0), cb.failure_count);
    try std.testing.expectEqual(State.closed, cb.state);
}

test "circuit breaker disabled when threshold is 0" {
    var cb = CircuitBreaker.init(.{ .threshold = 0 });
    cb.recordFailure();
    cb.recordFailure();
    cb.recordFailure();
    try std.testing.expectEqual(State.closed, cb.state);
    try std.testing.expect(cb.tryAcquire());
}

test "circuit breaker half-open closes on success" {
    var cb = CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0, .half_open_successes = 1 });
    cb.recordFailure();
    try std.testing.expectEqual(State.open, cb.state);

    // With timeout_ms = 0, tryAcquire should move to half-open immediately
    const available = cb.tryAcquire();
    try std.testing.expectEqual(State.half_open, cb.state);
    try std.testing.expect(available);

    cb.recordSuccess();
    try std.testing.expectEqual(State.closed, cb.state);
}

test "circuit breaker half-open re-opens on failure" {
    var cb = CircuitBreaker.init(.{ .threshold = 1, .timeout_ms = 0 });
    cb.recordFailure();
    _ = cb.tryAcquire(); // transition to half-open
    try std.testing.expectEqual(State.half_open, cb.state);

    cb.recordFailure();
    try std.testing.expectEqual(State.open, cb.state);
}

test "stateName returns correct labels" {
    var cb = CircuitBreaker.init(.{ .threshold = 1 });
    try std.testing.expectEqualStrings("closed", cb.stateName());
    cb.recordFailure();
    try std.testing.expectEqualStrings("open", cb.stateName());
}
