//! Deterministic renewal scheduling policy for native ACME (#835 / A5).
//!
//! This module does no I/O and never mutates certificate generations. A5's
//! worker must recover committed generations via `acme.activate`, use this
//! policy to choose a deadline, then reuse `acme.orders.obtain` and A4's
//! verified persistence + atomic publication. Do not treat a computed due
//! time as permission to start overlapping orders.
//!
//! Time values are Unix seconds. Network deadlines and interruptible waiting
//! must use a monotonic clock in the future lifecycle worker.

const std = @import("std");

pub const seconds_per_day: i64 = 86_400;
pub const retry_floor_seconds: i64 = 5 * 60;
pub const retry_ceiling_seconds: i64 = 6 * 60 * 60;

pub const Error = error{
    InvalidRenewalWindow,
    InvalidCertificateValidity,
    InvalidJitter,
};

pub const CertificateValidity = struct {
    not_before: i64,
    not_after: i64,
};

pub const Input = struct {
    now: i64,
    certificate: ?CertificateValidity = null,
    /// Operator configured value, validated elsewhere as 1..60 days.
    renew_days_before_expiry: u32 = 30,
    /// The order-group name set no longer matches the active certificate.
    names_changed: bool = false,
    /// Persist this alongside the group to enforce a floor across restarts.
    last_attempt_at: ?i64 = null,
    /// Consecutive failed attempts (zero after a successful publish).
    failures: u32 = 0,
    /// A CA-supplied Retry-After, already parsed and validated by transport.
    retry_after_at: ?i64 = null,
    /// Injected by the caller for deterministic tests; production picks a
    /// bounded random value. This policy never reads wall-clock randomness.
    jitter_percent: i8 = 0,
};

pub const Decision = struct {
    /// Earliest permissible next attempt, not a guarantee that an order runs.
    next_attempt_at: i64,
    /// True when a short-lived certificate caused the one-third fallback.
    shortened_window: bool = false,
};

/// Per-attempt backoff starts at five minutes, doubles, and caps its *base*
/// delay at six hours. A separately supplied ±10% jitter is applied last.
pub fn backoffSeconds(failures: u32, jitter_percent: i8) Error!i64 {
    if (jitter_percent < -10 or jitter_percent > 10) return error.InvalidJitter;
    if (failures == 0) return 0;

    var delay: i64 = retry_floor_seconds;
    var remaining = failures - 1;
    while (remaining > 0 and delay < retry_ceiling_seconds) : (remaining -= 1) {
        delay = @min(delay * 2, retry_ceiling_seconds);
    }

    return @divTrunc(delay * (100 + @as(i64, jitter_percent)), 100);
}

/// Compute a renewal deadline from authenticated, committed certificate
/// validity. A missing certificate or changed name set is immediately due
/// unless bounded retry/cooldown policy postpones the next attempt.
///
/// Only the persistent worker may perform issuance; this pure helper neither
/// starts network work nor changes a live credential generation.
pub fn nextAttempt(input: Input) Error!Decision {
    if (input.renew_days_before_expiry < 1 or input.renew_days_before_expiry > 60) {
        return error.InvalidRenewalWindow;
    }
    if (input.jitter_percent < -10 or input.jitter_percent > 10) {
        return error.InvalidJitter;
    }

    var decision = Decision{ .next_attempt_at = input.now };
    if (input.certificate) |cert| {
        if (cert.not_after <= cert.not_before) return error.InvalidCertificateValidity;
        const lifetime = std.math.sub(i64, cert.not_after, cert.not_before) catch {
            return error.InvalidCertificateValidity;
        };

        var renewal_window = @as(i64, input.renew_days_before_expiry) * seconds_per_day;
        if (renewal_window >= lifetime) {
            renewal_window = @max(@divTrunc(lifetime, 3), 1);
            decision.shortened_window = true;
        }
        decision.next_attempt_at = cert.not_after - renewal_window;
    }

    if (input.names_changed) decision.next_attempt_at = input.now;

    // An existing valid certificate outside the window needs no retry yet.
    // Prior CA throttling is irrelevant after a fresh generation is issued.
    if (decision.next_attempt_at > input.now) return decision;

    // Apply a cross-restart failure floor, even if a crash happened before
    // a failure counter was durably updated. The future worker owns durable
    // last_attempt_at and must not reset it on reload.
    if (input.last_attempt_at) |last| {
        const effective_failures = @max(input.failures, 1);
        const backoff = try backoffSeconds(effective_failures, input.jitter_percent);
        decision.next_attempt_at = @max(decision.next_attempt_at, last +| backoff);
    }
    if (input.retry_after_at) |retry_after| {
        decision.next_attempt_at = @max(decision.next_attempt_at, retry_after);
    }

    decision.next_attempt_at = @max(decision.next_attempt_at, input.now);
    return decision;
}

test "ACME renewal: fresh generation sleeps until configured window" {
    const now: i64 = 1_700_000_000;
    const decision = try nextAttempt(.{
        .now = now,
        .certificate = .{
            .not_before = now,
            .not_after = now + 90 * seconds_per_day,
        },
        .renew_days_before_expiry = 30,
    });
    try std.testing.expectEqual(now + 60 * seconds_per_day, decision.next_attempt_at);
    try std.testing.expect(!decision.shortened_window);
}

test "ACME renewal: due, expired, and changed names request an immediate attempt" {
    const now: i64 = 1_700_000_000;
    for ([_]CertificateValidity{
        .{ .not_before = now - 60 * seconds_per_day, .not_after = now + 20 * seconds_per_day },
        .{ .not_before = now - 60 * seconds_per_day, .not_after = now - seconds_per_day },
    }) |validity| {
        const decision = try nextAttempt(.{ .now = now, .certificate = validity });
        try std.testing.expectEqual(now, decision.next_attempt_at);
    }
    const none = try nextAttempt(.{ .now = now });
    try std.testing.expectEqual(now, none.next_attempt_at);
    const changed = try nextAttempt(.{
        .now = now,
        .certificate = .{ .not_before = now, .not_after = now + 90 * seconds_per_day },
        .names_changed = true,
    });
    try std.testing.expectEqual(now, changed.next_attempt_at);
}

test "ACME renewal: short-lived generations use one third of validity" {
    const now: i64 = 1_700_000_000;
    const decision = try nextAttempt(.{
        .now = now,
        .certificate = .{ .not_before = now, .not_after = now + 15 * seconds_per_day },
    });
    try std.testing.expectEqual(now + 10 * seconds_per_day, decision.next_attempt_at);
    try std.testing.expect(decision.shortened_window);
}

test "ACME renewal: repeated failures back off with bounded jitter" {
    try std.testing.expectEqual(@as(i64, 0), try backoffSeconds(0, 0));
    try std.testing.expectEqual(@as(i64, 300), try backoffSeconds(1, 0));
    try std.testing.expectEqual(@as(i64, 600), try backoffSeconds(2, 0));
    try std.testing.expectEqual(@as(i64, 1200), try backoffSeconds(3, 0));
    try std.testing.expectEqual(@as(i64, 19_440), try backoffSeconds(30, -10));
    try std.testing.expectEqual(@as(i64, 23_760), try backoffSeconds(30, 10));

    const now: i64 = 1_700_000_000;
    const attempt = try nextAttempt(.{
        .now = now,
        .last_attempt_at = now - 100,
        .failures = 3,
    });
    try std.testing.expectEqual(now + 1100, attempt.next_attempt_at);
}

test "ACME renewal: a restart cannot evade the floor or CA Retry-After" {
    const now: i64 = 1_700_000_000;
    const floor = try nextAttempt(.{ .now = now, .last_attempt_at = now - 10 });
    try std.testing.expectEqual(now + 290, floor.next_attempt_at);

    const delayed = try nextAttempt(.{
        .now = now,
        .last_attempt_at = now - 10,
        .failures = 1,
        .retry_after_at = now + 4_000,
    });
    try std.testing.expectEqual(now + 4_000, delayed.next_attempt_at);

    const expired_floor = try nextAttempt(.{
        .now = now,
        .certificate = .{ .not_before = now - 60 * seconds_per_day, .not_after = now - 1 },
        .last_attempt_at = now,
    });
    try std.testing.expectEqual(now + retry_floor_seconds, expired_floor.next_attempt_at);
}

test "ACME renewal: malformed validity and input limits fail closed" {
    const now: i64 = 1_700_000_000;
    try std.testing.expectError(error.InvalidRenewalWindow, nextAttempt(.{ .now = now, .renew_days_before_expiry = 0 }));
    try std.testing.expectError(error.InvalidRenewalWindow, nextAttempt(.{ .now = now, .renew_days_before_expiry = 61 }));
    try std.testing.expectError(error.InvalidCertificateValidity, nextAttempt(.{
        .now = now,
        .certificate = .{ .not_before = now, .not_after = now },
    }));
    try std.testing.expectError(error.InvalidCertificateValidity, nextAttempt(.{
        .now = now,
        .certificate = .{ .not_before = std.math.minInt(i64), .not_after = std.math.maxInt(i64) },
    }));
    try std.testing.expectError(error.InvalidJitter, nextAttempt(.{ .now = now, .jitter_percent = 11 }));
    try std.testing.expectError(error.InvalidJitter, backoffSeconds(4, -11));
}
