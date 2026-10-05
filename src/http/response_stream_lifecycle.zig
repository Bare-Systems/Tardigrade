const std = @import("std");

/// Process-wide defaults for long-lived streamed HTTP responses (#841).
pub const DEFAULT_MAX_ACTIVE: u32 = 256;
pub const DEFAULT_RELOAD_TIMEOUT_MS: u32 = 30_000;

/// Parse the unsigned-decimal syntax shared by every response-stream config
/// path. `std.fmt.parseInt` also accepts signs and digit separators, which are
/// intentionally outside the operator-facing contract for these settings.
pub fn parseStrictU32(value: []const u8) ?u32 {
    if (value.len == 0) return null;
    for (value) |byte| if (byte < '0' or byte > '9') return null;
    return std.fmt.parseInt(u32, value, 10) catch null;
}

/// What a successful reload does to a response stream admitted by an older
/// configuration generation. The relay reads this from the admission
/// generation; a later generation cannot change an existing stream's policy.
pub const ReloadPolicy = enum {
    preserve,
    drain,

    pub fn parse(raw: []const u8) ?ReloadPolicy {
        const value = std.mem.trim(u8, raw, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(value, "preserve")) return .preserve;
        if (std.ascii.eqlIgnoreCase(value, "drain")) return .drain;
        return null;
    }
};

/// Top-level response-stream admission and reload policy.
pub const Config = struct {
    max_active: u32 = DEFAULT_MAX_ACTIVE,
    reload: ReloadPolicy = .preserve,
    reload_timeout_ms: u32 = DEFAULT_RELOAD_TIMEOUT_MS,
};

/// Per-location policy. Capacity remains process-wide; locations may only
/// override how streams admitted through them react to a successful reload.
pub const LocationOverrides = struct {
    reload: ?ReloadPolicy = null,
    reload_timeout_ms: ?u32 = null,

    pub fn resolve(self: LocationOverrides, global: Config) AdmissionPolicy {
        return .{
            .reload = self.reload orelse global.reload,
            .reload_timeout_ms = self.reload_timeout_ms orelse global.reload_timeout_ms,
        };
    }
};

/// Immutable policy captured when a stream is admitted.
pub const AdmissionPolicy = struct {
    reload: ReloadPolicy,
    reload_timeout_ms: u32,
};

/// Fixed-cardinality outcomes and close reasons shared by metrics and relays.
pub const AdmissionOutcome = enum { admitted, capacity };
pub const CloseReason = enum { client, upstream, timeout, reload, shutdown, capacity };

/// Race-safe process-wide slot accounting. Callers pass the cap from the
/// configuration generation doing the admission. If a reload lowers the cap
/// below the current count, new admissions fail until enough streams close.
pub const Lifecycle = struct {
    active: std.atomic.Value(u32) = .init(0),

    pub fn tryReserve(self: *Lifecycle, max_active: u32) bool {
        if (max_active == 0) return false;
        var current = self.active.load(.acquire);
        while (current < max_active) {
            if (self.active.cmpxchgWeak(current, current + 1, .acq_rel, .acquire)) |observed| {
                current = observed;
                continue;
            }
            return true;
        }
        return false;
    }

    pub fn release(self: *Lifecycle) void {
        const previous = self.active.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
    }

    pub fn activeCount(self: *const Lifecycle) u32 {
        return self.active.load(.acquire);
    }
};

test "strict u32 parsing accepts digits only (#841)" {
    try std.testing.expectEqual(@as(?u32, 0), parseStrictU32("0"));
    try std.testing.expectEqual(@as(?u32, 30_000), parseStrictU32("30000"));
    try std.testing.expectEqual(@as(?u32, null), parseStrictU32("+1"));
    try std.testing.expectEqual(@as(?u32, null), parseStrictU32("-0"));
    try std.testing.expectEqual(@as(?u32, null), parseStrictU32("1_000"));
    try std.testing.expectEqual(@as(?u32, null), parseStrictU32("1s"));
    try std.testing.expectEqual(@as(?u32, null), parseStrictU32("4294967296"));
    try std.testing.expectEqual(@as(?u32, null), parseStrictU32(""));
}

test "ReloadPolicy accepts preserve and drain only (#841)" {
    try std.testing.expectEqual(ReloadPolicy.preserve, ReloadPolicy.parse("preserve").?);
    try std.testing.expectEqual(ReloadPolicy.drain, ReloadPolicy.parse(" DRAIN ").?);
    try std.testing.expect(ReloadPolicy.parse("restart") == null);
    try std.testing.expect(ReloadPolicy.parse("") == null);
}

test "location response-stream policy overrides fields independently (#841)" {
    const global: Config = .{ .reload = .drain, .reload_timeout_ms = 12_000 };
    try std.testing.expectEqual(AdmissionPolicy{ .reload = .preserve, .reload_timeout_ms = 12_000 }, (LocationOverrides{ .reload = .preserve }).resolve(global));
    try std.testing.expectEqual(AdmissionPolicy{ .reload = .drain, .reload_timeout_ms = 50 }, (LocationOverrides{ .reload_timeout_ms = 50 }).resolve(global));
}

test "lifecycle reserves exactly the configured process-wide capacity (#841)" {
    var lifecycle: Lifecycle = .{};
    try std.testing.expect(lifecycle.tryReserve(2));
    try std.testing.expect(lifecycle.tryReserve(2));
    try std.testing.expect(!lifecycle.tryReserve(2));
    try std.testing.expectEqual(@as(u32, 2), lifecycle.activeCount());

    lifecycle.release();
    try std.testing.expect(lifecycle.tryReserve(1) == false);
    lifecycle.release();
    try std.testing.expect(lifecycle.tryReserve(1));
    lifecycle.release();
    try std.testing.expectEqual(@as(u32, 0), lifecycle.activeCount());
}

test "lifecycle refuses an invalid zero cap without changing accounting (#841)" {
    var lifecycle: Lifecycle = .{};
    try std.testing.expect(!lifecycle.tryReserve(0));
    try std.testing.expectEqual(@as(u32, 0), lifecycle.activeCount());
}

test "lifecycle never exceeds its cap under concurrent admission (#841)" {
    const Context = struct {
        lifecycle: *Lifecycle,
        start: *std.atomic.Value(bool),
        violations: *std.atomic.Value(u32),

        fn yieldBestEffort() void {
            std.Thread.yield() catch {
                // A scheduler hint is optional; admission correctness does not
                // depend on the platform accepting it.
            };
        }

        fn run(ctx: @This()) void {
            while (!ctx.start.load(.acquire)) yieldBestEffort();
            for (0..2_000) |_| {
                if (!ctx.lifecycle.tryReserve(4)) {
                    yieldBestEffort();
                    continue;
                }
                if (ctx.lifecycle.activeCount() > 4) _ = ctx.violations.fetchAdd(1, .monotonic);
                yieldBestEffort();
                ctx.lifecycle.release();
            }
        }
    };

    var lifecycle: Lifecycle = .{};
    var start = std.atomic.Value(bool).init(false);
    var violations = std.atomic.Value(u32).init(0);
    var threads: [8]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Context.run, .{Context{ .lifecycle = &lifecycle, .start = &start, .violations = &violations }});
    start.store(true, .release);
    for (threads) |thread| thread.join();

    try std.testing.expectEqual(@as(u32, 0), violations.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), lifecycle.activeCount());
}
