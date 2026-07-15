const std = @import("std");

pub const Direction = enum {
    downstream_to_upstream,
    upstream_to_downstream,

    pub fn label(self: Direction) []const u8 {
        return switch (self) {
            .downstream_to_upstream => "downstream_to_upstream",
            .upstream_to_downstream => "upstream_to_downstream",
        };
    }
};

pub const Scope = enum {
    stream,
    connection,
    origin,
    global,

    pub fn label(self: Scope) []const u8 {
        return switch (self) {
            .stream => "stream",
            .connection => "connection",
            .origin => "origin",
            .global => "global",
        };
    }
};

pub const Limits = struct {
    per_stream_low_watermark: usize,
    per_stream_high_watermark: usize,
    per_stream_hard_limit: usize,
    per_origin_hard_limit: usize,
    global_hard_limit: usize,

    pub fn validate(self: Limits) !void {
        if (self.per_stream_low_watermark == 0 or
            self.per_stream_high_watermark == 0 or
            self.per_stream_hard_limit == 0)
        {
            return error.InvalidBufferLimits;
        }
        if (!(self.per_stream_low_watermark < self.per_stream_high_watermark and
            self.per_stream_high_watermark <= self.per_stream_hard_limit))
        {
            return error.InvalidBufferLimits;
        }
        if (self.per_origin_hard_limit != 0 and self.per_origin_hard_limit < self.per_stream_hard_limit) {
            return error.InvalidBufferLimits;
        }
        if (self.global_hard_limit != 0 and self.global_hard_limit < self.per_stream_hard_limit) {
            return error.InvalidBufferLimits;
        }
    }
};

pub const Snapshot = struct {
    current: usize,
    high_watermark_events: u64,
    limit_exceeded_events: u64,
    above_high_watermark: bool,
};

pub const Observer = struct {
    context: *anyopaque,
    recordReservationFn: *const fn (*anyopaque, Direction, usize, bool, bool) void,
    releaseReservationFn: *const fn (*anyopaque, Direction, usize) void,

    pub fn recordReservation(self: Observer, direction: Direction, bytes: usize, high_watermark: bool, limit_exceeded: bool) void {
        self.recordReservationFn(self.context, direction, bytes, high_watermark, limit_exceeded);
    }

    pub fn releaseReservation(self: Observer, direction: Direction, bytes: usize) void {
        self.releaseReservationFn(self.context, direction, bytes);
    }
};

/// Small owner-local accounting primitive for bytes currently retained by a
/// proxy body buffer or queue. Shared aggregate accounting remains outside this
/// type; callers record this object's transitions into the process metrics.
pub const Account = struct {
    direction: Direction,
    scope: Scope,
    limits: Limits,
    current: usize = 0,
    high_watermark_events: u64 = 0,
    limit_exceeded_events: u64 = 0,
    above_high_watermark: bool = false,

    pub fn init(direction: Direction, scope: Scope, limits: Limits) Account {
        std.debug.assert(scope == .stream);
        return .{
            .direction = direction,
            .scope = scope,
            .limits = limits,
        };
    }

    pub fn reserve(self: *Account, bytes: usize) !void {
        const next = std.math.add(usize, self.current, bytes) catch {
            self.limit_exceeded_events += 1;
            return error.BufferLimitExceeded;
        };
        if (next > self.limits.per_stream_hard_limit) {
            self.limit_exceeded_events += 1;
            return error.BufferLimitExceeded;
        }
        self.current = next;
        if (!self.above_high_watermark and self.current >= self.limits.per_stream_high_watermark) {
            self.above_high_watermark = true;
            self.high_watermark_events += 1;
        }
    }

    pub fn release(self: *Account, bytes: usize) !void {
        if (bytes > self.current) return error.BufferAccountingUnderflow;
        self.current -= bytes;
        if (self.above_high_watermark and self.current <= self.limits.per_stream_low_watermark) {
            self.above_high_watermark = false;
        }
    }

    pub fn releaseAll(self: *Account) void {
        self.current = 0;
        self.above_high_watermark = false;
    }

    pub fn snapshot(self: *const Account) Snapshot {
        return .{
            .current = self.current,
            .high_watermark_events = self.high_watermark_events,
            .limit_exceeded_events = self.limit_exceeded_events,
            .above_high_watermark = self.above_high_watermark,
        };
    }
};

test "proxy buffer account validates low high hard ordering" {
    try (Limits{
        .per_stream_low_watermark = 4,
        .per_stream_high_watermark = 8,
        .per_stream_hard_limit = 16,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    }).validate();

    try std.testing.expectError(error.InvalidBufferLimits, (Limits{
        .per_stream_low_watermark = 8,
        .per_stream_high_watermark = 8,
        .per_stream_hard_limit = 16,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    }).validate());

    try std.testing.expectError(error.InvalidBufferLimits, (Limits{
        .per_stream_low_watermark = 4,
        .per_stream_high_watermark = 8,
        .per_stream_hard_limit = 16,
        .per_origin_hard_limit = 12,
        .global_hard_limit = 0,
    }).validate());
}

test "proxy buffer account tracks high low transitions and release" {
    const limits = Limits{
        .per_stream_low_watermark = 4,
        .per_stream_high_watermark = 8,
        .per_stream_hard_limit = 16,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    var account = Account.init(.upstream_to_downstream, .stream, limits);

    try account.reserve(7);
    try std.testing.expectEqual(@as(usize, 7), account.snapshot().current);
    try std.testing.expect(!account.snapshot().above_high_watermark);

    try account.reserve(1);
    try std.testing.expect(account.snapshot().above_high_watermark);
    try std.testing.expectEqual(@as(u64, 1), account.snapshot().high_watermark_events);

    try account.release(3);
    try std.testing.expect(account.snapshot().above_high_watermark);
    try account.release(1);
    try std.testing.expect(!account.snapshot().above_high_watermark);

    try std.testing.expectError(error.BufferLimitExceeded, account.reserve(17));
    try std.testing.expectEqual(@as(u64, 1), account.snapshot().limit_exceeded_events);
    account.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), account.snapshot().current);
}

test "proxy buffer account reports over-release without changing current" {
    const limits = Limits{
        .per_stream_low_watermark = 4,
        .per_stream_high_watermark = 8,
        .per_stream_hard_limit = 16,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    var account = Account.init(.upstream_to_downstream, .stream, limits);

    try account.reserve(6);
    try std.testing.expectError(error.BufferAccountingUnderflow, account.release(7));
    try std.testing.expectEqual(@as(usize, 6), account.snapshot().current);
}
