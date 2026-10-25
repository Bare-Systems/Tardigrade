//! Real, process-wide H2 session/queue/flow-control counters for #863's
//! real-process transport validation evidence.
//!
//! Free-standing atomics, not threaded through `GatewayState.metrics_mutex`
//! or any `state` pointer: several call sites that need to update these
//! (`h2DetachSession`, `h2SettleAllSessions`, `flushHttp2SessionOutbound`)
//! only ever see `writer`/`sessions`/`allocator`/a bare `Scheduler`, never
//! `GatewayState` itself. Same free-standing-global shape `http/shutdown.zig`
//! already uses for its own process-wide flags.
const std = @import("std");

var active_sessions: std.atomic.Value(i64) = std.atomic.Value(i64).init(0);
var session_queued_bytes: std.atomic.Value(i64) = std.atomic.Value(i64).init(0);
var session_queued_bytes_high_water: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var writer_queue_bytes: std.atomic.Value(i64) = std.atomic.Value(i64).init(0);
var writer_queue_bytes_high_water: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var flow_control_blocked_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var flow_control_resumed_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var session_close_goaway_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var session_close_connection_closed_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var session_close_shutdown_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
/// Mid-connection-lifetime session teardown (ordinary end, RST_STREAM,
/// consumer wake failure) via `h2DetachSession` -- as opposed to the whole-
/// connection-teardown reasons above, which only ever fire from
/// `h2SettleAllSessions`. Not split further: `h2DetachSession` itself is
/// called from several different frame-level conditions without an
/// explicit reason parameter, and splitting those apart is out of scope
/// here.
var session_close_detached_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

fn bumpHighWater(high_water: *std.atomic.Value(u64), current: i64) void {
    if (current <= 0) return;
    const cur: u64 = @intCast(current);
    var prev = high_water.load(.monotonic);
    while (cur > prev) {
        prev = high_water.cmpxchgWeak(prev, cur, .monotonic, .monotonic) orelse return;
    }
}

pub fn sessionAttached() void {
    _ = active_sessions.fetchAdd(1, .monotonic);
}

pub fn sessionDetached() void {
    _ = active_sessions.fetchSub(1, .monotonic);
}

pub const SessionCloseReason = enum { goaway, connection_closed, shutdown, detached };

pub fn sessionClosed(reason: SessionCloseReason) void {
    switch (reason) {
        .goaway => _ = session_close_goaway_total.fetchAdd(1, .monotonic),
        .connection_closed => _ = session_close_connection_closed_total.fetchAdd(1, .monotonic),
        .shutdown => _ = session_close_shutdown_total.fetchAdd(1, .monotonic),
        .detached => _ = session_close_detached_total.fetchAdd(1, .monotonic),
    }
}

/// `delta` is the signed change in a #867 session's reserved
/// (`HTTP2_SESSION_RESERVED_BYTES`) share of the connection memory budget --
/// positive on attach, negative on detach.
pub fn sessionQueuedBytesChanged(delta: i64) void {
    const new_val = session_queued_bytes.fetchAdd(delta, .monotonic) + delta;
    bumpHighWater(&session_queued_bytes_high_water, new_val);
}

/// Snapshot of `Scheduler.queued_bytes` for one connection's outbound
/// writer queue, taken once per H2 connection-loop iteration (not on every
/// mutation inside the scheduler itself, to avoid touching its
/// concurrency-sensitive hot path) and published here so the process-wide
/// high-water mark reflects real queued bytes across every live connection,
/// even though each connection's `Scheduler` is otherwise never visible
/// outside the connection that owns it.
pub fn publishWriterQueueBytes(connection_queued_bytes: usize) void {
    const val: i64 = @intCast(@min(connection_queued_bytes, std.math.maxInt(i64)));
    _ = writer_queue_bytes.store(val, .monotonic);
    bumpHighWater(&writer_queue_bytes_high_water, val);
}

pub fn flowControlBlocked() void {
    _ = flow_control_blocked_total.fetchAdd(1, .monotonic);
}

pub fn flowControlResumed() void {
    _ = flow_control_resumed_total.fetchAdd(1, .monotonic);
}

pub const Snapshot = struct {
    active_sessions: u64,
    session_queued_bytes: u64,
    session_queued_bytes_high_water: u64,
    writer_queue_bytes: u64,
    writer_queue_bytes_high_water: u64,
    flow_control_blocked_total: u64,
    flow_control_resumed_total: u64,
    session_close_goaway_total: u64,
    session_close_connection_closed_total: u64,
    session_close_shutdown_total: u64,
    session_close_detached_total: u64,
};

pub fn snapshot() Snapshot {
    return .{
        .active_sessions = @intCast(@max(0, active_sessions.load(.monotonic))),
        .session_queued_bytes = @intCast(@max(0, session_queued_bytes.load(.monotonic))),
        .session_queued_bytes_high_water = session_queued_bytes_high_water.load(.monotonic),
        .writer_queue_bytes = @intCast(@max(0, writer_queue_bytes.load(.monotonic))),
        .writer_queue_bytes_high_water = writer_queue_bytes_high_water.load(.monotonic),
        .flow_control_blocked_total = flow_control_blocked_total.load(.monotonic),
        .flow_control_resumed_total = flow_control_resumed_total.load(.monotonic),
        .session_close_goaway_total = session_close_goaway_total.load(.monotonic),
        .session_close_connection_closed_total = session_close_connection_closed_total.load(.monotonic),
        .session_close_shutdown_total = session_close_shutdown_total.load(.monotonic),
        .session_close_detached_total = session_close_detached_total.load(.monotonic),
    };
}

/// Test-only: every counter here is a process-wide global shared by every
/// test in this binary (same convention as `http.shutdown.reset`), so a
/// test asserting on absolute values (not just deltas) must reset first.
pub fn resetForTesting() void {
    active_sessions.store(0, .monotonic);
    session_queued_bytes.store(0, .monotonic);
    session_queued_bytes_high_water.store(0, .monotonic);
    writer_queue_bytes.store(0, .monotonic);
    writer_queue_bytes_high_water.store(0, .monotonic);
    flow_control_blocked_total.store(0, .monotonic);
    flow_control_resumed_total.store(0, .monotonic);
    session_close_goaway_total.store(0, .monotonic);
    session_close_connection_closed_total.store(0, .monotonic);
    session_close_shutdown_total.store(0, .monotonic);
    session_close_detached_total.store(0, .monotonic);
}

test "sessionAttached/sessionDetached track a signed active count" {
    resetForTesting();
    sessionAttached();
    sessionAttached();
    sessionDetached();
    try std.testing.expectEqual(@as(u64, 1), snapshot().active_sessions);
}

test "sessionQueuedBytesChanged tracks current value and a monotonic high water mark" {
    resetForTesting();
    sessionQueuedBytesChanged(100);
    sessionQueuedBytesChanged(50);
    sessionQueuedBytesChanged(-80);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 70), s.session_queued_bytes);
    try std.testing.expectEqual(@as(u64, 150), s.session_queued_bytes_high_water);
}

test "publishWriterQueueBytes tracks current value and a monotonic high water mark" {
    resetForTesting();
    publishWriterQueueBytes(1000);
    publishWriterQueueBytes(200);
    publishWriterQueueBytes(600);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 600), s.writer_queue_bytes);
    try std.testing.expectEqual(@as(u64, 1000), s.writer_queue_bytes_high_water);
}

test "sessionClosed increments exactly the matching reason counter" {
    resetForTesting();
    sessionClosed(.goaway);
    sessionClosed(.goaway);
    sessionClosed(.shutdown);
    sessionClosed(.detached);
    sessionClosed(.connection_closed);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 2), s.session_close_goaway_total);
    try std.testing.expectEqual(@as(u64, 1), s.session_close_shutdown_total);
    try std.testing.expectEqual(@as(u64, 1), s.session_close_detached_total);
    try std.testing.expectEqual(@as(u64, 1), s.session_close_connection_closed_total);
}

test "flowControlBlocked/flowControlResumed are independent counters" {
    resetForTesting();
    flowControlBlocked();
    flowControlBlocked();
    flowControlResumed();
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 2), s.flow_control_blocked_total);
    try std.testing.expectEqual(@as(u64, 1), s.flow_control_resumed_total);
}
