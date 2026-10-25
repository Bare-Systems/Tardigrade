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
/// Every connection's `Scheduler` publishes its configured
/// `max_queued_bytes` here on `init` (#951 review). Production connections
/// all share the same constant (`h2_outbound_scheduler.default_max_queued_bytes`),
/// so repeated publication from multiple connections is idempotent; this
/// lets evidence/tests assert `writer_queue_bytes_high_water <= writer_queue_cap_bytes`
/// without importing `h2_outbound_scheduler.zig` here (which would otherwise
/// have to flow back through this module anyway).
var writer_queue_cap_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// #951 review: the aggregate gauges above prove a process-wide total, but
// cannot show *which* stream/connection is responsible for it, nor bound
// any individual stream's own queue against its configured cap --
// aggregating every live session together hides a single stream that
// exceeds its own share even while the total looks healthy. Each `Session`
// publishes its own identity and current byte counts into one of these
// fixed slots (claimed at `init`, released at `deinit`); nothing outside
// `h2_stream_session.zig` ever shares a `Session` pointer with this module,
// so there is no cross-thread lifetime hazard here, only plain atomics each
// slot's owning `Session` is the sole writer of (readers only ever see a
// consistent snapshot of already-published values, same as the aggregate
// counters above). Capacity is a generous fixed bound on concurrently
// tracked streams across the whole process, independent of any single
// connection's own (lower) concurrent-stream limit; a table overflow just
// means that one stream's per-stream detail is not tracked, not a
// correctness failure of the aggregate counters.
pub const MAX_TRACKED_STREAMS: usize = 256;

const SessionSlot = struct {
    in_use: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    inbound_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    outbound_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    high_water: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

var session_slots: [MAX_TRACKED_STREAMS]SessionSlot = [_]SessionSlot{.{}} ** MAX_TRACKED_STREAMS;

/// Claim a free slot for a newly created session. Idempotent-safe to skip
/// silently on table exhaustion (see `MAX_TRACKED_STREAMS` above).
pub fn sessionSlotRegister(stream_id: u31) void {
    for (&session_slots) |*slot| {
        if (slot.in_use.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
            slot.stream_id.store(stream_id, .release);
            slot.inbound_bytes.store(0, .release);
            slot.outbound_bytes.store(0, .release);
            slot.high_water.store(0, .release);
            return;
        }
    }
}

/// Publish this session's current queued-byte counts. Called from every
/// `h2_stream_session.zig` site that already mutates `inbound_bytes`/
/// `outbound_bytes` under `Session.mutex`, so these values are always a
/// real (not reserved-capacity) snapshot.
pub fn sessionSlotUpdate(stream_id: u31, inbound_bytes: usize, outbound_bytes: usize) void {
    for (&session_slots) |*slot| {
        if (slot.in_use.load(.acquire) and slot.stream_id.load(.acquire) == @as(u32, stream_id)) {
            const total: u64 = @intCast(inbound_bytes + outbound_bytes);
            slot.inbound_bytes.store(@intCast(inbound_bytes), .release);
            slot.outbound_bytes.store(@intCast(outbound_bytes), .release);
            var prev = slot.high_water.load(.monotonic);
            while (total > prev) {
                prev = slot.high_water.cmpxchgWeak(prev, total, .monotonic, .monotonic) orelse break;
            }
            return;
        }
    }
}

/// Release a session's slot. Safe to call even if `sessionSlotRegister`
/// never found a free slot for it (no-op).
pub fn sessionSlotUnregister(stream_id: u31) void {
    for (&session_slots) |*slot| {
        if (slot.in_use.load(.acquire) and slot.stream_id.load(.acquire) == @as(u32, stream_id)) {
            slot.in_use.store(false, .release);
            return;
        }
    }
}

pub const SessionSlotSnapshot = struct {
    stream_id: u31,
    queued_bytes: u64,
    queued_bytes_high_water: u64,
};

/// Copy every currently-registered slot into `buf`, returning the
/// filled prefix. Test/diagnostics-only.
pub fn snapshotSessionSlots(buf: []SessionSlotSnapshot) []SessionSlotSnapshot {
    var n: usize = 0;
    for (&session_slots) |*slot| {
        if (n >= buf.len) break;
        if (!slot.in_use.load(.acquire)) continue;
        buf[n] = .{
            .stream_id = @intCast(slot.stream_id.load(.acquire)),
            .queued_bytes = slot.inbound_bytes.load(.acquire) + slot.outbound_bytes.load(.acquire),
            .queued_bytes_high_water = slot.high_water.load(.acquire),
        };
        n += 1;
    }
    return buf[0..n];
}

/// Test-only: clears every slot so an earlier test's sessions (which may
/// never have reached `deinit` on a forcibly-leaked allocator failure path)
/// cannot leave a stream_id collision for a later test.
pub fn resetSessionSlotsForTesting() void {
    for (&session_slots) |*slot| slot.* = .{};
}

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

/// `delta` is the signed change in real bytes actually sitting in a #867
/// session's bounded inbound/outbound queues (`Session.inbound_bytes` +
/// `Session.outbound_bytes`), published from `h2_stream_session.zig` at
/// every enqueue (`deliverInbound`/`write`), dequeue (`read`/
/// `commitOutboundSent`), and settle (`settleLocked`, on reset/GOAWAY/
/// connection-closed/shutdown) -- not a static reserved-capacity share, so
/// an idle session reports 0 and a session queued up to its caps reports
/// the real occupied amount.
pub fn sessionQueuedBytesChanged(delta: i64) void {
    const new_val = session_queued_bytes.fetchAdd(delta, .monotonic) + delta;
    bumpHighWater(&session_queued_bytes_high_water, new_val);
}

/// `delta` is the signed change in one connection's `Scheduler.queued_bytes`,
/// published from `h2_outbound_scheduler.zig` at every real enqueue/flush/
/// cancel mutation (and on connection teardown, for whatever a torn-down
/// scheduler still held). Summing per-connection deltas into one aggregate
/// -- instead of each connection's own periodic sample overwriting the
/// last -- is what lets the process-wide value and high-water mark reflect
/// every live connection at once, and lets a peak that is enqueued and
/// drained within a single H2 loop iteration still register before the
/// matching decrement.
pub fn writerQueueBytesChanged(delta: i64) void {
    const new_val = writer_queue_bytes.fetchAdd(delta, .monotonic) + delta;
    bumpHighWater(&writer_queue_bytes_high_water, new_val);
}

pub fn setWriterQueueCapBytes(cap: usize) void {
    writer_queue_cap_bytes.store(@intCast(cap), .monotonic);
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
    writer_queue_cap_bytes: u64,
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
        .writer_queue_cap_bytes = writer_queue_cap_bytes.load(.monotonic),
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
    resetSessionSlotsForTesting();
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

test "writerQueueBytesChanged aggregates deltas across connections and tracks a monotonic high water mark" {
    resetForTesting();
    // Two "connections" each contributing their own queue depth: the
    // aggregate is their sum, not whichever published last (#951 review).
    writerQueueBytesChanged(1000);
    writerQueueBytesChanged(200);
    writerQueueBytesChanged(-1000);
    const s = snapshot();
    try std.testing.expectEqual(@as(u64, 200), s.writer_queue_bytes);
    try std.testing.expectEqual(@as(u64, 1200), s.writer_queue_bytes_high_water);
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

test "session slots track per-stream queued bytes independent of the aggregate, and release on unregister" {
    resetForTesting();
    sessionSlotRegister(5);
    sessionSlotRegister(9);
    sessionSlotUpdate(5, 100, 0);
    sessionSlotUpdate(9, 10, 20);
    sessionSlotUpdate(5, 40, 0); // stream 5 drained down; its own high water stays at 100.

    var buf: [8]SessionSlotSnapshot = undefined;
    const slots = snapshotSessionSlots(&buf);
    try std.testing.expectEqual(@as(usize, 2), slots.len);
    for (slots) |slot| {
        if (slot.stream_id == 5) {
            try std.testing.expectEqual(@as(u64, 40), slot.queued_bytes);
            try std.testing.expectEqual(@as(u64, 100), slot.queued_bytes_high_water);
        } else {
            try std.testing.expectEqual(@as(u31, 9), slot.stream_id);
            try std.testing.expectEqual(@as(u64, 30), slot.queued_bytes);
            try std.testing.expectEqual(@as(u64, 30), slot.queued_bytes_high_water);
        }
    }

    sessionSlotUnregister(5);
    const after_unregister = snapshotSessionSlots(&buf);
    try std.testing.expectEqual(@as(usize, 1), after_unregister.len);
    try std.testing.expectEqual(@as(u31, 9), after_unregister[0].stream_id);
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
