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
/// have to flow back through this module anyway). #951 second review: this
/// single global cannot be compared against the aggregate high water above
/// when more than one connection is live (each publishes its own cap, and
/// the aggregate sums every connection's bytes) -- kept only as a rough,
/// documented-as-such observability value; `writerQueueSlot*` below is the
/// real per-connection bound.
var writer_queue_cap_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Process-wide unique identifier for one H2 connection's lifetime, handed
/// out once per connection and threaded into every per-stream/per-connection
/// slot it registers below. #951 second review: stream ids are only unique
/// *within* a connection (two simultaneous connections commonly both use
/// stream 1), so attributing a slot by stream id alone silently corrupts
/// one connection's counters with another's.
var next_connection_id: std.atomic.Value(u64) = std.atomic.Value(u64).init(1);

pub fn nextConnectionId() u64 {
    return next_connection_id.fetchAdd(1, .monotonic);
}

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
// connection's own (lower) concurrent-stream limit; a table overflow is
// counted (`session_slot_overflow_total`) rather than silently dropped, so
// evidence/CI can detect and fail on it instead of quietly losing coverage.
pub const MAX_TRACKED_STREAMS: usize = 256;
/// Process-wide fixed bound on concurrently tracked *connections'* own
/// writer-queue slots (separate table from `MAX_TRACKED_STREAMS` above,
/// since a connection's own writer queue is one slot regardless of how many
/// streams it multiplexes).
pub const MAX_TRACKED_CONNECTIONS: usize = 128;

/// A session's or scheduler's claim on one fixed slot below. Carries a
/// generation counter (bumped every time the slot is claimed) so a handle
/// from a stale registration can never be mistaken for a later, unrelated
/// occupant of the same array index -- the ABA hazard a bare index would
/// otherwise have across `*Unregister`/`*Register` cycles.
pub const SlotHandle = struct { index: usize, generation: u64 };

var session_slot_overflow_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var writer_queue_slot_overflow_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

const SessionSlot = struct {
    in_use: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Published last (release), after every other field below, so a
    /// concurrent scraper never observes a slot it can read as `in_use` but
    /// whose identity/byte fields are still mid-initialization (#951 second
    /// review).
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    generation: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Seqlock counter (#951 third review): odd while register/update/
    /// unregister is actively mutating this slot's fields, even once that
    /// mutation has fully published. `in_use`/`ready` alone cannot prevent
    /// a scraper from being descheduled between reading them and reading
    /// the identity/byte fields below; by the time it resumes, the slot
    /// may have been released and reclaimed by a different session with a
    /// different `(connection_id, stream_id)`, producing an impossible
    /// mixed-identity sample. A reader snapshots this counter before and
    /// after copying every field and retries whenever it is odd or has
    /// changed, exactly as a classic seqlock.
    seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    connection_id: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    inbound_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    outbound_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    high_water: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

var session_slots: [MAX_TRACKED_STREAMS]SessionSlot = [_]SessionSlot{.{}} ** MAX_TRACKED_STREAMS;

/// Claim a free slot for a newly created session, scoped to
/// `connection_id` so two simultaneous connections using the same HTTP/2
/// stream id never collide. Returns `null` on table exhaustion (counted in
/// `session_slot_overflow_total`) instead of silently aliasing an unrelated
/// slot.
pub fn sessionSlotRegister(connection_id: u64, stream_id: u31) ?SlotHandle {
    for (&session_slots, 0..) |*slot, i| {
        if (slot.in_use.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
            _ = slot.seq.fetchAdd(1, .release); // odd: mutation in progress.
            const generation = slot.generation.fetchAdd(1, .monotonic) + 1;
            slot.connection_id.store(connection_id, .monotonic);
            slot.stream_id.store(stream_id, .monotonic);
            slot.inbound_bytes.store(0, .monotonic);
            slot.outbound_bytes.store(0, .monotonic);
            slot.high_water.store(0, .monotonic);
            slot.ready.store(true, .release);
            _ = slot.seq.fetchAdd(1, .release); // even: published.
            return .{ .index = i, .generation = generation };
        }
    }
    _ = session_slot_overflow_total.fetchAdd(1, .monotonic);
    return null;
}

/// Publish this session's current queued-byte counts. Called from every
/// `h2_stream_session.zig` site that already mutates `inbound_bytes`/
/// `outbound_bytes` under `Session.mutex`, so these values are always a
/// real (not reserved-capacity) snapshot. A `null` handle (table was
/// exhausted at registration) is a documented no-op.
pub fn sessionSlotUpdate(handle: ?SlotHandle, inbound_bytes: usize, outbound_bytes: usize) void {
    const h = handle orelse return;
    const slot = &session_slots[h.index];
    if (slot.generation.load(.monotonic) != h.generation) return;
    _ = slot.seq.fetchAdd(1, .release); // odd: mutation in progress.
    const total: u64 = @intCast(inbound_bytes + outbound_bytes);
    slot.inbound_bytes.store(@intCast(inbound_bytes), .monotonic);
    slot.outbound_bytes.store(@intCast(outbound_bytes), .monotonic);
    var prev = slot.high_water.load(.monotonic);
    while (total > prev) {
        prev = slot.high_water.cmpxchgWeak(prev, total, .monotonic, .monotonic) orelse break;
    }
    _ = slot.seq.fetchAdd(1, .release); // even: published.
}

/// Release a session's slot. Safe to call with a `null` handle (no-op).
pub fn sessionSlotUnregister(handle: ?SlotHandle) void {
    const h = handle orelse return;
    const slot = &session_slots[h.index];
    if (slot.generation.load(.monotonic) != h.generation) return;
    _ = slot.seq.fetchAdd(1, .release); // odd: mutation in progress.
    slot.ready.store(false, .release);
    slot.in_use.store(false, .release);
    _ = slot.seq.fetchAdd(1, .release); // even: released.
}

pub const SessionSlotSnapshot = struct {
    connection_id: u64,
    stream_id: u31,
    inbound_bytes: u64,
    outbound_bytes: u64,
    queued_bytes: u64,
    queued_bytes_high_water: u64,
};

/// Seqlock-consistent read of one slot (#951 third review): retries while
/// `seq` is odd (mutation in progress) or changed between the first and
/// last load, so a scrape can never mix one session's identity with
/// another's byte counts after an unregister/reuse interleaves with the
/// read. Returns `null` for a slot that is not currently in use/ready, or
/// that could not be read consistently within a bounded number of
/// retries (treated the same as "not currently observable", never as a
/// corrupted sample).
fn trySnapshotSessionSlot(slot: *SessionSlot) ?SessionSlotSnapshot {
    var attempt: usize = 0;
    while (attempt < 16) : (attempt += 1) {
        const seq_before = slot.seq.load(.acquire);
        if (seq_before % 2 != 0) continue;
        if (!slot.in_use.load(.acquire)) return null;
        if (!slot.ready.load(.acquire)) return null;
        const connection_id = slot.connection_id.load(.acquire);
        const stream_id = slot.stream_id.load(.acquire);
        const inbound = slot.inbound_bytes.load(.acquire);
        const outbound = slot.outbound_bytes.load(.acquire);
        const high_water = slot.high_water.load(.acquire);
        const seq_after = slot.seq.load(.acquire);
        if (seq_before != seq_after) continue;
        return .{
            .connection_id = connection_id,
            .stream_id = @intCast(stream_id),
            .inbound_bytes = inbound,
            .outbound_bytes = outbound,
            .queued_bytes = inbound + outbound,
            .queued_bytes_high_water = high_water,
        };
    }
    return null;
}

/// Copy every currently-registered, fully-published, consistently-read
/// slot into `buf`, returning the filled prefix. Test/diagnostics-only.
pub fn snapshotSessionSlots(buf: []SessionSlotSnapshot) []SessionSlotSnapshot {
    var n: usize = 0;
    for (&session_slots) |*slot| {
        if (n >= buf.len) break;
        if (trySnapshotSessionSlot(slot)) |snap| {
            buf[n] = snap;
            n += 1;
        }
    }
    return buf[0..n];
}

/// Test-only: clears every slot so an earlier test's sessions (which may
/// never have reached `deinit` on a forcibly-leaked allocator failure path)
/// cannot leave a stream_id collision for a later test.
pub fn resetSessionSlotsForTesting() void {
    for (&session_slots) |*slot| slot.* = .{};
    session_slot_overflow_total.store(0, .monotonic);
}

const WriterQueueSlot = struct {
    in_use: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    generation: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Seqlock counter, same convention and purpose as `SessionSlot.seq`
    /// (#951 third review): `snapshotWriterQueueSlots` has the identical
    /// identity-reuse hazard the session slot table had.
    seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    connection_id: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    cap_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    queued_bytes: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    high_water: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// #951 third review: pending frame *intents* (queued entries plus the
    /// in-flight `active` one, if any) -- a distinct dimension from byte
    /// occupancy above. A scheduler holding many tiny frames can be deep
    /// and unfair while still looking small by byte capacity alone.
    depth: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    depth_high_water: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

var writer_queue_slots: [MAX_TRACKED_CONNECTIONS]WriterQueueSlot = [_]WriterQueueSlot{.{}} ** MAX_TRACKED_CONNECTIONS;

/// Claim one connection-scoped writer-queue slot. #951 second review: the
/// previous single process-wide `writer_queue_cap_bytes` could only ever
/// hold one connection's cap, so comparing the aggregate high-water mark
/// (every live connection's queued bytes summed) against it failed on any
/// healthy multi-connection workload. Each connection's own queued bytes
/// and high water are now tracked and bounded against *that connection's
/// own* cap here, independent of every other live connection.
pub fn writerQueueSlotRegister(connection_id: u64, cap_bytes: usize) ?SlotHandle {
    for (&writer_queue_slots, 0..) |*slot, i| {
        if (slot.in_use.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
            _ = slot.seq.fetchAdd(1, .release); // odd: mutation in progress.
            const generation = slot.generation.fetchAdd(1, .monotonic) + 1;
            slot.connection_id.store(connection_id, .monotonic);
            slot.cap_bytes.store(@intCast(cap_bytes), .monotonic);
            slot.queued_bytes.store(0, .monotonic);
            slot.high_water.store(0, .monotonic);
            slot.depth.store(0, .monotonic);
            slot.depth_high_water.store(0, .monotonic);
            slot.ready.store(true, .release);
            _ = slot.seq.fetchAdd(1, .release); // even: published.
            return .{ .index = i, .generation = generation };
        }
    }
    _ = writer_queue_slot_overflow_total.fetchAdd(1, .monotonic);
    return null;
}

/// `delta` is the signed change in this one connection's own queued writer
/// bytes, published from the same real enqueue/flush/cancel mutation
/// points as the process-wide aggregate (`writerQueueBytesChanged`).
pub fn writerQueueSlotChanged(handle: ?SlotHandle, delta: i64) void {
    const h = handle orelse return;
    const slot = &writer_queue_slots[h.index];
    if (slot.generation.load(.monotonic) != h.generation) return;
    _ = slot.seq.fetchAdd(1, .release); // odd: mutation in progress.
    const new_val = slot.queued_bytes.fetchAdd(delta, .monotonic) + delta;
    if (new_val > 0) {
        const cur: u64 = @intCast(new_val);
        var prev = slot.high_water.load(.monotonic);
        while (cur > prev) {
            prev = slot.high_water.cmpxchgWeak(prev, cur, .monotonic, .monotonic) orelse break;
        }
    }
    _ = slot.seq.fetchAdd(1, .release); // even: published.
}

/// `delta` is the signed change in this one connection's own pending frame
/// *count* (queued entries plus the in-flight `active` one, if any) --
/// #951 third review's required writer-queue depth, distinct from byte
/// occupancy above.
pub fn writerQueueSlotDepthChanged(handle: ?SlotHandle, delta: i64) void {
    const h = handle orelse return;
    const slot = &writer_queue_slots[h.index];
    if (slot.generation.load(.monotonic) != h.generation) return;
    _ = slot.seq.fetchAdd(1, .release); // odd: mutation in progress.
    const new_val = slot.depth.fetchAdd(delta, .monotonic) + delta;
    if (new_val > 0) {
        const cur: u64 = @intCast(new_val);
        var prev = slot.depth_high_water.load(.monotonic);
        while (cur > prev) {
            prev = slot.depth_high_water.cmpxchgWeak(prev, cur, .monotonic, .monotonic) orelse break;
        }
    }
    _ = slot.seq.fetchAdd(1, .release); // even: published.
}

pub fn writerQueueSlotUnregister(handle: ?SlotHandle) void {
    const h = handle orelse return;
    const slot = &writer_queue_slots[h.index];
    if (slot.generation.load(.monotonic) != h.generation) return;
    _ = slot.seq.fetchAdd(1, .release); // odd: mutation in progress.
    slot.ready.store(false, .release);
    slot.in_use.store(false, .release);
    _ = slot.seq.fetchAdd(1, .release); // even: released.
}

pub const WriterQueueSlotSnapshot = struct {
    connection_id: u64,
    queued_bytes: u64,
    queued_bytes_high_water: u64,
    cap_bytes: u64,
    depth: u64,
    depth_high_water: u64,
};

/// Seqlock-consistent read of one writer-queue slot, same convention and
/// rationale as `trySnapshotSessionSlot` (#951 third review).
fn trySnapshotWriterQueueSlot(slot: *WriterQueueSlot) ?WriterQueueSlotSnapshot {
    var attempt: usize = 0;
    while (attempt < 16) : (attempt += 1) {
        const seq_before = slot.seq.load(.acquire);
        if (seq_before % 2 != 0) continue;
        if (!slot.in_use.load(.acquire)) return null;
        if (!slot.ready.load(.acquire)) return null;
        const connection_id = slot.connection_id.load(.acquire);
        const queued_bytes = slot.queued_bytes.load(.acquire);
        const high_water = slot.high_water.load(.acquire);
        const cap_bytes = slot.cap_bytes.load(.acquire);
        const depth = slot.depth.load(.acquire);
        const depth_high_water = slot.depth_high_water.load(.acquire);
        const seq_after = slot.seq.load(.acquire);
        if (seq_before != seq_after) continue;
        return .{
            .connection_id = connection_id,
            .queued_bytes = @intCast(@max(0, queued_bytes)),
            .queued_bytes_high_water = high_water,
            .cap_bytes = cap_bytes,
            .depth = @intCast(@max(0, depth)),
            .depth_high_water = depth_high_water,
        };
    }
    return null;
}

pub fn snapshotWriterQueueSlots(buf: []WriterQueueSlotSnapshot) []WriterQueueSlotSnapshot {
    var n: usize = 0;
    for (&writer_queue_slots) |*slot| {
        if (n >= buf.len) break;
        if (trySnapshotWriterQueueSlot(slot)) |snap| {
            buf[n] = snap;
            n += 1;
        }
    }
    return buf[0..n];
}

pub fn resetWriterQueueSlotsForTesting() void {
    for (&writer_queue_slots) |*slot| slot.* = .{};
    writer_queue_slot_overflow_total.store(0, .monotonic);
}

/// #951 second review: a real H2 connection count, derived from how many
/// writer-queue slots (one per live `Scheduler`, i.e. one per live H2
/// connection) are currently registered -- unlike the generic
/// `tardigrade_active_connections` gauge, which real-process evidence
/// observed reading 0 even while an H2 connection was demonstrably open
/// and serving traffic.
pub fn activeConnectionsCount() usize {
    var n: usize = 0;
    for (&writer_queue_slots) |*slot| {
        if (slot.in_use.load(.acquire) and slot.ready.load(.acquire)) n += 1;
    }
    return n;
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
    session_slot_overflow_total: u64,
    writer_queue_slot_overflow_total: u64,
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
        .session_slot_overflow_total = session_slot_overflow_total.load(.monotonic),
        .writer_queue_slot_overflow_total = writer_queue_slot_overflow_total.load(.monotonic),
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
    resetWriterQueueSlotsForTesting();
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
    const h5 = sessionSlotRegister(1, 5) orelse return error.TestUnexpectedResult;
    const h9 = sessionSlotRegister(1, 9) orelse return error.TestUnexpectedResult;
    sessionSlotUpdate(h5, 100, 0);
    sessionSlotUpdate(h9, 10, 20);
    sessionSlotUpdate(h5, 40, 0); // stream 5 drained down; its own high water stays at 100.

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

    sessionSlotUnregister(h5);
    const after_unregister = snapshotSessionSlots(&buf);
    try std.testing.expectEqual(@as(usize, 1), after_unregister.len);
    try std.testing.expectEqual(@as(u31, 9), after_unregister[0].stream_id);

    // A stale handle from before unregistration must not resurrect or
    // corrupt whatever later claims the same array slot (ABA hazard a bare
    // index would have, #951 second review).
    sessionSlotUpdate(h5, 999, 999);
    const still_only_nine = snapshotSessionSlots(&buf);
    try std.testing.expectEqual(@as(usize, 1), still_only_nine.len);
    try std.testing.expectEqual(@as(u64, 30), still_only_nine[0].queued_bytes);
}

test "session slots scope identical stream ids to their own connection id" {
    resetForTesting();
    // Two simultaneous connections both legitimately use stream 1 -- the
    // defect this regression guards against (#951 second review): a
    // lookup keyed on stream id alone would route both sessions' updates to
    // whichever slot matched first.
    const conn_a = sessionSlotRegister(100, 1) orelse return error.TestUnexpectedResult;
    const conn_b = sessionSlotRegister(200, 1) orelse return error.TestUnexpectedResult;
    sessionSlotUpdate(conn_a, 10, 0);
    sessionSlotUpdate(conn_b, 0, 20);

    var buf: [8]SessionSlotSnapshot = undefined;
    const slots = snapshotSessionSlots(&buf);
    try std.testing.expectEqual(@as(usize, 2), slots.len);
    var saw_a = false;
    var saw_b = false;
    for (slots) |slot| {
        try std.testing.expectEqual(@as(u31, 1), slot.stream_id);
        if (slot.connection_id == 100) {
            try std.testing.expectEqual(@as(u64, 10), slot.queued_bytes);
            saw_a = true;
        } else if (slot.connection_id == 200) {
            try std.testing.expectEqual(@as(u64, 20), slot.queued_bytes);
            saw_b = true;
        } else return error.TestUnexpectedResult;
    }
    try std.testing.expect(saw_a and saw_b);

    // Removal in either order must only ever release its own slot.
    sessionSlotUnregister(conn_b);
    const after_b = snapshotSessionSlots(&buf);
    try std.testing.expectEqual(@as(usize, 1), after_b.len);
    try std.testing.expectEqual(@as(u64, 100), after_b[0].connection_id);
    sessionSlotUnregister(conn_a);
    try std.testing.expectEqual(@as(usize, 0), snapshotSessionSlots(&buf).len);
}

test "session slot table reports overflow instead of silently dropping or aliasing a stream" {
    resetForTesting();
    var handles: [MAX_TRACKED_STREAMS]SlotHandle = undefined;
    for (0..MAX_TRACKED_STREAMS) |i| {
        handles[i] = sessionSlotRegister(1, @intCast(i + 1)) orelse return error.TestUnexpectedResult;
    }
    try std.testing.expectEqual(@as(u64, 0), snapshot().session_slot_overflow_total);

    // One more registration beyond capacity must be reported, not silently
    // aliased onto an already-occupied slot.
    try std.testing.expectEqual(@as(?SlotHandle, null), sessionSlotRegister(1, 9999));
    try std.testing.expectEqual(@as(u64, 1), snapshot().session_slot_overflow_total);

    for (handles) |h| sessionSlotUnregister(h);
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

test "writer queue slots bound each connection against its own cap, independent of the aggregate" {
    resetForTesting();
    // Two connections, each comfortably under its own 256KiB cap, whose sum
    // exceeds a single connection's cap -- the exact healthy scenario the
    // previous aggregate-vs-single-cap comparison (#951 review) failed.
    const conn_a = writerQueueSlotRegister(1, 256 * 1024) orelse return error.TestUnexpectedResult;
    const conn_b = writerQueueSlotRegister(2, 256 * 1024) orelse return error.TestUnexpectedResult;
    writerQueueSlotChanged(conn_a, 200 * 1024);
    writerQueueBytesChanged(200 * 1024);
    writerQueueSlotChanged(conn_b, 200 * 1024);
    writerQueueBytesChanged(200 * 1024);

    var buf: [8]WriterQueueSlotSnapshot = undefined;
    const slots = snapshotWriterQueueSlots(&buf);
    try std.testing.expectEqual(@as(usize, 2), slots.len);
    for (slots) |slot| {
        try std.testing.expect(slot.queued_bytes_high_water <= slot.cap_bytes);
        try std.testing.expectEqual(@as(u64, 200 * 1024), slot.queued_bytes_high_water);
    }
    // The process-wide aggregate (what the old, incorrect assertion used)
    // does exceed a single connection's cap here, proving the two scopes
    // are genuinely different quantities.
    try std.testing.expect(snapshot().writer_queue_bytes_high_water > 256 * 1024);

    writerQueueSlotChanged(conn_a, -(200 * 1024));
    writerQueueSlotUnregister(conn_a);
    writerQueueSlotChanged(conn_b, -(200 * 1024));
    writerQueueSlotUnregister(conn_b);
    try std.testing.expectEqual(@as(usize, 0), snapshotWriterQueueSlots(&buf).len);
}

test "writer queue slots track frame-intent depth independent of byte occupancy" {
    resetForTesting();
    const conn_a = writerQueueSlotRegister(1, 256 * 1024) orelse return error.TestUnexpectedResult;
    writerQueueSlotDepthChanged(conn_a, 1);
    writerQueueSlotDepthChanged(conn_a, 1);
    writerQueueSlotDepthChanged(conn_a, 1);
    writerQueueSlotDepthChanged(conn_a, -1); // one frame finished draining.

    var buf: [8]WriterQueueSlotSnapshot = undefined;
    const slots = snapshotWriterQueueSlots(&buf);
    try std.testing.expectEqual(@as(usize, 1), slots.len);
    try std.testing.expectEqual(@as(u64, 2), slots[0].depth);
    try std.testing.expectEqual(@as(u64, 3), slots[0].depth_high_water);

    writerQueueSlotUnregister(conn_a);
}

// PR review (#951 third review, wGtoM): a scraper observing `in_use=true,
// ready=true` could be descheduled, then another thread unregisters that
// slot and a new session reclaims it with a different `(connection_id,
// stream_id)` before the scraper resumes and reads the identity/byte
// fields -- producing an impossible mixed-identity sample. These tests
// hammer the exact same array slot with rapid register/update/unregister
// cycles under two distinct, fixed identity-to-bytes pairings while a
// concurrent reader continuously snapshots, asserting every observed
// sample's bytes match its own connection id's pairing -- any mismatch
// proves the seqlock protection (`SessionSlot.seq`/`WriterQueueSlot.seq`)
// failed to keep identity and bytes from the same mutation generation.
test "session slot snapshots never mix identity across concurrent register/unregister reuse" {
    resetForTesting();
    const Reader = struct {
        stop: *std.atomic.Value(bool),
        mismatch: *std.atomic.Value(bool),

        fn run(self: *@This()) void {
            var buf: [8]SessionSlotSnapshot = undefined;
            while (!self.stop.load(.acquire)) {
                for (snapshotSessionSlots(&buf)) |slot| {
                    // `(0, 0)` is the legitimate transient state between a
                    // fresh `sessionSlotRegister` and its immediately
                    // following `sessionSlotUpdate` -- not a mismatch. Any
                    // *other* byte pairing under a given connection id can
                    // only mean this snapshot mixed one identity with
                    // another generation's bytes.
                    const ok = switch (slot.connection_id) {
                        111 => (slot.inbound_bytes == 0 and slot.outbound_bytes == 0) or (slot.inbound_bytes == 11 and slot.outbound_bytes == 22),
                        222 => (slot.inbound_bytes == 0 and slot.outbound_bytes == 0) or (slot.inbound_bytes == 33 and slot.outbound_bytes == 44),
                        else => false,
                    };
                    if (!ok) self.mismatch.store(true, .release);
                }
            }
        }
    };
    var stop = std.atomic.Value(bool).init(false);
    var mismatch = std.atomic.Value(bool).init(false);
    var reader = Reader{ .stop = &stop, .mismatch = &mismatch };
    const reader_thread = try std.Thread.spawn(.{}, Reader.run, .{&reader});

    var i: usize = 0;
    while (i < 2_000) : (i += 1) {
        const h_a = sessionSlotRegister(111, 1) orelse return error.TestUnexpectedResult;
        sessionSlotUpdate(h_a, 11, 22);
        sessionSlotUnregister(h_a);
        const h_b = sessionSlotRegister(222, 1) orelse return error.TestUnexpectedResult;
        sessionSlotUpdate(h_b, 33, 44);
        sessionSlotUnregister(h_b);
    }
    stop.store(true, .release);
    reader_thread.join();
    try std.testing.expect(!mismatch.load(.acquire));
}

test "writer queue slot snapshots never mix identity across concurrent register/unregister reuse" {
    resetForTesting();
    const Reader = struct {
        stop: *std.atomic.Value(bool),
        mismatch: *std.atomic.Value(bool),

        fn run(self: *@This()) void {
            var buf: [8]WriterQueueSlotSnapshot = undefined;
            while (!self.stop.load(.acquire)) {
                for (snapshotWriterQueueSlots(&buf)) |slot| {
                    const ok = switch (slot.connection_id) {
                        111 => slot.cap_bytes == 1_000,
                        222 => slot.cap_bytes == 2_000,
                        else => false,
                    };
                    if (!ok) self.mismatch.store(true, .release);
                }
            }
        }
    };
    var stop = std.atomic.Value(bool).init(false);
    var mismatch = std.atomic.Value(bool).init(false);
    var reader = Reader{ .stop = &stop, .mismatch = &mismatch };
    const reader_thread = try std.Thread.spawn(.{}, Reader.run, .{&reader});

    var i: usize = 0;
    while (i < 2_000) : (i += 1) {
        const h_a = writerQueueSlotRegister(111, 1_000) orelse return error.TestUnexpectedResult;
        writerQueueSlotChanged(h_a, 10);
        writerQueueSlotUnregister(h_a);
        const h_b = writerQueueSlotRegister(222, 2_000) orelse return error.TestUnexpectedResult;
        writerQueueSlotChanged(h_b, 20);
        writerQueueSlotUnregister(h_b);
    }
    stop.store(true, .release);
    reader_thread.join();
    try std.testing.expect(!mismatch.load(.acquire));
}
