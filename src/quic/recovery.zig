//! QUIC loss detection and congestion control (#244, RFC 9002): ACK manager,
//! RTT estimator, loss detection, PTO, and a NewReno-baseline congestion
//! controller with pacing hooks.
//!
//! Consumes ACK frames decoded by `packet.zig` and the sent-packet metadata
//! recorded by `connection.zig`; drives retransmission and the send-allowance
//! that gates `stream.zig` output. Deliberately starts on a correct RFC 9002 /
//! NewReno baseline — BBR and aggressive optimizer work are explicitly deferred
//! (see the #240 non-goals).

const std = @import("std");

pub const max_ack_ranges = 32;
pub const max_tracked_packets = 128;
pub const max_datagram_size: usize = 1200;
pub const min_congestion_window: usize = 2 * max_datagram_size;
pub const initial_rtt_us: u64 = 333_000;
pub const timer_granularity_us: u64 = 1_000;
pub const packet_threshold: u64 = 3;
pub const default_max_ack_delay_us: u64 = 25_000;

const time_threshold_numerator: u64 = 9;
const time_threshold_denominator: u64 = 8;

pub const PacketNumberSpace = enum {
    initial,
    handshake,
    application,
};

pub const RecoveryEvent = enum {
    ack_range_inserted,
    packet_acked,
    packet_lost,
    pto_armed,
    congestion_event,
    persistent_congestion,
};

pub const Event = struct {
    kind: RecoveryEvent,
    space: ?PacketNumberSpace = null,
    packet_number: ?u64 = null,
    bytes_in_flight: usize = 0,
    congestion_window: usize = 0,
    rtt_us: ?u64 = null,
};

pub const EventSink = struct {
    context: ?*anyopaque = null,
    emitFn: ?*const fn (?*anyopaque, Event) void = null,

    pub fn emit(self: EventSink, event: Event) void {
        if (self.emitFn) |emit_fn| emit_fn(self.context, event);
    }
};

pub const AckRange = struct {
    first: u64,
    last: u64,

    pub fn init(first: u64, last: u64) AckRange {
        std.debug.assert(first <= last);
        return .{ .first = first, .last = last };
    }

    pub fn contains(self: AckRange, packet_number: u64) bool {
        return packet_number >= self.first and packet_number <= self.last;
    }

    pub fn len(self: AckRange) u64 {
        return self.last - self.first + 1;
    }
};

pub const AckFrameRange = struct {
    /// RFC 9000 ACK Range `Gap`: one less than the count of missing packet
    /// numbers between the previous range and this range.
    gap: u64,
    /// RFC 9000 ACK Range Length: one less than the count of acked packets in
    /// this range.
    length: u64,
};

pub const AckFrameModel = struct {
    largest_acknowledged: u64,
    ack_delay_us: u64,
    first_ack_range: u64,
    ranges: [max_ack_ranges - 1]AckFrameRange = undefined,
    range_count: usize = 0,
};

pub const AckRangeSet = struct {
    ranges: [max_ack_ranges]AckRange = undefined,
    count: usize = 0,

    pub fn clear(self: *AckRangeSet) void {
        self.count = 0;
    }

    pub fn contains(self: AckRangeSet, packet_number: u64) bool {
        for (self.ranges[0..self.count]) |range| {
            if (range.contains(packet_number)) return true;
            if (packet_number < range.first) return false;
        }
        return false;
    }

    pub fn insert(self: *AckRangeSet, packet_number: u64) error{TooManyAckRanges}!void {
        try self.insertRange(.{ .first = packet_number, .last = packet_number });
    }

    pub fn insertRange(self: *AckRangeSet, incoming: AckRange) error{TooManyAckRanges}!void {
        var merged = incoming;
        var index: usize = 0;
        while (index < self.count) {
            const current = self.ranges[index];
            if (merged.last +| 1 < current.first) break;
            if (current.last +| 1 < merged.first) {
                index += 1;
                continue;
            }
            merged.first = @min(merged.first, current.first);
            merged.last = @max(merged.last, current.last);
            self.removeAt(index);
        }
        if (self.count == max_ack_ranges) return error.TooManyAckRanges;
        var move = self.count;
        while (move > index) : (move -= 1) {
            self.ranges[move] = self.ranges[move - 1];
        }
        self.ranges[index] = merged;
        self.count += 1;
    }

    pub fn largest(self: AckRangeSet) ?u64 {
        if (self.count == 0) return null;
        return self.ranges[self.count - 1].last;
    }

    pub fn toAckFrame(self: AckRangeSet, ack_delay_us: u64) ?AckFrameModel {
        if (self.count == 0) return null;
        const largest_index = self.count - 1;
        const largest_range = self.ranges[largest_index];
        var frame = AckFrameModel{
            .largest_acknowledged = largest_range.last,
            .ack_delay_us = ack_delay_us,
            .first_ack_range = largest_range.len() - 1,
        };

        var previous_smallest = largest_range.first;
        var range_index = largest_index;
        while (range_index > 0) {
            range_index -= 1;
            const range = self.ranges[range_index];
            frame.ranges[frame.range_count] = .{
                .gap = previous_smallest - range.last - 2,
                .length = range.len() - 1,
            };
            frame.range_count += 1;
            previous_smallest = range.first;
        }
        return frame;
    }

    fn removeAt(self: *AckRangeSet, index: usize) void {
        var cursor = index;
        while (cursor + 1 < self.count) : (cursor += 1) {
            self.ranges[cursor] = self.ranges[cursor + 1];
        }
        self.count -= 1;
    }
};

pub const RttEstimator = struct {
    latest_rtt_us: ?u64 = null,
    smoothed_rtt_us: ?u64 = null,
    rttvar_us: ?u64 = null,
    min_rtt_us: ?u64 = null,
    max_ack_delay_us: u64 = default_max_ack_delay_us,

    pub fn init(max_ack_delay_us_value: u64) RttEstimator {
        return .{ .max_ack_delay_us = max_ack_delay_us_value };
    }

    pub fn hasSample(self: RttEstimator) bool {
        return self.smoothed_rtt_us != null;
    }

    pub fn update(self: *RttEstimator, latest_rtt_us_value: u64, ack_delay_us: u64) void {
        self.latest_rtt_us = latest_rtt_us_value;
        if (self.min_rtt_us == null or latest_rtt_us_value < self.min_rtt_us.?) {
            self.min_rtt_us = latest_rtt_us_value;
        }

        if (self.smoothed_rtt_us == null) {
            self.smoothed_rtt_us = latest_rtt_us_value;
            self.rttvar_us = latest_rtt_us_value / 2;
            return;
        }

        var adjusted_rtt = latest_rtt_us_value;
        const capped_ack_delay = @min(ack_delay_us, self.max_ack_delay_us);
        if (latest_rtt_us_value > self.min_rtt_us.? + capped_ack_delay) {
            adjusted_rtt -= capped_ack_delay;
        }

        const smoothed = self.smoothed_rtt_us.?;
        const variance_sample = absDiff(smoothed, adjusted_rtt);
        self.rttvar_us = (self.rttvar_us.? * 3 + variance_sample) / 4;
        self.smoothed_rtt_us = (smoothed * 7 + adjusted_rtt) / 8;
    }

    pub fn lossDelay(self: RttEstimator) u64 {
        const latest = self.latest_rtt_us orelse initial_rtt_us;
        const smoothed = self.smoothed_rtt_us orelse initial_rtt_us;
        const basis = @max(latest, smoothed);
        return @max(timer_granularity_us, ceilDiv(basis * time_threshold_numerator, time_threshold_denominator));
    }

    pub fn ptoDuration(self: RttEstimator, space: PacketNumberSpace) u64 {
        const smoothed = self.smoothed_rtt_us orelse initial_rtt_us;
        const variance = self.rttvar_us orelse initial_rtt_us / 2;
        const ack_delay = if (space == .application) self.max_ack_delay_us else 0;
        return smoothed + @max(4 * variance, timer_granularity_us) + ack_delay;
    }
};

pub const SentPacket = struct {
    space: PacketNumberSpace,
    packet_number: u64,
    time_sent_us: u64,
    size: usize,
    ack_eliciting: bool = true,
    in_flight: bool = true,
    lost: bool = false,
};

pub const AckResult = struct {
    packet: SentPacket,
    rtt_sample_us: ?u64,
};

pub const LossResult = struct {
    packet_threshold_losses: usize = 0,
    time_threshold_losses: usize = 0,
    lost_bytes: usize = 0,
    largest_lost_time_sent_us: ?u64 = null,
};

pub const PacketTracker = struct {
    packets: [max_tracked_packets]SentPacket = undefined,
    count: usize = 0,
    bytes_in_flight: usize = 0,
    largest_acked: [3]?u64 = .{ null, null, null },

    pub fn onPacketSent(self: *PacketTracker, packet: SentPacket) error{TooManyTrackedPackets}!void {
        if (self.count == max_tracked_packets) return error.TooManyTrackedPackets;
        self.packets[self.count] = packet;
        self.count += 1;
        if (packet.in_flight) self.bytes_in_flight += packet.size;
    }

    pub fn onAcked(self: *PacketTracker, space: PacketNumberSpace, packet_number: u64, now_us: u64) ?AckResult {
        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            const packet = self.packets[index];
            if (packet.space != space or packet.packet_number != packet_number or packet.lost) continue;
            if (packet.in_flight) self.bytes_in_flight -= packet.size;
            self.noteLargestAcked(space, packet_number);
            self.removeAt(index);
            return .{
                .packet = packet,
                .rtt_sample_us = if (packet.ack_eliciting) now_us - packet.time_sent_us else null,
            };
        }
        return null;
    }

    pub fn detectLost(self: *PacketTracker, space: PacketNumberSpace, now_us: u64, rtt: RttEstimator) LossResult {
        const largest = self.largest_acked[spaceIndex(space)] orelse return .{};
        const time_threshold = rtt.lossDelay();
        var result = LossResult{};
        var index: usize = 0;
        while (index < self.count) {
            var packet = self.packets[index];
            if (packet.space != space or packet.lost or packet.packet_number > largest) {
                index += 1;
                continue;
            }

            const threshold_lost = largest >= packet.packet_number + packet_threshold;
            const time_lost = now_us >= packet.time_sent_us and now_us - packet.time_sent_us >= time_threshold;
            if (!threshold_lost and !time_lost) {
                index += 1;
                continue;
            }

            if (threshold_lost) result.packet_threshold_losses += 1;
            if (time_lost) result.time_threshold_losses += 1;
            if (packet.in_flight) {
                result.lost_bytes += packet.size;
                self.bytes_in_flight -= packet.size;
            }
            if (result.largest_lost_time_sent_us == null or packet.time_sent_us > result.largest_lost_time_sent_us.?) {
                result.largest_lost_time_sent_us = packet.time_sent_us;
            }
            packet.lost = true;
            self.packets[index] = packet;
            self.removeAt(index);
        }
        return result;
    }

    fn noteLargestAcked(self: *PacketTracker, space: PacketNumberSpace, packet_number: u64) void {
        const index = spaceIndex(space);
        if (self.largest_acked[index] == null or packet_number > self.largest_acked[index].?) {
            self.largest_acked[index] = packet_number;
        }
    }

    fn removeAt(self: *PacketTracker, index: usize) void {
        var cursor = index;
        while (cursor + 1 < self.count) : (cursor += 1) {
            self.packets[cursor] = self.packets[cursor + 1];
        }
        self.count -= 1;
    }
};

pub const CongestionController = struct {
    congestion_window: usize = initialWindow(max_datagram_size),
    bytes_in_flight: usize = 0,
    ssthresh: usize = std.math.maxInt(usize),
    recovery_start_time_us: ?u64 = null,

    pub fn initialWindow(max_datagram: usize) usize {
        return @min(10 * max_datagram, @max(2 * max_datagram, 14_720));
    }

    pub fn onPacketSent(self: *CongestionController, bytes: usize) void {
        self.bytes_in_flight += bytes;
    }

    pub fn onPacketAcked(self: *CongestionController, packet: SentPacket) void {
        self.bytes_in_flight -|= packet.size;
        if (self.recovery_start_time_us) |start| {
            if (packet.time_sent_us <= start) return;
        }
        if (self.congestion_window < self.ssthresh) {
            self.congestion_window += packet.size;
        } else {
            self.congestion_window += @max(1, max_datagram_size * packet.size / self.congestion_window);
        }
    }

    pub fn onPacketsLost(self: *CongestionController, largest_lost_time_sent_us: u64, lost_bytes: usize, now_us: u64) void {
        if (lost_bytes == 0) return;
        self.bytes_in_flight -|= lost_bytes;
        if (self.recovery_start_time_us) |start| {
            if (largest_lost_time_sent_us <= start) return;
        }
        self.recovery_start_time_us = now_us;
        self.congestion_window = @max(self.congestion_window / 2, min_congestion_window);
        self.ssthresh = self.congestion_window;
    }

    pub fn onPersistentCongestion(self: *CongestionController) void {
        self.congestion_window = min_congestion_window;
        self.ssthresh = min_congestion_window;
    }

    pub fn pacingHint(self: CongestionController, now_us: u64, rtt: RttEstimator) PacingHint {
        const allowance = self.congestion_window -| self.bytes_in_flight;
        if (allowance > 0) return .{ .bytes_available = allowance, .next_send_time_us = now_us };
        return .{ .bytes_available = 0, .next_send_time_us = now_us + rtt.ptoDuration(.application) };
    }
};

pub const PacingHint = struct {
    bytes_available: usize,
    next_send_time_us: u64,

    pub fn canSend(self: PacingHint) bool {
        return self.bytes_available > 0;
    }
};

pub const RecoveryController = struct {
    ack_ranges: [3]AckRangeSet = .{ .{}, .{}, .{} },
    rtt: RttEstimator = .{},
    tracker: PacketTracker = .{},
    congestion: CongestionController = .{},
    events: EventSink = .{},

    pub fn onPacketReceived(self: *RecoveryController, space: PacketNumberSpace, packet_number: u64) error{TooManyAckRanges}!void {
        try self.ack_ranges[spaceIndex(space)].insert(packet_number);
        self.events.emit(.{ .kind = .ack_range_inserted, .space = space, .packet_number = packet_number });
    }

    pub fn ackFrameForSpace(self: *const RecoveryController, space: PacketNumberSpace, ack_delay_us: u64) ?AckFrameModel {
        return self.ack_ranges[spaceIndex(space)].toAckFrame(ack_delay_us);
    }

    pub fn onPacketSent(self: *RecoveryController, packet: SentPacket) error{TooManyTrackedPackets}!void {
        try self.tracker.onPacketSent(packet);
        if (packet.in_flight) self.congestion.onPacketSent(packet.size);
    }

    pub fn onAcked(self: *RecoveryController, space: PacketNumberSpace, packet_number: u64, now_us: u64, ack_delay_us: u64) void {
        if (self.tracker.onAcked(space, packet_number, now_us)) |acked| {
            self.congestion.onPacketAcked(acked.packet);
            if (acked.rtt_sample_us) |sample| self.rtt.update(sample, ack_delay_us);
            self.events.emit(.{
                .kind = .packet_acked,
                .space = space,
                .packet_number = packet_number,
                .bytes_in_flight = self.tracker.bytes_in_flight,
                .congestion_window = self.congestion.congestion_window,
                .rtt_us = self.rtt.smoothed_rtt_us,
            });
        }
    }

    pub fn detectLost(self: *RecoveryController, space: PacketNumberSpace, now_us: u64) LossResult {
        const result = self.tracker.detectLost(space, now_us, self.rtt);
        if (result.lost_bytes > 0) {
            self.congestion.onPacketsLost(result.largest_lost_time_sent_us.?, result.lost_bytes, now_us);
            self.events.emit(.{
                .kind = .packet_lost,
                .space = space,
                .bytes_in_flight = self.tracker.bytes_in_flight,
                .congestion_window = self.congestion.congestion_window,
            });
        }
        return result;
    }

    /// Reinitialize path-dependent state after migrating to a path with new
    /// characteristics (RFC 9000 §9.4): the RTT estimate and congestion
    /// controller reset to their initial values, while packet/ACK tracking
    /// continues — packets in flight on the old path are still accounted for
    /// and can still be acknowledged or declared lost. Skip this for a NAT
    /// rebinding that only changed the peer's port; `path.zig` documents the
    /// policy.
    pub fn resetForPathMigration(self: *RecoveryController) void {
        self.rtt = RttEstimator.init(self.rtt.max_ack_delay_us);
        self.congestion = .{ .bytes_in_flight = self.congestion.bytes_in_flight };
    }
};

fn spaceIndex(space: PacketNumberSpace) usize {
    return switch (space) {
        .initial => 0,
        .handshake => 1,
        .application => 2,
    };
}

fn absDiff(a: u64, b: u64) u64 {
    return if (a >= b) a - b else b - a;
}

fn ceilDiv(numerator: u64, denominator: u64) u64 {
    return (numerator + denominator - 1) / denominator;
}

const testing = std.testing;

test "ACK range tracker merges gaps reordering and duplicate ACKs" {
    var ranges = AckRangeSet{};
    try ranges.insert(10);
    try ranges.insert(12);
    try ranges.insert(11);
    try ranges.insert(15);
    try ranges.insert(12);

    try testing.expectEqual(@as(usize, 2), ranges.count);
    try testing.expectEqual(AckRange.init(10, 12), ranges.ranges[0]);
    try testing.expectEqual(AckRange.init(15, 15), ranges.ranges[1]);
    try testing.expect(ranges.contains(11));
    try testing.expect(!ranges.contains(14));
    try testing.expectEqual(@as(u64, 15), ranges.largest().?);
}

test "ACK frame model emits QUIC gaps from descending ranges" {
    var ranges = AckRangeSet{};
    try ranges.insertRange(AckRange.init(1, 2));
    try ranges.insertRange(AckRange.init(5, 7));
    try ranges.insert(10);

    const frame = ranges.toAckFrame(123).?;
    try testing.expectEqual(@as(u64, 10), frame.largest_acknowledged);
    try testing.expectEqual(@as(u64, 123), frame.ack_delay_us);
    try testing.expectEqual(@as(u64, 0), frame.first_ack_range);
    try testing.expectEqual(@as(usize, 2), frame.range_count);
    try testing.expectEqual(AckFrameRange{ .gap = 1, .length = 2 }, frame.ranges[0]);
    try testing.expectEqual(AckFrameRange{ .gap = 1, .length = 1 }, frame.ranges[1]);
}

test "recovery controller keeps ACK ranges per packet-number space" {
    var recovery = RecoveryController{};
    try recovery.onPacketReceived(.initial, 1);
    try recovery.onPacketReceived(.application, 1);
    try recovery.onPacketReceived(.application, 2);

    const initial_ack = recovery.ackFrameForSpace(.initial, 0).?;
    try testing.expectEqual(@as(u64, 1), initial_ack.largest_acknowledged);
    try testing.expectEqual(@as(u64, 0), initial_ack.first_ack_range);
    try testing.expectEqual(@as(usize, 0), initial_ack.range_count);

    const application_ack = recovery.ackFrameForSpace(.application, 0).?;
    try testing.expectEqual(@as(u64, 2), application_ack.largest_acknowledged);
    try testing.expectEqual(@as(u64, 1), application_ack.first_ack_range);
    try testing.expectEqual(@as(usize, 0), application_ack.range_count);

    try testing.expect(recovery.ackFrameForSpace(.handshake, 0) == null);
}

test "RTT estimator caps ACK delay and maintains min RTT" {
    var rtt = RttEstimator.init(25_000);
    rtt.update(100_000, 500_000);
    try testing.expectEqual(@as(u64, 100_000), rtt.latest_rtt_us.?);
    try testing.expectEqual(@as(u64, 100_000), rtt.smoothed_rtt_us.?);
    try testing.expectEqual(@as(u64, 50_000), rtt.rttvar_us.?);
    try testing.expectEqual(@as(u64, 100_000), rtt.min_rtt_us.?);

    rtt.update(200_000, 50_000);
    try testing.expectEqual(@as(u64, 109_375), rtt.smoothed_rtt_us.?);
    try testing.expectEqual(@as(u64, 56_250), rtt.rttvar_us.?);
    try testing.expectEqual(@as(u64, 100_000), rtt.min_rtt_us.?);
}

test "PTO duration is packet-number-space aware" {
    var rtt = RttEstimator.init(25_000);
    rtt.update(100_000, 0);

    try testing.expectEqual(@as(u64, 300_000), rtt.ptoDuration(.initial));
    try testing.expectEqual(@as(u64, 300_000), rtt.ptoDuration(.handshake));
    try testing.expectEqual(@as(u64, 325_000), rtt.ptoDuration(.application));
}

test "packet tracker accounts bytes in flight across ACKs" {
    var tracker = PacketTracker{};
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 1_000, .size = 1200 });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = 2_000, .size = 800 });
    try testing.expectEqual(@as(usize, 2_000), tracker.bytes_in_flight);

    const acked = tracker.onAcked(.application, 1, 3_500).?;
    try testing.expectEqual(@as(u64, 2_500), acked.rtt_sample_us.?);
    try testing.expectEqual(@as(usize, 800), tracker.bytes_in_flight);
    try testing.expectEqual(@as(usize, 1), tracker.count);
}

test "loss detection covers packet threshold and time threshold" {
    var tracker = PacketTracker{};
    var rtt = RttEstimator.init(0);
    rtt.update(100, 0);

    try tracker.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 100 });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = 10, .size = 100 });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = 20, .size = 100 });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 4, .time_sent_us = 30, .size = 100 });
    try tracker.onPacketSent(.{ .space = .application, .packet_number = 5, .time_sent_us = 40, .size = 100 });

    _ = tracker.onAcked(.application, 5, 100);
    const threshold_loss = tracker.detectLost(.application, 100, rtt);
    try testing.expectEqual(@as(usize, 2), threshold_loss.packet_threshold_losses);
    try testing.expectEqual(@as(usize, 200), threshold_loss.lost_bytes);
    try testing.expectEqual(@as(u64, 10), threshold_loss.largest_lost_time_sent_us.?);
    try testing.expectEqual(@as(usize, 200), tracker.bytes_in_flight);

    _ = tracker.onAcked(.application, 4, 120);
    const time_loss = tracker.detectLost(.application, 2_000, rtt);
    try testing.expectEqual(@as(usize, 1), time_loss.time_threshold_losses);
    try testing.expectEqual(@as(usize, 100), time_loss.lost_bytes);
    try testing.expectEqual(@as(u64, 20), time_loss.largest_lost_time_sent_us.?);
    try testing.expectEqual(@as(usize, 0), tracker.bytes_in_flight);
}

test "NewReno baseline halves cwnd and persistent congestion uses minimum window" {
    var cc = CongestionController{};
    const initial = cc.congestion_window;
    cc.onPacketSent(4_000);
    cc.onPacketAcked(.{ .space = .application, .packet_number = 1, .time_sent_us = 1_000, .size = 1_200 });
    try testing.expect(cc.congestion_window > initial);
    try testing.expectEqual(@as(usize, 2_800), cc.bytes_in_flight);

    cc.onPacketsLost(2_000, 1_200, 50_000);
    try testing.expectEqual(@as(usize, 1_600), cc.bytes_in_flight);
    try testing.expect(cc.congestion_window >= min_congestion_window);
    try testing.expectEqual(cc.congestion_window, cc.ssthresh);

    cc.onPersistentCongestion();
    try testing.expectEqual(@as(usize, min_congestion_window), cc.congestion_window);
    try testing.expectEqual(@as(usize, min_congestion_window), cc.ssthresh);
}

test "NewReno recovery period prevents repeated cwnd cuts and old ACK growth" {
    var cc = CongestionController{};
    const initial = cc.congestion_window;
    cc.onPacketSent(6_000);

    cc.onPacketsLost(2_000, 1_200, 50_000);
    const after_first_loss = cc.congestion_window;
    try testing.expect(after_first_loss < initial);
    try testing.expectEqual(@as(usize, 4_800), cc.bytes_in_flight);

    cc.onPacketsLost(2_000, 1_200, 60_000);
    try testing.expectEqual(after_first_loss, cc.congestion_window);
    try testing.expectEqual(@as(usize, 3_600), cc.bytes_in_flight);

    cc.onPacketAcked(.{ .space = .application, .packet_number = 1, .time_sent_us = 1_500, .size = 1_200 });
    try testing.expectEqual(after_first_loss, cc.congestion_window);
    try testing.expectEqual(@as(usize, 2_400), cc.bytes_in_flight);

    cc.onPacketAcked(.{ .space = .application, .packet_number = 5, .time_sent_us = 70_000, .size = 1_200 });
    try testing.expect(cc.congestion_window > after_first_loss);
    try testing.expectEqual(@as(usize, 1_200), cc.bytes_in_flight);
}

test "pacing hint exposes send allowance and blocked wake time" {
    var cc = CongestionController{};
    var rtt = RttEstimator.init(25_000);
    rtt.update(100_000, 0);

    var hint = cc.pacingHint(1_000, rtt);
    try testing.expect(hint.canSend());
    try testing.expectEqual(cc.congestion_window, hint.bytes_available);
    try testing.expectEqual(@as(u64, 1_000), hint.next_send_time_us);

    cc.bytes_in_flight = cc.congestion_window;
    hint = cc.pacingHint(1_000, rtt);
    try testing.expect(!hint.canSend());
    try testing.expectEqual(@as(usize, 0), hint.bytes_available);
    try testing.expectEqual(@as(u64, 326_000), hint.next_send_time_us);
}

test "recovery controller wires ACK RTT loss congestion and events" {
    const Recorder = struct {
        events: [8]Event = undefined,
        count: usize = 0,

        fn emit(ctx: ?*anyopaque, event: Event) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.events[self.count] = event;
            self.count += 1;
        }
    };

    var recorder = Recorder{};
    var recovery = RecoveryController{
        .events = .{ .context = &recorder, .emitFn = Recorder.emit },
    };

    try recovery.onPacketSent(.{ .space = .application, .packet_number = 1, .time_sent_us = 0, .size = 1200 });
    try recovery.onPacketSent(.{ .space = .application, .packet_number = 2, .time_sent_us = 10, .size = 1200 });
    try recovery.onPacketSent(.{ .space = .application, .packet_number = 3, .time_sent_us = 20, .size = 1200 });
    try recovery.onPacketSent(.{ .space = .application, .packet_number = 4, .time_sent_us = 30, .size = 1200 });
    try recovery.onPacketReceived(.application, 4);
    recovery.onAcked(.application, 4, 130, 0);
    const loss = recovery.detectLost(.application, 2_000);

    try testing.expectEqual(@as(u64, 100), recovery.rtt.latest_rtt_us.?);
    try testing.expectEqual(@as(usize, 3), loss.lost_bytes / 1200);
    try testing.expect(recorder.count >= 3);
    try testing.expectEqual(RecoveryEvent.ack_range_inserted, recorder.events[0].kind);
    try testing.expectEqual(RecoveryEvent.packet_acked, recorder.events[1].kind);
    try testing.expectEqual(RecoveryEvent.packet_lost, recorder.events[2].kind);
}

test {
    std.testing.refAllDecls(@This());
}
