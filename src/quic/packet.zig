//! QUIC packet layer (#243): long/short packet headers, packet number
//! encoding/reconstruction, and (later) the frame codec. The varint codec lives
//! in `varint.zig`; packet/header protection (crypto) lives with the TLS
//! adapter (#249). Long-header types: Initial, 0-RTT, Handshake, Retry; short
//! header for the 1-RTT application space (RFC 9000 §17).
//!
//! Status: packet-number encoding/reconstruction implemented; header and frame
//! codec land in follow-up commits of #243.

const std = @import("std");

/// Largest valid packet number (RFC 9000 §17.1: 2^62 - 1).
pub const max_packet_number: u64 = (1 << 62) - 1;

/// Minimal number of bytes (1..4) needed to encode `full_pn` such that a peer
/// who has acknowledged up to `largest_acked` can reconstruct it. Pass null for
/// `largest_acked` when no packet has been acknowledged yet. (RFC 9000 §A.2)
pub fn packetNumberLength(full_pn: u64, largest_acked: ?u64) u3 {
    std.debug.assert(full_pn <= max_packet_number);
    // A packet being sent always has a higher number than anything acked.
    if (largest_acked) |acked| std.debug.assert(acked < full_pn);
    const num_unacked: u64 = if (largest_acked) |acked| full_pn - acked else full_pn + 1;
    // Need enough bits so the window (2 * num_unacked) is representable.
    const min_bits: usize = @as(usize, 64) - @clz(num_unacked * 2);
    const num_bytes = (min_bits + 7) / 8;
    return @intCast(std.math.clamp(num_bytes, 1, 4));
}

/// The `pn_length` low-order bytes of `full_pn`, big-endian, as sent on the
/// wire. `pn_length` is 1..4.
pub fn truncatePacketNumber(full_pn: u64, pn_length: u3) u32 {
    std.debug.assert(full_pn <= max_packet_number);
    std.debug.assert(pn_length >= 1 and pn_length <= 4);
    const bits: u6 = @as(u6, pn_length) * 8;
    if (bits >= 32) return @truncate(full_pn);
    const mask: u64 = (@as(u64, 1) << bits) - 1;
    return @intCast(full_pn & mask);
}

/// Reconstruct the full packet number from a truncated one, given the largest
/// packet number successfully processed in the same space and the number of
/// bits that were sent. (RFC 9000 §A.3)
pub fn decodePacketNumber(largest_pn: u64, truncated_pn: u64, pn_nbits: u6) u64 {
    std.debug.assert(largest_pn <= max_packet_number);
    // Packet numbers are sent as 1..4 bytes.
    std.debug.assert(pn_nbits == 8 or pn_nbits == 16 or pn_nbits == 24 or pn_nbits == 32);
    std.debug.assert(truncated_pn < (@as(u64, 1) << pn_nbits));
    const expected_pn = largest_pn + 1;
    const pn_win: u64 = @as(u64, 1) << pn_nbits;
    const pn_hwin = pn_win / 2;
    const pn_mask = pn_win - 1;
    const candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
    if (candidate_pn <= expected_pn -% pn_hwin and candidate_pn < max_packet_number + 1 - pn_win and expected_pn >= pn_hwin) {
        return candidate_pn + pn_win;
    }
    if (candidate_pn > expected_pn + pn_hwin and candidate_pn >= pn_win) {
        return candidate_pn - pn_win;
    }
    return candidate_pn;
}

const testing = std.testing;

test "decodePacketNumber matches RFC 9000 A.3 example" {
    try testing.expectEqual(@as(u64, 0xa82f9b32), decodePacketNumber(0xa82f30ea, 0x9b32, 16));
}

test "truncate then reconstruct round-trips across a window" {
    // A peer at largest_pn reconstructs recent packet numbers exactly.
    const largest: u64 = 0xa82f30ea;
    var pn: u64 = largest + 1;
    while (pn < largest + 500) : (pn += 7) {
        const len = packetNumberLength(pn, largest);
        const trunc = truncatePacketNumber(pn, len);
        const nbits: u6 = @as(u6, len) * 8;
        try testing.expectEqual(pn, decodePacketNumber(largest, trunc, nbits));
    }
}

test "packetNumberLength at exact RFC threshold boundaries" {
    try testing.expectEqual(@as(u3, 1), packetNumberLength(100, 99));
    try testing.expectEqual(@as(u3, 1), packetNumberLength(0, null));
    // Boundaries where the required length steps up (largest_acked = 0).
    try testing.expectEqual(@as(u3, 1), packetNumberLength(127, 0));
    try testing.expectEqual(@as(u3, 2), packetNumberLength(128, 0));
    try testing.expectEqual(@as(u3, 2), packetNumberLength(32767, 0));
    try testing.expectEqual(@as(u3, 3), packetNumberLength(32768, 0));
    try testing.expectEqual(@as(u3, 3), packetNumberLength(8388607, 0));
    try testing.expectEqual(@as(u3, 4), packetNumberLength(8388608, 0));
}

test "truncatePacketNumber keeps the low-order bytes" {
    try testing.expectEqual(@as(u32, 0x9b32), truncatePacketNumber(0xa82f9b32, 2));
    try testing.expectEqual(@as(u32, 0x2f9b32), truncatePacketNumber(0xa82f9b32, 3));
    try testing.expectEqual(@as(u32, 0xa82f9b32), truncatePacketNumber(0xa82f9b32, 4));
    try testing.expectEqual(@as(u32, 0x32), truncatePacketNumber(0xa82f9b32, 1));
}

test "fuzz: packet number truncation reconstructs recent sends" {
    try testing.fuzz({}, fuzzPacketNumberRoundTrip, .{ .corpus = &.{
        "\x00\x00\x00\x00\x00\x00",
        "\x00\x00\x00\x01\x00\x01",
        "\x00\x00\x7f\xff\x00\x01",
        "\x00\x80\x00\x00\x00\x07",
        "\xff\xff\xff\xff\xff\xff",
    } });
}

fn fuzzPacketNumberRoundTrip(_: void, smith: *testing.Smith) !void {
    const largest = @as(u64, smith.value(u32));
    const delta = @as(u64, smith.value(u16)) + 1;
    const full = largest + delta;
    try testing.expect(full <= max_packet_number);

    const len = packetNumberLength(full, largest);
    try testing.expect(len >= 1 and len <= 4);
    const truncated = truncatePacketNumber(full, len);
    const bits: u6 = @as(u6, len) * 8;
    try testing.expect(truncated < (@as(u64, 1) << bits));
    try testing.expectEqual(full, decodePacketNumber(largest, truncated, bits));
}
