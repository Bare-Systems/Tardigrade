//! QUIC packet layer (#243): long/short packet headers, packet number
//! encoding/reconstruction, coalesced-datagram iteration, and Retry integrity
//! verification. The varint codec lives in `varint.zig`; the frame codec in
//! `frame.zig`; packet/header protection (crypto) with the TLS adapter
//! (#249). Long-header types: Initial, 0-RTT, Handshake, Retry; short header
//! for the 1-RTT application space (RFC 9000 §17).

const std = @import("std");
const varint = @import("quic_varint");

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

// ---------------------------------------------------------------------------
// Header codec (RFC 9000 §17) and coalesced-datagram iteration (§12.2).
// ---------------------------------------------------------------------------

pub const quic_v1: u32 = 0x00000001;
pub const max_cid_len = 20;
pub const retry_integrity_tag_len = 16;

pub const HeaderError = error{
    TruncatedPacket,
    /// The RFC 9000 fixed bit was zero (or a VN/Retry packet was malformed).
    MalformedPacket,
    /// Long-header connection ID longer than QUIC v1 permits.
    InvalidConnectionId,
};

pub const PacketKind = enum {
    initial,
    zero_rtt,
    handshake,
    retry,
    version_negotiation,
    one_rtt,
};

/// One parsed (still protected) packet at the front of a datagram slice.
/// Offsets are relative to the slice handed to `parsePacket`; `packet_len`
/// is where the next coalesced packet begins.
pub const ParsedPacket = struct {
    kind: PacketKind,
    version: u32 = 0,
    dcid: []const u8,
    scid: []const u8 = &.{},
    /// Initial packets: the address-validation token.
    token: []const u8 = &.{},
    /// Protected packets: offset of the (protected) packet number field.
    pn_offset: usize = 0,
    /// Total length of this packet, including header and payload/tag.
    packet_len: usize = 0,
    /// Retry packets: the Retry token (integrity tag excluded).
    retry_token: []const u8 = &.{},
    /// Retry packets: the 16-byte integrity tag.
    retry_tag: []const u8 = &.{},
    /// Version negotiation packets: raw list of 4-byte supported versions.
    supported_versions: []const u8 = &.{},
};

/// Parse the packet at the start of `bytes`. Short headers carry no CID
/// length, so the caller supplies its own local CID length. Nothing here
/// removes protection; the caller decides what it can decrypt.
pub fn parsePacket(bytes: []const u8, short_dcid_len: usize) HeaderError!ParsedPacket {
    if (bytes.len == 0) return error.TruncatedPacket;
    const first = bytes[0];
    if (first & 0x80 == 0) {
        // Short header (1-RTT).
        if (first & 0x40 == 0) return error.MalformedPacket;
        if (bytes.len < 1 + short_dcid_len) return error.TruncatedPacket;
        return .{
            .kind = .one_rtt,
            .dcid = bytes[1..][0..short_dcid_len],
            .pn_offset = 1 + short_dcid_len,
            .packet_len = bytes.len,
        };
    }

    var pos: usize = 1;
    if (bytes.len < pos + 4) return error.TruncatedPacket;
    const version = std.mem.readInt(u32, bytes[pos..][0..4], .big);
    pos += 4;

    if (bytes.len < pos + 1) return error.TruncatedPacket;
    const dcid_len = bytes[pos];
    pos += 1;
    if (dcid_len > max_cid_len) return error.InvalidConnectionId;
    if (bytes.len < pos + dcid_len) return error.TruncatedPacket;
    const dcid = bytes[pos..][0..dcid_len];
    pos += dcid_len;

    if (bytes.len < pos + 1) return error.TruncatedPacket;
    const scid_len = bytes[pos];
    pos += 1;
    if (scid_len > max_cid_len) return error.InvalidConnectionId;
    if (bytes.len < pos + scid_len) return error.TruncatedPacket;
    const scid = bytes[pos..][0..scid_len];
    pos += scid_len;

    if (version == 0) {
        // Version negotiation (§17.2.1): the rest is a list of u32 versions.
        const rest = bytes[pos..];
        if (rest.len == 0 or rest.len % 4 != 0) return error.MalformedPacket;
        return .{
            .kind = .version_negotiation,
            .dcid = dcid,
            .scid = scid,
            .supported_versions = rest,
            .packet_len = bytes.len,
        };
    }
    if (first & 0x40 == 0) return error.MalformedPacket;

    const long_type: u2 = @intCast((first >> 4) & 0x3);
    switch (long_type) {
        0b11 => {
            // Retry (§17.2.5): token then 16-byte integrity tag; never coalesced.
            const rest = bytes[pos..];
            if (rest.len < retry_integrity_tag_len) return error.TruncatedPacket;
            return .{
                .kind = .retry,
                .version = version,
                .dcid = dcid,
                .scid = scid,
                .retry_token = rest[0 .. rest.len - retry_integrity_tag_len],
                .retry_tag = rest[rest.len - retry_integrity_tag_len ..],
                .packet_len = bytes.len,
            };
        },
        else => {},
    }

    var token: []const u8 = &.{};
    if (long_type == 0b00) {
        const token_len = varint.decode(bytes[pos..]) catch return error.TruncatedPacket;
        pos += token_len.len;
        if (token_len.value > bytes.len - pos) return error.TruncatedPacket;
        token = bytes[pos..][0..@intCast(token_len.value)];
        pos += token.len;
    }
    const length = varint.decode(bytes[pos..]) catch return error.TruncatedPacket;
    pos += length.len;
    if (length.value > bytes.len - pos) return error.TruncatedPacket;

    return .{
        .kind = switch (long_type) {
            0b00 => .initial,
            0b01 => .zero_rtt,
            0b10 => .handshake,
            0b11 => unreachable,
        },
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .token = token,
        .pn_offset = pos,
        .packet_len = pos + @as(usize, @intCast(length.value)),
    };
}

pub const LongHeaderKind = enum(u2) {
    initial = 0b00,
    zero_rtt = 0b01,
    handshake = 0b10,
};

pub const WrittenLongHeader = struct {
    /// Offset where the packet number begins.
    pn_offset: usize,
    /// Offset of the 2-byte Length varint, patched after payload sealing.
    length_offset: usize,
};

/// Write an Initial/Handshake/0-RTT long header with a 2-byte Length varint
/// placeholder. `pn_len` is encoded into the first byte's low bits.
pub fn writeLongHeader(
    kind: LongHeaderKind,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    pn_len: u3,
    out: []u8,
) error{BufferTooShort}!WrittenLongHeader {
    std.debug.assert(pn_len >= 1 and pn_len <= 4);
    std.debug.assert(dcid.len <= max_cid_len and scid.len <= max_cid_len);
    var pos: usize = 0;
    const need_min = 1 + 4 + 1 + dcid.len + 1 + scid.len;
    if (out.len < need_min) return error.BufferTooShort;
    out[pos] = 0x80 | 0x40 | (@as(u8, @intFromEnum(kind)) << 4) | @as(u8, pn_len - 1);
    pos += 1;
    std.mem.writeInt(u32, out[pos..][0..4], version, .big);
    pos += 4;
    out[pos] = @intCast(dcid.len);
    pos += 1;
    @memcpy(out[pos..][0..dcid.len], dcid);
    pos += dcid.len;
    out[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(out[pos..][0..scid.len], scid);
    pos += scid.len;
    if (kind == .initial) {
        pos += varint.encode(token.len, out[pos..]) catch return error.BufferTooShort;
        if (token.len > out.len - pos) return error.BufferTooShort;
        @memcpy(out[pos..][0..token.len], token);
        pos += token.len;
    }
    const length_offset = pos;
    if (out.len < pos + 2) return error.BufferTooShort;
    pos += 2; // Length placeholder, always a 2-byte varint
    return .{ .pn_offset = pos, .length_offset = length_offset };
}

/// Patch the Length field written by `writeLongHeader` once the packet number
/// length and sealed payload length are known.
pub fn patchLongHeaderLength(out: []u8, length_offset: usize, value: usize) void {
    std.debug.assert(value < 0x4000);
    std.mem.writeInt(u16, out[length_offset..][0..2], @as(u16, @intCast(value)) | 0x4000, .big);
}

/// Write a short (1-RTT) header. Returns the packet number offset.
pub fn writeShortHeader(
    dcid: []const u8,
    key_phase: u1,
    pn_len: u3,
    out: []u8,
) error{BufferTooShort}!usize {
    std.debug.assert(pn_len >= 1 and pn_len <= 4);
    if (out.len < 1 + dcid.len) return error.BufferTooShort;
    out[0] = 0x40 | (@as(u8, key_phase) << 2) | @as(u8, pn_len - 1);
    @memcpy(out[1..][0..dcid.len], dcid);
    return 1 + dcid.len;
}

// RFC 9001 §5.8: fixed AEAD key/nonce for the QUIC v1 Retry integrity tag.
const retry_integrity_key_v1 = [16]u8{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
const retry_integrity_nonce_v1 = [12]u8{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
};

/// Verify the integrity tag of a parsed Retry packet against the DCID the
/// client sent in its first Initial (RFC 9001 §5.8). `retry_packet` is the
/// full packet including the tag.
pub fn verifyRetryIntegrity(retry_packet: []const u8, original_dcid: []const u8) bool {
    if (retry_packet.len < retry_integrity_tag_len) return false;
    if (original_dcid.len > max_cid_len) return false;
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

    // Retry pseudo-packet: ODCID length + ODCID + Retry packet without tag.
    var pseudo: [1 + max_cid_len + 1500]u8 = undefined;
    const body_len = retry_packet.len - retry_integrity_tag_len;
    if (1 + original_dcid.len + body_len > pseudo.len) return false;
    pseudo[0] = @intCast(original_dcid.len);
    @memcpy(pseudo[1..][0..original_dcid.len], original_dcid);
    @memcpy(pseudo[1 + original_dcid.len ..][0..body_len], retry_packet[0..body_len]);
    const aad = pseudo[0 .. 1 + original_dcid.len + body_len];

    var expected: [retry_integrity_tag_len]u8 = undefined;
    var empty_out: [0]u8 = undefined;
    Aes128Gcm.encrypt(&empty_out, &expected, "", aad, retry_integrity_nonce_v1, retry_integrity_key_v1);
    const received = retry_packet[body_len..][0..retry_integrity_tag_len];
    return std.crypto.timing_safe.eql([retry_integrity_tag_len]u8, expected, received.*);
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

test "long header roundtrips through parsePacket" {
    var buf: [128]u8 = undefined;
    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const scid = [_]u8{ 9, 10, 11 };
    const written = try writeLongHeader(.initial, quic_v1, &dcid, &scid, "tok", 2, &buf);
    // Simulate a sealed payload of 30 bytes after the 2-byte packet number.
    const payload_len = 2 + 30;
    patchLongHeaderLength(&buf, written.length_offset, payload_len);
    const total = written.pn_offset + payload_len;
    @memset(buf[written.pn_offset..total], 0xaa);

    const parsed = try parsePacket(buf[0..total], 8);
    try testing.expectEqual(PacketKind.initial, parsed.kind);
    try testing.expectEqual(quic_v1, parsed.version);
    try testing.expectEqualSlices(u8, &dcid, parsed.dcid);
    try testing.expectEqualSlices(u8, &scid, parsed.scid);
    try testing.expectEqualStrings("tok", parsed.token);
    try testing.expectEqual(written.pn_offset, parsed.pn_offset);
    try testing.expectEqual(total, parsed.packet_len);
}

test "coalesced packets split on the long-header Length field" {
    var buf: [256]u8 = undefined;
    const dcid = [_]u8{1} ** 8;
    const scid = [_]u8{2} ** 8;
    const first = try writeLongHeader(.initial, quic_v1, &dcid, &scid, "", 1, &buf);
    patchLongHeaderLength(&buf, first.length_offset, 1 + 20);
    const first_end = first.pn_offset + 1 + 20;
    @memset(buf[first.pn_offset..first_end], 0xbb);
    const second = try writeLongHeader(.handshake, quic_v1, &dcid, &scid, "", 1, buf[first_end..]);
    patchLongHeaderLength(buf[first_end..], second.length_offset, 1 + 17);
    const second_end = first_end + second.pn_offset + 1 + 17;
    @memset(buf[first_end + second.pn_offset .. second_end], 0xcc);

    const one = try parsePacket(buf[0..second_end], 8);
    try testing.expectEqual(PacketKind.initial, one.kind);
    try testing.expectEqual(first_end, one.packet_len);
    const two = try parsePacket(buf[one.packet_len..second_end], 8);
    try testing.expectEqual(PacketKind.handshake, two.kind);
    try testing.expectEqual(second_end - first_end, two.packet_len);
}

test "short header parses with caller-provided DCID length" {
    var buf: [64]u8 = undefined;
    const dcid = [_]u8{7} ** 8;
    const pn_offset = try writeShortHeader(&dcid, 1, 2, &buf);
    try testing.expectEqual(@as(usize, 9), pn_offset);
    @memset(buf[pn_offset..][0..20], 0xdd);
    const parsed = try parsePacket(buf[0 .. pn_offset + 20], dcid.len);
    try testing.expectEqual(PacketKind.one_rtt, parsed.kind);
    try testing.expectEqualSlices(u8, &dcid, parsed.dcid);
    try testing.expectEqual(pn_offset, parsed.pn_offset);
}

test "fixed-bit violations and truncations are typed errors" {
    try testing.expectError(error.TruncatedPacket, parsePacket(&.{}, 8));
    // Short header with fixed bit clear.
    try testing.expectError(error.MalformedPacket, parsePacket(&[_]u8{0x00} ** 12, 8));
    // Long header truncated in the version field.
    try testing.expectError(error.TruncatedPacket, parsePacket(&[_]u8{ 0xc0, 0x00 }, 8));
    // Long header with an oversized DCID length.
    try testing.expectError(error.InvalidConnectionId, parsePacket(&[_]u8{ 0xc0, 0, 0, 0, 1, 21 } ++ [_]u8{0} ** 30, 8));
}

test "Retry packet parses and RFC 9001 A.4 integrity tag verifies" {
    // RFC 9001 Appendix A.4 sample Retry packet for ODCID 0x8394c8f03e515708.
    const retry = [_]u8{
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
        0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
        0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
    };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const parsed = try parsePacket(&retry, 8);
    try testing.expectEqual(PacketKind.retry, parsed.kind);
    try testing.expectEqualStrings("token", parsed.retry_token);
    try testing.expectEqualSlices(u8, retry[7..15], parsed.scid);
    try testing.expect(verifyRetryIntegrity(&retry, &odcid));
    try testing.expect(!verifyRetryIntegrity(&retry, &[_]u8{0} ** 8));
    var tampered = retry;
    tampered[tampered.len - 1] ^= 1;
    try testing.expect(!verifyRetryIntegrity(&tampered, &odcid));
}

test "version negotiation packet exposes the version list" {
    var buf: [64]u8 = undefined;
    buf[0] = 0x80;
    std.mem.writeInt(u32, buf[1..5], 0, .big);
    buf[5] = 4;
    @memset(buf[6..10], 0x11); // dcid
    buf[10] = 4;
    @memset(buf[11..15], 0x22); // scid
    std.mem.writeInt(u32, buf[15..19], 0x00000001, .big);
    std.mem.writeInt(u32, buf[19..23], 0x6b3343cf, .big);
    const parsed = try parsePacket(buf[0..23], 8);
    try testing.expectEqual(PacketKind.version_negotiation, parsed.kind);
    try testing.expectEqual(@as(usize, 8), parsed.supported_versions.len);
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
