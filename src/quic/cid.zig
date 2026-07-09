//! QUIC connection ID management (#251, RFC 9000 §5.1): CID generation,
//! lookup/routing, retirement, and stateless-reset token derivation.
//!
//! The UDP endpoint (`udp.zig`) demultiplexes incoming datagrams to a
//! connection by destination CID via the lookup table owned here; NEW/RETIRE
//! CONNECTION_ID frame handling and the active-CID limit from `config.zig` also
//! live here. Deeper migration/path lifecycle is `path.zig`.
//!
//! Status: stateless-reset token derivation and reset-packet emission land with
//! #250; CID generation/lookup/retirement lifecycle in #251.

const std = @import("std");
const udp = @import("udp.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

// TODO(#251): CID generation/lookup/retirement and the active-CID limit.

// ---------------------------------------------------------------------------
// Stateless reset (RFC 9000 §10.3)
// ---------------------------------------------------------------------------

pub const stateless_reset_token_len = 16;

/// Derive a connection's stateless-reset token from its connection ID under a
/// static server key (RFC 9000 §10.3.1). The token is the first 16 bytes of
/// HMAC-SHA256(static_key, connection_id); it MUST be hard to guess, so the
/// static key must be secret and stable across the connection's lifetime.
pub fn statelessResetToken(static_key: [32]u8, connection_id: []const u8) [stateless_reset_token_len]u8 {
    var mac: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&mac, connection_id, &static_key);
    return mac[0..stateless_reset_token_len].*;
}

/// Emission rules and packet construction for stateless resets (RFC 9000 §10.3).
pub const StatelessReset = struct {
    /// Smallest reset we emit: >= 5 unpredictable bytes plus the 16-byte token,
    /// so it is indistinguishable from a short-header packet (RFC 9000 §10.3).
    pub const min_len = 5 + stateless_reset_token_len;

    /// Whether a stateless reset may be sent in response to a packet of
    /// `received_len` bytes. A reset must be at least `min_len` and strictly
    /// smaller than the packet it answers, which both avoids an endless
    /// reset↔reset loop between two endpoints and keeps a server from being an
    /// amplifier. Packets too small to carry a reset get no response.
    pub fn eligible(received_len: usize) bool {
        return received_len > min_len;
    }

    /// Build a stateless reset into `out` responding to a packet of
    /// `received_len` bytes. `unpredictable` supplies the leading random bytes
    /// (its first byte's high bits are forced to `01` so the datagram looks like
    /// a short-header packet); `token` is the connection's reset token. The
    /// reset is sized one byte smaller than the triggering packet, clamped to
    /// `out`. Returns the written slice.
    pub fn build(
        out: []u8,
        received_len: usize,
        unpredictable: []const u8,
        token: [stateless_reset_token_len]u8,
    ) error{ NotEligible, OutputTooSmall, NotEnoughEntropy }![]u8 {
        if (!eligible(received_len)) return error.NotEligible;
        // One byte smaller than the trigger, but no larger than the output buffer.
        const reset_len = @min(received_len - 1, out.len);
        if (reset_len < min_len) return error.OutputTooSmall;

        const entropy_len = reset_len - stateless_reset_token_len;
        if (unpredictable.len < entropy_len) return error.NotEnoughEntropy;

        @memcpy(out[0..entropy_len], unpredictable[0..entropy_len]);
        // Short header form: clear the long-header bit, set the fixed bit.
        out[0] = (out[0] & 0x3f) | 0x40;
        @memcpy(out[entropy_len..][0..stateless_reset_token_len], &token);
        return out[0..reset_len];
    }
};

const testing = std.testing;

test "stateless reset token is a stable function of the connection ID" {
    const key = [_]u8{0xab} ** 32;
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    const token = statelessResetToken(key, &cid);
    // Deterministic for a given key + CID.
    try testing.expectEqualSlices(u8, &token, &statelessResetToken(key, &cid));

    // A different CID or key yields a different token.
    const other_cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09 };
    try testing.expect(!std.mem.eql(u8, &token, &statelessResetToken(key, &other_cid)));
    const other_key = [_]u8{0xcd} ** 32;
    try testing.expect(!std.mem.eql(u8, &token, &statelessResetToken(other_key, &cid)));
}

test "stateless reset is only emitted for packets large enough to answer safely" {
    // Too small to carry a reset (min_len = 21): no response.
    try testing.expect(!StatelessReset.eligible(StatelessReset.min_len));
    try testing.expect(StatelessReset.eligible(StatelessReset.min_len + 1));

    var out: [64]u8 = undefined;
    const token = [_]u8{0x7e} ** stateless_reset_token_len;
    const unpredictable = [_]u8{0xff} ** 64;

    try testing.expectError(error.NotEligible, StatelessReset.build(&out, StatelessReset.min_len, &unpredictable, token));
}

test "stateless reset is shorter than the packet it answers and ends with the token" {
    var out: [128]u8 = undefined;
    const token = [_]u8{0x5c} ** stateless_reset_token_len;
    const unpredictable = [_]u8{0xff} ** 128;

    const reset = try StatelessReset.build(&out, 40, &unpredictable, token);
    // One byte smaller than the trigger, avoiding a reset loop.
    try testing.expectEqual(@as(usize, 39), reset.len);
    // Looks like a short-header packet: high bits are 01.
    try testing.expectEqual(@as(u8, 0x40), reset[0] & 0xc0);
    // Trailing 16 bytes carry the reset token.
    try testing.expectEqualSlices(u8, &token, reset[reset.len - stateless_reset_token_len ..]);
}

test "stateless reset clamps to the output buffer for large triggers" {
    var out: [30]u8 = undefined;
    const token = [_]u8{0x11} ** stateless_reset_token_len;
    const unpredictable = [_]u8{0xa0} ** 30;

    // Trigger is large, but the reset is bounded by the 30-byte output buffer.
    const reset = try StatelessReset.build(&out, 1200, &unpredictable, token);
    try testing.expectEqual(@as(usize, 30), reset.len);
    try testing.expectEqualSlices(u8, &token, reset[reset.len - stateless_reset_token_len ..]);
}

test {
    testing.refAllDecls(@This());
}
