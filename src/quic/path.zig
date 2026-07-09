//! QUIC server address-validation and anti-amplification (#250, RFC 9000 §8 &
//! RFC 9001 §5.8): the safety mechanisms that let a server handle
//! unauthenticated UDP before a peer's address is validated without becoming an
//! amplification vector.
//!
//! - `AntiAmplification` enforces the 3x send budget per unvalidated path.
//! - `RetryTokens` issues and verifies integrity-protected address-validation
//!   tokens (timestamp/expiry, address binding, key rotation, tamper rejection).
//! - `retryIntegrityTag` / `verifyRetryIntegrity` implement the RFC 9001 Retry
//!   integrity tag. Stateless-reset tokens/packets live in `cid.zig`.
//! - `Metrics` exposes the operator counters the issue requires.
//!
//! Packet framing and DCID parsing stay in `packet.zig` (#243); connection
//! migration / path validation stay in #251; interop/fuzz in #247.

const std = @import("std");
const udp = @import("udp.zig");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

// ---------------------------------------------------------------------------
// Anti-amplification (RFC 9000 §8.1)
// ---------------------------------------------------------------------------

/// A server may send at most this multiple of the bytes it has received from an
/// unvalidated peer address.
pub const anti_amplification_factor = 3;

/// Per-path ledger of bytes received from and sent to a peer whose address has
/// not yet been validated. Once the address is validated the limit is lifted.
/// The connection layer records every received datagram and every send (including
/// handshake/certificate bytes and retransmissions) against this ledger.
pub const AntiAmplification = struct {
    received: u64 = 0,
    sent: u64 = 0,
    validated: bool = false,

    pub fn recordReceived(self: *AntiAmplification, bytes: u64) void {
        self.received +|= bytes;
    }

    pub fn recordSent(self: *AntiAmplification, bytes: u64) void {
        self.sent +|= bytes;
    }

    /// Mark the peer address validated (a Retry/handshake token was verified or
    /// the handshake completed). Lifts the send budget.
    pub fn markValidated(self: *AntiAmplification) void {
        self.validated = true;
    }

    /// Total bytes this side is currently permitted to have sent.
    pub fn budget(self: *const AntiAmplification) u64 {
        if (self.validated) return std.math.maxInt(u64);
        return self.received *| anti_amplification_factor;
    }

    /// Bytes that may still be sent before the budget is exhausted.
    pub fn remaining(self: *const AntiAmplification) u64 {
        if (self.validated) return std.math.maxInt(u64);
        return self.budget() -| self.sent;
    }

    /// Whether a datagram of `bytes` may be sent now without exceeding the
    /// budget. A blocked send must be deferred, not dropped or spun on.
    pub fn canSend(self: *const AntiAmplification, bytes: u64) bool {
        if (self.validated) return true;
        return (self.sent +| bytes) <= self.budget();
    }
};

// ---------------------------------------------------------------------------
// Retry / address-validation tokens (RFC 9000 §8.1.1–§8.1.4)
// ---------------------------------------------------------------------------

pub const token_key_len = Aes128Gcm.key_length;
pub const token_nonce_len = Aes128Gcm.nonce_length;
pub const token_tag_len = Aes128Gcm.tag_length;
pub const max_token_keys = 8;

/// Encoded plaintext is `issued_at(8) + family(1) + addr_len(1) + addr(4|16) + port(2)`.
const token_min_plaintext_len = 8 + 1 + 1 + 4 + 2;
const token_max_plaintext_len = 8 + 1 + 1 + 16 + 2;

/// Largest possible encoded token (`key_id + nonce + plaintext + tag`).
pub const max_token_len = 1 + token_nonce_len + token_max_plaintext_len + token_tag_len;

pub const TokenError = error{
    /// Token is too short/long to be well-formed.
    MalformedToken,
    /// Token names a key id the server does not hold (e.g. rotated out).
    UnknownTokenKey,
    /// AEAD authentication failed — the token was forged or tampered with.
    TokenAuthenticationFailed,
    /// Token authenticated but was issued to a different peer address.
    TokenAddressMismatch,
    /// Token authenticated but is older than the configured lifetime.
    TokenExpired,
};

/// A rotating ring of AEAD keys used to protect address-validation tokens.
/// Installing a key makes it current; older keys remain valid for verification
/// until explicitly retired, so tokens issued before a rotation still validate.
pub const RetryTokenKeyRing = struct {
    keys: [max_token_keys]?[token_key_len]u8 = .{null} ** max_token_keys,
    current: u8 = 0,

    pub fn install(self: *RetryTokenKeyRing, key_id: u8, key: [token_key_len]u8) void {
        std.debug.assert(key_id < max_token_keys);
        self.keys[key_id] = key;
        self.current = key_id;
    }

    pub fn retire(self: *RetryTokenKeyRing, key_id: u8) void {
        if (key_id < max_token_keys) self.keys[key_id] = null;
    }

    fn get(self: *const RetryTokenKeyRing, key_id: u8) ?[token_key_len]u8 {
        if (key_id >= max_token_keys) return null;
        return self.keys[key_id];
    }
};

/// Issues and verifies address-validation tokens. Tokens are AEAD-sealed with a
/// key from the ring and bind the peer address plus an issue timestamp.
pub const RetryTokens = struct {
    keys: RetryTokenKeyRing = .{},
    /// Maximum token age, in microseconds, before verification rejects it.
    lifetime_us: u64 = 10 * std.time.us_per_s,

    /// Seal a token for `address` stamped at `issued_at_us`. `nonce` must be
    /// unique per token under the current key (the caller supplies it so the
    /// module stays deterministic and free of ambient randomness).
    pub fn issue(
        self: *const RetryTokens,
        address: udp.Address,
        issued_at_us: u64,
        nonce: [token_nonce_len]u8,
        out: []u8,
    ) error{ OutputTooSmall, NoTokenKey }![]u8 {
        const key = self.keys.get(self.keys.current) orelse return error.NoTokenKey;

        var plaintext: [token_max_plaintext_len]u8 = undefined;
        const plaintext_len = encodeTokenPlaintext(address, issued_at_us, &plaintext);
        const total = 1 + token_nonce_len + plaintext_len + token_tag_len;
        if (out.len < total) return error.OutputTooSmall;

        out[0] = self.keys.current;
        @memcpy(out[1..][0..token_nonce_len], &nonce);
        const cipher = out[1 + token_nonce_len ..][0..plaintext_len];
        var tag: [token_tag_len]u8 = undefined;
        Aes128Gcm.encrypt(cipher, &tag, plaintext[0..plaintext_len], &.{}, nonce, key);
        @memcpy(out[1 + token_nonce_len + plaintext_len ..][0..token_tag_len], &tag);
        return out[0..total];
    }

    /// Verify a token was issued by this server to `address` and is unexpired.
    pub fn validate(self: *const RetryTokens, token: []const u8, address: udp.Address, now_us: u64) TokenError!void {
        if (token.len < 1 + token_nonce_len + token_min_plaintext_len + token_tag_len) return error.MalformedToken;
        if (token.len > max_token_len) return error.MalformedToken;
        const plaintext_len = token.len - 1 - token_nonce_len - token_tag_len;

        const key = self.keys.get(token[0]) orelse return error.UnknownTokenKey;
        var nonce: [token_nonce_len]u8 = undefined;
        @memcpy(&nonce, token[1..][0..token_nonce_len]);
        const cipher = token[1 + token_nonce_len ..][0..plaintext_len];
        var tag: [token_tag_len]u8 = undefined;
        @memcpy(&tag, token[1 + token_nonce_len + plaintext_len ..][0..token_tag_len]);

        var plaintext: [token_max_plaintext_len]u8 = undefined;
        Aes128Gcm.decrypt(plaintext[0..plaintext_len], cipher, tag, &.{}, nonce, key) catch return error.TokenAuthenticationFailed;

        const decoded = decodeTokenPlaintext(plaintext[0..plaintext_len]) catch return error.MalformedToken;
        if (!addressEql(decoded.address, address)) return error.TokenAddressMismatch;
        if ((now_us -| decoded.issued_at_us) > self.lifetime_us) return error.TokenExpired;
    }
};

const DecodedToken = struct { issued_at_us: u64, address: udp.Address };

fn encodeTokenPlaintext(address: udp.Address, issued_at_us: u64, out: *[token_max_plaintext_len]u8) usize {
    std.mem.writeInt(u64, out[0..8], issued_at_us, .big);
    out[8] = @intFromEnum(address.family);
    const addr = address.slice();
    out[9] = @intCast(addr.len);
    @memcpy(out[10..][0..addr.len], addr);
    std.mem.writeInt(u16, out[10 + addr.len ..][0..2], address.port, .big);
    return 10 + addr.len + 2;
}

fn decodeTokenPlaintext(bytes: []const u8) error{MalformedToken}!DecodedToken {
    if (bytes.len < 10) return error.MalformedToken;
    const issued_at_us = std.mem.readInt(u64, bytes[0..8], .big);
    const family = std.enums.fromInt(udp.AddressFamily, bytes[8]) orelse return error.MalformedToken;
    const addr_len = bytes[9];
    const expected_addr_len: usize = switch (family) {
        .ip4 => 4,
        .ip6 => 16,
    };
    if (addr_len != expected_addr_len) return error.MalformedToken;
    if (bytes.len != 10 + expected_addr_len + 2) return error.MalformedToken;
    const port = std.mem.readInt(u16, bytes[10 + expected_addr_len ..][0..2], .big);
    var address = udp.Address{ .family = family, .port = port };
    @memcpy(address.bytes[0..expected_addr_len], bytes[10..][0..expected_addr_len]);
    return .{ .issued_at_us = issued_at_us, .address = address };
}

fn addressEql(a: udp.Address, b: udp.Address) bool {
    if (a.family != b.family or a.port != b.port) return false;
    if (!std.mem.eql(u8, a.slice(), b.slice())) return false;
    // scope_id only distinguishes link-local IPv6 paths.
    return a.scope_id == b.scope_id;
}

// ---------------------------------------------------------------------------
// Retry integrity tag (RFC 9001 §5.8)
// ---------------------------------------------------------------------------

/// QUIC v1 Retry integrity AEAD key (RFC 9001 §5.8).
pub const retry_integrity_key_v1 = [16]u8{
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
    0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
};
/// QUIC v1 Retry integrity AEAD nonce (RFC 9001 §5.8).
pub const retry_integrity_nonce_v1 = [12]u8{
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
    0x23, 0x98, 0x25, 0xbb,
};
pub const retry_integrity_tag_len = 16;

/// Largest Retry packet body (everything before the integrity tag) this module
/// assembles a pseudo-packet for.
pub const max_retry_body_len = 512;
const max_retry_pseudo_len = 1 + udp.MaxConnectionIdLen + max_retry_body_len;

/// Compute the Retry integrity tag over the Retry pseudo-packet
/// (`ODCID length || ODCID || Retry packet without tag`), RFC 9001 §5.8.
pub fn retryIntegrityTag(
    original_dcid: []const u8,
    retry_body: []const u8,
) error{ ConnectionIdTooLong, RetryBodyTooLong }![retry_integrity_tag_len]u8 {
    if (original_dcid.len > udp.MaxConnectionIdLen) return error.ConnectionIdTooLong;
    if (retry_body.len > max_retry_body_len) return error.RetryBodyTooLong;

    var pseudo: [max_retry_pseudo_len]u8 = undefined;
    var len: usize = 0;
    pseudo[len] = @intCast(original_dcid.len);
    len += 1;
    @memcpy(pseudo[len..][0..original_dcid.len], original_dcid);
    len += original_dcid.len;
    @memcpy(pseudo[len..][0..retry_body.len], retry_body);
    len += retry_body.len;

    var tag: [retry_integrity_tag_len]u8 = undefined;
    Aes128Gcm.encrypt(&.{}, &tag, &.{}, pseudo[0..len], retry_integrity_nonce_v1, retry_integrity_key_v1);
    return tag;
}

/// Verify a received Retry packet's trailing integrity tag against `original_dcid`.
/// `retry_packet` includes the 16-byte tag. Returns false on tamper.
pub fn verifyRetryIntegrity(original_dcid: []const u8, retry_packet: []const u8) bool {
    if (retry_packet.len < retry_integrity_tag_len) return false;
    const body = retry_packet[0 .. retry_packet.len - retry_integrity_tag_len];
    const received_tag = retry_packet[retry_packet.len - retry_integrity_tag_len ..][0..retry_integrity_tag_len];
    const expected = retryIntegrityTag(original_dcid, body) catch return false;
    return std.crypto.timing_safe.eql([retry_integrity_tag_len]u8, expected, received_tag.*);
}

// ---------------------------------------------------------------------------
// Operator metrics (issue #250)
// ---------------------------------------------------------------------------

/// Counters that let an operator distinguish normal Retry usage from invalid
/// tokens, budget-blocked sends, and unknown-CID / stateless-reset traffic.
pub const Metrics = struct {
    retry_packets_sent: u64 = 0,
    invalid_tokens: u64 = 0,
    amplification_blocked_sends: u64 = 0,
    stateless_resets_sent: u64 = 0,
    unknown_connection_id_packets: u64 = 0,

    pub fn recordRetrySent(self: *Metrics) void {
        self.retry_packets_sent += 1;
    }

    pub fn recordInvalidToken(self: *Metrics) void {
        self.invalid_tokens += 1;
    }

    pub fn recordAmplificationBlocked(self: *Metrics) void {
        self.amplification_blocked_sends += 1;
    }

    pub fn recordStatelessReset(self: *Metrics) void {
        self.stateless_resets_sent += 1;
    }

    pub fn recordUnknownConnectionId(self: *Metrics) void {
        self.unknown_connection_id_packets += 1;
    }

    /// Fold a token-validation result into the counters (invalid tokens are
    /// counted; a success is a no-op).
    pub fn recordTokenValidation(self: *Metrics, result: TokenError!void) void {
        if (result) |_| {} else |_| self.recordInvalidToken();
    }
};

const testing = std.testing;

fn loopbackV4(port: u16) udp.Address {
    return udp.Address.ip4(.{ 127, 0, 0, 1 }, port);
}

test "anti-amplification caps sends at 3x received until validated" {
    var limiter = AntiAmplification{};
    limiter.recordReceived(1200);
    try testing.expectEqual(@as(u64, 3600), limiter.budget());
    try testing.expectEqual(@as(u64, 3600), limiter.remaining());

    try testing.expect(limiter.canSend(3600));
    try testing.expect(!limiter.canSend(3601));

    limiter.recordSent(3000);
    try testing.expectEqual(@as(u64, 600), limiter.remaining());
    try testing.expect(limiter.canSend(600));
    try testing.expect(!limiter.canSend(601));

    // Validation lifts the budget entirely.
    limiter.markValidated();
    try testing.expect(limiter.canSend(std.math.maxInt(u64)));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), limiter.remaining());
}

test "anti-amplification accounting saturates instead of overflowing" {
    var limiter = AntiAmplification{};
    limiter.recordReceived(std.math.maxInt(u64));
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), limiter.budget());
    try testing.expect(limiter.canSend(std.math.maxInt(u64)));
}

test "retry token round-trips and binds the peer address" {
    var tokens = RetryTokens{ .lifetime_us = 10_000_000 };
    tokens.keys.install(0, [_]u8{0xa5} ** token_key_len);

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issue(loopbackV4(4433), 1_000_000, [_]u8{0x11} ** token_nonce_len, &buf);

    try tokens.validate(token, loopbackV4(4433), 1_500_000);
    // A different port is a different path.
    try testing.expectError(error.TokenAddressMismatch, tokens.validate(token, loopbackV4(4434), 1_500_000));
    // A different host is a different path.
    try testing.expectError(error.TokenAddressMismatch, tokens.validate(token, udp.Address.ip4(.{ 10, 0, 0, 1 }, 4433), 1_500_000));
}

test "retry token expires after its lifetime" {
    var tokens = RetryTokens{ .lifetime_us = 5_000_000 };
    tokens.keys.install(1, [_]u8{0x5a} ** token_key_len);

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issue(loopbackV4(443), 2_000_000, [_]u8{0x22} ** token_nonce_len, &buf);

    try tokens.validate(token, loopbackV4(443), 7_000_000); // exactly at the limit
    try testing.expectError(error.TokenExpired, tokens.validate(token, loopbackV4(443), 7_000_001));
}

test "retry token rejects tampering and unknown keys" {
    var tokens = RetryTokens{ .lifetime_us = 10_000_000 };
    tokens.keys.install(0, [_]u8{0x01} ** token_key_len);

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issue(loopbackV4(4433), 1_000_000, [_]u8{0x33} ** token_nonce_len, &buf);

    // Flip a ciphertext byte: AEAD authentication must fail.
    var tampered: [max_token_len]u8 = undefined;
    @memcpy(tampered[0..token.len], token);
    tampered[1 + token_nonce_len] ^= 0x80;
    try testing.expectError(error.TokenAuthenticationFailed, tokens.validate(tampered[0..token.len], loopbackV4(4433), 1_000_000));

    // Name a key id the ring never held.
    var wrong_key: [max_token_len]u8 = undefined;
    @memcpy(wrong_key[0..token.len], token);
    wrong_key[0] = 7;
    try testing.expectError(error.UnknownTokenKey, tokens.validate(wrong_key[0..token.len], loopbackV4(4433), 1_000_000));

    // Truncated token is malformed.
    try testing.expectError(error.MalformedToken, tokens.validate(token[0..10], loopbackV4(4433), 1_000_000));
}

test "retry token survives key rotation while a key is retained" {
    var tokens = RetryTokens{ .lifetime_us = 10_000_000 };
    tokens.keys.install(0, [_]u8{0x01} ** token_key_len);

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issue(loopbackV4(4433), 1_000_000, [_]u8{0x44} ** token_nonce_len, &buf);

    // Rotate to a new current key; the old key still validates prior tokens.
    tokens.keys.install(1, [_]u8{0x02} ** token_key_len);
    try tokens.validate(token, loopbackV4(4433), 1_000_000);

    // Retiring the issuing key invalidates its tokens.
    tokens.keys.retire(0);
    try testing.expectError(error.UnknownTokenKey, tokens.validate(token, loopbackV4(4433), 1_000_000));
}

test "retry integrity tag matches the RFC 9001 Appendix A.4 vector" {
    var odcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&odcid, "8394c8f03e515708");
    var retry_body: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&retry_body, "ff000000010008f067a5502a4262b5746f6b656e");

    const tag = try retryIntegrityTag(&odcid, &retry_body);
    var expected: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "04a265ba2eff4d829058fb3f0f2496ba");
    try testing.expectEqualSlices(u8, &expected, &tag);

    // The full Retry packet (body + tag) verifies; a tampered tag does not.
    var retry_packet: [36]u8 = undefined;
    @memcpy(retry_packet[0..20], &retry_body);
    @memcpy(retry_packet[20..], &tag);
    try testing.expect(verifyRetryIntegrity(&odcid, &retry_packet));

    retry_packet[35] ^= 0x01;
    try testing.expect(!verifyRetryIntegrity(&odcid, &retry_packet));
    // Wrong original DCID must also fail.
    @memcpy(retry_packet[20..], &tag);
    try testing.expect(!verifyRetryIntegrity("wrongdcid", &retry_packet));
}

test "metrics distinguish invalid tokens from normal retry usage" {
    var tokens = RetryTokens{ .lifetime_us = 1_000_000 };
    tokens.keys.install(0, [_]u8{0x09} ** token_key_len);
    var metrics = Metrics{};

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issue(loopbackV4(4433), 1_000_000, [_]u8{0x55} ** token_nonce_len, &buf);
    metrics.recordRetrySent();

    metrics.recordTokenValidation(tokens.validate(token, loopbackV4(4433), 1_500_000)); // valid
    metrics.recordTokenValidation(tokens.validate(token, loopbackV4(4433), 9_000_000)); // expired
    metrics.recordTokenValidation(tokens.validate(token, loopbackV4(9999), 1_500_000)); // wrong address

    try testing.expectEqual(@as(u64, 1), metrics.retry_packets_sent);
    try testing.expectEqual(@as(u64, 2), metrics.invalid_tokens);
}
