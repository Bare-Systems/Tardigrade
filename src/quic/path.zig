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
//! - `PathManager` (#251) owns the per-connection path table keyed by the
//!   (local, remote) address tuple: PATH_CHALLENGE/PATH_RESPONSE validation,
//!   NAT-rebinding vs. migration classification, the configurable migration
//!   policy from `config.zig`, and the RFC 9000 §9.4 congestion-reset rule.
//! - `Metrics` exposes the operator counters #250/#251 require.
//!
//! Packet framing and DCID parsing stay in `packet.zig` (#243); CID issuance
//! and routing live in `cid.zig`; interop/fuzz in #247.

const std = @import("std");
const config = @import("config.zig");
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

/// What a token authenticates. Retry tokens are bound to a specific connection
/// attempt (original DCID + QUIC version); the enum leaves room for the future
/// NEW_TOKEN address-validation flow (RFC 9000 §8.1.3) without a format break.
pub const TokenKind = enum(u8) {
    retry = 1,
    address_validation = 2,
};

/// Fixed-size prefix of the token plaintext: `kind(1) + version(4) +
/// issued_at(8) + odcid_len(1)`. The connection ID, address, and port follow.
const token_header_len = 1 + 4 + 8 + 1;
/// Variable address suffix: `family(1) + addr_len(1) + addr(4|16) +
/// scope_id(4, IPv6 only) + port(2)`.
const token_addr_min_len = 1 + 1 + 4 + 2; // IPv4
const token_addr_max_len = 1 + 1 + 16 + 4 + 2; // IPv6, with scope id
const token_min_plaintext_len = token_header_len + 0 + token_addr_min_len;
const token_max_plaintext_len = token_header_len + udp.MaxConnectionIdLen + token_addr_max_len;

/// Largest possible encoded token (`key_id + nonce + plaintext + tag`).
pub const max_token_len = 1 + token_nonce_len + token_max_plaintext_len + token_tag_len;

pub const TokenError = error{
    /// Token is too short/long or otherwise not well-formed.
    MalformedToken,
    /// Token names a key id the server does not hold (e.g. rotated out).
    UnknownTokenKey,
    /// AEAD authentication failed — the token was forged or tampered with.
    TokenAuthenticationFailed,
    /// Token authenticated but was issued to a different peer address.
    TokenAddressMismatch,
    /// Token authenticated but is expired or impossibly future-dated.
    TokenExpired,
    /// Token authenticated but is not the expected kind (e.g. NEW_TOKEN where a
    /// Retry token was required).
    UnexpectedTokenKind,
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

/// Context recovered from a validated Retry token. The connection layer needs
/// the original destination connection ID and QUIC version to validate the
/// Retry flow and populate/verify the `original_destination_connection_id`
/// transport parameter (RFC 9000 §7.3).
pub const RetryContext = struct {
    original_dcid: udp.ConnectionId,
    quic_version: u32,
};

/// Issues and verifies Retry address-validation tokens. Tokens are AEAD-sealed
/// with a key from the ring and bind the original destination connection ID,
/// the QUIC version, the peer address, and an issue timestamp.
pub const RetryTokens = struct {
    keys: RetryTokenKeyRing = .{},
    /// Maximum token age, in microseconds, before verification rejects it.
    lifetime_us: u64 = 10 * std.time.us_per_s,
    /// Tolerance for a token whose issue time is slightly ahead of the
    /// validator's clock. Tokens further in the future are rejected.
    allowed_clock_skew_us: u64 = 0,

    /// Seal a Retry token binding `original_dcid` + `quic_version` + `address`,
    /// stamped at `issued_at_us`. `nonce` must be unique per token under the
    /// current key (the caller supplies it so the module stays deterministic and
    /// free of ambient randomness).
    pub fn issueRetry(
        self: *const RetryTokens,
        original_dcid: []const u8,
        quic_version: u32,
        address: udp.Address,
        issued_at_us: u64,
        nonce: [token_nonce_len]u8,
        out: []u8,
    ) error{ OutputTooSmall, NoTokenKey, ConnectionIdTooLong }![]u8 {
        if (original_dcid.len > udp.MaxConnectionIdLen) return error.ConnectionIdTooLong;
        const key = self.keys.get(self.keys.current) orelse return error.NoTokenKey;

        var plaintext: [token_max_plaintext_len]u8 = undefined;
        const plaintext_len = encodeTokenPlaintext(.retry, quic_version, original_dcid, address, issued_at_us, &plaintext);
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

    /// Verify a Retry token was issued by this server to `address`, is a Retry
    /// token, and is neither expired nor impossibly future-dated. Returns the
    /// bound original DCID and QUIC version for the connection layer.
    pub fn validateRetry(self: *const RetryTokens, token: []const u8, address: udp.Address, now_us: u64) TokenError!RetryContext {
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
        if (decoded.kind != .retry) return error.UnexpectedTokenKind;
        if (!addressEql(decoded.address, address)) return error.TokenAddressMismatch;
        // Reject tokens dated further in the future than the allowed skew, so a
        // backwards clock jump cannot make a stale token look freshly issued.
        if (decoded.issued_at_us > now_us +| self.allowed_clock_skew_us) return error.TokenExpired;
        if ((now_us -| decoded.issued_at_us) > self.lifetime_us) return error.TokenExpired;
        return .{ .original_dcid = decoded.original_dcid, .quic_version = decoded.quic_version };
    }
};

const DecodedToken = struct {
    kind: TokenKind,
    quic_version: u32,
    issued_at_us: u64,
    original_dcid: udp.ConnectionId,
    address: udp.Address,
};

fn encodeTokenPlaintext(
    kind: TokenKind,
    quic_version: u32,
    original_dcid: []const u8,
    address: udp.Address,
    issued_at_us: u64,
    out: *[token_max_plaintext_len]u8,
) usize {
    var pos: usize = 0;
    out[pos] = @intFromEnum(kind);
    pos += 1;
    std.mem.writeInt(u32, out[pos..][0..4], quic_version, .big);
    pos += 4;
    std.mem.writeInt(u64, out[pos..][0..8], issued_at_us, .big);
    pos += 8;
    out[pos] = @intCast(original_dcid.len);
    pos += 1;
    @memcpy(out[pos..][0..original_dcid.len], original_dcid);
    pos += original_dcid.len;

    out[pos] = @intFromEnum(address.family);
    pos += 1;
    const addr = address.slice();
    out[pos] = @intCast(addr.len);
    pos += 1;
    @memcpy(out[pos..][0..addr.len], addr);
    pos += addr.len;
    // Encode scope_id for IPv6 so scoped (link-local) addresses round-trip.
    if (address.family == .ip6) {
        std.mem.writeInt(u32, out[pos..][0..4], address.scope_id, .big);
        pos += 4;
    }
    std.mem.writeInt(u16, out[pos..][0..2], address.port, .big);
    pos += 2;
    return pos;
}

fn decodeTokenPlaintext(bytes: []const u8) error{MalformedToken}!DecodedToken {
    var pos: usize = 0;
    if (bytes.len < token_header_len) return error.MalformedToken;
    const kind = std.enums.fromInt(TokenKind, bytes[pos]) orelse return error.MalformedToken;
    pos += 1;
    const quic_version = std.mem.readInt(u32, bytes[pos..][0..4], .big);
    pos += 4;
    const issued_at_us = std.mem.readInt(u64, bytes[pos..][0..8], .big);
    pos += 8;
    const odcid_len = bytes[pos];
    pos += 1;
    if (odcid_len > udp.MaxConnectionIdLen) return error.MalformedToken;
    if (bytes.len - pos < odcid_len) return error.MalformedToken;
    var original_dcid = udp.ConnectionId{ .len = odcid_len };
    @memcpy(original_dcid.bytes[0..odcid_len], bytes[pos..][0..odcid_len]);
    pos += odcid_len;

    if (bytes.len - pos < 2) return error.MalformedToken;
    const family = std.enums.fromInt(udp.AddressFamily, bytes[pos]) orelse return error.MalformedToken;
    pos += 1;
    const addr_len = bytes[pos];
    pos += 1;
    const expected_addr_len: usize = switch (family) {
        .ip4 => 4,
        .ip6 => 16,
    };
    if (addr_len != expected_addr_len) return error.MalformedToken;
    if (bytes.len - pos < expected_addr_len) return error.MalformedToken;
    var address = udp.Address{ .family = family, .port = 0 };
    @memcpy(address.bytes[0..expected_addr_len], bytes[pos..][0..expected_addr_len]);
    pos += expected_addr_len;
    if (family == .ip6) {
        if (bytes.len - pos < 4) return error.MalformedToken;
        address.scope_id = std.mem.readInt(u32, bytes[pos..][0..4], .big);
        pos += 4;
    }
    if (bytes.len - pos != 2) return error.MalformedToken;
    address.port = std.mem.readInt(u16, bytes[pos..][0..2], .big);

    return .{
        .kind = kind,
        .quic_version = quic_version,
        .issued_at_us = issued_at_us,
        .original_dcid = original_dcid,
        .address = address,
    };
}

fn addressEql(a: udp.Address, b: udp.Address) bool {
    if (a.family != b.family or a.port != b.port) return false;
    if (!std.mem.eql(u8, a.slice(), b.slice())) return false;
    // scope_id distinguishes link-local IPv6 paths and now round-trips in tokens.
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
    // Path lifecycle (#251): the acceptance criteria require distinguishing
    // rebinding, migration, validation failure, and blocked attempts.
    path_challenges_sent: u64 = 0,
    path_validations_succeeded: u64 = 0,
    /// Validations that failed terminally: the challenge expired unanswered.
    path_validations_failed: u64 = 0,
    /// PATH_RESPONSE frames that validated nothing — wrong payload, wrong
    /// path, or no outstanding challenge. Kept separate from
    /// `path_validations_failed` because the probe may still succeed; a spike
    /// here without failures suggests reordering or off-path spoofing.
    path_response_mismatches: u64 = 0,
    nat_rebindings: u64 = 0,
    migrations: u64 = 0,
    migrations_blocked: u64 = 0,

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
    /// counted; a success is a no-op). Accepts any `TokenError!T` result.
    pub fn recordTokenValidation(self: *Metrics, result: anytype) void {
        if (result) |_| {} else |_| self.recordInvalidToken();
    }
};

// ---------------------------------------------------------------------------
// Path state, PATH_CHALLENGE / PATH_RESPONSE validation, and migration policy
// (#251, RFC 9000 §8.2 / §9)
// ---------------------------------------------------------------------------

pub const path_challenge_len = 8;
/// Most concurrently tracked paths per connection: the active path plus a
/// small number of probes. A peer hopping addresses faster than probes
/// resolve recycles the oldest failed/unvalidated slot.
pub const max_paths = 4;
/// How long a PATH_CHALLENGE may stay unanswered before the validation fails
/// deterministically. Connection integration can override per RTT (3×PTO);
/// the default keeps standalone use safe.
pub const default_validation_timeout_us: u64 = 1_000_000;

/// A network path keyed by the (local, remote) address tuple.
pub const PathKey = struct {
    local: udp.Address,
    remote: udp.Address,

    pub fn eql(self: PathKey, other: PathKey) bool {
        return self.local.eql(other.local) and self.remote.eql(other.remote);
    }
};

pub const PathState = enum {
    /// Traffic seen, no validation started (policy denied or not yet probed).
    unvalidated,
    /// PATH_CHALLENGE outstanding.
    validating,
    /// PATH_RESPONSE echoed the challenge; the path is usable.
    validated,
    /// The challenge expired unanswered.
    failed,
};

/// How a new remote tuple is classified against the active path.
pub const AddressChange = enum {
    /// Same host, different port: almost always a NAT rebinding (RFC 9308 §4.1).
    nat_rebinding,
    /// Different host: a real migration with likely-new path characteristics.
    migration,
};

pub const Path = struct {
    key: PathKey,
    state: PathState = .unvalidated,
    change: AddressChange,
    challenge: [path_challenge_len]u8 = undefined,
    challenge_deadline_us: u64 = 0,
    anti_amplification: AntiAmplification = .{},
};

/// The action the connection takes for a datagram from a given tuple.
pub const PathDecision = union(enum) {
    /// Datagram arrived on the active path: nothing to do.
    on_active_path,
    /// A new/unvalidated tuple is being probed: send PATH_CHALLENGE with this
    /// payload on that path (RFC 9000 §9.3: packets from the new address are
    /// processed, but the path is validated before it becomes the active one).
    probe: [path_challenge_len]u8,
    /// Probe already in flight for this tuple; nothing new to send.
    probing,
    /// Migration policy forbids this address change: the caller drops state
    /// changes for this tuple (packets themselves stay processed on the
    /// active path per RFC 9000 §9.1 server behavior for disabled migration).
    blocked,
};

/// Result of a successful path validation switch.
pub const MigrationOutcome = struct {
    change: AddressChange,
    /// RFC 9000 §9.4 policy, documented here once: RTT and congestion state
    /// reset (`recovery.RecoveryController.resetForPathMigration`) when the
    /// peer's *host* changed — new path, unknown characteristics. A NAT
    /// rebinding that only changed the port keeps the estimator, since the
    /// underlying path is almost certainly the same.
    reset_congestion: bool,
};

pub const PathManager = struct {
    policy: config.MigrationPolicy,
    validation_timeout_us: u64 = default_validation_timeout_us,
    paths: [max_paths]?Path = [_]?Path{null} ** max_paths,
    /// Index of the active (validated, in-use) path.
    active: usize = 0,
    metrics: Metrics = .{},

    /// Start with the handshake path: it is validated by the handshake itself
    /// (RFC 9000 §8.1).
    pub fn init(policy: config.MigrationPolicy, handshake_path: PathKey) PathManager {
        var manager = PathManager{ .policy = policy };
        manager.paths[0] = .{
            .key = handshake_path,
            .state = .validated,
            .change = .migration,
        };
        manager.paths[0].?.anti_amplification.markValidated();
        return manager;
    }

    pub fn activePath(self: *const PathManager) *const Path {
        return &self.paths[self.active].?;
    }

    /// Classify a datagram's tuple and drive path state. `challenge_entropy`
    /// supplies the unpredictable PATH_CHALLENGE payload (RFC 9000 §8.2.1)
    /// when a probe starts.
    pub fn onDatagram(
        self: *PathManager,
        key: PathKey,
        challenge_entropy: [path_challenge_len]u8,
        now_us: u64,
    ) PathDecision {
        if (key.eql(self.paths[self.active].?.key)) return .on_active_path;

        const change: AddressChange = if (key.remote.sameHost(self.paths[self.active].?.key.remote))
            .nat_rebinding
        else
            .migration;

        const allowed = switch (self.policy) {
            .disabled => false,
            .nat_rebinding_only => change == .nat_rebinding,
            .full => true,
        };
        if (!allowed) {
            self.metrics.migrations_blocked += 1;
            return .blocked;
        }

        if (self.find(key)) |index| {
            const path = &self.paths[index].?;
            switch (path.state) {
                .validating => return .probing,
                // Fresh traffic on a previously failed/unvalidated tuple:
                // start a new probe.
                .failed, .unvalidated => {},
                // A validated non-active path re-activates only through a new
                // challenge round trip, keeping the switch deterministic.
                .validated => {},
            }
            path.state = .validating;
            path.change = change;
            path.challenge = challenge_entropy;
            path.challenge_deadline_us = now_us + self.validation_timeout_us;
            self.metrics.path_challenges_sent += 1;
            return .{ .probe = challenge_entropy };
        }

        const slot = self.claimSlot();
        self.paths[slot] = .{
            .key = key,
            .state = .validating,
            .change = change,
            .challenge = challenge_entropy,
            .challenge_deadline_us = now_us + self.validation_timeout_us,
        };
        self.metrics.path_challenges_sent += 1;
        return .{ .probe = challenge_entropy };
    }

    /// PATH_CHALLENGE handling is stateless: echo the payload in a
    /// PATH_RESPONSE on the same path (RFC 9000 §8.2.2).
    pub fn onPathChallenge(data: [path_challenge_len]u8) [path_challenge_len]u8 {
        return data;
    }

    /// Apply a PATH_RESPONSE received from `key`. On a match the path becomes
    /// validated and active, and the outcome says whether congestion/RTT
    /// state must reset. A response with no matching outstanding challenge —
    /// wrong payload, wrong path, or expired — is ignored (null) and counted
    /// in `path_response_mismatches`: responses do not validate paths they
    /// were not sent on (RFC 9000 §8.2.3), but the probe itself keeps waiting
    /// (only expiry fails it terminally).
    pub fn onPathResponse(
        self: *PathManager,
        key: PathKey,
        data: [path_challenge_len]u8,
        now_us: u64,
    ) ?MigrationOutcome {
        const index = self.find(key) orelse {
            self.metrics.path_response_mismatches += 1;
            return null;
        };
        const path = &self.paths[index].?;
        if (path.state != .validating) {
            self.metrics.path_response_mismatches += 1;
            return null;
        }
        if (now_us > path.challenge_deadline_us) {
            self.failValidation(path);
            return null;
        }
        if (!std.crypto.timing_safe.eql([path_challenge_len]u8, path.challenge, data)) {
            self.metrics.path_response_mismatches += 1;
            return null;
        }

        path.state = .validated;
        path.anti_amplification.markValidated();
        self.active = index;
        self.metrics.path_validations_succeeded += 1;
        switch (path.change) {
            .nat_rebinding => self.metrics.nat_rebindings += 1,
            .migration => self.metrics.migrations += 1,
        }
        return .{
            .change = path.change,
            .reset_congestion = path.change == .migration,
        };
    }

    /// Fail every probe whose challenge deadline has passed. Returns how many
    /// validations failed; callers run this off their timer wheel.
    pub fn expireValidations(self: *PathManager, now_us: u64) usize {
        var failed: usize = 0;
        for (&self.paths) |*slot| {
            const path = &(slot.* orelse continue);
            if (path.state != .validating) continue;
            if (now_us <= path.challenge_deadline_us) continue;
            self.failValidation(path);
            failed += 1;
        }
        return failed;
    }

    fn failValidation(self: *PathManager, path: *Path) void {
        path.state = .failed;
        self.metrics.path_validations_failed += 1;
    }

    fn find(self: *const PathManager, key: PathKey) ?usize {
        for (self.paths, 0..) |slot, index| {
            const path = slot orelse continue;
            if (path.key.eql(key)) return index;
        }
        return null;
    }

    /// A free slot, or the oldest non-active failed/unvalidated slot when the
    /// table is full — probe storms recycle probes, never the active path.
    fn claimSlot(self: *PathManager) usize {
        for (self.paths, 0..) |slot, index| {
            if (slot == null) return index;
        }
        for (self.paths, 0..) |slot, index| {
            if (index == self.active) continue;
            if (slot.?.state == .failed or slot.?.state == .unvalidated) return index;
        }
        // All slots are live probes: recycle the first non-active one.
        for (self.paths, 0..) |_, index| {
            if (index != self.active) return index;
        }
        unreachable; // max_paths >= 2 guarantees a non-active slot
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

const test_odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const test_version: u32 = 0x0000_0001;

test "retry token round-trips and recovers the original DCID and version" {
    var tokens = RetryTokens{ .lifetime_us = 10_000_000 };
    tokens.keys.install(0, [_]u8{0xa5} ** token_key_len);

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, test_version, loopbackV4(4433), 1_000_000, [_]u8{0x11} ** token_nonce_len, &buf);

    const ctx = try tokens.validateRetry(token, loopbackV4(4433), 1_500_000);
    try testing.expectEqualSlices(u8, &test_odcid, ctx.original_dcid.slice());
    try testing.expectEqual(test_version, ctx.quic_version);

    // A different port or host is a different path.
    try testing.expectError(error.TokenAddressMismatch, tokens.validateRetry(token, loopbackV4(4434), 1_500_000));
    try testing.expectError(error.TokenAddressMismatch, tokens.validateRetry(token, udp.Address.ip4(.{ 10, 0, 0, 1 }, 4433), 1_500_000));
}

test "retry token binds scoped IPv6 addresses including the scope id" {
    var tokens = RetryTokens{ .lifetime_us = 10_000_000 };
    tokens.keys.install(0, [_]u8{0xa5} ** token_key_len);

    const scoped = udp.Address.ip6([_]u8{0xfe} ++ [_]u8{0x80} ++ [_]u8{0} ** 13 ++ [_]u8{0x01}, 4433, 7);
    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, test_version, scoped, 1_000_000, [_]u8{0x66} ** token_nonce_len, &buf);

    // Same address including scope id validates; a different scope id does not.
    _ = try tokens.validateRetry(token, scoped, 1_500_000);
    const other_scope = udp.Address.ip6(scoped.bytes, 4433, 9);
    try testing.expectError(error.TokenAddressMismatch, tokens.validateRetry(token, other_scope, 1_500_000));
}

test "retry token expires after its lifetime" {
    var tokens = RetryTokens{ .lifetime_us = 5_000_000 };
    tokens.keys.install(1, [_]u8{0x5a} ** token_key_len);

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, test_version, loopbackV4(443), 2_000_000, [_]u8{0x22} ** token_nonce_len, &buf);

    _ = try tokens.validateRetry(token, loopbackV4(443), 7_000_000); // exactly at the limit
    try testing.expectError(error.TokenExpired, tokens.validateRetry(token, loopbackV4(443), 7_000_001));
}

test "retry token dated in the future is rejected" {
    var tokens = RetryTokens{ .lifetime_us = 5_000_000, .allowed_clock_skew_us = 1_000 };
    tokens.keys.install(0, [_]u8{0x7a} ** token_key_len);

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, test_version, loopbackV4(443), 5_000_000, [_]u8{0x77} ** token_nonce_len, &buf);

    // Within the allowed skew: accepted (age saturates to zero).
    _ = try tokens.validateRetry(token, loopbackV4(443), 4_999_500);
    // Further in the future than the skew: rejected instead of treated as fresh.
    try testing.expectError(error.TokenExpired, tokens.validateRetry(token, loopbackV4(443), 4_000_000));
}

test "retry token rejects tampering and unknown keys" {
    var tokens = RetryTokens{ .lifetime_us = 10_000_000 };
    tokens.keys.install(0, [_]u8{0x01} ** token_key_len);

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, test_version, loopbackV4(4433), 1_000_000, [_]u8{0x33} ** token_nonce_len, &buf);

    // Flip a ciphertext byte: AEAD authentication must fail.
    var tampered: [max_token_len]u8 = undefined;
    @memcpy(tampered[0..token.len], token);
    tampered[1 + token_nonce_len] ^= 0x80;
    try testing.expectError(error.TokenAuthenticationFailed, tokens.validateRetry(tampered[0..token.len], loopbackV4(4433), 1_000_000));

    // Name a key id the ring never held.
    var wrong_key: [max_token_len]u8 = undefined;
    @memcpy(wrong_key[0..token.len], token);
    wrong_key[0] = 7;
    try testing.expectError(error.UnknownTokenKey, tokens.validateRetry(wrong_key[0..token.len], loopbackV4(4433), 1_000_000));

    // Truncated token is malformed.
    try testing.expectError(error.MalformedToken, tokens.validateRetry(token[0..10], loopbackV4(4433), 1_000_000));
}

test "retry token survives key rotation while a key is retained" {
    var tokens = RetryTokens{ .lifetime_us = 10_000_000 };
    tokens.keys.install(0, [_]u8{0x01} ** token_key_len);

    var buf: [max_token_len]u8 = undefined;
    const token = try tokens.issueRetry(&test_odcid, test_version, loopbackV4(4433), 1_000_000, [_]u8{0x44} ** token_nonce_len, &buf);

    // Rotate to a new current key; the old key still validates prior tokens.
    tokens.keys.install(1, [_]u8{0x02} ** token_key_len);
    _ = try tokens.validateRetry(token, loopbackV4(4433), 1_000_000);

    // Retiring the issuing key invalidates its tokens.
    tokens.keys.retire(0);
    try testing.expectError(error.UnknownTokenKey, tokens.validateRetry(token, loopbackV4(4433), 1_000_000));
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
    const token = try tokens.issueRetry(&test_odcid, test_version, loopbackV4(4433), 1_000_000, [_]u8{0x55} ** token_nonce_len, &buf);
    metrics.recordRetrySent();

    metrics.recordTokenValidation(tokens.validateRetry(token, loopbackV4(4433), 1_500_000)); // valid
    metrics.recordTokenValidation(tokens.validateRetry(token, loopbackV4(4433), 9_000_000)); // expired
    metrics.recordTokenValidation(tokens.validateRetry(token, loopbackV4(9999), 1_500_000)); // wrong address

    try testing.expectEqual(@as(u64, 1), metrics.retry_packets_sent);
    try testing.expectEqual(@as(u64, 2), metrics.invalid_tokens);
}

// ---------------------------------------------------------------------------
// Path validation / migration tests (#251)
// ---------------------------------------------------------------------------

fn testKey(remote_port: u16) PathKey {
    return .{ .local = loopbackV4(4433), .remote = udp.Address.ip4(.{ 192, 0, 2, 10 }, remote_port) };
}

fn testKeyOtherHost(remote_port: u16) PathKey {
    return .{ .local = loopbackV4(4433), .remote = udp.Address.ip4(.{ 198, 51, 100, 7 }, remote_port) };
}

const test_challenge = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

test "datagrams on the active path require no action" {
    var manager = PathManager.init(.full, testKey(50_000));
    try testing.expectEqual(PathDecision.on_active_path, manager.onDatagram(testKey(50_000), test_challenge, 0));
    try testing.expectEqual(PathState.validated, manager.activePath().state);
}

test "path validation succeeds deterministically and switches the active path" {
    var manager = PathManager.init(.full, testKey(50_000));
    const rebound = testKey(50_001); // same host, new port: NAT rebinding

    const decision = manager.onDatagram(rebound, test_challenge, 1_000);
    try testing.expectEqualSlices(u8, &test_challenge, &decision.probe);
    try testing.expectEqual(@as(u64, 1), manager.metrics.path_challenges_sent);

    // Peer echoes the challenge (PATH_RESPONSE semantics are a pure echo).
    const echoed = PathManager.onPathChallenge(test_challenge);
    const outcome = manager.onPathResponse(rebound, echoed, 2_000).?;
    try testing.expectEqual(AddressChange.nat_rebinding, outcome.change);
    // Port-only rebinding: same underlying path, keep congestion/RTT state.
    try testing.expect(!outcome.reset_congestion);
    try testing.expect(manager.activePath().key.eql(rebound));
    try testing.expectEqual(@as(u64, 1), manager.metrics.nat_rebindings);
    try testing.expectEqual(@as(u64, 1), manager.metrics.path_validations_succeeded);
}

test "a real migration validates and requires congestion/RTT reset" {
    var manager = PathManager.init(.full, testKey(50_000));
    const migrated = testKeyOtherHost(50_000); // new host: real migration

    _ = manager.onDatagram(migrated, test_challenge, 0);
    const outcome = manager.onPathResponse(migrated, test_challenge, 100).?;
    try testing.expectEqual(AddressChange.migration, outcome.change);
    try testing.expect(outcome.reset_congestion);
    try testing.expectEqual(@as(u64, 1), manager.metrics.migrations);

    // The documented reset actually reinitializes recovery state.
    const recovery = @import("recovery.zig");
    var controller = recovery.RecoveryController{};
    controller.rtt.update(50_000, 0);
    controller.congestion.congestion_window = 3;
    const old_path_packet = recovery.SentPacket{
        .space = .application,
        .packet_number = 5,
        .time_sent_us = 10,
        .size = 999,
    };
    controller.congestion.onPacketSent(old_path_packet.size);
    controller.resetForPathMigration();
    try testing.expect(!controller.rtt.hasSample());
    try testing.expectEqual(recovery.CongestionController.initialWindow(recovery.max_datagram_size), controller.congestion.congestion_window);
    // Packets in flight on the old path stay in the single send ledger...
    try testing.expectEqual(@as(usize, 999), controller.congestion.bytes_in_flight);
    // ...and drain through the normal ack path without corrupting accounting.
    controller.congestion.onPacketAcked(old_path_packet);
    try testing.expectEqual(@as(usize, 0), controller.congestion.bytes_in_flight);
}

test "a wrong PATH_RESPONSE payload does not validate the path" {
    var manager = PathManager.init(.full, testKey(50_000));
    const rebound = testKey(50_001);
    _ = manager.onDatagram(rebound, test_challenge, 0);

    const wrong = [_]u8{0xff} ** path_challenge_len;
    try testing.expectEqual(@as(?MigrationOutcome, null), manager.onPathResponse(rebound, wrong, 100));
    // A response on a different tuple does not validate the probed one either.
    try testing.expectEqual(@as(?MigrationOutcome, null), manager.onPathResponse(testKeyOtherHost(1), test_challenge, 100));
    // Still probing; the active path is unchanged. Both bogus responses are
    // counted as mismatches, not as terminal validation failures — the probe
    // can still succeed.
    try testing.expect(manager.activePath().key.eql(testKey(50_000)));
    try testing.expectEqual(@as(u64, 0), manager.metrics.path_validations_succeeded);
    try testing.expectEqual(@as(u64, 0), manager.metrics.path_validations_failed);
    try testing.expectEqual(@as(u64, 2), manager.metrics.path_response_mismatches);
    try testing.expect(manager.onPathResponse(rebound, test_challenge, 200) != null);
}

test "path validation fails deterministically when the challenge expires" {
    var manager = PathManager.init(.full, testKey(50_000));
    manager.validation_timeout_us = 1_000;
    const rebound = testKey(50_001);
    _ = manager.onDatagram(rebound, test_challenge, 0);

    // Not yet expired: nothing fails.
    try testing.expectEqual(@as(usize, 0), manager.expireValidations(1_000));
    // Past the deadline: the probe fails and is counted.
    try testing.expectEqual(@as(usize, 1), manager.expireValidations(1_001));
    try testing.expectEqual(@as(u64, 1), manager.metrics.path_validations_failed);
    // A late response for the failed probe is ignored.
    try testing.expectEqual(@as(?MigrationOutcome, null), manager.onPathResponse(rebound, test_challenge, 1_002));
    // New traffic from the tuple restarts a probe.
    const retry = manager.onDatagram(rebound, test_challenge, 2_000);
    try testing.expectEqualSlices(u8, &test_challenge, &retry.probe);
}

test "migration policy gates rebinding and migration separately" {
    // disabled: even a port-only rebinding is blocked.
    var disabled = PathManager.init(.disabled, testKey(50_000));
    try testing.expectEqual(PathDecision.blocked, disabled.onDatagram(testKey(50_001), test_challenge, 0));
    try testing.expectEqual(@as(u64, 1), disabled.metrics.migrations_blocked);

    // nat_rebinding_only: port change probes, host change is blocked.
    var rebind_only = PathManager.init(.nat_rebinding_only, testKey(50_000));
    const probe = rebind_only.onDatagram(testKey(50_001), test_challenge, 0);
    try testing.expectEqualSlices(u8, &test_challenge, &probe.probe);
    try testing.expectEqual(PathDecision.blocked, rebind_only.onDatagram(testKeyOtherHost(50_000), test_challenge, 0));
    try testing.expectEqual(@as(u64, 1), rebind_only.metrics.migrations_blocked);

    // full: both probe.
    var full = PathManager.init(.full, testKey(50_000));
    const rebinding_probe = full.onDatagram(testKey(50_001), test_challenge, 0);
    try testing.expectEqualSlices(u8, &test_challenge, &rebinding_probe.probe);
    const migration_probe = full.onDatagram(testKeyOtherHost(50_000), test_challenge, 0);
    try testing.expectEqualSlices(u8, &test_challenge, &migration_probe.probe);
}

test "duplicate datagrams on a probing path do not restart the challenge" {
    var manager = PathManager.init(.full, testKey(50_000));
    const rebound = testKey(50_001);
    _ = manager.onDatagram(rebound, test_challenge, 0);
    const again = manager.onDatagram(rebound, [_]u8{0xee} ** path_challenge_len, 10);
    try testing.expectEqual(PathDecision.probing, again);
    try testing.expectEqual(@as(u64, 1), manager.metrics.path_challenges_sent);
    // The original challenge still validates.
    try testing.expect(manager.onPathResponse(rebound, test_challenge, 20) != null);
}

test "probe storms recycle probe slots but never the active path" {
    var manager = PathManager.init(.full, testKey(50_000));
    // More new tuples than slots: the oldest probes are recycled.
    var port: u16 = 50_001;
    while (port < 50_001 + 2 * max_paths) : (port += 1) {
        _ = manager.onDatagram(testKey(port), test_challenge, 0);
    }
    // The active path survived the storm and still routes.
    try testing.expect(manager.activePath().key.eql(testKey(50_000)));
    try testing.expectEqual(PathState.validated, manager.activePath().state);
    try testing.expectEqual(PathDecision.on_active_path, manager.onDatagram(testKey(50_000), test_challenge, 0));
}
