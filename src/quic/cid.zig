//! QUIC connection ID management (#251, RFC 9000 §5.1): CID generation,
//! lookup/routing, retirement, and stateless-reset token derivation.
//!
//! The UDP endpoint (`udp.zig`) demultiplexes incoming datagrams to a
//! connection by destination CID via `CidRoutingTable`, so packets route to the
//! right connection independent of the UDP 4-tuple. `LocalCidRegistry` owns the
//! CIDs this endpoint issued (NEW_CONNECTION_ID emission, RETIRE_CONNECTION_ID
//! consumption); `PeerCidPool` tracks the CIDs the peer issued to us
//! (NEW_CONNECTION_ID consumption, retire_prior_to, and the fresh-CID pick a
//! path migration needs per RFC 9000 §9.5). Frame structs are wire-free state
//! models like `stream.zig`'s; the packet codec owns the byte encoding.
//! Deeper migration/path lifecycle is `path.zig`.

const std = @import("std");
const udp = @import("udp.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const ConnectionId = udp.ConnectionId;

/// Smallest CID this endpoint generates. RFC 9000 allows zero-length CIDs, but
/// routing by DCID requires enough entropy to avoid collisions across
/// connections; 4 bytes is the practical floor for a proxy-scale table.
pub const min_generated_cid_len = 4;
pub const max_generated_cid_len = udp.MaxConnectionIdLen;

/// Copy caller-supplied entropy into a connection ID. Entropy always comes
/// from the caller in `src/quic/` — no ambient RNG — so generation is
/// deterministic in tests and auditable in production.
pub fn generateCid(entropy: []const u8, len: u8) error{ InvalidCidLength, NotEnoughEntropy }!ConnectionId {
    if (len < min_generated_cid_len or len > max_generated_cid_len) return error.InvalidCidLength;
    if (entropy.len < len) return error.NotEnoughEntropy;
    return ConnectionId.init(entropy[0..len]) catch unreachable;
}

// ---------------------------------------------------------------------------
// Frame state models (RFC 9000 §19.15 / §19.16)
// ---------------------------------------------------------------------------

pub const NewConnectionIdFrame = struct {
    sequence: u64,
    retire_prior_to: u64,
    cid: ConnectionId,
    stateless_reset_token: [stateless_reset_token_len]u8,
};

pub const RetireConnectionIdFrame = struct {
    sequence: u64,
};

/// Operator counters for CID lifecycle and routing (#251 acceptance: metrics
/// must distinguish unknown-CID traffic and retirement activity).
pub const Metrics = struct {
    cids_issued: u64 = 0,
    /// Our CIDs the peer retired via RETIRE_CONNECTION_ID.
    local_cids_retired: u64 = 0,
    /// Peer CIDs we retired (retire_prior_to sweeps or rotation).
    peer_cids_retired: u64 = 0,
    routing_hits: u64 = 0,
    routing_misses: u64 = 0,
};

// ---------------------------------------------------------------------------
// Routing table: destination CID -> connection handle
// ---------------------------------------------------------------------------

/// Maps every active locally-issued CID to an opaque connection handle so the
/// UDP endpoint can demultiplex by DCID alone (RFC 9000 §5.2). One connection
/// registers several CIDs; lookups never consult the peer address, which is
/// what lets a connection survive NAT rebinding and migration.
pub const CidRoutingTable = struct {
    allocator: std.mem.Allocator,
    routes: std.AutoHashMap(ConnectionId, u64),
    metrics: Metrics = .{},

    pub fn init(allocator: std.mem.Allocator) CidRoutingTable {
        return .{ .allocator = allocator, .routes = std.AutoHashMap(ConnectionId, u64).init(allocator) };
    }

    pub fn deinit(self: *CidRoutingTable) void {
        self.routes.deinit();
    }

    /// Register a CID for a connection. Re-registering the same CID for the
    /// same connection is idempotent; the same CID appearing for a *different*
    /// connection is a deterministic error — silently stealing a route would
    /// misdeliver protected packets and be brutal to debug (bad entropy,
    /// duplicate issuance, or an integration bug).
    pub fn insert(self: *CidRoutingTable, cid: ConnectionId, connection: u64) error{ CidCollision, OutOfMemory }!void {
        if (self.routes.get(cid)) |existing| {
            if (existing == connection) return;
            return error.CidCollision;
        }
        try self.routes.put(cid, connection);
    }

    /// Route a packet's destination CID to its connection. A miss is counted:
    /// unknown-CID traffic is the stateless-reset / drop path (#250).
    pub fn lookup(self: *CidRoutingTable, dcid: []const u8) ?u64 {
        const key = ConnectionId.init(dcid) catch {
            self.metrics.routing_misses += 1;
            return null;
        };
        if (self.routes.get(key)) |connection| {
            self.metrics.routing_hits += 1;
            return connection;
        }
        self.metrics.routing_misses += 1;
        return null;
    }

    /// Remove a retired CID; retired CIDs must no longer route.
    pub fn remove(self: *CidRoutingTable, cid: ConnectionId) void {
        _ = self.routes.remove(cid);
    }

    pub fn count(self: *const CidRoutingTable) usize {
        return self.routes.count();
    }
};

// ---------------------------------------------------------------------------
// Locally issued CIDs (what the peer uses to reach us)
// ---------------------------------------------------------------------------

/// Most CIDs this endpoint keeps active at once, independent of the peer's
/// advertised limit. Bounded storage, no allocation.
pub const max_local_active_cids = 8;

pub const LocalCidRegistry = struct {
    pub const Entry = struct {
        sequence: u64,
        cid: ConnectionId,
        stateless_reset_token: [stateless_reset_token_len]u8,
    };

    /// min(peer's active_connection_id_limit, local storage bound).
    active_limit: u64,
    /// Static secret for stateless-reset token derivation (RFC 9000 §10.3.1).
    reset_token_key: [32]u8,
    entries: [max_local_active_cids]?Entry = [_]?Entry{null} ** max_local_active_cids,
    next_sequence: u64 = 0,
    metrics: Metrics = .{},

    pub fn init(peer_active_connection_id_limit: u64, reset_token_key: [32]u8) LocalCidRegistry {
        return .{
            .active_limit = @min(peer_active_connection_id_limit, max_local_active_cids),
            .reset_token_key = reset_token_key,
        };
    }

    /// Register the CID chosen during the handshake as sequence 0
    /// (RFC 9000 §5.1.1). Call once, before any `issue`.
    pub fn registerInitial(self: *LocalCidRegistry, cid: ConnectionId) error{ CidLimitExceeded, DuplicateCid }!Entry {
        std.debug.assert(self.next_sequence == 0);
        return self.store(cid);
    }

    /// Issue a fresh CID from caller-supplied entropy and return the
    /// NEW_CONNECTION_ID frame model to send. Fails when the peer's active
    /// CID limit is reached (RFC 9000 §5.1.1: an endpoint MUST NOT provide
    /// more CIDs than the peer's limit).
    pub fn issue(self: *LocalCidRegistry, entropy: []const u8, cid_len: u8) !NewConnectionIdFrame {
        const cid = try generateCid(entropy, cid_len);
        const entry = try self.store(cid);
        self.metrics.cids_issued += 1;
        return .{
            .sequence = entry.sequence,
            .retire_prior_to = 0,
            .cid = entry.cid,
            .stateless_reset_token = entry.stateless_reset_token,
        };
    }

    fn store(self: *LocalCidRegistry, cid: ConnectionId) error{ CidLimitExceeded, DuplicateCid }!Entry {
        if (self.activeCount() >= self.active_limit) return error.CidLimitExceeded;
        // Repeated caller entropy must not mint the same CID twice under
        // different sequence numbers.
        for (self.entries) |existing| {
            if (existing) |entry| {
                if (std.mem.eql(u8, entry.cid.slice(), cid.slice())) return error.DuplicateCid;
            }
        }
        const slot = for (&self.entries) |*entry| {
            if (entry.* == null) break entry;
        } else return error.CidLimitExceeded;
        const entry = Entry{
            .sequence = self.next_sequence,
            .cid = cid,
            .stateless_reset_token = statelessResetToken(self.reset_token_key, cid.slice()),
        };
        slot.* = entry;
        self.next_sequence += 1;
        return entry;
    }

    /// Apply a peer RETIRE_CONNECTION_ID. Returns the retired CID so the
    /// caller removes it from the routing table, or null when the frame is a
    /// permitted retransmit of an already-retired sequence. A sequence this
    /// endpoint never issued is a protocol violation (RFC 9000 §19.16).
    pub fn retire(self: *LocalCidRegistry, frame: RetireConnectionIdFrame) error{ProtocolViolation}!?ConnectionId {
        if (frame.sequence >= self.next_sequence) return error.ProtocolViolation;
        for (&self.entries) |*slot| {
            const entry = &(slot.* orelse continue);
            if (entry.sequence != frame.sequence) continue;
            const cid = entry.cid;
            slot.* = null;
            self.metrics.local_cids_retired += 1;
            return cid;
        }
        // Issued in the past and already retired: a permitted retransmit.
        return null;
    }

    pub fn activeCount(self: *const LocalCidRegistry) usize {
        var active: usize = 0;
        for (self.entries) |entry| {
            if (entry != null) active += 1;
        }
        return active;
    }

    pub fn get(self: *const LocalCidRegistry, sequence: u64) ?Entry {
        for (self.entries) |entry| {
            if (entry) |value| {
                if (value.sequence == sequence) return value;
            }
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Peer-issued CIDs (what we use to reach the peer)
// ---------------------------------------------------------------------------

pub const max_peer_active_cids = 8;
pub const max_pending_retires = 16;

pub const PeerCidPool = struct {
    pub const Entry = struct {
        sequence: u64,
        cid: ConnectionId,
        stateless_reset_token: ?[stateless_reset_token_len]u8,
        /// The retire_prior_to the frame that introduced this sequence
        /// carried, kept to verify that a "retransmit" really is one.
        announced_retire_prior_to: u64 = 0,
        /// A CID already used on some path; migration wants a fresh one
        /// (RFC 9000 §9.5, linkability).
        used: bool = false,
    };

    /// The limit this endpoint advertised in active_connection_id_limit.
    local_active_limit: u64,
    entries: [max_peer_active_cids]?Entry = [_]?Entry{null} ** max_peer_active_cids,
    /// Highest retire_prior_to the peer has requested.
    retire_prior_to: u64 = 0,
    /// RETIRE_CONNECTION_ID sequences queued to send back to the peer.
    pending_retires: [max_pending_retires]u64 = undefined,
    pending_retire_count: usize = 0,
    metrics: Metrics = .{},

    pub fn init(local_active_connection_id_limit: u64) PeerCidPool {
        return .{ .local_active_limit = @min(local_active_connection_id_limit, max_peer_active_cids) };
    }

    /// Register the peer's handshake source CID as sequence 0. It carries no
    /// stateless-reset token (RFC 9000 §10.3: the handshake CID's token comes
    /// separately via the transport parameter).
    pub fn registerInitial(self: *PeerCidPool, cid: ConnectionId) error{ CidLimitExceeded, ProtocolViolation }!void {
        try self.storeValidated(.{
            .sequence = 0,
            .cid = cid,
            .stateless_reset_token = null,
            .used = true, // in use on the handshake path
        });
    }

    /// Apply a peer NEW_CONNECTION_ID frame (RFC 9000 §19.15 / §5.1.1):
    /// rejects malformed retire_prior_to, detects sequence reuse with
    /// different contents, tolerates exact retransmits, retires sequences
    /// below retire_prior_to (queueing RETIRE_CONNECTION_ID responses), and
    /// enforces the advertised active-CID limit.
    pub fn onNewConnectionId(self: *PeerCidPool, frame: NewConnectionIdFrame) error{ ProtocolViolation, CidLimitExceeded, RetireQueueFull }!void {
        if (frame.retire_prior_to > frame.sequence) return error.ProtocolViolation;

        // A repeated sequence number must be an exact retransmit: same CID,
        // same stateless reset token, and same retire_prior_to (RFC 9000
        // §19.15 — reuse with different contents is a protocol violation).
        for (self.entries) |existing| {
            const entry = existing orelse continue;
            const same_sequence = entry.sequence == frame.sequence;
            const same_cid = std.mem.eql(u8, entry.cid.slice(), frame.cid.slice());
            if (!same_sequence and same_cid) return error.ProtocolViolation;
            if (!same_sequence) continue;
            if (!same_cid) return error.ProtocolViolation;
            const same_token = if (entry.stateless_reset_token) |token|
                std.mem.eql(u8, &token, &frame.stateless_reset_token)
            else
                false;
            if (!same_token) return error.ProtocolViolation;
            if (entry.announced_retire_prior_to != frame.retire_prior_to) return error.ProtocolViolation;
            return; // exact retransmit
        }

        if (frame.retire_prior_to > self.retire_prior_to) {
            self.retire_prior_to = frame.retire_prior_to;
            try self.retireBelowThreshold();
        }

        // A sequence the peer already told us to retire: acknowledge with a
        // RETIRE_CONNECTION_ID and never store it (RFC 9000 §5.1.2).
        if (frame.sequence < self.retire_prior_to) {
            try self.queueRetire(frame.sequence);
            return;
        }

        try self.storeValidated(.{
            .sequence = frame.sequence,
            .cid = frame.cid,
            .stateless_reset_token = frame.stateless_reset_token,
            .announced_retire_prior_to = frame.retire_prior_to,
        });
    }

    fn storeValidated(self: *PeerCidPool, entry: Entry) error{ CidLimitExceeded, ProtocolViolation }!void {
        if (self.activeCount() >= self.local_active_limit) return error.CidLimitExceeded;
        const slot = for (&self.entries) |*candidate| {
            if (candidate.* == null) break candidate;
        } else return error.CidLimitExceeded;
        slot.* = entry;
    }

    fn retireBelowThreshold(self: *PeerCidPool) error{RetireQueueFull}!void {
        for (&self.entries) |*slot| {
            const entry = slot.* orelse continue;
            if (entry.sequence >= self.retire_prior_to) continue;
            try self.queueRetire(entry.sequence);
            slot.* = null;
            self.metrics.peer_cids_retired += 1;
        }
    }

    fn queueRetire(self: *PeerCidPool, sequence: u64) error{RetireQueueFull}!void {
        if (self.pending_retire_count == self.pending_retires.len) return error.RetireQueueFull;
        self.pending_retires[self.pending_retire_count] = sequence;
        self.pending_retire_count += 1;
    }

    /// Next RETIRE_CONNECTION_ID to send, or null when none is pending.
    pub fn takePendingRetire(self: *PeerCidPool) ?RetireConnectionIdFrame {
        if (self.pending_retire_count == 0) return null;
        const sequence = self.pending_retires[0];
        std.mem.copyForwards(u64, self.pending_retires[0 .. self.pending_retire_count - 1], self.pending_retires[1..self.pending_retire_count]);
        self.pending_retire_count -= 1;
        return .{ .sequence = sequence };
    }

    /// Claim a never-used peer CID for a new path (RFC 9000 §9.5: reusing a
    /// CID across paths links them). Returns null when the pool has no fresh
    /// CID — the caller must not migrate until the peer issues more.
    pub fn claimForMigration(self: *PeerCidPool) ?Entry {
        for (&self.entries) |*slot| {
            const entry = &(slot.* orelse continue);
            if (entry.used or entry.sequence < self.retire_prior_to) continue;
            entry.used = true;
            return entry.*;
        }
        return null;
    }

    pub fn activeCount(self: *const PeerCidPool) usize {
        var active: usize = 0;
        for (self.entries) |entry| {
            if (entry != null) active += 1;
        }
        return active;
    }
};

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

test "generateCid copies caller entropy and enforces length bounds" {
    const entropy = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    const cid = try generateCid(&entropy, 8);
    try testing.expectEqualSlices(u8, entropy[0..8], cid.slice());

    try testing.expectError(error.InvalidCidLength, generateCid(&entropy, 3));
    try testing.expectError(error.InvalidCidLength, generateCid(&entropy, max_generated_cid_len + 1));
    try testing.expectError(error.NotEnoughEntropy, generateCid(entropy[0..4], 8));
}

test "routing table routes by DCID independent of any address and counts misses" {
    var table = CidRoutingTable.init(testing.allocator);
    defer table.deinit();

    const cid_a = try ConnectionId.init(&.{ 1, 1, 1, 1, 1, 1, 1, 1 });
    const cid_b = try ConnectionId.init(&.{ 2, 2, 2, 2 });
    try table.insert(cid_a, 7);
    try table.insert(cid_b, 7); // several CIDs route to one connection
    const cid_other = try ConnectionId.init(&.{ 3, 3, 3, 3 });
    try table.insert(cid_other, 9);

    try testing.expectEqual(@as(?u64, 7), table.lookup(cid_a.slice()));
    try testing.expectEqual(@as(?u64, 7), table.lookup(cid_b.slice()));
    try testing.expectEqual(@as(?u64, 9), table.lookup(cid_other.slice()));
    try testing.expectEqual(@as(?u64, null), table.lookup(&.{ 9, 9, 9, 9 }));
    try testing.expectEqual(@as(?u64, null), table.lookup(""));
    try testing.expectEqual(@as(u64, 3), table.metrics.routing_hits);
    try testing.expectEqual(@as(u64, 2), table.metrics.routing_misses);
}

test "retired local CIDs stop routing and unknown retire sequences are violations" {
    var table = CidRoutingTable.init(testing.allocator);
    defer table.deinit();
    var registry = LocalCidRegistry.init(4, [_]u8{0xab} ** 32);

    const initial = try ConnectionId.init(&.{ 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa });
    const initial_entry = try registry.registerInitial(initial);
    try table.insert(initial_entry.cid, 1);

    var entropy = [_]u8{0x10} ** 8;
    const issued = try registry.issue(&entropy, 8);
    try table.insert(issued.cid, 1);
    try testing.expectEqual(@as(u64, 1), issued.sequence);
    try testing.expectEqual(@as(?u64, 1), table.lookup(issued.cid.slice()));

    // Retire the issued CID: it must come out of the routing table.
    const retired = (try registry.retire(.{ .sequence = issued.sequence })).?;
    table.remove(retired);
    try testing.expectEqual(@as(?u64, null), table.lookup(issued.cid.slice()));
    try testing.expectEqual(@as(u64, 1), registry.metrics.local_cids_retired);

    // A retransmitted RETIRE_CONNECTION_ID for the same sequence is a no-op.
    try testing.expectEqual(@as(?ConnectionId, null), try registry.retire(.{ .sequence = issued.sequence }));
    // A sequence never issued is a protocol violation (RFC 9000 §19.16).
    try testing.expectError(error.ProtocolViolation, registry.retire(.{ .sequence = 99 }));
}

test "local registry enforces the peer's active CID limit and derives reset tokens" {
    const key = [_]u8{0x77} ** 32;
    var registry = LocalCidRegistry.init(2, key);
    _ = try registry.registerInitial(try ConnectionId.init(&.{ 1, 2, 3, 4 }));

    var entropy = [_]u8{0x20} ** 8;
    const issued = try registry.issue(&entropy, 8);
    // The frame's token matches the RFC 9000 §10.3.1 derivation for the CID.
    try testing.expectEqualSlices(u8, &statelessResetToken(key, issued.cid.slice()), &issued.stateless_reset_token);

    // Limit of 2 is reached: further issuance must fail until one retires.
    var more_entropy = [_]u8{0x30} ** 8;
    try testing.expectError(error.CidLimitExceeded, registry.issue(&more_entropy, 8));
    _ = try registry.retire(.{ .sequence = issued.sequence });
    _ = try registry.issue(&more_entropy, 8);
    try testing.expectEqual(@as(usize, 2), registry.activeCount());
}

test "peer pool validates NEW_CONNECTION_ID and sweeps retire_prior_to" {
    var pool = PeerCidPool.init(4);
    try pool.registerInitial(try ConnectionId.init(&.{ 9, 9, 9, 9 }));

    const cid_1 = try ConnectionId.init(&.{ 1, 1, 1, 1 });
    const token_1 = [_]u8{0x01} ** stateless_reset_token_len;
    try pool.onNewConnectionId(.{ .sequence = 1, .retire_prior_to = 0, .cid = cid_1, .stateless_reset_token = token_1 });
    // Exact retransmit: tolerated.
    try pool.onNewConnectionId(.{ .sequence = 1, .retire_prior_to = 0, .cid = cid_1, .stateless_reset_token = token_1 });
    // Same sequence, different CID: protocol violation.
    const cid_conflict = try ConnectionId.init(&.{ 2, 2, 2, 2 });
    try testing.expectError(error.ProtocolViolation, pool.onNewConnectionId(.{ .sequence = 1, .retire_prior_to = 0, .cid = cid_conflict, .stateless_reset_token = token_1 }));
    // Same CID, different sequence: also a violation (RFC 9000 §5.1.1).
    try testing.expectError(error.ProtocolViolation, pool.onNewConnectionId(.{ .sequence = 2, .retire_prior_to = 0, .cid = cid_1, .stateless_reset_token = token_1 }));
    // retire_prior_to beyond the sequence itself is malformed.
    try testing.expectError(error.ProtocolViolation, pool.onNewConnectionId(.{ .sequence = 3, .retire_prior_to = 4, .cid = cid_conflict, .stateless_reset_token = token_1 }));

    // A frame with retire_prior_to = 2 sweeps sequences 0 and 1 and queues
    // RETIRE_CONNECTION_ID for each.
    const cid_2 = try ConnectionId.init(&.{ 3, 3, 3, 3 });
    try pool.onNewConnectionId(.{ .sequence = 2, .retire_prior_to = 2, .cid = cid_2, .stateless_reset_token = token_1 });
    try testing.expectEqual(@as(u64, 2), pool.metrics.peer_cids_retired);
    const first_retire = pool.takePendingRetire().?;
    const second_retire = pool.takePendingRetire().?;
    try testing.expect((first_retire.sequence == 0 and second_retire.sequence == 1) or
        (first_retire.sequence == 1 and second_retire.sequence == 0));
    try testing.expectEqual(@as(?RetireConnectionIdFrame, null), pool.takePendingRetire());

    // A late frame below retire_prior_to is retired immediately, never stored.
    const cid_late = try ConnectionId.init(&.{ 4, 4, 4, 4 });
    try pool.onNewConnectionId(.{ .sequence = 0, .retire_prior_to = 0, .cid = cid_late, .stateless_reset_token = token_1 });
    try testing.expectEqual(@as(u64, 0), pool.takePendingRetire().?.sequence);
    try testing.expectEqual(@as(usize, 1), pool.activeCount());
}

test "peer pool enforces the advertised active CID limit" {
    var pool = PeerCidPool.init(2);
    try pool.registerInitial(try ConnectionId.init(&.{ 9, 9, 9, 9 }));
    const token = [_]u8{0x0f} ** stateless_reset_token_len;
    try pool.onNewConnectionId(.{ .sequence = 1, .retire_prior_to = 0, .cid = try ConnectionId.init(&.{ 1, 0, 0, 1 }), .stateless_reset_token = token });
    try testing.expectError(error.CidLimitExceeded, pool.onNewConnectionId(.{ .sequence = 2, .retire_prior_to = 0, .cid = try ConnectionId.init(&.{ 2, 0, 0, 2 }), .stateless_reset_token = token }));
}

test "routing table rejects CID collisions across connections" {
    var table = CidRoutingTable.init(testing.allocator);
    defer table.deinit();
    const cid = try ConnectionId.init(&.{ 6, 6, 6, 6 });
    try table.insert(cid, 1);
    // Re-registering for the same connection is idempotent.
    try table.insert(cid, 1);
    try testing.expectEqual(@as(usize, 1), table.count());
    // The same CID must never silently route to a different connection.
    try testing.expectError(error.CidCollision, table.insert(cid, 2));
    try testing.expectEqual(@as(?u64, 1), table.lookup(cid.slice()));
}

test "local registry rejects duplicate CIDs from repeated entropy" {
    var registry = LocalCidRegistry.init(4, [_]u8{0x42} ** 32);
    _ = try registry.registerInitial(try ConnectionId.init(&.{ 1, 2, 3, 4, 5, 6, 7, 8 }));
    var entropy = [_]u8{0x99} ** 8;
    _ = try registry.issue(&entropy, 8);
    // Same entropy again would mint the same CID under a new sequence.
    try testing.expectError(error.DuplicateCid, registry.issue(&entropy, 8));
    // And so would re-registering the handshake CID.
    try testing.expectError(error.DuplicateCid, registry.issue(&[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, 8));
}

test "NEW_CONNECTION_ID sequence reuse must be an exact retransmit" {
    var pool = PeerCidPool.init(4);
    const cid = try ConnectionId.init(&.{ 8, 8, 8, 8 });
    const token = [_]u8{0x08} ** stateless_reset_token_len;
    try pool.onNewConnectionId(.{ .sequence = 1, .retire_prior_to = 1, .cid = cid, .stateless_reset_token = token });

    // Same sequence and CID with a different stateless reset token: violation.
    const other_token = [_]u8{0x09} ** stateless_reset_token_len;
    try testing.expectError(error.ProtocolViolation, pool.onNewConnectionId(.{ .sequence = 1, .retire_prior_to = 1, .cid = cid, .stateless_reset_token = other_token }));
    // Same sequence, CID, and token but a different retire_prior_to: also not
    // a retransmit of the same frame.
    try testing.expectError(error.ProtocolViolation, pool.onNewConnectionId(.{ .sequence = 1, .retire_prior_to = 0, .cid = cid, .stateless_reset_token = token }));
    // The true retransmit still passes.
    try pool.onNewConnectionId(.{ .sequence = 1, .retire_prior_to = 1, .cid = cid, .stateless_reset_token = token });
}

test "a stale retire_prior_to below the current threshold is a clean no-op" {
    var pool = PeerCidPool.init(8);
    const token = [_]u8{0x0a} ** stateless_reset_token_len;
    try pool.onNewConnectionId(.{ .sequence = 3, .retire_prior_to = 3, .cid = try ConnectionId.init(&.{ 3, 0, 0, 3 }), .stateless_reset_token = token });
    try testing.expectEqual(@as(u64, 3), pool.retire_prior_to);
    const retired_before = pool.metrics.peer_cids_retired;

    // A late frame carrying a lower retire_prior_to sweeps nothing and queues
    // nothing extra: the threshold never regresses.
    try pool.onNewConnectionId(.{ .sequence = 4, .retire_prior_to = 1, .cid = try ConnectionId.init(&.{ 4, 0, 0, 4 }), .stateless_reset_token = token });
    try testing.expectEqual(@as(u64, 3), pool.retire_prior_to);
    try testing.expectEqual(retired_before, pool.metrics.peer_cids_retired);
    try testing.expectEqual(@as(usize, 2), pool.activeCount());
}

test "migration claims only fresh peer CIDs" {
    var pool = PeerCidPool.init(4);
    try pool.registerInitial(try ConnectionId.init(&.{ 9, 9, 9, 9 }));
    // The handshake CID is in use; with nothing else the pool has no fresh CID.
    try testing.expectEqual(@as(?PeerCidPool.Entry, null), pool.claimForMigration());

    const token = [_]u8{0x0c} ** stateless_reset_token_len;
    const fresh = try ConnectionId.init(&.{ 5, 5, 5, 5 });
    try pool.onNewConnectionId(.{ .sequence = 1, .retire_prior_to = 0, .cid = fresh, .stateless_reset_token = token });
    const claimed = pool.claimForMigration().?;
    try testing.expectEqualSlices(u8, fresh.slice(), claimed.cid.slice());
    // Claimed once: a second migration needs yet another CID.
    try testing.expectEqual(@as(?PeerCidPool.Entry, null), pool.claimForMigration());
}

test "CID issue/retire churn does not leak routing table entries" {
    var table = CidRoutingTable.init(testing.allocator);
    defer table.deinit();
    var registry = LocalCidRegistry.init(4, [_]u8{0x55} ** 32);
    _ = try registry.registerInitial(try ConnectionId.init(&.{ 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa }));

    // Long-running rotation: issue a fresh CID and retire the previous one,
    // thousands of times. Table and registry stay bounded throughout.
    var previous_sequence: u64 = 0;
    var iteration: u64 = 0;
    while (iteration < 10_000) : (iteration += 1) {
        var entropy: [8]u8 = undefined;
        std.mem.writeInt(u64, &entropy, iteration + 1, .big);
        const issued = try registry.issue(&entropy, 8);
        try table.insert(issued.cid, 1);
        if (try registry.retire(.{ .sequence = previous_sequence })) |retired| {
            table.remove(retired);
        }
        previous_sequence = issued.sequence;
        try testing.expect(registry.activeCount() <= 2);
        try testing.expect(table.count() <= 2);
    }
    try testing.expectEqual(@as(u64, 10_000), registry.metrics.cids_issued);
    try testing.expectEqual(@as(u64, 10_000), registry.metrics.local_cids_retired);
}

test {
    testing.refAllDecls(@This());
}
