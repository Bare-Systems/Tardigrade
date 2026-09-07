//! Pure Zig QUIC/H3 configuration model (#248).
//!
//! These structs define the internal transport defaults before the pure Zig
//! implementation exists. Operator-facing env/config wiring should expose only
//! fields that are needed for safe rollout; the remaining values are internal
//! defaults until benchmarks or interop require public knobs.

const std = @import("std");
const secrets = @import("crypto_secrets");
const quic_datagram = @import("datagram.zig");

pub const QuicVersion = enum(u32) {
    v1 = 0x00000001,
    v2 = 0x6b3343cf,
};

pub const VersionSet = struct {
    v1: bool = true,
    v2: bool = false,

    pub fn supports(self: VersionSet, version: QuicVersion) bool {
        return switch (version) {
            .v1 => self.v1,
            .v2 => self.v2,
        };
    }

    pub fn preferred(self: VersionSet) ?QuicVersion {
        if (self.v1) return .v1;
        if (self.v2) return .v2;
        return null;
    }
};

pub const RetryPolicy = enum {
    off,
    address_validation,
};

pub const MigrationPolicy = enum {
    disabled,
    nat_rebinding_only,
    full,
};

pub const QpackMode = enum {
    static_only,
    dynamic,
};

/// qlog/keylog toggles for the pure-Zig QUIC/H3 stack (#255). Both default off
/// and are sensitive/debug-only: qlog reveals connection internals and keylog
/// reveals the TLS traffic secrets that decrypt the connection. See
/// `docs/QUIC_QLOG.md` for the event model and safe-handling rules. The event
/// seam lives in `src/quic/qlog.zig` (+ `keylog.zig`) and `src/http3/qlog.zig`;
/// destinations are supplied by the composition root, not this config.
pub const Observability = struct {
    qlog_enabled: bool = false,
    keylog_enabled: bool = false,
};

pub const QpackConfig = struct {
    mode: QpackMode = .static_only,
    dynamic_table_capacity: u64 = 0,
    blocked_streams: u64 = 0,
};

/// RFC 9000 §4.6: stream-count transport parameters above 2^60 are invalid.
pub const max_initial_streams_transport_parameter: u64 = 1 << 60;

/// Per-connection, per-direction cap on how many closed peer-initiated
/// streams `StreamManager`'s MAX_STREAMS replenishment (#247 soak finding)
/// will grant credit for (see `StreamManager.closed_peer_bidi`/`_uni` in
/// stream.zig). Every closed `Stream` object is retained for the life of the
/// connection, so replenishing credit without any bound would turn the
/// previous functional 100-stream lifetime cap into unbounded per-connection
/// memory growth -- exactly what #247 Lane B's bounded-resource contract
/// forbids. True retirement (freeing a closed stream's memory while keeping
/// a small tombstone so late/retransmitted frames for it are recognized
/// rather than misidentified as a new stream) is the complete fix, but it
/// requires auditing every caller that reads stream state immediately after
/// the operation that closed it -- a pervasive existing pattern this
/// codebase relies on -- and an unaudited attempt at removal produced
/// use-after-free crashes during development. This fixed ceiling keeps
/// retained per-connection stream state small and provable without that
/// audit; raising it is safe at any time, since it only ever changes how
/// much credit is granted, never how existing streams behave.
pub const max_retained_closed_streams_per_direction: u64 = 4096;

/// Per-stream cap on out-of-order receive-buffer segments. Each segment is
/// a non-contiguous byte range that arrived before the bytes preceding it,
/// so the count tracks how fragmented the peer's delivery is. Without a
/// cap, an attacker sending maximally interleaved 1-byte STREAM frames
/// can create up to `initial_max_stream_data / 1` segments per stream;
/// every subsequent insert then scans all accumulated segments (O(n) per
/// insert, O(n²) total) — a quadratic-CPU DoS reachable from linear wire
/// bytes.
///
/// 256 segments bounds disjoint reassembly work tightly. Contiguous data
/// is coalesced into existing ranges to prevent legitimate sequential
/// fragmentation from hitting this cap. A stream that hits this cap triggers
/// `error.TooManySegments`, which falls through to `INTERNAL_ERROR` and
/// immediately closes the QUIC connection.
pub const max_recv_segments: usize = 256;

pub const Config = struct {
    enabled: bool = false,
    versions: VersionSet = .{},
    idle_timeout_ms: u64 = 30_000,
    active_connection_id_limit: u64 = 4,
    /// RFC 9000 §18.2: the largest UDP payload this endpoint is willing to
    /// **receive**, advertised to the peer. It is endpoint receive capacity,
    /// not path state, so it must not exceed the receive buffers the
    /// implementation actually allocates — `validate()` enforces that against
    /// `quic.datagram.max_size`, which is the same symbol those buffers are
    /// sized from. Send-side limits live in `max_send_udp_payload_size` and
    /// `quic.datagram.Limits`.
    max_udp_payload_size: u64 = quic_datagram.max_size,
    /// The largest UDP payload this endpoint will ever put on the wire — a
    /// ceiling, not a size. DPLPMTUD (#256-B) searches inside
    /// `[base_size, this]` and raises the size actually emitted only when a
    /// probe of the larger size is acknowledged, so a fresh path still starts
    /// at the RFC 9000 §14 floor no matter how high this is set.
    ///
    /// It defaults to the floor, which means **discovery is off unless an
    /// embedder opts in**. That is deliberate: a probe only measures a path
    /// MTU if the socket it goes out on cannot source-fragment it (RFC 8899
    /// §3), and this layer owns no socket and cannot know. Only the
    /// composition root that created the socket can establish that contract,
    /// so only it may raise this — see `http3_runtime.configureNoFragment`.
    /// An embedder that raises it without one is asking discovery to trust an
    /// acknowledgement that may only prove reassembly. Always additionally
    /// bounded by the peer's advertised receive capacity.
    max_send_udp_payload_size: u64 = quic_datagram.base_size,
    initial_max_data: u64 = 8 * 1024 * 1024,
    initial_max_stream_data_bidi_local: u64 = 1024 * 1024,
    initial_max_stream_data_bidi_remote: u64 = 1024 * 1024,
    initial_max_stream_data_uni: u64 = 256 * 1024,
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 16,
    retry_policy: RetryPolicy = .off,
    migration_policy: MigrationPolicy = .disabled,
    /// Whether outbound packets may be marked ECT(0) and the peer's ACK_ECN
    /// counters acted on (#256-E, RFC 9000 §13.4).
    ///
    /// Off by default for the same reason `max_send_udp_payload_size` starts
    /// at the floor: this layer owns no socket. Marking a packet means asking
    /// the kernel to set an IP header field on a specific datagram, and
    /// reading the peer's marks back means ancillary receive metadata — both
    /// are platform capabilities only the composition root that created the
    /// socket can establish. Enabling it without them would mark nothing,
    /// observe nothing, and then conclude from the resulting silence that the
    /// *path* strips ECN.
    ///
    /// Enabling it is never a correctness risk in the other direction: every
    /// validation failure ends in ordinary non-ECN operation rather than a
    /// connection error.
    ecn_enabled: bool = false,
    /// 0-RTT is off unless an operator explicitly opts in, given its replay
    /// exposure (RFC 9001 §9.2). The TLS adapter refuses 0-RTT keys while false.
    zero_rtt_enabled: bool = false,
    observability: Observability = .{},
    qpack: QpackConfig = .{},

    pub fn validate(self: Config) !void {
        if (self.versions.preferred() == null) return error.UnsupportedQuicVersion;
        if (self.idle_timeout_ms == 0) return error.InvalidIdleTimeout;
        if (self.active_connection_id_limit < 2) return error.InvalidActiveConnectionIdLimit;
        // Never advertise receive capacity the implementation cannot process:
        // the ceiling here is the same symbol the receive scratch buffers are
        // sized from, so the two cannot drift.
        if (self.max_udp_payload_size < quic_datagram.base_size or self.max_udp_payload_size > quic_datagram.max_size) return error.InvalidMaxUdpPayloadSize;
        if (self.max_send_udp_payload_size < quic_datagram.base_size or self.max_send_udp_payload_size > quic_datagram.max_size) return error.InvalidMaxSendUdpPayloadSize;
        if (self.initial_max_data == 0) return error.InvalidFlowControlWindow;
        if (self.initial_max_stream_data_bidi_local > self.initial_max_data) return error.InvalidFlowControlWindow;
        if (self.initial_max_stream_data_bidi_remote > self.initial_max_data) return error.InvalidFlowControlWindow;
        if (self.initial_max_stream_data_uni > self.initial_max_data) return error.InvalidFlowControlWindow;
        if (self.initial_max_streams_bidi == 0) return error.InvalidStreamLimit;
        if (self.initial_max_streams_bidi > max_initial_streams_transport_parameter) return error.InvalidStreamLimit;
        if (self.initial_max_streams_uni > max_initial_streams_transport_parameter) return error.InvalidStreamLimit;
        if (self.qpack.mode == .static_only and (self.qpack.dynamic_table_capacity != 0 or self.qpack.blocked_streams != 0)) {
            return error.InvalidQpackConfig;
        }
    }

    pub fn transportParameters(self: Config) !TransportParameters {
        try self.validate();
        return .{
            .max_idle_timeout_ms = self.idle_timeout_ms,
            .active_connection_id_limit = self.active_connection_id_limit,
            .max_udp_payload_size = self.max_udp_payload_size,
            .initial_max_data = self.initial_max_data,
            .initial_max_stream_data_bidi_local = self.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = self.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = self.initial_max_stream_data_uni,
            .initial_max_streams_bidi = self.initial_max_streams_bidi,
            .initial_max_streams_uni = self.initial_max_streams_uni,
            // Only `.full` advertises active migration support; `.disabled`
            // and `.nat_rebinding_only` both disable it, since NAT rebinding
            // is validated port-only traffic, not client-initiated migration.
            .disable_active_migration = self.migration_policy != .full,
        };
    }
};

pub const TransportParameters = struct {
    max_idle_timeout_ms: u64,
    active_connection_id_limit: u64,
    max_udp_payload_size: u64,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    disable_active_migration: bool,
    /// RFC 9000 §18.2 ACK interpretation parameters; both default to the RFC
    /// values when a peer omits them.
    ack_delay_exponent: u8 = 3,
    max_ack_delay_ms: u64 = 25,
};

/// Largest connection ID QUIC v1 allows (RFC 9000 §17.2).
pub const max_cid_len = 20;

/// A connection ID value carried in a transport parameter. Fixed storage so
/// the TLS layer never borrows connection-layer memory.
pub const CidValue = struct {
    bytes: [max_cid_len]u8 = [_]u8{0} ** max_cid_len,
    len: u8 = 0,

    pub fn init(raw: []const u8) error{InvalidConnectionId}!CidValue {
        if (raw.len > max_cid_len) return error.InvalidConnectionId;
        var value = CidValue{ .len = @intCast(raw.len) };
        @memcpy(value.bytes[0..raw.len], raw);
        return value;
    }

    pub fn slice(self: *const CidValue) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// The authentication-binding transport parameters of RFC 9000 §7.3: the
/// connection IDs (and server stateless reset token) each side commits to in
/// the TLS handshake so an attacker cannot splice packet flows. The connection
/// layer supplies the local values before the handshake starts and validates
/// the peer's values when it completes.
pub const CidBinding = struct {
    /// Sent by both peers; must match the Source Connection ID field of the
    /// sender's packets.
    initial_source_connection_id: ?CidValue = null,
    /// Server only; must match the DCID of the client's first Initial.
    original_destination_connection_id: ?CidValue = null,
    /// Server only, after Retry; must match the Retry packet's SCID.
    retry_source_connection_id: ?CidValue = null,
    /// Server only.
    stateless_reset_token: ?[16]u8 = null,

    /// Wipes the only secret-bearing field before this binding (a local, a
    /// retained backend copy, or a peer-supplied copy) is discarded.
    pub fn deinit(self: *CidBinding) void {
        if (self.stateless_reset_token) |*token| secrets.secureZero(token);
        self.stateless_reset_token = null;
    }
};

test "default QUIC config maps to conservative transport parameters" {
    const cfg = Config{};
    const params = try cfg.transportParameters();
    try std.testing.expect(!cfg.enabled);
    try std.testing.expect(cfg.versions.supports(.v1));
    try std.testing.expect(!cfg.versions.supports(.v2));
    try std.testing.expectEqual(@as(u64, 30_000), params.max_idle_timeout_ms);
    try std.testing.expectEqual(@as(u64, 4), params.active_connection_id_limit);
    // The advertised parameter is receive capacity, so it matches the receive
    // buffers the implementation allocates; the send side stays conservative.
    try std.testing.expectEqual(@as(u64, quic_datagram.max_size), params.max_udp_payload_size);
    // The send ceiling defaults to the floor: discovery is off until a socket
    // owner that can guarantee no IP fragmentation opts in (#256-B).
    try std.testing.expectEqual(@as(u64, quic_datagram.base_size), cfg.max_send_udp_payload_size);
    try std.testing.expect(params.disable_active_migration);
    try std.testing.expect(!cfg.zero_rtt_enabled);
    try std.testing.expectEqual(QpackMode.static_only, cfg.qpack.mode);
}

test "QUIC config validation rejects unsafe combinations" {
    try std.testing.expectError(error.UnsupportedQuicVersion, (Config{ .versions = .{ .v1 = false, .v2 = false } }).validate());
    try std.testing.expectError(error.InvalidActiveConnectionIdLimit, (Config{ .active_connection_id_limit = 1 }).validate());
    try std.testing.expectError(error.InvalidMaxUdpPayloadSize, (Config{ .max_udp_payload_size = 1199 }).validate());
    // Advertising more than the implementation can actually receive is
    // rejected rather than promised to the peer.
    try std.testing.expectError(error.InvalidMaxUdpPayloadSize, (Config{ .max_udp_payload_size = quic_datagram.max_size + 1 }).validate());
    try std.testing.expectError(error.InvalidMaxSendUdpPayloadSize, (Config{ .max_send_udp_payload_size = 1199 }).validate());
    try std.testing.expectError(error.InvalidMaxSendUdpPayloadSize, (Config{ .max_send_udp_payload_size = quic_datagram.max_size + 1 }).validate());
    try std.testing.expectError(error.InvalidStreamLimit, (Config{ .initial_max_streams_bidi = max_initial_streams_transport_parameter + 1 }).validate());
    try std.testing.expectError(error.InvalidStreamLimit, (Config{ .initial_max_streams_uni = max_initial_streams_transport_parameter + 1 }).validate());
    try std.testing.expectError(error.InvalidFlowControlWindow, (Config{
        .initial_max_data = 1024,
        .initial_max_stream_data_bidi_local = 2048,
    }).validate());
    try std.testing.expectError(error.InvalidQpackConfig, (Config{
        .qpack = .{ .mode = .static_only, .dynamic_table_capacity = 4096 },
    }).validate());
}

test "migration policy maps to transport parameter" {
    const disabled = try (Config{ .migration_policy = .disabled }).transportParameters();
    const rebinding = try (Config{ .migration_policy = .nat_rebinding_only }).transportParameters();
    const full = try (Config{ .migration_policy = .full }).transportParameters();
    // Only `.full` permits client-initiated migration; NAT rebinding is
    // validated port-only traffic handled independently of this parameter.
    try std.testing.expect(disabled.disable_active_migration);
    try std.testing.expect(rebinding.disable_active_migration);
    try std.testing.expect(!full.disable_active_migration);
}
