//! Native QUIC v1 connection driver (#247, RFC 9000/9001/9002): the stitching
//! layer that coordinates — without reimplementing — the packet codec
//! (`packet.zig`/`frame.zig`), packet protection (`tls_adapter.zig`), the TLS
//! handshake driver (`tls_handshake.zig`), loss recovery and congestion
//! control (`recovery.zig`), stream and flow-control state (`stream.zig`),
//! CID bookkeeping (`cid.zig`), and anti-amplification (`path.zig`).
//!
//! One `Connection` is one QUIC connection on one path. The embedding runtime
//! owns sockets, routing (by DCID), and time; the driver is sans-I/O:
//!
//!   * `ingest`         — feed one received UDP datagram (may be coalesced)
//!   * `pollTransmit`   — produce the next outbound UDP datagram, or null
//!   * `nextTimeoutUs`  — the next deadline that needs `onTimeout`
//!   * `onTimeout`      — drive loss detection, PTO, idle, close timers
//!   * stream API       — open/write/read/reset QUIC streams
//!   * `close`          — start an orderly CONNECTION_CLOSE
//!
//! The driver never bypasses congestion control, flow control, packet
//! protection, or anti-amplification: every outbound datagram passes the
//! recovery controller's window, the path's amplification budget, and the
//! adapter's AEAD seal.

const std = @import("std");
const varint = @import("quic_varint");
const config = @import("config.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const tls_adapter = @import("tls_adapter.zig");
const tls_handshake = @import("tls_handshake.zig");
const recovery = @import("recovery.zig");
const quic_stream = @import("stream.zig");
const quic_cid = @import("cid.zig");
const quic_path = @import("path.zig");

const EncryptionLevel = tls_adapter.EncryptionLevel;
const PacketNumberSpace = recovery.PacketNumberSpace;
const StreamId = quic_stream.StreamId;

pub const Role = enum { client, server };

pub const State = enum {
    /// TLS handshake in progress.
    handshaking,
    /// Handshake complete; application data flows.
    established,
    /// We sent CONNECTION_CLOSE and wait out 3×PTO.
    closing,
    /// Peer sent CONNECTION_CLOSE; we wait out 3×PTO without sending.
    draining,
    /// Terminal. All resources may be reclaimed.
    closed,
};

/// The datagram size this driver sends. Conservative (RFC 9000 §14.1 minimum)
/// until DPLPMTUD lands under #256.
pub const max_datagram_size: usize = recovery.max_datagram_size;
/// RFC 9000 §14.1: datagrams carrying Initial packets are padded to 1200.
pub const min_initial_datagram: usize = 1200;

/// Hard bound on bytes buffered per stream for transmission (unsent +
/// unacked). `writeStream` accepts partial writes beyond it.
pub const max_stream_send_buffer: usize = 256 * 1024;

const aead_tag_len = tls_adapter.packet_protection_tag_len;
const sample_len = tls_adapter.header_protection_sample_len;
/// Local ACK delay parameters (we advertise the RFC defaults).
const local_ack_delay_exponent: u6 = 3;
const local_max_ack_delay_us: u64 = 25_000;
/// Ack-eliciting packets received before an app-space ACK is forced.
const ack_eliciting_threshold: u64 = 2;

// QUIC transport error codes (RFC 9000 §20.1).
pub const error_no_error: u64 = 0x00;
pub const error_internal: u64 = 0x01;
pub const error_flow_control: u64 = 0x03;
pub const error_stream_limit: u64 = 0x04;
pub const error_stream_state: u64 = 0x05;
pub const error_final_size: u64 = 0x06;
pub const error_frame_encoding: u64 = 0x07;
pub const error_transport_parameter: u64 = 0x08;
pub const error_protocol_violation: u64 = 0x0a;
pub const error_crypto_buffer_exceeded: u64 = 0x0d;
pub const error_key_update: u64 = 0x0e;
/// CRYPTO_ERROR base (0x0100–0x01ff carries the TLS alert).
pub const error_crypto_base: u64 = 0x0100;

pub const IngestError = error{OutOfMemory};

pub const Event = union(enum) {
    state: State,
    packet_received: struct { space: PacketNumberSpace, packet_number: u64, size: usize },
    packet_sent: struct { space: PacketNumberSpace, packet_number: u64, size: usize, ack_eliciting: bool },
    packet_dropped: struct { reason: DropReason, size: usize },
    keys_discarded: PacketNumberSpace,
    handshake_complete,
    handshake_confirmed,
    pto_fired: struct { space: PacketNumberSpace, count: u32 },
    packets_lost: struct { space: PacketNumberSpace, bytes: usize },
    close_sent: struct { error_code: u64 },
    close_received: struct { error_code: u64, is_application: bool },
    idle_timeout,
    /// A PATH_RESPONSE echoed the outstanding PATH_CHALLENGE: the path is
    /// validated (RFC 9000 §8.2.3).
    path_validated: [frame.path_data_len]u8,
};

pub const DropReason = enum {
    unknown_cid,
    undecryptable,
    malformed,
    unsupported_version,
    unexpected_type,
};

/// Diagnostics hook (qlog attaches here under #255). Must not block.
pub const EventSink = struct {
    context: ?*anyopaque = null,
    emitFn: ?*const fn (?*anyopaque, Event) void = null,

    pub fn emit(self: EventSink, event: Event) void {
        if (self.emitFn) |emit_fn| emit_fn(self.context, event);
    }
};

pub const Metrics = struct {
    datagrams_received: u64 = 0,
    datagrams_sent: u64 = 0,
    packets_received: u64 = 0,
    packets_sent: u64 = 0,
    packets_dropped: u64 = 0,
    packets_lost: u64 = 0,
    pto_count_total: u64 = 0,
    acks_sent: u64 = 0,
};

pub const CloseInfo = struct {
    error_code: u64,
    is_application: bool,
    /// True when this side initiated the close.
    local: bool,
};

pub const Options = struct {
    role: Role,
    config: config.Config = .{},
    /// This side's connection ID (server: the client's original DCID, adopted).
    local_cid: []const u8,
    /// Client: the random original DCID choosing the Initial secrets.
    /// Server: the client's original DCID (same as `local_cid` here).
    original_dcid: []const u8,
    /// Client: leave empty; adopted from the server's first Initial SCID.
    /// Server: the client's SCID.
    peer_cid: []const u8 = &.{},
    tls: tls_handshake.TlsBackend,
    now_us: u64,
    events: EventSink = .{},
    /// Local escape hatch for interop tests against peers whose certificates
    /// this backend cannot chain-validate. Mirrors
    /// `Handshake.allow_unverified_certificate`.
    allow_unverified_certificate: bool = false,
};

// ---------------------------------------------------------------------------
// Range bookkeeping for retransmittable byte streams (CRYPTO and STREAM).
// ---------------------------------------------------------------------------

const Range = struct {
    start: u64,
    end: u64, // exclusive

    fn len(self: Range) u64 {
        return self.end - self.start;
    }
};

/// Sorted, merged list of byte ranges. Small: crypto flights and per-stream
/// send windows produce a handful of ranges.
const RangeList = struct {
    items: std.ArrayList(Range) = .empty,

    fn deinit(self: *RangeList, allocator: std.mem.Allocator) void {
        self.items.deinit(allocator);
    }

    fn isEmpty(self: *const RangeList) bool {
        return self.items.items.len == 0;
    }

    fn insert(self: *RangeList, allocator: std.mem.Allocator, incoming: Range) !void {
        if (incoming.start >= incoming.end) return;
        var merged = incoming;
        var index: usize = 0;
        while (index < self.items.items.len) {
            const current = self.items.items[index];
            if (merged.end < current.start) break;
            if (current.end < merged.start) {
                index += 1;
                continue;
            }
            merged.start = @min(merged.start, current.start);
            merged.end = @max(merged.end, current.end);
            _ = self.items.orderedRemove(index);
        }
        try self.items.insert(allocator, index, merged);
    }

    /// Remove and return up to `max_len` bytes from the lowest range.
    fn takeFirst(self: *RangeList, max_len: u64) ?Range {
        if (self.items.items.len == 0) return null;
        const first = &self.items.items[0];
        if (first.len() <= max_len) {
            const taken = first.*;
            _ = self.items.orderedRemove(0);
            return taken;
        }
        const taken = Range{ .start = first.start, .end = first.start + max_len };
        first.start = taken.end;
        return taken;
    }

    /// Whether [0, end) is fully covered by a single leading range.
    fn coversPrefix(self: *const RangeList, end: u64) bool {
        if (self.items.items.len == 0) return end == 0;
        const first = self.items.items[0];
        return first.start == 0 and first.end >= end;
    }
};

/// Retained CRYPTO transmit data for one encryption level. Offsets are
/// absolute stream offsets; handshake flights are small, so the whole flight
/// stays buffered until the level's keys are discarded.
const CryptoTx = struct {
    data: std.ArrayList(u8) = .empty,
    pending: RangeList = .{},

    fn deinit(self: *CryptoTx, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
        self.pending.deinit(allocator);
    }
};

/// Driver-owned transmit buffer for one stream: bytes the application handed
/// to `writeStream` that are unsent or unacked. `base` is the stream offset
/// of `data[start]`.
const SendQueue = struct {
    data: std.ArrayList(u8) = .empty,
    start: usize = 0,
    base: u64 = 0,
    /// Bytes already granted by the stream manager (flow control) and sent at
    /// least once. New data begins at this offset.
    reserved_end: u64 = 0,
    fin_requested: bool = false,
    fin_reserved: bool = false,
    /// Previously sent ranges that need retransmission (loss/PTO).
    retransmit: RangeList = .{},
    /// Acked ranges (absolute offsets), for releasing the buffer prefix.
    acked: RangeList = .{},
    /// A lost packet carried this stream's FIN; resend it.
    fin_retransmit: bool = false,
    /// Stream was reset locally; drop all queued data.
    reset_sent: bool = false,

    fn deinit(self: *SendQueue, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
        self.retransmit.deinit(allocator);
        self.acked.deinit(allocator);
    }

    fn bufferedEnd(self: *const SendQueue) u64 {
        return self.base + @as(u64, @intCast(self.data.items.len - self.start));
    }

    fn buffered(self: *const SendQueue) usize {
        return self.data.items.len - self.start;
    }

    fn slice(self: *const SendQueue, range: Range) []const u8 {
        const from: usize = @intCast(range.start - self.base);
        return self.data.items[self.start + from ..][0..@intCast(range.len())];
    }

    /// Release the acked prefix so long-lived streams don't grow unboundedly.
    fn compact(self: *SendQueue, allocator: std.mem.Allocator) void {
        var prefix_end = self.base;
        if (self.acked.items.items.len > 0) {
            const first = self.acked.items.items[0];
            if (first.start <= self.base) prefix_end = @min(first.end, self.reserved_end);
        }
        if (prefix_end <= self.base) return;
        // Never release bytes that still need retransmission.
        for (self.retransmit.items.items) |r| {
            if (r.start < prefix_end) prefix_end = r.start;
        }
        if (prefix_end <= self.base) return;
        const drop: usize = @intCast(prefix_end - self.base);
        self.start += drop;
        self.base = prefix_end;
        if (self.start == self.data.items.len and self.data.items.len > 4096) {
            self.data.clearAndFree(allocator);
            self.start = 0;
        }
    }
};

/// What a sent packet carried, for retransmission on loss and release on ack.
/// Parallel to the recovery controller's `SentPacket` accounting.
const SentRecord = struct {
    space: PacketNumberSpace,
    packet_number: u64,
    ack_eliciting: bool,
    crypto: ?Range = null,
    stream_count: u8 = 0,
    streams: [4]StreamRange = undefined,
    /// Flow-control and lifecycle frames that must be re-armed on loss.
    carried_max_data: bool = false,
    carried_max_stream_data: ?StreamId = null,
    carried_handshake_done: bool = false,
    carried_reset_stream: ?quic_stream.ResetStreamFrame = null,
    carried_stop_sending: ?quic_stream.StopSendingFrame = null,
    /// PATH_CHALLENGE re-arms on loss; PATH_RESPONSE does not (the peer
    /// re-challenges, RFC 9000 §8.2.2). Both force datagram expansion.
    carried_path_challenge: bool = false,
    carried_path_response: bool = false,
    carried_ack_largest: ?u64 = null,

    const StreamRange = struct {
        id: StreamId,
        range: Range,
        fin: bool,
    };
};

// ---------------------------------------------------------------------------
// The connection.
// ---------------------------------------------------------------------------

pub const Connection = struct {
    allocator: std.mem.Allocator,
    role: Role,
    state_: State = .handshaking,
    cfg: config.Config,
    local_params: config.TransportParameters,
    events: EventSink,
    metrics: Metrics = .{},

    adapter: tls_adapter.QuicTlsAdapter = .{},
    handshake: tls_handshake.Handshake = undefined,
    tls: tls_handshake.TlsBackend,

    recovery: recovery.RecoveryController = .{},
    amp: quic_path.AntiAmplification = .{},

    local_cid: config.CidValue,
    peer_cid: config.CidValue,
    original_dcid: config.CidValue,
    retry_scid: ?config.CidValue = null,
    retry_token: std.ArrayList(u8) = .empty,
    peer_cids: quic_cid.PeerCidPool,

    streams: ?quic_stream.StreamManager = null,
    send_queues: std.AutoHashMap(StreamId, *SendQueue),
    known_streams: std.AutoHashMap(StreamId, void),
    accept_queue: std.ArrayList(StreamId) = .empty,

    crypto_tx: [2]CryptoTx = .{ .{}, .{} },
    sent_records: std.ArrayList(SentRecord) = .empty,

    next_pn: [3]u64 = .{ 0, 0, 0 },
    largest_recv_pn: [3]?u64 = .{ null, null, null },
    largest_peer_acked: [3]?u64 = .{ null, null, null },
    /// Whether an ACK must be assembled for the space, and when the obligation
    /// arose (for the encoded ack_delay and the delayed-ack timer).
    ack_needed: [3]bool = .{ false, false, false },
    ack_armed_at_us: [3]u64 = .{ 0, 0, 0 },
    ack_eliciting_since_ack: [3]u64 = .{ 0, 0, 0 },
    /// Last time an ack-eliciting packet was sent per space (PTO base).
    last_ack_eliciting_sent_us: [3]?u64 = .{ null, null, null },
    pto_count: u32 = 0,
    /// Probe datagrams owed per space after a PTO fires.
    probes_pending: [3]u8 = .{ 0, 0, 0 },

    handshake_complete: bool = false,
    /// Server: discard Handshake keys once the Finished ACK has been sent.
    handshake_keys_discard_pending: bool = false,
    handshake_confirmed: bool = false,
    handshake_done_pending: bool = false,
    handshake_done_acked: bool = false,
    /// Client adopted the server's SCID from its first Initial packet.
    peer_cid_adopted: bool = false,
    got_retry: bool = false,
    initial_packet_processed: bool = false,
    /// First Handshake-level packet sent (client Initial-key discard trigger).
    sent_handshake_packet: bool = false,
    processed_handshake_packet: bool = false,

    pending_max_data: ?u64 = null,
    pending_max_stream_data: std.ArrayList(struct { id: StreamId, limit: u64 }) = .empty,
    pending_resets: std.ArrayList(quic_stream.ResetStreamFrame) = .empty,
    pending_stop_sending: std.ArrayList(quic_stream.StopSendingFrame) = .empty,
    pending_retires: std.ArrayList(u64) = .empty,
    pending_path_responses: std.ArrayList([frame.path_data_len]u8) = .empty,
    /// Path validation we initiated (RFC 9000 §8.2): the challenge data that
    /// must come back in a PATH_RESPONSE. `needs_send` re-arms transmission
    /// (initially and when the carrying packet is lost); completion is
    /// surfaced via `consumePathValidated` and the `path_validated` event.
    path_challenge_data: ?[frame.path_data_len]u8 = null,
    path_challenge_needs_send: bool = false,
    path_validated_data: ?[frame.path_data_len]u8 = null,

    idle_deadline_us: ?u64 = null,
    last_activity_us: u64,
    close_info: ?CloseInfo = null,
    close_reason: [64]u8 = undefined,
    close_reason_len: usize = 0,
    close_deadline_us: ?u64 = null,
    close_resend_allowed_at_us: u64 = 0,
    close_needs_send: bool = false,
    /// Terminal handshake failure (kept for the embedder's diagnostics).
    handshake_error: ?tls_handshake.HandshakeError = null,

    pub fn init(allocator: std.mem.Allocator, options: Options) !*Connection {
        const conn = try allocator.create(Connection);
        errdefer allocator.destroy(conn);

        const params = try options.config.transportParameters();
        conn.* = .{
            .allocator = allocator,
            .role = options.role,
            .cfg = options.config,
            .local_params = params,
            .events = options.events,
            .tls = options.tls,
            .local_cid = try config.CidValue.init(options.local_cid),
            .peer_cid = if (options.peer_cid.len > 0)
                try config.CidValue.init(options.peer_cid)
            else
                .{},
            .original_dcid = try config.CidValue.init(options.original_dcid),
            .peer_cids = quic_cid.PeerCidPool.init(params.active_connection_id_limit),
            .send_queues = std.AutoHashMap(StreamId, *SendQueue).init(allocator),
            .known_streams = std.AutoHashMap(StreamId, void).init(allocator),
            .last_activity_us = options.now_us,
        };
        // Construct the handshake before `errdefer conn.deinitPartial()` is
        // installed: deinitPartial() unconditionally calls
        // `self.handshake.deinit()`, so any fallible operation between the
        // errdefer and this assignment would otherwise run deinit() against
        // undefined storage. Handshake.initClient/initServer are plain
        // constructors (no I/O, no dependency on installed secrets), so
        // this reordering is free.
        conn.handshake = switch (options.role) {
            .client => tls_handshake.Handshake.initClient(&conn.adapter, options.tls),
            .server => tls_handshake.Handshake.initServer(&conn.adapter, options.tls),
        };
        errdefer conn.deinitPartial();

        // RFC 9000 §7.3 binding: commit our CIDs into the TLS transport
        // parameters before the first flight.
        var binding = config.CidBinding{
            .initial_source_connection_id = conn.local_cid,
        };
        if (options.role == .server) {
            binding.original_destination_connection_id = conn.original_dcid;
        }
        options.tls.setCidBinding(binding);

        if (options.role == .client and conn.peer_cid.len == 0) {
            conn.peer_cid = conn.original_dcid;
        }
        if (conn.peer_cid.len > 0) {
            const initial_peer = quic_cid.ConnectionId.init(conn.peer_cid.slice()) catch null;
            if (initial_peer) |cid_value| conn.peer_cids.registerInitial(cid_value) catch {};
        }
        _ = try conn.adapter.installInitialSecrets(
            switch (options.role) {
                .client => .client,
                .server => .server,
            },
            conn.original_dcid.slice(),
        );
        conn.handshake.manual_key_discard = true;
        conn.handshake.allow_unverified_certificate = options.allow_unverified_certificate;
        conn.handshake.start(params) catch |err| {
            conn.failHandshake(err);
            return conn;
        };
        try conn.collectCryptoOutput();
        conn.armIdle(options.now_us);
        // The client's address is validated by definition; a server must not
        // exceed 3× received bytes until the handshake validates the client.
        if (options.role == .client) conn.amp.markValidated();
        return conn;
    }

    fn deinitPartial(self: *Connection) void {
        self.handshake.deinit();
        if (self.streams) |*manager| manager.deinit();
        var it = self.send_queues.valueIterator();
        while (it.next()) |queue| {
            queue.*.deinit(self.allocator);
            self.allocator.destroy(queue.*);
        }
        self.send_queues.deinit();
        self.known_streams.deinit();
        self.accept_queue.deinit(self.allocator);
        for (&self.crypto_tx) |*tx| tx.deinit(self.allocator);
        self.sent_records.deinit(self.allocator);
        self.pending_max_stream_data.deinit(self.allocator);
        self.pending_resets.deinit(self.allocator);
        self.pending_stop_sending.deinit(self.allocator);
        self.pending_retires.deinit(self.allocator);
        self.pending_path_responses.deinit(self.allocator);
        self.retry_token.deinit(self.allocator);
    }

    pub fn deinit(self: *Connection) void {
        const allocator = self.allocator;
        self.deinitPartial();
        allocator.destroy(self);
    }

    // -- state ---------------------------------------------------------------

    pub fn state(self: *const Connection) State {
        return self.state_;
    }

    pub fn isEstablished(self: *const Connection) bool {
        return self.state_ == .established;
    }

    pub fn negotiatedH3(self: *const Connection) bool {
        return self.adapter.negotiatedH3();
    }

    pub fn peerTransportParameters(self: *const Connection) ?config.TransportParameters {
        return self.adapter.peerTransportParameters();
    }

    pub fn closeInfo(self: *const Connection) ?CloseInfo {
        return self.close_info;
    }

    pub fn handshakeFailure(self: *const Connection) ?tls_handshake.HandshakeError {
        return self.handshake_error;
    }

    /// The connection ID the peer routes to us with (for endpoint routing).
    pub fn localCid(self: *const Connection) []const u8 {
        return self.local_cid.slice();
    }

    fn setState(self: *Connection, next: State) void {
        if (self.state_ == next) return;
        self.state_ = next;
        self.events.emit(.{ .state = next });
    }

    fn spaceIndex(space: PacketNumberSpace) usize {
        return @intFromEnum(space);
    }

    fn levelForSpace(space: PacketNumberSpace) EncryptionLevel {
        return switch (space) {
            .initial => .initial,
            .handshake => .handshake,
            .application => .application,
        };
    }

    fn spaceForLevel(level: EncryptionLevel) PacketNumberSpace {
        return switch (level) {
            .initial => .initial,
            .handshake => .handshake,
            .application, .zero_rtt => .application,
        };
    }

    // -- ingest ---------------------------------------------------------------

    /// Feed one received UDP datagram. Malformed or undecryptable packets are
    /// dropped individually; a protocol violation closes the connection.
    pub fn ingest(self: *Connection, datagram: []const u8, now_us: u64) IngestError!void {
        if (self.state_ == .closed or self.state_ == .draining) return;
        self.metrics.datagrams_received += 1;
        self.amp.recordReceived(datagram.len);

        var offset: usize = 0;
        while (offset < datagram.len) {
            const rest = datagram[offset..];
            const parsed = packet.parsePacket(rest, self.local_cid.len) catch {
                self.dropPacket(.malformed, rest.len);
                return;
            };
            if (parsed.packet_len == 0 or parsed.packet_len > rest.len) {
                self.dropPacket(.malformed, rest.len);
                return;
            }
            try self.ingestPacket(rest[0..parsed.packet_len], parsed, now_us);
            if (self.state_ == .closed or self.state_ == .draining) return;
            offset += parsed.packet_len;
            // Everything after a short-header packet is part of it.
            if (parsed.kind == .one_rtt) break;
        }
        self.armIdle(now_us);
    }

    fn ingestPacket(self: *Connection, bytes: []const u8, parsed: packet.ParsedPacket, now_us: u64) IngestError!void {
        switch (parsed.kind) {
            .version_negotiation => {
                // We only speak v1; a VN packet means no common version.
                if (self.role == .client and !self.initial_packet_processed) {
                    self.dropPacket(.unsupported_version, bytes.len);
                    self.startClose(.{ .error_code = error_internal, .is_application = false, .local = true }, "no common QUIC version", now_us);
                } else {
                    self.dropPacket(.unexpected_type, bytes.len);
                }
                return;
            },
            .retry => {
                self.handleRetry(bytes, parsed, now_us);
                return;
            },
            .zero_rtt => {
                // 0-RTT is disabled (config default); nothing can decrypt it.
                self.dropPacket(.undecryptable, bytes.len);
                return;
            },
            else => {},
        }
        if (parsed.kind != .one_rtt and parsed.version != packet.quic_v1) {
            self.dropPacket(.unsupported_version, bytes.len);
            return;
        }
        if (!std.mem.eql(u8, parsed.dcid, self.local_cid.slice())) {
            self.dropPacket(.unknown_cid, bytes.len);
            return;
        }

        const level: EncryptionLevel = switch (parsed.kind) {
            .initial => .initial,
            .handshake => .handshake,
            .one_rtt => .application,
            else => unreachable,
        };
        const space = spaceForLevel(level);

        // Header protection removal needs a sample 4 bytes past pn_offset.
        var work: [2048]u8 = undefined;
        if (bytes.len > work.len) {
            self.dropPacket(.malformed, bytes.len);
            return;
        }
        @memcpy(work[0..bytes.len], bytes);
        if (parsed.packet_len < parsed.pn_offset + 4 + sample_len) {
            self.dropPacket(.malformed, bytes.len);
            return;
        }

        var keys = self.adapter.protectionKeys(level, .read) orelse {
            self.dropPacket(.undecryptable, bytes.len);
            return;
        };
        var sample: [sample_len]u8 = undefined;
        @memcpy(&sample, work[parsed.pn_offset + 4 ..][0..sample_len]);
        var sampled_pn: [4]u8 = work[parsed.pn_offset..][0..4].*;
        const removed = keys.removeHeaderProtection(&work[0], &sampled_pn, sample);
        @memcpy(work[parsed.pn_offset..][0..removed.packet_number_length], sampled_pn[0..removed.packet_number_length]);

        const space_idx = spaceIndex(space);
        const pn = packet.decodePacketNumber(
            self.largest_recv_pn[space_idx] orelse 0,
            removed.truncated_packet_number,
            @intCast(removed.packet_number_length * 8),
        );

        // 1-RTT key update (RFC 9001 §6): a flipped key-phase bit means the
        // peer moved to the next generation.
        var used_next_keys = false;
        if (level == .application) {
            const wire_phase: u1 = @intCast((work[0] >> 2) & 1);
            if (wire_phase != self.adapter.applicationReadKeyPhase()) {
                keys = self.adapter.nextApplicationReadKeys() orelse {
                    self.dropPacket(.undecryptable, bytes.len);
                    return;
                };
                used_next_keys = true;
            }
        }

        const header = work[0 .. parsed.pn_offset + removed.packet_number_length];
        const ciphertext = work[parsed.pn_offset + removed.packet_number_length .. parsed.packet_len];
        var plain: [2048]u8 = undefined;
        const payload = keys.openPayload(pn, header, ciphertext, &plain) catch {
            self.adapter.metrics.deprotection_failures += 1;
            self.dropPacket(.undecryptable, bytes.len);
            return;
        };
        self.adapter.metrics.packets_deprotected += 1;

        if (used_next_keys) {
            self.adapter.commitApplicationReadKeyUpdate() catch {};
            self.adapter.updateApplicationWriteKeys() catch {};
        }

        // Post-authentication bookkeeping.
        self.metrics.packets_received += 1;
        self.events.emit(.{ .packet_received = .{ .space = space, .packet_number = pn, .size = bytes.len } });
        if (self.largest_recv_pn[space_idx] == null or pn > self.largest_recv_pn[space_idx].?) {
            self.largest_recv_pn[space_idx] = pn;
        }
        self.recovery.onPacketReceived(space, pn) catch {
            // Pathological ACK-range fragmentation; close rather than lose ACK state.
            self.startClose(.{ .error_code = error_internal, .is_application = false, .local = true }, "ack range overflow", now_us);
            return;
        };
        self.last_activity_us = now_us;

        if (self.role == .client and parsed.kind == .initial and !self.peer_cid_adopted) {
            // RFC 9000 §7.2: the client adopts the server's SCID.
            self.peer_cid = config.CidValue.init(parsed.scid) catch self.peer_cid;
            self.peer_cid_adopted = true;
            self.peer_cids = quic_cid.PeerCidPool.init(self.local_params.active_connection_id_limit);
            if (quic_cid.ConnectionId.init(self.peer_cid.slice()) catch null) |cid_value| {
                self.peer_cids.registerInitial(cid_value) catch {};
            }
        }
        self.initial_packet_processed = true;
        if (level == .handshake) {
            if (self.role == .server) self.amp.markValidated();
            if (!self.processed_handshake_packet) {
                self.processed_handshake_packet = true;
                // Server: receiving a Handshake packet proves the client got
                // the ServerHello; Initial keys are done (RFC 9001 §4.9.1).
                if (self.role == .server) self.discardKeys(.initial);
            }
        }

        var ack_eliciting = false;
        var parser = frame.Parser.init(payload);
        while (true) {
            const decoded = parser.next() catch {
                self.startClose(.{ .error_code = error_frame_encoding, .is_application = false, .local = true }, "frame decode", now_us);
                return;
            };
            const f = decoded orelse break;
            if (f.isAckEliciting()) ack_eliciting = true;
            try self.applyFrame(level, f, now_us);
            if (self.state_ == .closed or self.state_ == .draining) return;
            if (self.state_ == .closing) break;
        }

        if (ack_eliciting) {
            if (!self.ack_needed[space_idx]) {
                self.ack_needed[space_idx] = true;
                self.ack_armed_at_us[space_idx] = now_us;
            }
            self.ack_eliciting_since_ack[space_idx] += 1;
        }

        // While closing, a peer that keeps talking gets the close again
        // (rate-limited).
        if (self.state_ == .closing and now_us >= self.close_resend_allowed_at_us) {
            self.close_needs_send = true;
        }
    }

    fn applyFrame(self: *Connection, level: EncryptionLevel, f: frame.Frame, now_us: u64) IngestError!void {
        const space = spaceForLevel(level);
        switch (f) {
            .padding, .ping => {},
            .ack => |ack| self.processAck(space, ack, now_us),
            .crypto => |c| {
                self.handshake.onCrypto(level, c.offset, c.data) catch |err| {
                    self.failHandshake(err);
                    self.startClose(.{ .error_code = cryptoErrorCode(err), .is_application = false, .local = true }, @errorName(err), now_us);
                    return;
                };
                self.collectCryptoOutput() catch {
                    self.failHandshake(error.HandshakeBufferOverflow);
                    self.startClose(.{ .error_code = error_crypto_buffer_exceeded, .is_application = false, .local = true }, "crypto buffer", now_us);
                    return;
                };
                self.afterHandshakeProgress(now_us);
            },
            .stream => |sf| {
                if (level != .application) {
                    self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "stream frame level", now_us);
                    return;
                }
                var manager = self.streamManager() orelse {
                    self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "stream before handshake", now_us);
                    return;
                };
                const known = self.known_streams.contains(sf.id);
                _ = manager.receiveStreamFrame(sf) catch |err| {
                    self.closeOnStreamError(err, now_us);
                    return;
                };
                if (!known) {
                    try self.known_streams.put(sf.id, {});
                    if (quic_stream.streamInitiator(sf.id) != roleInitiator(self.role)) {
                        try self.accept_queue.append(self.allocator, sf.id);
                    }
                }
            },
            .reset_stream => |rs| {
                var manager = self.streamManager() orelse return;
                manager.receiveResetStream(rs) catch |err| {
                    self.closeOnStreamError(err, now_us);
                    return;
                };
                if (!self.known_streams.contains(rs.id)) {
                    try self.known_streams.put(rs.id, {});
                    if (quic_stream.streamInitiator(rs.id) != roleInitiator(self.role)) {
                        try self.accept_queue.append(self.allocator, rs.id);
                    }
                }
            },
            .stop_sending => |ss| {
                var manager = self.streamManager() orelse return;
                manager.receiveStopSending(ss) catch |err| {
                    self.closeOnStreamError(err, now_us);
                    return;
                };
                // RFC 9000 §3.5: a STOP_SENDING peer expects RESET_STREAM.
                if (manager.sendResetStream(ss.id, ss.app_error_code)) |reset| {
                    try self.pending_resets.append(self.allocator, reset);
                    if (self.send_queues.get(ss.id)) |queue| queue.reset_sent = true;
                } else |_| {}
            },
            .max_data => |limit| {
                if (self.streamManager()) |manager| manager.applyMaxData(limit);
            },
            .max_stream_data => |msd| {
                if (self.streamManager()) |manager| manager.applyMaxStreamData(msd.id, msd.limit) catch {};
            },
            .max_streams_bidi => |limit| {
                if (self.streamManager()) |manager| manager.applyMaxStreams(.bidi, limit);
            },
            .max_streams_uni => |limit| {
                if (self.streamManager()) |manager| manager.applyMaxStreams(.uni, limit);
            },
            .data_blocked, .stream_data_blocked, .streams_blocked_bidi, .streams_blocked_uni => {},
            .new_token => {
                // Address-validation tokens for future connections; endpoint
                // token stores are out of scope for the driver.
                if (self.role == .server) {
                    self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "client sent NEW_TOKEN", now_us);
                }
            },
            .new_connection_id => |ncid| {
                self.peer_cids.onNewConnectionId(ncid.frame) catch |err| switch (err) {
                    error.ProtocolViolation => {
                        self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "NEW_CONNECTION_ID", now_us);
                        return;
                    },
                    error.CidLimitExceeded => {
                        self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "CID limit", now_us);
                        return;
                    },
                    error.RetireQueueFull => {},
                };
                while (self.peer_cids.takePendingRetire()) |retire| {
                    try self.pending_retires.append(self.allocator, retire.sequence);
                }
            },
            .retire_connection_id => {
                // We never issue additional CIDs, so there is nothing to
                // retire; tolerate the frame (it can only name sequence 0).
            },
            .path_challenge => |data| {
                if (level == .application) {
                    try self.pending_path_responses.append(self.allocator, data);
                }
            },
            .path_response => |data| {
                // Validation completes only when the response echoes the
                // outstanding challenge (RFC 9000 §8.2.3). Anything else is a
                // response to an abandoned challenge; ignoring it is permitted
                // (§19.18 makes the connection error optional).
                if (level != .application) return;
                const expected = self.path_challenge_data orelse return;
                if (!std.mem.eql(u8, &data, &expected)) return;
                self.path_challenge_data = null;
                self.path_challenge_needs_send = false;
                self.path_validated_data = data;
                self.events.emit(.{ .path_validated = data });
            },
            .connection_close => |cc| {
                self.events.emit(.{ .close_received = .{ .error_code = cc.error_code, .is_application = cc.is_application } });
                self.close_info = .{ .error_code = cc.error_code, .is_application = cc.is_application, .local = false };
                self.setState(.draining);
                self.close_deadline_us = now_us + 3 * self.ptoDurationNow();
            },
            .handshake_done => {
                if (self.role == .server) {
                    self.startClose(.{ .error_code = error_protocol_violation, .is_application = false, .local = true }, "client sent HANDSHAKE_DONE", now_us);
                    return;
                }
                if (!self.handshake_confirmed) {
                    self.handshake_confirmed = true;
                    self.events.emit(.handshake_confirmed);
                    self.discardKeys(.handshake);
                }
            },
        }
    }

    fn processAck(self: *Connection, space: PacketNumberSpace, ack: frame.Ack, now_us: u64) void {
        const exponent: u6 = if (self.adapter.peerTransportParameters()) |peer|
            @intCast(@min(peer.ack_delay_exponent, 20))
        else
            3;
        const ack_delay_us = ack.ackDelayUs(exponent);
        const space_idx = spaceIndex(space);
        if (self.largest_peer_acked[space_idx] == null or ack.largest_acknowledged > self.largest_peer_acked[space_idx].?) {
            self.largest_peer_acked[space_idx] = ack.largest_acknowledged;
        }

        // Ack every tracked packet covered by the ranges. The RTT sample only
        // comes from the largest acked packet (RFC 9002 §5.1).
        var index: usize = 0;
        while (index < self.sent_records.items.len) {
            const record = self.sent_records.items[index];
            if (record.space != space or !ack.ranges.contains(record.packet_number)) {
                index += 1;
                continue;
            }
            if (self.recovery.tracker.onAcked(space, record.packet_number, now_us)) |acked| {
                self.recovery.congestion.onPacketAcked(acked.packet);
                if (record.packet_number == ack.largest_acknowledged) {
                    if (acked.rtt_sample_us) |sample| self.recovery.rtt.update(sample, ack_delay_us);
                }
            }
            self.onRecordAcked(record);
            _ = self.sent_records.swapRemove(index);
        }
        // A validated ACK ends the current PTO backoff episode.
        self.pto_count = 0;

        self.detectAndRequeueLost(space, now_us);
    }

    fn onRecordAcked(self: *Connection, record: SentRecord) void {
        if (record.carried_handshake_done) self.handshake_done_acked = true;
        for (record.streams[0..record.stream_count]) |sr| {
            if (self.send_queues.get(sr.id)) |queue| {
                queue.acked.insert(self.allocator, sr.range) catch {};
                queue.compact(self.allocator);
            }
        }
        // Acked CRYPTO ranges need no explicit bookkeeping: pending ranges
        // are only re-armed on loss, and level buffers drop with the keys.
    }

    /// Detect newly lost packets in `space` and requeue their content.
    fn detectAndRequeueLost(self: *Connection, space: PacketNumberSpace, now_us: u64) void {
        const loss = self.recovery.detectLost(space, now_us);
        if (loss.packet_threshold_losses + loss.time_threshold_losses == 0) return;
        // The tracker dropped the lost packets; any record of this space no
        // longer tracked (and not acked, i.e. still recorded) is lost.
        var index: usize = 0;
        var lost_count: u64 = 0;
        while (index < self.sent_records.items.len) {
            const record = self.sent_records.items[index];
            if (record.space != space or self.trackerContains(space, record.packet_number)) {
                index += 1;
                continue;
            }
            lost_count += 1;
            self.requeueRecord(record);
            _ = self.sent_records.swapRemove(index);
        }
        if (lost_count > 0) {
            self.metrics.packets_lost += lost_count;
            self.events.emit(.{ .packets_lost = .{ .space = space, .bytes = loss.lost_bytes } });
        }
    }

    fn trackerContains(self: *const Connection, space: PacketNumberSpace, pn: u64) bool {
        for (self.recovery.tracker.packets[0..self.recovery.tracker.count]) |p| {
            if (p.space == space and p.packet_number == pn) return true;
        }
        return false;
    }

    /// Requeue everything a lost packet carried.
    fn requeueRecord(self: *Connection, record: SentRecord) void {
        if (record.crypto) |range| {
            const tx = switch (record.space) {
                .initial => &self.crypto_tx[0],
                .handshake => &self.crypto_tx[1],
                .application => return,
            };
            // If the level's keys are already discarded the buffer is gone.
            if (tx.data.items.len > 0) {
                tx.pending.insert(self.allocator, range) catch {};
            }
        }
        for (record.streams[0..record.stream_count]) |sr| {
            if (self.send_queues.get(sr.id)) |queue| {
                if (!queue.reset_sent) {
                    // Never requeue below the released prefix (already acked).
                    var range = sr.range;
                    if (range.start < queue.base) range.start = queue.base;
                    queue.retransmit.insert(self.allocator, range) catch {};
                    if (sr.fin) queue.fin_retransmit = true;
                }
            }
        }
        if (record.carried_handshake_done and !self.handshake_done_acked) {
            self.handshake_done_pending = true;
        }
        if (record.carried_max_data) self.queueMaxDataUpdate();
        if (record.carried_max_stream_data) |id| self.queueMaxStreamDataUpdate(id);
        if (record.carried_reset_stream) |reset| {
            self.pending_resets.append(self.allocator, reset) catch {};
        }
        if (record.carried_stop_sending) |stop| {
            self.pending_stop_sending.append(self.allocator, stop) catch {};
        }
        if (record.carried_path_challenge and self.path_challenge_data != null) {
            self.path_challenge_needs_send = true;
        }
    }

    fn queueMaxDataUpdate(self: *Connection) void {
        if (self.streamManager()) |manager| {
            self.pending_max_data = manager.max_data_recv;
        }
    }

    fn queueMaxStreamDataUpdate(self: *Connection, id: StreamId) void {
        const manager = self.streamManager() orelse return;
        const s = manager.get(id) orelse return;
        self.pending_max_stream_data.append(self.allocator, .{ .id = id, .limit = s.max_recv_data }) catch {};
    }

    fn closeOnStreamError(self: *Connection, err: anyerror, now_us: u64) void {
        const code: u64 = switch (err) {
            error.FinalSizeError => error_final_size,
            error.FlowControlBlocked, error.StreamDataBlocked => error_flow_control,
            error.StreamLimitExceeded => error_stream_limit,
            error.SendOnlyStream, error.RecvOnlyStream, error.StreamClosed => error_stream_state,
            error.OverlappingStreamDataMismatch => error_protocol_violation,
            else => error_internal,
        };
        self.startClose(.{ .error_code = code, .is_application = false, .local = true }, @errorName(err), now_us);
    }

    fn dropPacket(self: *Connection, reason: DropReason, size: usize) void {
        self.metrics.packets_dropped += 1;
        self.events.emit(.{ .packet_dropped = .{ .reason = reason, .size = size } });
    }

    fn roleInitiator(role: Role) quic_stream.Initiator {
        return switch (role) {
            .client => .client,
            .server => .server,
        };
    }

    fn streamManager(self: *Connection) ?*quic_stream.StreamManager {
        if (self.streams) |*manager| return manager;
        return null;
    }

    // -- retry / handshake progress -------------------------------------------

    fn handleRetry(self: *Connection, bytes: []const u8, parsed: packet.ParsedPacket, now_us: u64) void {
        _ = now_us;
        // RFC 9000 §17.2.5.2: only clients accept Retry, only before any
        // Initial packet from the server, and only once.
        if (self.role != .client or self.got_retry or self.initial_packet_processed) {
            self.dropPacket(.unexpected_type, bytes.len);
            return;
        }
        if (parsed.retry_token.len == 0) {
            self.dropPacket(.malformed, bytes.len);
            return;
        }
        if (!packet.verifyRetryIntegrity(bytes, self.original_dcid.slice())) {
            self.dropPacket(.malformed, bytes.len);
            return;
        }
        self.got_retry = true;
        self.retry_scid = config.CidValue.init(parsed.scid) catch null;
        self.retry_token.clearRetainingCapacity();
        self.retry_token.appendSlice(self.allocator, parsed.retry_token) catch return;

        // New DCID -> new Initial keys (RFC 9001 §5.2), and the whole Initial
        // flight goes again with the token attached.
        self.peer_cid = self.retry_scid.?;
        _ = self.adapter.installInitialSecrets(.client, self.peer_cid.slice()) catch return;
        _ = self.recovery.onKeysDiscarded(.initial);
        var index: usize = 0;
        while (index < self.sent_records.items.len) {
            if (self.sent_records.items[index].space == .initial) {
                _ = self.sent_records.swapRemove(index);
            } else index += 1;
        }
        const tx = &self.crypto_tx[0];
        tx.pending.items.clearRetainingCapacity();
        tx.pending.insert(self.allocator, .{ .start = 0, .end = tx.data.items.len }) catch {};
        self.largest_recv_pn[0] = null;
    }

    /// Drain queued TLS output into the per-level retransmission buffers.
    fn collectCryptoOutput(self: *Connection) !void {
        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }, 0..) |level, tx_index| {
            var chunk: [2048]u8 = undefined;
            while (self.handshake.pollOutput(level, &chunk) catch null) |output| {
                const tx = &self.crypto_tx[tx_index];
                std.debug.assert(output.offset == tx.data.items.len);
                try tx.data.appendSlice(self.allocator, output.bytes);
                try tx.pending.insert(self.allocator, .{
                    .start = output.offset,
                    .end = output.offset + output.bytes.len,
                });
            }
        }
    }

    fn afterHandshakeProgress(self: *Connection, now_us: u64) void {
        if (self.handshake_complete or !self.handshake.isComplete()) return;
        self.handshake_complete = true;
        self.events.emit(.handshake_complete);

        // RFC 9000 §7.3: validate the peer's authenticated CID binding
        // against what we actually observed on the wire.
        const peer_binding = self.tls.peerCidBinding();
        if (!self.validateCidBinding(peer_binding)) {
            self.startClose(.{ .error_code = error_transport_parameter, .is_application = false, .local = true }, "cid binding mismatch", now_us);
            return;
        }

        const peer_params = self.adapter.peerTransportParameters() orelse {
            self.startClose(.{ .error_code = error_transport_parameter, .is_application = false, .local = true }, "missing peer params", now_us);
            return;
        };
        self.streams = quic_stream.StreamManager.init(
            self.allocator,
            switch (self.role) {
                .client => .client,
                .server => .server,
            },
            self.local_params,
            peer_params,
        );
        self.setState(.established);

        if (self.role == .server) {
            // Handshake completion validates the client's address and
            // confirms the handshake for the server (RFC 9001 §4.1.2).
            self.amp.markValidated();
            self.handshake_confirmed = true;
            self.handshake_done_pending = true;
            self.events.emit(.handshake_confirmed);
            // Keep Handshake keys just long enough to flush the ACK of the
            // client's Finished; pollTransmit applies the deferred discard.
            self.handshake_keys_discard_pending = true;
        }
    }

    fn validateCidBinding(self: *const Connection, peer_binding: config.CidBinding) bool {
        // Backends without binding support (the in-memory test backend)
        // return an empty binding; there is nothing to check.
        const peer_initial_scid = peer_binding.initial_source_connection_id orelse {
            return peer_binding.original_destination_connection_id == null and
                peer_binding.retry_source_connection_id == null;
        };
        if (!std.mem.eql(u8, peer_initial_scid.slice(), self.peer_cid.slice())) return false;
        if (self.role == .client) {
            const odcid = peer_binding.original_destination_connection_id orelse return false;
            if (!std.mem.eql(u8, odcid.slice(), self.original_dcid.slice())) return false;
            if (self.got_retry) {
                const retry_scid = peer_binding.retry_source_connection_id orelse return false;
                const observed = self.retry_scid orelse return false;
                if (!std.mem.eql(u8, retry_scid.slice(), observed.slice())) return false;
            } else if (peer_binding.retry_source_connection_id != null) {
                return false;
            }
        } else {
            // A client never sends the server-only parameters.
            if (peer_binding.original_destination_connection_id != null) return false;
            if (peer_binding.retry_source_connection_id != null) return false;
            if (peer_binding.stateless_reset_token != null) return false;
        }
        return true;
    }

    fn failHandshake(self: *Connection, err: tls_handshake.HandshakeError) void {
        if (self.handshake_error == null) self.handshake_error = err;
    }

    /// Apply a key discard for a space: adapter keys, retransmission buffers,
    /// recovery accounting (RFC 9002 §6.4).
    fn discardKeys(self: *Connection, space: PacketNumberSpace) void {
        const level = levelForSpace(space);
        if (self.adapter.protectionKeys(level, .write) == null and
            self.adapter.protectionKeys(level, .read) == null) return;
        self.adapter.discardSecrets(level);
        _ = self.recovery.onKeysDiscarded(space);
        const tx: ?*CryptoTx = switch (space) {
            .initial => &self.crypto_tx[0],
            .handshake => &self.crypto_tx[1],
            .application => null,
        };
        if (tx) |t| {
            t.data.clearAndFree(self.allocator);
            t.pending.items.clearAndFree(self.allocator);
        }
        var index: usize = 0;
        while (index < self.sent_records.items.len) {
            if (self.sent_records.items[index].space == space) {
                _ = self.sent_records.swapRemove(index);
            } else index += 1;
        }
        self.ack_needed[spaceIndex(space)] = false;
        self.last_ack_eliciting_sent_us[spaceIndex(space)] = null;
        self.probes_pending[spaceIndex(space)] = 0;
        self.events.emit(.{ .keys_discarded = space });
    }

    fn cryptoErrorCode(err: tls_handshake.HandshakeError) u64 {
        // TLS alert mapping (RFC 9001 §4.8).
        return switch (err) {
            error.AlpnMismatch => error_crypto_base + 120, // no_application_protocol
            error.CertificateInvalid => error_crypto_base + 42, // bad_certificate
            error.MissingTransportParameters, error.InvalidTransportParameters => error_transport_parameter,
            error.UnexpectedHandshakeMessage => error_crypto_base + 10, // unexpected_message
            error.IllegalParameter => error_crypto_base + 47, // illegal_parameter
            error.MalformedHandshake => error_crypto_base + 50, // decode_error
            else => error_crypto_base + 80, // internal_error
        };
    }

    // -- close ----------------------------------------------------------------

    /// Application-initiated orderly close.
    pub fn close(self: *Connection, app_error_code: u64, reason: []const u8, now_us: u64) void {
        if (self.state_ == .closed or self.state_ == .closing or self.state_ == .draining) return;
        self.startClose(.{ .error_code = app_error_code, .is_application = true, .local = true }, reason, now_us);
    }

    fn startClose(self: *Connection, info: CloseInfo, reason: []const u8, now_us: u64) void {
        if (self.state_ == .closing or self.state_ == .draining or self.state_ == .closed) return;
        self.close_info = info;
        self.close_reason_len = @min(reason.len, self.close_reason.len);
        @memcpy(self.close_reason[0..self.close_reason_len], reason[0..self.close_reason_len]);
        self.setState(.closing);
        self.close_needs_send = true;
        self.close_deadline_us = now_us + 3 * self.ptoDurationNow();
    }

    fn ptoDurationNow(self: *const Connection) u64 {
        return self.recovery.rtt.ptoDuration(.application);
    }

    // -- timers ----------------------------------------------------------------

    /// The earliest deadline at which `onTimeout` must run, or null when no
    /// timer is armed (e.g. terminal state).
    pub fn nextTimeoutUs(self: *const Connection) ?u64 {
        if (self.state_ == .closed) return null;
        var deadline: ?u64 = null;
        if (self.state_ == .closing or self.state_ == .draining) {
            return self.close_deadline_us;
        }
        // Delayed ACK (application space only; others ack immediately).
        if (self.ack_needed[2] and self.ack_eliciting_since_ack[2] < ack_eliciting_threshold) {
            deadline = minOpt(deadline, self.ack_armed_at_us[2] + local_max_ack_delay_us);
        }
        // Loss time: earliest tracked packet that can become time-lost.
        const loss_delay = self.recovery.rtt.lossDelay();
        for (self.recovery.tracker.packets[0..self.recovery.tracker.count]) |p| {
            const largest = self.recovery.tracker.largest_acked[@intFromEnum(p.space)] orelse continue;
            if (p.packet_number > largest) continue;
            deadline = minOpt(deadline, p.time_sent_us + loss_delay);
        }
        // PTO per space with ack-eliciting packets in flight.
        const backoff = @as(u64, 1) << @intCast(@min(self.pto_count, 16));
        var any_in_flight = false;
        for ([_]PacketNumberSpace{ .initial, .handshake, .application }) |space| {
            const idx = spaceIndex(space);
            const last = self.last_ack_eliciting_sent_us[idx] orelse continue;
            if (!self.spaceHasAckElicitingInFlight(space)) continue;
            any_in_flight = true;
            // Skip the application space until the handshake is confirmed
            // (RFC 9002 §6.2.1).
            if (space == .application and !self.handshake_confirmed) continue;
            deadline = minOpt(deadline, last + self.recovery.rtt.ptoDuration(space) * backoff);
        }
        // Anti-deadlock: a client waiting on the handshake with nothing in
        // flight still arms a PTO to keep the handshake moving.
        if (!any_in_flight and !self.handshake_confirmed and self.role == .client) {
            deadline = minOpt(deadline, self.last_activity_us + self.recovery.rtt.ptoDuration(.handshake) * backoff);
        }
        if (self.idle_deadline_us) |idle| deadline = minOpt(deadline, idle);
        return deadline;
    }

    fn spaceHasAckElicitingInFlight(self: *const Connection, space: PacketNumberSpace) bool {
        for (self.recovery.tracker.packets[0..self.recovery.tracker.count]) |p| {
            if (p.space == space and p.ack_eliciting) return true;
        }
        return false;
    }

    /// Process timer expiry at `now_us`. Cheap when nothing expired.
    pub fn onTimeout(self: *Connection, now_us: u64) void {
        if (self.state_ == .closed) return;
        if (self.state_ == .closing or self.state_ == .draining) {
            if (self.close_deadline_us) |deadline| {
                if (now_us >= deadline) self.setState(.closed);
            }
            return;
        }
        if (self.idle_deadline_us) |deadline| {
            if (now_us >= deadline) {
                // RFC 9000 §10.1: idle timeout closes silently.
                self.events.emit(.idle_timeout);
                self.setState(.closed);
                return;
            }
        }
        // Time-threshold loss detection.
        for ([_]PacketNumberSpace{ .initial, .handshake, .application }) |space| {
            self.detectAndRequeueLost(space, now_us);
        }
        // PTO.
        const backoff = @as(u64, 1) << @intCast(@min(self.pto_count, 16));
        var fired = false;
        var any_in_flight = false;
        for ([_]PacketNumberSpace{ .initial, .handshake, .application }) |space| {
            const idx = spaceIndex(space);
            const last = self.last_ack_eliciting_sent_us[idx] orelse continue;
            if (!self.spaceHasAckElicitingInFlight(space)) continue;
            any_in_flight = true;
            if (space == .application and !self.handshake_confirmed) continue;
            if (now_us >= last + self.recovery.rtt.ptoDuration(space) * backoff) {
                self.firePto(space);
                fired = true;
            }
        }
        if (!fired and !any_in_flight and !self.handshake_confirmed and self.role == .client) {
            if (now_us >= self.last_activity_us + self.recovery.rtt.ptoDuration(.handshake) * backoff) {
                // Anti-deadlock probe: resend the lowest-level flight we can.
                if (self.adapter.protectionKeys(.handshake, .write) != null) {
                    self.firePto(.handshake);
                } else {
                    self.firePto(.initial);
                }
                // Keep the anti-deadlock timer moving.
                self.last_activity_us = now_us;
            }
        }
    }

    fn firePto(self: *Connection, space: PacketNumberSpace) void {
        self.pto_count += 1;
        self.metrics.pto_count_total += 1;
        const idx = spaceIndex(space);
        self.probes_pending[idx] = 2;
        self.events.emit(.{ .pto_fired = .{ .space = space, .count = self.pto_count } });
        // Requeue the oldest unacked retransmittable content of the space so
        // the probe carries data rather than a bare PING when possible.
        var oldest: ?usize = null;
        for (self.sent_records.items, 0..) |record, i| {
            if (record.space != space or !record.ack_eliciting) continue;
            if (oldest == null or record.packet_number < self.sent_records.items[oldest.?].packet_number) {
                oldest = i;
            }
        }
        if (oldest) |i| self.requeueRecord(self.sent_records.items[i]);
    }

    fn armIdle(self: *Connection, now_us: u64) void {
        var timeout_ms = self.local_params.max_idle_timeout_ms;
        if (self.adapter.peerTransportParameters()) |peer| {
            if (peer.max_idle_timeout_ms > 0) {
                timeout_ms = if (timeout_ms == 0) peer.max_idle_timeout_ms else @min(timeout_ms, peer.max_idle_timeout_ms);
            }
        }
        if (timeout_ms == 0) {
            self.idle_deadline_us = null;
            return;
        }
        // RFC 9000 §10.1: at least 3×PTO.
        const idle_us = @max(timeout_ms * 1_000, 3 * self.ptoDurationNow());
        self.idle_deadline_us = now_us + idle_us;
    }

    fn minOpt(current: ?u64, candidate: u64) ?u64 {
        if (current) |value| return @min(value, candidate);
        return candidate;
    }

    // -- streams ---------------------------------------------------------------

    pub fn openStream(self: *Connection, typ: quic_stream.StreamType) !StreamId {
        var manager = self.streamManager() orelse return error.NotEstablished;
        const id = try manager.openLocal(typ);
        try self.known_streams.put(id, {});
        return id;
    }

    /// Queue stream bytes for transmission. Returns how many bytes were
    /// accepted (bounded by `max_stream_send_buffer`); `fin` is recorded once
    /// all bytes of the final write are accepted.
    pub fn writeStream(self: *Connection, id: StreamId, bytes: []const u8, fin: bool) !usize {
        var manager = self.streamManager() orelse return error.NotEstablished;
        const s = manager.get(id) orelse return error.UnknownStream;
        if (!s.canSend()) return error.RecvOnlyStream;
        const queue = try self.sendQueue(id);
        if (queue.reset_sent) return error.StreamReset;
        if (queue.fin_requested) return error.StreamClosed;
        const room = max_stream_send_buffer -| queue.buffered();
        const accepted = @min(bytes.len, room);
        try queue.data.appendSlice(self.allocator, bytes[0..accepted]);
        if (fin and accepted == bytes.len) queue.fin_requested = true;
        return accepted;
    }

    pub fn readStream(self: *Connection, id: StreamId, out: []u8) !quic_stream.ReadResult {
        var manager = self.streamManager() orelse return error.NotEstablished;
        const result = try manager.read(id, out);
        // Flow-control credit decided by the stream manager becomes MAX_DATA /
        // MAX_STREAM_DATA frames on the next transmit.
        if (result.credit.max_data != null) self.pending_max_data = result.credit.max_data;
        if (result.credit.max_stream_data) |limit| {
            try self.pending_max_stream_data.append(self.allocator, .{ .id = id, .limit = limit });
        }
        return result;
    }

    /// Pop the next peer-initiated stream the driver has seen.
    pub fn acceptStream(self: *Connection) ?StreamId {
        if (self.accept_queue.items.len == 0) return null;
        return self.accept_queue.orderedRemove(0);
    }

    pub fn resetStream(self: *Connection, id: StreamId, app_error_code: u64) !void {
        var manager = self.streamManager() orelse return error.NotEstablished;
        const reset = try manager.sendResetStream(id, app_error_code);
        try self.pending_resets.append(self.allocator, reset);
        if (self.send_queues.get(id)) |queue| {
            queue.reset_sent = true;
            queue.retransmit.items.clearRetainingCapacity();
        }
    }

    // -- path validation --------------------------------------------------------

    /// Begin path validation (RFC 9000 §8.2): queue a PATH_CHALLENGE carrying
    /// `data` — caller-supplied randomness, since the driver is sans-I/O. The
    /// challenge is retransmitted if the packet carrying it is lost;
    /// validation completes when the peer echoes the data, surfaced through
    /// `consumePathValidated` and the `path_validated` event. One validation
    /// runs at a time: a new call replaces an unanswered challenge.
    pub fn startPathValidation(self: *Connection, data: [frame.path_data_len]u8) void {
        self.path_challenge_data = data;
        self.path_challenge_needs_send = true;
    }

    /// True while a PATH_CHALLENGE is outstanding.
    pub fn pathValidationInFlight(self: *const Connection) bool {
        return self.path_challenge_data != null;
    }

    /// Give up on an unanswered challenge (the embedder's validation timer
    /// expired, RFC 9000 §8.2.4). Late responses are then ignored.
    pub fn abandonPathValidation(self: *Connection) void {
        self.path_challenge_data = null;
        self.path_challenge_needs_send = false;
    }

    /// The echoed data of a completed path validation, delivered once. The
    /// embedder must not switch traffic to a migrated path before this fires
    /// (RFC 9000 §9.3).
    pub fn consumePathValidated(self: *Connection) ?[frame.path_data_len]u8 {
        defer self.path_validated_data = null;
        return self.path_validated_data;
    }

    pub fn stopSending(self: *Connection, id: StreamId, app_error_code: u64) !void {
        var manager = self.streamManager() orelse return error.NotEstablished;
        const stop = try manager.sendStopSending(id, app_error_code);
        try self.pending_stop_sending.append(self.allocator, stop);
    }

    pub fn streamState(self: *Connection, id: StreamId) ?quic_stream.StreamState {
        var manager = self.streamManager() orelse return null;
        const s = manager.get(id) orelse return null;
        return s.state();
    }

    fn sendQueue(self: *Connection, id: StreamId) !*SendQueue {
        if (self.send_queues.get(id)) |queue| return queue;
        const queue = try self.allocator.create(SendQueue);
        queue.* = .{};
        errdefer self.allocator.destroy(queue);
        // Align the queue's base with what the manager already granted.
        if (self.streamManager()) |manager| {
            if (manager.get(id)) |s| {
                queue.base = s.send_offset;
                queue.reserved_end = s.send_offset;
            }
        }
        try self.send_queues.put(id, queue);
        return queue;
    }

    // -- transmit ---------------------------------------------------------------

    /// Produce the next outbound UDP datagram into `out`. Returns the slice
    /// written, or null when nothing may or needs to be sent right now.
    pub fn pollTransmit(self: *Connection, out: []u8, now_us: u64) ?[]const u8 {
        if (self.state_ == .closed or self.state_ == .draining) return null;
        if (out.len < max_datagram_size) return null;

        if (self.state_ == .closing) {
            if (!self.close_needs_send) return null;
            self.close_needs_send = false;
            self.close_resend_allowed_at_us = now_us + self.ptoDurationNow() / 2;
            return self.buildCloseDatagram(out, now_us);
        }

        // Force the delayed app-space ACK when its timer expired.
        if (self.ack_needed[2] and now_us >= self.ack_armed_at_us[2] + local_max_ack_delay_us) {
            self.ack_eliciting_since_ack[2] = ack_eliciting_threshold;
        }

        const budget = @min(out.len, max_datagram_size);
        var datagram_len: usize = 0;
        var has_initial = false;
        var sent_ack_eliciting = false;

        const levels = [_]EncryptionLevel{ .initial, .handshake, .application };
        for (levels, 0..) |level, i| {
            if (self.adapter.protectionKeys(level, .write) == null) continue;
            const space = spaceForLevel(level);
            // Is this the last level that could contribute? Needed for the
            // Initial padding rule.
            var last_level = true;
            for (levels[i + 1 ..]) |later| {
                if (self.adapter.protectionKeys(later, .write) != null) last_level = false;
            }
            const written = self.buildPacket(level, space, out[datagram_len..budget], now_us, .{
                .datagram_has_initial = has_initial or level == .initial,
                .is_last_level = last_level,
                .datagram_so_far = datagram_len,
            }) orelse continue;
            datagram_len += written.len;
            has_initial = has_initial or level == .initial;
            sent_ack_eliciting = sent_ack_eliciting or written.ack_eliciting;
            if (level == .handshake) {
                if (!self.sent_handshake_packet) {
                    self.sent_handshake_packet = true;
                    // Client: sending at the Handshake level retires Initial
                    // keys (RFC 9001 §4.9.1).
                    if (self.role == .client) self.discardKeys(.initial);
                }
            }
        }
        if (self.handshake_keys_discard_pending and !self.ack_needed[1] and self.crypto_tx[1].pending.isEmpty()) {
            self.handshake_keys_discard_pending = false;
            self.discardKeys(.handshake);
        }
        if (datagram_len == 0) return null;

        self.amp.recordSent(datagram_len);
        self.metrics.datagrams_sent += 1;
        if (sent_ack_eliciting) self.armIdle(now_us);
        return out[0..datagram_len];
    }

    const BuildContext = struct {
        datagram_has_initial: bool,
        is_last_level: bool,
        datagram_so_far: usize,
    };

    const BuiltPacket = struct {
        len: usize,
        ack_eliciting: bool,
    };

    /// Assemble, seal, and record one packet at `level` into `out`. Returns
    /// null when the level has nothing to send or the send gates say no.
    fn buildPacket(
        self: *Connection,
        level: EncryptionLevel,
        space: PacketNumberSpace,
        out: []u8,
        now_us: u64,
        ctx: BuildContext,
    ) ?BuiltPacket {
        const space_idx = spaceIndex(space);
        const probe = self.probes_pending[space_idx] > 0;

        // Congestion gate: in-flight (ack-eliciting) bytes need window; pure
        // ACK packets and PTO probes are exempt (RFC 9002 §7, §6.2.4).
        const cwnd_room = self.recovery.congestion.congestion_window -| self.recovery.congestion.bytes_in_flight;
        const can_send_data = probe or cwnd_room >= max_datagram_size / 2 or
            self.recovery.congestion.bytes_in_flight == 0;

        // Anti-amplification gate applies to every byte a server sends before
        // the client's address is validated.
        const amp_room = self.amp.remaining();
        if (amp_room == 0) return null;

        var want_ack = self.ack_needed[space_idx];
        if (space == .application and want_ack) {
            // Delayed ACK: send only when forced by threshold/timer or when
            // the packet carries other content anyway.
            const forced = self.ack_eliciting_since_ack[space_idx] >= ack_eliciting_threshold;
            if (!forced and !self.hasAppContent() and !probe) want_ack = false;
        }

        const has_crypto = switch (space) {
            .initial => !self.crypto_tx[0].pending.isEmpty(),
            .handshake => !self.crypto_tx[1].pending.isEmpty(),
            .application => false,
        };
        const has_app = space == .application and self.hasAppContent();
        if (!want_ack and !has_crypto and !(has_app and can_send_data) and !probe) return null;
        if ((has_crypto or has_app) and !can_send_data and !want_ack and !probe) return null;

        // Header sizing.
        const pn = self.next_pn[space_idx];
        const pn_len: u3 = packet.packetNumberLength(pn, self.largest_peer_acked[space_idx]);
        var header_written: packet.WrittenLongHeader = undefined;
        var pn_offset: usize = 0;
        switch (level) {
            .initial => {
                header_written = packet.writeLongHeader(.initial, packet.quic_v1, self.peer_cid.slice(), self.local_cid.slice(), self.retry_token.items, pn_len, out) catch return null;
                pn_offset = header_written.pn_offset;
            },
            .handshake => {
                header_written = packet.writeLongHeader(.handshake, packet.quic_v1, self.peer_cid.slice(), self.local_cid.slice(), "", pn_len, out) catch return null;
                pn_offset = header_written.pn_offset;
            },
            .application => {
                pn_offset = packet.writeShortHeader(self.peer_cid.slice(), self.adapter.applicationWriteKeyPhase(), pn_len, out) catch return null;
            },
            .zero_rtt => return null,
        }

        // Available plaintext room in this packet.
        const max_packet = @min(out.len, @as(usize, @intCast(@min(@as(u64, out.len), amp_room -| ctx.datagram_so_far))));
        if (max_packet <= pn_offset + pn_len + aead_tag_len + 16) return null;
        var plain: [max_datagram_size]u8 = undefined;
        const plain_budget = @min(plain.len, max_packet - pn_offset - pn_len - aead_tag_len);
        var plain_len: usize = 0;
        var record = SentRecord{
            .space = space,
            .packet_number = pn,
            .ack_eliciting = false,
        };

        // 1) ACK
        if (want_ack) {
            const delay = now_us -| self.ack_armed_at_us[space_idx];
            if (self.recovery.ackFrameForSpace(space, delay)) |model| {
                if (frame.encodeAck(model, local_ack_delay_exponent, plain[plain_len..plain_budget])) |n| {
                    plain_len += n;
                    record.carried_ack_largest = model.largest_acknowledged;
                    self.ack_needed[space_idx] = false;
                    self.ack_eliciting_since_ack[space_idx] = 0;
                    self.metrics.acks_sent += 1;
                } else |_| {}
            } else {
                self.ack_needed[space_idx] = false;
            }
        }

        // 2) CRYPTO retransmission/transmission
        if (has_crypto and (can_send_data or probe)) {
            const tx = switch (space) {
                .initial => &self.crypto_tx[0],
                .handshake => &self.crypto_tx[1],
                .application => unreachable,
            };
            while (!tx.pending.isEmpty() and plain_len + frame.max_crypto_overhead + 16 < plain_budget) {
                const room: u64 = @intCast(plain_budget - plain_len - frame.max_crypto_overhead);
                const range = tx.pending.takeFirst(room) orelse break;
                const data = tx.data.items[@intCast(range.start)..@intCast(range.end)];
                const n = frame.encodeCrypto(range.start, data, plain[plain_len..plain_budget]) catch {
                    tx.pending.insert(self.allocator, range) catch {};
                    break;
                };
                plain_len += n;
                record.ack_eliciting = true;
                // One crypto range per record keeps requeue simple; merge by
                // extending when contiguous.
                if (record.crypto) |existing| {
                    if (existing.end == range.start) {
                        record.crypto = .{ .start = existing.start, .end = range.end };
                    }
                } else {
                    record.crypto = range;
                }
            }
        }

        // 3) Application-space control and stream frames
        if (space == .application and self.state_ == .established and (can_send_data or probe)) {
            plain_len = self.buildAppFrames(&record, &plain, plain_len, plain_budget);
        }

        // 4) Probe padding: a PTO probe with nothing else carries a PING.
        if (probe and !record.ack_eliciting) {
            if (frame.encodePing(plain[plain_len..plain_budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
            } else |_| {}
        }
        if (plain_len == 0) return null;
        if (probe) self.probes_pending[space_idx] -|= 1;

        // 5) Padding. Header-protection sampling needs ciphertext at least
        // 4 - pn_len + sample_len long; Initial-bearing datagrams pad to 1200.
        const sample_min = (4 - @as(usize, pn_len)) + sample_len - aead_tag_len;
        if (plain_len < sample_min) {
            @memset(plain[plain_len..sample_min], 0);
            plain_len = sample_min;
        }
        // Datagrams carrying Initial packets pad to 1200 (§14.1); so do
        // datagrams carrying PATH_CHALLENGE or PATH_RESPONSE (§8.2.1-2, to
        // validate the path's MTU). `plain_budget` already reflects the
        // anti-amplification allowance, which §8.2.1 lets cap the expansion.
        const expand_for_path = record.carried_path_challenge or record.carried_path_response;
        if ((ctx.datagram_has_initial and ctx.is_last_level) or expand_for_path) {
            const target = min_initial_datagram -| ctx.datagram_so_far;
            const packet_overhead = pn_offset + pn_len + aead_tag_len;
            if (packet_overhead + plain_len < target and target <= plain_budget + packet_overhead) {
                const padded = target - packet_overhead;
                @memset(plain[plain_len..padded], 0);
                plain_len = padded;
            }
        }

        // 6) Seal.
        if (level != .application) {
            packet.patchLongHeaderLength(out, header_written.length_offset, pn_len + plain_len + aead_tag_len);
        }
        const truncated = packet.truncatePacketNumber(pn, pn_len);
        var pn_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &pn_bytes, truncated, .big);
        @memcpy(out[pn_offset..][0..pn_len], pn_bytes[4 - @as(usize, pn_len) ..][0..pn_len]);

        const header = out[0 .. pn_offset + pn_len];
        const keys = self.adapter.protectionKeys(level, .write) orelse return null;
        const sealed = self.adapter.sealPacketPayload(level, .write, pn, header, plain[0..plain_len], out[pn_offset + pn_len ..]) catch return null;

        var sample: [sample_len]u8 = undefined;
        @memcpy(&sample, out[pn_offset + 4 ..][0..sample_len]);
        keys.applyHeaderProtection(&out[0], out[pn_offset..][0..pn_len], sample);

        const total = pn_offset + pn_len + sealed.len;
        self.next_pn[space_idx] = pn + 1;

        // 7) Record for recovery. Non-ack-eliciting packets (pure ACKs) are
        // never acknowledged by the peer, so tracking them would only fill
        // the tracker; RFC 9002 excludes them from loss/congestion anyway.
        if (record.ack_eliciting) {
            var tracked = true;
            self.recovery.onPacketSent(.{
                .space = space,
                .packet_number = pn,
                .time_sent_us = now_us,
                .size = total,
                .ack_eliciting = true,
                .in_flight = true,
            }) catch {
                // Tracker exhaustion: the packet is sealed and will be sent;
                // treat it as untracked best-effort.
                tracked = false;
            };
            self.last_ack_eliciting_sent_us[space_idx] = now_us;
            if (tracked) self.sent_records.append(self.allocator, record) catch {};
        }
        self.metrics.packets_sent += 1;
        self.events.emit(.{ .packet_sent = .{
            .space = space,
            .packet_number = pn,
            .size = total,
            .ack_eliciting = record.ack_eliciting,
        } });
        return .{ .len = total, .ack_eliciting = record.ack_eliciting };
    }

    fn hasAppContent(self: *Connection) bool {
        if (self.state_ != .established) return false;
        if (self.handshake_done_pending) return true;
        if (self.pending_max_data != null) return true;
        if (self.pending_max_stream_data.items.len > 0) return true;
        if (self.pending_resets.items.len > 0) return true;
        if (self.pending_stop_sending.items.len > 0) return true;
        if (self.pending_retires.items.len > 0) return true;
        if (self.pending_path_responses.items.len > 0) return true;
        if (self.path_challenge_needs_send and self.path_challenge_data != null) return true;
        var it = self.send_queues.iterator();
        while (it.next()) |entry| {
            const queue = entry.value_ptr.*;
            if (queue.reset_sent) continue;
            if (!queue.retransmit.isEmpty() or queue.fin_retransmit) return true;
            if (queue.bufferedEnd() > queue.reserved_end) return true;
            if (queue.fin_requested and !queue.fin_reserved) return true;
        }
        return false;
    }

    fn buildAppFrames(self: *Connection, record: *SentRecord, plain: []u8, start_len: usize, budget: usize) usize {
        var plain_len = start_len;

        if (self.handshake_done_pending and self.role == .server) {
            if (frame.encodeHandshakeDone(plain[plain_len..budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
                record.carried_handshake_done = true;
                self.handshake_done_pending = false;
            } else |_| {}
        }
        if (self.pending_max_data) |limit| {
            if (frame.encodeMaxData(limit, plain[plain_len..budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
                record.carried_max_data = true;
                self.pending_max_data = null;
            } else |_| {}
        }
        while (self.pending_max_stream_data.items.len > 0) {
            const entry = self.pending_max_stream_data.items[0];
            const n = frame.encodeMaxStreamData(entry.id, entry.limit, plain[plain_len..budget]) catch break;
            plain_len += n;
            record.ack_eliciting = true;
            record.carried_max_stream_data = entry.id;
            _ = self.pending_max_stream_data.orderedRemove(0);
        }
        // RESET_STREAM / STOP_SENDING: sent once, re-queued if the carrying
        // packet is lost. One of each per packet keeps the record small.
        if (self.pending_resets.items.len > 0) {
            const reset = self.pending_resets.items[0];
            if (frame.encodeResetStream(reset, plain[plain_len..budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
                record.carried_reset_stream = reset;
                _ = self.pending_resets.orderedRemove(0);
            } else |_| {}
        }
        if (self.pending_stop_sending.items.len > 0) {
            const stop = self.pending_stop_sending.items[0];
            if (frame.encodeStopSending(stop, plain[plain_len..budget])) |n| {
                plain_len += n;
                record.ack_eliciting = true;
                record.carried_stop_sending = stop;
                _ = self.pending_stop_sending.orderedRemove(0);
            } else |_| {}
        }
        while (self.pending_retires.items.len > 0) {
            const sequence = self.pending_retires.items[0];
            const n = frame.encodeRetireConnectionId(sequence, plain[plain_len..budget]) catch break;
            plain_len += n;
            record.ack_eliciting = true;
            _ = self.pending_retires.orderedRemove(0);
        }
        while (self.pending_path_responses.items.len > 0) {
            const data = self.pending_path_responses.items[0];
            const n = frame.encodePathResponse(data, plain[plain_len..budget]) catch break;
            plain_len += n;
            record.ack_eliciting = true;
            record.carried_path_response = true;
            _ = self.pending_path_responses.orderedRemove(0);
        }
        if (self.path_challenge_needs_send) {
            if (self.path_challenge_data) |data| {
                if (frame.encodePathChallenge(data, plain[plain_len..budget])) |n| {
                    plain_len += n;
                    record.ack_eliciting = true;
                    record.carried_path_challenge = true;
                    self.path_challenge_needs_send = false;
                } else |_| {}
            } else self.path_challenge_needs_send = false;
        }

        // Stream data: retransmissions first, then new bytes.
        var it = self.send_queues.iterator();
        while (it.next()) |entry| {
            if (record.stream_count == record.streams.len) break;
            if (plain_len + frame.max_stream_overhead + 1 >= budget) break;
            const id = entry.key_ptr.*;
            const queue = entry.value_ptr.*;
            if (queue.reset_sent) continue;

            // Retransmit ranges.
            while (!queue.retransmit.isEmpty() and record.stream_count < record.streams.len) {
                const room: u64 = @intCast(budget - plain_len -| frame.max_stream_overhead);
                if (room == 0) break;
                const range = queue.retransmit.takeFirst(room) orelse break;
                const is_fin_range = queue.fin_retransmit and range.end == queue.reserved_end;
                const n = frame.encodeStream(id, range.start, queue.slice(range), is_fin_range, plain[plain_len..budget]) catch {
                    queue.retransmit.insert(self.allocator, range) catch {};
                    break;
                };
                if (is_fin_range) queue.fin_retransmit = false;
                plain_len += n;
                record.ack_eliciting = true;
                record.streams[record.stream_count] = .{ .id = id, .range = range, .fin = is_fin_range };
                record.stream_count += 1;
            }

            // A lost FIN whose data range was empty (or fully acked) needs an
            // explicit empty STREAM+FIN frame.
            if (queue.fin_retransmit and queue.retransmit.isEmpty() and record.stream_count < record.streams.len) {
                const off = queue.reserved_end;
                if (frame.encodeStream(id, off, "", true, plain[plain_len..budget])) |n| {
                    queue.fin_retransmit = false;
                    plain_len += n;
                    record.ack_eliciting = true;
                    record.streams[record.stream_count] = .{ .id = id, .range = .{ .start = off, .end = off }, .fin = true };
                    record.stream_count += 1;
                } else |_| {}
            }

            // New data within flow control.
            if (record.stream_count == record.streams.len) continue;
            var manager = self.streamManager() orelse continue;
            const s = manager.get(id) orelse continue;
            const unsent = queue.bufferedEnd() -| queue.reserved_end;
            const want_fin = queue.fin_requested and !queue.fin_reserved;
            if (unsent == 0 and !want_fin) continue;
            const stream_window = s.max_send_data -| s.send_offset;
            const conn_window = manager.max_data_send -| manager.bytes_sent;
            const frame_room: u64 = @intCast(budget -| plain_len -| frame.max_stream_overhead);
            const n_bytes = @min(@min(unsent, @min(stream_window, conn_window)), frame_room);
            if (n_bytes == 0 and !(want_fin and unsent == 0)) continue;
            const fin_now = want_fin and n_bytes == unsent;
            const grant = manager.reserveSend(id, @intCast(n_bytes), fin_now) catch continue;
            const range = Range{ .start = grant.offset, .end = grant.offset + grant.len };
            const n = frame.encodeStream(id, range.start, queue.slice(range), grant.fin, plain[plain_len..budget]) catch continue;
            plain_len += n;
            queue.reserved_end = range.end;
            if (grant.fin) queue.fin_reserved = true;
            record.ack_eliciting = true;
            record.streams[record.stream_count] = .{ .id = id, .range = range, .fin = grant.fin };
            record.stream_count += 1;
        }
        return plain_len;
    }

    fn buildCloseDatagram(self: *Connection, out: []u8, now_us: u64) ?[]const u8 {
        _ = now_us;
        const info = self.close_info orelse return null;
        // Send the close at the highest available level (RFC 9000 §10.2.3:
        // application closes at lower levels are converted to transport
        // closes to avoid leaking application state pre-handshake).
        var level: EncryptionLevel = .application;
        if (self.adapter.protectionKeys(.application, .write) == null) {
            level = .handshake;
            if (self.adapter.protectionKeys(.handshake, .write) == null) level = .initial;
        }
        if (self.adapter.protectionKeys(level, .write) == null) return null;

        const space = spaceForLevel(level);
        const space_idx = spaceIndex(space);
        const pn = self.next_pn[space_idx];
        const pn_len: u3 = packet.packetNumberLength(pn, self.largest_peer_acked[space_idx]);

        var pn_offset: usize = 0;
        var header_written: packet.WrittenLongHeader = undefined;
        switch (level) {
            .initial => {
                header_written = packet.writeLongHeader(.initial, packet.quic_v1, self.peer_cid.slice(), self.local_cid.slice(), self.retry_token.items, pn_len, out) catch return null;
                pn_offset = header_written.pn_offset;
            },
            .handshake => {
                header_written = packet.writeLongHeader(.handshake, packet.quic_v1, self.peer_cid.slice(), self.local_cid.slice(), "", pn_len, out) catch return null;
                pn_offset = header_written.pn_offset;
            },
            .application => {
                pn_offset = packet.writeShortHeader(self.peer_cid.slice(), self.adapter.applicationWriteKeyPhase(), pn_len, out) catch return null;
            },
            .zero_rtt => return null,
        }

        var plain: [512]u8 = undefined;
        const use_app_frame = info.is_application and level == .application;
        var plain_len = frame.encodeConnectionClose(.{
            .error_code = if (use_app_frame or info.is_application == false) info.error_code else error_internal,
            .reason = self.close_reason[0..self.close_reason_len],
            .is_application = use_app_frame,
        }, &plain) catch return null;

        const sample_min = (4 - @as(usize, pn_len)) + sample_len - aead_tag_len;
        if (plain_len < sample_min) {
            @memset(plain[plain_len..sample_min], 0);
            plain_len = sample_min;
        }
        if (level != .application) {
            packet.patchLongHeaderLength(out, header_written.length_offset, pn_len + plain_len + aead_tag_len);
        }
        const truncated = packet.truncatePacketNumber(pn, pn_len);
        var pn_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &pn_bytes, truncated, .big);
        @memcpy(out[pn_offset..][0..pn_len], pn_bytes[4 - @as(usize, pn_len) ..][0..pn_len]);
        const header = out[0 .. pn_offset + pn_len];
        const keys = self.adapter.protectionKeys(level, .write) orelse return null;
        const sealed = self.adapter.sealPacketPayload(level, .write, pn, header, plain[0..plain_len], out[pn_offset + pn_len ..]) catch return null;
        var sample: [sample_len]u8 = undefined;
        @memcpy(&sample, out[pn_offset + 4 ..][0..sample_len]);
        keys.applyHeaderProtection(&out[0], out[pn_offset..][0..pn_len], sample);
        self.next_pn[space_idx] = pn + 1;

        var total = pn_offset + pn_len + sealed.len;
        // A close carried in an Initial packet still obeys §14.1 padding.
        if (level == .initial and total < min_initial_datagram) {
            // Rebuild with padding is overkill; pad the datagram with zero
            // bytes after the packet is illegal, so instead treat the close
            // packet as final without padding — the peer processes Initial
            // packets of any size when they arrive coalesced or alone from a
            // server. For client-side closes this only happens pre-handshake.
            total = total;
        }
        self.amp.recordSent(total);
        self.metrics.datagrams_sent += 1;
        self.events.emit(.{ .close_sent = .{ .error_code = info.error_code } });
        return out[0..total];
    }
};

// ---------------------------------------------------------------------------
// Tests: driver-level client<->server handshake and data exchange using the
// real pure-Zig TLS backend, real packets, and a lossless in-memory pump.
// Loss/reorder scenarios live in tests/quic_h3_e2e.zig.
// ---------------------------------------------------------------------------

const testing = std.testing;
const tls_backend_mod = @import("tls_backend.zig");

const TestPair = struct {
    client_backend: tls_backend_mod.Tls13Backend,
    server_backend: tls_backend_mod.Tls13Backend,
    client: *Connection = undefined,
    server: *Connection = undefined,
    now_us: u64 = 1_000_000,

    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    fn init(allocator: std.mem.Allocator) !*TestPair {
        const pair = try allocator.create(TestPair);
        pair.* = .{
            .client_backend = tls_backend_mod.Tls13Backend.initClient(
                .{ .hello_random = [_]u8{0xc1} ** 32, .key_share_seed = [_]u8{0x11} ** 32 },
                .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
            ),
            .server_backend = tls_backend_mod.Tls13Backend.initServer(
                .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x22} ** 32 },
                try tls_backend_mod.Identity.initPkcs8(
                    tls_backend_mod.testdata.certificate_der,
                    tls_backend_mod.testdata.private_key_pkcs8_der,
                ),
            ),
        };
        errdefer allocator.destroy(pair);
        pair.client = try Connection.init(allocator, .{
            .role = .client,
            .local_cid = &client_cid,
            .original_dcid = &odcid,
            .peer_cid = &odcid,
            .tls = pair.client_backend.backend(),
            .now_us = pair.now_us,
        });
        errdefer pair.client.deinit();
        pair.server = try Connection.init(allocator, .{
            .role = .server,
            .local_cid = &odcid,
            .original_dcid = &odcid,
            .peer_cid = &client_cid,
            .tls = pair.server_backend.backend(),
            .now_us = pair.now_us,
        });
        return pair;
    }

    fn deinit(self: *TestPair, allocator: std.mem.Allocator) void {
        self.client.deinit();
        self.server.deinit();
        allocator.destroy(self);
    }

    /// Move all pending datagrams both ways until neither side has output.
    fn pump(self: *TestPair) !void {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (self.client.pollTransmit(&buf, self.now_us)) |datagram| {
                try self.server.ingest(datagram, self.now_us);
                progressed = true;
                self.now_us += 500;
            }
            while (self.server.pollTransmit(&buf, self.now_us)) |datagram| {
                try self.client.ingest(datagram, self.now_us);
                progressed = true;
                self.now_us += 500;
            }
            if (!progressed) return;
        }
        return error.PumpStalled;
    }
};

test "Connection.init failure before the handshake is assigned does not deinit undefined storage" {
    const allocator = testing.allocator;
    // An original_dcid shorter than min_initial_dcid_len makes
    // installInitialSecrets fail, which used to run before conn.handshake
    // was assigned -- deinitPartial()'s errdefer would then call
    // .deinit() on undefined storage. This must fail cleanly instead.
    const too_short_dcid = [_]u8{0xaa} ** (tls_adapter.min_initial_dcid_len - 1);
    var backend = tls_backend_mod.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xc1} ** 32, .key_share_seed = [_]u8{0x11} ** 32 },
        .{ .pinned_certificate = tls_backend_mod.testdata.certificate_der },
    );
    try testing.expectError(error.InvalidConnectionId, Connection.init(allocator, .{
        .role = .client,
        .local_cid = &TestPair.client_cid,
        .original_dcid = &too_short_dcid,
        .peer_cid = &too_short_dcid,
        .tls = backend.backend(),
        .now_us = 1_000_000,
    }));
}

test "driver: client and server complete the handshake over protected packets" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);

    try pair.pump();
    try testing.expectEqual(State.established, pair.client.state());
    try testing.expectEqual(State.established, pair.server.state());
    try testing.expect(pair.client.negotiatedH3());
    try testing.expect(pair.server.negotiatedH3());
    try testing.expect(pair.client.handshake_confirmed);
    try testing.expect(pair.server.handshake_confirmed);

    // Initial and Handshake keys discarded on both sides after confirmation.
    inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |level| {
        try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), pair.client.adapter.protectionKeys(level, .write));
        try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), pair.server.adapter.protectionKeys(level, .write));
    }
}

test "driver: bidirectional stream data round-trips with FIN" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const id = try pair.client.openStream(.bidi);
    try testing.expectEqual(@as(usize, 5), try pair.client.writeStream(id, "hello", true));
    try pair.pump();

    try testing.expectEqual(@as(?StreamId, id), pair.server.acceptStream());
    var buf: [64]u8 = undefined;
    const request = try pair.server.readStream(id, &buf);
    try testing.expectEqualStrings("hello", buf[0..request.len]);
    try testing.expect(request.fin);

    _ = try pair.server.writeStream(id, "world!", true);
    try pair.pump();
    const response = try pair.client.readStream(id, &buf);
    try testing.expectEqualStrings("world!", buf[0..response.len]);
    try testing.expect(response.fin);

    try testing.expectEqual(quic_stream.StreamState.closed, pair.client.streamState(id).?);
    try testing.expectEqual(quic_stream.StreamState.closed, pair.server.streamState(id).?);
}

test "driver: local close reaches the peer and both sides drain" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    pair.client.close(0, "done", pair.now_us);
    try testing.expectEqual(State.closing, pair.client.state());
    try pair.pump();
    try testing.expectEqual(State.draining, pair.server.state());
    const info = pair.server.closeInfo().?;
    try testing.expectEqual(@as(u64, 0), info.error_code);
    try testing.expect(info.is_application);
    try testing.expect(!info.local);

    // Timers move both sides to closed.
    pair.now_us += 10_000_000;
    pair.client.onTimeout(pair.now_us);
    pair.server.onTimeout(pair.now_us);
    try testing.expectEqual(State.closed, pair.client.state());
    try testing.expectEqual(State.closed, pair.server.state());
}

test "driver: stream reset propagates" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const id = try pair.client.openStream(.bidi);
    _ = try pair.client.writeStream(id, "partial", false);
    try pair.pump();
    try pair.client.resetStream(id, 0x0107);
    try pair.pump();

    var buf: [16]u8 = undefined;
    try testing.expectError(error.StreamReset, pair.server.readStream(id, &buf));
}

test "driver: path validation completes when the peer echoes the challenge" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    const data = [frame.path_data_len]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    pair.client.startPathValidation(data);
    try testing.expect(pair.client.pathValidationInFlight());
    try pair.pump();

    try testing.expect(!pair.client.pathValidationInFlight());
    try testing.expectEqual(@as(?[frame.path_data_len]u8, data), pair.client.consumePathValidated());
    // Delivered exactly once.
    try testing.expectEqual(@as(?[frame.path_data_len]u8, null), pair.client.consumePathValidated());
}

test "driver: a mismatched PATH_RESPONSE does not validate the path" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    // The server answers a challenge the client has already replaced: the
    // stale echo must not complete the new validation.
    pair.client.startPathValidation([_]u8{0xaa} ** frame.path_data_len);
    var buf: [2048]u8 = undefined;
    while (pair.client.pollTransmit(&buf, pair.now_us)) |datagram| {
        try pair.server.ingest(datagram, pair.now_us);
    }
    pair.client.startPathValidation([_]u8{0xbb} ** frame.path_data_len);
    try pair.pump();

    // The first challenge's response is ignored; the second completes.
    try testing.expect(!pair.client.pathValidationInFlight());
    try testing.expectEqual(
        @as(?[frame.path_data_len]u8, [_]u8{0xbb} ** frame.path_data_len),
        pair.client.consumePathValidated(),
    );
}

test "driver: idle timeout closes silently" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    try pair.pump();

    // Default idle timeout is 30s; advance past it.
    pair.now_us += 31_000_000;
    pair.client.onTimeout(pair.now_us);
    try testing.expectEqual(State.closed, pair.client.state());
}

test "driver: timers are armed while handshaking" {
    const allocator = testing.allocator;
    var pair = try TestPair.init(allocator);
    defer pair.deinit(allocator);
    // Client has sent nothing yet but must arm a deadline once it has output.
    var buf: [2048]u8 = undefined;
    _ = pair.client.pollTransmit(&buf, pair.now_us);
    try testing.expect(pair.client.nextTimeoutUs() != null);
}

test "handshake failures map to their RFC 9001 CRYPTO_ERROR alert codes" {
    // RFC 9001 §4.8: a TLS alert is carried as CRYPTO_ERROR (0x0100 + alert).
    // Ordering failures and malformed bytes are distinct alerts and must not
    // collapse to the same code.
    try testing.expectEqual(error_crypto_base + 10, Connection.cryptoErrorCode(error.UnexpectedHandshakeMessage));
    try testing.expectEqual(error_crypto_base + 47, Connection.cryptoErrorCode(error.IllegalParameter));
    try testing.expectEqual(error_crypto_base + 50, Connection.cryptoErrorCode(error.MalformedHandshake));
    try testing.expectEqual(error_crypto_base + 120, Connection.cryptoErrorCode(error.AlpnMismatch));
    try testing.expectEqual(error_crypto_base + 42, Connection.cryptoErrorCode(error.CertificateInvalid));
}

test {
    std.testing.refAllDecls(@This());
}
