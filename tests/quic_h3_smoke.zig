//! Local pure-Zig QUIC/TLS/H3 connection-driver smoke harness (#314, under the
//! #247 validation umbrella).
//!
//! Stitches the pure-Zig pieces from the #240 epic into one deterministic
//! in-process client<->server request/response path: the TLS 1.3 backend
//! (#296) driven through the handshake driver and `QuicTlsAdapter` (#249),
//! real QUIC v1 packets with AEAD packet protection and header protection,
//! CRYPTO/STREAM frames, packet-number encoding (#243), stream and
//! flow-control state (#245), and the HTTP/3 frame/session/QPACK layer
//! (#246/#252) — over an in-memory datagram pump instead of UDP sockets.
//!
//! Deliberately narrow (one client, one server, one request stream, one
//! response) and deliberately real at the QUIC boundaries: bytes cross between
//! the endpoints only as protected QUIC packets in whole datagrams. Not a
//! production connection driver: no ACK/loss recovery beyond the migration
//! reset hook (the pump is lossless and in order), no idle timers, no key
//! updates, no coalesced packets. Those integrate in follow-up #247 work; this
//! harness exists so that work starts from a stitched, passing path.
//!
//! The harness fails with stage-specific errors (`error.HandshakeStalled`,
//! `error.KeysUnavailableForLevel`, `error.UnexpectedFrameType`, ...) so a
//! regression points at handshake, packet protection, stream delivery, or
//! HTTP/3 parsing rather than a generic mismatch.

const std = @import("std");
const quic = @import("quic");
const http3 = @import("http3");
const stream_transport = @import("stream_transport");

const tls_adapter = quic.tls_adapter;
const tls_handshake = quic.tls_handshake;
const tls_backend = quic.tls_backend;
const quic_stream = quic.stream;
const quic_packet = quic.packet;
const varint = quic.varint;
const config = quic.config;
const quic_cid = quic.cid;
const quic_path = quic.path;
const quic_recovery = quic.recovery;
const quic_udp = quic.udp;

const EncryptionLevel = tls_adapter.EncryptionLevel;
const QuicTlsAdapter = tls_adapter.QuicTlsAdapter;

const testing = std.testing;

/// Connection ID length used by both endpoints. Short-header packets carry the
/// destination CID without a length, so the harness fixes one length up front.
const cid_len = 8;
/// QUIC v1 (RFC 9000).
const quic_v1: u32 = 0x00000001;
const max_datagram = 1500;
/// RFC 9000 §14.1: a client Initial datagram must be at least 1200 bytes.
const min_client_initial_datagram = 1200;

const aead_tag_len = tls_adapter.packet_protection_tag_len;
const sample_len = tls_adapter.header_protection_sample_len;

// ---------------------------------------------------------------------------
// Minimal QUIC v1 frame codec: PADDING, PING, CRYPTO, STREAM,
// PATH_CHALLENGE, and PATH_RESPONSE. Everything the smoke path does not send
// is a deterministic error on receive.
// ---------------------------------------------------------------------------

const frame_padding: u64 = 0x00;
const frame_ping: u64 = 0x01;
const frame_crypto: u64 = 0x06;
const frame_stream_base: u64 = 0x08; // 0x08..0x0f: OFF=0x04, LEN=0x02, FIN=0x01
const frame_path_challenge: u64 = 0x1a;
const frame_path_response: u64 = 0x1b;

const HarnessError = error{
    HandshakeStalled,
    KeysUnavailableForLevel,
    UnexpectedPacketType,
    UnexpectedQuicVersion,
    UnexpectedConnectionId,
    UnexpectedToken,
    UnexpectedFrameType,
    TruncatedFrame,
    TruncatedPacket,
    StreamsNotReady,
    BufferTooShort,
    PumpOverflow,
};

const PathFrame = union(enum) {
    challenge: [quic_path.path_challenge_len]u8,
    response: [quic_path.path_challenge_len]u8,
};

/// Deterministic bounds check for fixed packet-header fields: reading past the
/// datagram is a `TruncatedPacket` error, never an out-of-bounds panic.
fn requireAvailable(total: usize, pos: usize, need: usize) HarnessError!void {
    if (pos > total or need > total - pos) return error.TruncatedPacket;
}

fn encodeCryptoFrame(offset: u64, data: []const u8, out: []u8) ![]const u8 {
    var pos: usize = 0;
    pos += try varint.encode(frame_crypto, out[pos..]);
    pos += try varint.encode(offset, out[pos..]);
    pos += try varint.encode(data.len, out[pos..]);
    if (out.len - pos < data.len) return error.BufferTooShort;
    @memcpy(out[pos..][0..data.len], data);
    return out[0 .. pos + data.len];
}

/// STREAM frame with explicit offset and length (type 0x0e / 0x0f with FIN),
/// carrying exactly the bytes granted by `StreamManager.reserveSend`.
fn encodeStreamFrame(grant: quic_stream.SendGrant, data: []const u8, out: []u8) ![]const u8 {
    std.debug.assert(grant.len == data.len);
    var pos: usize = 0;
    const type_value = frame_stream_base | 0x04 | 0x02 | @as(u64, @intFromBool(grant.fin));
    pos += try varint.encode(type_value, out[pos..]);
    pos += try varint.encode(grant.id, out[pos..]);
    pos += try varint.encode(grant.offset, out[pos..]);
    pos += try varint.encode(data.len, out[pos..]);
    if (out.len - pos < data.len) return error.BufferTooShort;
    @memcpy(out[pos..][0..data.len], data);
    return out[0 .. pos + data.len];
}

fn encodePathFrame(frame: PathFrame, out: []u8) ![]const u8 {
    var pos: usize = 0;
    switch (frame) {
        .challenge => |data| {
            pos += try varint.encode(frame_path_challenge, out[pos..]);
            if (out.len - pos < data.len) return error.BufferTooShort;
            @memcpy(out[pos..][0..data.len], &data);
            pos += data.len;
        },
        .response => |data| {
            pos += try varint.encode(frame_path_response, out[pos..]);
            if (out.len - pos < data.len) return error.BufferTooShort;
            @memcpy(out[pos..][0..data.len], &data);
            pos += data.len;
        },
    }
    return out[0..pos];
}

fn extractDcid(datagram: []const u8) HarnessError![]const u8 {
    if (datagram.len == 0) return error.TruncatedPacket;
    var pos: usize = 0;
    if (datagram[0] & 0x80 != 0) {
        pos = 1;
        try requireAvailable(datagram.len, pos, 4);
        if (std.mem.readInt(u32, datagram[pos..][0..4], .big) != quic_v1) return error.UnexpectedQuicVersion;
        pos += 4;
        try requireAvailable(datagram.len, pos, 1);
        const len = datagram[pos];
        pos += 1;
        try requireAvailable(datagram.len, pos, len);
        return datagram[pos..][0..len];
    }
    pos = 1;
    try requireAvailable(datagram.len, pos, cid_len);
    return datagram[pos..][0..cid_len];
}

fn challengeForPath(key: quic_path.PathKey) [quic_path.path_challenge_len]u8 {
    var challenge: [quic_path.path_challenge_len]u8 = undefined;
    @memcpy(challenge[0..4], key.remote.slice()[0..4]);
    std.mem.writeInt(u16, challenge[4..6], key.remote.port, .big);
    std.mem.writeInt(u16, challenge[6..8], key.local.port, .big);
    return challenge;
}

// ---------------------------------------------------------------------------
// Deterministic in-memory datagram pump: whole datagrams, lossless, in order.
// ---------------------------------------------------------------------------

const DatagramQueue = struct {
    /// Largest burst either side produces in one round is three datagrams
    /// (ServerHello + handshake flight + 1-RTT); sixteen leaves headroom while
    /// keeping overflow a deterministic error instead of unbounded growth.
    const queue_capacity = 16;

    buffers: [queue_capacity][max_datagram]u8 = undefined,
    lengths: [queue_capacity]usize = [_]usize{0} ** queue_capacity,
    locals: [queue_capacity]quic_udp.Address = undefined,
    remotes: [queue_capacity]quic_udp.Address = undefined,
    received_at_us: [queue_capacity]u64 = [_]u64{0} ** queue_capacity,
    count: usize = 0,

    fn push(
        self: *DatagramQueue,
        datagram: []const u8,
        local: quic_udp.Address,
        remote: quic_udp.Address,
        received_at_us: u64,
    ) HarnessError!void {
        if (self.count == queue_capacity) return error.PumpOverflow;
        if (datagram.len > max_datagram) return error.BufferTooShort;
        @memcpy(self.buffers[self.count][0..datagram.len], datagram);
        self.lengths[self.count] = datagram.len;
        self.locals[self.count] = local;
        self.remotes[self.count] = remote;
        self.received_at_us[self.count] = received_at_us;
        self.count += 1;
    }

    /// Deliver every queued datagram to `endpoint` in order. Returns the
    /// number delivered (zero means the peer made no progress this round).
    fn deliverAll(self: *DatagramQueue, endpoint: *Endpoint, outbound: *DatagramQueue) !usize {
        const delivered = self.count;
        for (
            self.buffers[0..delivered],
            self.lengths[0..delivered],
            self.locals[0..delivered],
            self.remotes[0..delivered],
            self.received_at_us[0..delivered],
        ) |*buffer, length, local, remote, received_at_us| {
            try endpoint.onReceivedDatagram(.{
                .bytes = buffer[0..length],
                .local = local,
                .remote = remote,
                .received_at_us = received_at_us,
            }, outbound);
        }
        self.count = 0;
        return delivered;
    }
};

// ---------------------------------------------------------------------------
// Endpoint: one side's transport state — TLS handshake driver + adapter,
// per-space packet numbers, stream manager — plus packetization helpers.
// ---------------------------------------------------------------------------

const Endpoint = struct {
    const connection_handle: u64 = 1;

    allocator: std.mem.Allocator,
    role: tls_adapter.Perspective,
    adapter: QuicTlsAdapter = .{},
    backend: tls_backend.Tls13Backend,
    handshake: tls_handshake.Handshake = undefined,
    cid_routes: quic_cid.CidRoutingTable,
    paths: quic_path.PathManager,
    recovery: *quic_recovery.RecoveryController,
    /// Created only once the peer's transport parameters are authenticated.
    streams: ?quic_stream.StreamManager = null,
    local_params: config.TransportParameters,
    local_cid: [cid_len]u8,
    peer_cid: [cid_len]u8,
    local_addr: quic_udp.Address,
    peer_addr: quic_udp.Address,
    /// Next packet number to send / largest received, per packet-number space.
    next_pn: [3]u64 = .{ 0, 0, 0 },
    largest_recv_pn: [3]?u64 = .{ null, null, null },

    inline fn spaceIndex(level: EncryptionLevel) usize {
        return @intFromEnum(level.packetNumberSpace());
    }

    fn deinit(self: *Endpoint) void {
        if (self.streams) |*manager| manager.deinit();
        self.allocator.destroy(self.recovery);
        self.cid_routes.deinit();
    }

    fn registerLocalCid(self: *Endpoint) !void {
        try self.cid_routes.insert(try quic_cid.ConnectionId.init(&self.local_cid), connection_handle);
    }

    fn retireLocalCid(self: *Endpoint) void {
        self.cid_routes.remove(quic_cid.ConnectionId.init(&self.local_cid) catch unreachable);
    }

    /// Attach stream/flow-control state from the authenticated peer transport
    /// parameters. Fails when called before the handshake authenticated them.
    fn attachStreams(self: *Endpoint) !void {
        const peer_params = self.adapter.peerTransportParameters() orelse return error.StreamsNotReady;
        self.streams = quic_stream.StreamManager.init(
            self.allocator,
            switch (self.role) {
                .client => .client,
                .server => .server,
            },
            self.local_params,
            peer_params,
        );
    }

    /// Build one protected packet carrying `frames` at `level` and queue the
    /// datagram (one packet per datagram). `pad_datagram_to` grows the
    /// plaintext with PADDING so the datagram reaches the target size (the
    /// RFC 9000 §14.1 client Initial minimum); zero pads only to the header
    /// protection sample minimum.
    fn sendPacket(self: *Endpoint, level: EncryptionLevel, frames: []const u8, pad_datagram_to: usize, queue: *DatagramQueue) !void {
        try self.sendPacketOnPath(level, frames, pad_datagram_to, self.local_addr, self.peer_addr, queue);
    }

    fn sendPacketOnPath(
        self: *Endpoint,
        level: EncryptionLevel,
        frames: []const u8,
        pad_datagram_to: usize,
        local_addr: quic_udp.Address,
        remote_addr: quic_udp.Address,
        queue: *DatagramQueue,
    ) !void {
        const keys = self.adapter.protectionKeys(level, .write) orelse return error.KeysUnavailableForLevel;
        const space = spaceIndex(level);
        const pn = self.next_pn[space];
        self.next_pn[space] += 1;
        // No ACKs cross the lossless pump, so the peer reconstructs from its
        // own largest-received; packet numbers stay tiny either way.
        const pn_len: usize = quic_packet.packetNumberLength(pn, null);

        var pkt: [max_datagram]u8 = undefined;
        var pos: usize = 0;
        var length_at: usize = 0;
        switch (level) {
            .initial, .handshake => {
                const long_type: u8 = if (level == .initial) 0b00 else 0b10;
                pkt[0] = 0x80 | 0x40 | (long_type << 4) | @as(u8, @intCast(pn_len - 1));
                pos = 1;
                std.mem.writeInt(u32, pkt[pos..][0..4], quic_v1, .big);
                pos += 4;
                pkt[pos] = cid_len;
                pos += 1;
                @memcpy(pkt[pos..][0..cid_len], &self.peer_cid);
                pos += cid_len;
                pkt[pos] = cid_len;
                pos += 1;
                @memcpy(pkt[pos..][0..cid_len], &self.local_cid);
                pos += cid_len;
                if (level == .initial) {
                    pkt[pos] = 0; // token length (no Retry on the local path)
                    pos += 1;
                }
                length_at = pos;
                pos += 2; // Length as a 2-byte varint, patched below
            },
            .application => {
                pkt[0] = 0x40 | (@as(u8, self.adapter.applicationWriteKeyPhase()) << 2) | @as(u8, @intCast(pn_len - 1));
                pos = 1;
                @memcpy(pkt[pos..][0..cid_len], &self.peer_cid);
                pos += cid_len;
            },
            .zero_rtt => unreachable, // 0-RTT is out of scope for the smoke path
        }

        const pn_offset = pos;
        const truncated = quic_packet.truncatePacketNumber(pn, @intCast(pn_len));
        var pn_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &pn_bytes, truncated, .big);
        @memcpy(pkt[pos..][0..pn_len], pn_bytes[4 - pn_len ..][0..pn_len]);
        pos += pn_len;

        // Plaintext: frames plus PADDING. Header protection samples ciphertext
        // starting 4 bytes past the packet-number offset (RFC 9001 §5.4.2), so
        // the ciphertext must reach 4 - pn_len + sample_len bytes.
        var plain: [max_datagram]u8 = undefined;
        @memcpy(plain[0..frames.len], frames);
        var plain_len = frames.len;
        const sample_min = (4 - pn_len) + sample_len - aead_tag_len;
        if (plain_len < sample_min) plain_len = sample_min;
        if (pad_datagram_to > pos + plain_len + aead_tag_len) {
            plain_len = pad_datagram_to - pos - aead_tag_len;
        }
        @memset(plain[frames.len..plain_len], 0); // PADDING frames

        if (length_at != 0) {
            const length_value: u16 = @intCast(pn_len + plain_len + aead_tag_len);
            std.mem.writeInt(u16, pkt[length_at..][0..2], length_value | 0x4000, .big);
        }

        const header = pkt[0..pos];
        const sealed = try self.adapter.sealPacketPayload(level, .write, pn, header, plain[0..plain_len], pkt[pos..]);

        var sample: [sample_len]u8 = undefined;
        @memcpy(&sample, pkt[pn_offset + 4 ..][0..sample_len]);
        keys.applyHeaderProtection(&pkt[0], pkt[pn_offset..][0..pn_len], sample);

        try queue.push(pkt[0 .. pos + sealed.len], remote_addr, local_addr, 0);
    }

    /// Parse and deprotect one datagram (one packet), then process its frames.
    fn onDatagram(self: *Endpoint, datagram: []const u8) !void {
        var queue = DatagramQueue{};
        try self.onReceivedDatagram(.{
            .bytes = datagram,
            .local = self.local_addr,
            .remote = self.peer_addr,
            .received_at_us = 0,
        }, &queue);
    }

    /// Route by DCID, drive path decisions from the UDP tuple, parse and
    /// deprotect one datagram (one packet), then process its frames.
    fn onReceivedDatagram(self: *Endpoint, received: quic_udp.ReceivedDatagram, outbound: *DatagramQueue) !void {
        const dcid = try extractDcid(received.bytes);
        if (self.cid_routes.lookup(dcid) != connection_handle) return error.UnexpectedConnectionId;

        const path_key = quic_path.PathKey{
            .local = received.local orelse self.local_addr,
            .remote = received.remote,
        };
        switch (self.paths.onDatagram(path_key, challengeForPath(path_key), received.received_at_us)) {
            .on_active_path, .probing => {},
            .blocked => {},
            .probe => |challenge| {
                var frame_buf: [16]u8 = undefined;
                const encoded = try encodePathFrame(.{ .challenge = challenge }, &frame_buf);
                try self.sendPacketOnPath(.application, encoded, 0, path_key.local, path_key.remote, outbound);
            },
        }

        try self.openAndProcess(received.bytes, path_key, outbound, received.received_at_us);
    }

    fn openAndProcess(
        self: *Endpoint,
        datagram: []const u8,
        path_key: quic_path.PathKey,
        outbound: *DatagramQueue,
        now_us: u64,
    ) !void {
        var pkt: [max_datagram]u8 = undefined;
        if (datagram.len > pkt.len) return error.TruncatedPacket;
        @memcpy(pkt[0..datagram.len], datagram);

        if (datagram.len == 0) return error.TruncatedPacket;
        var pos: usize = 0;
        var level: EncryptionLevel = undefined;
        var packet_end: usize = datagram.len;
        if (pkt[0] & 0x80 != 0) {
            level = switch ((pkt[0] >> 4) & 0x3) {
                0b00 => .initial,
                0b10 => .handshake,
                else => return error.UnexpectedPacketType,
            };
            pos = 1;
            try requireAvailable(datagram.len, pos, 4);
            if (std.mem.readInt(u32, pkt[pos..][0..4], .big) != quic_v1) return error.UnexpectedQuicVersion;
            pos += 4;
            try requireAvailable(datagram.len, pos, 1);
            if (pkt[pos] != cid_len) return error.UnexpectedConnectionId;
            pos += 1;
            try requireAvailable(datagram.len, pos, cid_len);
            pos += cid_len;
            try requireAvailable(datagram.len, pos, 1);
            if (pkt[pos] != cid_len) return error.UnexpectedConnectionId;
            pos += 1;
            try requireAvailable(datagram.len, pos, cid_len); // peer's source CID
            pos += cid_len;
            if (level == .initial) {
                const token_len = varint.decode(pkt[pos..datagram.len]) catch return error.TruncatedPacket;
                if (token_len.value != 0) return error.UnexpectedToken;
                pos += token_len.len;
            }
            const length = varint.decode(pkt[pos..datagram.len]) catch return error.TruncatedPacket;
            pos += length.len;
            if (length.value > datagram.len - pos) return error.TruncatedPacket;
            packet_end = pos + @as(usize, @intCast(length.value));
        } else {
            level = .application;
            pos = 1;
            try requireAvailable(datagram.len, pos, cid_len);
            pos += cid_len;
        }

        const keys = self.adapter.protectionKeys(level, .read) orelse return error.KeysUnavailableForLevel;
        const pn_offset = pos;
        if (packet_end < pn_offset + 4 + sample_len) return error.TruncatedPacket;

        var sample: [sample_len]u8 = undefined;
        @memcpy(&sample, pkt[pn_offset + 4 ..][0..sample_len]);
        var sampled_pn: [4]u8 = pkt[pn_offset..][0..4].*;
        const removed = keys.removeHeaderProtection(&pkt[0], &sampled_pn, sample);
        @memcpy(pkt[pn_offset..][0..removed.packet_number_length], sampled_pn[0..removed.packet_number_length]);

        const space = spaceIndex(level);
        const pn = quic_packet.decodePacketNumber(
            self.largest_recv_pn[space] orelse 0,
            removed.truncated_packet_number,
            @intCast(removed.packet_number_length * 8),
        );
        const header = pkt[0 .. pn_offset + removed.packet_number_length];
        var plain: [max_datagram]u8 = undefined;
        const frames = try self.adapter.openPacketPayload(
            level,
            .read,
            pn,
            header,
            pkt[pn_offset + removed.packet_number_length .. packet_end],
            &plain,
        );
        if (self.largest_recv_pn[space] == null or pn > self.largest_recv_pn[space].?) {
            self.largest_recv_pn[space] = pn;
        }
        try self.processFrames(level, frames, path_key, outbound, now_us);
    }

    fn processFrames(
        self: *Endpoint,
        level: EncryptionLevel,
        frames: []const u8,
        path_key: quic_path.PathKey,
        outbound: *DatagramQueue,
        now_us: u64,
    ) !void {
        var pos: usize = 0;
        while (pos < frames.len) {
            const typ = try varint.decode(frames[pos..]);
            pos += typ.len;
            switch (typ.value) {
                frame_padding, frame_ping => {},
                frame_crypto => {
                    const offset = try varint.decode(frames[pos..]);
                    pos += offset.len;
                    const len = try varint.decode(frames[pos..]);
                    pos += len.len;
                    if (len.value > frames.len - pos) return error.TruncatedFrame;
                    const data = frames[pos..][0..@intCast(len.value)];
                    pos += data.len;
                    try self.handshake.onCrypto(level, offset.value, data);
                },
                frame_stream_base...frame_stream_base + 0x07 => {
                    if (level != .application) return error.UnexpectedFrameType;
                    const fin = typ.value & 0x01 != 0;
                    const has_offset = typ.value & 0x04 != 0;
                    const has_len = typ.value & 0x02 != 0;
                    const id = try varint.decode(frames[pos..]);
                    pos += id.len;
                    var offset: u64 = 0;
                    if (has_offset) {
                        const decoded = try varint.decode(frames[pos..]);
                        offset = decoded.value;
                        pos += decoded.len;
                    }
                    var data_len: usize = frames.len - pos;
                    if (has_len) {
                        const decoded = try varint.decode(frames[pos..]);
                        pos += decoded.len;
                        if (decoded.value > frames.len - pos) return error.TruncatedFrame;
                        data_len = @intCast(decoded.value);
                    }
                    const data = frames[pos..][0..data_len];
                    pos += data_len;
                    var manager = if (self.streams) |*m| m else return error.StreamsNotReady;
                    _ = try manager.receiveStreamFrame(.{ .id = id.value, .offset = offset, .data = data, .fin = fin });
                },
                frame_path_challenge => {
                    if (level != .application) return error.UnexpectedFrameType;
                    if (quic_path.path_challenge_len > frames.len - pos) return error.TruncatedFrame;
                    const response = quic_path.PathManager.onPathChallenge(frames[pos..][0..quic_path.path_challenge_len].*);
                    pos += quic_path.path_challenge_len;
                    var frame_buf: [16]u8 = undefined;
                    const encoded = try encodePathFrame(.{ .response = response }, &frame_buf);
                    try self.sendPacketOnPath(.application, encoded, 0, path_key.local, path_key.remote, outbound);
                },
                frame_path_response => {
                    if (level != .application) return error.UnexpectedFrameType;
                    if (quic_path.path_challenge_len > frames.len - pos) return error.TruncatedFrame;
                    const response = frames[pos..][0..quic_path.path_challenge_len].*;
                    pos += quic_path.path_challenge_len;
                    if (self.paths.onPathResponse(path_key, response, now_us)) |outcome| {
                        if (outcome.reset_congestion) self.recovery.resetForPathMigration();
                    }
                },
                else => return error.UnexpectedFrameType,
            }
        }
    }

    /// Packetize pending TLS handshake output for every level that can still
    /// send. Client Initial datagrams are padded to the RFC 9000 minimum.
    fn flushHandshake(self: *Endpoint, queue: *DatagramQueue) !void {
        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |level| {
            var chunk: [1024]u8 = undefined;
            while (try self.handshake.pollOutput(level, &chunk)) |output| {
                var frame_buf: [1100]u8 = undefined;
                const encoded = try encodeCryptoFrame(output.offset, output.bytes, &frame_buf);
                const pad_to: usize = if (self.role == .client and level == .initial) min_client_initial_datagram else 0;
                try self.sendPacket(level, encoded, pad_to, queue);
            }
        }
    }

    /// Reserve send window and packetize one STREAM frame at 1-RTT.
    fn sendStreamBytes(self: *Endpoint, id: quic_stream.StreamId, bytes: []const u8, fin: bool, queue: *DatagramQueue) !void {
        var manager = if (self.streams) |*m| m else return error.StreamsNotReady;
        const grant = try manager.reserveSend(id, bytes.len, fin);
        var frame_buf: [max_datagram]u8 = undefined;
        const encoded = try encodeStreamFrame(grant, bytes, &frame_buf);
        try self.sendPacket(.application, encoded, 0, queue);
    }

    fn sendStreamBytesFrom(
        self: *Endpoint,
        id: quic_stream.StreamId,
        bytes: []const u8,
        fin: bool,
        local_addr: quic_udp.Address,
        remote_addr: quic_udp.Address,
        queue: *DatagramQueue,
    ) !void {
        var manager = if (self.streams) |*m| m else return error.StreamsNotReady;
        const grant = try manager.reserveSend(id, bytes.len, fin);
        var frame_buf: [max_datagram]u8 = undefined;
        const encoded = try encodeStreamFrame(grant, bytes, &frame_buf);
        try self.sendPacketOnPath(.application, encoded, 0, local_addr, remote_addr, queue);
    }

    fn sendPingFrom(
        self: *Endpoint,
        local_addr: quic_udp.Address,
        remote_addr: quic_udp.Address,
        queue: *DatagramQueue,
    ) !void {
        var frame_buf: [8]u8 = undefined;
        const encoded_len = try varint.encode(frame_ping, &frame_buf);
        try self.sendPacketOnPath(.application, frame_buf[0..encoded_len], 0, local_addr, remote_addr, queue);
    }

    /// Drain everything currently readable from `id` into `out`; returns
    /// whether FIN has been consumed.
    fn readStream(self: *Endpoint, id: quic_stream.StreamId, out: *std.ArrayList(u8)) !bool {
        var manager = if (self.streams) |*m| m else return error.StreamsNotReady;
        var fin = false;
        var buf: [1024]u8 = undefined;
        while (true) {
            const result = try manager.read(id, &buf);
            if (result.len > 0) try out.appendSlice(self.allocator, buf[0..result.len]);
            fin = fin or result.fin;
            if (result.len == 0) break;
        }
        return fin;
    }
};

// ---------------------------------------------------------------------------
// Harness: two endpoints and the two directed datagram queues between them.
// ---------------------------------------------------------------------------

const Smoke = struct {
    client: Endpoint,
    server: Endpoint,
    to_server: *DatagramQueue,
    to_client: *DatagramQueue,

    /// The client's initial DCID: both sides derive Initial secrets from it
    /// (RFC 9001 §5.2) and the server adopts it as its connection ID.
    const server_cid = [cid_len]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_cid = [cid_len]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };

    fn init(allocator: std.mem.Allocator) !*Smoke {
        const client_addr = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 50_000);
        const server_addr = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 4433);
        const params = try (config.Config{ .migration_policy = .full }).transportParameters();
        const client_recovery = try allocator.create(quic_recovery.RecoveryController);
        errdefer allocator.destroy(client_recovery);
        client_recovery.* = .{};
        const server_recovery = try allocator.create(quic_recovery.RecoveryController);
        errdefer allocator.destroy(server_recovery);
        server_recovery.* = .{};
        const to_server = try allocator.create(DatagramQueue);
        errdefer allocator.destroy(to_server);
        to_server.* = .{};
        const to_client = try allocator.create(DatagramQueue);
        errdefer allocator.destroy(to_client);
        to_client.* = .{};
        const smoke = try allocator.create(Smoke);
        errdefer allocator.destroy(smoke);
        smoke.* = .{
            .client = .{
                .allocator = allocator,
                .role = .client,
                .backend = tls_backend.Tls13Backend.initClient(
                    .{ .hello_random = [_]u8{0xc1} ** 32, .key_share_seed = [_]u8{0x11} ** 32 },
                    .{ .pinned_certificate = tls_backend.testdata.certificate_der },
                ),
                .cid_routes = quic_cid.CidRoutingTable.init(allocator),
                .paths = quic_path.PathManager.init(.full, .{ .local = client_addr, .remote = server_addr }),
                .recovery = client_recovery,
                .local_params = params,
                .local_cid = client_cid,
                .peer_cid = server_cid,
                .local_addr = client_addr,
                .peer_addr = server_addr,
            },
            .server = .{
                .allocator = allocator,
                .role = .server,
                .backend = tls_backend.Tls13Backend.initServer(
                    .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x22} ** 32 },
                    try tls_backend.Identity.initPkcs8(
                        tls_backend.testdata.certificate_der,
                        tls_backend.testdata.private_key_pkcs8_der,
                    ),
                ),
                .cid_routes = quic_cid.CidRoutingTable.init(allocator),
                .paths = quic_path.PathManager.init(.full, .{ .local = server_addr, .remote = client_addr }),
                .recovery = server_recovery,
                .local_params = params,
                .local_cid = server_cid,
                .peer_cid = client_cid,
                .local_addr = server_addr,
                .peer_addr = client_addr,
            },
            .to_server = to_server,
            .to_client = to_client,
        };
        try smoke.client.registerLocalCid();
        try smoke.server.registerLocalCid();
        _ = try smoke.client.adapter.installInitialSecrets(.client, &server_cid);
        _ = try smoke.server.adapter.installInitialSecrets(.server, &server_cid);
        return smoke;
    }

    fn wire(self: *Smoke) !void {
        self.client.handshake = tls_handshake.Handshake.initClient(&self.client.adapter, self.client.backend.backend());
        self.server.handshake = tls_handshake.Handshake.initServer(&self.server.adapter, self.server.backend.backend());
        try self.server.handshake.start(self.server.local_params);
        try self.client.handshake.start(self.client.local_params);
    }

    fn deinit(self: *Smoke) void {
        const allocator = self.client.allocator;
        self.client.deinit();
        self.server.deinit();
        allocator.destroy(self.to_server);
        allocator.destroy(self.to_client);
        allocator.destroy(self);
    }

    /// Pump protected handshake packets between the endpoints until both
    /// report completion. Bounded rounds keep a stall deterministic.
    fn completeHandshake(self: *Smoke) !void {
        var rounds: usize = 0;
        while (rounds < 16) : (rounds += 1) {
            try self.client.flushHandshake(self.to_server);
            var progressed = try self.to_server.deliverAll(&self.server, self.to_client) > 0;
            try self.server.flushHandshake(self.to_client);
            progressed = (try self.to_client.deliverAll(&self.client, self.to_server) > 0) or progressed;
            if (self.client.handshake.isComplete() and self.server.handshake.isComplete() and !progressed) return;
        }
        if (!self.client.handshake.isComplete() or !self.server.handshake.isComplete()) return error.HandshakeStalled;
    }

    /// Move all pending 1-RTT datagrams in both directions.
    fn pumpApplication(self: *Smoke) !void {
        var rounds: usize = 0;
        while (rounds < 8) : (rounds += 1) {
            const server_progress = try self.to_server.deliverAll(&self.server, self.to_client);
            const client_progress = try self.to_client.deliverAll(&self.client, self.to_server);
            if (server_progress == 0 and client_progress == 0) return;
        }
        return error.HandshakeStalled;
    }
};

// ---------------------------------------------------------------------------
// The smoke test.
// ---------------------------------------------------------------------------

const request_body = "ping-h3-body";
const response_body = "pong-h3-body";

test "pure-Zig QUIC/TLS/H3 local smoke: handshake, request, response, close" {
    const allocator = testing.allocator;
    var smoke = try Smoke.init(allocator);
    defer smoke.deinit();
    try smoke.wire();

    // --- Stage 1: TLS 1.3 handshake over protected QUIC packets. ---
    try smoke.completeHandshake();
    try testing.expectEqual(@as(?tls_handshake.HandshakeError, null), smoke.client.handshake.failure());
    try testing.expectEqual(@as(?tls_handshake.HandshakeError, null), smoke.server.handshake.failure());

    // ALPN is h3 on both sides; the pinned certificate verified.
    try testing.expect(smoke.client.adapter.negotiatedH3());
    try testing.expect(smoke.server.adapter.negotiatedH3());
    try testing.expectEqual(tls_adapter.CertificateState.valid, smoke.client.adapter.certificateState());

    // Key lifecycle: Initial and Handshake keys are gone in both directions on
    // both adapters, 1-RTT keys usable.
    inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |level| {
        inline for (.{ tls_adapter.Direction.read, tls_adapter.Direction.write }) |direction| {
            try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), smoke.client.adapter.protectionKeys(level, direction));
            try testing.expectEqual(@as(?tls_adapter.PacketProtectionKeys, null), smoke.server.adapter.protectionKeys(level, direction));
        }
    }
    try testing.expect(smoke.client.adapter.protectionKeys(.application, .write) != null);
    try testing.expect(smoke.server.adapter.protectionKeys(.application, .write) != null);

    // Peer transport parameters are exposed only post-authentication.
    try testing.expect(smoke.client.adapter.peerTransportParameters() != null);
    try testing.expect(smoke.server.adapter.peerTransportParameters() != null);

    // --- Stage 2: stream state from authenticated transport parameters. ---
    try smoke.client.attachStreams();
    try smoke.server.attachStreams();

    // --- Stage 3: HTTP/3 control streams (SETTINGS first, both directions). ---
    var settings_bytes: [64]u8 = undefined;
    var settings_len: usize = 0;
    settings_len += (try http3.frame.encodeStreamType(.control, settings_bytes[settings_len..])).len;
    var settings_payload: [16]u8 = undefined;
    const empty_settings = try http3.frame.encodeSettings(&.{}, &settings_payload);
    settings_len += (try http3.frame.encodeKnownFrame(.settings, empty_settings, settings_bytes[settings_len..])).len;

    const client_control = try smoke.client.streams.?.openLocal(.uni);
    try smoke.client.sendStreamBytes(client_control, settings_bytes[0..settings_len], false, smoke.to_server);
    const server_control = try smoke.server.streams.?.openLocal(.uni);
    try smoke.server.sendStreamBytes(server_control, settings_bytes[0..settings_len], false, smoke.to_client);
    try smoke.pumpApplication();

    var server_control_registry = http3.frame.ControlStreamRegistry{};
    try server_control_registry.openControlStream(client_control);
    var server_control_view = http3.frame.ControlStream{};
    defer server_control_view.deinit(allocator);
    var control_bytes: std.ArrayList(u8) = .empty;
    defer control_bytes.deinit(allocator);
    _ = try smoke.server.readStream(client_control, &control_bytes);
    _ = try server_control_view.ingest(allocator, control_bytes.items);
    try testing.expect(server_control_view.saw_settings);

    var client_control_view = http3.frame.ControlStream{};
    defer client_control_view.deinit(allocator);
    control_bytes.clearRetainingCapacity();
    _ = try smoke.client.readStream(server_control, &control_bytes);
    _ = try client_control_view.ingest(allocator, control_bytes.items);
    try testing.expect(client_control_view.saw_settings);

    // --- Stage 4: client request (HEADERS + DATA, FIN) on a bidi stream. ---
    const request_stream = try smoke.client.streams.?.openLocal(.bidi);
    try testing.expectEqual(@as(quic_stream.StreamId, 0), request_stream);

    var request_fields = [_]http3.qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "tardigrade.test" },
        .{ .name = ":path", .value = "/smoke" },
        .{ .name = "user-agent", .value = "tardigrade-smoke/1" },
    };
    var qpack_buf: [512]u8 = undefined;
    const header_block = try http3.qpack.encode(&request_fields, &qpack_buf);
    var request_bytes: [1024]u8 = undefined;
    var request_len: usize = 0;
    request_len += (try http3.frame.encodeKnownFrame(.headers, header_block, request_bytes[request_len..])).len;
    request_len += (try http3.frame.encodeKnownFrame(.data, request_body, request_bytes[request_len..])).len;
    try smoke.client.sendStreamBytes(request_stream, request_bytes[0..request_len], true, smoke.to_server);
    try smoke.pumpApplication();

    // --- Stage 5: server decodes the request through the H3/QPACK session. ---
    var request_stream_bytes: std.ArrayList(u8) = .empty;
    defer request_stream_bytes.deinit(allocator);
    const request_fin = try smoke.server.readStream(request_stream, &request_stream_bytes);
    try testing.expect(request_fin);

    var session = http3.session.RequestStream.init(allocator, request_stream);
    defer session.deinit();
    var qpack_scratch: [1024]u8 = undefined;
    _ = try session.ingestBytes(request_stream_bytes.items, &qpack_scratch);
    const exchange = try session.finish();
    try testing.expectEqualStrings("GET", exchange.request.method);
    try testing.expectEqualStrings("https", exchange.request.scheme);
    try testing.expectEqualStrings("tardigrade.test", exchange.request.authority);
    try testing.expectEqualStrings("/smoke", exchange.request.path);
    try testing.expectEqual(@as(usize, 1), exchange.request.headers.len);
    try testing.expectEqualStrings("user-agent", exchange.request.headers[0].name);
    try testing.expectEqualStrings("tardigrade-smoke/1", exchange.request.headers[0].value);
    try testing.expectEqualStrings(request_body, exchange.body.buffered);

    // --- Stage 6: server response (HEADERS + DATA, FIN). ---
    const response_headers = [_]stream_transport.Header{
        .{ .name = "server", .value = "tardigrade" },
    };
    var response_bytes: [1024]u8 = undefined;
    var response_len: usize = 0;
    response_len += (try http3.session.ResponseEncoder.encodeHeaders(200, &response_headers, response_bytes[response_len..])).len;
    response_len += (try http3.session.ResponseEncoder.encodeData(response_body, response_bytes[response_len..])).len;
    try smoke.server.sendStreamBytes(request_stream, response_bytes[0..response_len], true, smoke.to_client);
    try smoke.pumpApplication();

    // --- Stage 7: client decodes the response HEADERS/DATA. ---
    var response_stream_bytes: std.ArrayList(u8) = .empty;
    defer response_stream_bytes.deinit(allocator);
    const response_fin = try smoke.client.readStream(request_stream, &response_stream_bytes);
    try testing.expect(response_fin);

    const headers_frame = try http3.frame.decodeFrame(response_stream_bytes.items);
    try testing.expectEqual(http3.frame.FrameType.headers, headers_frame.typ);
    var response_fields: [16]http3.qpack.HeaderField = undefined;
    const field_count = try http3.qpack.decode(headers_frame.payload, &response_fields, &qpack_scratch);
    try testing.expectEqual(@as(usize, 2), field_count);
    try testing.expectEqualStrings(":status", response_fields[0].name);
    try testing.expectEqualStrings("200", response_fields[0].value);
    try testing.expectEqualStrings("server", response_fields[1].name);
    try testing.expectEqualStrings("tardigrade", response_fields[1].value);

    const data_frame = try http3.frame.decodeFrame(response_stream_bytes.items[headers_frame.len..]);
    try testing.expectEqual(http3.frame.FrameType.data, data_frame.typ);
    try testing.expectEqualStrings(response_body, data_frame.payload);
    try testing.expectEqual(response_stream_bytes.items.len, headers_frame.len + data_frame.len);

    // --- Stage 8: close/drain — the request stream is fully closed on both
    // sides, nothing is left buffered, and no handshake output lingers. ---
    try testing.expectEqual(quic_stream.StreamState.closed, smoke.client.streams.?.get(request_stream).?.state());
    try testing.expectEqual(quic_stream.StreamState.closed, smoke.server.streams.?.get(request_stream).?.state());
    try testing.expectEqual(@as(u64, 1), smoke.client.streams.?.metrics.closed_streams);
    try testing.expectEqual(@as(u64, 1), smoke.server.streams.?.metrics.closed_streams);
    // The two control streams stay open by design (HTTP/3 keeps them for the
    // connection lifetime); nothing else is active.
    try testing.expectEqual(@as(u64, 2), smoke.client.streams.?.metrics.active_streams);
    try testing.expectEqual(@as(u64, 2), smoke.server.streams.?.metrics.active_streams);

    var drain_buf: [64]u8 = undefined;
    inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake, EncryptionLevel.application }) |level| {
        try testing.expectEqual(@as(usize, 0), smoke.client.adapter.outbound[level.index()].pending());
        try testing.expectEqual(@as(usize, 0), smoke.server.adapter.outbound[level.index()].pending());
    }
    const client_read = try smoke.client.streams.?.read(request_stream, &drain_buf);
    try testing.expectEqual(@as(usize, 0), client_read.len);
    try testing.expectEqual(@as(usize, 0), smoke.to_server.count);
    try testing.expectEqual(@as(usize, 0), smoke.to_client.count);

    // Packet protection saw real traffic in both directions and nothing was
    // forged along the way.
    try testing.expect(smoke.client.adapter.metrics.packets_deprotected > 0);
    try testing.expect(smoke.server.adapter.metrics.packets_deprotected > 0);
    try testing.expectEqual(@as(u64, 0), smoke.client.adapter.metrics.deprotection_failures);
    try testing.expectEqual(@as(u64, 0), smoke.server.adapter.metrics.deprotection_failures);
}

test "smoke harness rejects a datagram for an unknown connection id" {
    const allocator = testing.allocator;
    var smoke = try Smoke.init(allocator);
    defer smoke.deinit();
    try smoke.wire();
    try smoke.completeHandshake();

    // A 1-RTT packet addressed to a different CID must not decrypt state.
    var bogus: [64]u8 = undefined;
    bogus[0] = 0x40;
    @memset(bogus[1..], 0xee);
    try testing.expectError(error.UnexpectedConnectionId, smoke.server.onDatagram(&bogus));
}

test "smoke harness validates NAT rebinding through protected path frames" {
    const allocator = testing.allocator;
    var smoke = try Smoke.init(allocator);
    defer smoke.deinit();
    try smoke.wire();
    try smoke.completeHandshake();

    const rebound_client = quic_udp.Address.ip4(.{ 127, 0, 0, 1 }, 50_001);
    try smoke.client.sendPingFrom(rebound_client, smoke.server.local_addr, smoke.to_server);
    try smoke.pumpApplication();

    try testing.expect(smoke.server.paths.activePath().key.eql(.{
        .local = smoke.server.local_addr,
        .remote = rebound_client,
    }));
    try testing.expectEqual(@as(u64, 1), smoke.server.paths.metrics.nat_rebindings);
    try testing.expectEqual(@as(u64, 0), smoke.server.paths.metrics.migrations);
    try testing.expectEqual(@as(u64, 1), smoke.server.paths.metrics.path_validations_succeeded);
    try testing.expect(smoke.server.cid_routes.metrics.routing_hits > 0);
}

test "smoke harness blocks host migration when policy allows only NAT rebinding" {
    const allocator = testing.allocator;
    var smoke = try Smoke.init(allocator);
    defer smoke.deinit();
    try smoke.wire();
    try smoke.completeHandshake();

    smoke.server.paths.policy = .nat_rebinding_only;
    const migrated_client = quic_udp.Address.ip4(.{ 198, 51, 100, 7 }, 50_000);
    try smoke.client.sendPingFrom(migrated_client, smoke.server.local_addr, smoke.to_server);
    try smoke.pumpApplication();

    try testing.expect(smoke.server.paths.activePath().key.eql(.{
        .local = smoke.server.local_addr,
        .remote = smoke.server.peer_addr,
    }));
    try testing.expectEqual(@as(u64, 1), smoke.server.paths.metrics.migrations_blocked);
    try testing.expectEqual(@as(u64, 0), smoke.server.paths.metrics.path_challenges_sent);
    try testing.expectEqual(@as(u64, 0), smoke.server.paths.metrics.path_validations_succeeded);
}

test "smoke harness drops protected packets addressed to a retired CID route" {
    const allocator = testing.allocator;
    var smoke = try Smoke.init(allocator);
    defer smoke.deinit();
    try smoke.wire();
    try smoke.completeHandshake();

    try smoke.client.sendPingFrom(smoke.client.local_addr, smoke.server.local_addr, smoke.to_server);
    try testing.expectEqual(@as(usize, 1), smoke.to_server.count);
    smoke.server.retireLocalCid();

    const datagram = smoke.to_server.buffers[0][0..smoke.to_server.lengths[0]];
    try testing.expectError(error.UnexpectedConnectionId, smoke.server.onReceivedDatagram(.{
        .bytes = datagram,
        .local = smoke.to_server.locals[0],
        .remote = smoke.to_server.remotes[0],
        .received_at_us = smoke.to_server.received_at_us[0],
    }, smoke.to_client));
    try testing.expectEqual(@as(u64, 1), smoke.server.cid_routes.metrics.routing_misses);
}

test "smoke harness resets recovery when validated migration changes host" {
    const allocator = testing.allocator;
    var smoke = try Smoke.init(allocator);
    defer smoke.deinit();
    try smoke.wire();
    try smoke.completeHandshake();

    smoke.server.recovery.rtt.update(80_000, 0);
    smoke.server.recovery.congestion.congestion_window = 3 * quic_recovery.max_datagram_size;
    try testing.expect(smoke.server.recovery.rtt.hasSample());

    const migrated_client = quic_udp.Address.ip4(.{ 198, 51, 100, 7 }, 50_000);
    try smoke.client.sendPingFrom(migrated_client, smoke.server.local_addr, smoke.to_server);
    try smoke.pumpApplication();

    try testing.expect(smoke.server.paths.activePath().key.eql(.{
        .local = smoke.server.local_addr,
        .remote = migrated_client,
    }));
    try testing.expectEqual(@as(u64, 1), smoke.server.paths.metrics.migrations);
    try testing.expect(!smoke.server.recovery.rtt.hasSample());
    try testing.expectEqual(
        quic_recovery.CongestionController.initialWindow(quic_recovery.max_datagram_size),
        smoke.server.recovery.congestion.congestion_window,
    );
}

test "smoke harness surfaces payload forgery as an authentication failure" {
    const allocator = testing.allocator;
    var smoke = try Smoke.init(allocator);
    defer smoke.deinit();
    try smoke.wire();
    try smoke.completeHandshake();
    try smoke.client.attachStreams();
    try smoke.server.attachStreams();

    const id = try smoke.client.streams.?.openLocal(.bidi);
    try smoke.client.sendStreamBytes(id, "tamper-me", true, smoke.to_server);
    // Flip one ciphertext byte in flight: deprotection must fail and count.
    const datagram = smoke.to_server.buffers[0][0..smoke.to_server.lengths[0]];
    datagram[datagram.len - 1] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, smoke.server.onDatagram(datagram));
    try testing.expectEqual(@as(u64, 1), smoke.server.adapter.metrics.deprotection_failures);
}

test "smoke harness fails truncated long-header packets deterministically" {
    const allocator = testing.allocator;
    var smoke = try Smoke.init(allocator);
    defer smoke.deinit();
    try smoke.wire();

    // Produce a real client Initial, then truncate it at every prefix length
    // that cuts into the fixed header fields (version, DCID, SCID, token,
    // length) or the protected payload. Each must fail with a typed error —
    // never an out-of-bounds panic.
    try smoke.client.flushHandshake(smoke.to_server);
    try testing.expectEqual(@as(usize, 1), smoke.to_server.count);
    const initial = smoke.to_server.buffers[0][0..smoke.to_server.lengths[0]];

    var cut: usize = 0;
    while (cut < initial.len) : (cut += 1) {
        const result = smoke.server.onDatagram(initial[0..cut]);
        try testing.expectError(error.TruncatedPacket, result);
    }
    // The empty datagram is truncated too.
    try testing.expectError(error.TruncatedPacket, smoke.server.onDatagram(initial[0..0]));

    // The untouched packet still parses and advances the handshake.
    try smoke.server.onDatagram(initial);
    try testing.expect(smoke.server.adapter.metrics.packets_deprotected == 1);
}
