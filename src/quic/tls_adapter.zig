//! QUIC TLS 1.3 adapter (#249, RFC 9001): the boundary between the QUIC
//! connection and the TLS handshake. Carries CRYPTO frame data in/out of the
//! TLS state machine, installs read/write secrets per encryption level, and
//! provides packet-protection and header-protection keys to `packet.zig`.
//!
//! This is the one seam that may temporarily wrap an external TLS 1.3
//! implementation behind a no-leak interface (see the #242 design); no TLS
//! library type escapes this module. Initial-secret derivation and key updates
//! also live here.
//!
//! Status: foundation slice — adapter contract, CRYPTO reassembly, and AEAD
//! packet protection for every encryption level (Initial, Handshake, 1-RTT) are
//! in place for the TLS_AES_128_GCM_SHA256 suite. Backend TLS driving, further
//! cipher suites, and key updates land in later #249 slices.

const std = @import("std");
const config = @import("config.zig");

const crypto = std.crypto;
const tls = std.crypto.tls;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes128 = crypto.core.aes.Aes128;

pub const max_crypto_buffer = 64 * 1024;
pub const max_crypto_ranges = 32;
pub const max_handshake_record = 16 * 1024;
pub const max_secret_len = 64;
pub const min_initial_dcid_len = 8;
pub const max_connection_id_len = 20;
pub const initial_salt_v1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};
/// Length of a TLS-exported traffic secret for the SHA-256 based suite. QUIC
/// uses the same length for Initial, Handshake, and 1-RTT secrets.
pub const traffic_secret_len = HkdfSha256.prk_length;
pub const aead_key_len = Aes128Gcm.key_length;
pub const aead_iv_len = Aes128Gcm.nonce_length;
pub const header_protection_key_len = Aes128Gcm.key_length;
pub const packet_protection_tag_len = Aes128Gcm.tag_length;
pub const max_packet_number: u64 = (@as(u64, 1) << 62) - 1;

pub const EncryptionLevel = enum(u2) {
    initial,
    zero_rtt,
    handshake,
    application,

    pub fn index(self: EncryptionLevel) usize {
        return @intFromEnum(self);
    }

    pub fn packetNumberSpace(self: EncryptionLevel) PacketNumberSpace {
        return switch (self) {
            .initial => .initial,
            .handshake => .handshake,
            .zero_rtt, .application => .application,
        };
    }
};

fn cryptoStreamIndex(level: EncryptionLevel) error{InvalidCryptoLevel}!usize {
    return switch (level) {
        .initial, .handshake, .application => level.index(),
        .zero_rtt => error.InvalidCryptoLevel,
    };
}

pub const PacketNumberSpace = enum {
    initial,
    handshake,
    application,
};

pub const Direction = enum {
    read,
    write,
};

pub const Perspective = enum {
    client,
    server,
};

pub const CertificateState = enum {
    not_checked,
    valid,
    invalid,
};

pub const KeyPhase = enum {
    current,
    next,
};

pub const Secret = struct {
    level: EncryptionLevel,
    direction: Direction,
    phase: KeyPhase = .current,
    bytes: [max_secret_len]u8 = [_]u8{0} ** max_secret_len,
    len: usize = 0,

    pub fn init(level: EncryptionLevel, direction: Direction, bytes: []const u8) error{SecretTooLarge}!Secret {
        if (bytes.len > max_secret_len) return error.SecretTooLarge;
        var secret = Secret{ .level = level, .direction = direction };
        @memcpy(secret.bytes[0..bytes.len], bytes);
        secret.len = bytes.len;
        return secret;
    }

    pub fn slice(self: *const Secret) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const SecretStore = struct {
    read: [4]?Secret = .{ null, null, null, null },
    write: [4]?Secret = .{ null, null, null, null },

    pub fn install(self: *SecretStore, secret: Secret) void {
        switch (secret.direction) {
            .read => installSlot(&self.read[secret.level.index()], secret),
            .write => installSlot(&self.write[secret.level.index()], secret),
        }
    }

    pub fn get(self: *const SecretStore, level: EncryptionLevel, direction: Direction) ?*const Secret {
        return switch (direction) {
            .read => if (self.read[level.index()]) |*secret| secret else null,
            .write => if (self.write[level.index()]) |*secret| secret else null,
        };
    }

    pub fn discard(self: *SecretStore, level: EncryptionLevel) void {
        if (self.read[level.index()]) |*secret| wipe(secret);
        if (self.write[level.index()]) |*secret| wipe(secret);
        self.read[level.index()] = null;
        self.write[level.index()] = null;
    }

    fn installSlot(slot: *?Secret, secret: Secret) void {
        if (slot.*) |*old_secret| wipe(old_secret);
        slot.* = secret;
    }

    fn wipe(secret: *Secret) void {
        @memset(secret.bytes[0..], 0);
        secret.len = 0;
    }
};

/// AEAD packet-protection material for one encryption level and direction under
/// the TLS_AES_128_GCM_SHA256 suite (RFC 9001 §5.1). Initial keys are derived
/// from the QUIC v1 salt and client DCID; Handshake and 1-RTT keys are derived
/// from the traffic secrets TLS exports at each level. The derivation is
/// identical for every level, so the same type serves all of them.
pub const PacketProtectionKeys = struct {
    secret: [traffic_secret_len]u8,
    key: [aead_key_len]u8,
    iv: [aead_iv_len]u8,
    hp: [header_protection_key_len]u8,

    pub fn nonce(self: *const PacketProtectionKeys, packet_number: u64) [aead_iv_len]u8 {
        std.debug.assert(packet_number <= max_packet_number);

        var out = self.iv;
        var packet_number_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &packet_number_bytes, packet_number, .big);
        for (packet_number_bytes, 0..) |byte, index| {
            out[aead_iv_len - packet_number_bytes.len + index] ^= byte;
        }
        return out;
    }

    pub fn sealPayload(
        self: *const PacketProtectionKeys,
        packet_number: u64,
        header: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) error{ InvalidPacketNumber, OutputTooSmall }![]u8 {
        try validatePacketNumber(packet_number);
        if (plaintext.len > std.math.maxInt(usize) - packet_protection_tag_len) return error.OutputTooSmall;
        const required_len = plaintext.len + packet_protection_tag_len;
        if (out.len < required_len) return error.OutputTooSmall;

        var tag: [packet_protection_tag_len]u8 = undefined;
        Aes128Gcm.encrypt(
            out[0..plaintext.len],
            &tag,
            plaintext,
            header,
            self.nonce(packet_number),
            self.key,
        );
        @memcpy(out[plaintext.len..][0..packet_protection_tag_len], &tag);
        return out[0..required_len];
    }

    pub fn openPayload(
        self: *const PacketProtectionKeys,
        packet_number: u64,
        header: []const u8,
        protected_payload: []const u8,
        out: []u8,
    ) error{ InvalidPacketNumber, ProtectedPayloadTooShort, OutputTooSmall, AuthenticationFailed }![]u8 {
        try validatePacketNumber(packet_number);
        if (protected_payload.len < packet_protection_tag_len) return error.ProtectedPayloadTooShort;
        const ciphertext_len = protected_payload.len - packet_protection_tag_len;
        if (out.len < ciphertext_len) return error.OutputTooSmall;

        var tag: [packet_protection_tag_len]u8 = undefined;
        @memcpy(&tag, protected_payload[ciphertext_len..][0..packet_protection_tag_len]);
        Aes128Gcm.decrypt(
            out[0..ciphertext_len],
            protected_payload[0..ciphertext_len],
            tag,
            header,
            self.nonce(packet_number),
            self.key,
        ) catch return error.AuthenticationFailed;
        return out[0..ciphertext_len];
    }

    pub fn headerProtectionMask(self: *const PacketProtectionKeys, sample: [16]u8) [5]u8 {
        const aes = Aes128.initEnc(self.hp);
        var block: [16]u8 = undefined;
        aes.encrypt(&block, &sample);
        return block[0..5].*;
    }
};

fn validatePacketNumber(packet_number: u64) error{InvalidPacketNumber}!void {
    if (packet_number > max_packet_number) return error.InvalidPacketNumber;
}

pub const InitialSecrets = struct {
    initial_secret: [traffic_secret_len]u8,
    client: PacketProtectionKeys,
    server: PacketProtectionKeys,
};

pub fn deriveInitialSecretsV1(client_initial_dcid: []const u8) error{InvalidConnectionId}!InitialSecrets {
    if (client_initial_dcid.len < min_initial_dcid_len or client_initial_dcid.len > max_connection_id_len) {
        return error.InvalidConnectionId;
    }

    const initial_secret = HkdfSha256.extract(&initial_salt_v1, client_initial_dcid);
    const client_secret = tls.hkdfExpandLabel(HkdfSha256, initial_secret, "client in", "", traffic_secret_len);
    const server_secret = tls.hkdfExpandLabel(HkdfSha256, initial_secret, "server in", "", traffic_secret_len);
    return .{
        .initial_secret = initial_secret,
        .client = deriveAes128GcmKeys(client_secret),
        .server = deriveAes128GcmKeys(server_secret),
    };
}

/// Derive AEAD packet-protection keys for the TLS_AES_128_GCM_SHA256 suite from
/// a traffic `secret`, per RFC 9001 §5.1. The `secret` is the Initial secret for
/// Initial packets, or the TLS-exported Handshake / 1-RTT traffic secret for the
/// respective levels; the "quic key" / "quic iv" / "quic hp" derivation is the
/// same regardless of level.
pub fn deriveAes128GcmKeys(secret: [traffic_secret_len]u8) PacketProtectionKeys {
    return .{
        .secret = secret,
        .key = tls.hkdfExpandLabel(HkdfSha256, secret, "quic key", "", aead_key_len),
        .iv = tls.hkdfExpandLabel(HkdfSha256, secret, "quic iv", "", aead_iv_len),
        .hp = tls.hkdfExpandLabel(HkdfSha256, secret, "quic hp", "", header_protection_key_len),
    };
}

pub const ByteRange = struct {
    start: u64,
    end: u64,
};

pub const CryptoStream = struct {
    buffer: [max_crypto_buffer]u8 = undefined,
    ranges: [max_crypto_ranges]ByteRange = undefined,
    range_count: usize = 0,
    consumed_offset: u64 = 0,

    pub fn insert(self: *CryptoStream, offset: u64, data: []const u8) error{ CryptoBufferTooLarge, TooManyCryptoRanges }!void {
        if (data.len == 0) return;
        if (offset >= max_crypto_buffer) return error.CryptoBufferTooLarge;
        const offset_usize: usize = @intCast(offset);
        if (data.len > max_crypto_buffer - offset_usize) return error.CryptoBufferTooLarge;

        var start = offset;
        var bytes = data;
        if (start + bytes.len <= self.consumed_offset) return;
        if (start < self.consumed_offset) {
            const skip: usize = @intCast(self.consumed_offset - start);
            start = self.consumed_offset;
            bytes = bytes[skip..];
        }
        const end = start + bytes.len;

        try self.addRangeMerged(.{ .start = start, .end = end });
        @memcpy(self.buffer[@intCast(start)..@intCast(end)], bytes);
    }

    pub fn contiguous(self: *const CryptoStream) []const u8 {
        const end = self.contiguousEnd();
        if (end <= self.consumed_offset) return &.{};
        return self.buffer[@intCast(self.consumed_offset)..@intCast(end)];
    }

    pub fn consumeContiguous(self: *CryptoStream) []const u8 {
        const end = self.contiguousEnd();
        if (end <= self.consumed_offset) return &.{};
        const bytes = self.buffer[@intCast(self.consumed_offset)..@intCast(end)];
        self.consumed_offset = end;
        self.dropConsumedRanges();
        return bytes;
    }

    fn addRangeMerged(self: *CryptoStream, new_range: ByteRange) error{TooManyCryptoRanges}!void {
        var merged: [max_crypto_ranges]ByteRange = undefined;
        var merged_count: usize = 0;
        var pending = new_range;
        var inserted = false;

        var index: usize = 0;
        while (index < self.range_count) : (index += 1) {
            const current = self.ranges[index];
            if (current.end < pending.start) {
                try appendRange(&merged, &merged_count, current);
            } else if (pending.end < current.start) {
                if (!inserted) {
                    try appendRange(&merged, &merged_count, pending);
                    inserted = true;
                }
                try appendRange(&merged, &merged_count, current);
            } else {
                pending.start = @min(pending.start, current.start);
                pending.end = @max(pending.end, current.end);
            }
        }
        if (!inserted) try appendRange(&merged, &merged_count, pending);

        @memcpy(self.ranges[0..merged_count], merged[0..merged_count]);
        self.range_count = merged_count;
    }

    fn appendRange(ranges_out: *[max_crypto_ranges]ByteRange, count: *usize, range: ByteRange) error{TooManyCryptoRanges}!void {
        if (count.* == max_crypto_ranges) return error.TooManyCryptoRanges;
        ranges_out[count.*] = range;
        count.* += 1;
    }

    fn contiguousEnd(self: *const CryptoStream) u64 {
        var end = self.consumed_offset;
        var index: usize = 0;
        while (index < self.range_count) : (index += 1) {
            const range = self.ranges[index];
            if (range.end <= end) continue;
            if (range.start > end) break;
            end = range.end;
        }
        return end;
    }

    fn dropConsumedRanges(self: *CryptoStream) void {
        var out: usize = 0;
        var index: usize = 0;
        while (index < self.range_count) : (index += 1) {
            var range = self.ranges[index];
            if (range.end <= self.consumed_offset) continue;
            if (range.start < self.consumed_offset) range.start = self.consumed_offset;
            self.ranges[out] = range;
            out += 1;
        }
        self.range_count = out;
    }
};

pub const CryptoReassembler = struct {
    streams: [4]CryptoStream = .{ .{}, .{}, .{}, .{} },

    pub fn insert(self: *CryptoReassembler, level: EncryptionLevel, offset: u64, data: []const u8) error{ CryptoBufferTooLarge, TooManyCryptoRanges, InvalidCryptoLevel }!void {
        const index = try cryptoStreamIndex(level);
        try self.streams[index].insert(offset, data);
    }

    pub fn contiguous(self: *const CryptoReassembler, level: EncryptionLevel) error{InvalidCryptoLevel}![]const u8 {
        const index = try cryptoStreamIndex(level);
        return self.streams[index].contiguous();
    }

    pub fn consumeContiguous(self: *CryptoReassembler, level: EncryptionLevel) error{InvalidCryptoLevel}![]const u8 {
        const index = try cryptoStreamIndex(level);
        return self.streams[index].consumeContiguous();
    }
};

pub const HandshakeInput = struct {
    level: EncryptionLevel,
    bytes: []const u8,
};

pub const HandshakeOutput = struct {
    level: EncryptionLevel,
    offset: u64,
    bytes: []const u8,
};

pub const CryptoOutput = struct {
    buffer: [max_crypto_buffer]u8 = undefined,
    start: usize = 0,
    end: usize = 0,
    next_offset: u64 = 0,

    pub fn append(self: *CryptoOutput, bytes: []const u8) error{CryptoBufferTooLarge}!void {
        if (bytes.len == 0) return;
        if (self.end + bytes.len > max_crypto_buffer) {
            self.compact();
            if (self.end + bytes.len > max_crypto_buffer) return error.CryptoBufferTooLarge;
        }
        @memcpy(self.buffer[self.end .. self.end + bytes.len], bytes);
        self.end += bytes.len;
    }

    pub fn pending(self: *const CryptoOutput) usize {
        return self.end - self.start;
    }

    pub fn take(self: *CryptoOutput, max_bytes: usize) ?struct { offset: u64, bytes: []const u8 } {
        const available = self.pending();
        if (available == 0) return null;
        const len = @min(available, max_bytes);
        const offset = self.next_offset;
        const bytes = self.buffer[self.start .. self.start + len];
        self.start += len;
        self.next_offset += len;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
        return .{ .offset = offset, .bytes = bytes };
    }

    fn compact(self: *CryptoOutput) void {
        if (self.start == 0) return;
        const available = self.pending();
        if (available > 0) std.mem.copyForwards(u8, self.buffer[0..available], self.buffer[self.start..self.end]);
        self.start = 0;
        self.end = available;
    }
};

pub const QuicTlsAdapter = struct {
    local_transport_parameters: ?config.TransportParameters = null,
    peer_transport_parameters_authenticated: bool = false,
    reassembler: CryptoReassembler = .{},
    outbound: [4]CryptoOutput = .{ .{}, .{}, .{}, .{} },
    secrets: SecretStore = .{},
    alpn_h3: bool = false,
    certificate_state: CertificateState = .not_checked,

    pub fn setLocalTransportParameters(self: *QuicTlsAdapter, params: config.TransportParameters) void {
        self.local_transport_parameters = params;
    }

    pub fn authenticatePeerTransportParameters(self: *QuicTlsAdapter) void {
        self.peer_transport_parameters_authenticated = true;
    }

    pub fn receiveCrypto(self: *QuicTlsAdapter, level: EncryptionLevel, offset: u64, data: []const u8) error{ CryptoBufferTooLarge, TooManyCryptoRanges, InvalidCryptoLevel }!void {
        try self.reassembler.insert(level, offset, data);
    }

    pub fn nextHandshakeInput(self: *QuicTlsAdapter, level: EncryptionLevel) error{InvalidCryptoLevel}!?HandshakeInput {
        const bytes = try self.reassembler.consumeContiguous(level);
        if (bytes.len == 0) return null;
        return .{ .level = level, .bytes = bytes };
    }

    pub fn queueHandshakeOutput(self: *QuicTlsAdapter, level: EncryptionLevel, bytes: []const u8) error{ CryptoBufferTooLarge, InvalidCryptoLevel }!void {
        const index = try cryptoStreamIndex(level);
        try self.outbound[index].append(bytes);
    }

    pub fn nextHandshakeOutput(self: *QuicTlsAdapter, level: EncryptionLevel, max_bytes: usize) error{InvalidCryptoLevel}!?HandshakeOutput {
        const index = try cryptoStreamIndex(level);
        if (max_bytes == 0) return null;
        const output = self.outbound[index].take(max_bytes) orelse return null;
        return .{ .level = level, .offset = output.offset, .bytes = output.bytes };
    }

    pub fn installSecret(self: *QuicTlsAdapter, installed_secret: Secret) void {
        self.secrets.install(installed_secret);
    }

    pub fn secret(self: *const QuicTlsAdapter, level: EncryptionLevel, direction: Direction) ?*const Secret {
        return self.secrets.get(level, direction);
    }

    pub fn installInitialSecrets(self: *QuicTlsAdapter, perspective: Perspective, client_initial_dcid: []const u8) error{ InvalidConnectionId, SecretTooLarge }!InitialSecrets {
        const secrets = try deriveInitialSecretsV1(client_initial_dcid);
        switch (perspective) {
            .client => {
                self.installSecret(try Secret.init(.initial, .write, &secrets.client.secret));
                self.installSecret(try Secret.init(.initial, .read, &secrets.server.secret));
            },
            .server => {
                self.installSecret(try Secret.init(.initial, .read, &secrets.client.secret));
                self.installSecret(try Secret.init(.initial, .write, &secrets.server.secret));
            },
        }
        return secrets;
    }

    /// Derive AEAD packet-protection keys for `level` in `direction` from the
    /// installed traffic secret. Works for Initial, Handshake, and 1-RTT
    /// (`.application`) once the corresponding secret has been installed —
    /// Initial via `installInitialSecrets`, later levels via `installSecret`
    /// with the TLS-exported traffic secret. Returns null when no secret is
    /// installed or its length does not match the SHA-256 suite.
    pub fn protectionKeys(self: *const QuicTlsAdapter, level: EncryptionLevel, direction: Direction) ?PacketProtectionKeys {
        const installed_secret = self.secret(level, direction) orelse return null;
        if (installed_secret.len != traffic_secret_len) return null;
        return deriveAes128GcmKeys(installed_secret.bytes[0..traffic_secret_len].*);
    }

    pub fn discardSecrets(self: *QuicTlsAdapter, level: EncryptionLevel) void {
        self.secrets.discard(level);
    }

    pub fn markAlpn(self: *QuicTlsAdapter, protocol: []const u8) void {
        self.alpn_h3 = std.mem.eql(u8, protocol, "h3");
    }
};

const testing = std.testing;

fn expectHex(comptime hex: []const u8, actual: []const u8) !void {
    var expected: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, hex);
    try testing.expectEqualSlices(u8, &expected, actual);
}

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

test "encryption levels map to QUIC packet number spaces" {
    try testing.expectEqual(PacketNumberSpace.initial, EncryptionLevel.initial.packetNumberSpace());
    try testing.expectEqual(PacketNumberSpace.handshake, EncryptionLevel.handshake.packetNumberSpace());
    try testing.expectEqual(PacketNumberSpace.application, EncryptionLevel.zero_rtt.packetNumberSpace());
    try testing.expectEqual(PacketNumberSpace.application, EncryptionLevel.application.packetNumberSpace());
}

test "QUIC v1 Initial secrets match RFC 9001 sample vector" {
    var dcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dcid, "8394c8f03e515708");

    const secrets = try deriveInitialSecretsV1(&dcid);
    try expectHex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44", &secrets.initial_secret);
    try expectHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", &secrets.client.secret);
    try expectHex("1f369613dd76d5467730efcbe3b1a22d", &secrets.client.key);
    try expectHex("fa044b2f42a3fd3b46fb255c", &secrets.client.iv);
    try expectHex("9f50449e04a0e810283a1e9933adedd2", &secrets.client.hp);
    try expectHex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b", &secrets.server.secret);
    try expectHex("cf3a5331653c364c88f0f379b6067e37", &secrets.server.key);
    try expectHex("0ac1493ca1905853b0bba03e", &secrets.server.iv);
    try expectHex("c206b8d9b9f0f37644430b490eeaa314", &secrets.server.hp);
}

test "Initial packet protection derives nonce and header protection mask" {
    var dcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dcid, "8394c8f03e515708");
    const secrets = try deriveInitialSecretsV1(&dcid);

    try expectHex("fa044b2f42a3fd3b46fb255e", &secrets.client.nonce(2));

    var sample: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sample, "d1b1c98dd7689fb8ec11d242b123dc9b");
    try expectHex("437b9aec36", &secrets.client.headerProtectionMask(sample));
}

test "Initial packet protection seals RFC 9001 client Initial payload sample" {
    var dcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dcid, "8394c8f03e515708");
    const secrets = try deriveInitialSecretsV1(&dcid);

    var header: [22]u8 = undefined;
    _ = try std.fmt.hexToBytes(&header, "c300000001088394c8f03e5157080000449e00000002");
    const crypto_frame = hexBytes(
        "060040f1010000ed0303ebf8fa56f129" ++
            "39b9584a3896472ec40bb863cfd3e868" ++
            "04fe3a47f06a2b69484c000004130113" ++
            "02010000c000000010000e00000b6578" ++
            "616d706c652e636f6dff01000100000a" ++
            "00080006001d00170018001000070005" ++
            "04616c706e0005000501000000000033" ++
            "00260024001d00209370b2c9caa47fba" ++
            "baf4559fedba753de171fa71f50f1ce1" ++
            "5d43e994ec74d748002b000302030400" ++
            "0d0010000e0403050306030203080408" ++
            "050806002d00020101001c0002400100" ++
            "3900320408ffffffffffffffff050480" ++
            "00ffff07048000ffff08011001048000" ++
            "75300901100f088394c8f03e51570806" ++
            "048000ffff",
    );
    var plaintext = [_]u8{0} ** 1162;
    @memcpy(plaintext[0..crypto_frame.len], &crypto_frame);

    var protected_payload: [1178]u8 = undefined;
    const sealed = try secrets.client.sealPayload(2, &header, &plaintext, &protected_payload);
    try testing.expectEqual(@as(usize, plaintext.len + packet_protection_tag_len), sealed.len);
    const expected_protected_payload = hexBytes(
        "d1b1c98dd7689fb8ec11d242b123dc9b" ++
            "d8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" ++
            "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" ++
            "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" ++
            "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" ++
            "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" ++
            "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" ++
            "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" ++
            "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" ++
            "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" ++
            "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" ++
            "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" ++
            "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" ++
            "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" ++
            "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" ++
            "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" ++
            "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" ++
            "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" ++
            "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" ++
            "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" ++
            "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" ++
            "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" ++
            "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" ++
            "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" ++
            "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" ++
            "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" ++
            "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" ++
            "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" ++
            "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" ++
            "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" ++
            "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" ++
            "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" ++
            "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" ++
            "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" ++
            "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" ++
            "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" ++
            "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" ++
            "e221af44860018ab0856972e194cd934",
    );
    try testing.expectEqualSlices(u8, &expected_protected_payload, sealed);

    var opened: [1162]u8 = undefined;
    const unsealed = try secrets.client.openPayload(2, &header, sealed, &opened);
    try testing.expectEqualSlices(u8, &plaintext, unsealed);
}

test "Initial packet protection rejects invalid inputs" {
    var dcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dcid, "8394c8f03e515708");
    const secrets = try deriveInitialSecretsV1(&dcid);
    const header = "test header";
    const plaintext = "ping";

    var too_small_seal: [plaintext.len + packet_protection_tag_len - 1]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, secrets.client.sealPayload(0, header, plaintext, &too_small_seal));

    var protected_payload: [plaintext.len + packet_protection_tag_len]u8 = undefined;
    const sealed = try secrets.client.sealPayload(0, header, plaintext, &protected_payload);

    try testing.expectError(error.InvalidPacketNumber, secrets.client.sealPayload(max_packet_number + 1, header, plaintext, &protected_payload));

    var too_small_open: [plaintext.len - 1]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, secrets.client.openPayload(0, header, sealed, &too_small_open));
    try testing.expectError(error.ProtectedPayloadTooShort, secrets.client.openPayload(0, header, sealed[0 .. packet_protection_tag_len - 1], &too_small_open));

    var opened: [plaintext.len]u8 = undefined;
    try testing.expectError(error.InvalidPacketNumber, secrets.client.openPayload(max_packet_number + 1, header, sealed, &opened));
    try testing.expectError(error.AuthenticationFailed, secrets.server.openPayload(0, header, sealed, &opened));

    var tampered = protected_payload;
    tampered[0] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, secrets.client.openPayload(0, header, &tampered, &opened));
}

test "Initial secrets reject invalid destination connection IDs" {
    try testing.expectError(error.InvalidConnectionId, deriveInitialSecretsV1(""));
    const too_short = [_]u8{0xaa} ** (min_initial_dcid_len - 1);
    try testing.expectError(error.InvalidConnectionId, deriveInitialSecretsV1(&too_short));

    const min_len = [_]u8{0xbb} ** min_initial_dcid_len;
    _ = try deriveInitialSecretsV1(&min_len);

    const too_long = [_]u8{0xaa} ** (max_connection_id_len + 1);
    try testing.expectError(error.InvalidConnectionId, deriveInitialSecretsV1(&too_long));
}

test "adapter installs Initial secrets by endpoint perspective" {
    var dcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dcid, "8394c8f03e515708");

    var client = QuicTlsAdapter{};
    const client_secrets = try client.installInitialSecrets(.client, &dcid);
    try testing.expectEqualSlices(u8, &client_secrets.client.secret, client.secret(.initial, .write).?.slice());
    try testing.expectEqualSlices(u8, &client_secrets.server.secret, client.secret(.initial, .read).?.slice());
    const client_write_keys = client.protectionKeys(.initial, .write).?;
    try testing.expectEqualSlices(u8, &client_secrets.client.key, &client_write_keys.key);

    var server = QuicTlsAdapter{};
    const server_secrets = try server.installInitialSecrets(.server, &dcid);
    try testing.expectEqualSlices(u8, &server_secrets.client.secret, server.secret(.initial, .read).?.slice());
    try testing.expectEqualSlices(u8, &server_secrets.server.secret, server.secret(.initial, .write).?.slice());
    const server_write_keys = server.protectionKeys(.initial, .write).?;
    try testing.expectEqualSlices(u8, &server_secrets.server.hp, &server_write_keys.hp);
}

test "adapter derives Handshake and 1-RTT protection keys from installed traffic secrets" {
    var adapter = QuicTlsAdapter{};

    // No secret installed yet: every non-Initial level reports no keys.
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.protectionKeys(.handshake, .write));
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.protectionKeys(.application, .read));

    var hs_secret: [traffic_secret_len]u8 = undefined;
    for (&hs_secret, 0..) |*byte, i| byte.* = @intCast((i * 7 + 3) & 0xff);
    var app_secret: [traffic_secret_len]u8 = undefined;
    for (&app_secret, 0..) |*byte, i| byte.* = @intCast((i * 5 + 1) & 0xff);

    adapter.installSecret(try Secret.init(.handshake, .write, &hs_secret));
    adapter.installSecret(try Secret.init(.application, .read, &app_secret));

    // The adapter path matches the standalone derivation for the same suite.
    const hs_keys = adapter.protectionKeys(.handshake, .write).?;
    const expected_hs = deriveAes128GcmKeys(hs_secret);
    try testing.expectEqualSlices(u8, &expected_hs.key, &hs_keys.key);
    try testing.expectEqualSlices(u8, &expected_hs.iv, &hs_keys.iv);
    try testing.expectEqualSlices(u8, &expected_hs.hp, &hs_keys.hp);

    const app_keys = adapter.protectionKeys(.application, .read).?;
    try testing.expectEqualSlices(u8, &deriveAes128GcmKeys(app_secret).key, &app_keys.key);

    // Direction is honored: the untouched direction stays empty.
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.protectionKeys(.handshake, .read));
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.protectionKeys(.application, .write));
}

test "packet protection round-trips at Handshake and 1-RTT levels" {
    var adapter = QuicTlsAdapter{};
    const secret = hexBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    adapter.installSecret(try Secret.init(.handshake, .write, &secret));
    adapter.installSecret(try Secret.init(.application, .write, &secret));

    const header = "\xe0\x00\x00\x00\x01";
    const plaintext = "handshake and 1-rtt payloads use the same AEAD path";

    for ([_]EncryptionLevel{ .handshake, .application }) |level| {
        const keys = adapter.protectionKeys(level, .write).?;

        var sealed: [128]u8 = undefined;
        const protected = try keys.sealPayload(7, header, plaintext, &sealed);
        try testing.expectEqual(plaintext.len + packet_protection_tag_len, protected.len);

        var opened: [128]u8 = undefined;
        const recovered = try keys.openPayload(7, header, protected, &opened);
        try testing.expectEqualSlices(u8, plaintext, recovered);

        // A different packet number changes the nonce and fails authentication.
        try testing.expectError(error.AuthenticationFailed, keys.openPayload(8, header, protected, &opened));
    }
}

test "protection keys reject a traffic secret of the wrong length" {
    var adapter = QuicTlsAdapter{};
    const short_secret = [_]u8{0xab} ** (traffic_secret_len - 1);
    adapter.installSecret(try Secret.init(.application, .write, &short_secret));
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.protectionKeys(.application, .write));
}

test "CRYPTO reassembly emits only contiguous bytes by encryption level" {
    var reassembler = CryptoReassembler{};

    try reassembler.insert(.initial, 6, "world");
    try testing.expectEqual(@as(usize, 0), (try reassembler.contiguous(.initial)).len);

    try reassembler.insert(.handshake, 0, "other");
    try testing.expectEqualStrings("other", try reassembler.consumeContiguous(.handshake));

    try reassembler.insert(.initial, 0, "hello ");
    try testing.expectEqualStrings("hello world", try reassembler.consumeContiguous(.initial));
    try testing.expectEqual(@as(usize, 0), (try reassembler.consumeContiguous(.initial)).len);
}

test "CRYPTO reassembly merges duplicate and overlapping fragments" {
    var stream = CryptoStream{};
    try stream.insert(0, "abcde");
    try stream.insert(2, "cdef");
    try stream.insert(6, "g");

    try testing.expectEqual(@as(usize, 1), stream.range_count);
    try testing.expectEqualStrings("abcdefg", stream.consumeContiguous());
}

test "CRYPTO reassembly preserves a gap after consumed bytes" {
    var stream = CryptoStream{};
    try stream.insert(0, "abc");
    try stream.insert(6, "ghi");
    try testing.expectEqualStrings("abc", stream.consumeContiguous());
    try testing.expectEqual(@as(u64, 3), stream.consumed_offset);
    try testing.expectEqual(@as(usize, 1), stream.range_count);
    try testing.expectEqual(@as(usize, 0), stream.contiguous().len);

    try stream.insert(3, "def");
    try testing.expectEqualStrings("defghi", stream.consumeContiguous());
}

test "CRYPTO insert merges a full range set without partial failure" {
    var stream = CryptoStream{};
    stream.range_count = max_crypto_ranges;
    stream.ranges[0] = .{ .start = 0, .end = 2 };
    stream.ranges[1] = .{ .start = 4, .end = 6 };
    var index: usize = 2;
    while (index < max_crypto_ranges) : (index += 1) {
        const start: u64 = 10 + @as(u64, @intCast(index)) * 2;
        stream.ranges[index] = .{ .start = start, .end = start + 1 };
    }

    try stream.insert(2, "cd");
    try testing.expectEqual(@as(usize, max_crypto_ranges - 1), stream.range_count);
    try testing.expectEqual(ByteRange{ .start = 0, .end = 6 }, stream.ranges[0]);
    try testing.expectEqualStrings("cd", stream.buffer[2..4]);
}

test "CRYPTO insert does not mutate bytes when range insertion fails" {
    var stream = CryptoStream{};
    stream.range_count = max_crypto_ranges;
    var index: usize = 0;
    while (index < max_crypto_ranges) : (index += 1) {
        const start: u64 = 10 + @as(u64, @intCast(index)) * 2;
        stream.ranges[index] = .{ .start = start, .end = start + 1 };
    }
    stream.buffer[1] = 'x';

    try testing.expectError(error.TooManyCryptoRanges, stream.insert(1, "y"));
    try testing.expectEqual(@as(u8, 'x'), stream.buffer[1]);
    try testing.expectEqual(@as(usize, max_crypto_ranges), stream.range_count);
}

test "CRYPTO insert ignores and trims consumed retransmits" {
    var stream = CryptoStream{};
    try stream.insert(0, "hello");
    try testing.expectEqualStrings("hello", stream.consumeContiguous());
    try testing.expectEqual(@as(u64, 5), stream.consumed_offset);

    try stream.insert(0, "hello");
    try testing.expectEqual(@as(usize, 0), stream.range_count);
    try testing.expectEqual(@as(usize, 0), stream.contiguous().len);

    try stream.insert(3, "lo world");
    try testing.expectEqualStrings(" world", stream.consumeContiguous());
}

test "adapter tracks transport parameters ALPN secrets and handshake input" {
    var adapter = QuicTlsAdapter{};
    const params = try (config.Config{}).transportParameters();
    adapter.setLocalTransportParameters(params);
    try testing.expect(adapter.local_transport_parameters != null);

    adapter.markAlpn("h3");
    try testing.expect(adapter.alpn_h3);

    const read_secret = try Secret.init(.handshake, .read, "read-secret");
    adapter.installSecret(read_secret);
    const stored_read_secret = adapter.secret(.handshake, .read).?;
    try testing.expectEqualStrings("read-secret", stored_read_secret.slice());
    adapter.discardSecrets(.handshake);
    try testing.expect(adapter.secret(.handshake, .read) == null);

    try adapter.receiveCrypto(.initial, 4, "lo");
    try adapter.receiveCrypto(.initial, 0, "hel");
    const first_input = (try adapter.nextHandshakeInput(.initial)).?;
    try testing.expectEqual(EncryptionLevel.initial, first_input.level);
    try testing.expectEqualStrings("hel", first_input.bytes);
    try adapter.receiveCrypto(.initial, 3, "l");
    const input = (try adapter.nextHandshakeInput(.initial)).?;
    try testing.expectEqual(EncryptionLevel.initial, input.level);
    try testing.expectEqualStrings("llo", input.bytes);
}

test "secret store returns pointers and wipes discarded secret bytes" {
    var store = SecretStore{};
    store.install(try Secret.init(.application, .write, "app-secret"));
    const stored = store.get(.application, .write).?;
    try testing.expectEqualStrings("app-secret", stored.slice());

    var standalone = try Secret.init(.application, .write, "wipe-me");
    SecretStore.wipe(&standalone);
    try testing.expectEqual(@as(usize, 0), standalone.len);
    for (standalone.bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);

    store.discard(.application);
    try testing.expect(store.get(.application, .write) == null);
}

test "adapter queues outbound TLS handshake bytes as CRYPTO stream data" {
    var adapter = QuicTlsAdapter{};

    try adapter.queueHandshakeOutput(.initial, "client");
    try adapter.queueHandshakeOutput(.initial, " hello");
    try adapter.queueHandshakeOutput(.handshake, "server");

    const first = (try adapter.nextHandshakeOutput(.initial, 6)).?;
    try testing.expectEqual(EncryptionLevel.initial, first.level);
    try testing.expectEqual(@as(u64, 0), first.offset);
    try testing.expectEqualStrings("client", first.bytes);

    const second = (try adapter.nextHandshakeOutput(.initial, 32)).?;
    try testing.expectEqual(@as(u64, 6), second.offset);
    try testing.expectEqualStrings(" hello", second.bytes);
    try testing.expect((try adapter.nextHandshakeOutput(.initial, 1)) == null);

    const handshake = (try adapter.nextHandshakeOutput(.handshake, 32)).?;
    try testing.expectEqual(EncryptionLevel.handshake, handshake.level);
    try testing.expectEqual(@as(u64, 0), handshake.offset);
    try testing.expectEqualStrings("server", handshake.bytes);
}

test "0-RTT secrets are allowed but CRYPTO streams reject zero_rtt level" {
    var adapter = QuicTlsAdapter{};
    adapter.installSecret(try Secret.init(.zero_rtt, .read, "early-data-secret"));
    try testing.expectEqualStrings("early-data-secret", adapter.secret(.zero_rtt, .read).?.slice());

    try testing.expectError(error.InvalidCryptoLevel, adapter.receiveCrypto(.zero_rtt, 0, "bad"));
    try testing.expectError(error.InvalidCryptoLevel, adapter.queueHandshakeOutput(.zero_rtt, "bad"));
    try testing.expectError(error.InvalidCryptoLevel, adapter.nextHandshakeInput(.zero_rtt));
    try testing.expectError(error.InvalidCryptoLevel, adapter.nextHandshakeOutput(.zero_rtt, 1));
}

test {
    std.testing.refAllDecls(@This());
}
