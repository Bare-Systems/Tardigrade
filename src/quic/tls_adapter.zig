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
//! Status: foundation slice — adapter contract and CRYPTO reassembly are in
//! place. Backend TLS driving, packet/header protection, and key updates land
//! in later #249 slices.

const std = @import("std");
const config = @import("config.zig");

pub const max_crypto_buffer = 64 * 1024;
pub const max_crypto_ranges = 32;
pub const max_handshake_record = 16 * 1024;
pub const max_secret_len = 64;

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

pub const PacketNumberSpace = enum {
    initial,
    handshake,
    application,
};

pub const Direction = enum {
    read,
    write,
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
            .read => self.read[secret.level.index()] = secret,
            .write => self.write[secret.level.index()] = secret,
        }
    }

    pub fn get(self: *const SecretStore, level: EncryptionLevel, direction: Direction) ?Secret {
        return switch (direction) {
            .read => self.read[level.index()],
            .write => self.write[level.index()],
        };
    }

    pub fn discard(self: *SecretStore, level: EncryptionLevel) void {
        self.read[level.index()] = null;
        self.write[level.index()] = null;
    }
};

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
        if (offset > max_crypto_buffer) return error.CryptoBufferTooLarge;
        const end = offset + data.len;
        if (end > max_crypto_buffer) return error.CryptoBufferTooLarge;

        @memcpy(self.buffer[@intCast(offset)..@intCast(end)], data);
        try self.addRange(.{ .start = offset, .end = end });
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

    fn addRange(self: *CryptoStream, new_range: ByteRange) error{TooManyCryptoRanges}!void {
        if (self.range_count == max_crypto_ranges) return error.TooManyCryptoRanges;
        self.ranges[self.range_count] = new_range;
        self.range_count += 1;
        self.sortRanges();
        self.mergeRanges();
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

    fn sortRanges(self: *CryptoStream) void {
        var i: usize = 1;
        while (i < self.range_count) : (i += 1) {
            const current = self.ranges[i];
            var j = i;
            while (j > 0 and self.ranges[j - 1].start > current.start) : (j -= 1) {
                self.ranges[j] = self.ranges[j - 1];
            }
            self.ranges[j] = current;
        }
    }

    fn mergeRanges(self: *CryptoStream) void {
        if (self.range_count <= 1) return;
        var out: usize = 0;
        var index: usize = 1;
        while (index < self.range_count) : (index += 1) {
            const next = self.ranges[index];
            if (next.start <= self.ranges[out].end) {
                self.ranges[out].end = @max(self.ranges[out].end, next.end);
            } else {
                out += 1;
                self.ranges[out] = next;
            }
        }
        self.range_count = out + 1;
    }
};

pub const CryptoReassembler = struct {
    streams: [4]CryptoStream = .{ .{}, .{}, .{}, .{} },

    pub fn insert(self: *CryptoReassembler, level: EncryptionLevel, offset: u64, data: []const u8) error{ CryptoBufferTooLarge, TooManyCryptoRanges }!void {
        try self.streams[level.index()].insert(offset, data);
    }

    pub fn contiguous(self: *const CryptoReassembler, level: EncryptionLevel) []const u8 {
        return self.streams[level.index()].contiguous();
    }

    pub fn consumeContiguous(self: *CryptoReassembler, level: EncryptionLevel) []const u8 {
        return self.streams[level.index()].consumeContiguous();
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

    pub fn receiveCrypto(self: *QuicTlsAdapter, level: EncryptionLevel, offset: u64, data: []const u8) error{ CryptoBufferTooLarge, TooManyCryptoRanges }!void {
        try self.reassembler.insert(level, offset, data);
    }

    pub fn nextHandshakeInput(self: *QuicTlsAdapter, level: EncryptionLevel) ?HandshakeInput {
        const bytes = self.reassembler.consumeContiguous(level);
        if (bytes.len == 0) return null;
        return .{ .level = level, .bytes = bytes };
    }

    pub fn queueHandshakeOutput(self: *QuicTlsAdapter, level: EncryptionLevel, bytes: []const u8) error{CryptoBufferTooLarge}!void {
        try self.outbound[level.index()].append(bytes);
    }

    pub fn nextHandshakeOutput(self: *QuicTlsAdapter, level: EncryptionLevel, max_bytes: usize) ?HandshakeOutput {
        if (max_bytes == 0) return null;
        const output = self.outbound[level.index()].take(max_bytes) orelse return null;
        return .{ .level = level, .offset = output.offset, .bytes = output.bytes };
    }

    pub fn installSecret(self: *QuicTlsAdapter, installed_secret: Secret) void {
        self.secrets.install(installed_secret);
    }

    pub fn secret(self: *const QuicTlsAdapter, level: EncryptionLevel, direction: Direction) ?Secret {
        return self.secrets.get(level, direction);
    }

    pub fn discardSecrets(self: *QuicTlsAdapter, level: EncryptionLevel) void {
        self.secrets.discard(level);
    }

    pub fn markAlpn(self: *QuicTlsAdapter, protocol: []const u8) void {
        self.alpn_h3 = std.mem.eql(u8, protocol, "h3");
    }
};

const testing = std.testing;

test "encryption levels map to QUIC packet number spaces" {
    try testing.expectEqual(PacketNumberSpace.initial, EncryptionLevel.initial.packetNumberSpace());
    try testing.expectEqual(PacketNumberSpace.handshake, EncryptionLevel.handshake.packetNumberSpace());
    try testing.expectEqual(PacketNumberSpace.application, EncryptionLevel.zero_rtt.packetNumberSpace());
    try testing.expectEqual(PacketNumberSpace.application, EncryptionLevel.application.packetNumberSpace());
}

test "CRYPTO reassembly emits only contiguous bytes by encryption level" {
    var reassembler = CryptoReassembler{};

    try reassembler.insert(.initial, 6, "world");
    try testing.expectEqual(@as(usize, 0), reassembler.contiguous(.initial).len);

    try reassembler.insert(.handshake, 0, "other");
    try testing.expectEqualStrings("other", reassembler.consumeContiguous(.handshake));

    try reassembler.insert(.initial, 0, "hello ");
    try testing.expectEqualStrings("hello world", reassembler.consumeContiguous(.initial));
    try testing.expectEqual(@as(usize, 0), reassembler.consumeContiguous(.initial).len);
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

test "adapter tracks transport parameters ALPN secrets and handshake input" {
    var adapter = QuicTlsAdapter{};
    const params = try (config.Config{}).transportParameters();
    adapter.setLocalTransportParameters(params);
    try testing.expect(adapter.local_transport_parameters != null);

    adapter.markAlpn("h3");
    try testing.expect(adapter.alpn_h3);

    const read_secret = try Secret.init(.handshake, .read, "read-secret");
    adapter.installSecret(read_secret);
    try testing.expectEqualStrings("read-secret", adapter.secret(.handshake, .read).?.slice());
    adapter.discardSecrets(.handshake);
    try testing.expect(adapter.secret(.handshake, .read) == null);

    try adapter.receiveCrypto(.initial, 4, "lo");
    try adapter.receiveCrypto(.initial, 0, "hel");
    const first_input = adapter.nextHandshakeInput(.initial).?;
    try testing.expectEqual(EncryptionLevel.initial, first_input.level);
    try testing.expectEqualStrings("hel", first_input.bytes);
    try adapter.receiveCrypto(.initial, 3, "l");
    const input = adapter.nextHandshakeInput(.initial).?;
    try testing.expectEqual(EncryptionLevel.initial, input.level);
    try testing.expectEqualStrings("llo", input.bytes);
}

test "adapter queues outbound TLS handshake bytes as CRYPTO stream data" {
    var adapter = QuicTlsAdapter{};

    try adapter.queueHandshakeOutput(.initial, "client");
    try adapter.queueHandshakeOutput(.initial, " hello");
    try adapter.queueHandshakeOutput(.handshake, "server");

    const first = adapter.nextHandshakeOutput(.initial, 6).?;
    try testing.expectEqual(EncryptionLevel.initial, first.level);
    try testing.expectEqual(@as(u64, 0), first.offset);
    try testing.expectEqualStrings("client", first.bytes);

    const second = adapter.nextHandshakeOutput(.initial, 32).?;
    try testing.expectEqual(@as(u64, 6), second.offset);
    try testing.expectEqualStrings(" hello", second.bytes);
    try testing.expect(adapter.nextHandshakeOutput(.initial, 1) == null);

    const handshake = adapter.nextHandshakeOutput(.handshake, 32).?;
    try testing.expectEqual(EncryptionLevel.handshake, handshake.level);
    try testing.expectEqual(@as(u64, 0), handshake.offset);
    try testing.expectEqualStrings("server", handshake.bytes);
}

test {
    std.testing.refAllDecls(@This());
}
