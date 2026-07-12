//! TLS 1.3 record protection and deprotection.
//!
//! This layer sits above `record_codec`: the codec owns TLSPlaintext,
//! TLSCiphertext, and TLSInnerPlaintext framing, while this module owns traffic
//! key derivation, per-record nonces, sequence accounting, and AEAD use through
//! the shared crypto-provider boundary.

const std = @import("std");
const crypto = @import("crypto");
const algorithms = @import("algorithms.zig");
const record_codec = @import("record_codec.zig");

const provider = crypto.provider;
const secrets = crypto.secrets;

pub const Error = record_codec.Error || provider.HkdfError || provider.SealError || provider.OpenError || error{
    InvalidTrafficSecretLength,
    SequenceExhausted,
};

const KeySecret = secrets.FixedSecret(provider.max_aead_key_len);
const IvSecret = secrets.FixedSecret(provider.aead_nonce_len);

pub const SuiteProfile = struct {
    cipher_suite: algorithms.CipherSuite,
    hash: provider.Hash,
    aead: provider.Aead,
};

pub fn suiteProfile(cipher_suite: algorithms.CipherSuite) SuiteProfile {
    return switch (cipher_suite) {
        .tls_aes_128_gcm_sha256 => .{ .cipher_suite = cipher_suite, .hash = .sha256, .aead = .aes_128_gcm },
        .tls_aes_256_gcm_sha384 => .{ .cipher_suite = cipher_suite, .hash = .sha384, .aead = .aes_256_gcm },
        .tls_chacha20_poly1305_sha256 => .{ .cipher_suite = cipher_suite, .hash = .sha256, .aead = .chacha20_poly1305 },
    };
}

pub const TrafficKeys = struct {
    profile: SuiteProfile,
    key: KeySecret = .{},
    iv: IvSecret = .{},

    pub fn derive(crypto_provider: provider.CryptoProvider, cipher_suite: algorithms.CipherSuite, traffic_secret: []const u8) Error!TrafficKeys {
        const profile = suiteProfile(cipher_suite);
        if (traffic_secret.len != profile.hash.digestLength()) return error.InvalidTrafficSecretLength;
        const caps = crypto_provider.capabilities();
        if (!caps.supportsHash(profile.hash)) return error.UnsupportedCapability;
        if (!caps.supportsAead(profile.aead)) return error.UnsupportedCapability;

        var key_bytes: [provider.max_aead_key_len]u8 = undefined;
        defer provider.secureZero(&key_bytes);
        var iv_bytes: [provider.aead_nonce_len]u8 = undefined;
        defer provider.secureZero(&iv_bytes);

        try crypto_provider.hkdfExpandLabel(profile.hash, traffic_secret, "key", "", key_bytes[0..profile.aead.keyLength()]);
        try crypto_provider.hkdfExpandLabel(profile.hash, traffic_secret, "iv", "", &iv_bytes);

        var out = TrafficKeys{ .profile = profile };
        errdefer out.deinit();
        out.key.replace(key_bytes[0..profile.aead.keyLength()]) catch unreachable;
        out.iv.replace(&iv_bytes) catch unreachable;
        return out;
    }

    pub fn deinit(self: *TrafficKeys) void {
        self.key.deinit();
        self.iv.deinit();
    }
};

pub const WriteState = struct {
    crypto_provider: provider.CryptoProvider,
    keys: TrafficKeys,
    sequence: u64 = 0,
    exhausted: bool = false,

    pub fn init(crypto_provider: provider.CryptoProvider, keys: TrafficKeys) WriteState {
        return .{ .crypto_provider = crypto_provider, .keys = keys };
    }

    pub fn deinit(self: *WriteState) void {
        self.keys.deinit();
        self.sequence = 0;
        self.exhausted = true;
    }

    pub fn seal(self: *WriteState, content_type: record_codec.ContentType, plaintext: []const u8, padding_len: usize, out: []u8) Error![]const u8 {
        if (self.exhausted) return error.SequenceExhausted;

        var inner_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        defer provider.secureZero(&inner_buf);
        const inner = try record_codec.encodeInnerPlaintext(content_type, plaintext, padding_len, &inner_buf);
        const payload_len = inner.len + self.keys.profile.aead.tagLength();
        if (payload_len > record_codec.max_ciphertext_fragment_len) return error.RecordTooLarge;
        if (out.len < record_codec.header_len + payload_len) return error.RecordBufferOverflow;

        writeCiphertextHeader(payload_len, out[0..record_codec.header_len]);
        var nonce = nonceFor(self.keys.iv.slice(), self.sequence);
        defer provider.secureZero(&nonce);

        const ciphertext = out[record_codec.header_len..][0..inner.len];
        const tag = out[record_codec.header_len + inner.len ..][0..self.keys.profile.aead.tagLength()];
        try self.crypto_provider.aeadSeal(self.keys.profile.aead, self.keys.key.slice(), &nonce, out[0..record_codec.header_len], inner, ciphertext, tag);
        self.advanceSequence();
        return out[0 .. record_codec.header_len + payload_len];
    }

    fn advanceSequence(self: *WriteState) void {
        if (self.sequence == std.math.maxInt(u64)) {
            self.exhausted = true;
        } else {
            self.sequence += 1;
        }
    }
};

pub const ReadState = struct {
    crypto_provider: provider.CryptoProvider,
    keys: TrafficKeys,
    sequence: u64 = 0,
    exhausted: bool = false,

    pub fn init(crypto_provider: provider.CryptoProvider, keys: TrafficKeys) ReadState {
        return .{ .crypto_provider = crypto_provider, .keys = keys };
    }

    pub fn deinit(self: *ReadState) void {
        self.keys.deinit();
        self.sequence = 0;
        self.exhausted = true;
    }

    pub fn open(self: *ReadState, record: record_codec.TLSCiphertext, out: []u8) Error!record_codec.InnerPlaintext {
        if (self.exhausted) return error.SequenceExhausted;
        if (record.content_type != .application_data) return error.InvalidRecordType;
        if (record.legacy_version != record_codec.legacy_record_version) return error.InvalidRecordVersion;
        if (record.payload.len > record_codec.max_ciphertext_fragment_len) return error.RecordTooLarge;

        const tag_len = self.keys.profile.aead.tagLength();
        if (record.payload.len < tag_len) return error.MalformedInnerPlaintext;
        const ciphertext_len = record.payload.len - tag_len;
        if (out.len < ciphertext_len) return error.RecordBufferOverflow;

        var ad: [record_codec.header_len]u8 = undefined;
        writeCiphertextHeader(record.payload.len, &ad);
        var nonce = nonceFor(self.keys.iv.slice(), self.sequence);
        defer provider.secureZero(&nonce);

        const ciphertext = record.payload[0..ciphertext_len];
        const tag = record.payload[ciphertext_len..];
        const plaintext = out[0..ciphertext_len];
        try self.crypto_provider.aeadOpen(self.keys.profile.aead, self.keys.key.slice(), &nonce, &ad, ciphertext, tag, plaintext);
        const inner = record_codec.decodeInnerPlaintext(plaintext) catch |err| {
            provider.secureZero(plaintext);
            return err;
        };
        self.advanceSequence();
        return inner;
    }

    fn advanceSequence(self: *ReadState) void {
        if (self.sequence == std.math.maxInt(u64)) {
            self.exhausted = true;
        } else {
            self.sequence += 1;
        }
    }
};

fn writeCiphertextHeader(payload_len: usize, out: []u8) void {
    std.debug.assert(out.len == record_codec.header_len);
    std.debug.assert(payload_len <= record_codec.max_ciphertext_fragment_len);
    out[0] = @intFromEnum(record_codec.ContentType.application_data);
    std.mem.writeInt(u16, out[1..3], record_codec.legacy_record_version, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(payload_len), .big);
}

fn nonceFor(iv: []const u8, sequence: u64) [provider.aead_nonce_len]u8 {
    std.debug.assert(iv.len == provider.aead_nonce_len);
    var nonce: [provider.aead_nonce_len]u8 = undefined;
    @memcpy(&nonce, iv);
    var seq_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seq_bytes, sequence, .big);
    for (seq_bytes, 0..) |byte, i| {
        nonce[nonce.len - seq_bytes.len + i] ^= byte;
    }
    return nonce;
}

fn parsedCiphertext(bytes: []const u8) !record_codec.TLSCiphertext {
    if (bytes.len < record_codec.header_len) return error.TruncatedRecord;
    const header = try record_codec.parseHeader(bytes[0..record_codec.header_len], .ciphertext);
    const record_len = record_codec.header_len + header.payload_len;
    if (bytes.len != record_len) return error.TruncatedRecord;
    return .{
        .content_type = header.content_type,
        .legacy_version = header.legacy_version,
        .payload = bytes[record_codec.header_len..record_len],
    };
}

fn testProvider() provider.CryptoProvider {
    const pure_zig = crypto.pure_zig;
    const State = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x351);
        var provider_state = pure_zig.Provider.init(entropy.entropy());
    };
    return State.provider_state.cryptoProvider();
}

fn trafficSecret(comptime hash: provider.Hash, fill: u8) [hash.digestLength()]u8 {
    return [_]u8{fill} ** hash.digestLength();
}

test "traffic key derivation matches TLS 1.3 labels" {
    const cp = testProvider();
    const keys = try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &trafficSecret(.sha256, 0x11));
    var owned = keys;
    defer owned.deinit();

    const std_crypto = std.crypto;
    const HkdfSha256 = std_crypto.kdf.hkdf.HkdfSha256;
    const secret = trafficSecret(.sha256, 0x11);
    const expected_key = std_crypto.tls.hkdfExpandLabel(HkdfSha256, secret, "key", "", 16);
    const expected_iv = std_crypto.tls.hkdfExpandLabel(HkdfSha256, secret, "iv", "", provider.aead_nonce_len);

    try std.testing.expectEqualSlices(u8, &expected_key, owned.key.slice());
    try std.testing.expectEqualSlices(u8, &expected_iv, owned.iv.slice());
}

test "traffic key derivation enforces traffic-secret length" {
    const cp = testProvider();
    const short = [_]u8{0x11} ** 31;
    const long = [_]u8{0x22} ** 33;
    try std.testing.expectError(error.InvalidTrafficSecretLength, TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &short));
    try std.testing.expectError(error.InvalidTrafficSecretLength, TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &long));

    const sha384_short = [_]u8{0x33} ** 47;
    const sha384_long = [_]u8{0x44} ** 49;
    try std.testing.expectError(error.InvalidTrafficSecretLength, TrafficKeys.derive(cp, .tls_aes_256_gcm_sha384, &sha384_short));
    try std.testing.expectError(error.InvalidTrafficSecretLength, TrafficKeys.derive(cp, .tls_aes_256_gcm_sha384, &sha384_long));
}

test "record protection round-trips every supported cipher suite" {
    const cp = testProvider();
    inline for (.{
        algorithms.CipherSuite.tls_aes_128_gcm_sha256,
        algorithms.CipherSuite.tls_aes_256_gcm_sha384,
        algorithms.CipherSuite.tls_chacha20_poly1305_sha256,
    }) |suite| {
        const profile = comptime suiteProfile(suite);
        const secret = trafficSecret(profile.hash, @intCast(@intFromEnum(suite) & 0xff));
        var write = WriteState.init(cp, try TrafficKeys.derive(cp, suite, &secret));
        defer write.deinit();
        var read = ReadState.init(cp, try TrafficKeys.derive(cp, suite, &secret));
        defer read.deinit();

        var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = try write.seal(.handshake, "finished", 7, &protected);
        try std.testing.expectEqual(record_codec.ContentType.application_data, @as(record_codec.ContentType, @enumFromInt(record[0])));

        const parsed = try parsedCiphertext(record);
        var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        const inner = try read.open(parsed, &plaintext);
        try std.testing.expectEqual(record_codec.ContentType.handshake, inner.content_type);
        try std.testing.expectEqualStrings("finished", inner.content);
        try std.testing.expectEqual(@as(usize, 7), inner.padding_len);
        try std.testing.expectEqual(@as(u64, 1), write.sequence);
        try std.testing.expectEqual(@as(u64, 1), read.sequence);
    }
}

test "record protection rejects tampering and clears unauthenticated output" {
    const cp = testProvider();
    const secret = trafficSecret(.sha256, 0x22);
    var write = WriteState.init(cp, try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &secret));
    defer write.deinit();
    var read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &secret));
    defer read.deinit();

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record = try write.seal(.application_data, "hello", 0, &protected);
    var tampered: [record_codec.max_ciphertext_record_len]u8 = undefined;
    @memcpy(tampered[0..record.len], record);
    tampered[record.len - 1] ^= 0x80;

    const parsed = try parsedCiphertext(tampered[0..record.len]);
    var plaintext = [_]u8{0xaa} ** 64;
    try std.testing.expectError(error.AuthenticationFailed, read.open(parsed, &plaintext));
    for (plaintext[0 .. parsed.payload.len - provider.aead_tag_len]) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}

test "wrong traffic keys and modified record headers fail safely" {
    const cp = testProvider();
    var write = WriteState.init(cp, try TrafficKeys.derive(cp, .tls_chacha20_poly1305_sha256, &trafficSecret(.sha256, 0x33)));
    defer write.deinit();
    var wrong_read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_chacha20_poly1305_sha256, &trafficSecret(.sha256, 0x44)));
    defer wrong_read.deinit();

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record = try write.seal(.alert, &.{ 1, 0 }, 2, &protected);
    var parsed = try parsedCiphertext(record);

    var plaintext: [64]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, wrong_read.open(parsed, &plaintext));

    var good_read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_chacha20_poly1305_sha256, &trafficSecret(.sha256, 0x33)));
    defer good_read.deinit();
    parsed.legacy_version = 0x0301;
    try std.testing.expectError(error.InvalidRecordVersion, good_read.open(parsed, &plaintext));
}

test "all-zero inner plaintext fails closed after successful authentication" {
    const cp = testProvider();
    const secret = trafficSecret(.sha256, 0x55);
    var keys = try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &secret);
    defer keys.deinit();

    const inner = [_]u8{0} ** 3;
    const payload_len = inner.len + provider.aead_tag_len;
    var encoded: [record_codec.header_len + payload_len]u8 = undefined;
    writeCiphertextHeader(payload_len, encoded[0..record_codec.header_len]);
    var nonce = nonceFor(keys.iv.slice(), 0);
    defer provider.secureZero(&nonce);
    try cp.aeadSeal(.aes_128_gcm, keys.key.slice(), &nonce, encoded[0..record_codec.header_len], &inner, encoded[record_codec.header_len..][0..inner.len], encoded[record_codec.header_len + inner.len ..]);

    var read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &secret));
    defer read.deinit();
    const parsed = try parsedCiphertext(&encoded);
    var plaintext = [_]u8{0xaa} ** 16;
    try std.testing.expectError(error.MalformedInnerPlaintext, read.open(parsed, &plaintext));
    for (plaintext[0..inner.len]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "record protection allows final sequence number then reports exhaustion" {
    const cp = testProvider();
    const secret = trafficSecret(.sha256, 0x66);
    var write = WriteState.init(cp, try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &secret));
    defer write.deinit();
    write.sequence = std.math.maxInt(u64) - 1;

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    _ = try write.seal(.application_data, "x", 0, &protected);
    try std.testing.expectEqual(std.math.maxInt(u64), write.sequence);
    try std.testing.expect(!write.exhausted);

    const final_record = try write.seal(.application_data, "y", 0, &protected);
    try std.testing.expectEqual(std.math.maxInt(u64), write.sequence);
    try std.testing.expect(write.exhausted);
    try std.testing.expectError(error.SequenceExhausted, write.seal(.application_data, "z", 0, &protected));

    var read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &secret));
    defer read.deinit();
    read.sequence = std.math.maxInt(u64);
    const parsed = try parsedCiphertext(final_record);
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const inner = try read.open(parsed, &plaintext);
    try std.testing.expectEqualStrings("y", inner.content);
    try std.testing.expect(read.exhausted);
    try std.testing.expectError(error.SequenceExhausted, read.open(parsed, &plaintext));
}
