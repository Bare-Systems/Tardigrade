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
    const header = try record_codec.parseHeader(bytes[0..record_codec.header_len], .ciphertext, .strict);
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

// The following three tests cross-check TrafficKeys.derive, WriteState.seal,
// and ReadState.open against vectors computed by an independent, non-Zig
// implementation (RFC 5869 HKDF-Extract/Expand and RFC 8446 SS7.1 HKDF-
// Expand-Label from Python's stdlib hmac/hashlib; AEAD sealing via
// pycryptodome), so a bug shared between this module's seal and open paths
// (e.g. in AAD, nonce, or inner-plaintext construction) cannot hide behind a
// self-consistent round trip the way the round-trip test above would allow
// (#408 finding 7). The HKDF outputs were separately cross-checked against
// Zig's own std.crypto.tls.hkdfExpandLabel.

test "record protection matches independently computed AES-128-GCM known-answer vectors" {
    const cp = testProvider();

    {
        const secret = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
        const keys = try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, secret);
        var owned = keys;
        defer owned.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x28, 0x59, 0x6a, 0x23, 0x0c, 0x2c, 0x30, 0xa9, 0x52, 0xfe, 0x79, 0x48, 0x35, 0x68, 0xe1, 0x8e }, owned.key.slice());
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfc, 0x73, 0xb5, 0x22, 0xc6, 0x80, 0x9e, 0x02, 0x8f, 0x92, 0x2c, 0x68 }, owned.iv.slice());

        var write = WriteState.init(cp, try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, secret));
        defer write.deinit();
        write.sequence = 0;
        var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = try write.seal(.handshake, "server finished record", 4, &protected);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x2b, 0x09, 0xa0, 0x8c, 0x28, 0x1b, 0x14, 0x7b, 0x36, 0xe2, 0x77, 0xf6, 0xac, 0x67, 0x1c, 0xcd, 0x9c, 0xbc, 0x6c, 0x47, 0x9d, 0x90, 0x3c, 0xc2, 0x80, 0x5a, 0xda, 0x89, 0x81, 0xb6, 0x95, 0x79, 0x07, 0x4a, 0xaa, 0xd5, 0x0b, 0x62, 0x0a, 0xb1, 0x44, 0xa6, 0x02, 0x2e }, record);

        var read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, secret));
        defer read.deinit();
        read.sequence = 0;
        const parsed = try parsedCiphertext(record);
        var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        const inner = try read.open(parsed, &plaintext);
        try std.testing.expectEqual(record_codec.ContentType.handshake, inner.content_type);
        try std.testing.expectEqualStrings("server finished record", inner.content);
        try std.testing.expectEqual(@as(usize, 4), inner.padding_len);
    }
    {
        const secret = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
        const keys = try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, secret);
        var owned = keys;
        defer owned.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x28, 0x59, 0x6a, 0x23, 0x0c, 0x2c, 0x30, 0xa9, 0x52, 0xfe, 0x79, 0x48, 0x35, 0x68, 0xe1, 0x8e }, owned.key.slice());
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfc, 0x73, 0xb5, 0x22, 0xc6, 0x80, 0x9e, 0x02, 0x8f, 0x92, 0x2c, 0x68 }, owned.iv.slice());

        var write = WriteState.init(cp, try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, secret));
        defer write.deinit();
        write.sequence = 1;
        var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = try write.seal(.application_data, "GET / HTTP/1.1\r\n\r\n", 0, &protected);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x23, 0x1f, 0x89, 0x45, 0x6a, 0xf7, 0xd4, 0x31, 0x2d, 0xdd, 0xdc, 0x0f, 0xb4, 0x05, 0x0c, 0xc5, 0xfc, 0x07, 0x9c, 0x22, 0x59, 0x7b, 0x03, 0x92, 0xfd, 0x69, 0xf0, 0x16, 0x00, 0xdb, 0xae, 0x1c, 0xfe, 0x6a, 0x15, 0x64 }, record);

        var read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, secret));
        defer read.deinit();
        read.sequence = 1;
        const parsed = try parsedCiphertext(record);
        var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        const inner = try read.open(parsed, &plaintext);
        try std.testing.expectEqual(record_codec.ContentType.application_data, inner.content_type);
        try std.testing.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", inner.content);
        try std.testing.expectEqual(@as(usize, 0), inner.padding_len);
    }
}

test "record protection matches independently computed AES-256-GCM known-answer vectors" {
    const cp = testProvider();

    {
        const secret = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30 };
        const keys = try TrafficKeys.derive(cp, .tls_aes_256_gcm_sha384, secret);
        var owned = keys;
        defer owned.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xab, 0x56, 0xe7, 0xea, 0x07, 0xea, 0xef, 0x99, 0x98, 0x6a, 0x0f, 0x0a, 0xcc, 0xb5, 0x8f, 0x3a, 0xc7, 0xdb, 0x5c, 0xe3, 0x22, 0x19, 0x6d, 0x96, 0x67, 0x72, 0x2e, 0xd2, 0xa6, 0x3d, 0x8a, 0x64 }, owned.key.slice());
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfc, 0x4d, 0xc8, 0x7e, 0x05, 0xfa, 0x43, 0x37, 0xdb, 0x00, 0xad, 0x3d }, owned.iv.slice());

        var write = WriteState.init(cp, try TrafficKeys.derive(cp, .tls_aes_256_gcm_sha384, secret));
        defer write.deinit();
        write.sequence = 0;
        var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = try write.seal(.application_data, "application data over aes256gcm", 0, &protected);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x30, 0x91, 0x7f, 0x13, 0x52, 0xe8, 0x84, 0xa4, 0x46, 0xbf, 0xce, 0xc1, 0x3a, 0x32, 0x68, 0x69, 0x41, 0xae, 0x20, 0xd9, 0xfa, 0x4e, 0x8f, 0xdb, 0xa7, 0x3b, 0x2b, 0x1b, 0x7c, 0xf5, 0x77, 0x02, 0x32, 0xa4, 0x89, 0x9d, 0x4d, 0x7a, 0xce, 0xc2, 0x1e, 0x58, 0x64, 0x0b, 0xc5, 0x15, 0x01, 0x68, 0x99 }, record);

        var read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_aes_256_gcm_sha384, secret));
        defer read.deinit();
        read.sequence = 0;
        const parsed = try parsedCiphertext(record);
        var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        const inner = try read.open(parsed, &plaintext);
        try std.testing.expectEqual(record_codec.ContentType.application_data, inner.content_type);
        try std.testing.expectEqualStrings("application data over aes256gcm", inner.content);
        try std.testing.expectEqual(@as(usize, 0), inner.padding_len);
    }
    {
        const secret = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30 };
        const keys = try TrafficKeys.derive(cp, .tls_aes_256_gcm_sha384, secret);
        var owned = keys;
        defer owned.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xab, 0x56, 0xe7, 0xea, 0x07, 0xea, 0xef, 0x99, 0x98, 0x6a, 0x0f, 0x0a, 0xcc, 0xb5, 0x8f, 0x3a, 0xc7, 0xdb, 0x5c, 0xe3, 0x22, 0x19, 0x6d, 0x96, 0x67, 0x72, 0x2e, 0xd2, 0xa6, 0x3d, 0x8a, 0x64 }, owned.key.slice());
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfc, 0x4d, 0xc8, 0x7e, 0x05, 0xfa, 0x43, 0x37, 0xdb, 0x00, 0xad, 0x3d }, owned.iv.slice());

        var write = WriteState.init(cp, try TrafficKeys.derive(cp, .tls_aes_256_gcm_sha384, secret));
        defer write.deinit();
        write.sequence = 257;
        var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = try write.seal(.application_data, "second record", 3, &protected);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x21, 0x91, 0x35, 0x5f, 0x2d, 0xf6, 0x9b, 0xa9, 0xbf, 0xea, 0x47, 0xe6, 0x86, 0x41, 0xdb, 0x85, 0x4a, 0xc3, 0x22, 0x99, 0x74, 0x98, 0x90, 0x81, 0x70, 0x2c, 0x66, 0x84, 0x27, 0xc8, 0xfc, 0x68, 0x13, 0x92 }, record);

        var read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_aes_256_gcm_sha384, secret));
        defer read.deinit();
        read.sequence = 257;
        const parsed = try parsedCiphertext(record);
        var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        const inner = try read.open(parsed, &plaintext);
        try std.testing.expectEqual(record_codec.ContentType.application_data, inner.content_type);
        try std.testing.expectEqualStrings("second record", inner.content);
        try std.testing.expectEqual(@as(usize, 3), inner.padding_len);
    }
}

test "record protection matches independently computed ChaCha20-Poly1305 known-answer vectors" {
    const cp = testProvider();

    {
        const secret = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
        const keys = try TrafficKeys.derive(cp, .tls_chacha20_poly1305_sha256, secret);
        var owned = keys;
        defer owned.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xdb, 0x41, 0xe1, 0xe1, 0xdf, 0xca, 0x2c, 0x28, 0x6e, 0x8b, 0x26, 0x07, 0x08, 0x50, 0x7e, 0xc4, 0x43, 0x64, 0x03, 0x14, 0x51, 0x31, 0x51, 0xbe, 0x46, 0x57, 0x4c, 0xdf, 0x06, 0x1f, 0xb8, 0x16 }, owned.key.slice());
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfc, 0x73, 0xb5, 0x22, 0xc6, 0x80, 0x9e, 0x02, 0x8f, 0x92, 0x2c, 0x68 }, owned.iv.slice());

        var write = WriteState.init(cp, try TrafficKeys.derive(cp, .tls_chacha20_poly1305_sha256, secret));
        defer write.deinit();
        write.sequence = 0;
        var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = try write.seal(.handshake, "chacha finished body", 0, &protected);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x25, 0x73, 0x6e, 0xc3, 0xc0, 0x68, 0x88, 0x4c, 0x94, 0xa3, 0x50, 0x90, 0x8d, 0x22, 0x7d, 0xe4, 0xbc, 0x24, 0xf0, 0x62, 0x2c, 0xc4, 0xdb, 0x8d, 0x60, 0xd0, 0x7f, 0x74, 0xc4, 0x00, 0xf3, 0x35, 0x8e, 0x42, 0xdd, 0x1b, 0xa2, 0xea }, record);

        var read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_chacha20_poly1305_sha256, secret));
        defer read.deinit();
        read.sequence = 0;
        const parsed = try parsedCiphertext(record);
        var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        const inner = try read.open(parsed, &plaintext);
        try std.testing.expectEqual(record_codec.ContentType.handshake, inner.content_type);
        try std.testing.expectEqualStrings("chacha finished body", inner.content);
        try std.testing.expectEqual(@as(usize, 0), inner.padding_len);
    }
    {
        const secret = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
        const keys = try TrafficKeys.derive(cp, .tls_chacha20_poly1305_sha256, secret);
        var owned = keys;
        defer owned.deinit();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xdb, 0x41, 0xe1, 0xe1, 0xdf, 0xca, 0x2c, 0x28, 0x6e, 0x8b, 0x26, 0x07, 0x08, 0x50, 0x7e, 0xc4, 0x43, 0x64, 0x03, 0x14, 0x51, 0x31, 0x51, 0xbe, 0x46, 0x57, 0x4c, 0xdf, 0x06, 0x1f, 0xb8, 0x16 }, owned.key.slice());
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0xfc, 0x73, 0xb5, 0x22, 0xc6, 0x80, 0x9e, 0x02, 0x8f, 0x92, 0x2c, 0x68 }, owned.iv.slice());

        var write = WriteState.init(cp, try TrafficKeys.derive(cp, .tls_chacha20_poly1305_sha256, secret));
        defer write.deinit();
        write.sequence = 9;
        var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = try write.seal(.application_data, "chacha application data", 5, &protected);
        try std.testing.expectEqualSlices(u8, &[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x2d, 0xee, 0xc9, 0x6a, 0xaf, 0x10, 0x12, 0x14, 0xf5, 0x31, 0x78, 0x4d, 0x82, 0x6b, 0x3e, 0x25, 0x34, 0xc5, 0x21, 0x7a, 0x45, 0x41, 0xf3, 0xeb, 0x51, 0xdd, 0x9d, 0xbc, 0x37, 0x10, 0xe5, 0x7f, 0x6c, 0x83, 0x47, 0x7d, 0xca, 0x54, 0xf9, 0xdc, 0x71, 0xb0, 0x60, 0xdb, 0x03, 0x18 }, record);

        var read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_chacha20_poly1305_sha256, secret));
        defer read.deinit();
        read.sequence = 9;
        const parsed = try parsedCiphertext(record);
        var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        const inner = try read.open(parsed, &plaintext);
        try std.testing.expectEqual(record_codec.ContentType.application_data, inner.content_type);
        try std.testing.expectEqualStrings("chacha application data", inner.content);
        try std.testing.expectEqual(@as(usize, 5), inner.padding_len);
    }
}

test "a known-answer record only authenticates at its independently-derived sequence" {
    const cp = testProvider();
    const secret = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    // The seq=1 known-answer record from above: its nonce is only correct
    // when the sequence counter matches, so a reader at any other sequence
    // must fail closed even though the key material is otherwise correct.
    const record = &[_]u8{ 0x17, 0x03, 0x03, 0x00, 0x23, 0x1f, 0x89, 0x45, 0x6a, 0xf7, 0xd4, 0x31, 0x2d, 0xdd, 0xdc, 0x0f, 0xb4, 0x05, 0x0c, 0xc5, 0xfc, 0x07, 0x9c, 0x22, 0x59, 0x7b, 0x03, 0x92, 0xfd, 0x69, 0xf0, 0x16, 0x00, 0xdb, 0xae, 0x1c, 0xfe, 0x6a, 0x15, 0x64 };
    const parsed = try parsedCiphertext(record);

    var read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, secret));
    defer read.deinit();
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, read.open(parsed, &plaintext));
    for (plaintext[0 .. parsed.payload.len - provider.aead_tag_len]) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }

    read.sequence = 1;
    const inner = try read.open(parsed, &plaintext);
    try std.testing.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", inner.content);
}

test "record protection teardown zeroizes keys, resets sequence, and marks state exhausted" {
    const cp = testProvider();
    const secret = trafficSecret(.sha384, 0x77);
    var keys = try TrafficKeys.derive(cp, .tls_aes_256_gcm_sha384, &secret);
    try std.testing.expect(keys.key.len > 0);
    try std.testing.expect(keys.iv.len > 0);
    keys.deinit();
    try expectSecretsCleared(&keys);
    // Repeated teardown is safe and idempotent.
    keys.deinit();
    try expectSecretsCleared(&keys);

    var write = WriteState.init(cp, try TrafficKeys.derive(cp, .tls_aes_256_gcm_sha384, &secret));
    write.sequence = 1234;
    write.deinit();
    try expectSecretsCleared(&write.keys);
    try std.testing.expectEqual(@as(u64, 0), write.sequence);
    try std.testing.expect(write.exhausted);
    write.deinit();
    try std.testing.expect(write.exhausted);

    var read = ReadState.init(cp, try TrafficKeys.derive(cp, .tls_aes_256_gcm_sha384, &secret));
    read.sequence = 4321;
    read.deinit();
    try expectSecretsCleared(&read.keys);
    try std.testing.expectEqual(@as(u64, 0), read.sequence);
    try std.testing.expect(read.exhausted);

    // An exhausted state is inert: neither direction can be revived by a
    // caller that kept a pointer to it past teardown.
    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    try std.testing.expectError(error.SequenceExhausted, write.seal(.application_data, "x", 0, &protected));
    try std.testing.expectError(error.SequenceExhausted, read.open(.{
        .content_type = .application_data,
        .legacy_version = record_codec.legacy_record_version,
        .payload = &[_]u8{0} ** (provider.aead_tag_len + 1),
    }, &protected));
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

// -----------------------------------------------------------------------
// #493 fuzz targets and supporting fixtures. See
// docs/CRYPTO_FUZZ_CONTRACT.md's "#493" section for the shared rules these
// follow (fresh provider and state per case, fixed buffers, explicit
// bounds, typed-error classification, sanitized diagnostics).
// -----------------------------------------------------------------------

/// Asserts a `TrafficKeys` has actually been wiped: not just that the
/// borrowed `slice()` view is empty, but that the whole `FixedSecret`
/// backing array is zero, so a shortened `len` cannot hide retained key or
/// IV bytes.
fn expectSecretsCleared(keys: *const TrafficKeys) !void {
    try std.testing.expectEqual(@as(usize, 0), keys.key.len);
    try std.testing.expectEqual(@as(usize, 0), keys.iv.len);
    try std.testing.expect(std.mem.allEqual(u8, &keys.key.bytes, 0));
    try std.testing.expect(std.mem.allEqual(u8, &keys.iv.bytes, 0));
}

/// Test-only provider wrapper that either hides one capability from the
/// reported set or forces one documented typed provider failure.
///
/// `HkdfError` and `SealError` contain only `InvalidInput` and
/// `UnsupportedCapability`; `OpenError` adds `AuthenticationFailed`. Real
/// tampering already reaches `AuthenticationFailed`, and a capability mask
/// reaches `UnsupportedCapability` through `TrafficKeys.derive`'s own
/// preflight, but nothing this module can pass a conforming pure-Zig
/// provider produces `InvalidInput` -- the lengths it hands over are all
/// derived from the suite profile. Rather than invent a generic provider
/// error the record API cannot return, this fixture injects exactly the
/// documented ones at the vtable seam so their propagation and the caller's
/// transactional state can be asserted.
const FaultProvider = struct {
    inner: provider.CryptoProvider,
    masked_hash: ?provider.Hash = null,
    masked_aead: ?provider.Aead = null,
    hkdf_error: ?provider.HkdfError = null,
    seal_error: ?provider.SealError = null,
    open_error: ?provider.OpenError = null,

    fn capabilities(context: *anyopaque) provider.Capabilities {
        const self: *FaultProvider = @ptrCast(@alignCast(context));
        var caps = self.inner.capabilities();
        if (self.masked_hash) |hash| caps.hashes.remove(hash);
        if (self.masked_aead) |aead| caps.aeads.remove(aead);
        return caps;
    }

    fn hkdfExtract(context: *anyopaque, hash: provider.Hash, salt: []const u8, ikm: []const u8, out: []u8) provider.HkdfError!void {
        const self: *FaultProvider = @ptrCast(@alignCast(context));
        if (self.hkdf_error) |err| return err;
        return self.inner.hkdfExtract(hash, salt, ikm, out);
    }

    fn hkdfExpandLabel(
        context: *anyopaque,
        hash: provider.Hash,
        secret_bytes: []const u8,
        label: []const u8,
        hash_context: []const u8,
        out: []u8,
    ) provider.HkdfError!void {
        const self: *FaultProvider = @ptrCast(@alignCast(context));
        if (self.hkdf_error) |err| return err;
        return self.inner.hkdfExpandLabel(hash, secret_bytes, label, hash_context, out);
    }

    fn aeadSeal(
        context: *anyopaque,
        aead: provider.Aead,
        key: []const u8,
        nonce: []const u8,
        associated_data: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: []u8,
    ) provider.SealError!void {
        const self: *FaultProvider = @ptrCast(@alignCast(context));
        if (self.seal_error) |err| return err;
        return self.inner.aeadSeal(aead, key, nonce, associated_data, plaintext, ciphertext, tag);
    }

    fn aeadOpen(
        context: *anyopaque,
        aead: provider.Aead,
        key: []const u8,
        nonce: []const u8,
        associated_data: []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext: []u8,
    ) provider.OpenError!void {
        const self: *FaultProvider = @ptrCast(@alignCast(context));
        if (self.open_error) |err| {
            // A conforming provider never leaves unauthenticated plaintext
            // behind on a failed open (the `aeadOpen` vtable contract), so
            // the fixture must not either -- otherwise the "no plaintext
            // exposure" property would be proven against a fixture that is
            // weaker than the interface it stands in for.
            provider.secureZero(plaintext);
            return err;
        }
        return self.inner.aeadOpen(aead, key, nonce, associated_data, ciphertext, tag, plaintext);
    }

    fn quicHeaderProtectionMask(
        context: *anyopaque,
        hp: provider.QuicHeaderProtection,
        key: []const u8,
        sample: []const u8,
        mask: []u8,
    ) provider.QuicHeaderProtectionError!void {
        const self: *FaultProvider = @ptrCast(@alignCast(context));
        return self.inner.quicHeaderProtectionMask(hp, key, sample, mask);
    }

    fn generateKeyShare(context: *anyopaque, group: provider.Group, public_out: []u8, private_out: []u8) provider.KeyShareError!void {
        const self: *FaultProvider = @ptrCast(@alignCast(context));
        return self.inner.generateKeyShare(group, public_out, private_out);
    }

    fn deriveSharedSecret(
        context: *anyopaque,
        group: provider.Group,
        private_scalar: []const u8,
        peer_public: []const u8,
        out: []u8,
    ) provider.DeriveError!void {
        const self: *FaultProvider = @ptrCast(@alignCast(context));
        return self.inner.deriveSharedSecret(group, private_scalar, peer_public, out);
    }

    fn verify(
        context: *anyopaque,
        scheme: provider.SignatureScheme,
        public_key: []const u8,
        message: []const u8,
        signature: []const u8,
    ) provider.VerifyError!void {
        const self: *FaultProvider = @ptrCast(@alignCast(context));
        return self.inner.verify(scheme, public_key, message, signature);
    }

    fn cryptoProvider(self: *FaultProvider) provider.CryptoProvider {
        const vtable = provider.CryptoProvider.VTable{
            .capabilities = capabilities,
            .hkdfExtract = hkdfExtract,
            .hkdfExpandLabel = hkdfExpandLabel,
            .aeadSeal = aeadSeal,
            .aeadOpen = aeadOpen,
            .quicHeaderProtectionMask = quicHeaderProtectionMask,
            .generateKeyShare = generateKeyShare,
            .deriveSharedSecret = deriveSharedSecret,
            .verify = verify,
        };
        return .{ .context = self, .vtable = &vtable, .entropy = self.inner.entropy };
    }
};

const fuzz_protection_max_content = 64;
const fuzz_protection_max_padding = 32;
const fuzz_protection_sentinel: u8 = 0xa5;

const all_suites = [_]algorithms.CipherSuite{
    .tls_aes_128_gcm_sha256,
    .tls_aes_256_gcm_sha384,
    .tls_chacha20_poly1305_sha256,
};

/// The expected outcome of one `WriteState.seal` call, computed from the
/// generated inputs *before* the call so the fuzz target asserts an exact
/// typed error rather than accepting any rejection. Mirrors `seal`'s
/// documented rejection order: exhausted sequence, then
/// `encodeInnerPlaintext`'s own stages, then the sealed payload's size, then
/// the caller's output capacity.
const SealOracle = union(enum) {
    sequence_exhausted,
    invalid_type,
    too_large,
    output_overflow,
    ok: struct { record_len: usize, payload_len: usize },
};

fn expectedSeal(
    profile: SuiteProfile,
    exhausted: bool,
    content_type: record_codec.ContentType,
    content_len: usize,
    padding_len: usize,
    out_cap: usize,
) SealOracle {
    if (exhausted) return .sequence_exhausted;
    if (content_type == .change_cipher_spec) return .invalid_type;
    if (content_len > record_codec.max_plaintext_fragment_len) return .too_large;
    const with_type = std.math.add(usize, content_len, 1) catch return .too_large;
    const inner_len = std.math.add(usize, with_type, padding_len) catch return .too_large;
    // `seal` gives `encodeInnerPlaintext` a fixed `max_ciphertext_fragment_len`
    // scratch buffer, so the encoder's own capacity stage collapses into this
    // same bound and can never surface as `RecordBufferOverflow` from there.
    if (inner_len > record_codec.max_ciphertext_fragment_len) return .too_large;
    const payload_len = inner_len + profile.aead.tagLength();
    if (payload_len > record_codec.max_ciphertext_fragment_len) return .too_large;
    const record_len = record_codec.header_len + payload_len;
    if (out_cap < record_len) return .output_overflow;
    return .{ .ok = .{ .record_len = record_len, .payload_len = payload_len } };
}

/// Asserts one rejected `open` is transactional: the exact typed error, an
/// unchanged sequence/exhaustion snapshot, and either a fully untouched
/// output buffer (validation and preflight failures, which never reach the
/// AEAD) or a decrypted span that has been zeroed rather than left holding
/// unauthenticated plaintext.
fn expectFailedOpen(
    read: *ReadState,
    record: record_codec.TLSCiphertext,
    out: []u8,
    expected: anyerror,
    zeroes_attempted_span: bool,
) !void {
    const sequence_before = read.sequence;
    const exhausted_before = read.exhausted;
    @memset(out, fuzz_protection_sentinel);

    try std.testing.expectError(expected, read.open(record, out));
    try std.testing.expectEqual(sequence_before, read.sequence);
    try std.testing.expectEqual(exhausted_before, read.exhausted);

    if (zeroes_attempted_span) {
        const ciphertext_len = record.payload.len - read.keys.profile.aead.tagLength();
        try std.testing.expect(allEqualUninstrumented(u8, out[0..ciphertext_len], 0));
        try std.testing.expect(allEqualUninstrumented(u8, out[ciphertext_len..], fuzz_protection_sentinel));
    } else {
        try std.testing.expect(allEqualUninstrumented(u8, out, fuzz_protection_sentinel));
    }
}

/// Sentinel/zero scans over `out` (up to `max_ciphertext_record_len`) are
/// test-only bulk equality checks with no input-dependent coverage signal;
/// coverage instrumentation on their scalar loop otherwise dominates sampled
/// execution time under sustained fuzzing (~52% of `expectFailedOpen` time,
/// #675 campaign finding).
fn allEqualUninstrumented(comptime T: type, slice: []const T, scalar: T) bool {
    @disableInstrumentation();
    return std.mem.allEqual(T, slice, scalar);
}

test "fuzz: TLS record: protection tamper and sequence boundaries preserve authentication state" {
    try std.testing.fuzz({}, fuzzProtectionInput, .{
        .corpus = &.{
            "",
            &[_]u8{0},
            // Leading selector bytes steer the suite / traffic-secret-length /
            // content-type / content-length / padding / capacity / sequence
            // matrices toward their boundary arms.
            &[_]u8{ 0, 1, 0, 0, 1, 1, 0 },
            &[_]u8{ 1, 1, 1, 1, 2, 1, 1 },
            &[_]u8{ 2, 1, 2, 2, 3, 1, 2 },
            &[_]u8{ 0, 0, 0, 3, 4, 0, 3 },
            &[_]u8{ 1, 2, 1, 4, 5, 2, 4 },
            &[_]u8{ 2, 3, 2, 5, 0, 1, 5 },
            &[_]u8{ 0, 1, 3, 1, 1, 1, 4 },
            &[_]u8{ 1, 1, 0, 0, 2, 0, 5 },
            &([_]u8{0} ** 32),
            &([_]u8{0xff} ** 32),
            &([_]u8{ 1, 2, 3, 4, 5 } ** 8),
        },
    });
}

fn fuzzProtectionInput(_: void, smith: *std.testing.Smith) !void {
    const pure_zig = crypto.pure_zig;
    // Per the #493 shared rules, crypto state is constructed fresh inside the
    // callback rather than reusing this module's process-wide `testProvider()`
    // singleton, so no case can observe another case's provider state.
    var entropy = pure_zig.DeterministicEntropy.init(0x493b);
    var provider_state = pure_zig.Provider.init(entropy.entropy());
    const cp = provider_state.cryptoProvider();

    const suite = all_suites[smith.index(all_suites.len)];
    const profile = suiteProfile(suite);
    const digest_len = profile.hash.digestLength();
    const tag_len = profile.aead.tagLength();

    // 1. Traffic-secret length matrix at exact-minus-one/exact/exact-plus-one
    // for whichever of SHA-256/SHA-384 this suite uses. A wrong length must
    // be refused before any key material is derived.
    var secret_buf: [provider.max_digest_len + 1]u8 = undefined;
    var secret_seed: [1]u8 = undefined;
    smith.bytes(&secret_seed);
    for (&secret_buf, 0..) |*byte, i| byte.* = secret_seed[0] ^ @as(u8, @truncate(i));
    const wrong_len: usize = switch (smith.index(3)) {
        0 => digest_len - 1,
        1 => digest_len + 1,
        else => 0,
    };
    try std.testing.expectError(
        error.InvalidTrafficSecretLength,
        TrafficKeys.derive(cp, suite, secret_buf[0..wrong_len]),
    );
    const traffic_secret = secret_buf[0..digest_len];

    // 2. `UnsupportedCapability` is reachable only through `derive`'s
    // capability preflight, so drive it from a masked view of this same
    // provider -- alternating which of the suite's two required capabilities
    // is hidden -- and confirm the unmasked path still works.
    {
        var masked = FaultProvider{ .inner = cp };
        if (smith.index(2) == 0) masked.masked_hash = profile.hash else masked.masked_aead = profile.aead;
        try std.testing.expectError(
            error.UnsupportedCapability,
            TrafficKeys.derive(masked.cryptoProvider(), suite, traffic_secret),
        );
    }

    // 3. Sequence matrix: the ordinary counters plus both ends of the
    // 64-bit exhaustion boundary.
    const initial_sequence: u64 = switch (smith.index(6)) {
        0 => 0,
        1 => 1,
        2 => 255,
        3 => 256,
        4 => std.math.maxInt(u64) - 1,
        else => std.math.maxInt(u64),
    };

    var write = WriteState.init(cp, try TrafficKeys.derive(cp, suite, traffic_secret));
    defer write.deinit();
    var read = ReadState.init(cp, try TrafficKeys.derive(cp, suite, traffic_secret));
    defer read.deinit();
    write.sequence = initial_sequence;
    read.sequence = initial_sequence;

    // 4. Content type, content, padding, and output capacity. Padding
    // carries the size boundaries because it is a scalar the encoder
    // zero-fills: an exact-maximum sealed payload, one past it, and a
    // synthetic near-`usize`-max value are all expressible without an
    // oversized content buffer.
    const valid_types = [_]record_codec.ContentType{ .alert, .handshake, .application_data };
    const content_type: record_codec.ContentType = if (smith.index(8) == 0)
        .change_cipher_spec
    else
        valid_types[smith.index(valid_types.len)];

    var content_buf: [fuzz_protection_max_content]u8 = undefined;
    const content_len = switch (smith.index(4)) {
        0 => 0,
        1 => 1,
        else => smith.index(content_buf.len + 1),
    };
    smith.bytes(content_buf[0..content_len]);

    // The largest padding whose sealed payload still fits the ciphertext
    // fragment limit, given this content length and tag length.
    const max_valid_padding = record_codec.max_ciphertext_fragment_len - tag_len - 1 - content_len;
    const padding_len: usize = switch (smith.index(6)) {
        0 => 0,
        1 => 1,
        2 => max_valid_padding,
        3 => max_valid_padding + 1,
        4 => std.math.maxInt(usize),
        else => smith.index(fuzz_protection_max_padding + 1),
    };

    var out_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const required_len: ?usize = switch (expectedSeal(profile, false, content_type, content_len, padding_len, out_buf.len)) {
        .ok => |ok| ok.record_len,
        else => null,
    };
    const out_cap = switch (smith.index(4)) {
        0 => if (required_len) |len| len else smith.index(out_buf.len + 1),
        1 => if (required_len) |len| (if (len == 0) 0 else len - 1) else smith.index(out_buf.len + 1),
        2 => if (required_len) |len| @min(len + 1, out_buf.len) else smith.index(out_buf.len + 1),
        else => smith.index(out_buf.len + 1),
    };
    const out = out_buf[0..out_cap];
    @memset(out, fuzz_protection_sentinel);

    const seal_oracle = expectedSeal(profile, write.exhausted, content_type, content_len, padding_len, out_cap);
    var plaintext_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;

    switch (seal_oracle) {
        .sequence_exhausted, .invalid_type, .too_large, .output_overflow => {
            const expected: anyerror = switch (seal_oracle) {
                .sequence_exhausted => error.SequenceExhausted,
                .invalid_type => error.InvalidRecordType,
                .too_large => error.RecordTooLarge,
                .output_overflow => error.RecordBufferOverflow,
                .ok => unreachable,
            };
            try std.testing.expectError(expected, write.seal(content_type, content_buf[0..content_len], padding_len, out));
            // A rejected seal is transactional: no sequence advance and not
            // one byte written to the caller's buffer.
            try std.testing.expectEqual(initial_sequence, write.sequence);
            try std.testing.expect(std.mem.allEqual(u8, out, fuzz_protection_sentinel));
        },
        .ok => |ok| {
            const record = try write.seal(content_type, content_buf[0..content_len], padding_len, out);
            try std.testing.expectEqual(ok.record_len, record.len);
            try std.testing.expect(withinRange(out, record));
            // Bytes past the sealed record must still be untouched.
            try std.testing.expect(std.mem.allEqual(u8, out[record.len..], fuzz_protection_sentinel));

            // The header the AEAD authenticated as associated data must be
            // exactly the serialized record header, re-derived here rather
            // than read back from the implementation's own writer.
            try std.testing.expectEqual(@as(u8, @intFromEnum(record_codec.ContentType.application_data)), record[0]);
            try std.testing.expectEqual(record_codec.legacy_record_version, std.mem.readInt(u16, record[1..3], .big));
            try std.testing.expectEqual(ok.payload_len, std.mem.readInt(u16, record[3..5], .big));

            // A write at `maxInt(u64)` is legal exactly once, after which the
            // state is exhausted rather than wrapping to a reused nonce.
            if (initial_sequence == std.math.maxInt(u64)) {
                try std.testing.expectEqual(std.math.maxInt(u64), write.sequence);
                try std.testing.expect(write.exhausted);
                var exhausted_out: [record_codec.header_len + 64]u8 = undefined;
                @memset(&exhausted_out, fuzz_protection_sentinel);
                try std.testing.expectError(
                    error.SequenceExhausted,
                    write.seal(.application_data, "x", 0, &exhausted_out),
                );
                try std.testing.expect(std.mem.allEqual(u8, &exhausted_out, fuzz_protection_sentinel));
            } else {
                try std.testing.expectEqual(initial_sequence + 1, write.sequence);
                try std.testing.expect(!write.exhausted);
            }

            var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
            @memcpy(record_buf[0..record.len], record);
            const sealed = record_buf[0..record.len];
            const ciphertext_len = ok.payload_len - tag_len;
            const parsed = record_codec.TLSCiphertext{
                .content_type = .application_data,
                .legacy_version = record_codec.legacy_record_version,
                .payload = sealed[record_codec.header_len..],
            };

            // 5. Tamper battery. Every mutation runs against the same read
            // state, so each one also proves the failure left that state
            // usable for the legitimate open at the end.
            try fuzzProtectionTamper(smith, cp, suite, traffic_secret, &read, parsed, sealed, ciphertext_len, &plaintext_buf);

            // 6. A valid open against the same read state and sequence still
            // succeeds after every one of those failures, round-trips the
            // content exactly, and advances the read sequence exactly once.
            @memset(plaintext_buf[0..ciphertext_len], fuzz_protection_sentinel);
            const inner = try read.open(parsed, &plaintext_buf);
            try std.testing.expectEqual(content_type, inner.content_type);
            try std.testing.expectEqualSlices(u8, content_buf[0..content_len], inner.content);
            try std.testing.expectEqual(padding_len, inner.padding_len);
            try std.testing.expect(withinRange(plaintext_buf[0..ciphertext_len], inner.content));

            if (initial_sequence == std.math.maxInt(u64)) {
                try std.testing.expectEqual(std.math.maxInt(u64), read.sequence);
                try std.testing.expect(read.exhausted);
                try expectFailedOpen(&read, parsed, plaintext_buf[0..ciphertext_len], error.SequenceExhausted, false);
            } else {
                try std.testing.expectEqual(initial_sequence + 1, read.sequence);
                try std.testing.expect(!read.exhausted);
                // The same record at the *next* sequence has a different
                // nonce, so replaying it must fail closed.
                try expectFailedOpen(&read, parsed, plaintext_buf[0..ciphertext_len], error.AuthenticationFailed, true);
            }
        },
    }

    // 7. Teardown wipes both directions unconditionally, and a repeat is
    // safe -- the deferred `deinit`s above run again on the way out.
    write.deinit();
    read.deinit();
    try expectSecretsCleared(&write.keys);
    try expectSecretsCleared(&read.keys);
    try std.testing.expectEqual(@as(u64, 0), write.sequence);
    try std.testing.expectEqual(@as(u64, 0), read.sequence);
    try std.testing.expect(write.exhausted);
    try std.testing.expect(read.exhausted);
}

/// The independent tamper scenarios #493 requires, run against one sealed
/// record and a read state positioned at its sequence. Each must fail with
/// its exact typed error, leave the read sequence and exhaustion flag
/// untouched, and never hand back a plaintext view.
fn fuzzProtectionTamper(
    smith: *std.testing.Smith,
    cp: provider.CryptoProvider,
    suite: algorithms.CipherSuite,
    traffic_secret: []const u8,
    read: *ReadState,
    parsed: record_codec.TLSCiphertext,
    sealed: []u8,
    ciphertext_len: usize,
    plaintext_buf: []u8,
) !void {
    const profile = suiteProfile(suite);
    const tag_len = profile.aead.tagLength();
    const out = plaintext_buf[0..ciphertext_len];

    // (a) Ciphertext bit flip at a fuzzer-chosen offset.
    if (ciphertext_len > 0) {
        var flip_byte: [1]u8 = undefined;
        smith.bytes(&flip_byte);
        const offset = record_codec.header_len + smith.index(ciphertext_len);
        const original = sealed[offset];
        sealed[offset] ^= if (flip_byte[0] == 0) 0x01 else flip_byte[0];
        try expectFailedOpen(read, parsed, out, error.AuthenticationFailed, true);
        sealed[offset] = original;
    }

    // (b) Tag bit flip at a fuzzer-chosen offset within the tag.
    {
        const offset = record_codec.header_len + ciphertext_len + smith.index(tag_len);
        const original = sealed[offset];
        sealed[offset] ^= 0x80;
        try expectFailedOpen(read, parsed, out, error.AuthenticationFailed, true);
        sealed[offset] = original;
    }

    // (c) Tag truncation: the shortened payload changes both the tag and the
    // length field the associated data is built from. Dropping the whole tag
    // (and more) falls below the minimum payload and must be refused before
    // the AEAD runs, leaving the output entirely untouched.
    {
        const drop = 1 + smith.index(tag_len);
        const truncated = record_codec.TLSCiphertext{
            .content_type = .application_data,
            .legacy_version = record_codec.legacy_record_version,
            .payload = parsed.payload[0 .. parsed.payload.len - drop],
        };
        if (truncated.payload.len < tag_len) {
            try expectFailedOpen(read, truncated, out, error.MalformedInnerPlaintext, false);
        } else {
            try expectFailedOpen(read, truncated, out, error.AuthenticationFailed, true);
        }
    }

    // (d) Associated-data content type and version mutations are refused by
    // `open`'s own preflight, before any key is touched.
    {
        const wrong_types = [_]record_codec.ContentType{ .handshake, .alert, .change_cipher_spec };
        var wrong_type = parsed;
        wrong_type.content_type = wrong_types[smith.index(wrong_types.len)];
        try expectFailedOpen(read, wrong_type, out, error.InvalidRecordType, false);

        var wrong_version = parsed;
        wrong_version.legacy_version = if (smith.index(2) == 0) 0x0301 else 0x0304;
        try expectFailedOpen(read, wrong_version, out, error.InvalidRecordVersion, false);
    }

    // (e) Wrong read sequence: the nonce is the sequence XORed into the IV,
    // so a reader positioned anywhere else fails closed even with correct
    // key material.
    {
        const correct = read.sequence;
        const delta: u64 = 1 + smith.index(255);
        read.sequence = if (correct >= delta) correct - delta else correct + delta;
        try expectFailedOpen(read, parsed, out, error.AuthenticationFailed, true);
        read.sequence = correct;
    }

    // (f) Wrong traffic secret, and (g) wrong suite-derived keys from the
    // *same* secret. Both are fresh states, so the shared read state's
    // sequence is untouched by construction.
    {
        var wrong_secret_buf: [provider.max_digest_len]u8 = undefined;
        @memcpy(wrong_secret_buf[0..traffic_secret.len], traffic_secret);
        wrong_secret_buf[smith.index(traffic_secret.len)] ^= 0x01;
        var wrong_secret_read = ReadState.init(cp, try TrafficKeys.derive(cp, suite, wrong_secret_buf[0..traffic_secret.len]));
        defer wrong_secret_read.deinit();
        wrong_secret_read.sequence = read.sequence;
        try expectFailedOpen(&wrong_secret_read, parsed, out, error.AuthenticationFailed, true);

        // Only suites whose hash agrees can consume this secret length, so
        // pick the other same-hash suite when one exists.
        const other_suite: ?algorithms.CipherSuite = switch (suite) {
            .tls_aes_128_gcm_sha256 => .tls_chacha20_poly1305_sha256,
            .tls_chacha20_poly1305_sha256 => .tls_aes_128_gcm_sha256,
            .tls_aes_256_gcm_sha384 => null,
        };
        if (other_suite) |other| {
            var wrong_suite_read = ReadState.init(cp, try TrafficKeys.derive(cp, other, traffic_secret));
            defer wrong_suite_read.deinit();
            wrong_suite_read.sequence = read.sequence;
            try expectFailedOpen(&wrong_suite_read, parsed, out, error.AuthenticationFailed, true);
        }
    }

    // (h) Authenticated but malformed inner plaintext: an all-zero inner
    // plaintext carries no content type, so it must be rejected *after* a
    // successful AEAD open, with the decrypted span zeroed and the sequence
    // still not advanced.
    {
        const inner_len = 1 + smith.index(8);
        var inner = [_]u8{0} ** 9;
        const payload_len = inner_len + tag_len;
        var forged: [9 + provider.aead_tag_len + record_codec.header_len]u8 = undefined;
        writeCiphertextHeader(payload_len, forged[0..record_codec.header_len]);
        var nonce = nonceFor(read.keys.iv.slice(), read.sequence);
        defer provider.secureZero(&nonce);
        try cp.aeadSeal(
            profile.aead,
            read.keys.key.slice(),
            &nonce,
            forged[0..record_codec.header_len],
            inner[0..inner_len],
            forged[record_codec.header_len..][0..inner_len],
            forged[record_codec.header_len + inner_len ..][0..tag_len],
        );
        const forged_record = record_codec.TLSCiphertext{
            .content_type = .application_data,
            .legacy_version = record_codec.legacy_record_version,
            .payload = forged[record_codec.header_len..][0..payload_len],
        };
        try expectFailedOpen(read, forged_record, plaintext_buf[0..inner_len], error.MalformedInnerPlaintext, true);
    }

    // (i) Output capacity at exact-minus-one is a preflight failure: the
    // record is authentic, but a caller who cannot receive the whole
    // plaintext must get nothing rather than a truncated prefix.
    if (ciphertext_len > 0) {
        try expectFailedOpen(read, parsed, plaintext_buf[0 .. ciphertext_len - 1], error.RecordBufferOverflow, false);
    }

    // (j) Documented provider error classes propagate exactly and leave the
    // caller's state transactional. `AuthenticationFailed` is already covered
    // by real tampering above; these are the two that no conforming pure-Zig
    // provider produces from this module's own call shapes.
    {
        var fault = FaultProvider{ .inner = cp, .open_error = error.InvalidInput };
        var fault_read = ReadState.init(fault.cryptoProvider(), try TrafficKeys.derive(cp, suite, traffic_secret));
        defer fault_read.deinit();
        fault_read.sequence = read.sequence;
        try expectFailedOpen(&fault_read, parsed, out, error.InvalidInput, true);

        fault.open_error = error.UnsupportedCapability;
        try expectFailedOpen(&fault_read, parsed, out, error.UnsupportedCapability, true);

        var seal_fault = FaultProvider{ .inner = cp, .seal_error = error.InvalidInput };
        var fault_write = WriteState.init(seal_fault.cryptoProvider(), try TrafficKeys.derive(cp, suite, traffic_secret));
        defer fault_write.deinit();
        fault_write.sequence = read.sequence;
        var fault_out: [record_codec.header_len + 32]u8 = undefined;
        @memset(&fault_out, fuzz_protection_sentinel);
        try std.testing.expectError(error.InvalidInput, fault_write.seal(.application_data, "x", 0, &fault_out));
        try std.testing.expectEqual(read.sequence, fault_write.sequence);
        try std.testing.expect(!fault_write.exhausted);

        var hkdf_fault = FaultProvider{ .inner = cp, .hkdf_error = error.InvalidInput };
        try std.testing.expectError(
            error.InvalidInput,
            TrafficKeys.derive(hkdf_fault.cryptoProvider(), suite, traffic_secret),
        );
    }
}

/// True when `inner` is empty or lies wholly inside `outer`'s backing bytes,
/// mirroring `record_codec`'s `withinBounds` -- the #493 borrowed-view
/// lifetime property for sealed records and decoded inner plaintext.
fn withinRange(outer: []const u8, inner: []const u8) bool {
    if (inner.len == 0) return true;
    const outer_start = @intFromPtr(outer.ptr);
    const inner_start = @intFromPtr(inner.ptr);
    return inner_start >= outer_start and inner_start + inner.len <= outer_start + outer.len;
}

// The fuzz target's tamper battery reaches each of these arms only when the
// generated case happens to select the matching suite/length combination, and
// CI replays the seed corpus alone. These pin the classification stages
// deterministically, at every suite, so a regression cannot survive a plain
// `zig build test-tls`.
test "seal classifies every rejection stage at its exact boundary for every suite" {
    const cp = testProvider();
    inline for (all_suites) |suite| {
        const profile = comptime suiteProfile(suite);
        const secret = trafficSecret(profile.hash, 0x5a);
        var write = WriteState.init(cp, try TrafficKeys.derive(cp, suite, &secret));
        defer write.deinit();

        var out: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const tag_len = profile.aead.tagLength();
        const max_valid_padding = record_codec.max_ciphertext_fragment_len - tag_len - 1;

        // change_cipher_spec has no legal inner-plaintext encoding.
        try std.testing.expectError(
            error.InvalidRecordType,
            write.seal(.change_cipher_spec, "", 0, &out),
        );
        // Exactly the largest sealable payload, then one byte past it.
        const largest = try write.seal(.application_data, "", max_valid_padding, &out);
        try std.testing.expectEqual(
            record_codec.header_len + record_codec.max_ciphertext_fragment_len,
            largest.len,
        );
        try std.testing.expectError(
            error.RecordTooLarge,
            write.seal(.application_data, "", max_valid_padding + 1, &out),
        );
        // A padding length no allocation could represent still fails typed
        // rather than wrapping the inner-plaintext total.
        try std.testing.expectError(
            error.RecordTooLarge,
            write.seal(.application_data, "", std.math.maxInt(usize), &out),
        );
        // Output capacity at exactly one byte short of the record.
        const needed = record_codec.header_len + 1 + 1 + tag_len;
        try std.testing.expectError(
            error.RecordBufferOverflow,
            write.seal(.application_data, "x", 0, out[0 .. needed - 1]),
        );
        const exact = try write.seal(.application_data, "x", 0, out[0..needed]);
        try std.testing.expectEqual(needed, exact.len);
    }
}

test "open classifies every rejection stage at its exact boundary and never advances read state" {
    const cp = testProvider();
    inline for (all_suites) |suite| {
        const profile = comptime suiteProfile(suite);
        const secret = trafficSecret(profile.hash, 0x6b);
        var write = WriteState.init(cp, try TrafficKeys.derive(cp, suite, &secret));
        defer write.deinit();
        var read = ReadState.init(cp, try TrafficKeys.derive(cp, suite, &secret));
        defer read.deinit();

        var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = try write.seal(.handshake, "finished", 3, &protected);
        const parsed = try parsedCiphertext(record);
        const tag_len = profile.aead.tagLength();
        const ciphertext_len = parsed.payload.len - tag_len;
        var plaintext: [64]u8 = undefined;

        var wrong_type = parsed;
        wrong_type.content_type = .handshake;
        try expectFailedOpen(&read, wrong_type, plaintext[0..ciphertext_len], error.InvalidRecordType, false);

        var wrong_version = parsed;
        wrong_version.legacy_version = 0x0301;
        try expectFailedOpen(&read, wrong_version, plaintext[0..ciphertext_len], error.InvalidRecordVersion, false);

        const short = record_codec.TLSCiphertext{
            .content_type = .application_data,
            .legacy_version = record_codec.legacy_record_version,
            .payload = parsed.payload[0 .. tag_len - 1],
        };
        try expectFailedOpen(&read, short, plaintext[0..ciphertext_len], error.MalformedInnerPlaintext, false);

        try expectFailedOpen(&read, parsed, plaintext[0 .. ciphertext_len - 1], error.RecordBufferOverflow, false);

        // Every preceding rejection left the read state exactly where it
        // started, so the authentic record still opens at sequence 0.
        try std.testing.expectEqual(@as(u64, 0), read.sequence);
        const inner = try read.open(parsed, &plaintext);
        try std.testing.expectEqualStrings("finished", inner.content);
        try std.testing.expectEqual(@as(usize, 3), inner.padding_len);
        try std.testing.expectEqual(@as(u64, 1), read.sequence);
    }
}
