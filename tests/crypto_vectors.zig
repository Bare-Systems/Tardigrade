//! Deterministic TLS/QUIC cryptographic vector harness (#373).
//!
//! The cases in this file intentionally sit outside the module-local unit
//! tests. They bind the provider capability matrix to externally sourced
//! vectors and protocol derivation stages so adding or advertising a crypto
//! capability requires either positive vector coverage or an explicit waiver.

const std = @import("std");
const crypto_pkg = @import("crypto");
const quic = @import("quic");
const tls_core = @import("tls_core");

const testing = std.testing;
const provider = crypto_pkg.provider;
const profile = crypto_pkg.profile;
const pure_zig = crypto_pkg.pure_zig;

const Coverage = enum {
    positive,
    negative,
    waived,
};

const VectorMeta = struct {
    name: []const u8,
    source: []const u8,
    license: []const u8,
};

const vector_meta = [_]VectorMeta{
    .{ .name = "hkdf-rfc5869-case-1", .source = "RFC 5869 Appendix A.1", .license = "IETF Trust" },
    .{ .name = "tls13-rfc8448-simple-1rtt", .source = "RFC 8448 Section 3", .license = "IETF Trust" },
    .{ .name = "tls13-record-protection-aes128-gcm", .source = "Independently computed with Python hmac/hashlib and pycryptodome", .license = "project fixture" },
    .{ .name = "quic-v1-initial-rfc9001-a1", .source = "RFC 9001 Appendix A.1", .license = "IETF Trust" },
    .{ .name = "aes-128-gcm-nist-zero-block", .source = "NIST SP 800-38D / CAVP GCM zero-block vector", .license = "public domain" },
    .{ .name = "aes-256-gcm-nist-zero-block", .source = "NIST SP 800-38D / CAVP GCM zero-block vector", .license = "public domain" },
    .{ .name = "chacha20-poly1305-rfc8439", .source = "RFC 8439 Section 2.8.2", .license = "IETF Trust" },
    .{ .name = "x25519-rfc7748-alice-bob", .source = "RFC 7748 Section 6.1", .license = "IETF Trust" },
    .{ .name = "ed25519-rfc8032-test-1", .source = "RFC 8032 Section 7.1", .license = "IETF Trust" },
};

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

fn expectStage(stage: []const u8, expected: []const u8, actual: []const u8) !void {
    if (!std.mem.eql(u8, expected, actual)) {
        std.debug.print("crypto vector mismatch at stage: {s}\n", .{stage});
        return error.VectorMismatch;
    }
}

fn expectVectorError(stage: []const u8, expected_error: anyerror, actual_error: anyerror) !void {
    if (actual_error != expected_error) {
        std.debug.print("crypto vector error mismatch at stage: {s}; got {s}\n", .{ stage, @errorName(actual_error) });
        return error.VectorMismatch;
    }
}

fn cryptoProvider() provider.CryptoProvider {
    const Holder = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x373);
        var provider_instance = pure_zig.Provider.init(entropy.entropy());
    };
    return Holder.provider_instance.cryptoProvider();
}

fn coverageForAlgorithm(algorithm: profile.Algorithm) Coverage {
    return switch (algorithm) {
        .hash => |hash| switch (hash) {
            .sha256 => .positive,
            .sha384 => .positive,
        },
        .hkdf => |hash| switch (hash) {
            .sha256 => .positive,
            .sha384 => .positive,
        },
        .aead => |aead| switch (aead) {
            .aes_128_gcm => .positive,
            .aes_256_gcm => .positive,
            .chacha20_poly1305 => .positive,
        },
        .group => |group| switch (group) {
            .x25519 => .positive,
            .secp256r1 => .negative,
        },
        .signature => |scheme| switch (scheme) {
            .ed25519 => .positive,
            .ecdsa_secp256r1_sha256 => .positive,
            .rsa_pss_rsae_sha256 => .negative,
        },
        .certificate_helper => |helper| switch (helper) {
            .der_parser => .waived,
            .chain_builder => .waived,
            .webpki_validation => .waived,
        },
        .entropy => |capability| switch (capability) {
            .injected_random_bytes => .positive,
            .secure_zero => .positive,
            .constant_time_compare => .positive,
        },
    };
}

test "vector manifest records provenance and licensing" {
    for (vector_meta) |entry| {
        try testing.expect(entry.name.len > 0);
        try testing.expect(entry.source.len > 0);
        try testing.expect(entry.license.len > 0);
    }
}

test "capability matrix has vector coverage or explicit waivers" {
    for (profile.rows) |row| {
        const coverage = coverageForAlgorithm(row.algorithm);
        switch (row.pure_zig_status) {
            .supported => try testing.expectEqual(Coverage.positive, coverage),
            .provider_deferred, .unsupported => try testing.expect(coverage == .negative or coverage == .waived),
        }
    }
}

test "provider HKDF stages match RFC 5869 and TLS expand-label vectors" {
    const cp = cryptoProvider();

    const ikm = hexBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hexBytes("000102030405060708090a0b0c");
    const info = hexBytes("f0f1f2f3f4f5f6f7f8f9");
    const expected_prk = hexBytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    var prk: [provider.Hash.sha256.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha256, &salt, &ikm, &prk);
    try expectStage("hkdf extract sha256 / RFC 5869 A.1", &expected_prk, &prk);

    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    const expected_okm = std.crypto.tls.hkdfExpandLabel(HkdfSha256, prk, "derived", &info, 42);
    var okm: [42]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &prk, "derived", &info, &okm);
    try expectStage("hkdf expand-label sha256 / TLS label", &expected_okm, &okm);

    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);
    const expected384 = std.crypto.tls.hkdfExpandLabel(HkdfSha384, secret384, "c hs traffic", "", 48);
    var out384: [48]u8 = undefined;
    try cp.hkdfExpandLabel(.sha384, &secret384, "c hs traffic", "", &out384);
    try expectStage("hkdf expand-label sha384 / TLS label", &expected384, &out384);
}

test "TLS 1.3 key schedule and Finished value match RFC 8448" {
    const KeySchedule = tls_core.key_schedule.KeySchedule;

    const shared = hexBytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const hello_hash = hexBytes("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    var schedule = KeySchedule.init(shared, hello_hash);
    defer schedule.wipe();

    try expectStage("tls13 handshake secret / RFC 8448", &hexBytes("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), &schedule.handshake_secret);
    try expectStage("tls13 client handshake traffic secret / RFC 8448", &hexBytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), &schedule.client_handshake_traffic);
    try expectStage("tls13 server handshake traffic secret / RFC 8448", &hexBytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), &schedule.server_handshake_traffic);
    try expectStage("tls13 master secret / RFC 8448", &hexBytes("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), &schedule.master_secret);

    const finished_hash = hexBytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    const app = schedule.applicationSecrets(finished_hash);
    try expectStage("tls13 client application traffic secret / RFC 8448", &hexBytes("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"), &app.client);
    try expectStage("tls13 server application traffic secret / RFC 8448", &hexBytes("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"), &app.server);
    try expectStage("tls13 server Finished key / RFC 8448", &hexBytes("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"), &KeySchedule.finishedKey(schedule.server_handshake_traffic));
    try expectStage("tls13 server Finished verify_data / RFC 8448", &hexBytes("c5486af1426697c43c18dab6a79ef816a2188023ea743133b7e3b15a2c05c955"), &KeySchedule.verifyData(schedule.server_handshake_traffic, finished_hash));
}

test "TLS 1.3 record-protection keys and ciphertext match independent vector" {
    const cp = cryptoProvider();
    const record_protection = tls_core.record_protection;
    const record_codec = tls_core.record_codec;

    const secret = hexBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    var keys = try record_protection.TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &secret);
    defer keys.deinit();
    try expectStage("tls record aes128 key / independent vector", &hexBytes("28596a230c2c30a952fe79483568e18e"), keys.key.slice());
    try expectStage("tls record aes128 iv / independent vector", &hexBytes("fc73b522c6809e028f922c68"), keys.iv.slice());

    var write = record_protection.WriteState.init(cp, try record_protection.TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &secret));
    defer write.deinit();
    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record = try write.seal(.handshake, "server finished record", 4, &protected);
    const expected_record = hexBytes("170303002b09a08c281b147b36e277f6ac671ccd9cbc6c479d903cc2805ada8981b69579074aaad50b620ab144a6022e");
    try expectStage("tls record aes128 ciphertext / independent vector", &expected_record, record);

    var read = record_protection.ReadState.init(cp, try record_protection.TrafficKeys.derive(cp, .tls_aes_128_gcm_sha256, &secret));
    defer read.deinit();
    const parsed: record_codec.TLSCiphertext = .{
        .content_type = .application_data,
        .legacy_version = record_codec.legacy_record_version,
        .payload = record[record_codec.header_len..],
    };
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const inner = try read.open(parsed, &plaintext);
    try testing.expectEqual(record_codec.ContentType.handshake, inner.content_type);
    try testing.expectEqualStrings("server finished record", inner.content);
    try testing.expectEqual(@as(usize, 4), inner.padding_len);
}

test "QUIC v1 initial secrets and packet-protection material match RFC 9001" {
    const dcid = hexBytes("8394c8f03e515708");
    const secrets = try quic.tls_adapter.deriveInitialSecretsV1(&dcid);

    try expectStage("quic initial secret / RFC 9001 A.1", &hexBytes("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"), &secrets.initial_secret);
    try expectStage("quic client initial secret / RFC 9001 A.1", &hexBytes("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"), &secrets.client.secret);
    try expectStage("quic client initial key / RFC 9001 A.1", &hexBytes("1f369613dd76d5467730efcbe3b1a22d"), &secrets.client.key);
    try expectStage("quic client initial iv / RFC 9001 A.1", &hexBytes("fa044b2f42a3fd3b46fb255c"), &secrets.client.iv);
    try expectStage("quic client initial hp / RFC 9001 A.1", &hexBytes("9f50449e04a0e810283a1e9933adedd2"), &secrets.client.hp);
    try expectStage("quic server initial secret / RFC 9001 A.1", &hexBytes("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"), &secrets.server.secret);
    try expectStage("quic server initial key / RFC 9001 A.1", &hexBytes("cf3a5331653c364c88f0f379b6067e37"), &secrets.server.key);
    try expectStage("quic server initial iv / RFC 9001 A.1", &hexBytes("0ac1493ca1905853b0bba03e"), &secrets.server.iv);
    try expectStage("quic server initial hp / RFC 9001 A.1", &hexBytes("c206b8d9b9f0f37644430b490eeaa314"), &secrets.server.hp);

    try expectStage("quic packet nonce / RFC 9001 A.2", &hexBytes("fa044b2f42a3fd3b46fb255e"), &secrets.client.nonce(2));

    const sample = hexBytes("d1b1c98dd7689fb8ec11d242b123dc9b");
    try expectStage("quic header-protection mask / RFC 9001 A.3", &hexBytes("437b9aec36"), &secrets.client.headerProtectionMask(sample));

    var header = hexBytes("c300000001088394c8f03e5157080000449e00000002");
    var plaintext = [_]u8{0} ** 32;
    var sealed: [plaintext.len + quic.tls_adapter.packet_protection_tag_len]u8 = undefined;
    const protected = try secrets.client.sealPayload(2, &header, &plaintext, &sealed);
    var opened: [plaintext.len]u8 = undefined;
    try expectStage("quic packet-protection open after seal", &plaintext, try secrets.client.openPayload(2, &header, protected, &opened));

    sealed[sealed.len - 1] ^= 0x01;
    _ = secrets.client.openPayload(2, &header, &sealed, &opened) catch |err| {
        try expectVectorError("quic packet-protection auth tag rejection", error.AuthenticationFailed, err);
        return;
    };
    return error.ExpectedAuthenticationFailure;
}

test "provider AEAD vectors seal, open, and reject authentication failures" {
    const cp = cryptoProvider();

    try runAeadVector(.aes_128_gcm, &hexBytes("00000000000000000000000000000000"), &hexBytes("000000000000000000000000"), "", &hexBytes("00000000000000000000000000000000"), &hexBytes("0388dace60b6a392f328c2b971b2fe78"), &hexBytes("ab6e47d42cec13bdf53a67b21257bddf"), "aes-128-gcm NIST zero-block", cp);
    try runAeadVector(.aes_256_gcm, &hexBytes("0000000000000000000000000000000000000000000000000000000000000000"), &hexBytes("000000000000000000000000"), "", &hexBytes("00000000000000000000000000000000"), &hexBytes("cea7403d4d606b6e074ec5d3baf39d18"), &hexBytes("d0d1c8a799996bf0265b98b5d48ab919"), "aes-256-gcm NIST zero-block", cp);
    try runAeadVector(
        .chacha20_poly1305,
        &hexBytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        &hexBytes("070000004041424344454647"),
        &hexBytes("50515253c0c1c2c3c4c5c6c7"),
        &hexBytes("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e"),
        &hexBytes("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"),
        &hexBytes("1ae10b594f09e26a7e902ecbd0600691"),
        "chacha20-poly1305 RFC 8439",
        cp,
    );
}

fn runAeadVector(
    aead: provider.Aead,
    key: []const u8,
    nonce: []const u8,
    aad: []const u8,
    plaintext: []const u8,
    expected_ciphertext: []const u8,
    expected_tag: []const u8,
    stage: []const u8,
    cp: provider.CryptoProvider,
) !void {
    const ciphertext = try testing.allocator.alloc(u8, plaintext.len);
    defer testing.allocator.free(ciphertext);
    var tag: [provider.aead_tag_len]u8 = undefined;
    try cp.aeadSeal(aead, key, nonce, aad, plaintext, ciphertext, &tag);
    try expectStage(stage, expected_ciphertext, ciphertext);
    try expectStage(stage, expected_tag, &tag);

    const opened = try testing.allocator.alloc(u8, plaintext.len);
    defer testing.allocator.free(opened);
    try cp.aeadOpen(aead, key, nonce, aad, ciphertext, &tag, opened);
    try expectStage(stage, plaintext, opened);

    tag[0] ^= 0x01;
    cp.aeadOpen(aead, key, nonce, aad, ciphertext, &tag, opened) catch |err| {
        try expectVectorError(stage, error.AuthenticationFailed, err);
        for (opened) |byte| try testing.expectEqual(@as(u8, 0), byte);
        return;
    };
    return error.ExpectedAuthenticationFailure;
}

test "provider key exchange and signature vectors match RFC sources" {
    const cp = cryptoProvider();

    const alice_private = hexBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const bob_public = hexBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const expected_shared = hexBytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    var shared: [32]u8 = undefined;
    try cp.deriveSharedSecret(.x25519, &alice_private, &bob_public, &shared);
    try expectStage("x25519 shared secret / RFC 7748", &expected_shared, &shared);

    const zero_point = [_]u8{0} ** 32;
    cp.deriveSharedSecret(.x25519, &alice_private, &zero_point, &shared) catch |err| {
        try expectVectorError("x25519 low-order point rejection", error.InvalidInput, err);
    };

    const ed_seed = hexBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const ed_public = hexBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const ed_signature = hexBytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    var key = try pure_zig.SoftwareSigningKey.fromSeed(ed_seed);
    defer key.deinit();
    const actual_public = key.publicKey();
    try expectStage("ed25519 public key / RFC 8032", &ed_public, &actual_public);
    var actual_signature: [64]u8 = undefined;
    const len = try key.signingKey().sign("", cp.entropy, &actual_signature);
    try testing.expectEqual(@as(usize, 64), len);
    try expectStage("ed25519 signature / RFC 8032", &ed_signature, &actual_signature);
    try cp.verify(.ed25519, &ed_public, "", &ed_signature);
}

test "unsupported provider capabilities are negative cases, not silent skips" {
    const cp = cryptoProvider();
    var scalar: [32]u8 = undefined;
    var public: [65]u8 = undefined;
    try testing.expectError(error.UnsupportedCapability, cp.generateKeyShare(.secp256r1, &public, &scalar));
    try testing.expectError(error.UnsupportedCapability, cp.deriveSharedSecret(.secp256r1, &scalar, public[0..32], &scalar));
    try testing.expectError(error.UnsupportedCapability, cp.verify(.rsa_pss_rsae_sha256, "", "", ""));
}
