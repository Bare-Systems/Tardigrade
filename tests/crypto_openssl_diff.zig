//! Out-of-process OpenSSL differential crypto checks (#377).
//!
//! This target intentionally uses the `openssl` CLI as an oracle instead of
//! linking libcrypto into the Zig test binary. It covers deterministic TLS 1.3
//! and QUIC HKDF label construction plus Finished MAC derivation where the
//! current OpenSSL command surface is stable.

const std = @import("std");
const compat = @import("zig_compat");
const crypto_pkg = @import("crypto");
const tls_core = @import("tls_core");

const testing = std.testing;
const provider = crypto_pkg.provider;
const pure_zig = crypto_pkg.pure_zig;

const OpenSslError = error{
    OpenSslOracleFailed,
    DifferentialMismatch,
};

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

fn cryptoProvider() provider.CryptoProvider {
    const Holder = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x377);
        var provider_instance = pure_zig.Provider.init(entropy.entropy());
    };
    return Holder.provider_instance.cryptoProvider();
}

fn expectStage(stage: []const u8, expected: []const u8, actual: []const u8) OpenSslError!void {
    if (!std.mem.eql(u8, expected, actual)) {
        std.debug.print("OpenSSL differential mismatch at stage: {s}\n", .{stage});
        return error.DifferentialMismatch;
    }
}

fn hexAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const alphabet = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, index| {
        out[index * 2] = alphabet[byte >> 4];
        out[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return out;
}

fn tlsHkdfLabel(allocator: std.mem.Allocator, out_len: usize, label: []const u8, context: []const u8) ![]u8 {
    const prefix = "tls13 ";
    const full_label_len = prefix.len + label.len;
    if (out_len > std.math.maxInt(u16) or full_label_len > std.math.maxInt(u8) or context.len > std.math.maxInt(u8)) {
        return error.InvalidInput;
    }

    const encoded = try allocator.alloc(u8, 2 + 1 + full_label_len + 1 + context.len);
    encoded[0] = @intCast((out_len >> 8) & 0xff);
    encoded[1] = @intCast(out_len & 0xff);
    encoded[2] = @intCast(full_label_len);
    @memcpy(encoded[3..][0..prefix.len], prefix);
    @memcpy(encoded[3 + prefix.len ..][0..label.len], label);
    const context_len_offset = 3 + full_label_len;
    encoded[context_len_offset] = @intCast(context.len);
    @memcpy(encoded[context_len_offset + 1 ..][0..context.len], context);
    return encoded;
}

fn runOpenSsl(allocator: std.mem.Allocator, stage: []const u8, argv: []const []const u8) ![]u8 {
    const result = try std.process.run(allocator, compat.io(), .{
        .argv = argv,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    });
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code == 0) return result.stdout,
        else => {},
    }

    std.debug.print("OpenSSL oracle failed at stage: {s}; stderr: {s}\n", .{ stage, result.stderr });
    allocator.free(result.stdout);
    return error.OpenSslOracleFailed;
}

fn opensslHkdfExpandLabel(
    allocator: std.mem.Allocator,
    stage: []const u8,
    hash: provider.Hash,
    secret: []const u8,
    label: []const u8,
    context: []const u8,
    out_len: usize,
) ![]u8 {
    const secret_hex = try hexAlloc(allocator, secret);
    defer allocator.free(secret_hex);
    const info = try tlsHkdfLabel(allocator, out_len, label, context);
    defer allocator.free(info);
    const info_hex = try hexAlloc(allocator, info);
    defer allocator.free(info_hex);
    const key_opt = try std.fmt.allocPrint(allocator, "hexkey:{s}", .{secret_hex});
    defer allocator.free(key_opt);
    const info_opt = try std.fmt.allocPrint(allocator, "hexinfo:{s}", .{info_hex});
    defer allocator.free(info_opt);
    const key_len = try std.fmt.allocPrint(allocator, "{d}", .{out_len});
    defer allocator.free(key_len);
    const digest = switch (hash) {
        .sha256 => "digest:SHA256",
        .sha384 => "digest:SHA384",
    };

    return runOpenSsl(allocator, stage, &.{
        "openssl",
        "kdf",
        "-keylen",
        key_len,
        "-binary",
        "-kdfopt",
        digest,
        "-kdfopt",
        "mode:EXPAND_ONLY",
        "-kdfopt",
        key_opt,
        "-kdfopt",
        info_opt,
        "HKDF",
    });
}

fn opensslSha256File(allocator: std.mem.Allocator, stage: []const u8, path: []const u8) ![]u8 {
    return runOpenSsl(allocator, stage, &.{ "openssl", "dgst", "-sha256", "-binary", path });
}

fn opensslHmacSha256File(
    allocator: std.mem.Allocator,
    stage: []const u8,
    key: []const u8,
    path: []const u8,
) ![]u8 {
    const key_hex = try hexAlloc(allocator, key);
    defer allocator.free(key_hex);
    const key_opt = try std.fmt.allocPrint(allocator, "hexkey:{s}", .{key_hex});
    defer allocator.free(key_opt);
    return runOpenSsl(allocator, stage, &.{
        "openssl",
        "dgst",
        "-sha256",
        "-mac",
        "HMAC",
        "-macopt",
        key_opt,
        "-binary",
        path,
    });
}

test "OpenSSL HKDF oracle matches TLS 1.3 and QUIC label derivations" {
    const allocator = testing.allocator;
    const cp = cryptoProvider();

    const prk = hexBytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    const context = hexBytes("f0f1f2f3f4f5f6f7f8f9");
    var pure_sha256: [42]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &prk, "derived", &context, &pure_sha256);
    const openssl_sha256 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha256 / TLS derived", .sha256, &prk, "derived", &context, pure_sha256.len);
    defer allocator.free(openssl_sha256);
    try expectStage("hkdf expand-label sha256 / TLS derived", &pure_sha256, openssl_sha256);

    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    var pure_sha384: [48]u8 = undefined;
    try cp.hkdfExpandLabel(.sha384, &secret384, "c hs traffic", "", &pure_sha384);
    const openssl_sha384 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha384 / client handshake traffic", .sha384, &secret384, "c hs traffic", "", pure_sha384.len);
    defer allocator.free(openssl_sha384);
    try expectStage("hkdf expand-label sha384 / client handshake traffic", &pure_sha384, openssl_sha384);

    const tls_record_secret = hexBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    var pure_record_key: [16]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &tls_record_secret, "key", "", &pure_record_key);
    const openssl_record_key = try opensslHkdfExpandLabel(allocator, "tls record aes128 key", .sha256, &tls_record_secret, "key", "", pure_record_key.len);
    defer allocator.free(openssl_record_key);
    try expectStage("tls record aes128 key", &pure_record_key, openssl_record_key);

    var pure_record_iv: [provider.aead_nonce_len]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &tls_record_secret, "iv", "", &pure_record_iv);
    const openssl_record_iv = try opensslHkdfExpandLabel(allocator, "tls record aes128 iv", .sha256, &tls_record_secret, "iv", "", pure_record_iv.len);
    defer allocator.free(openssl_record_iv);
    try expectStage("tls record aes128 iv", &pure_record_iv, openssl_record_iv);

    const quic_initial_secret = hexBytes("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
    var pure_client_initial: [32]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &quic_initial_secret, "client in", "", &pure_client_initial);
    const openssl_client_initial = try opensslHkdfExpandLabel(allocator, "quic client initial traffic secret", .sha256, &quic_initial_secret, "client in", "", pure_client_initial.len);
    defer allocator.free(openssl_client_initial);
    try expectStage("quic client initial traffic secret", &pure_client_initial, openssl_client_initial);

    var pure_quic_key: [16]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &pure_client_initial, "quic key", "", &pure_quic_key);
    const openssl_quic_key = try opensslHkdfExpandLabel(allocator, "quic client initial key", .sha256, &pure_client_initial, "quic key", "", pure_quic_key.len);
    defer allocator.free(openssl_quic_key);
    try expectStage("quic client initial key", &pure_quic_key, openssl_quic_key);
}

test "OpenSSL digest and HMAC oracles match transcript and Finished values" {
    const allocator = testing.allocator;
    const io = testing.io;
    const KeySchedule = tls_core.key_schedule.KeySchedule;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const client_hello_1 = hexBytes("01000003aabbcc");
    try tmp.dir.writeFile(io, .{ .sub_path = "client_hello_1.bin", .data = &client_hello_1 });
    const client_hello_path = try tmp.dir.realPathFileAlloc(io, "client_hello_1.bin", allocator);
    defer allocator.free(client_hello_path);

    const openssl_ch1_hash = try opensslSha256File(allocator, "tls transcript ClientHello1 hash", client_hello_path);
    defer allocator.free(openssl_ch1_hash);
    try expectStage("tls transcript ClientHello1 hash", &hexBytes("93e26e55d8fd5b5236e00556a269142fc88e0d9616836ca9b8607841ac0287a0"), openssl_ch1_hash);

    const traffic_secret = hexBytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    const finished_hash = hexBytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    try tmp.dir.writeFile(io, .{ .sub_path = "finished_hash.bin", .data = &finished_hash });
    const finished_hash_path = try tmp.dir.realPathFileAlloc(io, "finished_hash.bin", allocator);
    defer allocator.free(finished_hash_path);

    const finished_key = KeySchedule.finishedKey(traffic_secret);
    const openssl_verify_data = try opensslHmacSha256File(allocator, "tls13 server Finished verify_data", &finished_key, finished_hash_path);
    defer allocator.free(openssl_verify_data);
    try expectStage("tls13 server Finished verify_data", &KeySchedule.verifyData(traffic_secret, finished_hash), openssl_verify_data);
}
