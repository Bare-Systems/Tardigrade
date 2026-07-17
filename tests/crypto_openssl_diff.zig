//! Out-of-process OpenSSL differential crypto checks (#377).
//!
//! This target intentionally uses the `openssl` CLI as an oracle instead of
//! linking libcrypto into the Zig test binary. It covers deterministic TLS 1.3
//! and QUIC HKDF label construction plus Finished MAC derivation where the
//! current OpenSSL command surface is stable.

const std = @import("std");
const compat = @import("zig_compat");
const crypto_pkg = @import("crypto");
const quic = @import("quic");
const tls_core = @import("tls_core");

const testing = std.testing;
const provider = crypto_pkg.provider;
const profile = crypto_pkg.profile;
const pure_zig = crypto_pkg.pure_zig;

const OpenSslError = error{
    MissingOpenSslKdfOracle,
    OpenSslOracleFailed,
    DifferentialMismatch,
};

const CoverageKind = enum {
    hkdf_extract,
    hkdf_expand_label,
    tls_record_keys,
    tls_key_schedule,
    quic_initial,
    transcript_hash,
    finished_hmac,
    aead,
    key_exchange,
    signature_sign,
    signature_verify,
    psk_binder,
};

const CoverageClass = enum {
    positive,
    negative,
};

const DifferentialCase = struct {
    kind: CoverageKind,
    algorithm: ?profile.Algorithm,
    class: CoverageClass,
    rationale: []const u8,
    run: *const fn (std.mem.Allocator) anyerror!void,
};

const Waiver = struct {
    kind: CoverageKind,
    algorithm: profile.Algorithm,
    class: CoverageClass,
    reason: []const u8,
    tracking_issue: []const u8,
};

const differential_cases = [_]DifferentialCase{
    .{ .kind = .hkdf_extract, .algorithm = .{ .hkdf = .sha256 }, .class = .positive, .rationale = "provider HKDF-Extract compared to OpenSSL EXTRACT_ONLY", .run = runHkdfExtractSha256 },
    .{ .kind = .hkdf_extract, .algorithm = .{ .hkdf = .sha384 }, .class = .positive, .rationale = "provider HKDF-Extract compared to OpenSSL EXTRACT_ONLY", .run = runHkdfExtractSha384 },
    .{ .kind = .hkdf_expand_label, .algorithm = .{ .hkdf = .sha256 }, .class = .positive, .rationale = "provider TLS HKDF-Expand-Label compared to OpenSSL EXPAND_ONLY", .run = runHkdfExpandSha256 },
    .{ .kind = .hkdf_expand_label, .algorithm = .{ .hkdf = .sha384 }, .class = .positive, .rationale = "provider TLS HKDF-Expand-Label compared to OpenSSL EXPAND_ONLY", .run = runHkdfExpandSha384 },
    .{ .kind = .tls_record_keys, .algorithm = .{ .aead = .aes_128_gcm }, .class = .positive, .rationale = "TrafficKeys.derive compared to independent OpenSSL key/iv labels", .run = runTlsRecordAes128 },
    .{ .kind = .tls_record_keys, .algorithm = .{ .aead = .aes_256_gcm }, .class = .positive, .rationale = "TrafficKeys.derive compared to independent OpenSSL key/iv labels", .run = runTlsRecordAes256 },
    .{ .kind = .tls_record_keys, .algorithm = .{ .aead = .chacha20_poly1305 }, .class = .positive, .rationale = "TrafficKeys.derive compared to independent OpenSSL key/iv labels", .run = runTlsRecordChacha20 },
    .{ .kind = .tls_key_schedule, .algorithm = .{ .hkdf = .sha256 }, .class = .positive, .rationale = "KeySchedule init/application traffic secrets compared to OpenSSL HKDF labels", .run = runTlsKeySchedule },
    .{ .kind = .quic_initial, .algorithm = .{ .aead = .aes_128_gcm }, .class = .positive, .rationale = "deriveInitialSecretsV1 compared to independent OpenSSL RFC 9001 extract/labels", .run = runQuicInitial },
    .{ .kind = .transcript_hash, .algorithm = .{ .hash = .sha256 }, .class = .positive, .rationale = "Transcript update/HRR replacement compared to OpenSSL SHA-256", .run = runTranscriptAndFinished },
    .{ .kind = .transcript_hash, .algorithm = .{ .hash = .sha256 }, .class = .negative, .rationale = "mutated handshake byte rebuilds Transcript and OpenSSL transcript hash", .run = runTranscriptAndFinished },
    .{ .kind = .finished_hmac, .algorithm = .{ .hkdf = .sha256 }, .class = .positive, .rationale = "KeySchedule Finished key and HMAC compared to independent OpenSSL HKDF/HMAC", .run = runTranscriptAndFinished },
    .{ .kind = .finished_hmac, .algorithm = .{ .hkdf = .sha256 }, .class = .negative, .rationale = "mutated transcript changes Zig and OpenSSL Finished verify_data", .run = runTranscriptAndFinished },
};

const waivers = [_]Waiver{
    .{ .kind = .aead, .algorithm = .{ .aead = .aes_128_gcm }, .class = .positive, .reason = "OpenSSL CLI cannot seal/open AEAD with detached tags portably; blocked on a dedicated out-of-process EVP oracle follow-up.", .tracking_issue = "#431" },
    .{ .kind = .aead, .algorithm = .{ .aead = .aes_128_gcm }, .class = .negative, .reason = "Invalid-tag parity requires the same dedicated EVP oracle follow-up.", .tracking_issue = "#431" },
    .{ .kind = .aead, .algorithm = .{ .aead = .aes_256_gcm }, .class = .positive, .reason = "OpenSSL CLI cannot seal/open AEAD with detached tags portably; blocked on a dedicated out-of-process EVP oracle follow-up.", .tracking_issue = "#431" },
    .{ .kind = .aead, .algorithm = .{ .aead = .aes_256_gcm }, .class = .negative, .reason = "Invalid-tag parity requires the same dedicated EVP oracle follow-up.", .tracking_issue = "#431" },
    .{ .kind = .aead, .algorithm = .{ .aead = .chacha20_poly1305 }, .class = .positive, .reason = "OpenSSL CLI cannot seal/open AEAD with detached tags portably; blocked on a dedicated out-of-process EVP oracle follow-up.", .tracking_issue = "#431" },
    .{ .kind = .aead, .algorithm = .{ .aead = .chacha20_poly1305 }, .class = .negative, .reason = "Invalid-tag parity requires the same dedicated EVP oracle follow-up.", .tracking_issue = "#431" },
    .{ .kind = .key_exchange, .algorithm = .{ .group = .x25519 }, .class = .positive, .reason = "X25519 parity needs stable raw-key EVP derive commands; tracked with the dedicated EVP oracle follow-up.", .tracking_issue = "#431" },
    .{ .kind = .key_exchange, .algorithm = .{ .group = .x25519 }, .class = .negative, .reason = "Low-order/invalid-key parity needs the same raw-key EVP derive oracle.", .tracking_issue = "#431" },
    .{ .kind = .signature_sign, .algorithm = .{ .signature = .ed25519 }, .class = .positive, .reason = "OpenSSL CLI raw Ed25519 signing fixtures require the dedicated EVP oracle follow-up.", .tracking_issue = "#431" },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ed25519 }, .class = .positive, .reason = "Raw-key Ed25519 verify parity requires the dedicated EVP oracle follow-up.", .tracking_issue = "#431" },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ed25519 }, .class = .negative, .reason = "Invalid-signature Ed25519 parity requires the same raw-key EVP oracle.", .tracking_issue = "#431" },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ecdsa_secp256r1_sha256 }, .class = .positive, .reason = "SEC1-key ECDSA verification parity requires the dedicated EVP oracle follow-up.", .tracking_issue = "#431" },
    .{ .kind = .signature_verify, .algorithm = .{ .signature = .ecdsa_secp256r1_sha256 }, .class = .negative, .reason = "Invalid-signature ECDSA parity requires the same SEC1-key EVP oracle.", .tracking_issue = "#431" },
    .{ .kind = .psk_binder, .algorithm = .{ .hkdf = .sha256 }, .class = .negative, .reason = "Pure-Zig PSK binder generation/verification is not implemented yet.", .tracking_issue = "#362" },
    .{ .kind = .psk_binder, .algorithm = .{ .hkdf = .sha384 }, .class = .negative, .reason = "Pure-Zig PSK binder generation/verification is not implemented yet.", .tracking_issue = "#362" },
};

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

fn algorithmEql(a: profile.Algorithm, b: profile.Algorithm) bool {
    return switch (a) {
        .hash => |value| b == .hash and b.hash == value,
        .hkdf => |value| b == .hkdf and b.hkdf == value,
        .aead => |value| b == .aead and b.aead == value,
        .group => |value| b == .group and b.group == value,
        .signature => |value| b == .signature and b.signature == value,
        .certificate_helper => |value| b == .certificate_helper and b.certificate_helper == value,
        .entropy => |value| b == .entropy and b.entropy == value,
    };
}

fn hasCoverage(kind: CoverageKind, algorithm: profile.Algorithm, class: CoverageClass) bool {
    for (differential_cases) |case| {
        const case_algorithm = case.algorithm orelse continue;
        if (case.kind == kind and case.class == class and algorithmEql(case_algorithm, algorithm)) return true;
    }
    return false;
}

fn hasWaiver(kind: CoverageKind, algorithm: profile.Algorithm, class: CoverageClass) bool {
    for (waivers) |waiver| {
        if (waiver.kind == kind and waiver.class == class and algorithmEql(waiver.algorithm, algorithm)) return true;
    }
    return false;
}

fn expectCoverageOrWaiver(kind: CoverageKind, algorithm: profile.Algorithm, class: CoverageClass) !void {
    if (hasCoverage(kind, algorithm, class) or hasWaiver(kind, algorithm, class)) return;
    std.debug.print("missing OpenSSL differential coverage or waiver: kind={s} class={s} algorithm={any}\n", .{ @tagName(kind), @tagName(class), algorithm });
    return error.MissingDifferentialCoverage;
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

fn runOpenSslProbe(allocator: std.mem.Allocator, argv: []const []const u8) !bool {
    const result = std.process.run(allocator, compat.io(), .{
        .argv = argv,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn runOpenSslOutputProbe(allocator: std.mem.Allocator, argv: []const []const u8, expected: []const u8) !bool {
    const result = std.process.run(allocator, compat.io(), .{
        .argv = argv,
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) return false,
        else => return false,
    }
    return std.mem.eql(u8, expected, result.stdout);
}

fn opensslMatchesHkdfOracle(allocator: std.mem.Allocator, path: []const u8) !bool {
    if (!try runOpenSslProbe(allocator, &.{ path, "kdf", "-help" })) return false;
    return runOpenSslOutputProbe(
        allocator,
        &.{
            path,
            "kdf",
            "-keylen",
            "42",
            "-binary",
            "-kdfopt",
            "digest:SHA256",
            "-kdfopt",
            "mode:EXPAND_ONLY",
            "-kdfopt",
            "hexkey:077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "-kdfopt",
            "hexinfo:002a0d746c73313320646572697665640af0f1f2f3f4f5f6f7f8f9",
            "HKDF",
        },
        &hexBytes("e29ebe58889156b196d8f9c31e3a4658a71eabdc113c50e4bf9d7a97ed3af464e6286979f53caa6fba0c"),
    );
}

const OpenSslBinary = struct {
    path: []const u8,
    owned: bool = false,

    fn deinit(self: OpenSslBinary, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.path);
    }
};

fn opensslBinary(allocator: std.mem.Allocator) !OpenSslBinary {
    if (compat.getEnvVarOwned(allocator, "OPENSSL_BIN")) |path| {
        if (try opensslMatchesHkdfOracle(allocator, path)) return .{ .path = path, .owned = true };
        allocator.free(path);
    } else |_| {}

    const candidates = [_][]const u8{
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
        "openssl",
    };
    for (candidates) |candidate| {
        if (try opensslMatchesHkdfOracle(allocator, candidate)) {
            return .{ .path = candidate };
        }
    }
    return error.MissingOpenSslKdfOracle;
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

fn opensslHkdfExtract(
    allocator: std.mem.Allocator,
    stage: []const u8,
    hash: provider.Hash,
    salt: []const u8,
    ikm: []const u8,
) ![]u8 {
    const salt_hex = try hexAlloc(allocator, salt);
    defer allocator.free(salt_hex);
    const ikm_hex = try hexAlloc(allocator, ikm);
    defer allocator.free(ikm_hex);
    const salt_opt = try std.fmt.allocPrint(allocator, "hexsalt:{s}", .{salt_hex});
    defer allocator.free(salt_opt);
    const key_opt = try std.fmt.allocPrint(allocator, "hexkey:{s}", .{ikm_hex});
    defer allocator.free(key_opt);
    const key_len = try std.fmt.allocPrint(allocator, "{d}", .{hash.digestLength()});
    defer allocator.free(key_len);
    const digest = switch (hash) {
        .sha256 => "digest:SHA256",
        .sha384 => "digest:SHA384",
    };
    const openssl = try opensslBinary(allocator);
    defer openssl.deinit(allocator);

    return runOpenSsl(allocator, stage, &.{
        openssl.path,
        "kdf",
        "-keylen",
        key_len,
        "-binary",
        "-kdfopt",
        digest,
        "-kdfopt",
        "mode:EXTRACT_ONLY",
        "-kdfopt",
        salt_opt,
        "-kdfopt",
        key_opt,
        "HKDF",
    });
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
    const openssl = try opensslBinary(allocator);
    defer openssl.deinit(allocator);

    return runOpenSsl(allocator, stage, &.{
        openssl.path,
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
    const openssl = try opensslBinary(allocator);
    defer openssl.deinit(allocator);
    return runOpenSsl(allocator, stage, &.{ openssl.path, "dgst", "-sha256", "-binary", path });
}

fn expectOpenSslSha256File(allocator: std.mem.Allocator, stage: []const u8, expected: []const u8, path: []const u8) !void {
    const actual = try opensslSha256File(allocator, stage, path);
    defer allocator.free(actual);
    try expectStage(stage, expected, actual);
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
    const openssl = try opensslBinary(allocator);
    defer openssl.deinit(allocator);
    return runOpenSsl(allocator, stage, &.{
        openssl.path,
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

const TlsRecordOracleParams = struct {
    hash: provider.Hash,
    key_len: usize,
    iv_len: usize,
};

fn tlsRecordOracleParams(suite: tls_core.algorithms.CipherSuite) TlsRecordOracleParams {
    return switch (suite) {
        .tls_aes_128_gcm_sha256 => .{ .hash = .sha256, .key_len = 16, .iv_len = 12 },
        .tls_aes_256_gcm_sha384 => .{ .hash = .sha384, .key_len = 32, .iv_len = 12 },
        .tls_chacha20_poly1305_sha256 => .{ .hash = .sha256, .key_len = 32, .iv_len = 12 },
    };
}

fn expectTlsTrafficKeys(
    allocator: std.mem.Allocator,
    stage: []const u8,
    cp: provider.CryptoProvider,
    suite: tls_core.algorithms.CipherSuite,
    traffic_secret: []const u8,
) !void {
    const record_protection = tls_core.record_protection;
    const params = tlsRecordOracleParams(suite);
    var keys = try record_protection.TrafficKeys.derive(cp, suite, traffic_secret);
    defer keys.deinit();

    try testing.expectEqual(params.key_len, keys.key.slice().len);
    try testing.expectEqual(params.iv_len, keys.iv.slice().len);

    const openssl_key = try opensslHkdfExpandLabel(allocator, stage, params.hash, traffic_secret, "key", "", params.key_len);
    defer allocator.free(openssl_key);
    try expectStage(stage, keys.key.slice(), openssl_key);

    const iv_stage = try std.fmt.allocPrint(allocator, "{s} iv", .{stage});
    defer allocator.free(iv_stage);
    const openssl_iv = try opensslHkdfExpandLabel(allocator, iv_stage, params.hash, traffic_secret, "iv", "", params.iv_len);
    defer allocator.free(openssl_iv);
    try expectStage(iv_stage, keys.iv.slice(), openssl_iv);
}

fn runHkdfAndTlsRecordDerivations(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();

    const ikm = hexBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hexBytes("000102030405060708090a0b0c");
    var prk: [provider.Hash.sha256.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha256, &salt, &ikm, &prk);
    const openssl_prk = try opensslHkdfExtract(allocator, "hkdf extract sha256 / RFC 5869 A.1", .sha256, &salt, &ikm);
    defer allocator.free(openssl_prk);
    try expectStage("hkdf extract sha256 / RFC 5869 A.1", &prk, openssl_prk);

    const context = hexBytes("f0f1f2f3f4f5f6f7f8f9");
    var pure_sha256: [42]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &prk, "derived", &context, &pure_sha256);
    const openssl_sha256 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha256 / TLS derived", .sha256, &prk, "derived", &context, pure_sha256.len);
    defer allocator.free(openssl_sha256);
    try expectStage("hkdf expand-label sha256 / TLS derived", &pure_sha256, openssl_sha256);

    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    var prk384: [provider.Hash.sha384.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha384, &secret384, &ikm, &prk384);
    const openssl_prk384 = try opensslHkdfExtract(allocator, "hkdf extract sha384 / fixed fixture", .sha384, &secret384, &ikm);
    defer allocator.free(openssl_prk384);
    try expectStage("hkdf extract sha384 / fixed fixture", &prk384, openssl_prk384);

    var pure_sha384: [48]u8 = undefined;
    try cp.hkdfExpandLabel(.sha384, &secret384, "c hs traffic", "", &pure_sha384);
    const openssl_sha384 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha384 / client handshake traffic", .sha384, &secret384, "c hs traffic", "", pure_sha384.len);
    defer allocator.free(openssl_sha384);
    try expectStage("hkdf expand-label sha384 / client handshake traffic", &pure_sha384, openssl_sha384);

    const tls_record_secret = hexBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    try expectTlsTrafficKeys(allocator, "tls record aes128 key", cp, .tls_aes_128_gcm_sha256, &tls_record_secret);
    try expectTlsTrafficKeys(allocator, "tls record aes256 key", cp, .tls_aes_256_gcm_sha384, &secret384);

    const chacha_secret = [_]u8{0x33} ** provider.Hash.sha256.digestLength();
    try expectTlsTrafficKeys(allocator, "tls record chacha20 key", cp, .tls_chacha20_poly1305_sha256, &chacha_secret);
}

fn runHkdfExtractSha256(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const ikm = hexBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hexBytes("000102030405060708090a0b0c");
    var prk: [provider.Hash.sha256.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha256, &salt, &ikm, &prk);
    const openssl_prk = try opensslHkdfExtract(allocator, "hkdf extract sha256 / RFC 5869 A.1", .sha256, &salt, &ikm);
    defer allocator.free(openssl_prk);
    try expectStage("hkdf extract sha256 / RFC 5869 A.1", &prk, openssl_prk);
}

fn runHkdfExtractSha384(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const ikm = hexBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    var prk384: [provider.Hash.sha384.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha384, &secret384, &ikm, &prk384);
    const openssl_prk384 = try opensslHkdfExtract(allocator, "hkdf extract sha384 / fixed fixture", .sha384, &secret384, &ikm);
    defer allocator.free(openssl_prk384);
    try expectStage("hkdf extract sha384 / fixed fixture", &prk384, openssl_prk384);
}

fn runHkdfExpandSha256(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const ikm = hexBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hexBytes("000102030405060708090a0b0c");
    var prk: [provider.Hash.sha256.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha256, &salt, &ikm, &prk);
    const context = hexBytes("f0f1f2f3f4f5f6f7f8f9");
    var pure_sha256: [42]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &prk, "derived", &context, &pure_sha256);
    const openssl_sha256 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha256 / TLS derived", .sha256, &prk, "derived", &context, pure_sha256.len);
    defer allocator.free(openssl_sha256);
    try expectStage("hkdf expand-label sha256 / TLS derived", &pure_sha256, openssl_sha256);
}

fn runHkdfExpandSha384(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    var pure_sha384: [48]u8 = undefined;
    try cp.hkdfExpandLabel(.sha384, &secret384, "c hs traffic", "", &pure_sha384);
    const openssl_sha384 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha384 / client handshake traffic", .sha384, &secret384, "c hs traffic", "", pure_sha384.len);
    defer allocator.free(openssl_sha384);
    try expectStage("hkdf expand-label sha384 / client handshake traffic", &pure_sha384, openssl_sha384);
}

fn runTlsRecordAes128(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const tls_record_secret = hexBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    try expectTlsTrafficKeys(allocator, "tls record aes128 key", cp, .tls_aes_128_gcm_sha256, &tls_record_secret);
}

fn runTlsRecordAes256(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    try expectTlsTrafficKeys(allocator, "tls record aes256 key", cp, .tls_aes_256_gcm_sha384, &secret384);
}

fn runTlsRecordChacha20(allocator: std.mem.Allocator) !void {
    const cp = cryptoProvider();
    const chacha_secret = [_]u8{0x33} ** provider.Hash.sha256.digestLength();
    try expectTlsTrafficKeys(allocator, "tls record chacha20 key", cp, .tls_chacha20_poly1305_sha256, &chacha_secret);
}

fn runTlsKeySchedule(allocator: std.mem.Allocator) !void {
    const KeySchedule = tls_core.key_schedule.KeySchedule;
    const shared = hexBytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const hello_hash = hexBytes("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    var schedule = KeySchedule.init(&shared, hello_hash);
    defer schedule.wipe();

    const zero = [_]u8{0} ** provider.Hash.sha256.digestLength();
    const empty_hash = hexBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const early_secret = try opensslHkdfExtract(allocator, "tls13 early secret", .sha256, "", &zero);
    defer allocator.free(early_secret);
    const derived_from_early = try opensslHkdfExpandLabel(allocator, "tls13 derived early secret", .sha256, early_secret, "derived", &empty_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(derived_from_early);
    const handshake_secret = try opensslHkdfExtract(allocator, "tls13 handshake secret", .sha256, derived_from_early, &shared);
    defer allocator.free(handshake_secret);
    try expectStage("tls13 handshake secret", &schedule.handshake_secret, handshake_secret);

    const client_hs = try opensslHkdfExpandLabel(allocator, "tls13 client handshake traffic secret", .sha256, handshake_secret, "c hs traffic", &hello_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(client_hs);
    try expectStage("tls13 client handshake traffic secret", &schedule.client_handshake_traffic, client_hs);

    const server_hs = try opensslHkdfExpandLabel(allocator, "tls13 server handshake traffic secret", .sha256, handshake_secret, "s hs traffic", &hello_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(server_hs);
    try expectStage("tls13 server handshake traffic secret", &schedule.server_handshake_traffic, server_hs);

    const derived_from_handshake = try opensslHkdfExpandLabel(allocator, "tls13 derived handshake secret", .sha256, handshake_secret, "derived", &empty_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(derived_from_handshake);
    const master_secret = try opensslHkdfExtract(allocator, "tls13 master secret", .sha256, derived_from_handshake, &zero);
    defer allocator.free(master_secret);
    try expectStage("tls13 master secret", &schedule.master_secret, master_secret);

    const finished_hash = hexBytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    var app = schedule.applicationSecrets(finished_hash);
    defer app.wipe();
    const client_app = try opensslHkdfExpandLabel(allocator, "tls13 client application traffic secret", .sha256, master_secret, "c ap traffic", &finished_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(client_app);
    try expectStage("tls13 client application traffic secret", &app.client, client_app);
    const server_app = try opensslHkdfExpandLabel(allocator, "tls13 server application traffic secret", .sha256, master_secret, "s ap traffic", &finished_hash, provider.Hash.sha256.digestLength());
    defer allocator.free(server_app);
    try expectStage("tls13 server application traffic secret", &app.server, server_app);
}

test "OpenSSL HKDF oracle matches provider and TLS record derivations" {
    const allocator = testing.allocator;
    const cp = cryptoProvider();

    const ikm = hexBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hexBytes("000102030405060708090a0b0c");
    var prk: [provider.Hash.sha256.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha256, &salt, &ikm, &prk);
    const openssl_prk = try opensslHkdfExtract(allocator, "hkdf extract sha256 / RFC 5869 A.1", .sha256, &salt, &ikm);
    defer allocator.free(openssl_prk);
    try expectStage("hkdf extract sha256 / RFC 5869 A.1", &prk, openssl_prk);

    const context = hexBytes("f0f1f2f3f4f5f6f7f8f9");
    var pure_sha256: [42]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &prk, "derived", &context, &pure_sha256);
    const openssl_sha256 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha256 / TLS derived", .sha256, &prk, "derived", &context, pure_sha256.len);
    defer allocator.free(openssl_sha256);
    try expectStage("hkdf expand-label sha256 / TLS derived", &pure_sha256, openssl_sha256);

    const secret384 = [_]u8{0x42} ** provider.Hash.sha384.digestLength();
    var prk384: [provider.Hash.sha384.digestLength()]u8 = undefined;
    try cp.hkdfExtract(.sha384, &secret384, &ikm, &prk384);
    const openssl_prk384 = try opensslHkdfExtract(allocator, "hkdf extract sha384 / fixed fixture", .sha384, &secret384, &ikm);
    defer allocator.free(openssl_prk384);
    try expectStage("hkdf extract sha384 / fixed fixture", &prk384, openssl_prk384);

    var pure_sha384: [48]u8 = undefined;
    try cp.hkdfExpandLabel(.sha384, &secret384, "c hs traffic", "", &pure_sha384);
    const openssl_sha384 = try opensslHkdfExpandLabel(allocator, "hkdf expand-label sha384 / client handshake traffic", .sha384, &secret384, "c hs traffic", "", pure_sha384.len);
    defer allocator.free(openssl_sha384);
    try expectStage("hkdf expand-label sha384 / client handshake traffic", &pure_sha384, openssl_sha384);

    const tls_record_secret = hexBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    try expectTlsTrafficKeys(allocator, "tls record aes128 key", cp, .tls_aes_128_gcm_sha256, &tls_record_secret);
    try expectTlsTrafficKeys(allocator, "tls record aes256 key", cp, .tls_aes_256_gcm_sha384, &secret384);

    const chacha_secret = [_]u8{0x33} ** provider.Hash.sha256.digestLength();
    try expectTlsTrafficKeys(allocator, "tls record chacha20 key", cp, .tls_chacha20_poly1305_sha256, &chacha_secret);
}

fn runQuicInitial(allocator: std.mem.Allocator) !void {
    const dcid = hexBytes("8394c8f03e515708");
    const zig_initial = try quic.tls_adapter.deriveInitialSecretsV1(&dcid);
    const rfc9001_initial_salt = hexBytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    const quic_secret_len = 32;
    const quic_key_len = 16;
    const quic_iv_len = 12;
    const quic_hp_len = 16;

    const openssl_initial = try opensslHkdfExtract(allocator, "quic v1 initial secret", .sha256, &rfc9001_initial_salt, &dcid);
    defer allocator.free(openssl_initial);
    try expectStage("quic v1 initial secret", &zig_initial.initial_secret, openssl_initial);

    const openssl_client_secret = try opensslHkdfExpandLabel(allocator, "quic client initial secret", .sha256, openssl_initial, "client in", "", quic_secret_len);
    defer allocator.free(openssl_client_secret);
    try expectStage("quic client initial secret", &zig_initial.client.secret, openssl_client_secret);

    const openssl_server_secret = try opensslHkdfExpandLabel(allocator, "quic server initial secret", .sha256, openssl_initial, "server in", "", quic_secret_len);
    defer allocator.free(openssl_server_secret);
    try expectStage("quic server initial secret", &zig_initial.server.secret, openssl_server_secret);

    const openssl_client_key = try opensslHkdfExpandLabel(allocator, "quic client initial key", .sha256, openssl_client_secret, "quic key", "", quic_key_len);
    defer allocator.free(openssl_client_key);
    try expectStage("quic client initial key", &zig_initial.client.key, openssl_client_key);

    const openssl_client_iv = try opensslHkdfExpandLabel(allocator, "quic client initial iv", .sha256, openssl_client_secret, "quic iv", "", quic_iv_len);
    defer allocator.free(openssl_client_iv);
    try expectStage("quic client initial iv", &zig_initial.client.iv, openssl_client_iv);

    const openssl_client_hp = try opensslHkdfExpandLabel(allocator, "quic client initial hp", .sha256, openssl_client_secret, "quic hp", "", quic_hp_len);
    defer allocator.free(openssl_client_hp);
    try expectStage("quic client initial hp", &zig_initial.client.hp, openssl_client_hp);

    const openssl_server_key = try opensslHkdfExpandLabel(allocator, "quic server initial key", .sha256, openssl_server_secret, "quic key", "", quic_key_len);
    defer allocator.free(openssl_server_key);
    try expectStage("quic server initial key", &zig_initial.server.key, openssl_server_key);

    const openssl_server_iv = try opensslHkdfExpandLabel(allocator, "quic server initial iv", .sha256, openssl_server_secret, "quic iv", "", quic_iv_len);
    defer allocator.free(openssl_server_iv);
    try expectStage("quic server initial iv", &zig_initial.server.iv, openssl_server_iv);

    const openssl_server_hp = try opensslHkdfExpandLabel(allocator, "quic server initial hp", .sha256, openssl_server_secret, "quic hp", "", quic_hp_len);
    defer allocator.free(openssl_server_hp);
    try expectStage("quic server initial hp", &zig_initial.server.hp, openssl_server_hp);
}

test "OpenSSL HKDF oracle matches QUIC production initial derivation" {
    try runQuicInitial(testing.allocator);
}

fn fillSyntheticHrr(
    out: []u8,
    ch1_hash: *const [tls_core.transcript.digest_len]u8,
    hello_retry_request: []const u8,
    client_hello_2: []const u8,
) void {
    out[0] = 0xfe;
    std.mem.writeInt(u24, out[1..4], tls_core.transcript.digest_len, .big);
    @memcpy(out[4..][0..tls_core.transcript.digest_len], ch1_hash);
    var offset: usize = 4 + tls_core.transcript.digest_len;
    @memcpy(out[offset..][0..hello_retry_request.len], hello_retry_request);
    offset += hello_retry_request.len;
    @memcpy(out[offset..][0..client_hello_2.len], client_hello_2);
}

fn runTranscriptAndFinished(allocator: std.mem.Allocator) !void {
    const io = testing.io;
    const KeySchedule = tls_core.key_schedule.KeySchedule;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const client_hello_1 = hexBytes("01000003aabbcc");
    try tmp.dir.writeFile(io, .{ .sub_path = "client_hello_1.bin", .data = &client_hello_1 });
    const client_hello_path = try tmp.dir.realPathFileAlloc(io, "client_hello_1.bin", allocator);
    defer allocator.free(client_hello_path);

    var transcript = tls_core.transcript.Transcript{};
    transcript.update(&client_hello_1);
    const zig_ch1_hash = transcript.peek();
    try expectOpenSslSha256File(allocator, "tls transcript ClientHello1 hash", &zig_ch1_hash, client_hello_path);

    const hello_retry_request = hexBytes("02000002cf21");
    var client_hello_2 = hexBytes("01000002ddee");
    transcript.replace(zig_ch1_hash);
    transcript.update(&hello_retry_request);
    transcript.update(&client_hello_2);
    const zig_hrr_hash = transcript.peek();

    var synthetic_and_hrr: [4 + tls_core.transcript.digest_len + hello_retry_request.len + client_hello_2.len]u8 = undefined;
    fillSyntheticHrr(&synthetic_and_hrr, &zig_ch1_hash, &hello_retry_request, &client_hello_2);
    try tmp.dir.writeFile(io, .{ .sub_path = "synthetic_hrr.bin", .data = &synthetic_and_hrr });
    const synthetic_hrr_path = try tmp.dir.realPathFileAlloc(io, "synthetic_hrr.bin", allocator);
    defer allocator.free(synthetic_hrr_path);
    try expectOpenSslSha256File(allocator, "tls transcript HRR hash", &zig_hrr_hash, synthetic_hrr_path);

    const traffic_secret = hexBytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
    try tmp.dir.writeFile(io, .{ .sub_path = "finished_hash.bin", .data = &zig_hrr_hash });
    const finished_hash_path = try tmp.dir.realPathFileAlloc(io, "finished_hash.bin", allocator);
    defer allocator.free(finished_hash_path);

    var zig_finished_key = KeySchedule.finishedKey(&traffic_secret);
    defer std.crypto.secureZero(u8, &zig_finished_key);
    const openssl_finished_key = try opensslHkdfExpandLabel(allocator, "tls13 server Finished key", .sha256, &traffic_secret, "finished", "", provider.Hash.sha256.digestLength());
    defer allocator.free(openssl_finished_key);
    try expectStage("tls13 server Finished key", &zig_finished_key, openssl_finished_key);

    const openssl_verify_data = try opensslHmacSha256File(allocator, "tls13 server Finished verify_data", openssl_finished_key, finished_hash_path);
    defer allocator.free(openssl_verify_data);
    var zig_verify_data = KeySchedule.verifyData(&traffic_secret, zig_hrr_hash);
    defer std.crypto.secureZero(u8, &zig_verify_data);
    try expectStage("tls13 server Finished verify_data", &zig_verify_data, openssl_verify_data);

    client_hello_2[client_hello_2.len - 1] ^= 0x01;
    var mutated_transcript = tls_core.transcript.Transcript{};
    mutated_transcript.update(&client_hello_1);
    const mutated_ch1_hash = mutated_transcript.peek();
    try expectStage("tls transcript mutated ClientHello1 stable hash", &zig_ch1_hash, &mutated_ch1_hash);
    mutated_transcript.replace(mutated_ch1_hash);
    mutated_transcript.update(&hello_retry_request);
    mutated_transcript.update(&client_hello_2);
    const zig_mutated_hrr_hash = mutated_transcript.peek();

    fillSyntheticHrr(&synthetic_and_hrr, &zig_ch1_hash, &hello_retry_request, &client_hello_2);
    try tmp.dir.writeFile(io, .{ .sub_path = "synthetic_hrr_mutated.bin", .data = &synthetic_and_hrr });
    const synthetic_hrr_mutated_path = try tmp.dir.realPathFileAlloc(io, "synthetic_hrr_mutated.bin", allocator);
    defer allocator.free(synthetic_hrr_mutated_path);
    try expectOpenSslSha256File(allocator, "tls transcript HRR mutated hash", &zig_mutated_hrr_hash, synthetic_hrr_mutated_path);

    try tmp.dir.writeFile(io, .{ .sub_path = "finished_hash_mutated.bin", .data = &zig_mutated_hrr_hash });
    const finished_hash_mutated_path = try tmp.dir.realPathFileAlloc(io, "finished_hash_mutated.bin", allocator);
    defer allocator.free(finished_hash_mutated_path);
    const openssl_mutated_verify_data = try opensslHmacSha256File(allocator, "tls13 server Finished mutated verify_data", openssl_finished_key, finished_hash_mutated_path);
    defer allocator.free(openssl_mutated_verify_data);
    var zig_mutated_verify_data = KeySchedule.verifyData(&traffic_secret, zig_mutated_hrr_hash);
    defer std.crypto.secureZero(u8, &zig_mutated_verify_data);
    try expectStage("tls13 server Finished mutated verify_data", &zig_mutated_verify_data, openssl_mutated_verify_data);
    var stable_verify_data = KeySchedule.verifyData(&traffic_secret, zig_hrr_hash);
    defer std.crypto.secureZero(u8, &stable_verify_data);
    try testing.expect(!std.mem.eql(u8, &stable_verify_data, &zig_mutated_verify_data));
}

test "OpenSSL digest and HMAC oracles match transcript and Finished values" {
    try runTranscriptAndFinished(testing.allocator);
}

test "OpenSSL differential coverage registry has explicit coverage or waivers" {
    for (differential_cases) |case| {
        try testing.expect(case.rationale.len > 0);
        errdefer std.debug.print("failed OpenSSL differential case: kind={s} class={s} rationale={s}\n", .{ @tagName(case.kind), @tagName(case.class), case.rationale });
        try case.run(testing.allocator);
    }
    for (waivers) |waiver| {
        try testing.expect(waiver.reason.len > 0);
        try testing.expect(waiver.tracking_issue.len > 0);
        try testing.expect(!std.mem.eql(u8, waiver.tracking_issue, "#377"));
    }

    try expectCoverageOrWaiver(.hkdf_extract, .{ .hkdf = .sha256 }, .positive);
    try expectCoverageOrWaiver(.hkdf_extract, .{ .hkdf = .sha384 }, .positive);
    try expectCoverageOrWaiver(.hkdf_expand_label, .{ .hkdf = .sha256 }, .positive);
    try expectCoverageOrWaiver(.hkdf_expand_label, .{ .hkdf = .sha384 }, .positive);

    try expectCoverageOrWaiver(.tls_record_keys, .{ .aead = .aes_128_gcm }, .positive);
    try expectCoverageOrWaiver(.tls_record_keys, .{ .aead = .aes_256_gcm }, .positive);
    try expectCoverageOrWaiver(.tls_record_keys, .{ .aead = .chacha20_poly1305 }, .positive);
    try expectCoverageOrWaiver(.tls_key_schedule, .{ .hkdf = .sha256 }, .positive);
    try expectCoverageOrWaiver(.quic_initial, .{ .aead = .aes_128_gcm }, .positive);
    try expectCoverageOrWaiver(.transcript_hash, .{ .hash = .sha256 }, .positive);
    try expectCoverageOrWaiver(.transcript_hash, .{ .hash = .sha256 }, .negative);
    try expectCoverageOrWaiver(.finished_hmac, .{ .hkdf = .sha256 }, .positive);
    try expectCoverageOrWaiver(.finished_hmac, .{ .hkdf = .sha256 }, .negative);

    try expectCoverageOrWaiver(.aead, .{ .aead = .aes_128_gcm }, .positive);
    try expectCoverageOrWaiver(.aead, .{ .aead = .aes_128_gcm }, .negative);
    try expectCoverageOrWaiver(.aead, .{ .aead = .aes_256_gcm }, .positive);
    try expectCoverageOrWaiver(.aead, .{ .aead = .aes_256_gcm }, .negative);
    try expectCoverageOrWaiver(.aead, .{ .aead = .chacha20_poly1305 }, .positive);
    try expectCoverageOrWaiver(.aead, .{ .aead = .chacha20_poly1305 }, .negative);
    try expectCoverageOrWaiver(.key_exchange, .{ .group = .x25519 }, .positive);
    try expectCoverageOrWaiver(.key_exchange, .{ .group = .x25519 }, .negative);
    try expectCoverageOrWaiver(.signature_sign, .{ .signature = .ed25519 }, .positive);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ed25519 }, .positive);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ed25519 }, .negative);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ecdsa_secp256r1_sha256 }, .positive);
    try expectCoverageOrWaiver(.signature_verify, .{ .signature = .ecdsa_secp256r1_sha256 }, .negative);
    try expectCoverageOrWaiver(.psk_binder, .{ .hkdf = .sha256 }, .negative);
    try expectCoverageOrWaiver(.psk_binder, .{ .hkdf = .sha384 }, .negative);
}
