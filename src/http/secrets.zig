const std = @import("std");
const compat = @import("../zig_compat.zig");

/// AES-256-GCM AEAD used for `ENC2:` secret storage.
/// Key length: 32 bytes. Nonce length: 12 bytes. Tag length: 16 bytes.
pub const SecretAead = std.crypto.aead.aes_gcm.Aes256Gcm;

/// Encrypt `plaintext` under `key` using AES-256-GCM and return a heap-allocated
/// blob: `nonce (12 B) || ciphertext || tag (16 B)`.
/// Caller owns the returned slice.
pub fn encryptSecret(allocator: std.mem.Allocator, plaintext: []const u8, key: [SecretAead.key_length]u8) ![]u8 {
    var nonce: [SecretAead.nonce_length]u8 = undefined;
    compat.randomBytes(&nonce);

    const blob_len = SecretAead.nonce_length + plaintext.len + SecretAead.tag_length;
    const blob = try allocator.alloc(u8, blob_len);
    errdefer allocator.free(blob);

    const ciphertext_out = blob[SecretAead.nonce_length .. SecretAead.nonce_length + plaintext.len];
    var tag: [SecretAead.tag_length]u8 = undefined;
    SecretAead.encrypt(ciphertext_out, &tag, plaintext, "", nonce, key);
    @memcpy(blob[0..SecretAead.nonce_length], &nonce);
    @memcpy(blob[SecretAead.nonce_length + plaintext.len ..], &tag);
    return blob;
}

/// Decrypt a blob produced by `encryptSecret`. Returns the plaintext.
/// Caller owns the returned slice.
pub fn decryptSecret(allocator: std.mem.Allocator, blob: []const u8, key: [SecretAead.key_length]u8) ![]u8 {
    const min_len = SecretAead.nonce_length + SecretAead.tag_length;
    if (blob.len < min_len) return error.InvalidBlob;

    const nonce = blob[0..SecretAead.nonce_length].*;
    const ciphertext = blob[SecretAead.nonce_length .. blob.len - SecretAead.tag_length];
    const tag_start = blob.len - SecretAead.tag_length;
    const tag: [SecretAead.tag_length]u8 = blob[tag_start..][0..SecretAead.tag_length].*;

    const plain = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plain);
    SecretAead.decrypt(plain, ciphertext, tag, "", nonce, key) catch return error.AuthenticationFailed;
    return plain;
}

pub const Overrides = struct {
    map: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) Overrides {
        return .{ .map = std.StringHashMap([]const u8).init(allocator) };
    }

    pub fn deinit(self: *Overrides, allocator: std.mem.Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
    }
};

pub fn loadOverrides(allocator: std.mem.Allocator) !Overrides {
    const path = compat.getEnvVarOwned(allocator, "TARDIGRADE_SECRETS_PATH") catch {
        return Overrides.init(allocator);
    };
    defer allocator.free(path);

    const keys_raw = compat.getEnvVarOwned(allocator, "TARDIGRADE_SECRET_KEYS") catch "";
    defer if (keys_raw.len > 0) allocator.free(keys_raw);
    if (keys_raw.len == 0) return Overrides.init(allocator);

    const key_list = try parseKeyList(allocator, keys_raw);
    defer {
        for (key_list) |k| allocator.free(k);
        allocator.free(key_list);
    }

    var out = Overrides.init(allocator);
    errdefer out.deinit(allocator);

    const raw = try std.Io.Dir.cwd().readFileAlloc(compat.io(), path, allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(raw);
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line_raw| {
        const no_comment = line_raw[0 .. std.mem.findScalar(u8, line_raw, '#') orelse line_raw.len];
        const line = std.mem.trim(u8, no_comment, " \t\r\n");
        if (line.len == 0) continue;
        const eq = std.mem.findScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (key.len == 0 or value.len == 0) continue;

        const plain = if (std.mem.startsWith(u8, value, "ENC2:"))
            try decryptValueAesGcm(allocator, value["ENC2:".len..], key_list)
        else if (std.mem.startsWith(u8, value, "ENC:"))
            try decryptValue(allocator, value["ENC:".len..], key_list)
        else
            try allocator.dupe(u8, value);
        defer allocator.free(plain);

        try putOverride(allocator, &out.map, key, plain);
    }

    return out;
}

fn putOverride(allocator: std.mem.Allocator, map: *std.StringHashMap([]const u8), key_raw: []const u8, value_raw: []const u8) !void {
    const key = try allocator.dupe(u8, key_raw);
    errdefer allocator.free(key);
    const val = try allocator.dupe(u8, value_raw);
    errdefer allocator.free(val);
    if (map.fetchRemove(key_raw)) |old| {
        allocator.free(old.key);
        allocator.free(old.value);
    }
    try map.put(key, val);
}

fn parseKeyList(allocator: std.mem.Allocator, raw: []const u8) ![][]u8 {
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |k| allocator.free(k);
        out.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        const key = try hexDecode(allocator, trimmed);
        if (key.len == 0) {
            allocator.free(key);
            continue;
        }
        try out.append(allocator, key);
    }
    return try out.toOwnedSlice(allocator);
}

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return allocator.alloc(u8, 0);
    var out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        const hi = std.fmt.charToDigit(hex[i * 2], 16) catch return allocator.alloc(u8, 0);
        const lo = std.fmt.charToDigit(hex[i * 2 + 1], 16) catch return allocator.alloc(u8, 0);
        out[i] = @as(u8, @intCast((hi << 4) | lo));
    }
    return out;
}

/// Decrypt an `ENC2:` value (AES-256-GCM).
/// Tries each key in `keys` that is exactly 32 bytes long.
fn decryptValueAesGcm(allocator: std.mem.Allocator, encoded: []const u8, keys: [][]u8) ![]u8 {
    const dec_len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    const blob = try allocator.alloc(u8, dec_len);
    defer allocator.free(blob);
    try std.base64.standard.Decoder.decode(blob, encoded);

    for (keys) |key_bytes| {
        if (key_bytes.len != SecretAead.key_length) continue;
        const key: [SecretAead.key_length]u8 = key_bytes[0..SecretAead.key_length].*;
        const plain = decryptSecret(allocator, blob, key) catch continue;
        return plain;
    }
    return error.SecretDecryptFailed;
}

fn decryptValue(allocator: std.mem.Allocator, encoded: []const u8, keys: [][]u8) ![]u8 {
    // Simple XOR envelope for branch-local encrypted secret storage (legacy).
    // ENC:<base64(xor(plaintext,key))>
    // Prefer ENC2: (AES-256-GCM) for new secrets.
    const dec_len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    const cipher = try allocator.alloc(u8, dec_len);
    defer allocator.free(cipher);
    try std.base64.standard.Decoder.decode(cipher, encoded);
    const decoded = cipher;
    for (keys) |key| {
        if (key.len == 0) continue;
        var plain = try allocator.alloc(u8, decoded.len);
        errdefer allocator.free(plain);
        for (decoded, 0..) |b, i| plain[i] = b ^ key[i % key.len];
        if (plain.len < 4 or !std.mem.eql(u8, plain[0..4], "TG1:")) {
            allocator.free(plain);
            continue;
        }
        const out = try allocator.dupe(u8, plain[4..]);
        allocator.free(plain);
        return out;
    }
    return error.SecretDecryptFailed;
}

test "AES-256-GCM encrypt and decrypt roundtrip" {
    const allocator = std.testing.allocator;
    var key: [SecretAead.key_length]u8 = undefined;
    compat.randomBytes(&key);

    const plaintext = "top-secret-value";
    const blob = try encryptSecret(allocator, plaintext, key);
    defer allocator.free(blob);

    // blob must contain nonce + ciphertext + tag
    try std.testing.expectEqual(SecretAead.nonce_length + plaintext.len + SecretAead.tag_length, blob.len);

    const recovered = try decryptSecret(allocator, blob, key);
    defer allocator.free(recovered);
    try std.testing.expectEqualStrings(plaintext, recovered);
}

test "AES-256-GCM decrypt fails with wrong key" {
    const allocator = std.testing.allocator;
    var key: [SecretAead.key_length]u8 = undefined;
    compat.randomBytes(&key);
    var bad_key: [SecretAead.key_length]u8 = undefined;
    compat.randomBytes(&bad_key);

    const blob = try encryptSecret(allocator, "secret", key);
    defer allocator.free(blob);

    const err = decryptSecret(allocator, blob, bad_key);
    try std.testing.expectError(error.AuthenticationFailed, err);
}

test "AES-256-GCM produces distinct ciphertexts for same plaintext (nonce randomness)" {
    const allocator = std.testing.allocator;
    var key: [SecretAead.key_length]u8 = undefined;
    compat.randomBytes(&key);

    const plain = "determinism-test";
    const blob1 = try encryptSecret(allocator, plain, key);
    defer allocator.free(blob1);
    const blob2 = try encryptSecret(allocator, plain, key);
    defer allocator.free(blob2);

    // Different nonces mean different ciphertexts (with overwhelming probability).
    try std.testing.expect(!std.mem.eql(u8, blob1, blob2));
}

test "ENC2 base64 roundtrip via decryptValueAesGcm" {
    const allocator = std.testing.allocator;
    var key_bytes: [SecretAead.key_length]u8 = undefined;
    compat.randomBytes(&key_bytes);

    const plaintext = "my-database-password";
    const blob = try encryptSecret(allocator, plaintext, key_bytes);
    defer allocator.free(blob);

    // Base64-encode the blob (as ENC2: would store it).
    const enc_len = std.base64.standard.Encoder.calcSize(blob.len);
    const enc = try allocator.alloc(u8, enc_len);
    defer allocator.free(enc);
    _ = std.base64.standard.Encoder.encode(enc, blob);

    var keys = std.ArrayList([]u8).empty;
    defer keys.deinit(allocator);
    const key_copy = try allocator.dupe(u8, &key_bytes);
    defer allocator.free(key_copy);
    try keys.append(allocator, key_copy);

    const out = try decryptValueAesGcm(allocator, enc, keys.items);
    defer allocator.free(out);
    try std.testing.expectEqualStrings(plaintext, out);
}

test "decrypt xor envelope with key rotation list" {
    const allocator = std.testing.allocator;
    const plain = "TG1:supersecret";
    const key = "aabbccddeeff00112233445566778899";
    const key_bytes = try hexDecode(allocator, key);
    defer allocator.free(key_bytes);

    var cipher = try allocator.alloc(u8, plain.len);
    defer allocator.free(cipher);
    for (plain, 0..) |c, i| cipher[i] = c ^ key_bytes[i % key_bytes.len];
    const enc_len = std.base64.standard.Encoder.calcSize(cipher.len);
    const enc = try allocator.alloc(u8, enc_len);
    defer allocator.free(enc);
    _ = std.base64.standard.Encoder.encode(enc, cipher);

    var keys = std.ArrayList([]u8).empty;
    defer keys.deinit(allocator);
    try keys.append(allocator, try hexDecode(allocator, "0000000000000000"));
    try keys.append(allocator, try hexDecode(allocator, key));
    defer {
        for (keys.items) |k| allocator.free(k);
    }

    const out = try decryptValue(allocator, enc, keys.items);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("supersecret", out);
}
