//! Strict RSA-PSS-RSAE-SHA256 verification.

const std = @import("std");
const crypto = std.crypto;
const ff = crypto.ff;

const Sha256 = crypto.hash.sha2.Sha256;
const max_modulus_bits = 4096;
const max_modulus_bytes = max_modulus_bits / 8;

const Error = error{InvalidInput};

const PublicKey = struct {
    modulus: []const u8,
    exponent: []const u8,
    bits: usize,
};

fn lessThanUnsigned(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return a.len < b.len;
    return std.mem.order(u8, a, b) == .lt;
}

fn readLength(input: []const u8, offset: *usize) Error!usize {
    if (offset.* >= input.len) return error.InvalidInput;
    const first = input[offset.*];
    offset.* += 1;
    if (first < 0x80) return first;
    const count = first & 0x7f;
    if (count == 0 or count > 4 or offset.* + count > input.len) return error.InvalidInput;
    if (input[offset.*] == 0) return error.InvalidInput;
    var length: usize = 0;
    for (input[offset.* .. offset.* + count]) |byte| {
        length = (length << 8) | byte;
    }
    offset.* += count;
    if (length < 0x80 or length > input.len - offset.*) return error.InvalidInput;
    return length;
}

fn readInteger(input: []const u8, offset: *usize) Error![]const u8 {
    if (offset.* >= input.len or input[offset.*] != 0x02) return error.InvalidInput;
    offset.* += 1;
    const length = try readLength(input, offset);
    if (length == 0 or length > input.len - offset.*) return error.InvalidInput;
    const value = input[offset.* .. offset.* + length];
    offset.* += length;
    if (value.len > 1 and value[0] == 0 and value[1] & 0x80 == 0) return error.InvalidInput;
    if (value[0] & 0x80 != 0) return error.InvalidInput;
    return value;
}

fn parsePublicKey(der: []const u8) Error!PublicKey {
    if (der.len < 2 or der[0] != 0x30) return error.InvalidInput;
    var offset: usize = 1;
    const sequence_len = try readLength(der, &offset);
    if (sequence_len != der.len - offset) return error.InvalidInput;
    const sequence_end = offset + sequence_len;
    const modulus_encoded = try readInteger(der, &offset);
    const exponent_encoded = try readInteger(der, &offset);
    if (offset != sequence_end) return error.InvalidInput;

    if (modulus_encoded.len == 1 and modulus_encoded[0] == 0) return error.InvalidInput;
    if (exponent_encoded.len == 1 and exponent_encoded[0] == 0) return error.InvalidInput;

    var modulus = modulus_encoded;
    if (modulus[0] == 0) modulus = modulus[1..];
    if (modulus.len == 0 or modulus[0] & 0x80 == 0) return error.InvalidInput;

    const bits = modulus.len * 8;
    if (bits != 2048 and bits != 3072 and bits != 4096) return error.InvalidInput;
    var exponent = exponent_encoded;
    if (exponent[0] == 0) exponent = exponent[1..];
    if (exponent.len == 0 or !lessThanUnsigned(exponent, modulus)) return error.InvalidInput;
    if (exponent.len == 1 and exponent[0] < 3) return error.InvalidInput;
    if (exponent[exponent.len - 1] & 1 == 0) return error.InvalidInput;
    return .{ .modulus = modulus, .exponent = exponent, .bits = bits };
}

fn mgf1(seed: *const [Sha256.digest_length]u8, out: []u8) void {
    var counter: u32 = 0;
    var offset: usize = 0;
    var input: [Sha256.digest_length + 4]u8 = undefined;
    while (offset < out.len) : (counter += 1) {
        @memcpy(input[0..Sha256.digest_length], seed);
        std.mem.writeInt(u32, input[Sha256.digest_length..][0..4], counter, .big);
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(&input, &digest, .{});
        const count = @min(digest.len, out.len - offset);
        @memcpy(out[offset .. offset + count], digest[0..count]);
        offset += count;
    }
}

fn verifyPss(em: []const u8, em_bits: usize, message: []const u8) Error!void {
    const h_len = Sha256.digest_length;
    const salt_len = Sha256.digest_length;
    if (em.len < h_len + salt_len + 2) return error.InvalidInput;
    if (em[em.len - 1] != 0xbc) return error.InvalidInput;

    const db_len = em.len - h_len - 1;
    if (db_len > max_modulus_bytes) return error.InvalidInput;
    const masked_db = em[0..db_len];
    const h = em[db_len .. db_len + h_len];
    const unused_bits = 8 * em.len - em_bits;
    if (unused_bits > 7) return error.InvalidInput;
    // The guard makes the following cast safe because u3 represents 0..7.
    const unused_shift: u3 = @intCast(unused_bits);
    // This mask preserves the meaningful low bits and excludes the unused
    // high-order bits required to be zero by RFC 8017. With zero unused bits
    // it is intentionally 0xff.
    const unused_mask: u8 = @as(u8, 0xff) >> unused_shift;
    // RFC 8017 requires the unused high bits of maskedDB to be zero.
    if (masked_db[0] & ~unused_mask != 0) return error.InvalidInput;

    var m_hash: [h_len]u8 = undefined;
    Sha256.hash(message, &m_hash, .{});
    var db: [max_modulus_bytes]u8 = undefined;
    var mask: [max_modulus_bytes]u8 = undefined;
    const h_array = h[0..h_len].*;
    mgf1(&h_array, mask[0..db_len]);
    for (db[0..db_len], masked_db, mask[0..db_len]) |*out, masked, mask_val| out.* = masked ^ mask_val;
    // Clear the unused high bits of DB before checking its zero-padding PS.
    db[0] &= unused_mask;

    const ps_len = db_len - salt_len - 1;
    for (db[0..ps_len]) |byte| if (byte != 0) return error.InvalidInput;
    if (db[ps_len] != 1) return error.InvalidInput;

    var hash_input: [8 + h_len + salt_len]u8 = undefined;
    @memset(hash_input[0..8], 0);
    @memcpy(hash_input[8 .. 8 + h_len], &m_hash);
    const salt = db[ps_len + 1 ..][0..salt_len];
    @memcpy(hash_input[8 + h_len ..], salt);
    var expected: [h_len]u8 = undefined;
    Sha256.hash(&hash_input, &expected, .{});
    if (!crypto.timing_safe.eql([h_len]u8, expected, h_array)) return error.InvalidInput;
}

/// Verify an RSA-PSS-RSAE-SHA256 signature.
///
/// `public_key_der` is a DER `RSAPublicKey` with a 2048-, 3072-, or 4096-bit
/// modulus. `signature` must be exactly one modulus wide. Malformed keys and
/// wrong-sized signatures return `error.InvalidInput`; a structurally valid
/// signature with invalid EMSA-PSS encoding returns `error.AuthenticationFailed`.
pub fn verifyPssSha256(public_key_der: []const u8, message: []const u8, signature: []const u8) (error{ InvalidInput, AuthenticationFailed })!void {
    const key = parsePublicKey(public_key_der) catch return error.InvalidInput;
    if (signature.len != key.modulus.len) return error.InvalidInput;

    var modulus_fe = ff.Modulus(max_modulus_bits).fromBytes(key.modulus, .big) catch return error.InvalidInput;
    const signature_fe = ff.Modulus(max_modulus_bits).Fe.fromBytes(modulus_fe, signature, .big) catch |err| switch (err) {
        error.NonCanonical => return error.AuthenticationFailed,
        else => return error.InvalidInput,
    };
    const recovered = modulus_fe.powWithEncodedPublicExponent(signature_fe, key.exponent, .big) catch return error.InvalidInput;
    var encoded: [max_modulus_bytes]u8 = undefined;
    recovered.toBytes(encoded[0..key.modulus.len], .big) catch return error.InvalidInput;
    verifyPss(encoded[0..key.modulus.len], key.bits - 1, message) catch return error.AuthenticationFailed;
}

/// Encode a DER length for the short form or two-octet long form used by the
/// synthetic RSA keys below.
fn writeTestLength(out: []u8, offset: *usize, length: usize) void {
    // DER uses one length octet for values up to and including 127.
    if (length <= 0x7f) {
        out[offset.*] = @intCast(length);
        offset.* += 1;
    } else {
        out[offset.*] = 0x82;
        out[offset.* + 1] = @intCast(length >> 8);
        out[offset.* + 2] = @intCast(length);
        offset.* += 3;
    }
}

/// Build an RSAPublicKey with a zero-filled modulus and the requested top byte.
/// `modulus_bytes` excludes the DER sign-padding byte; `modulus_top` controls
/// the high byte for valid-size and low-top-bit rejection cases.
fn makeTestPublicKey(out: []u8, exponent: []const u8, modulus_bytes: usize, modulus_top: u8) []const u8 {
    var offset: usize = 4;
    out[0] = 0x30;
    out[1] = 0x82;
    out[2] = 0;
    out[3] = 0;
    out[offset] = 0x02;
    offset += 1;
    writeTestLength(out, &offset, modulus_bytes + 1);
    out[offset] = 0;
    out[offset + 1] = modulus_top;
    @memset(out[offset + 2 .. offset + modulus_bytes + 1], 0);
    offset += modulus_bytes + 1;
    out[offset] = 0x02;
    offset += 1;
    writeTestLength(out, &offset, exponent.len);
    @memcpy(out[offset .. offset + exponent.len], exponent);
    offset += exponent.len;
    const sequence_len = offset - 4;
    out[2] = @intCast(sequence_len >> 8);
    out[3] = @intCast(sequence_len);
    return out[0..offset];
}

/// Build a deterministic EMSA-PSS-SHA256 encoded message for direct decoder
/// tests. `out.len` determines the encoded-message size and `em_bits` selects
/// the number of meaningful high-order bits; the output must fit the fixed
/// maximum modulus buffer and leave room for the hash and salt.
fn encodePssForTest(message: []const u8, salt: [Sha256.digest_length]u8, out: []u8, em_bits: usize) void {
    const h_len = Sha256.digest_length;
    const db_len = out.len - h_len - 1;
    const ps_len = db_len - h_len - 1;
    var m_hash: [h_len]u8 = undefined;
    Sha256.hash(message, &m_hash, .{});
    var db: [max_modulus_bytes]u8 = undefined;
    @memset(db[0..db_len], 0);
    db[ps_len] = 1;
    @memcpy(db[ps_len + 1 .. db_len], &salt);
    var hash_input: [8 + h_len + h_len]u8 = undefined;
    @memset(hash_input[0..8], 0);
    @memcpy(hash_input[8 .. 8 + h_len], &m_hash);
    @memcpy(hash_input[8 + h_len ..], &salt);
    var h: [h_len]u8 = undefined;
    Sha256.hash(&hash_input, &h, .{});
    var mask: [max_modulus_bytes]u8 = undefined;
    mgf1(&h, mask[0..db_len]);
    for (out[0..db_len], db[0..db_len], mask[0..db_len]) |*dst, value, mask_byte| {
        dst.* = value ^ mask_byte;
    }
    const unused_bits: u3 = @intCast(8 * out.len - em_bits);
    out[0] &= @as(u8, 0xff) >> unused_bits;
    @memcpy(out[db_len .. db_len + h_len], &h);
    out[out.len - 1] = 0xbc;
}

test "EMSA-PSS rejects every nonzero PS byte and structural corruption" {
    var encoded: [256]u8 = undefined;
    encodePssForTest("message", [_]u8{0x42} ** Sha256.digest_length, &encoded, 2047);
    try verifyPss(&encoded, 2047, "message");

    const db_len = encoded.len - Sha256.digest_length - 1;
    const ps_len = db_len - Sha256.digest_length - 1;
    for (0..ps_len) |position| {
        var corrupted = encoded;
        corrupted[position] ^= 1;
        try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    }

    var corrupted = encoded;
    corrupted[0] |= 0x80;
    try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    corrupted = encoded;
    corrupted[ps_len] ^= 1;
    try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    corrupted = encoded;
    corrupted[db_len] ^= 1;
    try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    corrupted = encoded;
    corrupted[ps_len + 1] ^= 1;
    try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    corrupted = encoded;
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidInput, verifyPss(&corrupted, 2047, "message"));
    try std.testing.expectError(error.InvalidInput, verifyPss(&encoded, 2047, "wrong message"));
}

test "RSA public-key DER rejects malformed encodings and unsupported moduli" {
    const exponent = [_]u8{ 1, 0, 1 };
    var der: [300]u8 = undefined;
    const key = makeTestPublicKey(&der, &exponent, max_modulus_bytes, 0x80);
    _ = try parsePublicKey(key);
    try std.testing.expectError(error.InvalidInput, parsePublicKey(&[_]u8{}));
    try std.testing.expectError(error.InvalidInput, parsePublicKey(&[_]u8{0x30}));
    try std.testing.expectError(error.InvalidInput, parsePublicKey(&[_]u8{ 0x30, 0x82, 0x01 }));
    try std.testing.expectError(error.InvalidInput, parsePublicKey(key[0 .. key.len - 1]));

    var nonminimal_length = der;
    nonminimal_length[2] = 0;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(nonminimal_length[0..key.len]));
    var nonminimal_integer = der;
    nonminimal_integer[9] = 0;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(nonminimal_integer[0..key.len]));

    var low_top_bit = der;
    low_top_bit[9] = 0x7f;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(low_top_bit[0..key.len]));

    var unsupported_size: [300]u8 = undefined;
    const short_key = makeTestPublicKey(&unsupported_size, &exponent, 255, 0x80);
    try std.testing.expectError(error.InvalidInput, parsePublicKey(short_key));
}

test "RSA public-key DER enforces exponent range and parity" {
    const cases = [_][]const u8{
        &[_]u8{0},
        &[_]u8{1},
        &[_]u8{2},
        &[_]u8{4},
    };
    for (cases) |exponent| {
        var der: [300]u8 = undefined;
        try std.testing.expectError(error.InvalidInput, parsePublicKey(makeTestPublicKey(&der, exponent, max_modulus_bytes, 0x80)));
    }

    // 257 bytes matches the encoded 2048-bit modulus with its sign byte.
    var equal_size_exponent: [257]u8 = [_]u8{0} ** 257;
    // The leading sign byte makes this exponent equal in encoded size to n.
    equal_size_exponent[1] = 0x80;
    var equal_size_der: [600]u8 = undefined;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(makeTestPublicKey(&equal_size_der, &equal_size_exponent, max_modulus_bytes, 0x80)));
    equal_size_exponent[1] = 0xff;
    var greater_size_der: [600]u8 = undefined;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(makeTestPublicKey(&greater_size_der, &equal_size_exponent, max_modulus_bytes, 0x80)));
    var exponent_too_long: [258]u8 = [_]u8{0} ** 258;
    exponent_too_long[1] = 0x80;
    var longer_der: [600]u8 = undefined;
    try std.testing.expectError(error.InvalidInput, parsePublicKey(makeTestPublicKey(&longer_der, &exponent_too_long, max_modulus_bytes, 0x80)));
}

test "RSA-PSS rejects short, long, and out-of-range signatures" {
    const exponent = [_]u8{ 1, 0, 1 };
    var der: [300]u8 = undefined;
    const key = makeTestPublicKey(&der, &exponent, max_modulus_bytes, 0x80);
    // This signature equals the minimum valid modulus used by the test key.
    const signature_equal_to_modulus = [_]u8{0x80} ++ ([_]u8{0} ** (max_modulus_bytes - 1));
    const signature_greater_than_modulus = [_]u8{0xff} ** max_modulus_bytes;
    try std.testing.expectError(error.AuthenticationFailed, verifyPssSha256(key, "message", &signature_equal_to_modulus));
    try std.testing.expectError(error.AuthenticationFailed, verifyPssSha256(key, "message", &signature_greater_than_modulus));
    try std.testing.expectError(error.InvalidInput, verifyPssSha256(key, "message", signature_equal_to_modulus[0 .. signature_equal_to_modulus.len - 1]));
    var long_signature: [max_modulus_bytes + 1]u8 = undefined;
    try std.testing.expectError(error.InvalidInput, verifyPssSha256(key, "message", &long_signature));
}
