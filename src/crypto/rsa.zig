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
