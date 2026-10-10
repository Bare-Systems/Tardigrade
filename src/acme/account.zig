//! ACME account key, JWK/thumbprint and ES256 JWS signing (#832, epic #759).
//!
//! Native only: P-256 key material lives in the crypto package's
//! `SoftwareEcdsaP256SigningKey` (scalar validation, wiped on `deinit`), and
//! SHA-256/base64url come from `std.crypto`/`std.base64`. No OpenSSL, no
//! foreign crypto. Private material never leaves this type except as a PKCS#8
//! PEM buffer returned to the caller for persistence, which the caller must
//! free with `secrets.secureZeroAndFree`.
//!
//! Protocol semantics follow RFC 8555 §6 (JWS over a flattened JSON
//! serialization) and RFC 7638 (JWK thumbprint); only `ES256` is produced.

const std = @import("std");
const crypto = @import("crypto");
const zig_compat = @import("zig_compat");

const secrets = crypto.secrets;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const SigningKey = crypto.pure_zig.SoftwareEcdsaP256SigningKey;
const b64url = std.base64.url_safe_no_pad;
const b64std = std.base64.standard;

pub const Error = error{
    OutOfMemory,
    InvalidKey,
    KeyGenFailed,
    SignFailed,
    /// A header field (URL, nonce, kid) contains characters that cannot be
    /// embedded in the protected header without escaping.
    InvalidHeaderField,
};

pub const max_nonce_len = 256;
pub const max_header_url_len = 2048;
pub const thumbprint_len = 43; // base64url(SHA-256), unpadded

/// The fixed bytes preceding the 32-byte scalar in the PKCS#8 encoding of a
/// P-256 key that carries its public point (RFC 5958 wrapping RFC 5915), as
/// written by `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`.
const pkcs8_prefix = [_]u8{
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
};
/// Between the scalar and the 65-byte uncompressed public point.
const pkcs8_public_prefix = [_]u8{ 0xa1, 0x44, 0x03, 0x42, 0x00 };
const pkcs8_len = pkcs8_prefix.len + 32 + pkcs8_public_prefix.len + 65;

const pem_begin = "-----BEGIN PRIVATE KEY-----\n";
const pem_end = "-----END PRIVATE KEY-----\n";
/// Upper bound on a key file we are willing to parse.
pub const max_pem_len = 512;

/// Public half of an ES256 account key.
pub const Jwk = struct {
    x: [32]u8,
    y: [32]u8,

    /// Canonical member order (RFC 7638 §3.2): crv, kty, x, y with no
    /// whitespace. The same bytes are the thumbprint input and a valid `jwk`
    /// protected-header member.
    pub fn writeJson(self: Jwk, out: []u8) []const u8 {
        var x_buf: [43]u8 = undefined;
        var y_buf: [43]u8 = undefined;
        const x = b64url.Encoder.encode(&x_buf, &self.x);
        const y = b64url.Encoder.encode(&y_buf, &self.y);
        return std.fmt.bufPrint(out, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ x, y }) catch unreachable;
    }

    pub const max_json_len = 128;

    /// RFC 7638 thumbprint, final base64url string (what RFC 8555 §8.1 uses
    /// in key authorizations).
    pub fn thumbprint(self: Jwk) [thumbprint_len]u8 {
        var json_buf: [max_json_len]u8 = undefined;
        const json = self.writeJson(&json_buf);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(json, &digest, .{});
        var out: [thumbprint_len]u8 = undefined;
        _ = b64url.Encoder.encode(&out, &digest);
        return out;
    }
};

pub const AccountKey = struct {
    key: SigningKey,

    /// Fresh key from OS entropy. A scalar outside [1, n-1] is rejected by the
    /// provider and redrawn; the loop is finite (the failure probability per
    /// draw is ~2^-32).
    pub fn generate() Error!AccountKey {
        var attempts: u8 = 0;
        while (attempts < 16) : (attempts += 1) {
            var scalar: [32]u8 = undefined;
            defer secrets.secureZero(&scalar);
            zig_compat.randomBytes(&scalar);
            if (SigningKey.fromScalarBytes(&scalar)) |key| return .{ .key = key } else |_| {}
        }
        return error.KeyGenFailed;
    }

    pub fn deinit(self: *AccountKey) void {
        secrets.secureZero(&self.key.key_pair.secret_key.bytes);
    }

    pub fn jwk(self: *const AccountKey) Jwk {
        const sec1 = self.key.key_pair.public_key.toUncompressedSec1();
        return .{ .x = sec1[1..33].*, .y = sec1[33..65].* };
    }

    /// Strict loader: exactly the 138-byte PKCS#8 shape this type writes (and
    /// openssl produces), a valid scalar, and an embedded public point that
    /// matches the one derived from it. Anything else is `InvalidKey`.
    pub fn fromPkcs8Der(der: []const u8) Error!AccountKey {
        if (der.len != pkcs8_len) return error.InvalidKey;
        if (!std.mem.eql(u8, der[0..pkcs8_prefix.len], &pkcs8_prefix)) return error.InvalidKey;
        const scalar_end = pkcs8_prefix.len + 32;
        if (!std.mem.eql(u8, der[scalar_end .. scalar_end + pkcs8_public_prefix.len], &pkcs8_public_prefix)) return error.InvalidKey;
        const key = SigningKey.fromScalarBytes(der[pkcs8_prefix.len..scalar_end]) catch return error.InvalidKey;
        var loaded = AccountKey{ .key = key };
        errdefer loaded.deinit();
        const sec1 = loaded.key.key_pair.public_key.toUncompressedSec1();
        if (!std.mem.eql(u8, &sec1, der[scalar_end + pkcs8_public_prefix.len ..])) return error.InvalidKey;
        return loaded;
    }

    /// PEM wrapper: the exact `-----BEGIN PRIVATE KEY-----` armor, standard
    /// base64 in 64-column lines, a single trailing newline, nothing else.
    pub fn fromPkcs8Pem(pem: []const u8) Error!AccountKey {
        if (pem.len > max_pem_len) return error.InvalidKey;
        if (!std.mem.startsWith(u8, pem, pem_begin)) return error.InvalidKey;
        if (!std.mem.endsWith(u8, pem, pem_end)) return error.InvalidKey;
        const body = pem[pem_begin.len .. pem.len - pem_end.len];
        var joined: [max_pem_len]u8 = undefined;
        var joined_len: usize = 0;
        var it = std.mem.splitScalar(u8, body, '\n');
        while (it.next()) |line| {
            if (line.len == 0) {
                // Only the empty remainder after the final newline is allowed.
                if (it.peek() != null) return error.InvalidKey;
                break;
            }
            if (line.len > 64 or joined_len + line.len > joined.len) return error.InvalidKey;
            @memcpy(joined[joined_len .. joined_len + line.len], line);
            joined_len += line.len;
        }
        var der: [pkcs8_len]u8 = undefined;
        defer secrets.secureZero(&der);
        const decoded_len = b64std.Decoder.calcSizeForSlice(joined[0..joined_len]) catch return error.InvalidKey;
        if (decoded_len != pkcs8_len) return error.InvalidKey;
        b64std.Decoder.decode(&der, joined[0..joined_len]) catch return error.InvalidKey;
        return fromPkcs8Der(&der);
    }

    /// Caller owns the result and must free it with `secrets.secureZeroAndFree`.
    pub fn toPkcs8Pem(self: *const AccountKey, allocator: std.mem.Allocator) Error![]u8 {
        var der: [pkcs8_len]u8 = undefined;
        defer secrets.secureZero(&der);
        @memcpy(der[0..pkcs8_prefix.len], &pkcs8_prefix);
        const scalar_end = pkcs8_prefix.len + 32;
        @memcpy(der[pkcs8_prefix.len..scalar_end], &self.key.key_pair.secret_key.bytes);
        @memcpy(der[scalar_end .. scalar_end + pkcs8_public_prefix.len], &pkcs8_public_prefix);
        const sec1 = self.key.key_pair.public_key.toUncompressedSec1();
        @memcpy(der[scalar_end + pkcs8_public_prefix.len ..], &sec1);

        var encoded: [b64std.Encoder.calcSize(pkcs8_len)]u8 = undefined;
        defer secrets.secureZero(&encoded);
        _ = b64std.Encoder.encode(&encoded, &der);

        const line_count = (encoded.len + 63) / 64;
        const total = pem_begin.len + encoded.len + line_count + pem_end.len;
        const out = try allocator.alloc(u8, total);
        errdefer secrets.secureZeroAndFree(allocator, out);
        var at: usize = 0;
        @memcpy(out[at .. at + pem_begin.len], pem_begin);
        at += pem_begin.len;
        var offset: usize = 0;
        while (offset < encoded.len) {
            const n = @min(64, encoded.len - offset);
            @memcpy(out[at .. at + n], encoded[offset .. offset + n]);
            at += n;
            offset += n;
            out[at] = '\n';
            at += 1;
        }
        @memcpy(out[at .. at + pem_end.len], pem_end);
        return out;
    }

    /// Raw `r || s` (RFC 7518 §3.4), 64 bytes.
    pub fn sign(self: *const AccountKey, message: []const u8) Error![64]u8 {
        var noise: [Ecdsa.noise_length]u8 = undefined;
        defer secrets.secureZero(&noise);
        zig_compat.randomBytes(&noise);
        const sig = self.key.key_pair.sign(message, noise) catch return error.SignFailed;
        return sig.toBytes();
    }
};

pub const Auth = union(enum) {
    /// newAccount (and revoke-with-account-key): embed the public JWK.
    jwk,
    /// Everything else: the account URL the CA returned.
    kid: []const u8,
};

pub const SignOptions = struct {
    url: []const u8,
    nonce: []const u8,
    auth: Auth,
};

/// Whether `value` can be embedded in a JSON string with no escaping and no
/// ambiguity: printable ASCII except `"` and `\`.
fn isPlainJsonString(value: []const u8) bool {
    for (value) |byte| {
        if (byte < 0x21 or byte > 0x7e or byte == '"' or byte == '\\') return false;
    }
    return true;
}

fn isBase64UrlToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        const ok = (byte >= 'A' and byte <= 'Z') or (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or byte == '-' or byte == '_';
        if (!ok) return false;
    }
    return true;
}

/// A nonce is opaque to the client but must be a base64url token (RFC 8555
/// §6.5.1) of bounded length; anything else is refused before it can reach a
/// signed header or a log line.
pub fn isValidNonce(nonce: []const u8) bool {
    return nonce.len <= max_nonce_len and isBase64UrlToken(nonce);
}

/// Build the flattened JWS JSON (RFC 7515 §7.2.2) for one ACME request.
/// `payload == null` is the POST-as-GET form (empty payload string, RFC 8555
/// §6.3). Caller owns the result.
pub fn signJws(
    allocator: std.mem.Allocator,
    key: *const AccountKey,
    options: SignOptions,
    payload: ?[]const u8,
) Error![]u8 {
    if (options.url.len == 0 or options.url.len > max_header_url_len or !isPlainJsonString(options.url)) return error.InvalidHeaderField;
    if (!isValidNonce(options.nonce)) return error.InvalidHeaderField;

    var jwk_buf: [Jwk.max_json_len]u8 = undefined;
    var protected_buf: std.ArrayList(u8) = .empty;
    defer protected_buf.deinit(allocator);
    switch (options.auth) {
        .jwk => {
            const jwk_json = key.jwk().writeJson(&jwk_buf);
            try protected_buf.print(allocator, "{{\"alg\":\"ES256\",\"jwk\":{s},\"nonce\":\"{s}\",\"url\":\"{s}\"}}", .{ jwk_json, options.nonce, options.url });
        },
        .kid => |kid| {
            if (kid.len == 0 or kid.len > max_header_url_len or !isPlainJsonString(kid)) return error.InvalidHeaderField;
            try protected_buf.print(allocator, "{{\"alg\":\"ES256\",\"kid\":\"{s}\",\"nonce\":\"{s}\",\"url\":\"{s}\"}}", .{ kid, options.nonce, options.url });
        },
    }

    const protected_b64_len = b64url.Encoder.calcSize(protected_buf.items.len);
    const payload_bytes = payload orelse "";
    const payload_b64_len = b64url.Encoder.calcSize(payload_bytes.len);

    // signing input = protected_b64 "." payload_b64
    const signing_input = try allocator.alloc(u8, protected_b64_len + 1 + payload_b64_len);
    defer allocator.free(signing_input);
    _ = b64url.Encoder.encode(signing_input[0..protected_b64_len], protected_buf.items);
    signing_input[protected_b64_len] = '.';
    _ = b64url.Encoder.encode(signing_input[protected_b64_len + 1 ..], payload_bytes);

    const signature = try key.sign(signing_input);
    var sig_b64: [86]u8 = undefined;
    _ = b64url.Encoder.encode(&sig_b64, &signature);

    return std.fmt.allocPrint(
        allocator,
        "{{\"protected\":\"{s}\",\"payload\":\"{s}\",\"signature\":\"{s}\"}}",
        .{ signing_input[0..protected_b64_len], signing_input[protected_b64_len + 1 ..], sig_b64 },
    );
}

// ---------------------------------------------------------------------------

const testing = std.testing;

// RFC 7515 Appendix A.3 (ES256 example key).
const rfc7515_d = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";
const rfc7515_x = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
const rfc7515_y = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

fn rfc7515Key() !AccountKey {
    var d: [32]u8 = undefined;
    try b64url.Decoder.decode(&d, rfc7515_d);
    return .{ .key = try SigningKey.fromScalarBytes(&d) };
}

test "ACME account: RFC 7515 A.3 scalar derives the published public point" {
    var key = try rfc7515Key();
    defer key.deinit();
    const jwk = key.jwk();
    var x: [43]u8 = undefined;
    var y: [43]u8 = undefined;
    try testing.expectEqualStrings(rfc7515_x, b64url.Encoder.encode(&x, &jwk.x));
    try testing.expectEqualStrings(rfc7515_y, b64url.Encoder.encode(&y, &jwk.y));
}

test "ACME account: JWK JSON is canonical and thumbprint is SHA-256 of it" {
    var key = try rfc7515Key();
    defer key.deinit();
    var buf: [Jwk.max_json_len]u8 = undefined;
    const json = key.jwk().writeJson(&buf);
    try testing.expectEqualStrings(
        "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" ++ rfc7515_x ++ "\",\"y\":\"" ++ rfc7515_y ++ "\"}",
        json,
    );
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(json, &digest, .{});
    var expected: [thumbprint_len]u8 = undefined;
    _ = b64url.Encoder.encode(&expected, &digest);
    const thumb = key.jwk().thumbprint();
    try testing.expectEqualStrings(&expected, &thumb);
}

test "ACME account: PKCS#8 PEM round trips and keeps the same identity" {
    var key = try AccountKey.generate();
    defer key.deinit();
    const pem = try key.toPkcs8Pem(testing.allocator);
    defer secrets.secureZeroAndFree(testing.allocator, pem);
    try testing.expect(std.mem.startsWith(u8, pem, pem_begin));
    try testing.expect(std.mem.endsWith(u8, pem, pem_end));
    try testing.expect(pem.len <= max_pem_len);

    var loaded = try AccountKey.fromPkcs8Pem(pem);
    defer loaded.deinit();
    try testing.expectEqualSlices(u8, &key.jwk().x, &loaded.jwk().x);
    try testing.expectEqualSlices(u8, &key.jwk().y, &loaded.jwk().y);
}

test "ACME account: key loader rejects malformed PEM and DER" {
    var key = try AccountKey.generate();
    defer key.deinit();
    const pem = try key.toPkcs8Pem(testing.allocator);
    defer secrets.secureZeroAndFree(testing.allocator, pem);

    try testing.expectError(error.InvalidKey, AccountKey.fromPkcs8Pem(""));
    try testing.expectError(error.InvalidKey, AccountKey.fromPkcs8Pem(pem[0 .. pem.len - 1]));
    try testing.expectError(error.InvalidKey, AccountKey.fromPkcs8Pem(pem[0 .. pem.len - pem_end.len]));

    const trailing = try std.mem.concat(testing.allocator, u8, &.{ pem, "x" });
    defer secrets.secureZeroAndFree(testing.allocator, trailing);
    try testing.expectError(error.InvalidKey, AccountKey.fromPkcs8Pem(trailing));

    const blank_line = try std.mem.concat(testing.allocator, u8, &.{ pem[0..pem_begin.len], "\n", pem[pem_begin.len..] });
    defer secrets.secureZeroAndFree(testing.allocator, blank_line);
    try testing.expectError(error.InvalidKey, AccountKey.fromPkcs8Pem(blank_line));

    // Mutated DER: every byte flip must fail closed (structure, scalar, or
    // public-point mismatch), never load a different key.
    var der: [pkcs8_len]u8 = undefined;
    defer secrets.secureZero(&der);
    var body: [max_pem_len]u8 = undefined;
    var body_len: usize = 0;
    for (pem[pem_begin.len .. pem.len - pem_end.len]) |c| {
        if (c == '\n') continue;
        body[body_len] = c;
        body_len += 1;
    }
    try b64std.Decoder.decode(&der, body[0..body_len]);
    for (0..der.len) |i| {
        var copy = der;
        defer secrets.secureZero(&copy);
        copy[i] ^= 0x01;
        try testing.expectError(error.InvalidKey, AccountKey.fromPkcs8Der(&copy));
    }
    try testing.expectError(error.InvalidKey, AccountKey.fromPkcs8Der(der[0 .. der.len - 1]));
}

test "ACME account: zero scalar and deinit wipe" {
    var der = [_]u8{0} ** pkcs8_len;
    @memcpy(der[0..pkcs8_prefix.len], &pkcs8_prefix);
    try testing.expectError(error.InvalidKey, AccountKey.fromPkcs8Der(&der));

    var key = try AccountKey.generate();
    var nonzero: u8 = 0;
    for (key.key.key_pair.secret_key.bytes) |b| nonzero |= b;
    try testing.expect(nonzero != 0);
    key.deinit();
    for (key.key.key_pair.secret_key.bytes) |b| try testing.expectEqual(@as(u8, 0), b);
}

fn verifyJws(allocator: std.mem.Allocator, jws_json: []const u8, jwk: Jwk) !std.json.Parsed(std.json.Value) {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, jws_json, .{});
    errdefer parsed.deinit();
    const obj = parsed.value.object;
    const protected = obj.get("protected").?.string;
    const payload = obj.get("payload").?.string;
    const signature = obj.get("signature").?.string;
    var sig_bytes: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 64), try b64url.Decoder.calcSizeForSlice(signature));
    try b64url.Decoder.decode(&sig_bytes, signature);
    const input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ protected, payload });
    defer allocator.free(input);
    var sec1: [65]u8 = undefined;
    sec1[0] = 4;
    @memcpy(sec1[1..33], &jwk.x);
    @memcpy(sec1[33..65], &jwk.y);
    const public_key = try Ecdsa.PublicKey.fromSec1(&sec1);
    try Ecdsa.Signature.fromBytes(sig_bytes).verify(input, public_key);
    return parsed;
}

test "ACME account: signed JWS verifies and carries jwk or kid, url and nonce" {
    var key = try AccountKey.generate();
    defer key.deinit();

    const jws = try signJws(testing.allocator, &key, .{
        .url = "https://ca.test/acme/new-acct",
        .nonce = "oFvnlFP1wIhRlYS2jTaXbA",
        .auth = .jwk,
    }, "{\"termsOfServiceAgreed\":true}");
    defer testing.allocator.free(jws);
    const parsed = try verifyJws(testing.allocator, jws, key.jwk());
    defer parsed.deinit();

    var header_buf: [512]u8 = undefined;
    const protected = parsed.value.object.get("protected").?.string;
    const header_len = try b64url.Decoder.calcSizeForSlice(protected);
    try b64url.Decoder.decode(header_buf[0..header_len], protected);
    const header = try std.json.parseFromSlice(std.json.Value, testing.allocator, header_buf[0..header_len], .{});
    defer header.deinit();
    try testing.expectEqualStrings("ES256", header.value.object.get("alg").?.string);
    try testing.expectEqualStrings("https://ca.test/acme/new-acct", header.value.object.get("url").?.string);
    try testing.expectEqualStrings("oFvnlFP1wIhRlYS2jTaXbA", header.value.object.get("nonce").?.string);
    try testing.expect(header.value.object.get("jwk") != null);
    try testing.expect(header.value.object.get("kid") == null);

    const kid_jws = try signJws(testing.allocator, &key, .{
        .url = "https://ca.test/acme/order",
        .nonce = "abc_DEF-123",
        .auth = .{ .kid = "https://ca.test/acme/acct/1" },
    }, null);
    defer testing.allocator.free(kid_jws);
    const kid_parsed = try verifyJws(testing.allocator, kid_jws, key.jwk());
    defer kid_parsed.deinit();
    try testing.expectEqualStrings("", kid_parsed.value.object.get("payload").?.string);
}

test "ACME account: JWS refuses header fields that need escaping" {
    var key = try AccountKey.generate();
    defer key.deinit();
    const bad_urls = [_][]const u8{ "", "https://ca.test/a\"b", "https://ca.test/a\\b", "https://ca.test/a b", "https://ca.test/\n" };
    for (bad_urls) |url| {
        try testing.expectError(error.InvalidHeaderField, signJws(testing.allocator, &key, .{ .url = url, .nonce = "abc", .auth = .jwk }, null));
    }
    const bad_nonces = [_][]const u8{ "", "a b", "a\"b", "a+b", "a=b", "x" ** (max_nonce_len + 1) };
    for (bad_nonces) |nonce| {
        try testing.expectError(error.InvalidHeaderField, signJws(testing.allocator, &key, .{ .url = "https://ca.test/x", .nonce = nonce, .auth = .jwk }, null));
    }
    try testing.expectError(error.InvalidHeaderField, signJws(testing.allocator, &key, .{ .url = "https://ca.test/x", .nonce = "abc", .auth = .{ .kid = "bad\"kid" } }, null));
}
