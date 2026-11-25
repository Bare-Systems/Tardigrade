//! Native RFC 8737 TLS-ALPN-01 challenge certificate construction (#938,
//! A6-2 of #759). Depends on the merged #932 lease registry
//! (`tls_alpn_challenges.zig`).
//!
//! `build` consumes one already-admitted `Registry.Lease` and returns a
//! short-lived, self-signed, native-Zig X.509 leaf: a fresh ephemeral P-256
//! key (never the ACME account key, never a persistent serving-site leaf
//! key), SAN = exactly the lease's canonical DNS identifier, and a critical
//! `id-pe-acmeIdentifier` extension (RFC 8737 S3) carrying
//! SHA-256(keyAuthorization). DER is assembled with `pki.der`/`pki.oid` --
//! the same primitives `csr.zig`'s PKCS#10 writer uses -- so nothing here
//! depends on the test-only `test_cert_builder.zig` or any C/OpenSSL crypto.
//! The resulting key is the same `crypto.pure_zig.SoftwareEcdsaP256SigningKey`
//! type the native TLS 1.3 handshake signer already consumes elsewhere, so
//! a `ChallengeIdentity` is directly usable there without conversion.
//!
//! This module only constructs validation material. It never hooks into
//! ClientHello/SNI selection, never advertises `acme-tls/1`, and the
//! resulting certificate is reachable only through the `ChallengeIdentity`
//! this returns -- never through ordinary HTTPS identity lookup. Wiring a
//! `ChallengeIdentity` into the native handshake is a successor child's job
//! (#836 tracks final A6 acceptance; do not close it from here).
//!
//! `build` takes ownership of the `Lease` it is given: every failure path
//! deinitializes (and so wipes) it before returning, and a successful
//! `ChallengeIdentity.deinit` wipes the ephemeral private key and releases
//! the lease's material together, in one call.

const std = @import("std");
const pki = @import("pki");
const crypto = @import("crypto");
const zig_compat = @import("zig_compat");
const account_mod = @import("account.zig");
const names_mod = @import("names.zig");
const challenges_mod = @import("tls_alpn_challenges.zig");
const challenge_store_mod = @import("../http/acme_challenge_store.zig");

const secrets = crypto.secrets;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Tag = pki.der.Tag;

pub const Error = error{
    OutOfMemory,
    InvalidHost,
    InvalidKeyAuthorization,
    InvalidValidity,
    KeyGenFailed,
    SignFailed,
};

/// Structurally `account.AccountKey` (same OS-entropy P-256 generation,
/// scalar validation, wipe-on-`deinit`): the name documents usage, not a
/// different type -- see `csr.LeafKey`'s identical convention.
pub const ChallengeKey = account_mod.AccountKey;

/// RFC 8555 S8.1 key authorizations are `token "." thumbprint`; this is the
/// same bound `acme_challenge_store.max_key_authorization_len` enforces for
/// the HTTP-01 value of identical shape.
pub const max_key_authorization_len: usize = challenge_store_mod.max_key_authorization_len;

/// Certificate validity never extends more than this past `not_before`,
/// regardless of how far out the lease's own expiry is -- matches
/// `tls_alpn_challenges.default_ttl_s`, the bound the registry already
/// enforces on lease lifetime.
pub const max_validity_s: i64 = challenges_mod.default_ttl_s;

const SEQUENCE = Tag.universal(16, true);
const INTEGER = Tag.universal(2, false);
const BIT_STRING = Tag.universal(3, false);
const OCTET_STRING = Tag.universal(4, false);
const OBJECT_IDENTIFIER = Tag.universal(6, false);
const BOOLEAN = Tag.universal(1, false);
const UTC_TIME = Tag.universal(23, false);

pub const ChallengeIdentity = struct {
    allocator: std.mem.Allocator,
    /// DER X.509 leaf: self-signed, CA=false, exactly one SAN dNSName,
    /// critical id-pe-acmeIdentifier. Not secret -- it is exactly what a
    /// validating client receives.
    certificate_der: []u8,
    /// Ephemeral signing key matching `certificate_der`'s public key.
    key: ChallengeKey,
    /// The consumed lease (see module doc): released by `deinit`, not
    /// separately by the caller.
    lease: challenges_mod.Lease,

    /// Wipes the ephemeral private key, frees the certificate DER, and
    /// releases (wiping) the lease's material -- one call, no separate
    /// `lease.deinit()` needed or expected from the caller.
    pub fn deinit(self: *ChallengeIdentity) void {
        self.key.deinit();
        self.allocator.free(self.certificate_der);
        self.lease.deinit();
    }
};

/// Consumes `lease` (see module doc) and builds the `ChallengeIdentity` it
/// authorizes. Re-validates the lease's host and material even though
/// `tls_alpn_challenges.Registry` already did -- the same defense-in-depth
/// posture `csr.validateGroup` documents for its own caller -- so this never
/// trusts an arbitrary or forged lease. `not_before` is the certificate's
/// start of validity and the clock `max_validity_s`/lease-expiry capping is
/// measured from; a lease that is already at or past its own expiry by
/// `not_before` fails with `InvalidValidity` and no certificate is built.
pub fn build(allocator: std.mem.Allocator, lease: challenges_mod.Lease, not_before: i64) Error!ChallengeIdentity {
    var owned_lease = lease;
    errdefer owned_lease.deinit();

    names_mod.validateName(owned_lease.host, true) catch return error.InvalidHost;
    if (!isValidKeyAuthorization(owned_lease.material)) return error.InvalidKeyAuthorization;

    const capped_after = std.math.add(i64, not_before, max_validity_s) catch std.math.maxInt(i64);
    const not_after = @min(owned_lease.expires_at, capped_after);
    if (not_after <= not_before) return error.InvalidValidity;

    var digest: [32]u8 = undefined;
    Sha256.hash(owned_lease.material, &digest, .{});

    var key = ChallengeKey.generate() catch return error.KeyGenFailed;
    errdefer key.deinit();

    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    defer arena_inst.deinit();
    const der = try buildCertificate(arena_inst.allocator(), &key, owned_lease.host, &digest, not_before, not_after);
    const owned_der = allocator.dupe(u8, der) catch return error.OutOfMemory;

    return .{ .allocator = allocator, .certificate_der = owned_der, .key = key, .lease = owned_lease };
}

/// RFC 8555 S8.1 shape: `token "." thumbprint`, both base64url, the
/// thumbprint exactly `account.thumbprint_len` and the token within
/// `acme_challenge_store`'s HTTP-01 token bounds (the same grammar an ACME
/// server-minted value of this kind must already satisfy).
fn isValidKeyAuthorization(value: []const u8) bool {
    if (value.len == 0 or value.len > max_key_authorization_len) return false;
    const dot = std.mem.indexOfScalar(u8, value, '.') orelse return false;
    const token = value[0..dot];
    const thumbprint = value[dot + 1 ..];
    if (token.len < challenge_store_mod.min_token_len or token.len > challenge_store_mod.max_token_len) return false;
    if (thumbprint.len != account_mod.thumbprint_len) return false;
    if (std.mem.indexOfScalar(u8, thumbprint, '.') != null) return false;
    for (value, 0..) |c, i| {
        if (i == dot) continue;
        if (!isBase64UrlChar(c)) return false;
    }
    return true;
}

fn isBase64UrlChar(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-' or c == '_';
}

// ---------------------------------------------------------------------------
// DER assembly
// ---------------------------------------------------------------------------

/// One TLV, concatenating already-encoded `parts` as its content. Mirrors
/// `csr.zig`'s `tlv` helper (same `pki.der` tag/length primitives); the
/// `catch unreachable`s there document why encoding cannot fail for the
/// small universal/context tag numbers and sub-64KiB content this module
/// ever produces -- the same reasoning applies here.
fn tlv(allocator: std.mem.Allocator, tag: Tag, parts: []const []const u8) error{OutOfMemory}![]u8 {
    var total: usize = 0;
    for (parts) |part| total += part.len;
    var tag_buf: [2]u8 = undefined;
    const tag_len = pki.der.encodeTag(tag, &tag_buf) catch unreachable;
    var len_buf: [4]u8 = undefined;
    const len_len = pki.der.encodeLength(total, &len_buf) catch unreachable;
    const out = try allocator.alloc(u8, tag_len + len_len + total);
    @memcpy(out[0..tag_len], tag_buf[0..tag_len]);
    @memcpy(out[tag_len..][0..len_len], len_buf[0..len_len]);
    var offset = tag_len + len_len;
    for (parts) |part| {
        @memcpy(out[offset..][0..part.len], part);
        offset += part.len;
    }
    return out;
}

fn oidTlv(allocator: std.mem.Allocator, components: []const u32) error{OutOfMemory}![]u8 {
    var buf: [16]u8 = undefined;
    const n = pki.oid.encodeComponents(components, &buf) catch unreachable;
    return tlv(allocator, OBJECT_IDENTIFIER, &.{buf[0..n]});
}

fn algorithmEcdsaSha256(allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    return tlv(allocator, SEQUENCE, &.{try oidTlv(allocator, &pki.oid.well_known.ecdsa_with_sha256)});
}

fn emptyName(allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    return tlv(allocator, SEQUENCE, &.{});
}

fn versionTlv(allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    return tlv(allocator, Tag.contextSpecific(0, true), &.{try tlv(allocator, INTEGER, &.{&[_]u8{2}})});
}

/// A random, minimal two's-complement-positive serial (RFC 5280 S4.1.2.2):
/// trims leading zero bytes from fresh entropy, then restores exactly one
/// zero byte iff the first significant byte's sign bit is set.
fn randomSerialContent(buf: *[17]u8) []const u8 {
    var raw: [16]u8 = undefined;
    zig_compat.randomBytes(&raw);
    var start: usize = 0;
    while (start < raw.len - 1 and raw[start] == 0) start += 1;
    const significant = raw[start..];
    if (significant[0] & 0x80 != 0) {
        buf[0] = 0;
        @memcpy(buf[1..][0..significant.len], significant);
        return buf[0 .. 1 + significant.len];
    }
    @memcpy(buf[0..significant.len], significant);
    return buf[0..significant.len];
}

fn utcTimeContent(buf: *[13]u8, unix: i64) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(unix) };
    const day_seconds = es.getDaySeconds();
    const year_day = es.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const yy: u8 = @intCast(year_day.year % 100);
    return std.fmt.bufPrint(buf, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
        yy,
        month_day.month.numeric(),
        @as(u8, month_day.day_index) + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    }) catch unreachable;
}

fn validityTlv(allocator: std.mem.Allocator, not_before: i64, not_after: i64) error{OutOfMemory}![]u8 {
    var nb_buf: [13]u8 = undefined;
    var na_buf: [13]u8 = undefined;
    return tlv(allocator, SEQUENCE, &.{
        try tlv(allocator, UTC_TIME, &.{utcTimeContent(&nb_buf, not_before)}),
        try tlv(allocator, UTC_TIME, &.{utcTimeContent(&na_buf, not_after)}),
    });
}

fn spkiEcdsaP256(allocator: std.mem.Allocator, key: *const ChallengeKey) error{OutOfMemory}![]u8 {
    const algorithm = try tlv(allocator, SEQUENCE, &.{
        try oidTlv(allocator, &pki.oid.well_known.ec_public_key),
        try oidTlv(allocator, &pki.oid.well_known.secp256r1),
    });
    const sec1 = key.key.key_pair.public_key.toUncompressedSec1();
    var pub_bits: [1 + sec1.len]u8 = undefined;
    pub_bits[0] = 0; // no unused bits
    @memcpy(pub_bits[1..], &sec1);
    return tlv(allocator, SEQUENCE, &.{ algorithm, try tlv(allocator, BIT_STRING, &.{&pub_bits}) });
}

fn extensionTlv(allocator: std.mem.Allocator, ext_oid: []const u32, critical: bool, value: []const u8) error{OutOfMemory}![]u8 {
    const oid = try oidTlv(allocator, ext_oid);
    const octet = try tlv(allocator, OCTET_STRING, &.{value});
    if (critical) {
        return tlv(allocator, SEQUENCE, &.{ oid, try tlv(allocator, BOOLEAN, &.{&[_]u8{0xff}}), octet });
    }
    // `critical` is DEFAULT FALSE and omitted in canonical DER.
    return tlv(allocator, SEQUENCE, &.{ oid, octet });
}

/// Exactly one dNSName -- the lease's own canonical identifier, already
/// re-validated by `build` -- never a wildcard, never a second name.
fn sanExtension(allocator: std.mem.Allocator, host: []const u8) error{OutOfMemory}![]u8 {
    const dns_name_tlv = try tlv(allocator, Tag.contextSpecific(2, false), &.{host});
    const general_names = try tlv(allocator, SEQUENCE, &.{dns_name_tlv});
    return extensionTlv(allocator, &pki.oid.well_known.subject_alt_name, false, general_names);
}

/// digitalSignature is the lone asserted named bit: one content octet with
/// 7 unused trailing bits (RFC 5280 S4.2.1.3's DER named-bit minimization
/// drops everything after the last set bit).
fn keyUsageExtension(allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    const bits = try tlv(allocator, BIT_STRING, &.{&[_]u8{ 7, 0x80 }});
    return extensionTlv(allocator, &pki.oid.well_known.key_usage, true, bits);
}

/// Empty BasicConstraints SEQUENCE: `cA` DEFAULT FALSE is omitted per
/// canonical DER, which is exactly the non-CA assertion this leaf needs.
fn basicConstraintsExtension(allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    const value = try tlv(allocator, SEQUENCE, &.{});
    return extensionTlv(allocator, &pki.oid.well_known.basic_constraints, true, value);
}

/// RFC 8737 S3: extnValue wraps a DER OCTET STRING containing exactly the
/// 32-byte SHA-256(keyAuthorization) digest.
fn acmeIdentifierExtension(allocator: std.mem.Allocator, digest: *const [32]u8) error{OutOfMemory}![]u8 {
    const inner = try tlv(allocator, OCTET_STRING, &.{digest});
    return extensionTlv(allocator, &pki.oid.well_known.acme_identifier, true, inner);
}

fn extensionsTlv(allocator: std.mem.Allocator, host: []const u8, digest: *const [32]u8) error{OutOfMemory}![]u8 {
    const entries = try tlv(allocator, SEQUENCE, &.{
        try sanExtension(allocator, host),
        try keyUsageExtension(allocator),
        try basicConstraintsExtension(allocator),
        try acmeIdentifierExtension(allocator, digest),
    });
    return tlv(allocator, Tag.contextSpecific(3, true), &.{entries});
}

/// Subject is the empty `Name` (zero RDNs), same as `csr.zig`'s CSR subject:
/// identity lives entirely in the SAN extension. Self-signed, so issuer is
/// the identical empty `Name`.
fn buildTbs(allocator: std.mem.Allocator, key: *const ChallengeKey, host: []const u8, digest: *const [32]u8, not_before: i64, not_after: i64) error{OutOfMemory}![]u8 {
    var serial_buf: [17]u8 = undefined;
    const name = try emptyName(allocator);
    return tlv(allocator, SEQUENCE, &.{
        try versionTlv(allocator),
        try tlv(allocator, INTEGER, &.{randomSerialContent(&serial_buf)}),
        try algorithmEcdsaSha256(allocator),
        name,
        try validityTlv(allocator, not_before, not_after),
        name,
        try spkiEcdsaP256(allocator, key),
        try extensionsTlv(allocator, host, digest),
    });
}

fn buildCertificate(allocator: std.mem.Allocator, key: *const ChallengeKey, host: []const u8, digest: *const [32]u8, not_before: i64, not_after: i64) Error![]u8 {
    const tbs = try buildTbs(allocator, key, host, digest, not_before, not_after);

    var noise: [Ecdsa.noise_length]u8 = undefined;
    defer secrets.secureZero(&noise);
    zig_compat.randomBytes(&noise);
    const signature = key.key.key_pair.sign(tbs, noise) catch return error.SignFailed;
    var sig_der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = signature.toDer(&sig_der_buf);

    var sig_bits: [1 + Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    sig_bits[0] = 0; // no unused bits
    @memcpy(sig_bits[1 .. 1 + sig_der.len], sig_der);

    return tlv(allocator, SEQUENCE, &.{
        tbs,
        try algorithmEcdsaSha256(allocator),
        try tlv(allocator, BIT_STRING, &.{sig_bits[0 .. 1 + sig_der.len]}),
    });
}

// ---------------------------------------------------------------------------

const testing = std.testing;

const test_binding: challenges_mod.Binding = [_]u8{0xAB} ** 32;
const valid_token = "a" ** 32;
const valid_thumbprint = "b" ** account_mod.thumbprint_len;
const valid_key_authorization = valid_token ++ "." ++ valid_thumbprint;

fn testLease(allocator: std.mem.Allocator, host: []const u8, material: []const u8, binding: challenges_mod.Binding, expires_at: i64) !challenges_mod.Lease {
    const owned_host = try allocator.dupe(u8, host);
    errdefer allocator.free(owned_host);
    const owned_material = try allocator.dupe(u8, material);
    return .{ .allocator = allocator, .host = owned_host, .binding = binding, .material = owned_material, .expires_at = expires_at };
}

test "ACME TLS-ALPN identity: independent X.509 parse verifies self-signature, SAN, critical acmeIdentifier digest, and non-CA" {
    const lease = try testLease(testing.allocator, "a.example.test", valid_key_authorization, 1000);
    var identity = try build(testing.allocator, lease, 0);
    defer identity.deinit();

    var cert = try pki.x509.Certificate.parse(testing.allocator, identity.certificate_der, pki.x509.default_limits);
    defer cert.deinit(testing.allocator);

    try testing.expect(cert.isSelfIssued());
    try testing.expectEqual(pki.x509.SignatureAlgorithm.ecdsa_sha256, cert.signatureAlgorithm());

    var sec1_fixed: [65]u8 = undefined;
    try testing.expectEqual(@as(usize, 65), cert.subject_public_key_info.subject_public_key.data.len);
    @memcpy(&sec1_fixed, cert.subject_public_key_info.subject_public_key.data);
    const public_key = try Ecdsa.PublicKey.fromSec1(&sec1_fixed);
    const signature = try Ecdsa.Signature.fromDer(cert.signature_value.data);
    try signature.verify(cert.tbs_raw, public_key);

    const san = cert.subjectAltName().?;
    try testing.expectEqual(@as(usize, 1), san.len);
    try testing.expectEqualStrings("a.example.test", san[0].dns_name);

    try testing.expect(!cert.basicConstraints().?.is_ca);
    try testing.expect(cert.keyUsage().?.digital_signature);

    const ext = cert.findExtension(&pki.oid.well_known.acme_identifier).?;
    try testing.expect(ext.critical);
    var reader = pki.der.Reader.init(ext.value, pki.der.default_limits);
    const inner = try reader.readOctetString();
    try reader.expectEnd();
    var expected_digest: [32]u8 = undefined;
    Sha256.hash(valid_key_authorization, &expected_digest, .{});
    try testing.expectEqualSlices(u8, &expected_digest, inner);

    // Short, bounded validity: capped to `max_validity_s` from epoch here,
    // well inside the lease's own (much further out) expiry.
    try testing.expectEqual(@as(u16, 1970), cert.validity.not_before.year);
    try testing.expectEqual(@as(u8, 0), cert.validity.not_before.minute);
    try testing.expectEqual(@as(u16, 1970), cert.validity.not_after.year);
    try testing.expectEqual(@as(u8, 10), cert.validity.not_after.minute);
}

test "ACME TLS-ALPN identity: different host or key authorization yields a different certificate" {
    const lease_a = try testLease(testing.allocator, "a.example.test", valid_key_authorization, 1000);
    var id_a = try build(testing.allocator, lease_a, 0);
    defer id_a.deinit();

    const other_key_authorization = valid_token ++ "." ++ ("c" ** account_mod.thumbprint_len);
    const lease_b = try testLease(testing.allocator, "a.example.test", other_key_authorization, 1000);
    var id_b = try build(testing.allocator, lease_b, 0);
    defer id_b.deinit();
    try testing.expect(!std.mem.eql(u8, id_a.certificate_der, id_b.certificate_der));

    const lease_c = try testLease(testing.allocator, "b.example.test", valid_key_authorization, 1000);
    var id_c = try build(testing.allocator, lease_c, 0);
    defer id_c.deinit();
    try testing.expect(!std.mem.eql(u8, id_a.certificate_der, id_c.certificate_der));
}

test "ACME TLS-ALPN identity: rejects invalid host, expired lease, and malformed/oversized key authorization, wiping the lease either way" {
    var detector = crypto.secrets.CredentialWipeDetector.init(testing.allocator);
    const allocator = detector.allocator();

    {
        // Non-canonical host: rejected before any cert work.
        const lease = try testLease(allocator, "A.example.test", valid_key_authorization, 1000);
        detector.watch(lease.material);
        try testing.expectError(error.InvalidHost, build(testing.allocator, lease, 0));
    }
    {
        // Already past its own expiry by `not_before`.
        const lease = try testLease(allocator, "a.example.test", valid_key_authorization, 0);
        detector.watch(lease.material);
        try testing.expectError(error.InvalidValidity, build(testing.allocator, lease, 0));
    }
    const bad_key_authorizations = [_][]const u8{
        "",
        "a" ** (max_key_authorization_len + 1),
        "no-dot-separator",
        valid_token ++ "." ++ "short",
    };
    for (bad_key_authorizations) |bad| {
        const lease = try testLease(allocator, "a.example.test", bad, 1000);
        detector.watch(lease.material);
        try testing.expectError(error.InvalidKeyAuthorization, build(testing.allocator, lease, 0));
    }

    try testing.expect(detector.allWatchedWiped());
}

test "ACME TLS-ALPN identity: deinit wipes the ephemeral key and releases the lease material" {
    var detector = crypto.secrets.CredentialWipeDetector.init(testing.allocator);
    const allocator = detector.allocator();
    const lease = try testLease(allocator, "a.example.test", valid_key_authorization, 1000);
    detector.watch(lease.material);

    var identity = try build(allocator, lease, 0);
    identity.deinit();
    for (identity.key.key.key_pair.secret_key.bytes) |b| try testing.expectEqual(@as(u8, 0), b);
    try testing.expect(detector.allWatchedWiped());
}

test "ACME TLS-ALPN identity: no leaks on allocation failure during construction" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const lease = try testLease(allocator, "a.example.test", valid_key_authorization, 1000);
            var identity = try build(allocator, lease, 0);
            identity.deinit();
        }
    }.run, .{});
}

fn fuzzIdentity(_: void, smith: *testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    const lease = testLease(testing.allocator, "a.example.test", buf[0..len], 1000) catch return;
    var identity = build(testing.allocator, lease, 0) catch return;
    identity.deinit();
}

test "fuzz: ACME TLS-ALPN identity construction is bounded for arbitrary key-authorization bytes" {
    try testing.fuzz({}, fuzzIdentity, .{ .corpus = &.{
        "",
        valid_key_authorization,
        "a" ** 300,
        ".",
    } });
}

test {
    std.testing.refAllDecls(@This());
}
