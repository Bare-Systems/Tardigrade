//! Native RFC 8737 TLS-ALPN-01 challenge certificate construction (#938,
//! A6-2 of #759). Builds on the #932 registry (`tls_alpn_challenges.zig`).
//!
//! ## What this produces
//!
//! `build` returns a `ChallengeIdentity`: a fresh ephemeral P-256 key (never
//! the ACME account key, never a serving-site key) and a self-signed X.509
//! leaf whose SAN is exactly one dNSName -- the authorized host -- plus a
//! critical `id-pe-acmeIdentifier` extension (RFC 8737 S3) whose extnValue is
//! a DER OCTET STRING of SHA-256(keyAuthorization). Subject and issuer are the
//! same fixed non-empty CN (RFC 5280 S4.1.2.4 forbids an empty issuer), the
//! leaf is `CA:FALSE` with `digitalSignature` only, the serial is 16 random
//! bytes forced positive and nonzero, and validity is UTCTime/GeneralizedTime
//! per RFC 5280 S4.1.2.5 (UTCTime through 2049). Pure native Zig: DER via
//! `pki.der`/`pki.oid`, signing via `crypto.pure_zig`, no OpenSSL.
//!
//! ## Authorization contract (for #939)
//!
//! A `Registry.Lease` is a plain value and proves nothing by itself: it can
//! be forged, and by design it outlives `remove`/expiry. `build` therefore
//! requires the owning `*Registry` and calls `Registry.confirmAndAcquire`,
//! which succeeds only if a live (unexpired, uncancelled) slot exists for the
//! same host with the lease's exact activation id (process-wide unique, so
//! neither re-publication nor registry reload can revive it) and identical
//! order/account `binding`, material and expiry. The
//! caller additionally passes the `expected_host` (the SNI it looked the
//! lease up with) and `expected_binding` (the order it is serving); both must
//! match the lease byte-for-byte. No separate registry exists.
//!
//! ## Ownership and lifecycle
//!
//! * `build` CONSUMES `lease` on every path: the lease (key authorization
//!   included) is wiped and freed before `build` returns, success or error.
//!   The caller must not use or deinit it afterwards.
//! * On success the caller owns the `ChallengeIdentity` and must call
//!   `deinit` exactly once: it wipes the private key, frees
//!   `certificate_der` with the allocator passed to `build`, and releases one
//!   of `tls_alpn_challenges.max_live_identities` slots. The identity holds a
//!   refcounted `IdentityGate`, not the registry, so `deinit` is safe even
//!   after `Registry.deinit` (which closes the gate to new identities). The
//!   gate is allocated from the registry's allocator, which must therefore
//!   outlive the LAST identity, not merely the registry.
//! * Authorization is linearized with cancellation: `confirmAndAcquire` runs
//!   under the registry lock and checks the lease's activation generation, so
//!   a lease whose activation was cancelled is refused even if an identical
//!   activation was re-published; a build already admitted drains (#932).
//! * `key.key.signingKey()` yields the `crypto.provider.SigningKey` handle the
//!   native TLS 1.3 signer consumes (ecdsa_secp256r1_sha256); it borrows the
//!   identity.
//! * Entropy: the caller injects a fallible `crypto.provider.Entropy` (the
//!   composition root passes the same OS source the native TLS provider
//!   uses). Every draw -- key scalar, serial, signature noise -- propagates
//!   `EntropyFailure`; invalid scalars are redrawn a bounded number of times
//!   (`KeyGenFailed`). Partially filled buffers are wiped on failure.
//! * Lifetime: validity is `[now, min(lease.expires_at, now + max_validity_s)]`
//!   and can never exceed the authorized lifetime. The certificate is only
//!   reachable through the returned value, never ordinary HTTPS lookup.
//!
//! Errors never contain or log the key authorization or key material.

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
    /// Lease host is not a canonical ACME DNS name, or differs from `expected_host`.
    InvalidHost,
    /// Lease material is not `token "." thumbprint` within bounds.
    InvalidKeyAuthorization,
    /// `now` is unrepresentable/negative, or the lease leaves no validity window.
    InvalidValidity,
    /// Lease binding differs from `expected_binding`, or the registry does not
    /// vouch for the lease (forged, cancelled, replaced).
    NotAuthorized,
    /// The injected entropy source failed (key scalar, serial or noise draw).
    EntropyFailure,
    /// The registry's authorization has expired at `now`.
    Expired,
    /// `max_live_identities` identities are already live.
    TooManyIdentities,
    KeyGenFailed,
    SignFailed,
};

/// Structurally `account.AccountKey` (scalar validation, wipe-on-`deinit`);
/// generated here from the injected entropy, never via `AccountKey.generate`.
pub const ChallengeKey = account_mod.AccountKey;
const SigningKey = crypto.pure_zig.SoftwareEcdsaP256SigningKey;
const max_keygen_attempts = 16;

/// Same bound `acme_challenge_store` enforces for the HTTP-01 value.
pub const max_key_authorization_len: usize = challenge_store_mod.max_key_authorization_len;

/// Validity never extends more than this past `not_before`.
pub const max_validity_s: i64 = challenges_mod.default_ttl_s;

/// 9999-12-31T23:59:59Z: last instant a 4-digit-year GeneralizedTime can name.
const max_unix_time: i64 = 253402300799;
/// First instant (2050-01-01T00:00:00Z) that must use GeneralizedTime.
const generalized_time_from: i64 = 2524608000;

const issuer_common_name = "Tardigrade TLS-ALPN-01 validation";

const SEQUENCE = Tag.universal(16, true);
const SET = Tag.universal(17, true);
const INTEGER = Tag.universal(2, false);
const BIT_STRING = Tag.universal(3, false);
const OCTET_STRING = Tag.universal(4, false);
const OBJECT_IDENTIFIER = Tag.universal(6, false);
const UTF8_STRING = Tag.universal(12, false);
const BOOLEAN = Tag.universal(1, false);
const UTC_TIME = Tag.universal(23, false);
const GENERALIZED_TIME = Tag.universal(24, false);

pub const ChallengeIdentity = struct {
    allocator: std.mem.Allocator,
    gate: *challenges_mod.IdentityGate,
    /// DER X.509 leaf. Not secret -- it is what a validating client receives.
    certificate_der: []u8,
    /// Ephemeral signing key matching `certificate_der`'s public key.
    key: ChallengeKey,

    /// Wipes the private key, frees the certificate, releases the identity slot.
    pub fn deinit(self: *ChallengeIdentity) void {
        self.key.deinit();
        self.allocator.free(self.certificate_der);
        self.gate.release();
    }
};

/// Test-only fault injection; production `build` always passes `.{}`.
const Faults = struct {
    fail_sign: bool = false,
};

/// See the module doc for the full contract. `now` is the caller's clock
/// (unix seconds); it is both the confirmation time and `notBefore`.
pub fn build(
    registry: *challenges_mod.Registry,
    allocator: std.mem.Allocator,
    entropy: crypto.provider.Entropy,
    lease: challenges_mod.Lease,
    expected_host: []const u8,
    expected_binding: challenges_mod.Binding,
    now: i64,
) Error!ChallengeIdentity {
    return buildWithFaults(registry, allocator, entropy, lease, expected_host, expected_binding, now, .{});
}

fn buildWithFaults(
    registry: *challenges_mod.Registry,
    allocator: std.mem.Allocator,
    entropy: crypto.provider.Entropy,
    lease: challenges_mod.Lease,
    expected_host: []const u8,
    expected_binding: challenges_mod.Binding,
    now: i64,
    faults: Faults,
) Error!ChallengeIdentity {
    var owned_lease = lease;
    defer owned_lease.deinit();

    names_mod.validateName(owned_lease.host, true) catch return error.InvalidHost;
    if (!std.mem.eql(u8, owned_lease.host, expected_host)) return error.InvalidHost;
    if (!isValidKeyAuthorization(owned_lease.material)) return error.InvalidKeyAuthorization;
    if (now < 0 or now >= max_unix_time - max_validity_s) return error.InvalidValidity;
    if (!std.mem.eql(u8, &owned_lease.binding, &expected_binding)) return error.NotAuthorized;
    const gate = registry.confirmAndAcquire(&owned_lease, now) catch |err| return switch (err) {
        error.NotAuthorized => error.NotAuthorized,
        error.Expired => error.Expired,
        error.TooManyIdentities => error.TooManyIdentities,
        error.OutOfMemory => error.OutOfMemory,
    };
    errdefer gate.release();

    const not_after = @min(owned_lease.expires_at, now + max_validity_s);
    if (not_after <= now) return error.InvalidValidity;

    var digest: [32]u8 = undefined;
    Sha256.hash(owned_lease.material, &digest, .{});

    var key = try generateKey(entropy);
    errdefer key.deinit();

    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    defer arena_inst.deinit();
    const der = try buildCertificate(arena_inst.allocator(), entropy, &key, owned_lease.host, &digest, now, not_after, faults);
    const owned_der = allocator.dupe(u8, der) catch return error.OutOfMemory;

    const result: ChallengeIdentity = .{ .allocator = allocator, .gate = gate, .certificate_der = owned_der, .key = key };
    secrets.secureZero(&key.key.key_pair.secret_key.bytes); // wipe the frame-local copy
    return result;
}

/// Fresh P-256 key from the injected entropy; rejects out-of-range scalars
/// by redrawing a bounded number of times.
fn generateKey(entropy: crypto.provider.Entropy) Error!ChallengeKey {
    var attempts: u8 = 0;
    while (attempts < max_keygen_attempts) : (attempts += 1) {
        var scalar: [32]u8 = undefined;
        defer secrets.secureZero(&scalar);
        entropy.fill(&scalar) catch return error.EntropyFailure;
        if (SigningKey.fromScalarBytes(&scalar)) |key| return .{ .key = key } else |_| {}
    }
    return error.KeyGenFailed;
}

/// RFC 8555 S8.1 shape: `token "." thumbprint`, both base64url, thumbprint
/// exactly `account.thumbprint_len`, token within HTTP-01 token bounds.
fn isValidKeyAuthorization(value: []const u8) bool {
    if (value.len == 0 or value.len > max_key_authorization_len) return false;
    const dot = std.mem.indexOfScalar(u8, value, '.') orelse return false;
    const token = value[0..dot];
    const thumbprint = value[dot + 1 ..];
    if (token.len < challenge_store_mod.min_token_len or token.len > challenge_store_mod.max_token_len) return false;
    if (thumbprint.len != account_mod.thumbprint_len) return false;
    for (value, 0..) |c, idx| {
        if (idx == dot) continue;
        if (!isBase64UrlChar(c)) return false;
    }
    // The thumbprint must be the canonical unpadded base64url of a 32-byte
    // SHA-256 digest: 43 alphabet characters alone allow nonzero pad bits.
    const codec = std.base64.url_safe_no_pad;
    var raw: [32]u8 = undefined;
    codec.Decoder.decode(&raw, thumbprint) catch return false;
    var again: [account_mod.thumbprint_len]u8 = undefined;
    _ = codec.Encoder.encode(&again, &raw);
    return std.mem.eql(u8, &again, thumbprint);
}

fn isBase64UrlChar(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-' or c == '_';
}

// ---------------------------------------------------------------------------
// DER assembly
// ---------------------------------------------------------------------------

/// One TLV over the concatenation of `parts`. Lengths here are bounded by the
/// 253-byte host + fixed fields (< 1 KiB), so the 4-byte length buffer never
/// overflows; `encodeLength` is still exercised at its boundaries in tests.
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

/// `Name` with one RDN: CN = `issuer_common_name`. Used for subject AND issuer
/// (self-issued); non-empty as RFC 5280 S4.1.2.4 requires of the issuer.
fn challengeName(allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    const atv = try tlv(allocator, SEQUENCE, &.{
        try oidTlv(allocator, &pki.oid.well_known.common_name),
        try tlv(allocator, UTF8_STRING, &.{issuer_common_name}),
    });
    return tlv(allocator, SEQUENCE, &.{try tlv(allocator, SET, &.{atv})});
}

fn versionTlv(allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    return tlv(allocator, Tag.contextSpecific(0, true), &.{try tlv(allocator, INTEGER, &.{&[_]u8{2}})});
}

/// 16 random bytes with the top two bits forced to `01`: always positive
/// (RFC 5280 S4.1.2.2), never zero, and minimally encoded (first byte
/// 0x40..0x7f), at the cost of 2 of 128 bits of entropy.
fn randomSerial(entropy: crypto.provider.Entropy) Error![16]u8 {
    var raw: [16]u8 = undefined;
    entropy.fill(&raw) catch return error.EntropyFailure;
    raw[0] = (raw[0] & 0x3f) | 0x40;
    return raw;
}

const TimeText = struct {
    buf: [15]u8,
    len: usize,
    generalized: bool,

    fn slice(self: *const TimeText) []const u8 {
        return self.buf[0..self.len];
    }
};

/// RFC 5280 S4.1.2.5: UTCTime (YYMMDDHHMMSSZ) for years < 2050, otherwise
/// GeneralizedTime (YYYYMMDDHHMMSSZ). `unix` must be in `[0, max_unix_time]`.
fn encodeTime(unix: i64) error{InvalidValidity}!TimeText {
    if (unix < 0 or unix > max_unix_time) return error.InvalidValidity;
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(unix) };
    const day_seconds = es.getDaySeconds();
    const year_day = es.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    var out: TimeText = .{ .buf = undefined, .len = 0, .generalized = unix >= generalized_time_from };
    const printed = if (out.generalized)
        std.fmt.bufPrint(&out.buf, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
            year_day.year,
            month_day.month.numeric(),
            @as(u8, month_day.day_index) + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        })
    else
        std.fmt.bufPrint(&out.buf, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
            year_day.year % 100,
            month_day.month.numeric(),
            @as(u8, month_day.day_index) + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        });
    out.len = (printed catch unreachable).len;
    return out;
}

fn timeTlv(allocator: std.mem.Allocator, unix: i64) Error![]u8 {
    const text = try encodeTime(unix);
    return tlv(allocator, if (text.generalized) GENERALIZED_TIME else UTC_TIME, &.{text.slice()});
}

fn validityTlv(allocator: std.mem.Allocator, not_before: i64, not_after: i64) Error![]u8 {
    return tlv(allocator, SEQUENCE, &.{
        try timeTlv(allocator, not_before),
        try timeTlv(allocator, not_after),
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

fn buildTbs(allocator: std.mem.Allocator, entropy: crypto.provider.Entropy, key: *const ChallengeKey, host: []const u8, digest: *const [32]u8, not_before: i64, not_after: i64) Error![]u8 {
    const serial = try randomSerial(entropy);
    const name = try challengeName(allocator);
    return tlv(allocator, SEQUENCE, &.{
        try versionTlv(allocator),
        try tlv(allocator, INTEGER, &.{&serial}),
        try algorithmEcdsaSha256(allocator),
        name,
        try validityTlv(allocator, not_before, not_after),
        name,
        try spkiEcdsaP256(allocator, key),
        try extensionsTlv(allocator, host, digest),
    });
}

fn buildCertificate(allocator: std.mem.Allocator, entropy: crypto.provider.Entropy, key: *const ChallengeKey, host: []const u8, digest: *const [32]u8, not_before: i64, not_after: i64, faults: Faults) Error![]u8 {
    const tbs = try buildTbs(allocator, entropy, key, host, digest, not_before, not_after);

    var noise: [Ecdsa.noise_length]u8 = undefined;
    defer secrets.secureZero(&noise);
    entropy.fill(&noise) catch return error.EntropyFailure;
    if (faults.fail_sign) return error.SignFailed;
    const signature = key.key.key_pair.sign(tbs, noise) catch return error.SignFailed;
    // Defense in depth: never ship a certificate whose signature does not
    // verify under its own embedded key.
    signature.verify(tbs, key.key.key_pair.public_key) catch return error.SignFailed;
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
const StdCertificate = std.crypto.Certificate;

const binding_a: challenges_mod.Binding = [_]u8{0xAB} ** 32;
const binding_b: challenges_mod.Binding = [_]u8{0xCD} ** 32;
const valid_token = "a" ** 32;
fn canonicalThumbprint(comptime fill: u8) [account_mod.thumbprint_len]u8 {
    var out: [account_mod.thumbprint_len]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&out, &([_]u8{fill} ** 32));
    return out;
}
const valid_thumbprint = canonicalThumbprint(0x42);
const other_thumbprint = canonicalThumbprint(0x43);
const valid_key_authorization = valid_token ++ "." ++ valid_thumbprint;
const test_entropy: crypto.provider.Entropy = .{ .context = @constCast(&test_entropy_ctx), .fillFn = testFill };
const test_entropy_ctx: u8 = 0;
fn testFill(_: *anyopaque, buffer: []u8) crypto.provider.EntropyError!void {
    zig_compat.randomBytes(buffer);
}

fn tbuild(registry: *challenges_mod.Registry, allocator: std.mem.Allocator, lease: challenges_mod.Lease, host: []const u8, binding: challenges_mod.Binding, now: i64) Error!ChallengeIdentity {
    return build(registry, allocator, test_entropy, lease, host, binding, now);
}
const challenge_alpn = [_][]const u8{challenges_mod.protocol};

/// A real lease: published into `registry` and fetched back via `lookup`.
fn realLease(registry: *challenges_mod.Registry, allocator: std.mem.Allocator, host: []const u8, binding: challenges_mod.Binding, key_authorization: []const u8, now: i64, expires_at: i64) !challenges_mod.Lease {
    try registry.put(now, host, binding, key_authorization, expires_at);
    return (try registry.lookup(allocator, now, host, &challenge_alpn)).?;
}

/// A hand-built lease the registry never issued (forgeable by design).
fn forgedLease(allocator: std.mem.Allocator, host: []const u8, binding: challenges_mod.Binding, material: []const u8, expires_at: i64) !challenges_mod.Lease {
    const owned_host = try allocator.dupe(u8, host);
    errdefer allocator.free(owned_host);
    const owned_material = try allocator.dupe(u8, material);
    return .{ .allocator = allocator, .host = owned_host, .binding = binding, .material = owned_material, .expires_at = expires_at, .generation = 0 };
}

fn expectDigestExtensionBytes(der: []const u8, key_authorization: []const u8) !void {
    // Byte-level (no parser): SEQUENCE{ OID 1.3.6.1.5.5.7.1.31, BOOLEAN TRUE,
    // OCTET STRING{ OCTET STRING(32) digest } } appears exactly once.
    var digest: [32]u8 = undefined;
    Sha256.hash(key_authorization, &digest, .{});
    var pattern: [2 + 10 + 3 + 2 + 2 + 32]u8 = undefined;
    const prefix = [_]u8{ 0x30, 0x2c + 0x00, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f, 0x01, 0x01, 0xff, 0x04, 0x22, 0x04, 0x20 };
    var full: [prefix.len + 32]u8 = undefined;
    @memcpy(full[0..prefix.len], &prefix);
    @memcpy(full[prefix.len..], &digest);
    full[1] = full.len - 2;
    _ = &pattern;
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, der, &full));
}

fn expectFullyValid(der: []const u8, host: []const u8, key_authorization: []const u8, now: i64, not_after: i64) !void {
    // 1. Zig std's independent X.509 parser: parse, self-verify signature,
    //    host-name match (exact SAN dNSName), validity window.
    const std_cert = StdCertificate{ .buffer = der, .index = 0 };
    const parsed = try std_cert.parse();
    try parsed.verify(parsed, now);
    try parsed.verifyHostName(host);
    try testing.expectEqual(@as(i64, now), @as(i64, @intCast(parsed.validity.not_before)));
    try testing.expectEqual(@as(i64, not_after), @as(i64, @intCast(parsed.validity.not_after)));
    try testing.expectError(error.CertificateExpired, parsed.verify(parsed, not_after + 1));

    // 2. Tardigrade's own PKI model for extension semantics.
    var cert = try pki.x509.Certificate.parse(testing.allocator, der, pki.x509.default_limits);
    defer cert.deinit(testing.allocator);
    try testing.expect(cert.isSelfIssued());
    try testing.expectEqual(pki.x509.SignatureAlgorithm.ecdsa_sha256, cert.signatureAlgorithm());
    try testing.expectEqual(@as(usize, 65), cert.subject_public_key_info.subject_public_key.data.len);
    const san = cert.subjectAltName().?;
    try testing.expectEqual(@as(usize, 1), san.len);
    try testing.expectEqualStrings(host, san[0].dns_name);
    try testing.expect(!cert.basicConstraints().?.is_ca);
    const usage = cert.keyUsage().?;
    try testing.expect(usage.digital_signature);
    try testing.expect(!usage.key_cert_sign);
    const ext = cert.findExtension(&pki.oid.well_known.acme_identifier).?;
    try testing.expect(ext.critical);
    var reader = pki.der.Reader.init(ext.value, pki.der.default_limits);
    const inner = try reader.readOctetString();
    try reader.expectEnd();
    var expected_digest: [32]u8 = undefined;
    Sha256.hash(key_authorization, &expected_digest, .{});
    try testing.expectEqualSlices(u8, &expected_digest, inner);
    try expectDigestExtensionBytes(der, key_authorization);

    // The embedded public key + signature check by hand (not via either parser's verify).
    var sec1: [65]u8 = undefined;
    @memcpy(&sec1, cert.subject_public_key_info.subject_public_key.data);
    const public_key = try Ecdsa.PublicKey.fromSec1(&sec1);
    try (try Ecdsa.Signature.fromDer(cert.signature_value.data)).verify(cert.tbs_raw, public_key);
}

test "ACME TLS-ALPN identity: independent decode of every acceptance property" {
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    const now: i64 = 1_800_000_000;
    const lease = try realLease(&registry, testing.allocator, "a.example.test", binding_a, valid_key_authorization, now, now + 100);
    var identity = try tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, now);
    defer identity.deinit();

    try expectFullyValid(identity.certificate_der, "a.example.test", valid_key_authorization, now, now + 100);
    try testing.expect(identity.certificate_der.len < 1024);

    // Certificate/key correspondence: the key's public point is the SPKI.
    var cert = try pki.x509.Certificate.parse(testing.allocator, identity.certificate_der, pki.x509.default_limits);
    defer cert.deinit(testing.allocator);
    const sec1 = identity.key.key.key_pair.public_key.toUncompressedSec1();
    try testing.expectEqualSlices(u8, &sec1, cert.subject_public_key_info.subject_public_key.data);
    // Serial: positive, nonzero, minimal.
    const serial = cert.serial_number.content;
    try testing.expect(serial.len == 16 and serial[0] >= 0x40 and serial[0] < 0x80);
}

test "ACME TLS-ALPN identity: native TLS signer handle signs under the certificate's key" {
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    const lease = try realLease(&registry, testing.allocator, "a.example.test", binding_a, valid_key_authorization, 1000, 1100);
    var identity = try tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, 1000);
    defer identity.deinit();

    const handle = identity.key.key.signingKey();
    try testing.expectEqual(crypto.provider.SignatureScheme.ecdsa_secp256r1_sha256, handle.scheme());
    var out: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const n = try handle.sign("CertificateVerify transcript", test_entropy, &out);
    var cert = try pki.x509.Certificate.parse(testing.allocator, identity.certificate_der, pki.x509.default_limits);
    defer cert.deinit(testing.allocator);
    var sec1: [65]u8 = undefined;
    @memcpy(&sec1, cert.subject_public_key_info.subject_public_key.data);
    try (try Ecdsa.Signature.fromDer(out[0..n])).verify("CertificateVerify transcript", try Ecdsa.PublicKey.fromSec1(&sec1));
}

test "ACME TLS-ALPN identity: hostname, order and key authorization each bind independently" {
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    const other_ka = valid_token ++ "." ++ other_thumbprint;
    const cases = [_]struct { host: []const u8, ka: []const u8, binding: challenges_mod.Binding }{
        .{ .host = "a.example.test", .ka = valid_key_authorization, .binding = binding_a },
        .{ .host = "b.example.test", .ka = valid_key_authorization, .binding = binding_a },
        .{ .host = "c.example.test", .ka = other_ka, .binding = binding_b },
    };
    var keys: [cases.len][65]u8 = undefined;
    for (cases, 0..) |c, idx| {
        const lease = try realLease(&registry, testing.allocator, c.host, c.binding, c.ka, 1_800_000_000, 1_800_000_500);
        var identity = try tbuild(&registry, testing.allocator, lease, c.host, c.binding, 1_800_000_000);
        defer identity.deinit();
        try expectFullyValid(identity.certificate_der, c.host, c.ka, 1_800_000_000, 1_800_000_500);
        keys[idx] = identity.key.key.key_pair.public_key.toUncompressedSec1();
    }
    // Ephemeral keys are unique per identity.
    try testing.expect(!std.mem.eql(u8, &keys[0], &keys[1]));
    try testing.expect(!std.mem.eql(u8, &keys[1], &keys[2]));
    try testing.expect(!std.mem.eql(u8, &keys[0], &keys[2]));
}

test "ACME TLS-ALPN identity: unauthorized leases are rejected, wiped, and leave no identity slot held" {
    var detector = crypto.secrets.CredentialWipeDetector.init(testing.allocator);
    const allocator = detector.allocator();
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    const now: i64 = 1000;
    try registry.put(now, "a.example.test", binding_a, valid_key_authorization, now + 100);

    // forged: valid-looking lease for a host/binding/material the registry never issued
    {
        const lease = try forgedLease(allocator, "b.example.test", binding_a, valid_key_authorization, now + 100);
        detector.watch(lease.material);
        try testing.expectError(error.NotAuthorized, tbuild(&registry, testing.allocator, lease, "b.example.test", binding_a, now));
    }
    // forged: right host, wrong binding / wrong material / wrong expiry
    {
        const lease = try forgedLease(allocator, "a.example.test", binding_b, valid_key_authorization, now + 100);
        detector.watch(lease.material);
        try testing.expectError(error.NotAuthorized, tbuild(&registry, testing.allocator, lease, "a.example.test", binding_b, now));
    }
    {
        const lease = try forgedLease(allocator, "a.example.test", binding_a, valid_token ++ "." ++ other_thumbprint, now + 100);
        detector.watch(lease.material);
        try testing.expectError(error.NotAuthorized, tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, now));
    }
    {
        const lease = try forgedLease(allocator, "a.example.test", binding_a, valid_key_authorization, now + 101);
        detector.watch(lease.material);
        try testing.expectError(error.NotAuthorized, tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, now));
    }
    // caller's expected host / binding must match the (genuine) lease
    {
        const lease = (try registry.lookup(allocator, now, "a.example.test", &challenge_alpn)).?;
        detector.watch(lease.material);
        try testing.expectError(error.InvalidHost, tbuild(&registry, testing.allocator, lease, "b.example.test", binding_a, now));
    }
    {
        const lease = (try registry.lookup(allocator, now, "a.example.test", &challenge_alpn)).?;
        detector.watch(lease.material);
        try testing.expectError(error.NotAuthorized, tbuild(&registry, testing.allocator, lease, "a.example.test", binding_b, now));
    }
    // cancelled after lookup: the lease survives but is no longer authorization
    {
        const lease = (try registry.lookup(allocator, now, "a.example.test", &challenge_alpn)).?;
        detector.watch(lease.material);
        try testing.expectEqual(.closed, registry.remove("a.example.test", binding_a));
        try testing.expectError(error.NotAuthorized, tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, now));
    }
    // expired after lookup
    {
        const lease = try realLease(&registry, allocator, "a.example.test", binding_a, valid_key_authorization, now, now + 50);
        detector.watch(lease.material);
        try testing.expectError(error.Expired, tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, now + 50));
    }
    try testing.expect(detector.allWatchedWiped());
    try testing.expectEqual(@as(u32, 0), registry.liveIdentities());
}

test "ACME TLS-ALPN identity: invalid hosts and key authorizations are rejected and wiped" {
    var detector = crypto.secrets.CredentialWipeDetector.init(testing.allocator);
    const allocator = detector.allocator();
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();

    const bad_hosts = [_][]const u8{ "", "A.example.test", "*.example.test", "a.example.test.", "xn--.example.test", "a b.example.test", "-a.example.test", "a" ** 64 ++ ".example.test", "127.0.0.1", ("a." ** 130) ++ "test" };
    for (bad_hosts) |host| {
        const lease = try forgedLease(testing.allocator, host, binding_a, valid_key_authorization, 100);
        try testing.expectError(error.InvalidHost, tbuild(&registry, testing.allocator, lease, host, binding_a, 0));
    }
    // One watched lease: host rejection wipes the material too.
    const bad_lease = try forgedLease(allocator, "A.example.test", binding_a, valid_key_authorization, 100);
    detector.watch(bad_lease.material);
    try testing.expectError(error.InvalidHost, tbuild(&registry, testing.allocator, bad_lease, "A.example.test", binding_a, 0));
    try testing.expect(detector.allWatchedWiped());
    var detector2 = crypto.secrets.CredentialWipeDetector.init(testing.allocator);
    const allocator2 = detector2.allocator();
    const bad_key_authorizations = [_][]const u8{
        "",
        "a" ** (max_key_authorization_len + 1),
        "no-dot-separator",
        valid_token ++ "." ++ "short",
        "short." ++ valid_thumbprint,
        valid_token ++ "." ++ valid_thumbprint ++ "=",
        valid_token ++ "." ++ ("b" ** 42) ++ "+",
        valid_token ++ ".." ++ ("b" ** 42),
    };
    for (bad_key_authorizations) |bad| {
        const lease = try forgedLease(allocator2, "a.example.test", binding_a, bad, 100);
        if (bad.len != 0) detector2.watch(lease.material); // nothing to wipe in an empty buffer
        try testing.expectError(error.InvalidKeyAuthorization, tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, 0));
    }
    try testing.expect(detector2.allWatchedWiped());

    // Alphabet-valid, 43-char thumbprints whose final character carries nonzero
    // pad bits are REGISTERED (the registry accepts any material) and must be
    // refused by syntax alone.
    for ([_][]const u8{ "b", "B", "-", "_", "1" }) |last| {
        var bad: [valid_token.len + 1 + account_mod.thumbprint_len]u8 = undefined;
        @memcpy(bad[0..valid_key_authorization.len], valid_key_authorization);
        bad[bad.len - 1] = last[0];
        try testing.expect(!isValidKeyAuthorization(&bad));
        const lease = try realLease(&registry, testing.allocator, "a.example.test", binding_a, &bad, 0, 100);
        try testing.expectError(error.InvalidKeyAuthorization, tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, 0));
        _ = registry.remove("a.example.test", binding_a);
    }
    try testing.expect(isValidKeyAuthorization(valid_key_authorization));
}

test "ACME TLS-ALPN identity: timestamp boundaries and ASN.1 time encoding" {
    // encodeTime: UTCTime through 2049-12-31T23:59:59Z, GeneralizedTime after.
    try testing.expectEqualStrings("700101000000Z", (try encodeTime(0)).slice());
    try testing.expectEqualStrings("491231235959Z", (try encodeTime(generalized_time_from - 1)).slice());
    try testing.expect(!(try encodeTime(generalized_time_from - 1)).generalized);
    try testing.expectEqualStrings("20500101000000Z", (try encodeTime(generalized_time_from)).slice());
    try testing.expect((try encodeTime(generalized_time_from)).generalized);
    try testing.expectEqualStrings("99991231235959Z", (try encodeTime(max_unix_time)).slice());
    try testing.expectError(error.InvalidValidity, encodeTime(-1));
    try testing.expectError(error.InvalidValidity, encodeTime(max_unix_time + 1));
    try testing.expectError(error.InvalidValidity, encodeTime(std.math.minInt(i64)));
    try testing.expectError(error.InvalidValidity, encodeTime(std.math.maxInt(i64)));

    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    // Unrepresentable `now` values are rejected before touching the registry.
    for ([_]i64{ -1, std.math.minInt(i64), std.math.maxInt(i64), max_unix_time, max_unix_time - max_validity_s }) |bad_now| {
        const lease = try forgedLease(testing.allocator, "a.example.test", binding_a, valid_key_authorization, std.math.maxInt(i64));
        try testing.expectError(error.InvalidValidity, tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, bad_now));
    }

    // Across the 2049/2050 boundary: notBefore is UTCTime, notAfter GeneralizedTime,
    // and an independent parser agrees on both instants.
    const now = generalized_time_from - 5;
    const lease = try realLease(&registry, testing.allocator, "a.example.test", binding_a, valid_key_authorization, now, now + 100);
    var identity = try tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, now);
    defer identity.deinit();
    try expectFullyValid(identity.certificate_der, "a.example.test", valid_key_authorization, now, now + 100);
    try testing.expect(std.mem.indexOf(u8, identity.certificate_der, "\x17\x0d491231235955Z\x18\x0f20500101000135Z") != null);

    // A far-future requested expiry is clamped to 600s by the registry, and an
    // identity built later in the window is capped by the remaining lease life.
    const far = try realLease(&registry, testing.allocator, "b.example.test", binding_a, valid_key_authorization, 1_800_000_000, std.math.maxInt(i64));
    var capped = try tbuild(&registry, testing.allocator, far, "b.example.test", binding_a, 1_800_000_100);
    defer capped.deinit();
    try expectFullyValid(capped.certificate_der, "b.example.test", valid_key_authorization, 1_800_000_100, 1_800_000_000 + max_validity_s);
}

test "ACME TLS-ALPN identity: live identities are bounded and slots are returned" {
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    var identities: [challenges_mod.max_live_identities]ChallengeIdentity = undefined;
    var host_buf: [challenges_mod.max_live_identities][24]u8 = undefined;
    for (&identities, 0..) |*slot, idx| {
        const host = try std.fmt.bufPrint(&host_buf[idx], "h{d}.example.test", .{idx});
        const lease = try realLease(&registry, testing.allocator, host, binding_a, valid_key_authorization, 0, 100);
        slot.* = try tbuild(&registry, testing.allocator, lease, host, binding_a, 0);
    }
    try testing.expectEqual(challenges_mod.max_live_identities, registry.liveIdentities());

    var detector = crypto.secrets.CredentialWipeDetector.init(testing.allocator);
    const allocator = detector.allocator();
    _ = registry.remove("h0.example.test", binding_a);
    const over = try realLease(&registry, allocator, "h0.example.test", binding_a, valid_key_authorization, 0, 100);
    detector.watch(over.material);
    try testing.expectError(error.TooManyIdentities, tbuild(&registry, testing.allocator, over, "h0.example.test", binding_a, 0));
    try testing.expect(detector.allWatchedWiped());

    identities[0].deinit();
    const again = (try registry.lookup(testing.allocator, 0, "h0.example.test", &challenge_alpn)).?;
    var replacement = try tbuild(&registry, testing.allocator, again, "h0.example.test", binding_a, 0);
    replacement.deinit();
    for (identities[1..]) |*identity| identity.deinit();
    try testing.expectEqual(@as(u32, 0), registry.liveIdentities());
}

/// Entropy that fails on the `fail_at`-th draw, optionally after writing part
/// of the buffer.
const FlakyEntropy = struct {
    calls: usize = 0,
    fail_at: usize,
    partial: bool,

    fn entropy(self: *FlakyEntropy) crypto.provider.Entropy {
        return .{ .context = self, .fillFn = fill };
    }

    fn fill(context: *anyopaque, buffer: []u8) crypto.provider.EntropyError!void {
        const self: *FlakyEntropy = @ptrCast(@alignCast(context));
        defer self.calls += 1;
        if (self.calls == self.fail_at) {
            if (self.partial) zig_compat.randomBytes(buffer[0 .. buffer.len / 2]);
            return error.EntropyFailure;
        }
        zig_compat.randomBytes(buffer);
    }
};

test "ACME TLS-ALPN identity: entropy failure on every draw yields no identity, wiped lease, released slot" {
    var detector = crypto.secrets.CredentialWipeDetector.init(testing.allocator);
    const allocator = detector.allocator();
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    // Draws: 0 = key scalar, 1 = serial, 2 = signature noise.
    var failures: usize = 0;
    for ([_]bool{ false, true }) |partial| {
        for (0..3) |fail_at| {
            var flaky: FlakyEntropy = .{ .fail_at = fail_at, .partial = partial };
            const lease = try realLease(&registry, allocator, "a.example.test", binding_a, valid_key_authorization, 0, 100);
            detector.watch(lease.material);
            try testing.expectError(error.EntropyFailure, build(&registry, testing.allocator, flaky.entropy(), lease, "a.example.test", binding_a, 0));
            try testing.expectEqual(fail_at + 1, flaky.calls);
            try testing.expectEqual(@as(u32, 0), registry.liveIdentities());
            _ = registry.remove("a.example.test", binding_a);
            failures += 1;
            if (failures % 6 == 0) {
                try testing.expect(detector.allWatchedWiped());
                detector = crypto.secrets.CredentialWipeDetector.init(testing.allocator);
            }
        }
    }
    // No draw fails: three draws are all a successful build needs.
    var ok: FlakyEntropy = .{ .fail_at = 99, .partial = false };
    const lease = try realLease(&registry, testing.allocator, "a.example.test", binding_a, valid_key_authorization, 0, 100);
    var identity = try build(&registry, testing.allocator, ok.entropy(), lease, "a.example.test", binding_a, 0);
    identity.deinit();
    try testing.expectEqual(@as(usize, 3), ok.calls);
}

test "ACME TLS-ALPN identity: signing failure wipes the lease, key slot and releases capacity" {
    var detector = crypto.secrets.CredentialWipeDetector.init(testing.allocator);
    const allocator = detector.allocator();
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    const lease = try realLease(&registry, allocator, "a.example.test", binding_a, valid_key_authorization, 0, 100);
    detector.watch(lease.material);
    try testing.expectError(error.SignFailed, buildWithFaults(&registry, testing.allocator, test_entropy, lease, "a.example.test", binding_a, 0, .{ .fail_sign = true }));
    try testing.expectEqual(@as(u32, 0), registry.liveIdentities());
    try testing.expect(detector.allWatchedWiped());
}

test "ACME TLS-ALPN identity: a cancelled activation cannot be resurrected by an identical re-publish (ABA)" {
    const t0: i64 = 1_800_000_000;
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    const lease = try realLease(&registry, testing.allocator, "a.example.test", binding_a, valid_key_authorization, t0, t0 + 100);
    try testing.expectEqual(.closed, registry.remove("a.example.test", binding_a));
    try registry.put(t0 + 1, "a.example.test", binding_a, valid_key_authorization, t0 + 100);
    try testing.expectError(error.NotAuthorized, tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, t0 + 1));

    // The fresh activation's own lease is accepted; a build admitted BEFORE a
    // later cancellation drains and stays usable.
    const fresh = (try registry.lookup(testing.allocator, t0 + 1, "a.example.test", &challenge_alpn)).?;
    var identity = try tbuild(&registry, testing.allocator, fresh, "a.example.test", binding_a, t0 + 1);
    try testing.expectEqual(.closed, registry.remove("a.example.test", binding_a));
    try expectFullyValid(identity.certificate_der, "a.example.test", valid_key_authorization, t0 + 1, t0 + 100);
    identity.deinit();
    try testing.expectEqual(@as(u32, 0), registry.liveIdentities());
}

test "ACME TLS-ALPN identity: an identity outlives registry shutdown and still releases safely" {
    const t0: i64 = 1_800_000_000;
    var registry = challenges_mod.Registry.init(testing.allocator);
    const lease = try realLease(&registry, testing.allocator, "a.example.test", binding_a, valid_key_authorization, t0, t0 + 100);
    var identity = try tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, t0);
    const key_bytes = &identity.key.key.key_pair.secret_key.bytes;
    registry.deinit(); // teardown with a live identity: closes the gate, no dangling pointer
    try expectFullyValid(identity.certificate_der, "a.example.test", valid_key_authorization, t0, t0 + 100);
    identity.deinit(); // frees the gate (testing.allocator verifies no leak)
    for (key_bytes) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "ACME TLS-ALPN identity: deinit wipes the key; the consumed lease is wiped on success" {
    var detector = crypto.secrets.CredentialWipeDetector.init(testing.allocator);
    const allocator = detector.allocator();
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    const lease = try realLease(&registry, allocator, "a.example.test", binding_a, valid_key_authorization, 0, 100);
    detector.watch(lease.material);

    var identity = try tbuild(&registry, allocator, lease, "a.example.test", binding_a, 0);
    // Lease material is already wiped while the identity is still live.
    try testing.expect(detector.allWatchedWiped());
    var nonzero: u8 = 0;
    for (identity.key.key.key_pair.secret_key.bytes) |b| nonzero |= b;
    try testing.expect(nonzero != 0);
    const key_bytes = &identity.key.key.key_pair.secret_key.bytes;
    identity.deinit();
    for (key_bytes) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "ACME TLS-ALPN identity: no leaks or double frees under allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var registry = challenges_mod.Registry.init(allocator);
            defer registry.deinit();
            const lease = try realLease(&registry, allocator, "a.example.test", binding_a, valid_key_authorization, 0, 100);
            var identity = try tbuild(&registry, allocator, lease, "a.example.test", binding_a, 0);
            identity.deinit();
        }
    }.run, .{});
}

test "ACME TLS-ALPN identity: DER length encoding boundaries round-trip and malformed lengths are rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    for ([_]usize{ 0, 1, 127, 128, 255, 256, 65535, 65536 }) |len| {
        const content = try arena.allocator().alloc(u8, len);
        @memset(content, 0x5a);
        const encoded = try tlv(arena.allocator(), OCTET_STRING, &.{content});
        var reader = pki.der.Reader.init(encoded, .{ .max_element_len = 1 << 20 });
        try testing.expectEqualSlices(u8, content, try reader.readOctetString());
        try reader.expectEnd();
        if (len > 0) { // truncated body
            var short = pki.der.Reader.init(encoded[0 .. encoded.len - 1], .{ .max_element_len = 1 << 20 });
            try testing.expectError(error.LengthBeyondInput, short.readOctetString());
        }
    }
    // Overlong (length claims more than present) and non-minimal length forms.
    var overlong = pki.der.Reader.init(&[_]u8{ 0x04, 0x82, 0x01, 0x00, 0x00 }, .{});
    try testing.expectError(error.LengthBeyondInput, overlong.readOctetString());
    var non_minimal = pki.der.Reader.init(&[_]u8{ 0x04, 0x81, 0x01, 0x00 }, .{});
    try testing.expect(std.meta.isError(non_minimal.readOctetString()));
    // encodeLength itself refuses a too-small output buffer rather than overflow.
    var tiny: [1]u8 = undefined;
    try testing.expect(std.meta.isError(pki.der.encodeLength(300, &tiny)));
}

test "ACME TLS-ALPN identity: maximum-length hostname crosses DER length transitions" {
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    const l63 = "a" ** 63;
    const host = l63 ++ "." ++ l63 ++ "." ++ l63 ++ "." ++ ("a" ** 61);
    try testing.expectEqual(@as(usize, 253), host.len);
    const lease = try realLease(&registry, testing.allocator, host, binding_a, valid_key_authorization, 1_800_000_000, 1_800_000_100);
    var identity = try tbuild(&registry, testing.allocator, lease, host, binding_a, 1_800_000_000);
    defer identity.deinit();
    try expectFullyValid(identity.certificate_der, host, valid_key_authorization, 1_800_000_000, 1_800_000_100);
    try testing.expect(identity.certificate_der.len < 1024);
}

fn fuzzIdentity(_: void, smith: *testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    const material = buf[0..len];
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    registry.put(1_800_000_000, "a.example.test", binding_a, material, 1_800_000_100) catch return;
    const lease = (try registry.lookup(testing.allocator, 1_800_000_000, "a.example.test", &challenge_alpn)).?;
    if (tbuild(&registry, testing.allocator, lease, "a.example.test", binding_a, 1_800_000_000)) |built| {
        var identity = built;
        defer identity.deinit();
        try testing.expect(isValidKeyAuthorization(material));
        try expectFullyValid(identity.certificate_der, "a.example.test", material, 1_800_000_000, 1_800_000_100);
    } else |err| {
        try testing.expectEqual(error.InvalidKeyAuthorization, err);
        try testing.expect(!isValidKeyAuthorization(material));
    }
    try testing.expectEqual(@as(u32, 0), registry.liveIdentities());
}

test "fuzz: ACME TLS-ALPN identity construction constructs-and-verifies valid input and rejects the rest" {
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

test "ACME TLS-ALPN identity: activation ids are unique across registries, reload and reused storage" {
    const t0: i64 = 1_800_000_000;
    var registry_a = challenges_mod.Registry.init(testing.allocator);
    const stale = try realLease(&registry_a, testing.allocator, "a.example.test", binding_a, valid_key_authorization, t0, t0 + 100);
    registry_a.deinit();

    // Reload into the same stack storage and publish the identical tuple first.
    registry_a = challenges_mod.Registry.init(testing.allocator);
    defer registry_a.deinit();
    const fresh = try realLease(&registry_a, testing.allocator, "a.example.test", binding_a, valid_key_authorization, t0, t0 + 100);
    try testing.expect(stale.generation != fresh.generation);
    try testing.expectError(error.NotAuthorized, tbuild(&registry_a, testing.allocator, stale, "a.example.test", binding_a, t0));

    // A concurrently live second registry with the identical tuple also rejects it.
    var registry_b = challenges_mod.Registry.init(testing.allocator);
    defer registry_b.deinit();
    const other = try realLease(&registry_b, testing.allocator, "a.example.test", binding_a, valid_key_authorization, t0, t0 + 100);
    try testing.expect(other.generation != fresh.generation);
    var cross = try forgedLease(testing.allocator, "a.example.test", binding_a, valid_key_authorization, t0 + 100);
    cross.generation = fresh.generation;
    try testing.expectError(error.NotAuthorized, tbuild(&registry_b, testing.allocator, cross, "a.example.test", binding_a, t0));

    var ok_a = try tbuild(&registry_a, testing.allocator, fresh, "a.example.test", binding_a, t0);
    ok_a.deinit();
    var ok_b = try tbuild(&registry_b, testing.allocator, other, "a.example.test", binding_a, t0);
    ok_b.deinit();
}

fn gateHammer(registry: *challenges_mod.Registry, lease: *const challenges_mod.Lease, t0: i64) void {
    for (0..5000) |_| {
        const gate = registry.confirmAndAcquire(lease, t0) catch continue;
        gate.release();
    }
}

test "ACME TLS-ALPN identity: concurrent acquire/release never loses capacity" {
    const t0: i64 = 1_800_000_000;
    var registry = challenges_mod.Registry.init(testing.allocator);
    defer registry.deinit();
    var lease = try realLease(&registry, testing.allocator, "a.example.test", binding_a, valid_key_authorization, t0, t0 + 100);
    defer lease.deinit();

    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, gateHammer, .{ &registry, &lease, t0 });
    for (threads) |thread| thread.join();
    try testing.expectEqual(@as(u32, 0), registry.liveIdentities());

    // Full capacity is still available afterwards (and exactly that much).
    var gates: [challenges_mod.max_live_identities]*challenges_mod.IdentityGate = undefined;
    for (&gates) |*gate| gate.* = try registry.confirmAndAcquire(&lease, t0);
    try testing.expectError(error.TooManyIdentities, registry.confirmAndAcquire(&lease, t0));
    for (gates) |gate| gate.release();
    try testing.expectEqual(@as(u32, 0), registry.liveIdentities());
}
