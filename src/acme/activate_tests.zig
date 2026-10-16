//! Tests for `activate.zig` (#879): real ECDSA P-256 certificate fixtures
//! (self-signed and two-entry chains, built and signed in-process — no
//! fixture files, no OpenSSL), verification edge cases, atomic persistence
//! with fault injection at every write step, and restart/crash recovery.

const std = @import("std");
const pki = @import("pki");
const zig_compat = @import("zig_compat");
const account_mod = @import("account.zig");
const state_mod = @import("state.zig");
const activate = @import("activate.zig");

const testing = std.testing;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

// ---------------------------------------------------------------------------
// Minimal real-crypto DER certificate builder (mirrors the structure of
// `pki/x509_tests.zig`'s synthetic-corpus builder, but signs with real P-256
// keys so chain-signature and key-binding checks have something genuine to
// verify against).
// ---------------------------------------------------------------------------

fn tlv(arena: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts) |part| total += part.len;
    var len_buf: [9]u8 = undefined;
    const len_len = try pki.der.encodeLength(total, &len_buf);
    const out = try arena.alloc(u8, 1 + len_len + total);
    out[0] = tag;
    @memcpy(out[1 .. 1 + len_len], len_buf[0..len_len]);
    var offset = 1 + len_len;
    for (parts) |part| {
        @memcpy(out[offset .. offset + part.len], part);
        offset += part.len;
    }
    return out;
}

fn oidTlv(arena: std.mem.Allocator, components: []const u32) ![]u8 {
    var buf: [64]u8 = undefined;
    const n = try pki.oid.encodeComponents(components, &buf);
    return tlv(arena, 0x06, &.{buf[0..n]});
}

fn bitStringNoUnused(arena: std.mem.Allocator, data: []const u8) ![]u8 {
    const content = try arena.alloc(u8, data.len + 1);
    content[0] = 0;
    @memcpy(content[1..], data);
    return tlv(arena, 0x03, &.{content});
}

fn nameWithCn(arena: std.mem.Allocator, cn: []const u8) ![]u8 {
    const atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &pki.oid.well_known.common_name),
        try tlv(arena, 0x0c, &.{cn}),
    });
    return tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{atv})});
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

fn validityTlv(arena: std.mem.Allocator, not_before: i64, not_after: i64) ![]u8 {
    var nb_buf: [13]u8 = undefined;
    var na_buf: [13]u8 = undefined;
    return tlv(arena, 0x30, &.{
        try tlv(arena, 0x17, &.{utcTimeContent(&nb_buf, not_before)}),
        try tlv(arena, 0x17, &.{utcTimeContent(&na_buf, not_after)}),
    });
}

fn algorithmEcdsaSha256(arena: std.mem.Allocator) ![]u8 {
    return tlv(arena, 0x30, &.{try oidTlv(arena, &pki.oid.well_known.ecdsa_with_sha256)});
}

fn spkiEcdsaP256(arena: std.mem.Allocator, pubkey_sec1: []const u8) ![]u8 {
    const algorithm = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &pki.oid.well_known.ec_public_key),
        try oidTlv(arena, &pki.oid.well_known.secp256r1),
    });
    return tlv(arena, 0x30, &.{ algorithm, try bitStringNoUnused(arena, pubkey_sec1) });
}

fn versionTlv(arena: std.mem.Allocator, value: u8) ![]u8 {
    return tlv(arena, 0xa0, &.{try tlv(arena, 0x02, &.{&[_]u8{value}})});
}

fn extensionTlv(arena: std.mem.Allocator, ext_oid: []const u32, critical: bool, value: []const u8) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    try parts.append(arena, try oidTlv(arena, ext_oid));
    if (critical) try parts.append(arena, try tlv(arena, 0x01, &.{&[_]u8{0xff}}));
    try parts.append(arena, try tlv(arena, 0x04, &.{value}));
    return tlv(arena, 0x30, parts.items);
}

fn extensionsWrapper(arena: std.mem.Allocator, extensions: []const []const u8) ![]u8 {
    return tlv(arena, 0xa3, &.{try tlv(arena, 0x30, extensions)});
}

fn buildTbs(
    arena: std.mem.Allocator,
    serial: u8,
    issuer_name: []const u8,
    subject_name: []const u8,
    validity: []const u8,
    spki: []const u8,
    extensions: ?[]const u8,
) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    try parts.append(arena, try versionTlv(arena, 2));
    try parts.append(arena, try tlv(arena, 0x02, &.{&[_]u8{serial}}));
    try parts.append(arena, try algorithmEcdsaSha256(arena));
    try parts.append(arena, issuer_name);
    try parts.append(arena, validity);
    try parts.append(arena, subject_name);
    try parts.append(arena, spki);
    if (extensions) |ext| try parts.append(arena, ext);
    return tlv(arena, 0x30, parts.items);
}

fn signAndBuildCertificate(arena: std.mem.Allocator, signer: EcdsaP256Sha256.KeyPair, tbs: []const u8) ![]u8 {
    var noise: [EcdsaP256Sha256.noise_length]u8 = undefined;
    zig_compat.randomBytes(&noise);
    const signature = try signer.sign(tbs, noise);
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = signature.toDer(&der_buf);
    return tlv(arena, 0x30, &.{ tbs, try algorithmEcdsaSha256(arena), try bitStringNoUnused(arena, sig_der) });
}

fn buildCertDer(
    arena: std.mem.Allocator,
    signer: EcdsaP256Sha256.KeyPair,
    serial: u8,
    issuer_cn: []const u8,
    subject_cn: []const u8,
    subject_pub_sec1: []const u8,
    not_before: i64,
    not_after: i64,
    extensions: ?[]const []const u8,
) ![]u8 {
    const issuer_name = try nameWithCn(arena, issuer_cn);
    const subject_name = try nameWithCn(arena, subject_cn);
    const validity = try validityTlv(arena, not_before, not_after);
    const spki = try spkiEcdsaP256(arena, subject_pub_sec1);
    const ext_wrapper = if (extensions) |ext| try extensionsWrapper(arena, ext) else null;
    const tbs = try buildTbs(arena, serial, issuer_name, subject_name, validity, spki, ext_wrapper);
    return signAndBuildCertificate(arena, signer, tbs);
}

fn sanExtension(arena: std.mem.Allocator, hostnames: []const []const u8) ![]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    for (hostnames) |h| try parts.append(arena, try tlv(arena, 0x82, &.{h}));
    const san_value = try tlv(arena, 0x30, parts.items);
    return try extensionTlv(arena, &pki.oid.well_known.subject_alt_name, false, san_value);
}

fn basicConstraintsCaExtension(arena: std.mem.Allocator) ![]const u8 {
    const value = try tlv(arena, 0x30, &.{try tlv(arena, 0x01, &.{&[_]u8{0xff}})});
    return try extensionTlv(arena, &pki.oid.well_known.basic_constraints, true, value);
}

fn pemEncodeCertificate(allocator: std.mem.Allocator, der: []const u8) ![]u8 {
    const b64 = std.base64.standard.Encoder;
    const encoded_len = b64.calcSize(der.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = b64.encode(encoded, der);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "-----BEGIN CERTIFICATE-----\n");
    var offset: usize = 0;
    while (offset < encoded.len) {
        const n = @min(64, encoded.len - offset);
        try out.appendSlice(allocator, encoded[offset .. offset + n]);
        try out.append(allocator, '\n');
        offset += n;
    }
    try out.appendSlice(allocator, "-----END CERTIFICATE-----\n");
    return out.toOwnedSlice(allocator);
}

fn pemEncodeChain(allocator: std.mem.Allocator, ders: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (ders) |der| {
        const block = try pemEncodeCertificate(allocator, der);
        defer allocator.free(block);
        try out.appendSlice(allocator, block);
    }
    return out.toOwnedSlice(allocator);
}

/// A self-signed leaf: SAN only, no basicConstraints/keyUsage/EKU. Exercises
/// every §6.4 check except chain-signature coherence (count == 1, so that
/// loop never runs).
fn selfSignedLeaf(allocator: std.mem.Allocator, hostnames: []const []const u8, not_before: i64, not_after: i64) !struct {
    pem: []u8,
    key: account_mod.AccountKey,
} {
    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var key = try account_mod.AccountKey.generate();
    errdefer key.deinit();
    const pub_sec1 = key.key.publicKeySec1();

    const extensions = [_][]const u8{try sanExtension(arena, hostnames)};
    const der = try buildCertDer(arena, key.key.key_pair, 1, "acme-leaf", "acme-leaf", &pub_sec1, not_before, not_after, &extensions);
    const pem = try pemEncodeCertificate(allocator, der);
    return .{ .pem = pem, .key = key };
}

/// A two-entry leaf-first chain: leaf signed by an intermediate CA whose own
/// certificate asserts `basicConstraints CA:TRUE`.
fn chainWithIntermediate(allocator: std.mem.Allocator, hostnames: []const []const u8, not_before: i64, not_after: i64) !struct {
    pem: []u8,
    key: account_mod.AccountKey,
} {
    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var ca_seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    zig_compat.randomBytes(&ca_seed);
    const ca_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(ca_seed);
    const ca_pub_sec1 = ca_kp.public_key.toUncompressedSec1();
    const ca_extensions = [_][]const u8{try basicConstraintsCaExtension(arena)};
    const ca_der = try buildCertDer(arena, ca_kp, 2, "Tardigrade ACME Test CA", "Tardigrade ACME Test CA", &ca_pub_sec1, not_before, not_after, &ca_extensions);

    var key = try account_mod.AccountKey.generate();
    errdefer key.deinit();
    const leaf_pub_sec1 = key.key.publicKeySec1();
    const leaf_extensions = [_][]const u8{try sanExtension(arena, hostnames)};
    const leaf_der = try buildCertDer(arena, ca_kp, 1, "Tardigrade ACME Test CA", "acme-leaf", &leaf_pub_sec1, not_before, not_after, &leaf_extensions);

    const pem = try pemEncodeChain(allocator, &.{ leaf_der, ca_der });
    return .{ .pem = pem, .key = key };
}

/// A two-entry leaf-first chain shaped exactly like `chainWithIntermediate`,
/// except the leaf is signed by an unrelated key instead of the
/// intermediate's — the issuer/subject DNs still match, so verification
/// reaches the signature check and deterministically fails it.
fn chainWithBadLeafSignature(allocator: std.mem.Allocator, hostnames: []const []const u8, not_before: i64, not_after: i64) !struct {
    pem: []u8,
    key: account_mod.AccountKey,
} {
    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var ca_seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    zig_compat.randomBytes(&ca_seed);
    const ca_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(ca_seed);
    const ca_pub_sec1 = ca_kp.public_key.toUncompressedSec1();
    const ca_extensions = [_][]const u8{try basicConstraintsCaExtension(arena)};
    const ca_der = try buildCertDer(arena, ca_kp, 2, "Tardigrade ACME Test CA", "Tardigrade ACME Test CA", &ca_pub_sec1, not_before, not_after, &ca_extensions);

    var wrong_seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    zig_compat.randomBytes(&wrong_seed);
    const wrong_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(wrong_seed);

    var key = try account_mod.AccountKey.generate();
    errdefer key.deinit();
    const leaf_pub_sec1 = key.key.publicKeySec1();
    const leaf_extensions = [_][]const u8{try sanExtension(arena, hostnames)};
    const leaf_der = try buildCertDer(arena, wrong_kp, 1, "Tardigrade ACME Test CA", "acme-leaf", &leaf_pub_sec1, not_before, not_after, &leaf_extensions);

    const pem = try pemEncodeChain(allocator, &.{ leaf_der, ca_der });
    return .{ .pem = pem, .key = key };
}

const hour: i64 = 60 * 60;
const day: i64 = 24 * hour;
const base_now: i64 = 1_800_000_000; // 2027-01-15, well inside UTCTime's 2-digit-year range.

// ---------------------------------------------------------------------------
// verifyChain
// ---------------------------------------------------------------------------

test "verifyChain accepts a valid self-signed leaf with an exact SAN match" {
    const allocator = testing.allocator;
    const hosts = [_][]const u8{ "a.example.com", "b.example.com" };
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }

    const summary = try activate.verifyChain(allocator, &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now });
    try testing.expectEqual(base_now - hour, summary.not_before);
    try testing.expectEqual(base_now + 90 * day, summary.not_after);
}

test "verifyChain rejects a missing or an extra SAN entry" {
    const allocator = testing.allocator;
    const hosts = [_][]const u8{ "a.example.com", "b.example.com" };
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }

    const too_few = [_][]const u8{"a.example.com"};
    try testing.expectError(error.SanMismatch, activate.verifyChain(allocator, &fixture.key, fixture.pem, .{ .hostnames = &too_few, .now = base_now }));

    const too_many = [_][]const u8{ "a.example.com", "b.example.com", "c.example.com" };
    try testing.expectError(error.SanMismatch, activate.verifyChain(allocator, &fixture.key, fixture.pem, .{ .hostnames = &too_many, .now = base_now }));
}

test "verifyChain rejects wildcard coverage, duplicate requests, and duplicate SANs" {
    const allocator = testing.allocator;
    const requested = [_][]const u8{ "a.example.com", "b.example.com" };
    const wildcard_plus_extra = [_][]const u8{ "*.example.com", "extra.invalid" };
    var wildcard = try selfSignedLeaf(allocator, &wildcard_plus_extra, base_now - hour, base_now + 90 * day);
    defer {
        wildcard.key.deinit();
        allocator.free(wildcard.pem);
    }
    try testing.expectError(error.SanMismatch, activate.verifyChain(allocator, &wildcard.key, wildcard.pem, .{ .hostnames = &requested, .now = base_now }));

    const duplicate_san = [_][]const u8{ "a.example.com", "a.example.com" };
    var duplicate = try selfSignedLeaf(allocator, &duplicate_san, base_now - hour, base_now + 90 * day);
    defer {
        duplicate.key.deinit();
        allocator.free(duplicate.pem);
    }
    try testing.expectError(error.SanMismatch, activate.verifyChain(allocator, &duplicate.key, duplicate.pem, .{ .hostnames = &requested, .now = base_now }));

    const duplicate_request = [_][]const u8{ "a.example.com", "A.EXAMPLE.COM" };
    var ordinary = try selfSignedLeaf(allocator, &.{"a.example.com"}, base_now - hour, base_now + 90 * day);
    defer {
        ordinary.key.deinit();
        allocator.free(ordinary.pem);
    }
    try testing.expectError(error.SanMismatch, activate.verifyChain(allocator, &ordinary.key, ordinary.pem, .{ .hostnames = &duplicate_request, .now = base_now }));
}

test "verifyChain rejects a private key that does not match the certificate" {
    const allocator = testing.allocator;
    const hosts = [_][]const u8{"a.example.com"};
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }

    var other_key = try account_mod.AccountKey.generate();
    defer other_key.deinit();
    try testing.expectError(error.KeyCertificateMismatch, activate.verifyChain(allocator, &other_key, fixture.pem, .{ .hostnames = &hosts, .now = base_now }));
}

test "verifyChain rejects a leaf key that reuses the account key" {
    const allocator = testing.allocator;
    const hosts = [_][]const u8{"a.example.com"};
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }
    const account_pub = fixture.key.key.publicKeySec1();

    try testing.expectError(error.LeafKeyReusesAccountKey, activate.verifyChain(allocator, &fixture.key, fixture.pem, .{
        .hostnames = &hosts,
        .now = base_now,
        .account_public_key_sec1 = &account_pub,
    }));
}

test "verifyChain rejects not-yet-valid, expired, and overlong-validity certificates" {
    const allocator = testing.allocator;
    const hosts = [_][]const u8{"a.example.com"};

    var not_yet = try selfSignedLeaf(allocator, &hosts, base_now + day, base_now + 90 * day);
    defer {
        not_yet.key.deinit();
        allocator.free(not_yet.pem);
    }
    try testing.expectError(error.NotYetValid, activate.verifyChain(allocator, &not_yet.key, not_yet.pem, .{ .hostnames = &hosts, .now = base_now }));

    var expired = try selfSignedLeaf(allocator, &hosts, base_now - 10 * day, base_now - day);
    defer {
        expired.key.deinit();
        allocator.free(expired.pem);
    }
    try testing.expectError(error.Expired, activate.verifyChain(allocator, &expired.key, expired.pem, .{ .hostnames = &hosts, .now = base_now }));

    var overlong = try selfSignedLeaf(allocator, &hosts, base_now - day, base_now + 500 * day);
    defer {
        overlong.key.deinit();
        allocator.free(overlong.pem);
    }
    try testing.expectError(error.ValidityTooLong, activate.verifyChain(allocator, &overlong.key, overlong.pem, .{ .hostnames = &hosts, .now = base_now }));
}

test "verifyChain accepts a coherent two-certificate chain and rejects a tampered signature" {
    const allocator = testing.allocator;
    const hosts = [_][]const u8{"leaf.example.com"};
    var fixture = try chainWithIntermediate(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }
    _ = try activate.verifyChain(allocator, &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    // An unambiguously well-formed chain whose leaf was actually signed by
    // an unrelated key (its issuer DN still matches the intermediate's
    // subject DN, so chain ordering passes before the signature check
    // runs). Deterministic regardless of the random ECDSA signature's DER
    // encoding/length, unlike flipping an arbitrary byte near the end of
    // the PEM body, which can land on a DER tag/length/boundary instead of
    // signature content and produce `MalformedChain` on some seeds.
    var tampered = try chainWithBadLeafSignature(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        tampered.key.deinit();
        allocator.free(tampered.pem);
    }
    try testing.expectError(error.CertificateSignatureInvalid, activate.verifyChain(allocator, &tampered.key, tampered.pem, .{ .hostnames = &hosts, .now = base_now }));
}

test "verifyChain rejects a structurally malformed certificate" {
    const allocator = testing.allocator;
    const hosts = [_][]const u8{"a.example.com"};
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }

    // An invalid base64 character inside the PEM body breaks decoding
    // independent of the certificate's random content.
    var corrupted = try allocator.dupe(u8, fixture.pem);
    defer allocator.free(corrupted);
    const marker = "-----BEGIN CERTIFICATE-----\n";
    const start = std.mem.indexOf(u8, corrupted, marker).? + marker.len;
    corrupted[start] = '!';
    try testing.expectError(error.MalformedChain, activate.verifyChain(allocator, &fixture.key, corrupted, .{ .hostnames = &hosts, .now = base_now }));
}

// ---------------------------------------------------------------------------
// verifyAndPersist / loadCommitted
// ---------------------------------------------------------------------------

const TempState = struct {
    tmp: testing.TmpDir,
    path: []u8,

    fn init() !TempState {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = try tmp.dir.realPath(zig_compat.io(), &buf);
        const path = try std.fmt.allocPrint(testing.allocator, "{s}/state", .{buf[0..n]});
        return .{ .tmp = tmp, .path = path };
    }

    fn deinit(self: *TempState) void {
        testing.allocator.free(self.path);
        self.tmp.cleanup();
    }
};

test "verifyAndPersist writes a recoverable generation and loadCommitted round-trips it" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const hosts = [_][]const u8{ "a.example.com", "b.example.com" };
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }

    const persisted = try activate.verifyAndPersist(allocator, &state, "group-1", &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now });
    try testing.expect(persisted.generationId().len > 0);

    var loaded = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
    defer loaded.deinit(allocator);
    try testing.expectEqualStrings(persisted.generationId(), loaded.generationId());
    try testing.expectEqual(base_now + 90 * day, loaded.meta.notAfter());
    try testing.expectEqualSlices(u8, &fixture.key.jwk().x, &loaded.leaf_key.jwk().x);
}

test "loadCommitted returns null for a group that was never persisted" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const hosts = [_][]const u8{"a.example.com"};
    try testing.expectEqual(@as(?activate.LoadedGeneration, null), try activate.loadCommitted(allocator, &state, "never-seen", &hosts, base_now));
}

test "loadCommitted never promotes a generation without a committed current pointer" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();
    const hosts = [_][]const u8{"a.example.com"};
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }
    _ = try activate.verifyAndPersist(allocator, &state, "group-1", &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    var groups = try state.openSubdirStrict("groups");
    defer groups.close();
    var group = try groups.openSubdirStrict("group-1");
    defer group.close();
    try group.renameWithin("current", "current.tmp");

    try testing.expectEqual(@as(?activate.LoadedGeneration, null), try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now));
}

test "loadCommitted rejects an insecure current pointer without mutating generations" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();
    const hosts = [_][]const u8{"a.example.com"};
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }
    _ = try activate.verifyAndPersist(allocator, &state, "group-1", &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    var groups = try state.openSubdirStrict("groups");
    defer groups.close();
    var group = try groups.openSubdirStrict("group-1");
    defer group.close();
    const current_fd = try zig_compat.openAtNoFollow(group.fd, "current", .{ .write = true }, 0);
    defer zig_compat.closeFd(current_fd);
    try zig_compat.fchmodFd(current_fd, 0o666);

    try testing.expectError(error.InsecurePermissions, activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now));
}

test "verifyAndPersist leaves the prior committed generation untouched on failed verification" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const hosts = [_][]const u8{"a.example.com"};
    var good = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        good.key.deinit();
        allocator.free(good.pem);
    }
    const first = try activate.verifyAndPersist(allocator, &state, "group-1", &good.key, good.pem, .{ .hostnames = &hosts, .now = base_now });

    var expired = try selfSignedLeaf(allocator, &hosts, base_now - 10 * day, base_now - day);
    defer {
        expired.key.deinit();
        allocator.free(expired.pem);
    }
    try testing.expectError(error.Expired, activate.verifyAndPersist(allocator, &state, "group-1", &expired.key, expired.pem, .{ .hostnames = &hosts, .now = base_now }));

    var loaded = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
    defer loaded.deinit(allocator);
    try testing.expectEqualStrings(first.generationId(), loaded.generationId());
}

test "a failure at every persist and commit step keeps the previously committed generation" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const hosts = [_][]const u8{"a.example.com"};
    var good = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        good.key.deinit();
        allocator.free(good.pem);
    }
    const first = try activate.verifyAndPersist(allocator, &state, "group-1", &good.key, good.pem, .{ .hostnames = &hosts, .now = base_now });

    // Target every write step at every file the persist procedure writes,
    // not just `leaf.key` (the first write the old untargeted fault always
    // hit): `chain.pem`, `meta.json`, and the commit marker's own write of
    // `current.tmp` each get the same create/write/fsync/rename treatment.
    const write_points = [_]state_mod.Fault{ .create_temp, .write, .short_write, .fsync_file, .close_file, .rename, .fsync_dir };
    const write_targets = [_][]const u8{ "leaf.key", "chain.pem", "meta.json", "current.tmp" };
    for (write_targets) |target| {
        for (write_points) |point| {
            var replacement = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 120 * day);
            defer {
                replacement.key.deinit();
                allocator.free(replacement.pem);
            }
            state.fault_file = target;
            state.fault = point;
            try testing.expectError(error.InjectedFault, activate.verifyAndPersist(allocator, &state, "group-1", &replacement.key, replacement.pem, .{ .hostnames = &hosts, .now = base_now }));
            state.fault_file = null;

            var loaded = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
            defer loaded.deinit(allocator);
            try testing.expectEqualStrings(first.generationId(), loaded.generationId());
            try testing.expectEqual(base_now + 90 * day, loaded.meta.notAfter());
        }
    }

    // The `current.tmp -> current` commit rename itself: no ordinary
    // write's own `.rename` fault point ever reaches this, because it is a
    // second, separate rename performed after `current.tmp`'s own write
    // (including its internal rename) already succeeded.
    {
        var replacement = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 120 * day);
        defer {
            replacement.key.deinit();
            allocator.free(replacement.pem);
        }
        state.fault_file = "current";
        state.fault = .rename;
        try testing.expectError(error.InjectedFault, activate.verifyAndPersist(allocator, &state, "group-1", &replacement.key, replacement.pem, .{ .hostnames = &hosts, .now = base_now }));
        state.fault_file = null;

        var loaded = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
        defer loaded.deinit(allocator);
        try testing.expectEqualStrings(first.generationId(), loaded.generationId());
        try testing.expectEqual(base_now + 90 * day, loaded.meta.notAfter());
    }

    // The fsync that follows the commit rename is ambiguous on failure: the
    // rename already made the new generation visible, so (unlike every
    // other step above) the correct outcome here is that the new
    // generation becomes current despite the reported error.
    {
        var replacement = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 150 * day);
        defer {
            replacement.key.deinit();
            allocator.free(replacement.pem);
        }
        state.fault_file = "current";
        state.fault = .fsync_dir;
        try testing.expectError(error.InjectedFault, activate.verifyAndPersist(allocator, &state, "group-1", &replacement.key, replacement.pem, .{ .hostnames = &hosts, .now = base_now }));
        state.fault_file = null;

        var loaded = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
        defer loaded.deinit(allocator);
        try testing.expectEqual(base_now + 150 * day, loaded.meta.notAfter());
    }
}

test "loadCommitted falls back to the previous generation when the current one is corrupted" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const hosts = [_][]const u8{"a.example.com"};
    var first_fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        first_fixture.key.deinit();
        allocator.free(first_fixture.pem);
    }
    const first = try activate.verifyAndPersist(allocator, &state, "group-1", &first_fixture.key, first_fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    var second_fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 120 * day);
    defer {
        second_fixture.key.deinit();
        allocator.free(second_fixture.pem);
    }
    const second = try activate.verifyAndPersist(allocator, &state, "group-1", &second_fixture.key, second_fixture.pem, .{ .hostnames = &hosts, .now = base_now });
    try testing.expect(!std.mem.eql(u8, first.generationId(), second.generationId()));

    // A healthy restart must retain the prior committed fallback, not prune
    // it merely because the current generation verified successfully.
    var initial_restart = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
    initial_restart.deinit(allocator);

    // Corrupt the now-current (second) generation's leaf key directly on
    // disk, simulating a crash that left a half-written/garbled file.
    var groups = try state.openSubdirStrict("groups");
    defer groups.close();
    var group = try groups.openSubdirStrict("group-1");
    defer group.close();
    var generations = try group.openSubdirStrict("generations");
    defer generations.close();
    var gen_dir = try generations.openSubdirStrict(second.generationId());
    try gen_dir.writeFileAtomic("leaf.key", "not a key", 0o600);
    gen_dir.close();

    var loaded = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
    defer loaded.deinit(allocator);
    try testing.expectEqualStrings(first.generationId(), loaded.generationId());

    // The corrupted generation was renamed away, never deleted.
    var names: [64][64]u8 = undefined;
    var lens: [64]usize = undefined;
    var generations_again = try group.openSubdirStrict("generations");
    defer generations_again.close();
    const count = generations_again.listNames(&names, &lens);
    var saw_corrupt = false;
    for (0..count) |i| {
        if (std.mem.indexOf(u8, names[i][0..lens[i]], ".corrupt-") != null) saw_corrupt = true;
    }
    try testing.expect(saw_corrupt);
}

test "verifyAndPersist refuses a symlinked groups directory" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const target = try std.fmt.allocPrint(testing.allocator, "{s}-elsewhere", .{tmp.path});
    defer testing.allocator.free(target);
    try zig_compat.mkdirPath(target, 0o700);
    try tmp.tmp.dir.symLink(zig_compat.io(), target, "state/groups", .{ .is_directory = true });

    const hosts = [_][]const u8{"a.example.com"};
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }
    try testing.expectError(error.UnsafeFileType, activate.verifyAndPersist(allocator, &state, "group-1", &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now }));
}

test "loadCommitted does not leak the recovered generation on a hard error validating the retained previous" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const hosts = [_][]const u8{"a.example.com"};
    var first_fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        first_fixture.key.deinit();
        allocator.free(first_fixture.pem);
    }
    const first = try activate.verifyAndPersist(allocator, &state, "group-1", &first_fixture.key, first_fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    var second_fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 120 * day);
    defer {
        second_fixture.key.deinit();
        allocator.free(second_fixture.pem);
    }
    _ = try activate.verifyAndPersist(allocator, &state, "group-1", &second_fixture.key, second_fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    // Make the retained-fallback (first) generation's metadata file insecure
    // (group/other writable). Validating it during recovery must now be a
    // hard error, not a soft "fall back further" corruption.
    var groups = try state.openSubdirStrict("groups");
    defer groups.close();
    var group = try groups.openSubdirStrict("group-1");
    defer group.close();
    var generations = try group.openSubdirStrict("generations");
    defer generations.close();
    var gen_dir = try generations.openSubdirStrict(first.generationId());
    const meta_fd = try zig_compat.openAtNoFollow(gen_dir.fd, "meta.json", .{ .write = true }, 0);
    try zig_compat.fchmodFd(meta_fd, 0o666);
    zig_compat.closeFd(meta_fd);
    gen_dir.close();

    // `testing.allocator` fails the build on any leak; this call must
    // return the error without leaking the already-loaded current
    // generation's leaf key, chain, or metadata.
    try testing.expectError(error.InsecurePermissions, activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now));
}

test "loadCommitted does not leak the recovered generation when dropping a dead previous fails to commit" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const hosts = [_][]const u8{"a.example.com"};
    var first_fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        first_fixture.key.deinit();
        allocator.free(first_fixture.pem);
    }
    const first = try activate.verifyAndPersist(allocator, &state, "group-1", &first_fixture.key, first_fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    var second_fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 120 * day);
    defer {
        second_fixture.key.deinit();
        allocator.free(second_fixture.pem);
    }
    _ = try activate.verifyAndPersist(allocator, &state, "group-1", &second_fixture.key, second_fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    // Soft-corrupt the retained fallback (first) so recovery drops it from
    // the commit record — the marker rewrite that must then run is exactly
    // the step the injected fault below targets.
    var groups = try state.openSubdirStrict("groups");
    defer groups.close();
    var group = try groups.openSubdirStrict("group-1");
    defer group.close();
    var generations = try group.openSubdirStrict("generations");
    defer generations.close();
    var gen_dir = try generations.openSubdirStrict(first.generationId());
    try gen_dir.writeFileAtomic("leaf.key", "not a key", 0o600);
    gen_dir.close();

    state.fault_file = "current";
    state.fault = .fsync_dir;
    defer state.fault_file = null;
    try testing.expectError(error.InjectedFault, activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now));
}

test "loadCommitted rejects insecure permissions on chain.pem and meta.json without falling back" {
    const allocator = testing.allocator;

    inline for (.{ "chain.pem", "meta.json" }) |insecure_file| {
        var tmp = try TempState.init();
        defer tmp.deinit();
        var state = try state_mod.StateDir.open(tmp.path);
        defer state.close();

        const hosts = [_][]const u8{"a.example.com"};
        var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
        defer {
            fixture.key.deinit();
            allocator.free(fixture.pem);
        }
        const first = try activate.verifyAndPersist(allocator, &state, "group-1", &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now });

        var groups = try state.openSubdirStrict("groups");
        defer groups.close();
        var group = try groups.openSubdirStrict("group-1");
        defer group.close();
        var generations = try group.openSubdirStrict("generations");
        defer generations.close();
        var gen_dir = try generations.openSubdirStrict(first.generationId());
        const fd = try zig_compat.openAtNoFollow(gen_dir.fd, insecure_file, .{ .write = true }, 0);
        try zig_compat.fchmodFd(fd, 0o666);
        zig_compat.closeFd(fd);
        gen_dir.close();

        try testing.expectError(error.InsecurePermissions, activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now));
    }
}

/// A maximal-length (253-octet) distinct DNS name: three 63-octet labels
/// followed by a 61-octet label carrying `index` so every name differs.
fn maxLengthHostname(buf: *[253]u8, index: u8) []const u8 {
    var offset: usize = 0;
    for (0..3) |_| {
        @memset(buf[offset .. offset + 63], 'a');
        offset += 63;
        buf[offset] = '.';
        offset += 1;
    }
    const last_label = buf[offset .. offset + 61];
    last_label[0] = 'n';
    last_label[1] = '0' + @as(u8, @intCast(index / 10));
    last_label[2] = '0' + @as(u8, @intCast(index % 10));
    @memset(last_label[3..], 'z');
    offset += 61;
    return buf[0..offset];
}

test "verifyAndPersist and loadCommitted round-trip a maximum-size 16-name group" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    var name_bufs: [activate.max_hostnames_per_group][253]u8 = undefined;
    var hosts: [activate.max_hostnames_per_group][]const u8 = undefined;
    for (0..activate.max_hostnames_per_group) |i| {
        hosts[i] = maxLengthHostname(&name_bufs[i], @intCast(i));
    }

    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }
    const persisted = try activate.verifyAndPersist(allocator, &state, "group-1", &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    var loaded = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
    defer loaded.deinit(allocator);
    try testing.expectEqualStrings(persisted.generationId(), loaded.generationId());
    try testing.expectEqual(@as(usize, activate.max_hostnames_per_group), loaded.meta.hostnames().len);
}

test "pruneGenerations reclaims orphans past the 64-entry directory snapshot" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const hosts = [_][]const u8{"a.example.com"};
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }
    const first = try activate.verifyAndPersist(allocator, &state, "group-1", &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    {
        var groups = try state.openSubdirStrict("groups");
        defer groups.close();
        var group = try groups.openSubdirStrict("group-1");
        defer group.close();
        var generations = try group.openSubdirStrict("generations");
        defer generations.close();

        // Far more orphan generation directories than the 64-entry
        // enumeration snapshot can hold in one pass.
        var i: u64 = 1000;
        while (i < 1090) : (i += 1) {
            var name_buf: [64]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "{d}-{x:0>16}", .{ i, i }) catch unreachable;
            var orphan = try generations.openOrCreateSubdir(name);
            orphan.close();
        }
    }

    var second = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 120 * day);
    defer {
        second.key.deinit();
        allocator.free(second.pem);
    }
    const persisted = try activate.verifyAndPersist(allocator, &state, "group-1", &second.key, second.pem, .{ .hostnames = &hosts, .now = base_now });
    try testing.expect(!std.mem.eql(u8, first.generationId(), persisted.generationId()));

    var groups = try state.openSubdirStrict("groups");
    defer groups.close();
    var group = try groups.openSubdirStrict("group-1");
    defer group.close();
    var generations = try group.openSubdirStrict("generations");
    defer generations.close();
    var names: [64][64]u8 = undefined;
    var lens: [64]usize = undefined;
    const count = try generations.listNamesStrict(&names, &lens);
    try testing.expectEqual(@as(usize, 2), count);
}

test "pruneGenerations reclaims orphans behind a wall of retained corrupt archives" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const hosts = [_][]const u8{"a.example.com"};
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }
    const first = try activate.verifyAndPersist(allocator, &state, "group-1", &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    const orphan_count = 20;
    {
        var groups = try state.openSubdirStrict("groups");
        defer groups.close();
        var group = try groups.openSubdirStrict("group-1");
        defer group.close();
        var generations = try group.openSubdirStrict("generations");
        defer generations.close();

        // More retained `*.corrupt-*` archives than a single 64-entry
        // enumeration snapshot can hold, so a scan that gives up after the
        // first 64 raw entries would never see the orphans below,
        // regardless of the filesystem's iteration order.
        var i: u64 = 0;
        while (i < 70) : (i += 1) {
            var name_buf: [64]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "{d}-{x:0>16}.corrupt-{d}", .{ 500 + i, i, i }) catch unreachable;
            var corrupt = try generations.openOrCreateSubdir(name);
            corrupt.close();
        }
        // Real orphans, sitting behind the archive wall in creation order.
        var j: u64 = 1000;
        while (j < 1000 + orphan_count) : (j += 1) {
            var name_buf: [64]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "{d}-{x:0>16}", .{ j, j }) catch unreachable;
            var orphan = try generations.openOrCreateSubdir(name);
            orphan.close();
        }
    }

    var second = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 120 * day);
    defer {
        second.key.deinit();
        allocator.free(second.pem);
    }
    const persisted = try activate.verifyAndPersist(allocator, &state, "group-1", &second.key, second.pem, .{ .hostnames = &hosts, .now = base_now });

    var groups = try state.openSubdirStrict("groups");
    defer groups.close();
    var group = try groups.openSubdirStrict("group-1");
    defer group.close();
    var generations = try group.openSubdirStrict("generations");
    defer generations.close();

    var j: u64 = 1000;
    while (j < 1000 + orphan_count) : (j += 1) {
        var name_buf: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "{d}-{x:0>16}", .{ j, j }) catch unreachable;
        try testing.expectError(error.NotFound, generations.openSubdirStrict(name));
    }

    var i: u64 = 0;
    while (i < 70) : (i += 1) {
        var name_buf: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "{d}-{x:0>16}.corrupt-{d}", .{ 500 + i, i, i }) catch unreachable;
        var corrupt = try generations.openSubdirStrict(name);
        corrupt.close();
    }

    // The two live generations are untouched by the sweep.
    var loaded = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
    defer loaded.deinit(allocator);
    try testing.expectEqualStrings(persisted.generationId(), loaded.generationId());
    try testing.expect(!std.mem.eql(u8, first.generationId(), persisted.generationId()));
}

test "pruneGenerations stops rather than looping forever on a stuck generation-shaped regular file" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const hosts = [_][]const u8{"a.example.com"};
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }
    const first = try activate.verifyAndPersist(allocator, &state, "group-1", &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    const removable_orphan = "1000-0000000000000001";
    const stuck_name = "1001-0000000000000002";
    {
        var groups = try state.openSubdirStrict("groups");
        defer groups.close();
        var group = try groups.openSubdirStrict("group-1");
        defer group.close();
        var generations = try group.openSubdirStrict("generations");
        defer generations.close();

        // A genuinely removable orphan, so a successful batch is still
        // possible alongside the stuck entry below.
        var orphan = try generations.openOrCreateSubdir(removable_orphan);
        orphan.close();

        // A regular file shaped like a generation id: `openSubdirStrict`
        // fails with `error.UnsafeFileType` on every pass, so without a
        // progress check `pruneGenerations` would resubmit it forever.
        try generations.writeFileAtomic(stuck_name, "not a directory", 0o600);
    }

    var second = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 120 * day);
    defer {
        second.key.deinit();
        allocator.free(second.pem);
    }
    const persisted = try activate.verifyAndPersist(allocator, &state, "group-1", &second.key, second.pem, .{ .hostnames = &hosts, .now = base_now });
    try testing.expect(!std.mem.eql(u8, first.generationId(), persisted.generationId()));

    var groups = try state.openSubdirStrict("groups");
    defer groups.close();
    var group = try groups.openSubdirStrict("group-1");
    defer group.close();
    var generations = try group.openSubdirStrict("generations");
    defer generations.close();

    try testing.expectError(error.NotFound, generations.openSubdirStrict(removable_orphan));
    // The stuck file is left in place rather than causing a hang; the
    // committed pair is unaffected.
    const stuck_stat = try generations.readFileAlloc(allocator, stuck_name, 64, false);
    defer allocator.free(stuck_stat);
    try testing.expectEqualStrings("not a directory", stuck_stat);

    var loaded = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
    defer loaded.deinit(allocator);
    try testing.expectEqualStrings(persisted.generationId(), loaded.generationId());
}

test "pruneGenerations stops rather than looping forever on a non-empty generation directory" {
    const allocator = testing.allocator;
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try state_mod.StateDir.open(tmp.path);
    defer state.close();

    const hosts = [_][]const u8{"a.example.com"};
    var fixture = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 90 * day);
    defer {
        fixture.key.deinit();
        allocator.free(fixture.pem);
    }
    const first = try activate.verifyAndPersist(allocator, &state, "group-1", &fixture.key, fixture.pem, .{ .hostnames = &hosts, .now = base_now });

    const removable_orphan = "1000-0000000000000001";
    const stuck_name = "1001-0000000000000002";
    {
        var groups = try state.openSubdirStrict("groups");
        defer groups.close();
        var group = try groups.openSubdirStrict("group-1");
        defer group.close();
        var generations = try group.openSubdirStrict("generations");
        defer generations.close();

        var orphan = try generations.openOrCreateSubdir(removable_orphan);
        orphan.close();

        // A generation directory with an unexpected extra file alongside
        // it: removing the three known generation files still leaves the
        // directory non-empty, so `removeEmpty` keeps failing every pass.
        var stuck = try generations.openOrCreateSubdir(stuck_name);
        try stuck.writeFileAtomic("unexpected.txt", "surprise", 0o600);
        stuck.close();
    }

    var second = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 120 * day);
    defer {
        second.key.deinit();
        allocator.free(second.pem);
    }
    const persisted = try activate.verifyAndPersist(allocator, &state, "group-1", &second.key, second.pem, .{ .hostnames = &hosts, .now = base_now });
    try testing.expect(!std.mem.eql(u8, first.generationId(), persisted.generationId()));

    var groups = try state.openSubdirStrict("groups");
    defer groups.close();
    var group = try groups.openSubdirStrict("group-1");
    defer group.close();
    var generations = try group.openSubdirStrict("generations");
    defer generations.close();

    try testing.expectError(error.NotFound, generations.openSubdirStrict(removable_orphan));
    // The stuck directory survives (its extra file blocks `removeEmpty`)
    // rather than causing a hang; the committed pair is unaffected.
    var stuck = try generations.openSubdirStrict(stuck_name);
    defer stuck.close();
    const leftover = try stuck.readFileAlloc(allocator, "unexpected.txt", 64, false);
    defer allocator.free(leftover);
    try testing.expectEqualStrings("surprise", leftover);

    var loaded = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
    defer loaded.deinit(allocator);
    try testing.expectEqualStrings(persisted.generationId(), loaded.generationId());
}
