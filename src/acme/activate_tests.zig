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

    // Flip a byte inside the PEM's base64 body (comfortably inside the
    // leaf's signature bytes near the end of the first block) and confirm
    // the chain no longer verifies.
    const tampered = try allocator.dupe(u8, fixture.pem);
    defer allocator.free(tampered);
    const marker = "-----END CERTIFICATE-----";
    const end = std.mem.indexOf(u8, tampered, marker).?;
    tampered[end - 4] = if (tampered[end - 4] == 'A') 'B' else 'A';
    try testing.expectError(error.CertificateSignatureInvalid, activate.verifyChain(allocator, &fixture.key, tampered, .{ .hostnames = &hosts, .now = base_now }));
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

test "a failure at every persist step keeps the previously committed generation" {
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

    const points = [_]state_mod.Fault{ .create_temp, .write, .short_write, .fsync_file, .close_file, .rename, .fsync_dir };
    for (points) |point| {
        var replacement = try selfSignedLeaf(allocator, &hosts, base_now - hour, base_now + 120 * day);
        defer {
            replacement.key.deinit();
            allocator.free(replacement.pem);
        }
        state.fault = point;
        try testing.expectError(error.InjectedFault, activate.verifyAndPersist(allocator, &state, "group-1", &replacement.key, replacement.pem, .{ .hostnames = &hosts, .now = base_now }));

        var loaded = (try activate.loadCommitted(allocator, &state, "group-1", &hosts, base_now)).?;
        defer loaded.deinit(allocator);
        try testing.expectEqualStrings(first.generationId(), loaded.generationId());
        try testing.expectEqual(base_now + 90 * day, loaded.meta.notAfter());
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
