//! Test-only, minimal real-crypto DER certificate builder (#884), shared by
//! every test that needs an actually-verifiable issued chain rather than a
//! scripted/fixture one (`fake_ca.zig`'s own certificate response is not
//! real X.509 -- see `acme_activation.zig`'s negative test for why). Mirrors
//! `activate_tests.zig`'s self-signed-leaf builder, which in turn mirrors
//! `pki/x509_tests.zig`'s synthetic-corpus builder; signs with a real P-256
//! key so `pki.verify`/`activate.verifyChain`'s signature and key-binding
//! checks have something genuine to check.
//!
//! Not imported by any production path; only by test files.

const std = @import("std");
const pki = @import("pki");
const zig_compat = @import("zig_compat");
const account_mod = @import("account.zig");

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

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
    if (critical) {
        return tlv(arena, 0x30, &.{
            try oidTlv(arena, ext_oid),
            try tlv(arena, 0x01, &.{&[_]u8{0xff}}),
            try tlv(arena, 0x04, &.{value}),
        });
    }
    return tlv(arena, 0x30, &.{ try oidTlv(arena, ext_oid), try tlv(arena, 0x04, &.{value}) });
}

fn sanExtension(arena: std.mem.Allocator, hostnames: []const []const u8) ![]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    for (hostnames) |h| try parts.append(arena, try tlv(arena, 0x82, &.{h}));
    const san_value = try tlv(arena, 0x30, parts.items);
    return try extensionTlv(arena, &pki.oid.well_known.subject_alt_name, false, san_value);
}

fn caExtensions(arena: std.mem.Allocator) ![]const u8 {
    const basic_constraints = try tlv(arena, 0x30, &.{try tlv(arena, 0x01, &.{&[_]u8{0xff}})});
    const key_usage = try tlv(arena, 0x03, &.{&[_]u8{ 0, 0x04 }});
    return tlv(arena, 0x30, &.{
        try extensionTlv(arena, &pki.oid.well_known.basic_constraints, true, basic_constraints),
        try extensionTlv(arena, &pki.oid.well_known.key_usage, true, key_usage),
    });
}

fn buildTbs(
    arena: std.mem.Allocator,
    issuer: []const u8,
    subject: []const u8,
    validity: []const u8,
    spki: []const u8,
    extensions: []const u8,
) ![]u8 {
    return tlv(arena, 0x30, &.{
        try versionTlv(arena, 2),
        try tlv(arena, 0x02, &.{&[_]u8{1}}),
        try algorithmEcdsaSha256(arena),
        issuer,
        validity,
        subject,
        spki,
        try tlv(arena, 0xa3, &.{try tlv(arena, 0x30, &.{extensions})}),
    });
}

fn signAndBuildCertificate(arena: std.mem.Allocator, signer: EcdsaP256Sha256.KeyPair, tbs: []const u8) ![]u8 {
    var noise: [EcdsaP256Sha256.noise_length]u8 = undefined;
    zig_compat.randomBytes(&noise);
    const signature = try signer.sign(tbs, noise);
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = signature.toDer(&der_buf);
    return tlv(arena, 0x30, &.{ tbs, try algorithmEcdsaSha256(arena), try bitStringNoUnused(arena, sig_der) });
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

/// A real, self-signed (SAN only) P-256 leaf certificate and its matching
/// fresh key, built and signed in-process -- no fixture files, no CA.
pub fn selfSignedLeaf(allocator: std.mem.Allocator, hostnames: []const []const u8, not_before: i64, not_after: i64) !struct {
    pem: []u8,
    key: account_mod.AccountKey,
} {
    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var key = try account_mod.AccountKey.generate();
    errdefer key.deinit();
    const pub_sec1 = key.key.publicKeySec1();

    const name = try nameWithCn(arena, "acme-leaf");
    const validity = try validityTlv(arena, not_before, not_after);
    const spki = try spkiEcdsaP256(arena, &pub_sec1);
    const extensions = try sanExtension(arena, hostnames);
    const tbs = try buildTbs(arena, name, name, validity, spki, extensions);
    const der = try signAndBuildCertificate(arena, key.key.key_pair, tbs);
    const pem = try pemEncodeCertificate(allocator, der);
    return .{ .pem = pem, .key = key };
}

fn csrPublicKey(csr_der: []const u8) ![]const u8 {
    var top = pki.der.Reader.init(csr_der, pki.der.default_limits);
    var csr = try top.readSequence();
    try top.expectEnd();
    const tbs_elem = try csr.readElement();
    var tbs_top = pki.der.Reader.init(tbs_elem.encoded, pki.der.default_limits);
    var tbs = try tbs_top.readSequence();
    _ = try tbs.readInteger();
    var subject = try tbs.readSequence();
    try subject.expectEnd();
    var spki = try tbs.readSequence();
    var algorithm = try spki.readSequence();
    const ec_oid = try algorithm.readObjectIdentifier();
    if (!ec_oid.eqlComponents(&pki.oid.well_known.ec_public_key)) return error.InvalidCsr;
    const curve_oid = try algorithm.readObjectIdentifier();
    if (!curve_oid.eqlComponents(&pki.oid.well_known.secp256r1)) return error.InvalidCsr;
    try algorithm.expectEnd();
    const public_bits = try spki.readBitString();
    try spki.expectEnd();
    if (public_bits.data.len != 65) return error.InvalidCsr;

    return public_bits.data;
}

/// Persistent in-process test CA. Its leaf-first PEM output can be verified
/// independently by trusting `certificate_pem`, unlike the old throwaway
/// signer whose public key was discarded.
pub const TestCa = struct {
    key: account_mod.AccountKey,
    certificate_pem: []u8,

    pub fn init(allocator: std.mem.Allocator, not_before: i64, not_after: i64) !TestCa {
        var key = try account_mod.AccountKey.generate();
        errdefer key.deinit();
        var arena_inst = std.heap.ArenaAllocator.init(allocator);
        defer arena_inst.deinit();
        const arena = arena_inst.allocator();
        const name = try nameWithCn(arena, "acme-test-ca");
        const spki = try spkiEcdsaP256(arena, &key.key.publicKeySec1());
        const tbs = try buildTbs(arena, name, name, try validityTlv(arena, not_before, not_after), spki, try caExtensions(arena));
        const der = try signAndBuildCertificate(arena, key.key.key_pair, tbs);
        return .{ .key = key, .certificate_pem = try pemEncodeCertificate(allocator, der) };
    }

    pub fn deinit(self: *TestCa, allocator: std.mem.Allocator) void {
        self.key.deinit();
        allocator.free(self.certificate_pem);
        self.* = undefined;
    }

    pub fn issueForCsr(self: *const TestCa, allocator: std.mem.Allocator, csr_der: []const u8, hostnames: []const []const u8, not_before: i64, not_after: i64) ![]u8 {
        const public_bits = try csrPublicKey(csr_der);
        var arena_inst = std.heap.ArenaAllocator.init(allocator);
        defer arena_inst.deinit();
        const arena = arena_inst.allocator();
        const issuer = try nameWithCn(arena, "acme-test-ca");
        const subject = try nameWithCn(arena, "acme-issued-leaf");
        const leaf_spki = try spkiEcdsaP256(arena, public_bits);
        const extensions = try sanExtension(arena, hostnames);
        const tbs = try buildTbs(arena, issuer, subject, try validityTlv(arena, not_before, not_after), leaf_spki, extensions);
        const der = try signAndBuildCertificate(arena, self.key.key.key_pair, tbs);
        const leaf_pem = try pemEncodeCertificate(allocator, der);
        defer allocator.free(leaf_pem);
        return std.mem.concat(allocator, u8, &.{ leaf_pem, self.certificate_pem });
    }
};

/// Builds a one-off CA-issued chain. Callers that rotate generations should
/// retain a `TestCa` and trust its stable `certificate_pem` instead.
pub fn leafForCsr(allocator: std.mem.Allocator, csr_der: []const u8, hostnames: []const []const u8, not_before: i64, not_after: i64) ![]u8 {
    var ca = try TestCa.init(allocator, not_before, not_after);
    defer ca.deinit(allocator);
    return ca.issueForCsr(allocator, csr_der, hostnames, not_before, not_after);
}

test {
    std.testing.refAllDecls(@This());
}
