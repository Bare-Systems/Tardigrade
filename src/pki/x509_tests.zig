//! X.509 certificate model regression and adversarial tests (#341).
//!
//! Real-world fixtures under `testdata/` were generated with OpenSSL 3.0:
//! an RSA-2048 self-signed CA (name constraints, 2059 expiry), a P-256
//! leaf signed by that CA (SAN, EKU, AKI with issuer+serial, AIA, CRLDP,
//! policies), a self-signed Ed25519 certificate, and a v1 certificate.
//! Synthetic corpora are built with a minimal DER builder.

const std = @import("std");
const der = @import("der.zig");
const oid = @import("oid.zig");
const pem = @import("pem.zig");
const x509 = @import("x509.zig");

const testing = std.testing;

const rsa_ca_pem = @embedFile("testdata/rsa_ca.crt");
const ecdsa_leaf_pem = @embedFile("testdata/ecdsa_leaf.crt");
const ed25519_pem = @embedFile("testdata/ed25519.crt");
const v1_leaf_pem = @embedFile("testdata/v1_leaf.crt");

fn loadFixture(allocator: std.mem.Allocator, pem_text: []const u8) !pem.Certificate {
    return pem.loadCertificatePem(allocator, pem_text, .{});
}

test "RSA CA fixture parses into typed fields" {
    const allocator = testing.allocator;
    var fixture = try loadFixture(allocator, rsa_ca_pem);
    defer fixture.deinit(allocator);

    var cert = try x509.Certificate.parse(allocator, fixture.der, .{});
    defer cert.deinit(allocator);

    try testing.expectEqual(x509.Version.v3, cert.version);
    try testing.expectEqual(x509.SignatureAlgorithm.rsa_pkcs1_sha256, cert.signatureAlgorithm());
    try testing.expectEqual(x509.PublicKeyType.rsa, cert.subject_public_key_info.key_type);
    try testing.expect(!cert.serial_number.isNegative());
    try testing.expect(cert.isSelfIssued());
    try testing.expect(!cert.hasUnhandledCriticalExtension());

    // TBS bytes are preserved exactly: they sit inside `raw` and start with
    // a SEQUENCE tag.
    try testing.expect(cert.tbs_raw.len > 0);
    try testing.expectEqual(@as(u8, 0x30), cert.tbs_raw[0]);
    const tbs_offset = @intFromPtr(cert.tbs_raw.ptr) - @intFromPtr(cert.raw.ptr);
    try testing.expect(tbs_offset <= 4);
    try testing.expectEqualSlices(u8, cert.raw[tbs_offset..][0..cert.tbs_raw.len], cert.tbs_raw);

    const cn = cert.subject.commonName() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("Tardigrade Test RSA CA", cn);
    const org = cert.subject.findAttribute(&oid.well_known.organization) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("Tardigrade Test", org.value);

    // Expires 2059: GeneralizedTime after the 2050 UTCTime cutoff.
    try testing.expectEqual(x509.TimeEncoding.utc, cert.validity.not_before.encoding);
    try testing.expectEqual(x509.TimeEncoding.generalized, cert.validity.not_after.encoding);
    try testing.expectEqual(@as(u16, 2059), cert.validity.not_after.year);
    try testing.expect(cert.validity.not_before.order(cert.validity.not_after) == .lt);

    const bc = cert.basicConstraints() orelse return error.TestUnexpectedResult;
    try testing.expect(bc.is_ca);
    try testing.expectEqual(@as(?u32, 1), bc.max_path_len);
    const bc_ext = cert.findExtension(&oid.well_known.basic_constraints).?;
    try testing.expect(bc_ext.critical);

    const ku = cert.keyUsage() orelse return error.TestUnexpectedResult;
    try testing.expect(ku.key_cert_sign);
    try testing.expect(ku.crl_sign);
    try testing.expect(!ku.digital_signature);

    const nc = cert.nameConstraints() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 1), nc.permitted.len);
    try testing.expectEqualStrings(".example.com", nc.permitted[0].base.dns_name);
    try testing.expectEqual(@as(usize, 1), nc.excluded.len);
    // Name-constraint IP form is address plus mask.
    try testing.expectEqual(@as(usize, 8), nc.excluded[0].base.ip_address.len);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 0, 255, 0, 0, 0 }, nc.excluded[0].base.ip_address);

    const ski = cert.subjectKeyIdentifier() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 20), ski.len);
    const aki = cert.authorityKeyIdentifier() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, ski, aki.key_identifier.?);

    try testing.expect(cert.signature_value.data.len > 0);
    try testing.expectEqual(@as(u3, 0), cert.signature_value.unused_bits);
}

test "ECDSA P-256 leaf fixture parses SAN, EKU, AKI, AIA, CRLDP, and policies" {
    const allocator = testing.allocator;
    var fixture = try loadFixture(allocator, ecdsa_leaf_pem);
    defer fixture.deinit(allocator);

    var cert = try x509.Certificate.parse(allocator, fixture.der, .{});
    defer cert.deinit(allocator);

    try testing.expectEqual(x509.Version.v3, cert.version);
    // Signed by the RSA CA; the key itself is P-256.
    try testing.expectEqual(x509.SignatureAlgorithm.rsa_pkcs1_sha256, cert.signatureAlgorithm());
    try testing.expectEqual(x509.PublicKeyType.ecdsa_p256, cert.subject_public_key_info.key_type);
    try testing.expect(cert.subject_public_key_info.named_curve.?.eqlComponents(&oid.well_known.secp256r1));
    try testing.expect(!cert.isSelfIssued());
    try testing.expect(!cert.hasUnhandledCriticalExtension());

    const san = cert.subjectAltName() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 6), san.len);
    try testing.expectEqualStrings("leaf.example.com", san[0].dns_name);
    try testing.expectEqualStrings("*.leaf.example.com", san[1].dns_name);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, san[2].ip_address);
    try testing.expectEqual(@as(usize, 16), san[3].ip_address.len);
    try testing.expectEqualStrings("admin@example.com", san[4].rfc822_name);
    try testing.expectEqualStrings("https://leaf.example.com/app", san[5].uniform_resource_identifier);

    const eku = cert.extendedKeyUsage() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 2), eku.purposes.len);
    try testing.expect(eku.allowsServerAuth());
    try testing.expect(eku.allowsClientAuth());
    try testing.expect(!eku.contains(&oid.well_known.code_signing));

    const bc = cert.basicConstraints() orelse return error.TestUnexpectedResult;
    try testing.expect(!bc.is_ca);
    try testing.expectEqual(@as(?u32, null), bc.max_path_len);

    const ku = cert.keyUsage() orelse return error.TestUnexpectedResult;
    try testing.expect(ku.digital_signature);
    try testing.expect(!ku.key_cert_sign);

    // AKI generated with issuer:always carries all three fields.
    const aki = cert.authorityKeyIdentifier() orelse return error.TestUnexpectedResult;
    try testing.expect(aki.key_identifier != null);
    try testing.expect(aki.authority_cert_issuer_raw != null);
    try testing.expect(aki.authority_cert_serial != null);

    const aia_ext = cert.findExtension(&oid.well_known.authority_info_access) orelse return error.TestUnexpectedResult;
    const aia = aia_ext.parsed.authority_info_access;
    try testing.expectEqual(@as(usize, 2), aia.len);
    try testing.expect(aia[0].method.eqlComponents(&oid.well_known.aia_ocsp));
    try testing.expectEqualStrings("http://ocsp.example.com", aia[0].location.uniform_resource_identifier);
    try testing.expect(aia[1].method.eqlComponents(&oid.well_known.aia_ca_issuers));
    try testing.expectEqualStrings("http://ca.example.com/ca.der", aia[1].location.uniform_resource_identifier);

    const crldp_ext = cert.findExtension(&oid.well_known.crl_distribution_points) orelse return error.TestUnexpectedResult;
    const points = crldp_ext.parsed.crl_distribution_points;
    try testing.expectEqual(@as(usize, 1), points.len);
    try testing.expectEqual(@as(usize, 1), points[0].full_names.len);
    try testing.expectEqualStrings("http://crl.example.com/ca.crl", points[0].full_names[0].uniform_resource_identifier);

    const policies_ext = cert.findExtension(&oid.well_known.certificate_policies) orelse return error.TestUnexpectedResult;
    const policies = policies_ext.parsed.certificate_policies;
    try testing.expectEqual(@as(usize, 1), policies.len);
    try testing.expect(policies[0].policy.eqlComponents(&.{ 1, 3, 6, 1, 4, 1, 99999, 1 }));
    try testing.expectEqual(@as(?[]const u8, null), policies[0].qualifiers_raw);
}

test "Ed25519 fixture parses" {
    const allocator = testing.allocator;
    var fixture = try loadFixture(allocator, ed25519_pem);
    defer fixture.deinit(allocator);

    var cert = try x509.Certificate.parse(allocator, fixture.der, .{});
    defer cert.deinit(allocator);

    try testing.expectEqual(x509.SignatureAlgorithm.ed25519, cert.signatureAlgorithm());
    try testing.expectEqual(x509.PublicKeyType.ed25519, cert.subject_public_key_info.key_type);
    // Ed25519 keys are 32 bytes with no unused bits.
    try testing.expectEqual(@as(usize, 32), cert.subject_public_key_info.subject_public_key.data.len);
    try testing.expectEqual(@as(usize, 64), cert.signature_value.data.len);

    const san = cert.subjectAltName() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("ed25519.example.com", san[0].dns_name);
    const bc = cert.basicConstraints() orelse return error.TestUnexpectedResult;
    try testing.expect(!bc.is_ca);
}

test "v1 fixture parses without extensions or unique identifiers" {
    const allocator = testing.allocator;
    var fixture = try loadFixture(allocator, v1_leaf_pem);
    defer fixture.deinit(allocator);

    var cert = try x509.Certificate.parse(allocator, fixture.der, .{});
    defer cert.deinit(allocator);

    try testing.expectEqual(x509.Version.v1, cert.version);
    try testing.expectEqual(@as(usize, 0), cert.extensions.len);
    try testing.expectEqual(@as(?der.BitStringView, null), cert.issuer_unique_id);
    try testing.expectEqual(@as(?der.BitStringView, null), cert.subject_unique_id);
    try testing.expectEqual(@as(?x509.BasicConstraints, null), cert.basicConstraints());
    const cn = cert.subject.commonName() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("leaf.example.com", cn);
}

// --- Synthetic corpora ------------------------------------------------------

/// Concatenate `parts` into one TLV with a single-byte tag.
fn tlv(arena: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts) |part| total += part.len;
    var len_buf: [9]u8 = undefined;
    const len_len = try der.encodeLength(total, &len_buf);
    var out = try arena.alloc(u8, 1 + len_len + total);
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
    const n = try oid.encodeComponents(components, &buf);
    return tlv(arena, 0x06, &.{buf[0..n]});
}

const ed25519_components = [_]u32{ 1, 3, 101, 112 };
const ecdsa_sha256_components = [_]u32{ 1, 2, 840, 10045, 4, 3, 2 };

fn algorithmEd25519(arena: std.mem.Allocator) ![]u8 {
    return tlv(arena, 0x30, &.{try oidTlv(arena, &ed25519_components)});
}

fn nameWithCn(arena: std.mem.Allocator, cn: []const u8) ![]u8 {
    return nameWithCnTag(arena, 0x0c, cn);
}

fn nameWithCnTag(arena: std.mem.Allocator, value_tag: u8, cn: []const u8) ![]u8 {
    const atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        try tlv(arena, value_tag, &.{cn}),
    });
    return tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{atv})});
}

/// A Name with one domainComponent RDN per label, e.g. `["EXAMPLE", "COM"]`
/// for `DC=EXAMPLE,DC=COM`.
fn dnWithDomainComponents(arena: std.mem.Allocator, labels: []const []const u8, value_tag: u8) ![]u8 {
    var rdns: std.ArrayList([]const u8) = .empty;
    defer rdns.deinit(arena);
    for (labels) |label| {
        const atv = try tlv(arena, 0x30, &.{
            try oidTlv(arena, &oid.well_known.domain_component),
            try tlv(arena, value_tag, &.{label}),
        });
        try rdns.append(arena, try tlv(arena, 0x31, &.{atv}));
    }
    return tlv(arena, 0x30, rdns.items);
}

fn utcValidity(arena: std.mem.Allocator) ![]u8 {
    return tlv(arena, 0x30, &.{
        try tlv(arena, 0x17, &.{"260101000000Z"}),
        try tlv(arena, 0x17, &.{"270101000000Z"}),
    });
}

fn spkiEd25519(arena: std.mem.Allocator) ![]u8 {
    const key = [_]u8{0x00} ++ [_]u8{0xaa} ** 32;
    return tlv(arena, 0x30, &.{
        try algorithmEd25519(arena),
        try tlv(arena, 0x03, &.{&key}),
    });
}

fn signatureBits(arena: std.mem.Allocator) ![]u8 {
    const sig = [_]u8{0x00} ++ [_]u8{0xbb} ** 64;
    return tlv(arena, 0x03, &.{&sig});
}

const TbsOptions = struct {
    /// Full [0] EXPLICIT version TLV; null omits the field (v1).
    version: ?[]const u8 = null,
    inner_algorithm: ?[]const u8 = null,
    /// Full [3] extensions TLV.
    extensions_wrapper: ?[]const u8 = null,
    /// Raw TLVs appended between SPKI and extensions (unique IDs).
    trailing: []const []const u8 = &.{},
};

fn versionTlv(arena: std.mem.Allocator, value: u8) ![]u8 {
    return tlv(arena, 0xa0, &.{try tlv(arena, 0x02, &.{&[_]u8{value}})});
}

fn buildTbs(arena: std.mem.Allocator, options: TbsOptions) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(arena);
    if (options.version) |version| try parts.append(arena, version);
    try parts.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
    try parts.append(arena, options.inner_algorithm orelse try algorithmEd25519(arena));
    try parts.append(arena, try nameWithCn(arena, "Synthetic Issuer"));
    try parts.append(arena, try utcValidity(arena));
    try parts.append(arena, try nameWithCn(arena, "Synthetic Subject"));
    try parts.append(arena, try spkiEd25519(arena));
    for (options.trailing) |extra| try parts.append(arena, extra);
    if (options.extensions_wrapper) |extensions| try parts.append(arena, extensions);
    return tlv(arena, 0x30, parts.items);
}

fn buildCertificate(arena: std.mem.Allocator, options: TbsOptions) ![]u8 {
    return tlv(arena, 0x30, &.{
        try buildTbs(arena, options),
        try algorithmEd25519(arena),
        try signatureBits(arena),
    });
}

fn extensionTlv(arena: std.mem.Allocator, ext_oid: []const u32, critical: bool, value: []const u8) ![]u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(arena);
    try parts.append(arena, try oidTlv(arena, ext_oid));
    if (critical) try parts.append(arena, try tlv(arena, 0x01, &.{&[_]u8{0xff}}));
    try parts.append(arena, try tlv(arena, 0x04, &.{value}));
    return tlv(arena, 0x30, parts.items);
}

fn extensionsWrapper(arena: std.mem.Allocator, extensions: []const []const u8) ![]u8 {
    return tlv(arena, 0xa3, &.{try tlv(arena, 0x30, extensions)});
}

const unknown_ext_oid = [_]u32{ 1, 3, 6, 1, 4, 1, 99999, 99 };

test "synthetic v3 certificate round-trips through the builder" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const san_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x82, &.{"a.test"})});
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.subject_alt_name, false, san_value),
        }),
    });

    var cert = try x509.Certificate.parse(testing.allocator, bytes, .{});
    defer cert.deinit(testing.allocator);
    try testing.expectEqual(x509.Version.v3, cert.version);
    try testing.expectEqual(x509.SignatureAlgorithm.ed25519, cert.signatureAlgorithm());
    try testing.expectEqualStrings("Synthetic Subject", cert.subject.commonName().?);
    try testing.expectEqualStrings("a.test", cert.subjectAltName().?[0].dns_name);
    try testing.expectEqualSlices(u8, bytes, cert.raw);
}

test "inner and outer signature algorithm mismatch fails typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const mismatched_inner = try tlv(arena, 0x30, &.{try oidTlv(arena, &ecdsa_sha256_components)});
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .inner_algorithm = mismatched_inner,
    });
    try testing.expectError(error.SignatureAlgorithmMismatch, x509.Certificate.parse(testing.allocator, bytes, .{}));
}

test "explicit default version encoding fails typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const bytes = try buildCertificate(arena, .{ .version = try versionTlv(arena, 0) });
    try testing.expectError(error.UnsupportedVersion, x509.Certificate.parse(testing.allocator, bytes, .{}));

    const future = try buildCertificate(arena, .{ .version = try versionTlv(arena, 3) });
    try testing.expectError(error.UnsupportedVersion, x509.Certificate.parse(testing.allocator, future, .{}));
}

test "extensions require v3 and unique identifiers require v2 or v3" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const san_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x82, &.{"a.test"})});
    const extensions = try extensionsWrapper(arena, &.{
        try extensionTlv(arena, &oid.well_known.subject_alt_name, false, san_value),
    });

    // Extensions without a version field (v1).
    const v1_with_extensions = try buildCertificate(arena, .{ .extensions_wrapper = extensions });
    try testing.expectError(error.UnsupportedVersion, x509.Certificate.parse(testing.allocator, v1_with_extensions, .{}));

    // Extensions on v2.
    const v2_with_extensions = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 1),
        .extensions_wrapper = extensions,
    });
    try testing.expectError(error.UnsupportedVersion, x509.Certificate.parse(testing.allocator, v2_with_extensions, .{}));

    // issuerUniqueID on v1.
    const unique_id = try tlv(arena, 0x81, &.{&[_]u8{ 0x00, 0x99 }});
    const v1_with_unique = try buildCertificate(arena, .{ .trailing = &.{unique_id} });
    try testing.expectError(error.UnsupportedVersion, x509.Certificate.parse(testing.allocator, v1_with_unique, .{}));

    // issuerUniqueID on v2 parses.
    const v2_with_unique = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 1),
        .trailing = &.{unique_id},
    });
    var cert = try x509.Certificate.parse(testing.allocator, v2_with_unique, .{});
    defer cert.deinit(testing.allocator);
    try testing.expectEqual(x509.Version.v2, cert.version);
    try testing.expectEqualSlices(u8, &.{0x99}, cert.issuer_unique_id.?.data);
    try testing.expectEqual(@as(?der.BitStringView, null), cert.subject_unique_id);
}

test "duplicate extension OIDs fail typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const san_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x82, &.{"a.test"})});
    const san_ext = try extensionTlv(arena, &oid.well_known.subject_alt_name, false, san_value);
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{ san_ext, san_ext }),
    });
    try testing.expectError(error.DuplicateExtension, x509.Certificate.parse(testing.allocator, bytes, .{}));
}

test "unknown critical extensions are retained and surfaced for fail-closed validation" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const payload = try tlv(arena, 0x04, &.{"opaque"});
    const critical_bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &unknown_ext_oid, true, payload),
        }),
    });
    var critical_cert = try x509.Certificate.parse(testing.allocator, critical_bytes, .{});
    defer critical_cert.deinit(testing.allocator);
    try testing.expect(critical_cert.hasUnhandledCriticalExtension());
    const retained = critical_cert.findExtension(&unknown_ext_oid).?;
    try testing.expect(retained.critical);
    try testing.expect(retained.parsed == .unrecognized);
    try testing.expectEqualSlices(u8, payload, retained.value);

    // The same unknown extension without criticality is retained and ignored.
    const benign_bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &unknown_ext_oid, false, payload),
        }),
    });
    var benign_cert = try x509.Certificate.parse(testing.allocator, benign_bytes, .{});
    defer benign_cert.deinit(testing.allocator);
    try testing.expect(!benign_cert.hasUnhandledCriticalExtension());
}

test "explicit critical FALSE and explicit cA FALSE fail typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // critical FALSE spelled out violates DER DEFAULT omission.
    const san_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x82, &.{"a.test"})});
    const explicit_false_ext = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.subject_alt_name),
        try tlv(arena, 0x01, &.{&[_]u8{0x00}}),
        try tlv(arena, 0x04, &.{san_value}),
    });
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{explicit_false_ext}),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bytes, .{}));

    // cA FALSE spelled out inside BasicConstraints.
    const bc_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x01, &.{&[_]u8{0x00}})});
    const bc_bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.basic_constraints, true, bc_value),
        }),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bc_bytes, .{}));
}

test "pathLen without cA and unknown Key Usage bits fail typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // pathLenConstraint is forbidden unless cA is asserted TRUE.
    const path_len_without_ca = try tlv(arena, 0x30, &.{try tlv(arena, 0x02, &.{&[_]u8{0}})});
    const bad_path_len = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.basic_constraints, true, path_len_without_ca),
        }),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bad_path_len, .{}));

    // Key Usage assigns only bits 0..8. Bit 9 is canonically encoded here
    // but unknown to RFC 5280 and therefore rejected by the strict parser.
    const unknown_key_usage = try tlv(arena, 0x03, &.{&[_]u8{ 6, 0, 0x40 }});
    const bad_key_usage = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.key_usage, true, unknown_key_usage),
        }),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bad_key_usage, .{}));
}

test "malformed structures fail deterministically" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const valid = try buildCertificate(arena, .{ .version = try versionTlv(arena, 2) });

    // Truncation at every prefix fails without crashing; full input parses.
    var prefix_len: usize = 0;
    while (prefix_len < valid.len) : (prefix_len += 7) {
        const result = x509.Certificate.parse(testing.allocator, valid[0..prefix_len], .{});
        try testing.expectError(error.MalformedCertificate, result);
    }

    // Trailing bytes after the certificate.
    const trailing = try std.mem.concat(arena, u8, &.{ valid, "\x00" });
    try testing.expectError(error.MalformedCertificate, x509.Certificate.parse(testing.allocator, trailing, .{}));

    // Empty extensions SEQUENCE violates SIZE (1..MAX).
    const empty_extensions = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try tlv(arena, 0xa3, &.{try tlv(arena, 0x30, &.{})}),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, empty_extensions, .{}));

    // GeneralizedTime before 2050 must have used UTCTime.
    const bad_validity = try tlv(arena, 0x30, &.{
        try tlv(arena, 0x18, &.{"20260101000000Z"}),
        try tlv(arena, 0x18, &.{"20270101000000Z"}),
    });
    const bad_time_tbs = blk: {
        // Rebuild manually with the invalid validity in place.
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(arena);
        try list.append(arena, try versionTlv(arena, 2));
        try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
        try list.append(arena, try algorithmEd25519(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Issuer"));
        try list.append(arena, bad_validity);
        try list.append(arena, try nameWithCn(arena, "Synthetic Subject"));
        try list.append(arena, try spkiEd25519(arena));
        break :blk try tlv(arena, 0x30, list.items);
    };
    const bad_time_cert = try tlv(arena, 0x30, &.{
        bad_time_tbs,
        try algorithmEd25519(arena),
        try signatureBits(arena),
    });
    try testing.expectError(error.MalformedValidity, x509.Certificate.parse(testing.allocator, bad_time_cert, .{}));

    // SAN iPAddress with an invalid length.
    const bad_ip_san = try tlv(arena, 0x30, &.{try tlv(arena, 0x87, &.{&[_]u8{ 1, 2, 3, 4, 5 }})});
    const bad_ip_cert = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.subject_alt_name, false, bad_ip_san),
        }),
    });
    try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bad_ip_cert, .{}));

    // Empty RDN SET inside a name.
    const empty_rdn_name = try tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{})});
    const bad_name_tbs = blk: {
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(arena);
        try list.append(arena, try versionTlv(arena, 2));
        try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
        try list.append(arena, try algorithmEd25519(arena));
        try list.append(arena, empty_rdn_name);
        try list.append(arena, try utcValidity(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Subject"));
        try list.append(arena, try spkiEd25519(arena));
        break :blk try tlv(arena, 0x30, list.items);
    };
    const bad_name_cert = try tlv(arena, 0x30, &.{
        bad_name_tbs,
        try algorithmEd25519(arena),
        try signatureBits(arena),
    });
    try testing.expectError(error.MalformedName, x509.Certificate.parse(testing.allocator, bad_name_cert, .{}));

    // EC SPKI without curve parameters.
    const ec_alg = try tlv(arena, 0x30, &.{try oidTlv(arena, &oid.well_known.ec_public_key)});
    const key = [_]u8{0x00} ++ [_]u8{0xaa} ** 32;
    const bad_spki = try tlv(arena, 0x30, &.{ ec_alg, try tlv(arena, 0x03, &.{&key}) });
    const bad_spki_tbs = blk: {
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(arena);
        try list.append(arena, try versionTlv(arena, 2));
        try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
        try list.append(arena, try algorithmEd25519(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Issuer"));
        try list.append(arena, try utcValidity(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Subject"));
        try list.append(arena, bad_spki);
        break :blk try tlv(arena, 0x30, list.items);
    };
    const bad_spki_cert = try tlv(arena, 0x30, &.{
        bad_spki_tbs,
        try algorithmEd25519(arena),
        try signatureBits(arena),
    });
    try testing.expectError(error.MalformedPublicKeyInfo, x509.Certificate.parse(testing.allocator, bad_spki_cert, .{}));
}

test "constructed encodings of known directory-string tags fail typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // A constructed UTF8String (0x0c | 0x20) wrapping a primitive segment is
    // valid BER but not DER; the value must not be retained as unknown.
    const constructed_utf8 = try tlv(arena, 0x2c, &.{try tlv(arena, 0x0c, &.{"CN"})});
    const atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        constructed_utf8,
    });
    const bad_name = try tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{atv})});
    const bad_cert = blk: {
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(arena);
        try list.append(arena, try versionTlv(arena, 2));
        try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
        try list.append(arena, try algorithmEd25519(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Issuer"));
        try list.append(arena, try utcValidity(arena));
        try list.append(arena, bad_name);
        try list.append(arena, try spkiEd25519(arena));
        const bad_tbs = try tlv(arena, 0x30, list.items);
        break :blk try tlv(arena, 0x30, &.{
            bad_tbs,
            try algorithmEd25519(arena),
            try signatureBits(arena),
        });
    };
    try testing.expectError(error.MalformedName, x509.Certificate.parse(testing.allocator, bad_cert, .{}));

    // A genuinely unknown attribute-value tag is still retained raw, even
    // when constructed (e.g. a SEQUENCE-valued attribute).
    const seq_value = try tlv(arena, 0x30, &.{try tlv(arena, 0x0c, &.{"inner"})});
    const seq_atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        seq_value,
    });
    const seq_name = try tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{seq_atv})});
    const seq_cert = blk: {
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(arena);
        try list.append(arena, try versionTlv(arena, 2));
        try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
        try list.append(arena, try algorithmEd25519(arena));
        try list.append(arena, try nameWithCn(arena, "Synthetic Issuer"));
        try list.append(arena, try utcValidity(arena));
        try list.append(arena, seq_name);
        try list.append(arena, try spkiEd25519(arena));
        const seq_tbs = try tlv(arena, 0x30, list.items);
        break :blk try tlv(arena, 0x30, &.{
            seq_tbs,
            try algorithmEd25519(arena),
            try signatureBits(arena),
        });
    };
    var cert = try x509.Certificate.parse(testing.allocator, seq_cert, .{});
    defer cert.deinit(testing.allocator);
    try testing.expect(cert.subject.rdns[0].attributes[0].value_tag.constructed);
}

test "DistributionPoint fields must be ordered, unique, and well-formed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const uri_name = try tlv(arena, 0x86, &.{"http://crl.example.com/ca.crl"});
    const dp_name = try tlv(arena, 0xa0, &.{try tlv(arena, 0xa0, &.{uri_name})});
    const valid_reasons = try tlv(arena, 0x81, &.{&[_]u8{ 0x01, 0x40 }});
    const valid_issuer = try tlv(arena, 0xa2, &.{uri_name});

    const CaseExpectation = enum { parses, fails };
    const cases = [_]struct {
        parts: []const []const u8,
        expected: CaseExpectation,
    }{
        // All three fields in order.
        .{ .parts = &.{ dp_name, valid_reasons, valid_issuer }, .expected = .parses },
        // cRLIssuer alone satisfies the presence rule.
        .{ .parts = &.{valid_issuer}, .expected = .parses },
        // Duplicate [0].
        .{ .parts = &.{ dp_name, dp_name }, .expected = .fails },
        // Out of order: [1] before [0].
        .{ .parts = &.{ valid_reasons, dp_name }, .expected = .fails },
        // reasons alone (RFC 5280 §4.2.1.13).
        .{ .parts = &.{valid_reasons}, .expected = .fails },
        // Empty DistributionPoint.
        .{ .parts = &.{}, .expected = .fails },
    };

    for (cases) |case| {
        const point = try tlv(arena, 0x30, case.parts);
        const value = try tlv(arena, 0x30, &.{point});
        const bytes = try buildCertificate(arena, .{
            .version = try versionTlv(arena, 2),
            .extensions_wrapper = try extensionsWrapper(arena, &.{
                try extensionTlv(arena, &oid.well_known.crl_distribution_points, false, value),
            }),
        });
        const result = x509.Certificate.parse(testing.allocator, bytes, .{});
        switch (case.expected) {
            .parses => {
                var cert = try result;
                cert.deinit(testing.allocator);
            },
            .fails => try testing.expectError(error.MalformedExtension, result),
        }
    }

    // Malformed reasons payload: unused-bit count above 7.
    const bad_reasons = try tlv(arena, 0x81, &.{&[_]u8{ 0x08, 0xff }});
    // Constructed reasons field.
    const constructed_reasons = try tlv(arena, 0xa1, &.{&[_]u8{ 0x01, 0x40 }});
    // cRLIssuer containing a non-GeneralName element.
    const bad_issuer = try tlv(arena, 0xa2, &.{try tlv(arena, 0x0c, &.{"nope"})});
    // Primitive cRLIssuer field.
    const primitive_issuer = try tlv(arena, 0x82, &.{"nope"});
    // Empty cRLIssuer violates GeneralNames SIZE (1..MAX).
    const empty_issuer = try tlv(arena, 0xa2, &.{});
    // Primitive distributionPoint wrapper.
    const primitive_dp = try tlv(arena, 0x80, &.{"nope"});

    for ([_][]const []const u8{
        &.{ dp_name, bad_reasons },
        &.{ dp_name, constructed_reasons },
        &.{ dp_name, valid_reasons, bad_issuer },
        &.{ dp_name, valid_reasons, primitive_issuer },
        &.{ dp_name, valid_reasons, empty_issuer },
        &.{primitive_dp},
    }) |parts| {
        const point = try tlv(arena, 0x30, parts);
        const value = try tlv(arena, 0x30, &.{point});
        const bytes = try buildCertificate(arena, .{
            .version = try versionTlv(arena, 2),
            .extensions_wrapper = try extensionsWrapper(arena, &.{
                try extensionTlv(arena, &oid.well_known.crl_distribution_points, false, value),
            }),
        });
        try testing.expectError(error.MalformedExtension, x509.Certificate.parse(testing.allocator, bytes, .{}));
    }
}

test "directoryName SAN entries retain the Name TLV for later parsing" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const dir_name = try nameWithCn(arena, "Directory CN");
    // directoryName [4] is EXPLICIT: constructed context tag wrapping Name.
    const san_value = try tlv(arena, 0x30, &.{try tlv(arena, 0xa4, &.{dir_name})});
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &oid.well_known.subject_alt_name, false, san_value),
        }),
    });

    var cert = try x509.Certificate.parse(testing.allocator, bytes, .{});
    defer cert.deinit(testing.allocator);
    const san = cert.subjectAltName().?;
    try testing.expectEqualSlices(u8, dir_name, san[0].directory_name);

    const parsed_name = try x509.parseNameRaw(arena, san[0].directory_name, .{});
    try testing.expectEqualStrings("Directory CN", parsed_name.commonName().?);
}

test "extension count limit fails typed" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const payload = try tlv(arena, 0x04, &.{"x"});
    const other_oid = [_]u32{ 1, 3, 6, 1, 4, 1, 99999, 100 };
    const bytes = try buildCertificate(arena, .{
        .version = try versionTlv(arena, 2),
        .extensions_wrapper = try extensionsWrapper(arena, &.{
            try extensionTlv(arena, &unknown_ext_oid, false, payload),
            try extensionTlv(arena, &other_oid, false, payload),
        }),
    });
    var limits: x509.Limits = .{};
    limits.max_extensions = 1;
    try testing.expectError(error.CountLimitExceeded, x509.Certificate.parse(testing.allocator, bytes, limits));
}

test "name chaining unifies PrintableString and UTF8String with case and space folding" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // RFC 5280 §7.1: the same value in different DirectoryString encodings
    // must chain even though the encodings differ byte-for-byte.
    const utf8_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "Example CA"), .{});
    const printable_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x13, "Example CA"), .{});
    try testing.expect(utf8_name.eqlForChaining(&printable_name));
    try testing.expect(!utf8_name.eqlEncoding(&printable_name));

    // Rules (c)/(d): case-insensitive, leading/trailing white space dropped,
    // internal runs collapsed.
    const noisy_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x13, "  EXAMPLE   ca "), .{});
    try testing.expect(utf8_name.eqlForChaining(&noisy_name));

    // Different values do not chain.
    const different_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "Example CA 2"), .{});
    try testing.expect(!utf8_name.eqlForChaining(&different_name));

    // BMPString sits outside the caseIgnore class: exact bytes under its
    // own tag, so the same text does not chain with the UTF8String form.
    const bmp_text = [_]u8{ 0, 'E', 0, 'x', 0, 'a', 0, 'm', 0, 'p', 0, 'l', 0, 'e', 0, ' ', 0, 'C', 0, 'A' };
    const bmp_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x1e, &bmp_text), .{});
    try testing.expect(!utf8_name.eqlForChaining(&bmp_name));
}

test "name chaining uses RFC 4518 DirectoryString preparation" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const sharp_s = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "Straße"), .{});
    const ss = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "STRASSE"), .{});
    try testing.expect(sharp_s.eqlForChaining(&ss));
    try testing.expect(!sharp_s.eqlEncoding(&ss));

    const soft_hyphen = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "soft\u{00AD}hyphen"), .{});
    const no_hyphen = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "softhyphen"), .{});
    try testing.expect(soft_hyphen.eqlForChaining(&no_hyphen));

    const composed = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{00E9}"), .{});
    const decomposed = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "e\u{0301}"), .{});
    try testing.expect(composed.eqlForChaining(&decomposed));

    const full_width = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{FF21}\u{FF23}\u{FF2D}\u{FF25}"), .{});
    const ascii = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "ACME"), .{});
    try testing.expect(full_width.eqlForChaining(&ascii));

    const nbsp_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "Example\u{00A0}CA"), .{});
    const space_name = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "Example CA"), .{});
    try testing.expect(nbsp_name.eqlForChaining(&space_name));

    const spaced_mn = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, " \u{0301}A"), .{});
    const bare_mn = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{0301}A"), .{});
    try testing.expect(!spaced_mn.eqlForChaining(&bare_mn));

    const spaced_mc_ccc0 = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, " \u{093E}A"), .{});
    const bare_mc_ccc0 = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{093E}A"), .{});
    try testing.expect(!spaced_mc_ccc0.eqlForChaining(&bare_mc_ccc0));

    // RFC 4518 Appendix A is the definitive combining-mark table. U+05BD is
    // classified Mn by Unicode 3.2 but intentionally absent from Appendix A,
    // so a preceding U+0020 remains an insignificant leading space.
    const spaced_non_appendix_a_mark = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, " \u{05BD}A"), .{});
    const bare_non_appendix_a_mark = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{05BD}A"), .{});
    try testing.expect(spaced_non_appendix_a_mark.eqlForChaining(&bare_non_appendix_a_mark));

    const different = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "STRASZE"), .{});
    try testing.expect(!sharp_s.eqlForChaining(&different));
}

test "name chaining accepts Unicode 3.2 assigned values absent from RFC 3454 B.2" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    _ = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{10A0}"), .{});
    _ = try x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{04C0}"), .{});

    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{2D00}"), .{}),
    );
    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{04CF}"), .{}),
    );
}

test "name chaining rejects undefined RFC 4518 stored DirectoryString preparation" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{E000}"), .{}),
    );
    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{0221}"), .{}),
    );
    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{1C90}"), .{}),
    );
    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{1E900}"), .{}),
    );
    try testing.expectError(
        error.NamePreparationFailed,
        x509.parseNameRaw(arena, try nameWithCnTag(arena, 0x0c, "\u{A7B0}"), .{}),
    );
}

test "domainComponent RDN values compare with caseIgnoreIA5Match" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // RFC 5280 §7.1 / RFC 4517 §4.2.3: domainComponent (IA5String) chains
    // case-insensitively — DC=EXAMPLE,DC=COM must chain to dc=example,dc=com.
    const upper = try x509.parseNameRaw(arena, try dnWithDomainComponents(arena, &.{ "EXAMPLE", "COM" }, 0x16), .{});
    const lower = try x509.parseNameRaw(arena, try dnWithDomainComponents(arena, &.{ "example", "com" }, 0x16), .{});
    try testing.expect(upper.eqlForChaining(&lower));
    try testing.expect(!upper.eqlEncoding(&lower));

    const different = try x509.parseNameRaw(arena, try dnWithDomainComponents(arena, &.{ "example", "net" }, 0x16), .{});
    try testing.expect(!upper.eqlForChaining(&different));
}

test "isSelfIssued uses RFC 4518 name chaining, not encoding equality" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    // RFC 5280 defines self-issued via §7.1 name chaining, not encoding
    // identity. This pair depends on RFC 3454 B.2 one-to-many mapping.
    var list: std.ArrayList([]const u8) = .empty;
    defer list.deinit(arena);
    try list.append(arena, try versionTlv(arena, 2));
    try list.append(arena, try tlv(arena, 0x02, &.{&[_]u8{0x01}}));
    try list.append(arena, try algorithmEd25519(arena));
    try list.append(arena, try nameWithCnTag(arena, 0x0c, "Straße CA"));
    try list.append(arena, try utcValidity(arena));
    try list.append(arena, try nameWithCnTag(arena, 0x0c, "STRASSE CA"));
    try list.append(arena, try spkiEd25519(arena));
    const tbs = try tlv(arena, 0x30, list.items);
    const bytes = try tlv(arena, 0x30, &.{ tbs, try algorithmEd25519(arena), try signatureBits(arena) });

    var cert = try x509.Certificate.parse(testing.allocator, bytes, .{});
    defer cert.deinit(testing.allocator);
    try testing.expect(!cert.issuer.eqlEncoding(&cert.subject));
    try testing.expect(cert.issuer.eqlForChaining(&cert.subject));
    try testing.expect(cert.isSelfIssued());
}

test "name chaining keys are structure-sensitive" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const cn_atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        try tlv(arena, 0x0c, &.{"A"}),
    });
    const org_atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.organization),
        try tlv(arena, 0x0c, &.{"B"}),
    });

    // One RDN holding both attributes is distinct from two single-attribute
    // RDNs carrying the same values (the count prefixes keep the flat key
    // injective).
    const multi_attribute = try tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{ cn_atv, org_atv })});
    const multi_rdn = try tlv(arena, 0x30, &.{
        try tlv(arena, 0x31, &.{cn_atv}),
        try tlv(arena, 0x31, &.{org_atv}),
    });
    const combined = try x509.parseNameRaw(arena, multi_attribute, .{});
    const sequential = try x509.parseNameRaw(arena, multi_rdn, .{});
    try testing.expect(!combined.eqlForChaining(&sequential));

    // Same structure, same values: chains regardless of value encodings.
    const printable_cn_atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        try tlv(arena, 0x13, &.{"A"}),
    });
    const multi_attribute_printable = try tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{ printable_cn_atv, org_atv })});
    const combined_printable = try x509.parseNameRaw(arena, multi_attribute_printable, .{});
    try testing.expect(combined.eqlForChaining(&combined_printable));
}

test "name chaining key construction is leak-free across allocation failure points" {
    var fixture_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer fixture_arena.deinit();
    const fixture_allocator = fixture_arena.allocator();
    const name_der = try nameWithCnTag(fixture_allocator, 0x0c, "Straße \u{00AD} \u{FF21}\u{FF23}\u{FF2D}\u{FF25}");

    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(inner_allocator: std.mem.Allocator, der_bytes: []const u8) !void {
            var arena_inst = std.heap.ArenaAllocator.init(inner_allocator);
            defer arena_inst.deinit();
            _ = try x509.parseNameRaw(arena_inst.allocator(), der_bytes, .{});
        }
    }.run, .{name_der});
}

test "parser is leak-free across allocation failure points" {
    const allocator = testing.allocator;
    var fixture = try loadFixture(allocator, ecdsa_leaf_pem);
    defer fixture.deinit(allocator);

    try testing.checkAllAllocationFailures(allocator, struct {
        fn run(inner_allocator: std.mem.Allocator, der_bytes: []const u8) !void {
            var cert = try x509.Certificate.parse(inner_allocator, der_bytes, .{});
            cert.deinit(inner_allocator);
        }
    }.run, .{fixture.der});
}

test "fuzz entrypoint tolerates arbitrary and hostile input" {
    const allocator = testing.allocator;
    x509.fuzzParseCertificate(allocator, "");
    x509.fuzzParseCertificate(allocator, "\x30\x03\x02\x01\x01");
    x509.fuzzParseCertificate(allocator, "\x30\x82\xff\xff" ++ "\x00" ** 32);

    var fixture = try loadFixture(allocator, rsa_ca_pem);
    defer fixture.deinit(allocator);
    x509.fuzzParseCertificate(allocator, fixture.der);

    // Bit-flip corpus over a real certificate.
    var mutated = try allocator.dupe(u8, fixture.der);
    defer allocator.free(mutated);
    var index: usize = 0;
    while (index < mutated.len) : (index += 11) {
        mutated[index] ^= 0x40;
        x509.fuzzParseCertificate(allocator, mutated);
        mutated[index] ^= 0x40;
    }
}
