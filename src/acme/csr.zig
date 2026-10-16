//! Native PKCS#10 CSR generation for ACME HTTP-01 orders (#878, epic #759).
//!
//! Produces a signed `CertificationRequest` (RFC 2986) carrying a
//! `subjectAltName` extension request (RFC 2985 `extensionRequest`) that
//! covers exactly one validated ACME order group (`names.zig`). This is an
//! owned result for the A3 order engine (#882): nothing here submits an
//! order, contacts a CA, or activates a certificate.
//!
//! The leaf key is a fresh P-256 key from OS entropy, structurally the same
//! as `account.AccountKey` (same generation, wipe-on-`deinit` and PKCS#8
//! round trip), but always a distinct instance -- the ACME account key is
//! never reused as a certificate key.
//!
//! DER is assembled from the bounded TLV primitives in `pki.der`
//! (`encodeTag`/`encodeLength`) and `pki.oid`, the same primitives the PKI
//! package's own test builders use; nothing here reimplements ASN.1 length
//! or tag encoding. Subject is the empty `Name` (zero relative distinguished
//! names): HTTP-01 identity lives entirely in the SAN extension.

const std = @import("std");
const account = @import("account.zig");
const names_mod = @import("names.zig");
const pki = @import("pki");
const crypto = @import("crypto");
const zig_compat = @import("zig_compat");
const dns_name = @import("tls_core").dns_name;

const secrets = crypto.secrets;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Tag = pki.der.Tag;

pub const Error = account.Error || error{
    Empty,
    TooManyNames,
    InvalidName,
    WildcardUnsupported,
    Duplicate,
};

/// One certificate per order group (RFC 8555 S7.4); same cap as
/// `names.max_names_per_group` so a CSR can never cover more names than a
/// single order is allowed to request.
pub const max_names_per_csr = names_mod.max_names_per_group;

/// Structurally `account.AccountKey`: OS-entropy P-256 generation, scalar
/// validation, wipe on `deinit`, PKCS#8 round trip. The name documents
/// usage, not a different type -- see the module doc comment above.
pub const LeafKey = account.AccountKey;

/// Owned result of `issue`: a fresh leaf key and the CSR it signed. The
/// caller must call `deinit` exactly once.
pub const Issued = struct {
    key: LeafKey,
    /// DER-encoded PKCS#10 `CertificationRequest`.
    csr_der: []u8,

    pub fn deinit(self: *Issued, allocator: std.mem.Allocator) void {
        self.key.deinit();
        allocator.free(self.csr_der);
    }
};

/// Generate a distinct leaf key and a signed CSR whose SAN covers exactly
/// `order_group`. Re-validates syntax, duplicates and the per-group cap
/// itself (does not trust the caller already ran `names.validate`), so this
/// fails closed even when called directly.
pub fn issue(allocator: std.mem.Allocator, order_group: []const []const u8) Error!Issued {
    try validateGroup(order_group);

    var key = try LeafKey.generate();
    errdefer key.deinit();

    const csr_der = try buildCsr(allocator, &key, order_group);
    return .{ .key = key, .csr_der = csr_der };
}

fn validateGroup(order_group: []const []const u8) Error!void {
    if (order_group.len == 0) return error.Empty;
    if (order_group.len > max_names_per_csr) return error.TooManyNames;
    for (order_group, 0..) |name, i| {
        if (std.mem.indexOfScalar(u8, name, '*') != null) return error.WildcardUnsupported;
        dns_name.validateHostName(name) catch return error.InvalidName;
        for (order_group[0..i]) |earlier| {
            if (std.mem.eql(u8, earlier, name)) return error.Duplicate;
        }
    }
}

// ---------------------------------------------------------------------------
// DER assembly
// ---------------------------------------------------------------------------

const extension_request_oid = [_]u32{ 1, 2, 840, 113549, 1, 9, 14 };

const SEQUENCE = Tag.universal(16, true);
const SET = Tag.universal(17, true);
const INTEGER = Tag.universal(2, false);
const BIT_STRING = Tag.universal(3, false);
const OCTET_STRING = Tag.universal(4, false);
const OBJECT_IDENTIFIER = Tag.universal(6, false);

/// Append one TLV: a fixed-size stack buffer is always sufficient for the
/// tag/length shapes produced here (small universal/context tag numbers,
/// content well under 64 KiB), so the encode calls cannot fail in practice;
/// `unreachable` documents that rather than threading a dead error path.
fn tlv(allocator: std.mem.Allocator, list: *std.ArrayList(u8), tag: Tag, content: []const u8) Error!void {
    var tag_buf: [2]u8 = undefined;
    const tag_len = pki.der.encodeTag(tag, &tag_buf) catch unreachable;
    var len_buf: [4]u8 = undefined;
    const len_len = pki.der.encodeLength(content.len, &len_buf) catch unreachable;
    try list.ensureUnusedCapacity(allocator, tag_len + len_len + content.len);
    list.appendSliceAssumeCapacity(tag_buf[0..tag_len]);
    list.appendSliceAssumeCapacity(len_buf[0..len_len]);
    list.appendSliceAssumeCapacity(content);
}

/// DER content bytes of an OBJECT IDENTIFIER with hardcoded well-known
/// components; `buf` is always large enough for the OIDs used here.
fn oidContent(buf: *[16]u8, components: []const u32) []const u8 {
    const n = pki.oid.encodeComponents(components, buf) catch unreachable;
    return buf[0..n];
}

fn signDer(key: *const LeafKey, message: []const u8, out: *[Ecdsa.Signature.der_encoded_length_max]u8) Error![]u8 {
    var noise: [Ecdsa.noise_length]u8 = undefined;
    defer secrets.secureZero(&noise);
    zig_compat.randomBytes(&noise);
    const sig = key.key.key_pair.sign(message, noise) catch return error.SignFailed;
    return sig.toDer(out);
}

fn buildSubjectPublicKeyInfo(allocator: std.mem.Allocator, key: *const LeafKey) Error![]u8 {
    var alg: std.ArrayList(u8) = .empty;
    defer alg.deinit(allocator);
    var ec_oid_buf: [16]u8 = undefined;
    try tlv(allocator, &alg, OBJECT_IDENTIFIER, oidContent(&ec_oid_buf, &pki.oid.well_known.ec_public_key));
    var curve_oid_buf: [16]u8 = undefined;
    try tlv(allocator, &alg, OBJECT_IDENTIFIER, oidContent(&curve_oid_buf, &pki.oid.well_known.secp256r1));
    var alg_seq: std.ArrayList(u8) = .empty;
    defer alg_seq.deinit(allocator);
    try tlv(allocator, &alg_seq, SEQUENCE, alg.items);

    const sec1 = key.key.key_pair.public_key.toUncompressedSec1();
    var pub_bits: [1 + sec1.len]u8 = undefined;
    pub_bits[0] = 0; // no unused bits
    @memcpy(pub_bits[1..], &sec1);
    var pub_tlv: std.ArrayList(u8) = .empty;
    defer pub_tlv.deinit(allocator);
    try tlv(allocator, &pub_tlv, BIT_STRING, &pub_bits);

    var spki: std.ArrayList(u8) = .empty;
    defer spki.deinit(allocator);
    try spki.appendSlice(allocator, alg_seq.items);
    try spki.appendSlice(allocator, pub_tlv.items);

    var spki_seq: std.ArrayList(u8) = .empty;
    try tlv(allocator, &spki_seq, SEQUENCE, spki.items);
    return spki_seq.toOwnedSlice(allocator);
}

/// `[0] IMPLICIT SET OF Attribute` holding exactly one `extensionRequest`
/// attribute whose value is a `subjectAltName` extension covering every name
/// in `order_group` (already validated by the caller).
fn buildAttributes(allocator: std.mem.Allocator, order_group: []const []const u8) Error![]u8 {
    var san_names: std.ArrayList(u8) = .empty;
    defer san_names.deinit(allocator);
    for (order_group) |name| {
        // dNSName [2] IMPLICIT IA5String: no further tag wrapping.
        try tlv(allocator, &san_names, Tag.contextSpecific(2, false), name);
    }
    var san_general_names: std.ArrayList(u8) = .empty;
    defer san_general_names.deinit(allocator);
    try tlv(allocator, &san_general_names, SEQUENCE, san_names.items);

    var san_ext: std.ArrayList(u8) = .empty;
    defer san_ext.deinit(allocator);
    var san_oid_buf: [16]u8 = undefined;
    try tlv(allocator, &san_ext, OBJECT_IDENTIFIER, oidContent(&san_oid_buf, &pki.oid.well_known.subject_alt_name));
    // `critical` is DEFAULT FALSE and omitted in canonical DER.
    try tlv(allocator, &san_ext, OCTET_STRING, san_general_names.items);
    var san_ext_seq: std.ArrayList(u8) = .empty;
    defer san_ext_seq.deinit(allocator);
    try tlv(allocator, &san_ext_seq, SEQUENCE, san_ext.items);

    // `Extensions ::= SEQUENCE OF Extension`; exactly one entry here.
    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(allocator);
    try tlv(allocator, &extensions, SEQUENCE, san_ext_seq.items);

    var ext_req_attr: std.ArrayList(u8) = .empty;
    defer ext_req_attr.deinit(allocator);
    var ext_req_oid_buf: [16]u8 = undefined;
    try tlv(allocator, &ext_req_attr, OBJECT_IDENTIFIER, oidContent(&ext_req_oid_buf, &extension_request_oid));
    var ext_req_values: std.ArrayList(u8) = .empty;
    defer ext_req_values.deinit(allocator);
    try tlv(allocator, &ext_req_values, SET, extensions.items);
    try ext_req_attr.appendSlice(allocator, ext_req_values.items);

    var attribute: std.ArrayList(u8) = .empty;
    defer attribute.deinit(allocator);
    try tlv(allocator, &attribute, SEQUENCE, ext_req_attr.items);

    var attributes: std.ArrayList(u8) = .empty;
    try tlv(allocator, &attributes, Tag.contextSpecific(0, true), attribute.items);
    return attributes.toOwnedSlice(allocator);
}

fn buildCertificationRequestInfo(allocator: std.mem.Allocator, key: *const LeafKey, order_group: []const []const u8) Error![]u8 {
    const spki = try buildSubjectPublicKeyInfo(allocator, key);
    defer allocator.free(spki);
    const attributes = try buildAttributes(allocator, order_group);
    defer allocator.free(attributes);

    var version: std.ArrayList(u8) = .empty;
    defer version.deinit(allocator);
    try tlv(allocator, &version, INTEGER, &[_]u8{0});

    var subject: std.ArrayList(u8) = .empty;
    defer subject.deinit(allocator);
    // Empty `Name` (RDNSequence of zero elements): identity lives in SAN.
    try tlv(allocator, &subject, SEQUENCE, &.{});

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, version.items);
    try body.appendSlice(allocator, subject.items);
    try body.appendSlice(allocator, spki);
    try body.appendSlice(allocator, attributes);

    var tbs: std.ArrayList(u8) = .empty;
    try tlv(allocator, &tbs, SEQUENCE, body.items);
    return tbs.toOwnedSlice(allocator);
}

fn buildCsr(allocator: std.mem.Allocator, key: *const LeafKey, order_group: []const []const u8) Error![]u8 {
    const tbs = try buildCertificationRequestInfo(allocator, key, order_group);
    defer allocator.free(tbs);

    var sig_der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = try signDer(key, tbs, &sig_der_buf);

    var sig_alg: std.ArrayList(u8) = .empty;
    defer sig_alg.deinit(allocator);
    var sig_oid_buf: [16]u8 = undefined;
    try tlv(allocator, &sig_alg, OBJECT_IDENTIFIER, oidContent(&sig_oid_buf, &pki.oid.well_known.ecdsa_with_sha256));
    var sig_alg_seq: std.ArrayList(u8) = .empty;
    defer sig_alg_seq.deinit(allocator);
    try tlv(allocator, &sig_alg_seq, SEQUENCE, sig_alg.items);

    var sig_bits: [1 + Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    sig_bits[0] = 0; // no unused bits
    @memcpy(sig_bits[1 .. 1 + sig_der.len], sig_der);
    var sig_tlv: std.ArrayList(u8) = .empty;
    defer sig_tlv.deinit(allocator);
    try tlv(allocator, &sig_tlv, BIT_STRING, sig_bits[0 .. 1 + sig_der.len]);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, tbs);
    try body.appendSlice(allocator, sig_alg_seq.items);
    try body.appendSlice(allocator, sig_tlv.items);

    var csr: std.ArrayList(u8) = .empty;
    try tlv(allocator, &csr, SEQUENCE, body.items);
    return csr.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------

const testing = std.testing;

/// Independent-of-the-writer parse: walks the DER with `pki.der.Reader`
/// (the same reader x509 parsing uses) rather than re-deriving byte offsets
/// from the builder above.
const ParsedCsr = struct {
    spki_sec1: [65]u8,
    san: std.ArrayList([]const u8),
    tbs_raw: []const u8,
    sig_alg: pki.oid.ObjectIdentifier,
    signature: Ecdsa.Signature,

    fn deinit(self: *ParsedCsr, allocator: std.mem.Allocator) void {
        self.san.deinit(allocator);
    }
};

fn parseCsr(allocator: std.mem.Allocator, der: []const u8) !ParsedCsr {
    var top = pki.der.Reader.init(der, pki.der.default_limits);
    var csr = try top.readSequence();
    try top.expectEnd();

    const tbs_elem = try csr.readElement();
    try testing.expect(tbs_elem.tag.eql(SEQUENCE));
    const tbs_raw = tbs_elem.encoded;
    var tbs_top = pki.der.Reader.init(tbs_elem.encoded, pki.der.default_limits);
    var tbs = try tbs_top.readSequence();

    const version = try tbs.readInteger();
    try testing.expectEqualSlices(u8, &[_]u8{0}, version.content);

    var subject = try tbs.readSequence();
    try subject.expectEnd();

    var spki_reader = try tbs.readSequence();
    var alg = try spki_reader.readSequence();
    const ec_oid = try alg.readObjectIdentifier();
    try testing.expect(ec_oid.eqlComponents(&pki.oid.well_known.ec_public_key));
    const curve_oid = try alg.readObjectIdentifier();
    try testing.expect(curve_oid.eqlComponents(&pki.oid.well_known.secp256r1));
    try alg.expectEnd();
    const pub_bits = try spki_reader.readBitString();
    try spki_reader.expectEnd();
    var spki_sec1: [65]u8 = undefined;
    try testing.expectEqual(@as(usize, 65), pub_bits.data.len);
    @memcpy(&spki_sec1, pub_bits.data);

    const attrs_elem = try tbs.readContextSpecific(0, true);
    var attrs = try tbs.childReader(attrs_elem.content_offset, attrs_elem.content.len);
    try tbs.expectEnd();

    var attribute = try attrs.readSequence();
    try attrs.expectEnd();
    const attr_oid = try attribute.readObjectIdentifier();
    try testing.expect(attr_oid.eqlComponents(&extension_request_oid));
    var values = try attribute.readSet();
    try attribute.expectEnd();
    var extensions = try values.readSequence();
    try values.expectEnd();
    var extension = try extensions.readSequence();
    try extensions.expectEnd();
    const ext_oid = try extension.readObjectIdentifier();
    try testing.expect(ext_oid.eqlComponents(&pki.oid.well_known.subject_alt_name));
    const ext_value = try extension.readOctetString();
    try extension.expectEnd();

    var san: std.ArrayList([]const u8) = .empty;
    var general_names_top = pki.der.Reader.init(ext_value, pki.der.default_limits);
    var general_names = try general_names_top.readSequence();
    while (general_names.remaining() > 0) {
        const name_elem = try general_names.readContextSpecific(2, false);
        try san.append(allocator, name_elem.content);
    }

    const sig_alg_elem = try csr.readSequence();
    var sig_alg_reader = sig_alg_elem;
    const sig_alg_oid = try sig_alg_reader.readObjectIdentifier();
    try sig_alg_reader.expectEnd();

    const sig_bits = try csr.readBitString();
    try csr.expectEnd();
    try testing.expectEqual(@as(u3, 0), sig_bits.unused_bits);
    const signature = try Ecdsa.Signature.fromDer(sig_bits.data);

    return .{
        .spki_sec1 = spki_sec1,
        .san = san,
        .tbs_raw = tbs_raw,
        .sig_alg = sig_alg_oid,
        .signature = signature,
    };
}

test "ACME CSR: native CSR parses, SAN matches, and the signature verifies" {
    const order_group = [_][]const u8{ "a.example.com", "b.example.com" };
    var result = try issue(testing.allocator, &order_group);
    defer result.deinit(testing.allocator);

    var parsed = try parseCsr(testing.allocator, result.csr_der);
    defer parsed.deinit(testing.allocator);

    try testing.expect(parsed.sig_alg.eqlComponents(&pki.oid.well_known.ecdsa_with_sha256));

    try testing.expectEqual(@as(usize, 2), parsed.san.items.len);
    try testing.expectEqualStrings("a.example.com", parsed.san.items[0]);
    try testing.expectEqualStrings("b.example.com", parsed.san.items[1]);

    const expected_sec1 = result.key.key.key_pair.public_key.toUncompressedSec1();
    try testing.expectEqualSlices(u8, &expected_sec1, &parsed.spki_sec1);

    const public_key = try Ecdsa.PublicKey.fromSec1(&parsed.spki_sec1);
    try parsed.signature.verify(parsed.tbs_raw, public_key);
}

test "ACME CSR: each call issues a distinct leaf key" {
    const order_group = [_][]const u8{"example.com"};
    var a = try issue(testing.allocator, &order_group);
    defer a.deinit(testing.allocator);
    var b = try issue(testing.allocator, &order_group);
    defer b.deinit(testing.allocator);
    try testing.expect(!std.mem.eql(u8, &a.key.jwk().x, &b.key.jwk().x) or !std.mem.eql(u8, &a.key.jwk().y, &b.key.jwk().y));
}

test "ACME CSR: rejects invalid, wildcard, duplicate and oversized groups" {
    try testing.expectError(error.Empty, issue(testing.allocator, &[_][]const u8{}));
    try testing.expectError(error.WildcardUnsupported, issue(testing.allocator, &[_][]const u8{"*.example.com"}));
    try testing.expectError(error.InvalidName, issue(testing.allocator, &[_][]const u8{"exa mple.com"}));
    try testing.expectError(error.Duplicate, issue(testing.allocator, &[_][]const u8{ "a.example.com", "a.example.com" }));

    var too_many: [max_names_per_csr + 1][]const u8 = undefined;
    var buf: [(max_names_per_csr + 1) * 32]u8 = undefined;
    var len: usize = 0;
    for (0..too_many.len) |i| {
        const name = std.fmt.bufPrint(buf[len..], "h{d}.example.com", .{i}) catch unreachable;
        too_many[i] = name;
        len += name.len;
    }
    try testing.expectError(error.TooManyNames, issue(testing.allocator, &too_many));
}

test "ACME CSR: boundary-sized name at the DNS length cap round-trips" {
    // Three max-length (63-byte) labels, a 61-byte label, and three dots:
    // 63*3 + 61 + 3 == 253 == `dns_name.max_name_len`.
    var boundary_buf: [253]u8 = undefined;
    @memset(boundary_buf[0..63], 'a');
    boundary_buf[63] = '.';
    @memset(boundary_buf[64..127], 'a');
    boundary_buf[127] = '.';
    @memset(boundary_buf[128..191], 'a');
    boundary_buf[191] = '.';
    @memset(boundary_buf[192..253], 'a');
    const boundary_name = &boundary_buf;
    try testing.expectEqual(@as(usize, 253), boundary_name.len);
    const order_group = [_][]const u8{boundary_name};
    var result = try issue(testing.allocator, &order_group);
    defer result.deinit(testing.allocator);

    var parsed = try parseCsr(testing.allocator, result.csr_der);
    defer parsed.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), parsed.san.items.len);
    try testing.expectEqualStrings(boundary_name, parsed.san.items[0]);
}

fn fuzzIssue(_: void, smith: *testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    var name_storage: [max_names_per_csr][]const u8 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, buf[0..len], ',');
    while (it.next()) |name| {
        if (count >= name_storage.len) break;
        name_storage[count] = name;
        count += 1;
    }
    var result = issue(testing.allocator, name_storage[0..count]) catch return;
    defer result.deinit(testing.allocator);
}

test "fuzz: ACME: CSR issuance is bounded for arbitrary name lists" {
    try testing.fuzz({}, fuzzIssue, .{ .corpus = &.{
        "",
        "example.com",
        "a.example.com,b.example.com",
        "*.example.com",
        "a.example.com,a.example.com",
    } });
}
