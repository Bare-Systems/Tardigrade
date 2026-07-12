//! Typed, policy-neutral X.509 certificate model (#341).
//!
//! Parses a DER certificate into the fields needed for identity matching,
//! signature verification, path building, and RFC 5280 validation
//! (#324-D through #324-G). Parsing enforces structure and DER
//! well-formedness only; trust decisions (expiry, key usage acceptance,
//! path rules) belong to validation policy layered on top.
//!
//! ## Ownership
//!
//! `Certificate.parse` borrows the caller's DER buffer — every `[]const u8`
//! and `Name`/`Extension` view points into it, so the buffer must outlive
//! the certificate (pair with `pem.Certificate.der`, which is owned).
//! Variable-length collections (RDNs, extensions, SAN entries, ...) are
//! allocated from an internal arena; one `deinit(allocator)` with the same
//! allocator releases everything. Parsed objects are immutable views.
//!
//! ## Structural strictness
//!
//! DER defaults must be omitted (explicit v1 version, `critical FALSE`,
//! `cA FALSE` are rejected), inner and outer signature algorithms must have
//! identical encodings (RFC 5280 §4.1.2.3), extensions require v3 and
//! unique identifiers v2/v3, duplicate extension OIDs are rejected, and
//! every nested structure must consume its input exactly.
//!
//! ## Unknown extensions
//!
//! Unrecognized extensions are retained with their OID, criticality, and
//! raw value. `hasUnhandledCriticalExtension` surfaces unknown critical
//! extensions so validation can fail closed (RFC 5280 §4.2).

const std = @import("std");
const der = @import("der.zig");
const oid_mod = @import("oid.zig");
const time_mod = @import("time.zig");

const wk = oid_mod.well_known;

/// Configurable parser resource bounds, applied on top of `der.Limits`.
pub const Limits = struct {
    der: der.Limits = .{},
    max_extensions: usize = 64,
    max_name_rdns: usize = 32,
    max_name_attributes: usize = 8,
    max_general_names: usize = 64,
    max_eku_purposes: usize = 32,
    max_policies: usize = 32,
    max_distribution_points: usize = 16,
    max_access_descriptions: usize = 16,
    max_name_constraint_subtrees: usize = 64,
};

pub const default_limits: Limits = .{};

pub const Error = error{
    MalformedCertificate,
    UnsupportedVersion,
    MalformedSerialNumber,
    MalformedAlgorithm,
    SignatureAlgorithmMismatch,
    MalformedName,
    MalformedValidity,
    MalformedPublicKeyInfo,
    MalformedUniqueId,
    MalformedSignature,
    MalformedExtension,
    DuplicateExtension,
    CountLimitExceeded,
    OutOfMemory,
};

pub const Version = enum(u8) {
    v1 = 0,
    v2 = 1,
    v3 = 2,
};

/// AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
pub const AlgorithmIdentifier = struct {
    /// Full TLV bytes of the SEQUENCE, for byte-exact comparison.
    raw: []const u8,
    oid: oid_mod.ObjectIdentifier,
    /// Full TLV bytes of the parameters element when present.
    parameters_raw: ?[]const u8,
    /// True when parameters are an explicit ASN.1 NULL.
    parameters_null: bool,

    pub fn eqlEncoding(self: *const AlgorithmIdentifier, other: *const AlgorithmIdentifier) bool {
        return std.mem.eql(u8, self.raw, other.raw);
    }
};

/// Identification of well-known signature algorithms. `unrecognized` is a
/// statement about this parser's tables, not a rejection — policy decides
/// what to accept.
pub const SignatureAlgorithm = enum {
    rsa_pkcs1_sha256,
    rsa_pkcs1_sha384,
    rsa_pkcs1_sha512,
    rsa_pss,
    ecdsa_sha256,
    ecdsa_sha384,
    ecdsa_sha512,
    ed25519,
    unrecognized,

    pub fn classify(algorithm: *const AlgorithmIdentifier) SignatureAlgorithm {
        const o = &algorithm.oid;
        if (o.eqlComponents(&wk.sha256_with_rsa)) return .rsa_pkcs1_sha256;
        if (o.eqlComponents(&wk.sha384_with_rsa)) return .rsa_pkcs1_sha384;
        if (o.eqlComponents(&wk.sha512_with_rsa)) return .rsa_pkcs1_sha512;
        if (o.eqlComponents(&wk.rsa_pss)) return .rsa_pss;
        if (o.eqlComponents(&wk.ecdsa_with_sha256)) return .ecdsa_sha256;
        if (o.eqlComponents(&wk.ecdsa_with_sha384)) return .ecdsa_sha384;
        if (o.eqlComponents(&wk.ecdsa_with_sha512)) return .ecdsa_sha512;
        if (o.eqlComponents(&wk.ed25519)) return .ed25519;
        return .unrecognized;
    }
};

/// Identification of well-known SPKI key types.
pub const PublicKeyType = enum {
    rsa,
    ecdsa_p256,
    ecdsa_p384,
    ecdsa_p521,
    ed25519,
    unrecognized,
};

pub const AttributeTypeAndValue = struct {
    type: oid_mod.ObjectIdentifier,
    /// Tag of the attribute value (ANY — commonly a directory string type).
    value_tag: der.Tag,
    /// Content bytes of the attribute value. Validated when the tag is a
    /// known string type; otherwise raw.
    value: []const u8,
};

pub const RelativeDistinguishedName = struct {
    attributes: []const AttributeTypeAndValue,
};

/// Name ::= RDNSequence. Comparison across certificates is byte-exact on
/// `raw` (RFC 5280 binary comparison); looser matching rules are policy.
pub const Name = struct {
    /// Full TLV bytes of the Name SEQUENCE.
    raw: []const u8,
    rdns: []const RelativeDistinguishedName,

    pub fn eqlEncoding(self: *const Name, other: *const Name) bool {
        return std.mem.eql(u8, self.raw, other.raw);
    }

    pub fn isEmpty(self: *const Name) bool {
        return self.rdns.len == 0;
    }

    /// First attribute value with the given type OID, in RDN order.
    pub fn findAttribute(self: *const Name, type_components: []const u32) ?*const AttributeTypeAndValue {
        for (self.rdns) |rdn| {
            for (rdn.attributes) |*attribute| {
                if (attribute.type.eqlComponents(type_components)) return attribute;
            }
        }
        return null;
    }

    pub fn commonName(self: *const Name) ?[]const u8 {
        const attribute = self.findAttribute(&wk.common_name) orelse return null;
        return attribute.value;
    }
};

pub const TimeEncoding = enum { utc, generalized };

/// A validity time in a single representation regardless of source
/// encoding (UTCTime through 2049, GeneralizedTime from 2050; RFC 5280).
pub const Time = struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    encoding: TimeEncoding,

    pub fn order(self: Time, other: Time) std.math.Order {
        inline for (.{ "year", "month", "day", "hour", "minute", "second" }) |field| {
            const ord = std.math.order(@field(self, field), @field(other, field));
            if (ord != .eq) return ord;
        }
        return .eq;
    }
};

pub const Validity = struct {
    not_before: Time,
    not_after: Time,
};

pub const SubjectPublicKeyInfo = struct {
    /// Full TLV bytes of the SPKI SEQUENCE (input to key identifiers and
    /// SPKI pinning).
    raw: []const u8,
    algorithm: AlgorithmIdentifier,
    subject_public_key: der.BitStringView,
    key_type: PublicKeyType,
    /// Named-curve OID for `ecdsa_*` key types.
    named_curve: ?oid_mod.ObjectIdentifier,
};

/// GeneralName (RFC 5280 §4.2.1.6). Constructed alternatives that later
/// stories do not consume as structure (otherName, x400Address,
/// ediPartyName) are retained raw. `directory_name` keeps the Name TLV
/// bytes; parse with `parseNameRaw` when structure is needed.
pub const GeneralName = union(enum) {
    /// [1] IA5String
    rfc822_name: []const u8,
    /// [2] IA5String
    dns_name: []const u8,
    /// [4] Name (full TLV bytes)
    directory_name: []const u8,
    /// [6] IA5String
    uniform_resource_identifier: []const u8,
    /// [7] OCTET STRING: 4/16 bytes in SAN, address+mask 8/32 bytes in
    /// name constraints.
    ip_address: []const u8,
    /// [8] OBJECT IDENTIFIER
    registered_id: oid_mod.ObjectIdentifier,
    /// [0], [3], [5]: full TLV bytes, tag number preserved.
    other: struct {
        tag_number: u32,
        raw: []const u8,
    },
};

pub const BasicConstraints = struct {
    is_ca: bool,
    /// Present only when the certificate asserts a path length constraint.
    max_path_len: ?u32,
};

/// KeyUsage named bits (RFC 5280 §4.2.1.3).
pub const KeyUsage = struct {
    digital_signature: bool = false,
    non_repudiation: bool = false,
    key_encipherment: bool = false,
    data_encipherment: bool = false,
    key_agreement: bool = false,
    key_cert_sign: bool = false,
    crl_sign: bool = false,
    encipher_only: bool = false,
    decipher_only: bool = false,
};

pub const ExtendedKeyUsage = struct {
    purposes: []const oid_mod.ObjectIdentifier,

    pub fn contains(self: *const ExtendedKeyUsage, components: []const u32) bool {
        for (self.purposes) |*purpose| {
            if (purpose.eqlComponents(components)) return true;
        }
        return false;
    }

    pub fn allowsServerAuth(self: *const ExtendedKeyUsage) bool {
        return self.contains(&wk.server_auth) or self.contains(&wk.any_ext_key_usage);
    }

    pub fn allowsClientAuth(self: *const ExtendedKeyUsage) bool {
        return self.contains(&wk.client_auth) or self.contains(&wk.any_ext_key_usage);
    }
};

pub const AuthorityKeyIdentifier = struct {
    key_identifier: ?[]const u8,
    /// [1] GeneralNames, retained raw (full TLV) when present.
    authority_cert_issuer_raw: ?[]const u8,
    /// [2] certificate serial content bytes when present.
    authority_cert_serial: ?[]const u8,
};

pub const GeneralSubtree = struct {
    base: GeneralName,
};

pub const NameConstraints = struct {
    permitted: []const GeneralSubtree,
    excluded: []const GeneralSubtree,
};

pub const AccessDescription = struct {
    method: oid_mod.ObjectIdentifier,
    location: GeneralName,
};

pub const DistributionPoint = struct {
    /// Full TLV bytes of the DistributionPoint SEQUENCE.
    raw: []const u8,
    /// GeneralNames from a [0] fullName choice; empty for the
    /// nameRelativeToCRLIssuer alternative or an absent distributionPoint.
    full_names: []const GeneralName,
};

pub const PolicyInformation = struct {
    policy: oid_mod.ObjectIdentifier,
    /// Full TLV bytes of the policyQualifiers SEQUENCE when present.
    qualifiers_raw: ?[]const u8,
};

pub const Extension = struct {
    oid: oid_mod.ObjectIdentifier,
    critical: bool,
    /// extnValue OCTET STRING content — the extension's own DER.
    value: []const u8,
    parsed: Parsed,

    pub const Parsed = union(enum) {
        basic_constraints: BasicConstraints,
        key_usage: KeyUsage,
        subject_alt_name: []const GeneralName,
        extended_key_usage: ExtendedKeyUsage,
        subject_key_identifier: []const u8,
        authority_key_identifier: AuthorityKeyIdentifier,
        name_constraints: NameConstraints,
        authority_info_access: []const AccessDescription,
        crl_distribution_points: []const DistributionPoint,
        certificate_policies: []const PolicyInformation,
        unrecognized: void,
    };
};

pub const Certificate = struct {
    /// Full certificate DER (borrowed).
    raw: []const u8,
    /// Exact TBSCertificate TLV bytes — the input to signature verification.
    tbs_raw: []const u8,
    version: Version,
    /// Serial content bytes: validated minimal two's-complement encoding.
    serial_number: der.IntegerView,
    /// Outer signatureAlgorithm. Guaranteed encoding-identical to the inner
    /// TBS `signature` field.
    signature_algorithm: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    issuer_unique_id: ?der.BitStringView,
    subject_unique_id: ?der.BitStringView,
    extensions: []const Extension,
    signature_value: der.BitStringView,

    arena_state: std.heap.ArenaAllocator.State,

    /// Parse one DER certificate. `der_bytes` is borrowed and must outlive
    /// the returned value; internal collections are arena-owned and freed
    /// by `deinit` with the same `allocator`.
    pub fn parse(allocator: std.mem.Allocator, der_bytes: []const u8, limits: Limits) Error!Certificate {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var parser = Parser{
            .arena = arena.allocator(),
            .limits = limits,
        };
        var certificate = try parser.parseCertificate(der_bytes);
        certificate.arena_state = arena.state;
        return certificate;
    }

    pub fn deinit(self: *Certificate, allocator: std.mem.Allocator) void {
        self.arena_state.promote(allocator).deinit();
        self.* = undefined;
    }

    pub fn signatureAlgorithm(self: *const Certificate) SignatureAlgorithm {
        return SignatureAlgorithm.classify(&self.signature_algorithm);
    }

    pub fn isSelfIssued(self: *const Certificate) bool {
        return self.issuer.eqlEncoding(&self.subject);
    }

    pub fn findExtension(self: *const Certificate, components: []const u32) ?*const Extension {
        for (self.extensions) |*extension| {
            if (extension.oid.eqlComponents(components)) return extension;
        }
        return null;
    }

    /// True when any critical extension was not parsed into a typed
    /// representation. RFC 5280 §4.2 requires rejecting such certificates;
    /// the rejection itself is validation policy.
    pub fn hasUnhandledCriticalExtension(self: *const Certificate) bool {
        for (self.extensions) |*extension| {
            if (extension.critical and extension.parsed == .unrecognized) return true;
        }
        return false;
    }

    pub fn basicConstraints(self: *const Certificate) ?BasicConstraints {
        const extension = self.findExtension(&wk.basic_constraints) orelse return null;
        return extension.parsed.basic_constraints;
    }

    pub fn keyUsage(self: *const Certificate) ?KeyUsage {
        const extension = self.findExtension(&wk.key_usage) orelse return null;
        return extension.parsed.key_usage;
    }

    pub fn subjectAltName(self: *const Certificate) ?[]const GeneralName {
        const extension = self.findExtension(&wk.subject_alt_name) orelse return null;
        return extension.parsed.subject_alt_name;
    }

    pub fn extendedKeyUsage(self: *const Certificate) ?ExtendedKeyUsage {
        const extension = self.findExtension(&wk.ext_key_usage) orelse return null;
        return extension.parsed.extended_key_usage;
    }

    pub fn subjectKeyIdentifier(self: *const Certificate) ?[]const u8 {
        const extension = self.findExtension(&wk.subject_key_identifier) orelse return null;
        return extension.parsed.subject_key_identifier;
    }

    pub fn authorityKeyIdentifier(self: *const Certificate) ?AuthorityKeyIdentifier {
        const extension = self.findExtension(&wk.authority_key_identifier) orelse return null;
        return extension.parsed.authority_key_identifier;
    }

    pub fn nameConstraints(self: *const Certificate) ?NameConstraints {
        const extension = self.findExtension(&wk.name_constraints) orelse return null;
        return extension.parsed.name_constraints;
    }
};

/// Parse a raw Name TLV (as retained by `GeneralName.directory_name`) into
/// structured RDNs. Collections are allocated directly from `arena` and are
/// not individually freed — pass an arena allocator.
pub fn parseNameRaw(arena: std.mem.Allocator, name_tlv: []const u8, limits: Limits) Error!Name {
    var reader = der.Reader.init(name_tlv, limits.der);
    var parser = Parser{ .arena = arena, .limits = limits };
    const name = try parser.parseName(&reader);
    reader.expectEnd() catch return error.MalformedName;
    return name;
}

const Parser = struct {
    arena: std.mem.Allocator,
    limits: Limits,

    fn parseCertificate(self: *Parser, der_bytes: []const u8) Error!Certificate {
        var reader = der.Reader.init(der_bytes, self.limits.der);

        const cert_elem = reader.readElement() catch return error.MalformedCertificate;
        try expectSequence(cert_elem);
        reader.expectEnd() catch return error.MalformedCertificate;

        var outer = reader.childReader(cert_elem.content_offset, cert_elem.content.len) catch return error.MalformedCertificate;

        const tbs_elem = outer.readElement() catch return error.MalformedCertificate;
        try expectSequence(tbs_elem);

        const signature_algorithm = try self.parseAlgorithmIdentifier(&outer, error.MalformedAlgorithm);

        const signature_value = outer.readBitString() catch return error.MalformedSignature;
        outer.expectEnd() catch return error.MalformedCertificate;

        var tbs = outer.childReader(tbs_elem.content_offset, tbs_elem.content.len) catch return error.MalformedCertificate;

        const version = try self.parseVersion(&tbs);

        const serial_number = tbs.readInteger() catch return error.MalformedSerialNumber;

        const tbs_signature_algorithm = try self.parseAlgorithmIdentifier(&tbs, error.MalformedAlgorithm);
        // RFC 5280 §4.1.2.3: the TBS signature field must carry the same
        // algorithm as the outer signatureAlgorithm. Encoding-exact
        // comparison keeps this policy-free.
        if (!signature_algorithm.eqlEncoding(&tbs_signature_algorithm)) {
            return error.SignatureAlgorithmMismatch;
        }

        const issuer = try self.parseName(&tbs);
        const validity = try self.parseValidity(&tbs);
        const subject = try self.parseName(&tbs);
        const spki = try self.parseSubjectPublicKeyInfo(&tbs);

        var issuer_unique_id: ?der.BitStringView = null;
        var subject_unique_id: ?der.BitStringView = null;
        var extensions: []const Extension = &.{};

        // Optional trailing fields: [1] issuerUniqueID, [2] subjectUniqueID
        // (v2/v3 only), [3] extensions (v3 only), in ascending tag order.
        var last_context_tag: u32 = 0;
        while (tbs.remaining() > 0) {
            const elem = tbs.readElement() catch return error.MalformedCertificate;
            if (elem.tag.class != .context_specific) return error.MalformedCertificate;
            if (elem.tag.number <= last_context_tag) return error.MalformedCertificate;
            last_context_tag = elem.tag.number;
            switch (elem.tag.number) {
                1, 2 => {
                    if (version == .v1) return error.UnsupportedVersion;
                    // IMPLICIT BIT STRING: primitive context tag.
                    if (elem.tag.constructed) return error.MalformedUniqueId;
                    const view = der.decodeBitStringContent(elem.content) catch return error.MalformedUniqueId;
                    if (elem.tag.number == 1) issuer_unique_id = view else subject_unique_id = view;
                },
                3 => {
                    if (version != .v3) return error.UnsupportedVersion;
                    if (!elem.tag.constructed) return error.MalformedExtension;
                    var wrapper = tbs.childReader(elem.content_offset, elem.content.len) catch return error.MalformedExtension;
                    extensions = try self.parseExtensions(&wrapper);
                    wrapper.expectEnd() catch return error.MalformedExtension;
                },
                else => return error.MalformedCertificate,
            }
        }

        return .{
            .raw = cert_elem.encoded,
            .tbs_raw = tbs_elem.encoded,
            .version = version,
            .serial_number = serial_number,
            .signature_algorithm = signature_algorithm,
            .issuer = issuer,
            .validity = validity,
            .subject = subject,
            .subject_public_key_info = spki,
            .issuer_unique_id = issuer_unique_id,
            .subject_unique_id = subject_unique_id,
            .extensions = extensions,
            .signature_value = signature_value,
            .arena_state = undefined,
        };
    }

    fn parseVersion(self: *Parser, tbs: *der.Reader) Error!Version {
        _ = self;
        // version [0] EXPLICIT INTEGER DEFAULT v1: probe without consuming.
        var probe = tbs.*;
        const first = probe.readElement() catch return error.MalformedCertificate;
        if (first.tag.class != .context_specific or first.tag.number != 0) return .v1;

        const elem = tbs.readExplicitContext(0) catch return error.MalformedCertificate;
        if (!elem.tag.eql(der.Tag.universal(@intFromEnum(der.UniversalTag.integer), false))) {
            return error.MalformedCertificate;
        }
        der.validateInteger(elem.content, 2) catch return error.UnsupportedVersion;
        if (elem.content.len != 1) return error.UnsupportedVersion;
        return switch (elem.content[0]) {
            // DER: DEFAULT values must be omitted, so an explicit v1 is
            // non-canonical.
            0 => error.UnsupportedVersion,
            1 => .v2,
            2 => .v3,
            else => error.UnsupportedVersion,
        };
    }

    fn parseAlgorithmIdentifier(self: *Parser, reader: *der.Reader, comptime err: Error) Error!AlgorithmIdentifier {
        const elem = reader.readElement() catch return err;
        if (!isSequence(elem)) return err;
        var inner = reader.childReader(elem.content_offset, elem.content.len) catch return err;

        const oid = inner.readObjectIdentifier() catch return err;

        var parameters_raw: ?[]const u8 = null;
        var parameters_null = false;
        if (inner.remaining() > 0) {
            const params = inner.readElement() catch return err;
            parameters_raw = params.encoded;
            parameters_null = params.tag.eql(der.Tag.universal(@intFromEnum(der.UniversalTag.null), false)) and
                params.content.len == 0;
        }
        inner.expectEnd() catch return err;

        _ = self;
        return .{
            .raw = elem.encoded,
            .oid = oid,
            .parameters_raw = parameters_raw,
            .parameters_null = parameters_null,
        };
    }

    fn parseName(self: *Parser, reader: *der.Reader) Error!Name {
        const name_elem = reader.readElement() catch return error.MalformedName;
        if (!isSequence(name_elem)) return error.MalformedName;
        var rdn_reader = reader.childReader(name_elem.content_offset, name_elem.content.len) catch return error.MalformedName;

        var rdns: std.ArrayList(RelativeDistinguishedName) = .empty;
        while (rdn_reader.remaining() > 0) {
            if (rdns.items.len >= self.limits.max_name_rdns) return error.CountLimitExceeded;
            var set_reader = rdn_reader.readSet() catch return error.MalformedName;

            var attributes: std.ArrayList(AttributeTypeAndValue) = .empty;
            while (set_reader.remaining() > 0) {
                if (attributes.items.len >= self.limits.max_name_attributes) return error.CountLimitExceeded;
                var atv_reader = set_reader.readSequence() catch return error.MalformedName;
                const type_oid = atv_reader.readObjectIdentifier() catch return error.MalformedName;
                const value_elem = atv_reader.readElement() catch return error.MalformedName;
                try validateDirectoryString(value_elem);
                atv_reader.expectEnd() catch return error.MalformedName;
                try attributes.append(self.arena, .{
                    .type = type_oid,
                    .value_tag = value_elem.tag,
                    .value = value_elem.content,
                });
            }
            if (attributes.items.len == 0) return error.MalformedName;
            set_reader.expectEnd() catch return error.MalformedName;
            try rdns.append(self.arena, .{ .attributes = attributes.items });
        }
        rdn_reader.expectEnd() catch return error.MalformedName;

        return .{ .raw = name_elem.encoded, .rdns = rdns.items };
    }

    fn parseValidity(self: *Parser, reader: *der.Reader) Error!Validity {
        _ = self;
        var validity_reader = reader.readSequence() catch return error.MalformedValidity;
        const not_before = try parseTime(&validity_reader);
        const not_after = try parseTime(&validity_reader);
        validity_reader.expectEnd() catch return error.MalformedValidity;
        return .{ .not_before = not_before, .not_after = not_after };
    }

    fn parseSubjectPublicKeyInfo(self: *Parser, reader: *der.Reader) Error!SubjectPublicKeyInfo {
        const spki_elem = reader.readElement() catch return error.MalformedPublicKeyInfo;
        if (!isSequence(spki_elem)) return error.MalformedPublicKeyInfo;
        var inner = reader.childReader(spki_elem.content_offset, spki_elem.content.len) catch return error.MalformedPublicKeyInfo;

        const algorithm = try self.parseAlgorithmIdentifier(&inner, error.MalformedPublicKeyInfo);
        const public_key = inner.readBitString() catch return error.MalformedPublicKeyInfo;
        inner.expectEnd() catch return error.MalformedPublicKeyInfo;

        var key_type: PublicKeyType = .unrecognized;
        var named_curve: ?oid_mod.ObjectIdentifier = null;
        if (algorithm.oid.eqlComponents(&wk.rsa_encryption)) {
            key_type = .rsa;
        } else if (algorithm.oid.eqlComponents(&wk.ed25519)) {
            key_type = .ed25519;
        } else if (algorithm.oid.eqlComponents(&wk.ec_public_key)) {
            // id-ecPublicKey parameters must be a namedCurve OID for the
            // key to be identified; explicit curve parameters remain
            // unrecognized rather than malformed.
            const params = algorithm.parameters_raw orelse return error.MalformedPublicKeyInfo;
            var params_reader = der.Reader.init(params, self.limits.der);
            if (params_reader.readObjectIdentifier()) |curve| {
                named_curve = curve;
                if (curve.eqlComponents(&wk.secp256r1)) {
                    key_type = .ecdsa_p256;
                } else if (curve.eqlComponents(&wk.secp384r1)) {
                    key_type = .ecdsa_p384;
                } else if (curve.eqlComponents(&wk.secp521r1)) {
                    key_type = .ecdsa_p521;
                }
            } else |_| {}
        }

        return .{
            .raw = spki_elem.encoded,
            .algorithm = algorithm,
            .subject_public_key = public_key,
            .key_type = key_type,
            .named_curve = named_curve,
        };
    }

    fn parseExtensions(self: *Parser, wrapper: *der.Reader) Error![]const Extension {
        var list_reader = wrapper.readSequence() catch return error.MalformedExtension;
        var extensions: std.ArrayList(Extension) = .empty;

        while (list_reader.remaining() > 0) {
            if (extensions.items.len >= self.limits.max_extensions) return error.CountLimitExceeded;
            var ext_reader = list_reader.readSequence() catch return error.MalformedExtension;
            const ext_oid = ext_reader.readObjectIdentifier() catch return error.MalformedExtension;

            for (extensions.items) |existing| {
                if (existing.oid.eql(&ext_oid)) return error.DuplicateExtension;
            }

            var critical = false;
            {
                var probe = ext_reader;
                const next = probe.readElement() catch return error.MalformedExtension;
                if (next.tag.eql(der.Tag.universal(@intFromEnum(der.UniversalTag.boolean), false))) {
                    critical = ext_reader.readBoolean() catch return error.MalformedExtension;
                    // DER: critical DEFAULT FALSE must be omitted.
                    if (!critical) return error.MalformedExtension;
                }
            }

            const value = ext_reader.readOctetString() catch return error.MalformedExtension;
            ext_reader.expectEnd() catch return error.MalformedExtension;

            const parsed = try self.parseExtensionValue(&ext_oid, value);
            try extensions.append(self.arena, .{
                .oid = ext_oid,
                .critical = critical,
                .value = value,
                .parsed = parsed,
            });
        }
        if (extensions.items.len == 0) return error.MalformedExtension;
        list_reader.expectEnd() catch return error.MalformedExtension;

        return extensions.items;
    }

    fn parseExtensionValue(self: *Parser, ext_oid: *const oid_mod.ObjectIdentifier, value: []const u8) Error!Extension.Parsed {
        if (ext_oid.eqlComponents(&wk.basic_constraints)) {
            return .{ .basic_constraints = try self.parseBasicConstraints(value) };
        } else if (ext_oid.eqlComponents(&wk.key_usage)) {
            return .{ .key_usage = try self.parseKeyUsage(value) };
        } else if (ext_oid.eqlComponents(&wk.subject_alt_name)) {
            return .{ .subject_alt_name = try self.parseGeneralNames(value, .host) };
        } else if (ext_oid.eqlComponents(&wk.ext_key_usage)) {
            return .{ .extended_key_usage = try self.parseExtendedKeyUsage(value) };
        } else if (ext_oid.eqlComponents(&wk.subject_key_identifier)) {
            return .{ .subject_key_identifier = try self.parseSubjectKeyIdentifier(value) };
        } else if (ext_oid.eqlComponents(&wk.authority_key_identifier)) {
            return .{ .authority_key_identifier = try self.parseAuthorityKeyIdentifier(value) };
        } else if (ext_oid.eqlComponents(&wk.name_constraints)) {
            return .{ .name_constraints = try self.parseNameConstraints(value) };
        } else if (ext_oid.eqlComponents(&wk.authority_info_access)) {
            return .{ .authority_info_access = try self.parseAuthorityInfoAccess(value) };
        } else if (ext_oid.eqlComponents(&wk.crl_distribution_points)) {
            return .{ .crl_distribution_points = try self.parseCrlDistributionPoints(value) };
        } else if (ext_oid.eqlComponents(&wk.certificate_policies)) {
            return .{ .certificate_policies = try self.parseCertificatePolicies(value) };
        }
        return .unrecognized;
    }

    fn parseBasicConstraints(self: *Parser, value: []const u8) Error!BasicConstraints {
        var reader = der.Reader.init(value, self.limits.der);
        var inner = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;

        var is_ca = false;
        if (inner.remaining() > 0) {
            var probe = inner;
            const next = probe.readElement() catch return error.MalformedExtension;
            if (next.tag.eql(der.Tag.universal(@intFromEnum(der.UniversalTag.boolean), false))) {
                is_ca = inner.readBoolean() catch return error.MalformedExtension;
                // DER: cA DEFAULT FALSE must be omitted.
                if (!is_ca) return error.MalformedExtension;
            }
        }

        var max_path_len: ?u32 = null;
        if (inner.remaining() > 0) {
            const path_len = inner.readInteger() catch return error.MalformedExtension;
            if (path_len.isNegative()) return error.MalformedExtension;
            max_path_len = integerToU32(path_len) orelse return error.MalformedExtension;
        }
        inner.expectEnd() catch return error.MalformedExtension;
        return .{ .is_ca = is_ca, .max_path_len = max_path_len };
    }

    fn parseKeyUsage(self: *Parser, value: []const u8) Error!KeyUsage {
        var reader = der.Reader.init(value, self.limits.der);
        const bits = reader.readBitString() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;
        if (bits.data.len > 2) return error.MalformedExtension;
        // DER named bits: trailing zero bits are removed, so the final data
        // byte's lowest used bit must be set.
        if (bits.data.len > 0) {
            const last = bits.data[bits.data.len - 1];
            if (last == 0) return error.MalformedExtension;
            if ((last >> bits.unused_bits) & 1 == 0) return error.MalformedExtension;
        }

        var usage = KeyUsage{};
        const fields = [_]*bool{
            &usage.digital_signature, &usage.non_repudiation, &usage.key_encipherment,
            &usage.data_encipherment, &usage.key_agreement,   &usage.key_cert_sign,
            &usage.crl_sign,          &usage.encipher_only,   &usage.decipher_only,
        };
        for (fields, 0..) |field, bit_index| {
            const byte_index = bit_index / 8;
            if (byte_index >= bits.data.len) break;
            const mask = @as(u8, 0x80) >> @intCast(bit_index % 8);
            field.* = (bits.data[byte_index] & mask) != 0;
        }
        return usage;
    }

    fn parseExtendedKeyUsage(self: *Parser, value: []const u8) Error!ExtendedKeyUsage {
        var reader = der.Reader.init(value, self.limits.der);
        var inner = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;

        var purposes: std.ArrayList(oid_mod.ObjectIdentifier) = .empty;
        while (inner.remaining() > 0) {
            if (purposes.items.len >= self.limits.max_eku_purposes) return error.CountLimitExceeded;
            const purpose = inner.readObjectIdentifier() catch return error.MalformedExtension;
            try purposes.append(self.arena, purpose);
        }
        if (purposes.items.len == 0) return error.MalformedExtension;
        return .{ .purposes = purposes.items };
    }

    fn parseSubjectKeyIdentifier(self: *Parser, value: []const u8) Error![]const u8 {
        var reader = der.Reader.init(value, self.limits.der);
        const identifier = reader.readOctetString() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;
        if (identifier.len == 0) return error.MalformedExtension;
        return identifier;
    }

    fn parseAuthorityKeyIdentifier(self: *Parser, value: []const u8) Error!AuthorityKeyIdentifier {
        var reader = der.Reader.init(value, self.limits.der);
        var inner = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;

        var result = AuthorityKeyIdentifier{
            .key_identifier = null,
            .authority_cert_issuer_raw = null,
            .authority_cert_serial = null,
        };
        var last_tag: i64 = -1;
        while (inner.remaining() > 0) {
            const elem = inner.readElement() catch return error.MalformedExtension;
            if (elem.tag.class != .context_specific) return error.MalformedExtension;
            if (elem.tag.number <= last_tag) return error.MalformedExtension;
            last_tag = elem.tag.number;
            switch (elem.tag.number) {
                0 => {
                    if (elem.tag.constructed) return error.MalformedExtension;
                    if (elem.content.len == 0) return error.MalformedExtension;
                    result.key_identifier = elem.content;
                },
                1 => {
                    if (!elem.tag.constructed) return error.MalformedExtension;
                    result.authority_cert_issuer_raw = elem.encoded;
                },
                2 => {
                    if (elem.tag.constructed) return error.MalformedExtension;
                    der.validateInteger(elem.content, self.limits.der.max_integer_bytes) catch return error.MalformedExtension;
                    result.authority_cert_serial = elem.content;
                },
                else => return error.MalformedExtension,
            }
        }
        // RFC 5280 §4.2.1.1: issuer and serial appear together or not at all.
        if ((result.authority_cert_issuer_raw == null) != (result.authority_cert_serial == null)) {
            return error.MalformedExtension;
        }
        return result;
    }

    fn parseNameConstraints(self: *Parser, value: []const u8) Error!NameConstraints {
        var reader = der.Reader.init(value, self.limits.der);
        var inner = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;

        var permitted: []const GeneralSubtree = &.{};
        var excluded: []const GeneralSubtree = &.{};
        var last_tag: i64 = -1;
        while (inner.remaining() > 0) {
            const elem = inner.readElement() catch return error.MalformedExtension;
            if (elem.tag.class != .context_specific or !elem.tag.constructed) return error.MalformedExtension;
            if (elem.tag.number <= last_tag) return error.MalformedExtension;
            last_tag = elem.tag.number;
            var subtree_reader = inner.childReader(elem.content_offset, elem.content.len) catch return error.MalformedExtension;
            const subtrees = try self.parseGeneralSubtrees(&subtree_reader);
            switch (elem.tag.number) {
                0 => permitted = subtrees,
                1 => excluded = subtrees,
                else => return error.MalformedExtension,
            }
        }
        // RFC 5280 §4.2.1.10: at least one of permitted/excluded must appear.
        if (permitted.len == 0 and excluded.len == 0) return error.MalformedExtension;
        return .{ .permitted = permitted, .excluded = excluded };
    }

    fn parseGeneralSubtrees(self: *Parser, reader: *der.Reader) Error![]const GeneralSubtree {
        var subtrees: std.ArrayList(GeneralSubtree) = .empty;
        while (reader.remaining() > 0) {
            if (subtrees.items.len >= self.limits.max_name_constraint_subtrees) return error.CountLimitExceeded;
            var subtree_reader = reader.readSequence() catch return error.MalformedExtension;
            const base = try self.parseGeneralName(&subtree_reader, .cidr);
            // minimum [0] DEFAULT 0 / maximum [1] OPTIONAL: RFC 5280
            // requires minimum absent (DER default) and maximum unused;
            // their presence is structural noise we reject deterministically.
            if (subtree_reader.remaining() > 0) return error.MalformedExtension;
            subtree_reader.expectEnd() catch return error.MalformedExtension;
            try subtrees.append(self.arena, .{ .base = base });
        }
        if (subtrees.items.len == 0) return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;
        return subtrees.items;
    }

    fn parseAuthorityInfoAccess(self: *Parser, value: []const u8) Error![]const AccessDescription {
        var reader = der.Reader.init(value, self.limits.der);
        var inner = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;

        var descriptions: std.ArrayList(AccessDescription) = .empty;
        while (inner.remaining() > 0) {
            if (descriptions.items.len >= self.limits.max_access_descriptions) return error.CountLimitExceeded;
            var desc_reader = inner.readSequence() catch return error.MalformedExtension;
            const method = desc_reader.readObjectIdentifier() catch return error.MalformedExtension;
            const location = try self.parseGeneralName(&desc_reader, .host);
            desc_reader.expectEnd() catch return error.MalformedExtension;
            try descriptions.append(self.arena, .{ .method = method, .location = location });
        }
        if (descriptions.items.len == 0) return error.MalformedExtension;
        return descriptions.items;
    }

    fn parseCrlDistributionPoints(self: *Parser, value: []const u8) Error![]const DistributionPoint {
        var reader = der.Reader.init(value, self.limits.der);
        var inner = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;

        var points: std.ArrayList(DistributionPoint) = .empty;
        while (inner.remaining() > 0) {
            if (points.items.len >= self.limits.max_distribution_points) return error.CountLimitExceeded;
            const point_elem = inner.readElement() catch return error.MalformedExtension;
            if (!isSequence(point_elem)) return error.MalformedExtension;
            var point_reader = inner.childReader(point_elem.content_offset, point_elem.content.len) catch return error.MalformedExtension;

            var full_names: []const GeneralName = &.{};
            var has_distribution_point = false;
            var has_crl_issuer = false;
            var last_tag: i64 = -1;
            while (point_reader.remaining() > 0) {
                const elem = point_reader.readElement() catch return error.MalformedExtension;
                if (elem.tag.class != .context_specific) return error.MalformedExtension;
                // OPTIONAL fields appear at most once, in ascending tag order.
                if (elem.tag.number <= last_tag) return error.MalformedExtension;
                last_tag = elem.tag.number;
                switch (elem.tag.number) {
                    0 => {
                        // distributionPoint [0] { fullName [0] GeneralNames |
                        // nameRelativeToCRLIssuer [1] RDN }
                        if (!elem.tag.constructed) return error.MalformedExtension;
                        has_distribution_point = true;
                        var choice_reader = point_reader.childReader(elem.content_offset, elem.content.len) catch return error.MalformedExtension;
                        const choice = choice_reader.readElement() catch return error.MalformedExtension;
                        choice_reader.expectEnd() catch return error.MalformedExtension;
                        if (choice.tag.class != .context_specific) return error.MalformedExtension;
                        if (choice.tag.number == 0) {
                            var names_reader = choice_reader.childReader(choice.content_offset, choice.content.len) catch return error.MalformedExtension;
                            full_names = try self.parseGeneralNameList(&names_reader, .host);
                            if (full_names.len == 0) return error.MalformedExtension;
                        } else if (choice.tag.number != 1) {
                            return error.MalformedExtension;
                        }
                    },
                    1 => {
                        // reasons [1] IMPLICIT BIT STRING: validated, then
                        // retained via `raw` only.
                        if (elem.tag.constructed) return error.MalformedExtension;
                        _ = der.decodeBitStringContent(elem.content) catch return error.MalformedExtension;
                    },
                    2 => {
                        // cRLIssuer [2] IMPLICIT GeneralNames: validated,
                        // then retained via `raw` only.
                        if (!elem.tag.constructed) return error.MalformedExtension;
                        has_crl_issuer = true;
                        var issuer_reader = point_reader.childReader(elem.content_offset, elem.content.len) catch return error.MalformedExtension;
                        const issuer_names = try self.parseGeneralNameList(&issuer_reader, .host);
                        if (issuer_names.len == 0) return error.MalformedExtension;
                    },
                    else => return error.MalformedExtension,
                }
            }
            // RFC 5280 §4.2.1.13: a DistributionPoint must carry a
            // distributionPoint or a cRLIssuer; reasons alone is invalid.
            if (!has_distribution_point and !has_crl_issuer) return error.MalformedExtension;
            try points.append(self.arena, .{ .raw = point_elem.encoded, .full_names = full_names });
        }
        if (points.items.len == 0) return error.MalformedExtension;
        return points.items;
    }

    fn parseCertificatePolicies(self: *Parser, value: []const u8) Error![]const PolicyInformation {
        var reader = der.Reader.init(value, self.limits.der);
        var inner = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;

        var policies: std.ArrayList(PolicyInformation) = .empty;
        while (inner.remaining() > 0) {
            if (policies.items.len >= self.limits.max_policies) return error.CountLimitExceeded;
            var info_reader = inner.readSequence() catch return error.MalformedExtension;
            const policy = info_reader.readObjectIdentifier() catch return error.MalformedExtension;
            var qualifiers_raw: ?[]const u8 = null;
            if (info_reader.remaining() > 0) {
                const qualifiers = info_reader.readElement() catch return error.MalformedExtension;
                if (!isSequence(qualifiers)) return error.MalformedExtension;
                qualifiers_raw = qualifiers.encoded;
            }
            info_reader.expectEnd() catch return error.MalformedExtension;
            try policies.append(self.arena, .{ .policy = policy, .qualifiers_raw = qualifiers_raw });
        }
        if (policies.items.len == 0) return error.MalformedExtension;
        return policies.items;
    }

    /// Wrap a SEQUENCE OF GeneralName held in `value` (SAN payload).
    fn parseGeneralNames(self: *Parser, value: []const u8, ip_mode: IpMode) Error![]const GeneralName {
        var reader = der.Reader.init(value, self.limits.der);
        var inner = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;
        const names = try self.parseGeneralNameList(&inner, ip_mode);
        if (names.len == 0) return error.MalformedExtension;
        return names;
    }

    fn parseGeneralNameList(self: *Parser, reader: *der.Reader, ip_mode: IpMode) Error![]const GeneralName {
        var names: std.ArrayList(GeneralName) = .empty;
        while (reader.remaining() > 0) {
            if (names.items.len >= self.limits.max_general_names) return error.CountLimitExceeded;
            const name = try self.parseGeneralName(reader, ip_mode);
            try names.append(self.arena, name);
        }
        reader.expectEnd() catch return error.MalformedExtension;
        return names.items;
    }

    const IpMode = enum {
        /// SAN and access locations: 4 (IPv4) or 16 (IPv6) bytes.
        host,
        /// Name constraints: address plus mask, 8 or 32 bytes.
        cidr,
    };

    fn parseGeneralName(self: *Parser, reader: *der.Reader, ip_mode: IpMode) Error!GeneralName {
        _ = self;
        const elem = reader.readElement() catch return error.MalformedExtension;
        if (elem.tag.class != .context_specific) return error.MalformedExtension;
        switch (elem.tag.number) {
            1, 2, 6 => {
                if (elem.tag.constructed) return error.MalformedExtension;
                der.validateIa5String(elem.content) catch return error.MalformedExtension;
                return switch (elem.tag.number) {
                    1 => .{ .rfc822_name = elem.content },
                    2 => .{ .dns_name = elem.content },
                    else => .{ .uniform_resource_identifier = elem.content },
                };
            },
            4 => {
                // directoryName [4] is EXPLICIT (Name is a CHOICE): the
                // context tag wraps the Name SEQUENCE TLV.
                if (!elem.tag.constructed) return error.MalformedExtension;
                var inner = reader.childReader(elem.content_offset, elem.content.len) catch return error.MalformedExtension;
                const name_elem = inner.readElement() catch return error.MalformedExtension;
                if (!isSequence(name_elem)) return error.MalformedExtension;
                inner.expectEnd() catch return error.MalformedExtension;
                return .{ .directory_name = name_elem.encoded };
            },
            7 => {
                if (elem.tag.constructed) return error.MalformedExtension;
                const valid_len = switch (ip_mode) {
                    .host => elem.content.len == 4 or elem.content.len == 16,
                    .cidr => elem.content.len == 8 or elem.content.len == 32,
                };
                if (!valid_len) return error.MalformedExtension;
                return .{ .ip_address = elem.content };
            },
            8 => {
                if (elem.tag.constructed) return error.MalformedExtension;
                const registered = oid_mod.decode(elem.content, oid_mod.max_components) catch return error.MalformedExtension;
                return .{ .registered_id = registered };
            },
            0, 3, 5 => {
                if (!elem.tag.constructed) return error.MalformedExtension;
                return .{ .other = .{ .tag_number = elem.tag.number, .raw = elem.encoded } };
            },
            else => return error.MalformedExtension,
        }
    }
};

fn parseTime(reader: *der.Reader) Error!Time {
    const elem = reader.readElement() catch return error.MalformedValidity;
    if (elem.tag.class != .universal or elem.tag.constructed) return error.MalformedValidity;
    switch (elem.tag.number) {
        @intFromEnum(der.UniversalTag.utc_time) => {
            const utc = time_mod.parseUtcTime(elem.content) catch return error.MalformedValidity;
            return .{
                .year = utc.year,
                .month = utc.month,
                .day = utc.day,
                .hour = utc.hour,
                .minute = utc.minute,
                .second = utc.second,
                .encoding = .utc,
            };
        },
        @intFromEnum(der.UniversalTag.generalized_time) => {
            const gen = time_mod.parseGeneralizedTime(elem.content) catch return error.MalformedValidity;
            // RFC 5280 §4.1.2.5: dates through 2049 must use UTCTime.
            if (gen.year < 2050) return error.MalformedValidity;
            return .{
                .year = gen.year,
                .month = gen.month,
                .day = gen.day,
                .hour = gen.hour,
                .minute = gen.minute,
                .second = gen.second,
                .encoding = .generalized,
            };
        },
        else => return error.MalformedValidity,
    }
}

fn validateDirectoryString(elem: der.Element) Error!void {
    if (elem.tag.class != .universal) return;
    // DER string encodings must be primitive; a constructed form of a
    // recognized string tag is non-canonical, not an unknown type. Genuinely
    // unknown attribute-value tags are retained raw.
    switch (elem.tag.number) {
        @intFromEnum(der.UniversalTag.utf8_string) => {
            if (elem.tag.constructed) return error.MalformedName;
            der.validateUtf8(elem.content) catch return error.MalformedName;
        },
        @intFromEnum(der.UniversalTag.printable_string) => {
            if (elem.tag.constructed) return error.MalformedName;
            der.validatePrintableString(elem.content) catch return error.MalformedName;
        },
        @intFromEnum(der.UniversalTag.ia5_string) => {
            if (elem.tag.constructed) return error.MalformedName;
            der.validateIa5String(elem.content) catch return error.MalformedName;
        },
        @intFromEnum(der.UniversalTag.bmp_string) => {
            if (elem.tag.constructed) return error.MalformedName;
            der.validateBmpString(elem.content) catch return error.MalformedName;
        },
        else => {},
    }
}

fn integerToU32(view: der.IntegerView) ?u32 {
    var value: u64 = 0;
    for (view.content) |byte| {
        if (value > std.math.maxInt(u32) >> 8) return null;
        value = (value << 8) | byte;
    }
    if (value > std.math.maxInt(u32)) return null;
    return @intCast(value);
}

fn isSequence(elem: der.Element) bool {
    return elem.tag.eql(der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true));
}

fn expectSequence(elem: der.Element) Error!void {
    if (!isSequence(elem)) return error.MalformedCertificate;
}

/// Fuzz and regression entrypoint (#327-G): parse arbitrary bytes as a
/// certificate under strict limits without I/O, panics, or unbounded
/// allocation.
pub fn fuzzParseCertificate(allocator: std.mem.Allocator, input: []const u8) void {
    const limits: Limits = .{
        .der = .{
            .max_depth = 16,
            .max_element_len = 64 * 1024,
            .max_elements = 512,
        },
        .max_extensions = 16,
        .max_general_names = 16,
    };
    var certificate = Certificate.parse(allocator, input, limits) catch return;
    certificate.deinit(allocator);
}

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
