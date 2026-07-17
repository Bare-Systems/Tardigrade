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
const rfc4518_data = @import("rfc4518_data.zig");
const time_mod = @import("time.zig");

const wk = oid_mod.well_known;
/// ASN.1 VisibleString is universal tag 26 (X.680, clause 8.23).
const visible_string_tag_number: u32 = 26;

/// Configurable parser resource bounds, applied on top of `der.Limits`.
pub const Limits = struct {
    der: der.Limits = .{},
    max_extensions: usize = 64,
    max_name_rdns: usize = 32,
    max_name_attributes: usize = 8,
    max_general_names: usize = 64,
    max_eku_purposes: usize = 32,
    max_policies: usize = 32,
    max_policy_qualifiers: usize = 16,
    max_policy_qualifier_bytes: usize = 4096,
    max_policy_mappings: usize = 64,
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
    NamePreparationFailed,
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

/// Name ::= RDNSequence. Two comparisons exist: `eqlEncoding` is byte-exact
/// on `raw` (encoding identity), and `eqlForChaining` implements the
/// RFC 5280 §7.1 name-chaining rules via the precomputed `chaining_key`.
pub const Name = struct {
    /// Full TLV bytes of the Name SEQUENCE.
    raw: []const u8,
    rdns: []const RelativeDistinguishedName,
    /// Canonical name-chaining key (RFC 5280 §7.1), arena-owned: RDNs in
    /// sequence order, each RDN's attributes compared as a set (sorted
    /// canonical forms), attribute types by decoded OID. Three matching
    /// classes select the per-attribute normalization:
    ///
    /// - `domainComponent` (id-domainComponent) values carried in a
    ///   primitive IA5String are compared with `caseIgnoreIA5Match`
    ///   (RFC 4517 §4.2.3): ASCII case folded. IA5String is ASCII-only, so
    ///   this is an exact implementation of the rule, not an approximation.
    /// - Primitive PrintableString/UTF8String values (the required
    ///   DirectoryString forms) are unified into one caseIgnore class using
    ///   RFC 4518 stored-value preparation with RFC 3454 B.2 case mapping,
    ///   Unicode 3.2 Form KC normalization, prohibited/unassigned rejection,
    ///   and RFC 4518 §2.6.1 insignificant-space handling.
    /// - Every other value type (including BMPString, which RFC 5280
    ///   permits but is legacy and rare) compares as exact bytes under its
    ///   own tag.
    ///
    /// Two names chain exactly when their keys are byte-equal.
    chaining_key: []const u8,
    /// Per-RDN canonical keys built by the same RFC 4518/4517 machinery as
    /// `chaining_key`.  They permit RFC 5280 directoryName subtree matching
    /// without reparsing or implementing a second normalization path.
    rdn_chaining_keys: []const []const u8,

    pub fn eqlEncoding(self: *const Name, other: *const Name) bool {
        return std.mem.eql(u8, self.raw, other.raw);
    }

    /// RFC 5280 §7.1 name-chaining equality (see `chaining_key`).
    pub fn eqlForChaining(self: *const Name, other: *const Name) bool {
        return std.mem.eql(u8, self.chaining_key, other.chaining_key);
    }

    pub fn isEmpty(self: *const Name) bool {
        return self.rdns.len == 0;
    }

    /// RFC 5280 §7.1 directoryName subtree membership.  A subject is
    /// within a constraint when the constraint's RDN sequence is a canonical
    /// prefix of the subject's sequence.  RDN equality uses exactly the same
    /// matching rules as issuer/subject chaining.
    pub fn isWithinSubtree(self: *const Name, constraint: *const Name) bool {
        if (constraint.rdn_chaining_keys.len > self.rdn_chaining_keys.len) return false;
        for (constraint.rdn_chaining_keys, self.rdn_chaining_keys[0..constraint.rdn_chaining_keys.len]) |expected, actual| {
            if (!std.mem.eql(u8, expected, actual)) return false;
        }
        return true;
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

pub const PolicyQualifier = struct {
    pub const Kind = enum { cps_pointer, user_notice, unsupported };

    oid: oid_mod.ObjectIdentifier,
    /// Full TLV bytes of the qualifier value. Borrowed from certificate DER.
    value_raw: []const u8,
    kind: Kind,
};

pub const PolicyInformation = struct {
    policy: oid_mod.ObjectIdentifier,
    qualifiers: []const PolicyQualifier,
};

pub const PolicyMapping = struct {
    issuer_domain_policy: oid_mod.ObjectIdentifier,
    subject_domain_policy: oid_mod.ObjectIdentifier,
};

pub const PolicyConstraints = struct {
    /// RFC 5280 SkipCerts values are unbounded non-negative INTEGERs. Values
    /// larger than this platform can represent saturate because validation
    /// only compares them with the much smaller bounded path counters.
    require_explicit_policy: ?usize,
    inhibit_policy_mapping: ?usize,
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
        policy_mappings: []const PolicyMapping,
        policy_constraints: PolicyConstraints,
        inhibit_any_policy: usize,
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

    /// RFC 5280 defines self-issued as the issuer and subject DNs matching
    /// under §7.1 name-chaining rules, not encoding identity: a CA that
    /// re-encodes its own name between issuer and subject fields (a
    /// PrintableString subject, UTF8String issuer, for example) is still
    /// self-issued.
    pub fn isSelfIssued(self: *const Certificate) bool {
        return self.issuer.eqlForChaining(&self.subject);
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

    pub fn certificatePolicies(self: *const Certificate) ?[]const PolicyInformation {
        const extension = self.findExtension(&wk.certificate_policies) orelse return null;
        return extension.parsed.certificate_policies;
    }

    pub fn policyMappings(self: *const Certificate) ?[]const PolicyMapping {
        const extension = self.findExtension(&wk.policy_mappings) orelse return null;
        return extension.parsed.policy_mappings;
    }

    pub fn policyConstraints(self: *const Certificate) ?PolicyConstraints {
        const extension = self.findExtension(&wk.policy_constraints) orelse return null;
        return extension.parsed.policy_constraints;
    }

    pub fn inhibitAnyPolicy(self: *const Certificate) ?usize {
        const extension = self.findExtension(&wk.inhibit_any_policy) orelse return null;
        return extension.parsed.inhibit_any_policy;
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

        const rdn_chaining_keys = try self.buildRdnChainingKeys(rdns.items);
        return .{
            .raw = name_elem.encoded,
            .rdns = rdns.items,
            .chaining_key = try self.buildChainingKey(rdn_chaining_keys),
            .rdn_chaining_keys = rdn_chaining_keys,
        };
    }

    fn buildRdnChainingKeys(self: *Parser, rdns: []const RelativeDistinguishedName) Error![]const []const u8 {
        const keys = try self.arena.alloc([]const u8, rdns.len);
        for (rdns, keys) |rdn, *key| {
            var bytes: std.ArrayList(u8) = .empty;
            try appendCount(&bytes, self.arena, rdn.attributes.len);
            // SET semantics: attribute order inside an RDN must not affect
            // the key, and canonicalization can reorder attributes relative
            // to their DER encoding, so sort the canonical forms.
            const blobs = try self.arena.alloc([]const u8, rdn.attributes.len);
            for (rdn.attributes, blobs) |*attribute, *blob| {
                blob.* = try self.attributeChainingBlob(attribute);
            }
            std.mem.sort([]const u8, blobs, {}, sliceLessThan);
            for (blobs) |blob| try bytes.appendSlice(self.arena, blob);
            key.* = bytes.items;
        }
        return keys;
    }

    /// Serialize the canonical `Name.chaining_key`. Every piece is
    /// length/count-prefixed, so the flat concatenation is injective: two
    /// keys are byte-equal exactly when the names chain under the documented
    /// RFC 5280 §7.1 rules.
    fn buildChainingKey(self: *Parser, rdn_keys: []const []const u8) Error![]const u8 {
        var key: std.ArrayList(u8) = .empty;
        try appendCount(&key, self.arena, rdn_keys.len);
        for (rdn_keys) |rdn_key| try key.appendSlice(self.arena, rdn_key);
        return key.items;
    }

    fn attributeChainingBlob(self: *Parser, attribute: *const AttributeTypeAndValue) Error![]const u8 {
        var blob: std.ArrayList(u8) = .empty;
        const components = attribute.type.components();
        try appendCount(&blob, self.arena, components.len);
        for (components) |component| try appendBe32(&blob, self.arena, component);
        if (attribute.type.eqlComponents(&wk.domain_component) and isPrimitiveIa5(attribute.value_tag)) {
            // RFC 5280 §7.1 / RFC 4517 §4.2.3 caseIgnoreIA5Match: exact, not
            // an approximation, since IA5String content is ASCII-only.
            try blob.append(self.arena, 0x02);
            const normalized = try self.arena.alloc(u8, attribute.value.len);
            for (attribute.value, normalized) |byte, *out| out.* = std.ascii.toLower(byte);
            try appendCount(&blob, self.arena, normalized.len);
            try blob.appendSlice(self.arena, normalized);
        } else if (isCaseIgnoreStringTag(attribute.value_tag)) {
            try blob.append(self.arena, 0x00);
            const normalized = try normalizeDirectoryString(self.arena, attribute.value);
            try appendCount(&blob, self.arena, normalized.len);
            try blob.appendSlice(self.arena, normalized);
        } else {
            try blob.append(self.arena, 0x01);
            const class_bits: u8 = @intFromEnum(attribute.value_tag.class);
            try blob.append(self.arena, (class_bits << 1) | @intFromBool(attribute.value_tag.constructed));
            try appendBe32(&blob, self.arena, attribute.value_tag.number);
            try appendCount(&blob, self.arena, attribute.value.len);
            try blob.appendSlice(self.arena, attribute.value);
        }
        return blob.items;
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
        } else if (ext_oid.eqlComponents(&wk.policy_mappings)) {
            return .{ .policy_mappings = try self.parsePolicyMappings(value) };
        } else if (ext_oid.eqlComponents(&wk.policy_constraints)) {
            return .{ .policy_constraints = try self.parsePolicyConstraints(value) };
        } else if (ext_oid.eqlComponents(&wk.inhibit_any_policy)) {
            return .{ .inhibit_any_policy = try self.parseInhibitAnyPolicy(value) };
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
        // RFC 5280 §4.2.1.9: pathLenConstraint is meaningful, and permitted,
        // only when cA is asserted TRUE.
        if (max_path_len != null and !is_ca) return error.MalformedExtension;
        return .{ .is_ca = is_ca, .max_path_len = max_path_len };
    }

    fn parseKeyUsage(self: *Parser, value: []const u8) Error!KeyUsage {
        var reader = der.Reader.init(value, self.limits.der);
        const bits = reader.readBitString() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;
        // RFC 5280 §4.2.1.3: when Key Usage is present, at least one bit MUST
        // be set. An empty BIT STRING would otherwise become an all-false KU.
        if (bits.data.len == 0 or bits.data.len > 2) return error.MalformedExtension;
        // DER named bits: trailing zero bits are removed, so the final data
        // byte's lowest used bit must be set.
        if (bits.data.len > 0) {
            const last = bits.data[bits.data.len - 1];
            if (last == 0) return error.MalformedExtension;
            if ((last >> bits.unused_bits) & 1 == 0) return error.MalformedExtension;
        }
        // Only bits 0..8 are assigned by RFC 5280. The low seven bits of a
        // second content octet are unknown and fail the parser's strict,
        // policy-neutral encoding profile.
        if (bits.data.len == 2 and bits.data[1] & 0x7f != 0) return error.MalformedExtension;

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
            for (policies.items) |existing| {
                if (existing.policy.eql(&policy)) return error.MalformedExtension;
            }

            var qualifiers: []const PolicyQualifier = &.{};
            if (info_reader.remaining() > 0) {
                var qualifiers_reader = info_reader.readSequence() catch return error.MalformedExtension;
                var parsed_qualifiers: std.ArrayList(PolicyQualifier) = .empty;
                while (qualifiers_reader.remaining() > 0) {
                    if (parsed_qualifiers.items.len >= self.limits.max_policy_qualifiers) return error.CountLimitExceeded;
                    var qualifier_reader = qualifiers_reader.readSequence() catch return error.MalformedExtension;
                    const qualifier_oid = qualifier_reader.readObjectIdentifier() catch return error.MalformedExtension;
                    const qualifier_value = qualifier_reader.readElement() catch return error.MalformedExtension;
                    qualifier_reader.expectEnd() catch return error.MalformedExtension;
                    if (qualifier_value.encoded.len > self.limits.max_policy_qualifier_bytes) return error.CountLimitExceeded;

                    const kind: PolicyQualifier.Kind = if (qualifier_oid.eqlComponents(&wk.policy_qualifier_cps)) blk: {
                        try self.validateCpsPointer(qualifier_value);
                        break :blk .cps_pointer;
                    } else if (qualifier_oid.eqlComponents(&wk.policy_qualifier_user_notice)) blk: {
                        try self.validateUserNotice(qualifier_value);
                        break :blk .user_notice;
                    } else blk: {
                        try self.validateAnyValue(&qualifier_reader, qualifier_value);
                        break :blk .unsupported;
                    };
                    try parsed_qualifiers.append(self.arena, .{
                        .oid = qualifier_oid,
                        .value_raw = qualifier_value.encoded,
                        .kind = kind,
                    });
                }
                if (parsed_qualifiers.items.len == 0) return error.MalformedExtension;
                qualifiers_reader.expectEnd() catch return error.MalformedExtension;
                qualifiers = parsed_qualifiers.items;
            }
            info_reader.expectEnd() catch return error.MalformedExtension;
            try policies.append(self.arena, .{ .policy = policy, .qualifiers = qualifiers });
        }
        if (policies.items.len == 0) return error.MalformedExtension;
        return policies.items;
    }

    fn validateCpsPointer(self: *Parser, elem: der.Element) Error!void {
        _ = self;
        if (!elem.tag.eql(der.Tag.universal(@intFromEnum(der.UniversalTag.ia5_string), false))) {
            return error.MalformedExtension;
        }
        der.validateIa5String(elem.content) catch return error.MalformedExtension;
        if (elem.content.len == 0) return error.MalformedExtension;
    }

    fn validateUserNotice(self: *Parser, elem: der.Element) Error!void {
        if (!isSequence(elem)) return error.MalformedExtension;
        var reader = der.Reader.init(elem.encoded, self.limits.der);
        var notice = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;
        if (notice.remaining() == 0) return;

        var probe = notice;
        const first = probe.readElement() catch return error.MalformedExtension;
        if (isSequence(first)) {
            const notice_ref = notice.readElement() catch return error.MalformedExtension;
            try self.validateNoticeReference(notice_ref);
            if (notice.remaining() > 0) {
                const text = notice.readElement() catch return error.MalformedExtension;
                try self.validateDisplayText(text);
            }
        } else {
            const text = notice.readElement() catch return error.MalformedExtension;
            try self.validateDisplayText(text);
        }
        notice.expectEnd() catch return error.MalformedExtension;
    }

    fn validateNoticeReference(self: *Parser, elem: der.Element) Error!void {
        if (!isSequence(elem)) return error.MalformedExtension;
        var reader = der.Reader.init(elem.encoded, self.limits.der);
        var notice_ref = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;
        const organization = notice_ref.readElement() catch return error.MalformedExtension;
        try self.validateDisplayText(organization);
        var numbers = notice_ref.readSequence() catch return error.MalformedExtension;
        while (numbers.remaining() > 0) {
            _ = numbers.readInteger() catch return error.MalformedExtension;
        }
        numbers.expectEnd() catch return error.MalformedExtension;
        notice_ref.expectEnd() catch return error.MalformedExtension;
    }

    fn validateDisplayText(self: *Parser, elem: der.Element) Error!void {
        _ = self;
        if (elem.tag.class != .universal or elem.tag.constructed) return error.MalformedExtension;
        var character_count: usize = 0;
        switch (elem.tag.number) {
            @intFromEnum(der.UniversalTag.ia5_string) => {
                der.validateIa5String(elem.content) catch return error.MalformedExtension;
                character_count = elem.content.len;
            },
            visible_string_tag_number => {
                for (elem.content) |byte| if (byte < 0x20 or byte > 0x7e) return error.MalformedExtension;
                character_count = elem.content.len;
            },
            @intFromEnum(der.UniversalTag.bmp_string) => {
                der.validateBmpString(elem.content) catch return error.MalformedExtension;
                character_count = elem.content.len / 2;
            },
            @intFromEnum(der.UniversalTag.utf8_string) => {
                der.validateUtf8(elem.content) catch return error.MalformedExtension;
                var view = std.unicode.Utf8View.init(elem.content) catch return error.MalformedExtension;
                var iterator = view.iterator();
                while (iterator.nextCodepoint() != null) character_count += 1;
            },
            else => return error.MalformedExtension,
        }
        if (character_count == 0 or character_count > 200) return error.MalformedExtension;
    }

    fn validateAnyValue(self: *Parser, parent: *der.Reader, elem: der.Element) Error!void {
        if (!elem.tag.constructed) return;
        var readers: std.ArrayList(der.Reader) = .empty;
        try readers.append(self.arena, parent.childReader(elem.content_offset, elem.content.len) catch return error.MalformedExtension);
        while (readers.items.len != 0) {
            const index = readers.items.len - 1;
            if (readers.items[index].remaining() == 0) {
                readers.items[index].expectEnd() catch return error.MalformedExtension;
                _ = readers.pop();
                continue;
            }
            const nested = readers.items[index].readElement() catch return error.MalformedExtension;
            if (!nested.tag.constructed) continue;
            const child = readers.items[index].childReader(nested.content_offset, nested.content.len) catch return error.MalformedExtension;
            try readers.append(self.arena, child);
        }
    }

    fn parsePolicyMappings(self: *Parser, value: []const u8) Error![]const PolicyMapping {
        var reader = der.Reader.init(value, self.limits.der);
        var inner = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;
        var mappings: std.ArrayList(PolicyMapping) = .empty;
        while (inner.remaining() > 0) {
            if (mappings.items.len >= self.limits.max_policy_mappings) return error.CountLimitExceeded;
            var pair = inner.readSequence() catch return error.MalformedExtension;
            const issuer = pair.readObjectIdentifier() catch return error.MalformedExtension;
            const subject = pair.readObjectIdentifier() catch return error.MalformedExtension;
            pair.expectEnd() catch return error.MalformedExtension;
            for (mappings.items) |existing| {
                if (existing.issuer_domain_policy.eql(&issuer) and existing.subject_domain_policy.eql(&subject)) {
                    return error.MalformedExtension;
                }
            }
            try mappings.append(self.arena, .{
                .issuer_domain_policy = issuer,
                .subject_domain_policy = subject,
            });
        }
        if (mappings.items.len == 0) return error.MalformedExtension;
        inner.expectEnd() catch return error.MalformedExtension;
        return mappings.items;
    }

    fn parsePolicyConstraints(self: *Parser, value: []const u8) Error!PolicyConstraints {
        var reader = der.Reader.init(value, self.limits.der);
        var inner = reader.readSequence() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;
        var constraints = PolicyConstraints{ .require_explicit_policy = null, .inhibit_policy_mapping = null };
        var last_tag: ?u32 = null;
        while (inner.remaining() > 0) {
            const elem = inner.readElement() catch return error.MalformedExtension;
            if (elem.tag.class != .context_specific or elem.tag.constructed or elem.tag.number > 1) {
                return error.MalformedExtension;
            }
            if (last_tag) |last| if (elem.tag.number <= last) return error.MalformedExtension;
            last_tag = elem.tag.number;
            der.validateInteger(elem.content, self.limits.der.max_integer_bytes) catch return error.MalformedExtension;
            const integer = der.IntegerView{ .content = elem.content };
            if (integer.isNegative()) return error.MalformedExtension;
            const count = integerToSaturatingUsize(integer);
            if (elem.tag.number == 0) {
                constraints.require_explicit_policy = count;
            } else {
                constraints.inhibit_policy_mapping = count;
            }
        }
        if (constraints.require_explicit_policy == null and constraints.inhibit_policy_mapping == null) {
            return error.MalformedExtension;
        }
        inner.expectEnd() catch return error.MalformedExtension;
        return constraints;
    }

    fn parseInhibitAnyPolicy(self: *Parser, value: []const u8) Error!usize {
        var reader = der.Reader.init(value, self.limits.der);
        const integer = reader.readInteger() catch return error.MalformedExtension;
        reader.expectEnd() catch return error.MalformedExtension;
        if (integer.isNegative()) return error.MalformedExtension;
        return integerToSaturatingUsize(integer);
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

/// The RFC 5280 §7.1 caseIgnore class: primitive PrintableString and
/// UTF8String values are normalized and compared as one class so encoding
/// migrations (a CA re-encoding `CN=Example CA` from PrintableString to
/// UTF8String) still chain.
fn isCaseIgnoreStringTag(tag: der.Tag) bool {
    if (tag.class != .universal or tag.constructed) return false;
    return tag.number == @intFromEnum(der.UniversalTag.utf8_string) or
        tag.number == @intFromEnum(der.UniversalTag.printable_string);
}

fn isPrimitiveIa5(tag: der.Tag) bool {
    return tag.class == .universal and !tag.constructed and
        tag.number == @intFromEnum(der.UniversalTag.ia5_string);
}

/// RFC 5280 §7.1 DirectoryString preparation for caseIgnoreMatch. Inputs are
/// already validated as PrintableString/UTF8String by RDN parsing. Generated
/// tables are pinned to RFC 3454 / Unicode 3.2, which is the stringprep
/// repertoire RFC 4518 uses for stored values.
fn normalizeDirectoryString(arena: std.mem.Allocator, content: []const u8) Error![]const u8 {
    var mapped: std.ArrayList(u21) = .empty;
    var view = std.unicode.Utf8View.init(content) catch return error.MalformedName;
    var iterator = view.iterator();
    while (iterator.nextCodepoint()) |codepoint| {
        if (containsRange(rfc4518_data.unassigned[0..], codepoint)) return error.NamePreparationFailed;
        if (try mappingFor(rfc4518_data.map[0..], rfc4518_data.map_data[0..], codepoint)) |replacement| {
            try appendScalars(&mapped, arena, replacement);
        } else {
            try appendScalar(&mapped, arena, codepoint);
        }
    }

    var decomposed: std.ArrayList(u21) = .empty;
    for (mapped.items) |codepoint| try appendNfkd(&decomposed, arena, codepoint);
    try canonicalOrder(arena, decomposed.items);

    const normalized = try composeNfkc(arena, decomposed.items);
    for (normalized) |codepoint| {
        if (containsRange(rfc4518_data.unassigned[0..], codepoint) or
            containsRange(rfc4518_data.prohibited[0..], codepoint))
        {
            return error.NamePreparationFailed;
        }
    }

    return encodeCaseIgnoreAttributeValue(arena, normalized);
}

fn mappingFor(
    table: []const rfc4518_data.ScalarMapping,
    data: []const u21,
    codepoint: u21,
) Error!?[]const u21 {
    var low: usize = 0;
    var high: usize = table.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const entry = table[mid];
        if (codepoint < entry.scalar) {
            high = mid;
        } else if (codepoint > entry.scalar) {
            low = mid + 1;
        } else {
            const start: usize = entry.offset;
            const end = std.math.add(usize, start, entry.len) catch return error.NamePreparationFailed;
            if (end > data.len) return error.NamePreparationFailed;
            return data[start..end];
        }
    }
    return null;
}

fn appendNfkd(list: *std.ArrayList(u21), arena: std.mem.Allocator, codepoint: u21) Error!void {
    const s_base = 0xac00;
    const l_base = 0x1100;
    const v_base = 0x1161;
    const t_base = 0x11a7;
    const l_count = 19;
    const v_count = 21;
    const t_count = 28;
    const n_count = v_count * t_count;
    const s_count = l_count * n_count;

    if (codepoint >= s_base and codepoint < s_base + s_count) {
        const s_index = codepoint - s_base;
        try appendScalar(list, arena, l_base + s_index / n_count);
        try appendScalar(list, arena, v_base + (s_index % n_count) / t_count);
        const t_index = s_index % t_count;
        if (t_index != 0) try appendScalar(list, arena, t_base + t_index);
        return;
    }

    if (try mappingFor(rfc4518_data.nfkd[0..], rfc4518_data.nfkd_data[0..], codepoint)) |replacement| {
        try appendScalars(list, arena, replacement);
    } else {
        try appendScalar(list, arena, codepoint);
    }
}

fn canonicalOrder(arena: std.mem.Allocator, codepoints: []u21) Error!void {
    return canonicalOrderCounting(arena, codepoints, null);
}

fn canonicalOrderCounting(arena: std.mem.Allocator, codepoints: []u21, lookup_counter: ?*usize) Error!void {
    if (codepoints.len < 2) return;
    const scratch = try arena.alloc(u21, codepoints.len);
    const ccc_scratch = try arena.alloc(u8, codepoints.len);

    var segment_start: usize = 0;
    while (segment_start < codepoints.len) {
        const first_ccc = combiningClassCounting(codepoints[segment_start], lookup_counter);
        const sortable_start = segment_start + @intFromBool(first_ccc == 0);

        var segment_end = sortable_start;
        while (segment_end < codepoints.len and
            combiningClassCounting(codepoints[segment_end], lookup_counter) != 0)
        {
            segment_end += 1;
        }

        try stableOrderByCombiningClass(
            codepoints[sortable_start..segment_end],
            scratch[0 .. segment_end - sortable_start],
            ccc_scratch[0 .. segment_end - sortable_start],
            lookup_counter,
        );

        segment_start = segment_end;
    }
}

fn stableOrderByCombiningClass(
    values: []u21,
    scratch: []u21,
    ccc_scratch: []u8,
    lookup_counter: ?*usize,
) Error!void {
    if (values.len < 2) return;

    var counts = [_]usize{0} ** 256;
    for (values, ccc_scratch) |codepoint, *ccc_out| {
        const ccc = combiningClassCounting(codepoint, lookup_counter);
        if (ccc == 0) return error.NamePreparationFailed;
        ccc_out.* = ccc;
        counts[ccc] = std.math.add(usize, counts[ccc], 1) catch return error.NamePreparationFailed;
    }

    var offsets = [_]usize{0} ** 256;
    var next: usize = 0;
    for (1..256) |ccc| {
        offsets[ccc] = next;
        next = std.math.add(usize, next, counts[ccc]) catch return error.NamePreparationFailed;
    }

    var cursors = offsets;
    for (values, ccc_scratch) |codepoint, ccc| {
        const slot = cursors[ccc];
        if (slot >= scratch.len) return error.NamePreparationFailed;
        scratch[slot] = codepoint;
        cursors[ccc] = std.math.add(usize, cursors[ccc], 1) catch return error.NamePreparationFailed;
    }

    @memcpy(values, scratch[0..values.len]);
}

fn composeNfkc(arena: std.mem.Allocator, input: []const u21) Error![]const u21 {
    var output: std.ArrayList(u21) = .empty;
    if (input.len == 0) return output.items;

    try appendScalar(&output, arena, input[0]);
    var starter_index: ?usize = if (combiningClass(input[0]) == 0) 0 else null;
    var last_ccc = combiningClass(input[0]);

    for (input[1..]) |codepoint| {
        const ccc = combiningClass(codepoint);
        var composed = false;
        if (starter_index) |starter| {
            if (last_ccc < ccc or last_ccc == 0) {
                if (composePair(output.items[starter], codepoint)) |composite| {
                    output.items[starter] = composite;
                    composed = true;
                }
            }
        }

        if (!composed) {
            try appendScalar(&output, arena, codepoint);
            if (ccc == 0) starter_index = output.items.len - 1;
            last_ccc = ccc;
        }
    }

    return output.items;
}

fn composePair(first: u21, second: u21) ?u21 {
    const l_base = 0x1100;
    const v_base = 0x1161;
    const t_base = 0x11a7;
    const s_base = 0xac00;
    const l_count = 19;
    const v_count = 21;
    const t_count = 28;
    const n_count = v_count * t_count;
    const s_count = l_count * n_count;

    if (first >= l_base and first < l_base + l_count and second >= v_base and second < v_base + v_count) {
        return s_base + ((first - l_base) * n_count) + ((second - v_base) * t_count);
    }
    if (first >= s_base and first < s_base + s_count and (first - s_base) % t_count == 0 and
        second > t_base and second < t_base + t_count)
    {
        return first + (second - t_base);
    }

    var low: usize = 0;
    var high: usize = rfc4518_data.compositions.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const entry = rfc4518_data.compositions[mid];
        if (first < entry.first or (first == entry.first and second < entry.second)) {
            high = mid;
        } else if (first > entry.first or (first == entry.first and second > entry.second)) {
            low = mid + 1;
        } else {
            return entry.composite;
        }
    }
    return null;
}

fn encodeCaseIgnoreAttributeValue(arena: std.mem.Allocator, codepoints: []const u21) Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var index: usize = 0;
    var wrote_run = false;

    while (index < codepoints.len and isInsignificantSpaceAt(codepoints, index)) : (index += 1) {}
    if (index == codepoints.len) {
        try appendUtf8(&out, arena, ' ');
        try appendUtf8(&out, arena, ' ');
        return out.items;
    }

    try appendUtf8(&out, arena, ' ');
    while (index < codepoints.len) {
        while (index < codepoints.len and isInsignificantSpaceAt(codepoints, index)) : (index += 1) {}
        if (index == codepoints.len) break;
        if (wrote_run) {
            try appendUtf8(&out, arena, ' ');
            try appendUtf8(&out, arena, ' ');
        }
        while (index < codepoints.len and !isInsignificantSpaceAt(codepoints, index)) : (index += 1) {
            try appendUtf8(&out, arena, codepoints[index]);
        }
        wrote_run = true;
    }
    try appendUtf8(&out, arena, ' ');
    return out.items;
}

fn isInsignificantSpaceAt(codepoints: []const u21, index: usize) bool {
    if (codepoints[index] != ' ') return false;
    return index + 1 == codepoints.len or !isCombiningMark(codepoints[index + 1]);
}

fn isCombiningMark(codepoint: u21) bool {
    return containsRange(rfc4518_data.combining_marks[0..], codepoint);
}

fn combiningClass(codepoint: u21) u8 {
    return combiningClassCounting(codepoint, null);
}

fn combiningClassCounting(codepoint: u21, lookup_counter: ?*usize) u8 {
    if (lookup_counter) |counter| counter.* += 1;
    var low: usize = 0;
    var high: usize = rfc4518_data.combining_classes.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const range = rfc4518_data.combining_classes[mid];
        if (codepoint < range.first) {
            high = mid;
        } else if (codepoint > range.last) {
            low = mid + 1;
        } else {
            return range.ccc;
        }
    }
    return 0;
}

fn containsRange(ranges: []const rfc4518_data.Range, codepoint: u21) bool {
    var low: usize = 0;
    var high: usize = ranges.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const range = ranges[mid];
        if (codepoint < range.first) {
            high = mid;
        } else if (codepoint > range.last) {
            low = mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

fn appendScalar(list: *std.ArrayList(u21), arena: std.mem.Allocator, scalar: u21) Error!void {
    _ = std.math.add(usize, list.items.len, 1) catch return error.NamePreparationFailed;
    try list.append(arena, scalar);
}

fn appendScalars(list: *std.ArrayList(u21), arena: std.mem.Allocator, scalars: []const u21) Error!void {
    _ = std.math.add(usize, list.items.len, scalars.len) catch return error.NamePreparationFailed;
    try list.appendSlice(arena, scalars);
}

fn appendUtf8(list: *std.ArrayList(u8), arena: std.mem.Allocator, codepoint: u21) Error!void {
    const encoded_len = std.unicode.utf8CodepointSequenceLength(codepoint) catch return error.NamePreparationFailed;
    const new_len = std.math.add(usize, list.items.len, encoded_len) catch return error.NamePreparationFailed;
    try list.ensureTotalCapacity(arena, new_len);
    list.items.len += encoded_len;
    _ = std.unicode.utf8Encode(codepoint, list.items[list.items.len - encoded_len ..]) catch return error.NamePreparationFailed;
}

fn appendCount(list: *std.ArrayList(u8), arena: std.mem.Allocator, count: usize) error{OutOfMemory}!void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, count, .big);
    try list.appendSlice(arena, &buf);
}

fn appendBe32(list: *std.ArrayList(u8), arena: std.mem.Allocator, value: u32) error{OutOfMemory}!void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    try list.appendSlice(arena, &buf);
}

fn sliceLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
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

fn integerToSaturatingUsize(view: der.IntegerView) usize {
    var value: usize = 0;
    for (view.content) |byte| {
        value = std.math.mul(usize, value, 256) catch return std.math.maxInt(usize);
        value = std.math.add(usize, value, @as(usize, byte)) catch return std.math.maxInt(usize);
    }
    return value;
}

test "SkipCerts conversion saturates values wider than usize" {
    const wider_than_usize = [_]u8{0x01} ++ ([_]u8{0x00} ** @sizeOf(usize));
    try std.testing.expectEqual(
        std.math.maxInt(usize),
        integerToSaturatingUsize(.{ .content = &wider_than_usize }),
    );
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

test "RFC 4518 canonical ordering handles adversarial runs in bounded work" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const run_len = 4096;
    const total = 1 + run_len * 2;
    const codepoints = try arena.alloc(u21, total);
    codepoints[0] = 'A';
    @memset(codepoints[1 .. 1 + run_len], 0x0315);
    @memset(codepoints[1 + run_len ..], 0x0300);

    var lookups: usize = 0;
    try canonicalOrderCounting(arena, codepoints, &lookups);

    try testing.expectEqual(@as(u21, 'A'), codepoints[0]);
    for (codepoints[1 .. 1 + run_len]) |codepoint| try testing.expectEqual(@as(u21, 0x0300), codepoint);
    for (codepoints[1 + run_len ..]) |codepoint| try testing.expectEqual(@as(u21, 0x0315), codepoint);
    try testing.expect(lookups <= total * 3);
}

test "RFC 4518 canonical ordering is stable and respects starters" {
    var arena_inst = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    var equal_ccc = [_]u21{ 'A', 0x0301, 0x0300 };
    try canonicalOrder(arena, &equal_ccc);
    try testing.expectEqualSlices(u21, &[_]u21{ 'A', 0x0301, 0x0300 }, &equal_ccc);

    var starter_boundaries = [_]u21{ 'A', 0x0315, 0x0300, 'B', 0x0315, 0x0300 };
    try canonicalOrder(arena, &starter_boundaries);
    try testing.expectEqualSlices(u21, &[_]u21{ 'A', 0x0300, 0x0315, 'B', 0x0300, 0x0315 }, &starter_boundaries);

    var leading_nonstarters = [_]u21{ 0x0315, 0x0300, 'A' };
    try canonicalOrder(arena, &leading_nonstarters);
    try testing.expectEqualSlices(u21, &[_]u21{ 0x0300, 0x0315, 'A' }, &leading_nonstarters);
}

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
