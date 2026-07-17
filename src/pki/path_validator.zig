//! Deterministic RFC 5280 certification-path validation core (#345).
//!
//! This module validates paths already discovered by `path_builder`; it does
//! not build paths, fetch issuers, consult the network, or expose provider
//! implementation details.  Validation is iterative and bounded by
//! `ValidationPolicy.maximum_path_length`.
//!
//! Policy choices in this first slice:
//! - configured anchors are authenticated by their `path_builder` input index
//!   and exact DER. Their self-signatures and certificate extensions are not
//!   validation inputs; anchor restrictions require explicit local policy;
//! - anchor validity is ignored by default (it is trust configuration), but
//!   can be enabled explicitly;
//! - absent Key Usage and Extended Key Usage permit the requested use, as in
//!   RFC 5280; when present they restrict it;
//! - Name Constraints are processed by the bounded RFC 5280 engine for the
//!   directoryName, dNSName, rfc822Name, URI, and IP forms. Certificate-policy
//!   processing remains deferred: noncritical certificatePolicies are accepted
//!   under the implicit any-policy policy, while critical instances fail closed.

const std = @import("std");
const crypto = @import("crypto");
const identity = @import("identity.zig");
const name_constraints = @import("name_constraints.zig");
const oid = @import("oid.zig");
const path_builder = @import("path_builder.zig");
const verify = @import("verify.zig");
const x509 = @import("x509.zig");

const wk = oid.well_known;

pub const ValidationPolicy = struct {
    /// Unix time in seconds. Injected by the caller; validation never reads a
    /// clock, which keeps boundary behavior deterministic.
    validation_time: i64,
    expected_dns_name: ?[]const u8 = null,
    require_server_auth_eku: bool = true,
    maximum_path_length: usize = 8,
    /// Bounds the validator's duplicate-extension scan even for a malformed
    /// caller-constructed certificate view. The parser default is also 64.
    maximum_extensions_per_certificate: usize = 64,
    name_constraints: name_constraints.Limits = .{},
    /// Anchors passed to `path_builder.build`, in the same order. Borrowed for
    /// the call only. The terminal element's input index and DER must match.
    trust_anchors: []const x509.Certificate,
    /// RFC 5280 treats the trust anchor as input to validation rather than a
    /// certificate in the prospective path. Its validity is therefore not
    /// checked by default.
    enforce_anchor_validity: bool = false,
};

pub const FailureReason = enum {
    malformed_path,
    invalid_anchor_termination,
    untrusted_anchor,
    signature_invalid,
    signature_algorithm_unsupported,
    signature_key_mismatch,
    signature_malformed,
    issuer_public_key_malformed,
    certificate_not_yet_valid,
    certificate_expired,
    issuer_is_not_ca,
    path_length_exceeded,
    key_usage_violation,
    extended_key_usage_violation,
    unknown_critical_extension,
    duplicate_extension,
    name_constraints_violation,
    name_constraints_unsupported,
    name_constraints_resource_limit_exceeded,
    identity_mismatch,
    invalid_identity_reference,
    validation_resource_limit_exceeded,
    out_of_memory,
};

pub const ValidationFailure = struct {
    reason: FailureReason,
    /// Leaf-first index. Null only when no certificate can be identified
    /// (for example, an empty path or allocation failure).
    certificate_index: ?usize,
    /// A value copy, never a borrowed attacker-controlled string.
    extension_oid: ?oid.ObjectIdentifier = null,
    name_constraint_kind: ?name_constraints.ConstraintKind = null,
    name_form: ?name_constraints.Form = null,
    constraint_certificate_index: ?usize = null,
};

pub const AcceptedPath = struct {
    /// Owned shallow copy of the path elements. Certificate pointers remain
    /// borrowed from the parsed inputs and must outlive this result.
    accepted_path: []const path_builder.Element,
};

pub const ValidationResult = union(enum) {
    accepted: AcceptedPath,
    rejected: ValidationFailure,

    pub fn deinit(self: *ValidationResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .accepted => |accepted| allocator.free(accepted.accepted_path),
            .rejected => {},
        }
        self.* = undefined;
    }
};

/// Validate one leaf-first, anchor-last candidate path. The only allocation is
/// the owned element slice returned on success; allocation failure is itself a
/// structured rejection. No certificate bytes or provider objects are owned.
pub fn validatePath(
    allocator: std.mem.Allocator,
    path: path_builder.Path,
    policy: ValidationPolicy,
    crypto_provider: crypto.provider.CryptoProvider,
) ValidationResult {
    if (checkStructure(path, policy)) |validation_failure| return .{ .rejected = validation_failure };

    const anchor_index = path.elements.len - 1;

    // The target and intermediates form the prospective certification path.
    // The configured anchor is trust input: its certificate extensions do not
    // silently become local anchor policy (RFC 5280 §§6.1, 6.2).
    for (path.elements[0..anchor_index], 0..) |element, certificate_index| {
        if (element.certificate.extensions.len > policy.maximum_extensions_per_certificate) {
            return reject(.validation_resource_limit_exceeded, certificate_index);
        }
        if (checkExtensions(element.certificate, certificate_index)) |validation_failure| {
            return .{ .rejected = validation_failure };
        }
    }

    // Authenticate every child with the next certificate. The configured
    // anchor's self-signature is deliberately irrelevant to trust.
    for (path.elements[0 .. path.elements.len - 1], 0..) |element, certificate_index| {
        const issuer = path.elements[certificate_index + 1].certificate;
        verify.verifyCertificateSignature(
            crypto_provider,
            element.certificate,
            &issuer.subject_public_key_info,
        ) catch |err| return .{ .rejected = signatureFailure(err, certificate_index) };
    }

    for (path.elements, 0..) |element, certificate_index| {
        const is_anchor = certificate_index == path.elements.len - 1;
        if (!is_anchor or policy.enforce_anchor_validity) {
            const validity = element.certificate.validity;
            if (policy.validation_time < unixSeconds(validity.not_before)) {
                return reject(.certificate_not_yet_valid, certificate_index);
            }
            if (policy.validation_time > unixSeconds(validity.not_after)) {
                return reject(.certificate_expired, certificate_index);
            }
        }
    }

    // Every intermediate issues the certificate below it. The terminal trust
    // anchor supplies the trusted name and key but is not a path certificate.
    for (path.elements[1..anchor_index], 1..) |element, certificate_index| {
        const constraints = element.certificate.basicConstraints() orelse
            return reject(.issuer_is_not_ca, certificate_index);
        if (!constraints.is_ca) return reject(.issuer_is_not_ca, certificate_index);

        if (element.certificate.keyUsage()) |usage| {
            if (!usage.key_cert_sign) return rejectOid(.key_usage_violation, certificate_index, &wk.key_usage);
        }

        if (constraints.max_path_len) |limit| {
            var non_self_issued_cas: usize = 0;
            for (path.elements[1..certificate_index]) |below| {
                if (!below.certificate.isSelfIssued()) non_self_issued_cas += 1;
            }
            if (non_self_issued_cas > limit) {
                return rejectOid(.path_length_exceeded, certificate_index, &wk.basic_constraints);
            }
        }
    }

    const leaf = path.elements[0].certificate;
    if (leaf.keyUsage()) |usage| {
        // Tardigrade's TLS stack is TLS 1.3: CertificateVerify always signs,
        // including with RSA. keyEncipherment alone describes legacy RSA key
        // transport and cannot authorize this authentication operation.
        if (!usage.digital_signature) return rejectOid(.key_usage_violation, 0, &wk.key_usage);
    }

    if (policy.require_server_auth_eku) {
        // A present EKU restricts every non-anchor certificate in the path;
        // absence is unrestricted. Trust-anchor purpose is configuration.
        for (path.elements[0 .. path.elements.len - 1], 0..) |element, certificate_index| {
            if (element.certificate.extendedKeyUsage()) |eku| {
                if (!eku.allowsServerAuth()) {
                    return rejectOid(.extended_key_usage_violation, certificate_index, &wk.ext_key_usage);
                }
            }
        }
    }

    if (name_constraints.validatePath(allocator, path, policy.name_constraints)) |name_failure| {
        return .{ .rejected = nameConstraintsFailure(name_failure) };
    }

    // Identity is intentionally last: no path is accepted based on a name
    // match before its signatures and RFC 5280 policy checks succeed.
    if (policy.expected_dns_name) |expected| {
        const verdict = identity.verifyHost(leaf, expected) catch
            return reject(.invalid_identity_reference, 0);
        if (!verdict.isMatch()) return reject(.identity_mismatch, 0);
    }

    const owned = allocator.dupe(path_builder.Element, path.elements) catch
        return rejectWithoutCertificate(.out_of_memory);
    return .{ .accepted = .{ .accepted_path = owned } };
}

/// Validate candidates in builder order and return the first accepted path.
/// If bounded discovery was truncated and no returned candidate validates, the
/// outcome is a resource-limit rejection rather than a false assertion that no
/// valid path exists beyond the builder's search frontier.
pub fn validateCandidates(
    allocator: std.mem.Allocator,
    candidates: path_builder.CandidatePaths,
    policy: ValidationPolicy,
    crypto_provider: crypto.provider.CryptoProvider,
) ValidationResult {
    var first_failure: ?ValidationFailure = null;
    for (candidates.paths) |path| {
        var result = validatePath(allocator, path, policy, crypto_provider);
        switch (result) {
            .accepted => return result,
            .rejected => |validation_failure| {
                if (validation_failure.reason == .out_of_memory) return result;
                if (first_failure == null) first_failure = validation_failure;
                result.deinit(allocator);
            },
        }
    }
    if (candidates.truncated) return rejectWithoutCertificate(.validation_resource_limit_exceeded);
    return .{ .rejected = first_failure orelse .{
        .reason = .malformed_path,
        .certificate_index = null,
    } };
}

fn checkStructure(path: path_builder.Path, policy: ValidationPolicy) ?ValidationFailure {
    if (path.elements.len == 0) return failure(.malformed_path, null);
    if (path.elements.len > policy.maximum_path_length) {
        return failure(.validation_resource_limit_exceeded, null);
    }
    if (path.elements.len < 2) return failure(.malformed_path, 0);
    if (path.elements[0].source != .leaf or path.elements[0].input_index != 0) {
        return failure(.malformed_path, 0);
    }

    const last = path.elements.len - 1;
    for (path.elements[1..last], 1..) |element, certificate_index| {
        if (element.source != .intermediate) return failure(.malformed_path, certificate_index);
    }
    if (path.elements[last].source != .anchor) {
        return failure(.invalid_anchor_termination, last);
    }

    const anchor = path.elements[last];
    if (anchor.input_index >= policy.trust_anchors.len) return failure(.untrusted_anchor, last);
    const configured_anchor = &policy.trust_anchors[anchor.input_index];
    if (anchor.certificate != configured_anchor or
        !std.mem.eql(u8, anchor.certificate.raw, configured_anchor.raw))
    {
        return failure(.untrusted_anchor, last);
    }

    for (path.elements, 0..) |element, index| {
        for (path.elements[0..index]) |earlier| {
            if (element.certificate == earlier.certificate or
                std.mem.eql(u8, element.certificate.raw, earlier.certificate.raw))
            {
                return failure(.malformed_path, index);
            }
        }
        if (index < last and
            !element.certificate.issuer.eqlForChaining(&path.elements[index + 1].certificate.subject))
        {
            return failure(.malformed_path, index);
        }
    }
    return null;
}

fn checkExtensions(certificate: *const x509.Certificate, certificate_index: usize) ?ValidationFailure {
    for (certificate.extensions, 0..) |extension, index| {
        for (certificate.extensions[0..index]) |earlier| {
            if (extension.oid.eql(&earlier.oid)) {
                return .{
                    .reason = .duplicate_extension,
                    .certificate_index = certificate_index,
                    .extension_oid = extension.oid,
                };
            }
        }
    }
    for (certificate.extensions) |extension| {
        if (extension.critical and !criticalExtensionHandled(&extension.oid)) {
            return .{
                .reason = .unknown_critical_extension,
                .certificate_index = certificate_index,
                .extension_oid = extension.oid,
            };
        }
    }
    return null;
}

fn criticalExtensionHandled(extension_oid: *const oid.ObjectIdentifier) bool {
    return extension_oid.eqlComponents(&wk.basic_constraints) or
        extension_oid.eqlComponents(&wk.key_usage) or
        extension_oid.eqlComponents(&wk.subject_alt_name) or
        extension_oid.eqlComponents(&wk.ext_key_usage) or
        extension_oid.eqlComponents(&wk.name_constraints) or
        extension_oid.eqlComponents(&wk.subject_key_identifier) or
        extension_oid.eqlComponents(&wk.authority_key_identifier);
}

fn nameConstraintsFailure(name_failure: name_constraints.Failure) ValidationFailure {
    const reason: FailureReason = switch (name_failure.reason) {
        .violation => .name_constraints_violation,
        .unsupported => .name_constraints_unsupported,
        .resource_limit_exceeded => .name_constraints_resource_limit_exceeded,
        .out_of_memory => .out_of_memory,
    };
    return .{
        .reason = reason,
        .certificate_index = name_failure.certificate_index,
        .extension_oid = oid.ObjectIdentifier.fromComponents(&wk.name_constraints) catch unreachable,
        .name_constraint_kind = name_failure.constraint_kind,
        .name_form = name_failure.name_form,
        .constraint_certificate_index = name_failure.constraint_certificate_index,
    };
}

fn signatureFailure(err: verify.Error, certificate_index: usize) ValidationFailure {
    const reason: FailureReason = switch (err) {
        error.InvalidSignature => .signature_invalid,
        error.UnsupportedSignatureAlgorithm => .signature_algorithm_unsupported,
        error.IssuerKeyMismatch => .signature_key_mismatch,
        error.MalformedSignature => .signature_malformed,
        error.MalformedPublicKey => .issuer_public_key_malformed,
    };
    return .{ .reason = reason, .certificate_index = certificate_index };
}

fn reject(reason: FailureReason, certificate_index: usize) ValidationResult {
    return .{ .rejected = .{ .reason = reason, .certificate_index = certificate_index } };
}

fn rejectOid(reason: FailureReason, certificate_index: usize, components: []const u32) ValidationResult {
    return .{
        .rejected = .{
            .reason = reason,
            .certificate_index = certificate_index,
            // Callers pass only compile-time well-known OIDs, all below the fixed
            // component bound; external input cannot reach this invariant.
            .extension_oid = oid.ObjectIdentifier.fromComponents(components) catch unreachable,
        },
    };
}

fn rejectWithoutCertificate(reason: FailureReason) ValidationResult {
    return .{ .rejected = .{ .reason = reason, .certificate_index = null } };
}

fn failure(reason: FailureReason, certificate_index: ?usize) ValidationFailure {
    return .{ .reason = reason, .certificate_index = certificate_index };
}

/// Convert the parser's validated UTC date to Unix seconds without consulting
/// ambient time. Howard Hinnant's civil-date transform handles pre-1970 dates
/// as well as the full four-digit GeneralizedTime range.
fn unixSeconds(value: x509.Time) i64 {
    var year: i64 = value.year;
    const month: i64 = value.month;
    const day: i64 = value.day;
    year -= @intFromBool(month <= 2);
    const era = @divFloor(year, 400);
    const year_of_era = year - era * 400;
    const adjusted_month = month + (if (month > 2) @as(i64, -3) else 9);
    const day_of_year = @divFloor(153 * adjusted_month + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) -
        @divFloor(year_of_era, 100) + day_of_year;
    const days = era * 146097 + day_of_era - 719468;
    return days * 86400 + @as(i64, value.hour) * 3600 +
        @as(i64, value.minute) * 60 + value.second;
}

const testing = std.testing;

test "Unix conversion preserves exact validity boundaries" {
    const epoch = x509.Time{ .year = 1970, .month = 1, .day = 1, .hour = 0, .minute = 0, .second = 0, .encoding = .utc };
    const leap = x509.Time{ .year = 2024, .month = 2, .day = 29, .hour = 12, .minute = 34, .second = 56, .encoding = .utc };
    try testing.expectEqual(@as(i64, 0), unixSeconds(epoch));
    try testing.expectEqual(@as(i64, 1_709_210_096), unixSeconds(leap));
}

test {
    testing.refAllDecls(@This());
}
