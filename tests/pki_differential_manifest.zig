//! Executable registry for the bounded PKI differential corpus (#348).

pub const Profile = enum { core, extended };

pub const Category = enum {
    valid_chain,
    malformed_der,
    unknown_critical_extension,
    duplicate_extension,
    identity,
    cross_signing,
    name_constraints,
    path_length,
    algorithm_failure,
};

pub const Validator = enum { tardigrade, openssl, go_crypto_x509 };

pub const Status = enum { accept, reject, tool_failure };

/// Validator-neutral, bounded semantic identity for one validation outcome.
/// Native diagnostics are retained by the harness, but are never comparison
/// keys or long-term manifest expectations.
pub const Reason = enum {
    accepted,
    malformed_certificate,
    malformed_der,
    duplicate_extension,
    unknown_critical_extension,
    identity_mismatch,
    name_constraints_violation,
    path_length_violation,
    signature_algorithm_invalid,
    signature_invalid,
    issuer_key_or_spki_invalid,
    validity_failure,
    key_usage_failure,
    extended_key_usage_failure,
    policy_failure,
    untrusted_or_incomplete_path,
    resource_limit,
    fixture_load_failure,
    oracle_launch_failure,
    oracle_timeout,
    oracle_signal,
    oracle_stdout_limit,
    oracle_stderr_limit,
    oracle_malformed_output,
    oracle_unexpected_exit,
    oracle_failure,
    unclassified_rejection,

    pub fn isTool(self: Reason) bool {
        return switch (self) {
            .resource_limit,
            .fixture_load_failure,
            .oracle_launch_failure,
            .oracle_timeout,
            .oracle_signal,
            .oracle_stdout_limit,
            .oracle_stderr_limit,
            .oracle_malformed_output,
            .oracle_unexpected_exit,
            .oracle_failure,
            => true,
            else => false,
        };
    }
};

pub const Expected = struct {
    status: Status,
    reason: Reason,

    pub fn accepted() Expected {
        return .{ .status = .accept, .reason = .accepted };
    }

    pub fn rejected(reason: Reason) Expected {
        return .{ .status = .reject, .reason = reason };
    }

    pub fn eql(self: Expected, other: Expected) bool {
        return self.status == other.status and self.reason == other.reason;
    }
};

pub const Expectations = struct {
    tardigrade: Expected,
    openssl: Expected,
    go: Expected,

    pub fn allAccepted() Expectations {
        return .{
            .tardigrade = .accepted(),
            .openssl = .accepted(),
            .go = .accepted(),
        };
    }

    pub fn allRejected(reason: Reason) Expectations {
        return .{
            .tardigrade = .rejected(reason),
            .openssl = .rejected(reason),
            .go = .rejected(reason),
        };
    }

    pub fn agree(self: Expectations) bool {
        return self.tardigrade.eql(self.openssl) and self.openssl.eql(self.go);
    }
};

pub const Case = struct {
    id: []const u8,
    profile: Profile,
    /// Required for extended-only cases so normal-CI exclusions stay
    /// deliberate and reviewable.
    extended_rationale: ?[]const u8 = null,
    category: Category,
    root_file: []const u8,
    intermediate_file: ?[]const u8 = null,
    leaf_file: []const u8,
    dns_name: ?[]const u8 = null,
    expected: Expectations,
    /// Required whenever the three expected decisions differ. This is the
    /// explicit policy-normalization record, never an implicit waiver.
    normalization: ?[]const u8 = null,
    provenance: []const u8,
    license: []const u8,
    /// Focused unit/fuzz destination for any reduced disagreement.
    regression_target: []const u8,
};

const nc = "src/pki/testdata/name_constraints";
const hostile = "tests/vectors/pki";

fn mutationCase(
    comptime id: []const u8,
    profile: Profile,
    category: Category,
    expected: Expectations,
    normalization: ?[]const u8,
) Case {
    return .{
        .id = id,
        .profile = profile,
        .extended_rationale = if (profile == .extended)
            "Extended mutation-matrix member; core retains one representative case from this major class."
        else
            null,
        .category = category,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/intermediate.crt",
        .leaf_file = hostile ++ "/" ++ id ++ ".crt",
        .expected = expected,
        .normalization = normalization,
        .provenance = "Deterministic project-owned DER mutation; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/der_tests.zig, src/pki/x509_tests.zig, and PKI fuzz corpora",
    };
}

pub const cases = [_]Case{
    .{
        .id = "valid-intermediate-chain",
        .profile = .core,
        .category = .valid_chain,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/intermediate.crt",
        .leaf_file = hostile ++ "/valid-leaf.crt",
        .dns_name = "api.example.test",
        .expected = .allAccepted(),
        .provenance = "Deterministic project-owned Ed25519 fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/path_builder_tests.zig and src/pki/path_validator_tests.zig",
    },
    .{
        .id = "identity-wildcard-one-label",
        .profile = .core,
        .category = .identity,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/intermediate.crt",
        .leaf_file = hostile ++ "/wildcard-leaf.crt",
        .dns_name = "api.example.test",
        .expected = .allAccepted(),
        .provenance = "Deterministic project-owned Ed25519 fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/identity_tests.zig",
    },
    .{
        .id = "identity-wildcard-apex",
        .profile = .core,
        .category = .identity,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/intermediate.crt",
        .leaf_file = hostile ++ "/wildcard-leaf.crt",
        .dns_name = "example.test",
        .expected = .allRejected(.identity_mismatch),
        .provenance = "Deterministic project-owned Ed25519 fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/identity_tests.zig",
    },
    .{
        .id = "identity-wildcard-multiple-labels",
        .profile = .extended,
        .extended_rationale = "Redundant wildcard depth variant; the core corpus retains the apex mismatch.",
        .category = .identity,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/intermediate.crt",
        .leaf_file = hostile ++ "/wildcard-leaf.crt",
        .dns_name = "deep.api.example.test",
        .expected = .allRejected(.identity_mismatch),
        .provenance = "Deterministic project-owned Ed25519 fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/identity_tests.zig",
    },
    .{
        .id = "unknown-critical-extension",
        .profile = .core,
        .category = .unknown_critical_extension,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/intermediate.crt",
        .leaf_file = hostile ++ "/unknown-critical-leaf.crt",
        .dns_name = "critical.example.test",
        .expected = .allRejected(.unknown_critical_extension),
        .provenance = "Deterministic project-owned Ed25519 fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/path_validator_tests.zig",
    },
    .{
        .id = "duplicate-critical-extension",
        .profile = .core,
        .category = .duplicate_extension,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/intermediate.crt",
        .leaf_file = hostile ++ "/duplicate-extension-leaf.crt",
        .dns_name = "duplicate.example.test",
        .expected = .{
            .tardigrade = .rejected(.duplicate_extension),
            .openssl = .rejected(.unknown_critical_extension),
            .go = .rejected(.duplicate_extension),
        },
        .normalization = "OpenSSL reason=unknown_critical_extension while Tardigrade and Go crypto/x509 reason=duplicate_extension: OpenSSL reports numeric verify code 34 after parsing the duplicate critical extension.",
        .provenance = "Deterministic project-owned DER-mutated Ed25519 fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/x509_tests.zig and src/pki/path_validator_tests.zig",
    },
    .{
        .id = "corrupt-certificate-signature",
        .profile = .core,
        .category = .algorithm_failure,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/intermediate.crt",
        .leaf_file = hostile ++ "/signature-corrupt-leaf.crt",
        .dns_name = "api.example.test",
        .expected = .{
            .tardigrade = .rejected(.signature_invalid),
            .openssl = .rejected(.signature_invalid),
            .go = .rejected(.untrusted_or_incomplete_path),
        },
        .normalization = "Go crypto/x509 reason=untrusted_or_incomplete_path while Tardigrade and OpenSSL reason=signature_invalid: Go exposes the failed candidate chain as UnknownAuthorityError rather than a stable signature-failure type.",
        .provenance = "Deterministic project-owned Ed25519 fixture with one signature bit changed; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/verify_tests.zig",
    },
    .{
        .id = "path-length-zero-violation",
        .profile = .core,
        .category = .path_length,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/pathlen-chain.crt",
        .leaf_file = hostile ++ "/pathlen-leaf.crt",
        .dns_name = "pathlen.example.test",
        .expected = .allRejected(.path_length_violation),
        .provenance = "Deterministic project-owned Ed25519 fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/path_validator_tests.zig",
    },
    .{
        .id = "ambiguous-cross-signed-path",
        .profile = .extended,
        .extended_rationale = "Multi-path ordering is deterministic but more expensive than the representative core chain.",
        .category = .cross_signing,
        .root_file = hostile ++ "/cross-roots.crt",
        .intermediate_file = hostile ++ "/cross-untrusted-b-first.crt",
        .leaf_file = hostile ++ "/cross-leaf.crt",
        .dns_name = "cross.example.test",
        .expected = .allAccepted(),
        .provenance = "Deterministic project-owned dual-root Ed25519 fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/path_builder_tests.zig",
    },
    .{
        .id = "malformed-truncated-certificate",
        .profile = .core,
        .category = .malformed_der,
        .root_file = hostile ++ "/root.crt",
        .leaf_file = hostile ++ "/malformed-truncated.crt",
        .expected = .allRejected(.malformed_der),
        .provenance = "Project-owned reduced malformed DER seed; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/x509_tests.zig fuzz corpus",
    },
    .{
        .id = "name-constraints-dns-permitted",
        .profile = .core,
        .category = .name_constraints,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/dns-constraints-intermediate.crt",
        .leaf_file = hostile ++ "/dns-permitted-leaf.crt",
        .dns_name = "api.example.test",
        .expected = .allAccepted(),
        .provenance = "Deterministic project-owned DNS-only Name Constraints fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/name_constraints.zig and src/pki/identity_tests.zig",
    },
    .{
        .id = "name-constraints-dns-excluded",
        .profile = .core,
        .category = .name_constraints,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/dns-constraints-intermediate.crt",
        .leaf_file = hostile ++ "/dns-excluded-leaf.crt",
        .dns_name = "blocked.example.test",
        .expected = .allRejected(.name_constraints_violation),
        .provenance = "Deterministic project-owned DNS-only Name Constraints fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/name_constraints.zig",
    },
    .{
        .id = "identity-san-mismatch",
        .profile = .core,
        .category = .identity,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/intermediate.crt",
        .leaf_file = hostile ++ "/identity-mismatch-leaf.crt",
        .dns_name = "wrong.example.test",
        .expected = .allRejected(.identity_mismatch),
        .provenance = "Deterministic project-owned identity-only negative fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/identity_tests.zig",
    },
    .{
        .id = "name-constraints-ip-permitted-boundary",
        .profile = .core,
        .category = .name_constraints,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/ip-constraints-intermediate.crt",
        .leaf_file = hostile ++ "/ip-permitted-leaf.crt",
        .expected = .allAccepted(),
        .provenance = "Deterministic project-owned IP-only Name Constraints fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/name_constraints.zig",
    },
    .{
        .id = "name-constraints-ip-excluded",
        .profile = .core,
        .category = .name_constraints,
        .root_file = hostile ++ "/root.crt",
        .intermediate_file = hostile ++ "/ip-constraints-intermediate.crt",
        .leaf_file = hostile ++ "/ip-excluded-leaf.crt",
        .expected = .allRejected(.name_constraints_violation),
        .provenance = "Deterministic project-owned IP-only Name Constraints fixture; see tests/vectors/pki/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/name_constraints.zig",
    },
    .{
        .id = "name-constraints-leading-dot-subdomain",
        .profile = .extended,
        .extended_rationale = "Leading-dot compatibility is a second-order Name Constraints boundary; core retains DNS/IP excluded cases.",
        .category = .name_constraints,
        .root_file = nc ++ "/root.crt",
        .intermediate_file = nc ++ "/leading-dot-intermediate.crt",
        .leaf_file = nc ++ "/leading-dot-subdomain.crt",
        .dns_name = "sub.example.com",
        .expected = .allAccepted(),
        .provenance = "Project-owned OpenSSL-generated RFC 5280 fixture; see src/pki/testdata/name_constraints/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/name_constraints.zig",
    },
    .{
        .id = "name-constraints-leading-dot-exact",
        .profile = .extended,
        .extended_rationale = "Leading-dot exact-name rejection pairs with the extended subdomain acceptance case.",
        .category = .name_constraints,
        .root_file = nc ++ "/root.crt",
        .intermediate_file = nc ++ "/leading-dot-intermediate.crt",
        .leaf_file = nc ++ "/leading-dot-exact.crt",
        .dns_name = "example.com",
        .expected = .allRejected(.name_constraints_violation),
        .provenance = "Project-owned OpenSSL-generated RFC 5280 fixture; see src/pki/testdata/name_constraints/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/name_constraints.zig",
    },
    .{
        .id = "name-constraints-directory-name-permitted",
        .profile = .extended,
        .extended_rationale = "Explicitly records Go's directoryName limitation; core DNS/IP cases contain no unrelated constraint forms.",
        .category = .name_constraints,
        .root_file = nc ++ "/root.crt",
        .intermediate_file = nc ++ "/intermediate.crt",
        .leaf_file = nc ++ "/dns-good.crt",
        .dns_name = "api.example.com",
        .expected = .{ .tardigrade = .accepted(), .openssl = .accepted(), .go = .rejected(.unknown_critical_extension) },
        .normalization = "Go status=reject reason=unknown_critical_extension while Tardigrade and OpenSSL status=accept reason=accepted because Go does not implement critical directoryName constraints.",
        .provenance = "Project-owned OpenSSL-generated RFC 5280 fixture; see src/pki/testdata/name_constraints/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/name_constraints.zig",
    },
    .{
        .id = "name-constraints-directory-name-excluded",
        .profile = .extended,
        .extended_rationale = "Explicitly records Go's directoryName limitation; core DNS/IP cases contain no unrelated constraint forms.",
        .category = .name_constraints,
        .root_file = nc ++ "/root.crt",
        .intermediate_file = nc ++ "/intermediate.crt",
        .leaf_file = nc ++ "/directory-bad.crt",
        .expected = .{
            .tardigrade = .rejected(.name_constraints_violation),
            .openssl = .rejected(.name_constraints_violation),
            .go = .rejected(.unknown_critical_extension),
        },
        .normalization = "Go reason=unknown_critical_extension while Tardigrade and OpenSSL reason=name_constraints_violation because Go cannot evaluate the critical directoryName exclusion.",
        .provenance = "Project-owned OpenSSL-generated RFC 5280 fixture; see src/pki/testdata/name_constraints/README.md",
        .license = "Apache-2.0",
        .regression_target = "src/pki/name_constraints.zig",
    },
    mutationCase(
        "algorithm-outer-inner-mismatch",
        .core,
        .algorithm_failure,
        .{
            .tardigrade = .rejected(.signature_algorithm_invalid),
            .openssl = .rejected(.signature_invalid),
            .go = .rejected(.signature_algorithm_invalid),
        },
        "OpenSSL reason=signature_invalid while Tardigrade and Go reason=signature_algorithm_invalid for the exact inner/outer AlgorithmIdentifier mismatch.",
    ),
    mutationCase(
        "algorithm-issuer-key-mismatch",
        .extended,
        .algorithm_failure,
        .{
            .tardigrade = .rejected(.signature_algorithm_invalid),
            .openssl = .rejected(.untrusted_or_incomplete_path),
            .go = .rejected(.untrusted_or_incomplete_path),
        },
        "Tardigrade reason=signature_algorithm_invalid while OpenSSL and Go reason=untrusted_or_incomplete_path because the external path APIs collapse issuer-key incompatibility into candidate-path failure.",
    ),
    mutationCase(
        "algorithm-unsupported-signature-oid",
        .extended,
        .algorithm_failure,
        .{
            .tardigrade = .rejected(.signature_algorithm_invalid),
            .openssl = .rejected(.untrusted_or_incomplete_path),
            .go = .rejected(.untrusted_or_incomplete_path),
        },
        "Tardigrade reason=signature_algorithm_invalid while OpenSSL and Go reason=untrusted_or_incomplete_path because their path APIs hide the unsupported candidate signature OID.",
    ),
    mutationCase(
        "algorithm-malformed-signature-oid",
        .extended,
        .algorithm_failure,
        .{
            .tardigrade = .rejected(.signature_algorithm_invalid),
            .openssl = .rejected(.signature_algorithm_invalid),
            .go = .rejected(.malformed_der),
        },
        "Go reason=malformed_der while Tardigrade and OpenSSL reason=signature_algorithm_invalid because Go exposes only a generic malformed-OID parser diagnostic.",
    ),
    mutationCase(
        "algorithm-ed25519-illegal-parameters",
        .extended,
        .algorithm_failure,
        .{
            .tardigrade = .rejected(.signature_algorithm_invalid),
            .openssl = .rejected(.signature_invalid),
            .go = .rejected(.untrusted_or_incomplete_path),
        },
        "Tardigrade reason=signature_algorithm_invalid, OpenSSL reason=signature_invalid, and Go reason=untrusted_or_incomplete_path for forbidden Ed25519 parameters, reflecting each API's stable granularity.",
    ),
    mutationCase(
        "algorithm-rsa-pss-parameter-confusion",
        .extended,
        .algorithm_failure,
        .{
            .tardigrade = .rejected(.signature_algorithm_invalid),
            .openssl = .rejected(.untrusted_or_incomplete_path),
            .go = .rejected(.untrusted_or_incomplete_path),
        },
        "Tardigrade reason=signature_algorithm_invalid while OpenSSL and Go reason=untrusted_or_incomplete_path for RSA-PSS parameters incompatible with the Ed25519 issuer key.",
    ),
    mutationCase(
        "algorithm-rsa-null-absent",
        .extended,
        .algorithm_failure,
        .{
            .tardigrade = .rejected(.signature_algorithm_invalid),
            .openssl = .rejected(.untrusted_or_incomplete_path),
            .go = .rejected(.untrusted_or_incomplete_path),
        },
        "Tardigrade reason=signature_algorithm_invalid while OpenSSL and Go reason=untrusted_or_incomplete_path for an RSA AlgorithmIdentifier with required NULL parameters absent and an incompatible issuer key.",
    ),
    mutationCase(
        "algorithm-malformed-spki",
        .extended,
        .algorithm_failure,
        .{
            .tardigrade = .rejected(.issuer_key_or_spki_invalid),
            .openssl = .rejected(.issuer_key_or_spki_invalid),
            .go = .rejected(.malformed_der),
        },
        "Go reason=malformed_der while Tardigrade and OpenSSL reason=issuer_key_or_spki_invalid because Go reports the malformed SPKI OID through its generic parser diagnostic.",
    ),
    mutationCase(
        "algorithm-incompatible-spki-key",
        .extended,
        .algorithm_failure,
        .{
            .tardigrade = .rejected(.signature_invalid),
            .openssl = .rejected(.signature_invalid),
            .go = .rejected(.untrusted_or_incomplete_path),
        },
        "Tardigrade and OpenSSL reason=signature_invalid while Go reason=untrusted_or_incomplete_path for the incompatible SPKI BIT STRING encoding.",
    ),
    mutationCase(
        "algorithm-malformed-signature-bits",
        .extended,
        .algorithm_failure,
        .allRejected(.signature_algorithm_invalid),
        null,
    ),
    mutationCase(
        "der-non-minimal-long-length",
        .core,
        .malformed_der,
        .{
            .tardigrade = .rejected(.malformed_der),
            .openssl = .accepted(),
            .go = .rejected(.malformed_der),
        },
        "OpenSSL status=accept reason=accepted while Tardigrade and Go status=reject reason=malformed_der because OpenSSL accepts the non-minimal BER length form.",
    ),
    mutationCase(
        "der-indefinite-length",
        .extended,
        .malformed_der,
        .{
            .tardigrade = .rejected(.malformed_der),
            .openssl = .accepted(),
            .go = .rejected(.malformed_der),
        },
        "OpenSSL status=accept reason=accepted while Tardigrade and Go status=reject reason=malformed_der because OpenSSL accepts the BER indefinite-length wrapper.",
    ),
    mutationCase("der-truncated-long-length", .extended, .malformed_der, .allRejected(.malformed_der), null),
    mutationCase(
        "der-non-minimal-integer",
        .extended,
        .malformed_der,
        .{
            .tardigrade = .rejected(.malformed_certificate),
            .openssl = .rejected(.malformed_der),
            .go = .rejected(.malformed_der),
        },
        "Tardigrade reason=malformed_certificate while OpenSSL and Go reason=malformed_der because the X.509 layer labels the non-minimal serial-number encoding.",
    ),
    mutationCase(
        "der-invalid-bit-string-unused",
        .extended,
        .malformed_der,
        .{
            .tardigrade = .rejected(.signature_algorithm_invalid),
            .openssl = .rejected(.malformed_der),
            .go = .rejected(.signature_algorithm_invalid),
        },
        "OpenSSL reason=malformed_der while Tardigrade and Go reason=signature_algorithm_invalid for the invalid signature BIT STRING unused-bit count.",
    ),
    mutationCase(
        "der-nonzero-bit-string-padding",
        .extended,
        .malformed_der,
        .{
            .tardigrade = .rejected(.signature_algorithm_invalid),
            .openssl = .rejected(.signature_invalid),
            .go = .rejected(.signature_algorithm_invalid),
        },
        "OpenSSL reason=signature_invalid while Tardigrade and Go reason=signature_algorithm_invalid for nonzero signature BIT STRING padding bits.",
    ),
    mutationCase(
        "der-constructed-bit-string",
        .extended,
        .malformed_der,
        .{
            .tardigrade = .rejected(.signature_algorithm_invalid),
            .openssl = .rejected(.malformed_der),
            .go = .rejected(.signature_algorithm_invalid),
        },
        "OpenSSL reason=malformed_der while Tardigrade and Go reason=signature_algorithm_invalid for a constructed signature BIT STRING tag.",
    ),
    mutationCase(
        "der-trailing-data",
        .extended,
        .malformed_der,
        .{
            .tardigrade = .rejected(.malformed_der),
            .openssl = .accepted(),
            .go = .rejected(.malformed_der),
        },
        "OpenSSL status=accept reason=accepted while Tardigrade and Go status=reject reason=malformed_der because OpenSSL ignores bytes after the certificate object.",
    ),
    mutationCase(
        "der-malformed-nested-extension-len",
        .extended,
        .malformed_der,
        .{
            .tardigrade = .rejected(.malformed_certificate),
            .openssl = .rejected(.malformed_der),
            .go = .rejected(.malformed_der),
        },
        "Tardigrade reason=malformed_certificate while OpenSSL and Go reason=malformed_der because the X.509 layer labels the nested extension-length failure.",
    ),
};
